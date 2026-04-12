/**
 * Copyright (C) 2021-2024 Saturneric <eric@bktus.com>
 *
 * This file is part of GpgFrontend.
 *
 * GpgFrontend is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GpgFrontend is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GpgFrontend. If not, see <https://www.gnu.org/licenses/>.
 *
 * The initial version of the source code is inherited from
 * the gpg4usb project, which is under GPL-3.0-or-later.
 *
 * All the source code of GpgFrontend was modified and released by
 * Saturneric <eric@bktus.com> starting on May 12, 2021.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

#include "GpgBasicOperator.h"

#include <gpg-error.h>

#include "core/function/GFKeyDatabase.h"
#include "core/model/GpgData.h"
#include "core/model/GpgDecryptResult.h"
#include "core/model/GpgEncryptResult.h"
#include "core/model/GpgSignResult.h"
#include "core/model/GpgVerifyResult.h"
#include "core/utils/AsyncUtils.h"
#include "core/utils/GpgUtils.h"

namespace GpgFrontend {

GpgBasicOperator::GpgBasicOperator(int channel)
    : SingletonFunctionObject<GpgBasicOperator>(channel) {}

void SetSignersImpl(GpgContext& ctx_, const GpgAbstractKeyPtrList& signers,
                    bool ascii) {
  auto* ctx = ascii ? ctx_.DefaultContext() : ctx_.BinaryContext();

  gpgme_signers_clear(ctx);

  auto keys = ConvertKey2GpgKeyList(ctx_.GetChannel(), signers);
  for (const auto& key : keys) {
    LOG_D() << "signer's key fpr: " << key->Fingerprint();
    if (key->IsHasSignCap()) {
      auto error = gpgme_signers_add(ctx, static_cast<gpgme_key_t>(*key));
      CheckGpgError(error);
    }
  }

  auto count = gpgme_signers_count(ctx_.DefaultContext());
  if (static_cast<unsigned int>(signers.size()) != count) {
    FLOG_D("not all signers added");
  }
}

auto EncryptImpl(GpgContext& ctx_, const GpgAbstractKeyPtrList& keys,
                 const GFBuffer& in_buffer, bool ascii,
                 const DataObjectPtr& data_object) -> GpgError {
  auto recipients = Convert2RawGpgMEKeyList(ctx_.GetChannel(), keys);

  GpgData data_in(in_buffer);
  GpgData data_out;

  auto* ctx = ascii ? ctx_.DefaultContext() : ctx_.BinaryContext();
  auto err = CheckGpgError(
      gpgme_op_encrypt(ctx, keys.isEmpty() ? nullptr : recipients.data(),
                       GPGME_ENCRYPT_ALWAYS_TRUST, data_in, data_out));
  data_object->Swap({
      GpgEncryptResult(gpgme_op_encrypt_result(ctx)),
      data_out.Read2GFBuffer(),
  });

  return err;
}

auto EncryptRpgpImpl(GpgContext& ctx_, const GpgAbstractKeyPtrList& keys,
                     const GFBuffer& in_buffer, bool ascii,
                     const DataObjectPtr& data_object) -> GpgError {
  auto key_db = ctx_.KeyDatabase();
  if (!key_db) {
    LOG_E() << "Failed to get key database from context";
    return GPG_ERR_GENERAL;
  }

  // 1. Vector to hold the actual memory of the UTF-8 strings
  QContainer<QByteArray> key_blocks_utf8;

  // 2. Vector to hold the pointers to pass to Rust FFI
  std::vector<const char*> recipient_cstrs;

  for (const auto& key : keys) {
    auto key_block = key_db->GetKeyBlocks(key->Fingerprint());
    if (!key_block || key_block->public_key.isEmpty()) {
      LOG_W() << "No valid public key block found for key with fpr: "
              << key->Fingerprint();
      continue;
    }

    // Keep the QByteArray alive by pushing it to the vector
    key_blocks_utf8.push_back(key_block->public_key.toUtf8());
  }

  if (key_blocks_utf8.empty()) {
    LOG_E() << "No valid recipients found for encryption.";
    return GPG_ERR_GENERAL;  // Or appropriate error code
  }

  // Pre-allocate space for performance
  recipient_cstrs.reserve(key_blocks_utf8.size());

  // Safely extract pointers from the valid memory blocks
  for (const auto& ba : key_blocks_utf8) {
    recipient_cstrs.push_back(ba.constData());
  }

  std::string name;
  uint8_t* out_encrypted = nullptr;
  size_t out_len = 0;

  // Call Rust FFI. Ensure in_buffer is a null-terminated C-string if Rust
  // expects it.
  auto status = Rust::gfr_crypto_encrypt_text(
      name.c_str(), reinterpret_cast<const uint8_t*>(in_buffer.Data()),
      in_buffer.Size(), recipient_cstrs.data(), recipient_cstrs.size(), ascii,
      &out_encrypted, &out_len);

  if (status != Rust::GfrStatus::Success || (out_encrypted == nullptr)) {
    LOG_E() << "Rust FFI encryption failed.";
    return GPG_ERR_GENERAL;
  }

  data_object->Swap({
      GpgEncryptResult(),
      GFBuffer(reinterpret_cast<const char*>(out_encrypted), out_len),
  });

  // Free the memory allocated by Rust if necessary
  Rust::gfr_crypto_free_buffer(out_encrypted, out_len);
  return GPG_ERR_NO_ERROR;
}

void GpgBasicOperator::Encrypt(const GpgAbstractKeyPtrList& keys,
                               const GFBuffer& in_buffer, bool ascii,
                               const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (ctx_.BackendType() == PGPBackendType::kRPGP) {
          return EncryptRpgpImpl(ctx_, keys, in_buffer, ascii, data_object);
        }
        return EncryptImpl(ctx_, keys, in_buffer, ascii, data_object);
      },
      cb, "gpgme_op_encrypt", "2.2.0");
}

auto GpgBasicOperator::EncryptSync(const GpgAbstractKeyPtrList& keys,
                                   const GFBuffer& in_buffer, bool ascii)
    -> std::tuple<GpgError, DataObjectPtr> {
  return RunGpgOperaSync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (ctx_.BackendType() == PGPBackendType::kRPGP) {
          return EncryptRpgpImpl(ctx_, keys, in_buffer, ascii, data_object);
        }
        return EncryptImpl(ctx_, keys, in_buffer, ascii, data_object);
      },
      "gpgme_op_encrypt", "2.2.0");
}

void GpgBasicOperator::EncryptSymmetric(const GFBuffer& in_buffer, bool ascii,
                                        const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) {
        return EncryptImpl(ctx_, {}, in_buffer, ascii, data_object);
      },
      cb, "gpgme_op_encrypt_symmetric", "2.2.0");
}

auto GpgBasicOperator::EncryptSymmetricSync(const GFBuffer& in_buffer,
                                            bool ascii)
    -> std::tuple<GpgError, DataObjectPtr> {
  return RunGpgOperaSync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) {
        return EncryptImpl(ctx_, {}, in_buffer, ascii, data_object);
      },
      "gpgme_op_encrypt_symmetric", "2.2.0");
}

auto DecryptImpl(GpgContext& ctx_, const GFBuffer& in_buffer,
                 const DataObjectPtr& data_object) -> GpgError {
  GpgData data_in(in_buffer);
  GpgData data_out;

  auto err =
      CheckGpgError(gpgme_op_decrypt(ctx_.DefaultContext(), data_in, data_out));
  data_object->Swap({
      GpgDecryptResult(gpgme_op_decrypt_result(ctx_.DefaultContext())),
      data_out.Read2GFBuffer(),
  });

  return err;
}

auto DecryptRpgpImpl(GpgContext& ctx_, const GFBuffer& in_buffer,
                     const DataObjectPtr& data_object) -> GpgError {
  char* out_recipients = nullptr;
  auto err = Rust::gfr_crypto_get_recipients(
      reinterpret_cast<const uint8_t*>(in_buffer.Data()), in_buffer.Size(),
      &out_recipients);

  if (err != Rust::GfrStatus::Success || out_recipients == nullptr) {
    LOG_E() << "Rust FFI get_recipients failed.";
    return GPG_ERR_GENERAL;
  }

  auto recipients_str = QString::fromUtf8(out_recipients);
  Rust::gfr_crypto_free_string(out_recipients);

  QStringList recipient_ids = recipients_str.split(",", Qt::SkipEmptyParts);

  LOG_D() << "Recipients extracted from RPGP message: " << recipient_ids;

  auto key_db = ctx_.KeyDatabase();
  if (!key_db) {
    LOG_E() << "Failed to get key database from context";
    return GPG_ERR_GENERAL;
  }

  // Variables to store our target key for decryption
  QString target_secret_key_block;
  QString target_primary_fpr;
  bool found_usable_secret = false;

  // 2. Iterate through all sniffed recipient IDs to find a USABLE secret key
  for (const auto& key_id : recipient_ids) {
    // Fetch the full metadata tree (Primary + Subkeys)
    auto meta_opt = key_db->GetKeyMetadata(key_id);
    if (!meta_opt) continue;

    // Check if the recipient ID matches the primary key itself
    // (Rare for encryption, but possible with older RSA keys)
    if (meta_opt->key_id.toUpper() == key_id.toUpper() ||
        meta_opt->fpr.toUpper() == key_id.toUpper()) {
      if (meta_opt->has_secret) {
        found_usable_secret = true;
      }
    } else {
      // Check if the recipient ID matches a subkey, and IF THAT SUBKEY HAS A
      // SECRET
      for (const auto& subkey : meta_opt->subkeys) {
        if (subkey.key_id.toUpper() == key_id.toUpper() ||
            subkey.fpr.toUpper() == key_id.toUpper()) {
          if (subkey.has_secret) {
            found_usable_secret = true;
          } else {
            LOG_W() << "Subkey " << key_id
                    << " matched, but its secret is stripped/offline.";
          }
          break;  // Stop searching subkeys for this specific recipient_id
        }
      }
    }

    // If we found a usable secret key, fetch the actual key block and stop
    // searching
    if (found_usable_secret) {
      auto blocks = key_db->GetKeyBlocks(meta_opt->fpr);
      if (blocks && !blocks->secret_key.isEmpty()) {
        target_secret_key_block = blocks->secret_key;
        target_primary_fpr = meta_opt->fpr;
        break;
      }
      // Fallback in case DB is inconsistent
      found_usable_secret = false;
    }
  }

  // 3. Handle the result of our search
  if (!found_usable_secret) {
    LOG_E() << "No USABLE secret key found in local database to decrypt this "
               "message. "
            << "Keys might be offline or on a smartcard.";
    return GPG_ERR_NO_SECKEY;
  }

  Rust::GfrDecryptResultC decrypt_result;
  auto secret_key_utf8 = target_secret_key_block.toUtf8();

  err = Rust::gfr_crypto_decrypt_data(
      reinterpret_cast<const uint8_t*>(in_buffer.Data()), in_buffer.Size(),
      secret_key_utf8.constData(), "123456", &decrypt_result);

  if (err != Rust::GfrStatus::Success || decrypt_result.data == nullptr) {
    LOG_E() << "Rust FFI decryption failed.";
    return GPG_ERR_GENERAL;
  }

  GFDecryptResult result;
  result.data = GFBuffer(reinterpret_cast<const char*>(decrypt_result.data),
                         decrypt_result.data_len);
  result.filename = QString::fromUtf8(decrypt_result.filename);
  for (size_t i = 0; i < decrypt_result.recipient_count; ++i) {
    const auto& rec = decrypt_result.recipients[i];
    GFRecipientStatus status = GFRecipientStatus::kERROR;
    if (rec.status == Rust::GfrRecipientStatus::Success) {
      status = GFRecipientStatus::kSUCCESS;
    } else if (rec.status == Rust::GfrRecipientStatus::NoKey) {
      status = GFRecipientStatus::kNO_KEY;
    } else {
      status = GFRecipientStatus::kERROR;
    }
    result.recipients.push_back({
        QString::fromUtf8(rec.key_id).toUpper(),
        QString::fromUtf8(rec.pub_algo),
        status,
    });
  }

  Rust::gfr_crypto_free_decrypt_result(&decrypt_result);

  data_object->Swap({
      GpgDecryptResult(result),
      result.data,
  });

  return GPG_ERR_NO_ERROR;
}

void GpgBasicOperator::Decrypt(const GFBuffer& in_buffer,
                               const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (ctx_.BackendType() == PGPBackendType::kRPGP) {
          return DecryptRpgpImpl(ctx_, in_buffer, data_object);
        }
        return DecryptImpl(ctx_, in_buffer, data_object);
      },
      cb, "gpgme_op_decrypt", "2.2.0");
}

auto GpgBasicOperator::DecryptSync(const GFBuffer& in_buffer)
    -> std::tuple<GpgError, DataObjectPtr> {
  return RunGpgOperaSync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (ctx_.BackendType() == PGPBackendType::kRPGP) {
          return DecryptRpgpImpl(ctx_, in_buffer, data_object);
        }
        return DecryptImpl(ctx_, in_buffer, data_object);
      },
      "gpgme_op_decrypt", "2.2.0");
}

auto VerifyImpl(GpgContext& ctx_, const GFBuffer& in_buffer,
                const GFBuffer& sig_buffer, const DataObjectPtr& data_object)
    -> GpgError {
  GpgError err;

  GpgData data_in(in_buffer);
  GpgData data_out;

  if (!sig_buffer.Empty()) {
    GpgData sig_data(sig_buffer);
    err = CheckGpgError(
        gpgme_op_verify(ctx_.DefaultContext(), sig_data, data_in, nullptr));
  } else {
    err = CheckGpgError(
        gpgme_op_verify(ctx_.DefaultContext(), data_in, nullptr, data_out));
  }

  data_object->Swap({
      GpgVerifyResult(gpgme_op_verify_result(ctx_.DefaultContext())),
      GFBuffer(),
  });

  return err;
}

auto VerifyRpgpImpl(GpgContext& ctx_, const GFBuffer& in_buffer,
                    const GFBuffer& sig_buffer,
                    const DataObjectPtr& data_object) -> GpgError {
  char* out_issuers = nullptr;
  auto err = Rust::gfr_crypto_get_signature_issuers(
      reinterpret_cast<const uint8_t*>(in_buffer.Data()), in_buffer.Size(),
      &out_issuers);

  if (err != Rust::GfrStatus::Success || out_issuers == nullptr) {
    LOG_E() << "Rust FFI get_signature_issuers failed.";
    return GPG_ERR_GENERAL;
  }

  auto issuers_str = QString::fromUtf8(out_issuers);
  Rust::gfr_crypto_free_string(out_issuers);

  LOG_D() << "Signature issuers extracted from RPGP message: " << issuers_str;

  auto issuer_ids = issuers_str.split(",", Qt::SkipEmptyParts);
  auto key_db = ctx_.KeyDatabase();
  if (!key_db) {
    LOG_E() << "Failed to get key database from context";
    return GPG_ERR_GENERAL;
  }

  QContainer<QByteArray> verified_keys_utf8;
  for (const auto& issuer_id : issuer_ids) {
    auto key = key_db->GetKeyBlocks(issuer_id);
    if (key && !key->public_key.isEmpty()) {
      verified_keys_utf8.push_back(key->public_key.toUtf8());
    }
  }

  QContainer<const char*> c_verified_keys;
  for (const auto& key : verified_keys_utf8) {
    c_verified_keys.push_back(key.constData());
  }

  Rust::GfrVerifyResultC verify_result;

  auto status = Rust::gfr_crypto_verify_data(
      reinterpret_cast<const uint8_t*>(in_buffer.Data()), in_buffer.Size(),
      reinterpret_cast<const uint8_t*>(sig_buffer.Data()), sig_buffer.Size(),
      c_verified_keys.data(), c_verified_keys.size(),
      sig_buffer.Empty() ? Rust::GfrSignMode::ClearText
                         : Rust::GfrSignMode::Detached,
      &verify_result);

  if (status != Rust::GfrStatus::Success) {
    LOG_E() << "Rust FFI verification failed with status: "
            << static_cast<int>(status);
    return GPG_ERR_GENERAL;
  }

  GFVerifyResult result;
  result.is_verified = verify_result.is_verified;
  for (size_t i = 0; i < verify_result.signature_count; ++i) {
    const auto& sig = verify_result.signatures[i];

    auto sig_status = GFSignatureStatus::kUNKNOWN_ERROR;
    switch (sig.status) {
      case Rust::GfrSignatureStatus::Valid:
        sig_status = GFSignatureStatus::kVALID;
        break;
      case Rust::GfrSignatureStatus::BadSignature:
        sig_status = GFSignatureStatus::kBAD_SIGNATURE;
        break;
      case Rust::GfrSignatureStatus::NoKey:
        sig_status = GFSignatureStatus::kNO_KEY;
        break;
      case Rust::GfrSignatureStatus::UnknownError:
      default:
        sig_status = GFSignatureStatus::kUNKNOWN_ERROR;
        break;
    }

    LOG_D() << "Signature from issuer "
            << QString::fromUtf8(sig.issuer_fpr).toUpper()
            << " has status: " << static_cast<int>(sig_status)
            << ", pub_algo: " << sig.pub_algo
            << ", hash_algo: " << sig.hash_algo;

    result.signatures.push_back({
        QString::fromUtf8(sig.issuer_fpr).toUpper(),
        sig_status,
        sig.created_at,
        sig.pub_algo,
        sig.hash_algo,
    });
  }

  Rust::gfr_crypto_free_verify_result(&verify_result);

  LOG_D() << "Verification result: "
          << (result.is_verified ? "VALID" : "INVALID")
          << ", Signatures found: " << result.signatures.size();

  data_object->Swap({
      GpgVerifyResult(result),
      GFBuffer(),
  });
  return GPG_ERR_NO_ERROR;
}

void GpgBasicOperator::Verify(const GFBuffer& in_buffer,
                              const GFBuffer& sig_buffer,
                              const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (ctx_.BackendType() == PGPBackendType::kRPGP) {
          return VerifyRpgpImpl(ctx_, in_buffer, sig_buffer, data_object);
        }
        return VerifyImpl(ctx_, in_buffer, sig_buffer, data_object);
      },
      cb, "gpgme_op_verify", "2.2.0");
}

auto GpgBasicOperator::VerifySync(const GFBuffer& in_buffer,
                                  const GFBuffer& sig_buffer)
    -> std::tuple<GpgError, DataObjectPtr> {
  return RunGpgOperaSync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (ctx_.BackendType() == PGPBackendType::kRPGP) {
          return VerifyRpgpImpl(ctx_, in_buffer, sig_buffer, data_object);
        }
        return VerifyImpl(ctx_, in_buffer, sig_buffer, data_object);
      },
      "gpgme_op_verify", "2.2.0");
}

auto SignImpl(GpgContext& ctx_, const GpgAbstractKeyPtrList& signers,
              const GFBuffer& in_buffer, GpgSignMode mode, bool ascii,
              const DataObjectPtr& data_object) -> GpgError {
  if (signers.empty()) return GPG_ERR_CANCELED;

  GpgError err;

  // Set Singers of this opera
  SetSignersImpl(ctx_, signers, ascii);

  GpgData data_in(in_buffer);
  GpgData data_out;

  auto* ctx = ascii ? ctx_.DefaultContext() : ctx_.BinaryContext();
  err = CheckGpgError(gpgme_op_sign(ctx, data_in, data_out, mode));

  data_object->Swap({
      GpgSignResult(gpgme_op_sign_result(ctx)),
      data_out.Read2GFBuffer(),
  });
  return err;
}

auto SignRpgpImpl(GpgContext& ctx, const GpgAbstractKeyPtrList& signers,
                  const GFBuffer& in_buffer, GpgSignMode mode, bool ascii,
                  const DataObjectPtr& data_object) -> GpgError {
  if (signers.isEmpty()) {
    return GPG_ERR_INV_ARG;
  }

  auto key_db = ctx.KeyDatabase();
  if (!key_db) return GPG_ERR_GENERAL;

  std::vector<QByteArray> skey_utf8_list;
  std::vector<QByteArray> pwd_utf8_list;
  std::vector<const char*> c_skeys;
  std::vector<const char*> c_pwds;

  // Fetch key blocks and safely store memory
  for (const auto& signer : signers) {
    auto blocks = key_db->GetKeyBlocks(signer->Fingerprint());
    if (!blocks || blocks->secret_key.isEmpty()) {
      LOG_E() << "Failed to find secret key block for FPR: "
              << signer->Fingerprint();
      return GPG_ERR_NO_SECKEY;
    }

    skey_utf8_list.push_back(blocks->secret_key.toUtf8());
    // Placeholder password, replace with actual if needed
    pwd_utf8_list.emplace_back("123456");
  }

  // Extract C-string pointers
  for (size_t i = 0; i < skey_utf8_list.size(); ++i) {
    c_skeys.push_back(skey_utf8_list[i].constData());
    c_pwds.push_back(pwd_utf8_list[i].constData());
  }

  QByteArray name_utf8;
  Rust::GfrSignMode rs_mode;

  if (mode == GPGME_SIG_MODE_DETACH) {
    rs_mode = Rust::GfrSignMode::Detached;
  } else if (mode == GPGME_SIG_MODE_CLEAR) {
    rs_mode = Rust::GfrSignMode::ClearText;
  } else {
    rs_mode = Rust::GfrSignMode::Inline;
  }

  Rust::GfrSignResultC sign_result;

  auto status = Rust::gfr_crypto_sign_data(
      name_utf8.constData(), reinterpret_cast<const uint8_t*>(in_buffer.Data()),
      in_buffer.Size(), c_skeys.data(), c_pwds.data(), c_skeys.size(), rs_mode,
      ascii, &sign_result);

  if (status != Rust::GfrStatus::Success || sign_result.data == nullptr) {
    LOG_E() << "Rust FFI multi-signature failed with status: "
            << static_cast<int>(status);
    return GPG_ERR_GENERAL;
  }

  GFSignResult result;
  result.signatures.reserve(sign_result.signature_count);
  for (size_t i = 0; i < sign_result.signature_count; ++i) {
    const auto& sig = sign_result.signatures[i];
    GFSignatureStatus sig_status;

    switch (sig.status) {
      case Rust::GfrSignatureStatus::Valid:
        sig_status = GFSignatureStatus::kVALID;
        break;
      case Rust::GfrSignatureStatus::BadSignature:
        sig_status = GFSignatureStatus::kBAD_SIGNATURE;
        break;
      case Rust::GfrSignatureStatus::NoKey:
        sig_status = GFSignatureStatus::kNO_KEY;
        break;
      default:
        sig_status = GFSignatureStatus::kUNKNOWN_ERROR;
        break;
    }

    LOG_D() << "Created signature for issuer "
            << QString::fromUtf8(sig.issuer_fpr).toUpper()
            << " with status: " << static_cast<int>(sig_status)
            << ", pub_algo: " << sig.pub_algo
            << ", hash_algo: " << sig.hash_algo;

    result.signatures.push_back({
        QString::fromUtf8(sig.issuer_fpr).toUpper(),
        sig_status,
        sig.created_at,
        sig.pub_algo,
        sig.hash_algo,
    });
  }

  result.data = GFBuffer(reinterpret_cast<const char*>(sign_result.data),
                         sign_result.data_len);

  Rust::gfr_crypto_free_sign_result(&sign_result);
  data_object->Swap({
      GpgSignResult(result),
      result.data,
  });

  return GPG_ERR_NO_ERROR;
}

void GpgBasicOperator::Sign(const GpgAbstractKeyPtrList& signers,
                            const GFBuffer& in_buffer, GpgSignMode mode,
                            bool ascii, const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (ctx_.BackendType() == PGPBackendType::kRPGP) {
          return SignRpgpImpl(ctx_, signers, in_buffer, mode, ascii,
                              data_object);
        }
        return SignImpl(ctx_, signers, in_buffer, mode, ascii, data_object);
      },
      cb, "gpgme_op_sign", "2.2.0");
}

auto GpgBasicOperator::SignSync(const GpgAbstractKeyPtrList& signers,
                                const GFBuffer& in_buffer, GpgSignMode mode,
                                bool ascii)
    -> std::tuple<GpgError, DataObjectPtr> {
  return RunGpgOperaSync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (ctx_.BackendType() == PGPBackendType::kRPGP) {
          return SignRpgpImpl(ctx_, signers, in_buffer, mode, ascii,
                              data_object);
        }
        return SignImpl(ctx_, signers, in_buffer, mode, ascii, data_object);
      },
      "gpgme_op_sign", "2.2.0");
}

auto DecryptVerifyImpl(GpgContext& ctx_, const GFBuffer& in_buffer,
                       const DataObjectPtr& data_object) -> GpgError {
  GpgError err;

  GpgData data_in(in_buffer);
  GpgData data_out;

  err = CheckGpgError(
      gpgme_op_decrypt_verify(ctx_.DefaultContext(), data_in, data_out));

  data_object->Swap({
      GpgDecryptResult(gpgme_op_decrypt_result(ctx_.DefaultContext())),
      GpgVerifyResult(gpgme_op_verify_result(ctx_.DefaultContext())),
      data_out.Read2GFBuffer(),
  });

  return err;
}

void GpgBasicOperator::DecryptVerify(const GFBuffer& in_buffer,
                                     const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) {
        return DecryptVerifyImpl(ctx_, in_buffer, data_object);
      },
      cb, "gpgme_op_decrypt_verify", "2.2.0");
}

auto GpgBasicOperator::DecryptVerifySync(const GFBuffer& in_buffer)
    -> std::tuple<GpgError, DataObjectPtr> {
  return RunGpgOperaSync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        return DecryptVerifyImpl(ctx_, in_buffer, data_object);
      },
      "gpgme_op_decrypt_verify", "2.2.0");
}

auto EncryptSignImpl(GpgContext& ctx_, const GpgAbstractKeyPtrList& keys,
                     const GpgAbstractKeyPtrList& signers,
                     const GFBuffer& in_buffer, bool ascii,
                     const DataObjectPtr& data_object) -> GpgError {
  if (keys.empty() || signers.empty()) return GPG_ERR_CANCELED;

  GpgError err;
  auto recipients = Convert2RawGpgMEKeyList(ctx_.GetChannel(), keys);

  // Last entry data_in array has to be nullptr
  recipients.push_back(nullptr);

  SetSignersImpl(ctx_, signers, ascii);

  GpgData data_in(in_buffer);
  GpgData data_out;

  auto* ctx = ascii ? ctx_.DefaultContext() : ctx_.BinaryContext();
  err = CheckGpgError(gpgme_op_encrypt_sign(
      ctx, recipients.data(), GPGME_ENCRYPT_ALWAYS_TRUST, data_in, data_out));

  data_object->Swap({
      GpgEncryptResult(gpgme_op_encrypt_result(ctx)),
      GpgSignResult(gpgme_op_sign_result(ctx)),
      data_out.Read2GFBuffer(),
  });
  return err;
}

void GpgBasicOperator::EncryptSign(const GpgAbstractKeyPtrList& keys,
                                   const GpgAbstractKeyPtrList& signers,
                                   const GFBuffer& in_buffer, bool ascii,
                                   const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        return EncryptSignImpl(ctx_, keys, signers, in_buffer, ascii,
                               data_object);
      },
      cb, "gpgme_op_encrypt_sign", "2.2.0");
}

auto GpgBasicOperator::EncryptSignSync(const GpgAbstractKeyPtrList& keys,
                                       const GpgAbstractKeyPtrList& signers,
                                       const GFBuffer& in_buffer, bool ascii)
    -> std::tuple<GpgError, DataObjectPtr> {
  return RunGpgOperaSync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        return EncryptSignImpl(ctx_, keys, signers, in_buffer, ascii,
                               data_object);
      },
      "gpgme_op_encrypt_sign", "2.2.0");
}

void GpgBasicOperator::SetSigners(const GpgAbstractKeyPtrList& signers,
                                  bool ascii) {
  SetSignersImpl(ctx_, signers, ascii);
}

auto GpgBasicOperator::GetSigners(bool ascii) -> KeyArgsList {
  auto* ctx = ascii ? ctx_.DefaultContext() : ctx_.BinaryContext();

  auto count = gpgme_signers_count(ctx);
  auto signers = KeyArgsList{};
  for (auto i = 0U; i < count; i++) {
    auto key = GpgKey(gpgme_signers_enum(ctx, i));
    signers.push_back(GpgKey(key));
  }
  return signers;
}
}  // namespace GpgFrontend
