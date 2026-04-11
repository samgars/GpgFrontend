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
  std::vector<QByteArray> key_blocks_utf8;

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

  char* out_encrypted = nullptr;

  // Call Rust FFI. Ensure in_buffer is a null-terminated C-string if Rust
  // expects it.
  auto status =
      Rust::gfr_crypto_encrypt_text(in_buffer.Data(), recipient_cstrs.data(),
                                    recipient_cstrs.size(), &out_encrypted);

  if (status != Rust::GfrStatus::Success || (out_encrypted == nullptr)) {
    LOG_E() << "Rust FFI encryption failed.";
    return GPG_ERR_GENERAL;
  }

  data_object->Swap({
      GpgEncryptResult(),
      GFBuffer(out_encrypted, std::strlen(out_encrypted)),
  });

  // Free the memory allocated by Rust if necessary
  Rust::gfr_crypto_free_string(out_encrypted);
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

void GpgBasicOperator::Decrypt(const GFBuffer& in_buffer,
                               const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) {
        return DecryptImpl(ctx_, in_buffer, data_object);
      },
      cb, "gpgme_op_decrypt", "2.2.0");
}

auto GpgBasicOperator::DecryptSync(const GFBuffer& in_buffer)
    -> std::tuple<GpgError, DataObjectPtr> {
  return RunGpgOperaSync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) {
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

void GpgBasicOperator::Verify(const GFBuffer& in_buffer,
                              const GFBuffer& sig_buffer,
                              const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        return VerifyImpl(ctx_, in_buffer, sig_buffer, data_object);
      },
      cb, "gpgme_op_verify", "2.2.0");
}

auto GpgBasicOperator::VerifySync(const GFBuffer& in_buffer,
                                  const GFBuffer& sig_buffer)
    -> std::tuple<GpgError, DataObjectPtr> {
  return RunGpgOperaSync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) {
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

void GpgBasicOperator::Sign(const GpgAbstractKeyPtrList& signers,
                            const GFBuffer& in_buffer, GpgSignMode mode,
                            bool ascii, const GpgOperationCallback& cb) {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) {
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
      [=](const DataObjectPtr& data_object) {
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
