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

#include "BasicCryptoOpera.h"

#include "core/GpgCoreRust.h"
#include "core/function/GFKeyDatabase.h"
#include "core/function/rpgp/RustEngineCallback.h"
#include "core/model/GpgDecryptResult.h"
#include "core/model/GpgEncryptResult.h"
#include "core/model/GpgSignResult.h"
#include "core/model/GpgVerifyResult.h"
#include "core/utils/RustUtils.h"

namespace GpgFrontend {

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
  Rust::GfrEncryptResultC encrypt_result;

  // Call Rust FFI. Ensure in_buffer is a null-terminated C-string if Rust
  // expects it.
  auto status = Rust::gfr_crypto_encrypt_data(
      name.c_str(), reinterpret_cast<const uint8_t*>(in_buffer.Data()),
      in_buffer.Size(), recipient_cstrs.data(), recipient_cstrs.size(), ascii,
      &encrypt_result);

  if (status != Rust::GfrStatus::Success) {
    LOG_E() << "Rust FFI encryption failed.";
    return GPG_ERR_GENERAL;
  }

  GFEncryptResult result = GfrEncryptResultC2GFEncryptResult(encrypt_result);
  Rust::gfr_crypto_free_encrypt_result(&encrypt_result);

  data_object->Swap({GpgEncryptResult(result), result.data});

  // Free the memory allocated by Rust if necessary
  Rust::gfr_crypto_free_buffer(encrypt_result.data, encrypt_result.data_len);
  return GPG_ERR_NO_ERROR;
}

auto DecryptRpgpImpl(GpgContext& ctx_, const GFBuffer& in_buffer,
                     const DataObjectPtr& data_object) -> GpgError {
  auto key_db = ctx_.KeyDatabase();
  if (!key_db) {
    LOG_E() << "Failed to get key database from context";
    return GPG_ERR_GENERAL;
  }

  QStringList recipient_ids = SniffRecipientKeyIds(in_buffer);
  LOG_D() << "Recipients extracted from RPGP message: " << recipient_ids;

  // Variables to store our target key for decryption
  QString target_secret_key_block =
      GetKeyBlockFromKeyIdsForDecryption(*key_db, recipient_ids);
  if (target_secret_key_block.isEmpty()) {
    LOG_E() << "No USABLE secret key found in local database to decrypt: "
            << recipient_ids;
    return GPG_ERR_NO_SECKEY;
  }

  Rust::GfrDecryptResultC decrypt_result;
  auto secret_key_utf8 = target_secret_key_block.toUtf8();

  auto err = Rust::gfr_crypto_decrypt_data(
      ctx_.GetChannel(), reinterpret_cast<const uint8_t*>(in_buffer.Data()),
      in_buffer.Size(), secret_key_utf8.constData(), FetchPasswordCallback,
      FreeCallback, &decrypt_result);

  if (err != Rust::GfrStatus::Success) {
    LOG_E() << "Rust FFI decryption failed."
            << " Status: " << static_cast<int>(err);
    return GPG_ERR_GENERAL;
  }

  GFDecryptResult result = GfrDecryptResultC2GFDecryptResult(decrypt_result);
  Rust::gfr_crypto_free_decrypt_result(&decrypt_result);

  data_object->Swap({
      GpgDecryptResult(result),
      result.data,
  });

  return GPG_ERR_NO_ERROR;
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
      ctx.GetChannel(), name_utf8.constData(),
      reinterpret_cast<const uint8_t*>(in_buffer.Data()), in_buffer.Size(),
      c_skeys.data(), c_skeys.size(), FetchPasswordCallback, FreeCallback,
      rs_mode, ascii, &sign_result);

  if (status != Rust::GfrStatus::Success || sign_result.data == nullptr) {
    LOG_E() << "Rust FFI multi-signature failed with status: "
            << static_cast<int>(status);
    return GPG_ERR_GENERAL;
  }

  GFSignResult result = GfrSignResultC2GFSignResult(sign_result);
  Rust::gfr_crypto_free_sign_result(&sign_result);

  data_object->Swap({
      GpgSignResult(result),
      result.data,
  });

  return GPG_ERR_NO_ERROR;
}

auto EncryptSignRpgpImpl(GpgContext& ctx, const GpgAbstractKeyPtrList& keys,
                         const GpgAbstractKeyPtrList& signers,
                         const GFBuffer& in_buffer, bool ascii,
                         const DataObjectPtr& data_object) -> GpgError {
  auto key_db = ctx.KeyDatabase();
  if (!key_db) {
    LOG_E() << "Failed to get key database from context";
    return GPG_ERR_GENERAL;
  }

  if (signers.isEmpty() || keys.isEmpty()) return GPG_ERR_INV_ARG;

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

  std::vector<QByteArray> skey_utf8_list;
  std::vector<const char*> c_skeys;

  // Fetch key blocks and safely store memory
  for (const auto& signer : signers) {
    auto blocks = key_db->GetKeyBlocks(signer->Fingerprint());
    if (!blocks || blocks->secret_key.isEmpty()) {
      LOG_E() << "Failed to find secret key block for FPR: "
              << signer->Fingerprint();
      return GPG_ERR_NO_SECKEY;
    }

    skey_utf8_list.push_back(blocks->secret_key.toUtf8());
  }

  // Extract C-string pointers
  c_skeys.reserve(skey_utf8_list.size());
  for (const auto& i : skey_utf8_list) {
    c_skeys.push_back(i.constData());
  }

  QString name;
  Rust::GfrEncryptAndSignResultC encrypt_sign_result;

  auto err = Rust::gfr_crypto_encrypt_and_sign_data(
      ctx.GetChannel(), name.toUtf8().constData(),
      reinterpret_cast<const uint8_t*>(in_buffer.Data()), in_buffer.Size(),
      recipient_cstrs.data(), recipient_cstrs.size(), c_skeys.data(),
      c_skeys.size(), FetchPasswordCallback, FreeCallback, ascii,
      &encrypt_sign_result);

  if (err != Rust::GfrStatus::Success) {
    LOG_E() << "Rust FFI encrypt_and_sign failed with status: "
            << static_cast<int>(err);
    return GPG_ERR_GENERAL;
  }

  GFEncryptAndSignResult result =
      GfrEncryptAndSignResultC2GFEncryptAndSignResult(encrypt_sign_result);
  Rust::gfr_crypto_free_encrypt_and_sign_result(&encrypt_sign_result);

  data_object->Swap({
      GpgEncryptResult(result.encrypt_result),
      GpgSignResult(result.sign_result),
      result.data,
  });

  return GPG_ERR_NO_ERROR;
}

auto DecryptVerifyRpgpImpl(GpgContext& ctx_, const GFBuffer& in_buffer,
                           const DataObjectPtr& data_object) -> GpgError {
  auto key_db = ctx_.KeyDatabase();
  if (!key_db) {
    LOG_E() << "Failed to get key database from context";
    return GPG_ERR_GENERAL;
  }

  QStringList recipient_ids = SniffRecipientKeyIds(in_buffer);
  LOG_D() << "Recipients extracted from RPGP message: " << recipient_ids;

  // Variables to store our target key for decryption
  QString target_secret_key_block =
      GetKeyBlockFromKeyIdsForDecryption(*key_db, recipient_ids);
  if (target_secret_key_block.isEmpty()) {
    LOG_E() << "No USABLE secret key found in local database to decrypt: "
            << recipient_ids;
    return GPG_ERR_NO_SECKEY;
  }

  Rust::GfrDecryptAndVerifyResultC decrypt_verify_result;

  auto err = Rust::gfr_crypto_decrypt_and_verify_data(
      ctx_.GetChannel(), reinterpret_cast<const uint8_t*>(in_buffer.Data()),
      in_buffer.Size(), target_secret_key_block.toUtf8().constData(),
      FetchPasswordCallback, FetchPublicKeyCallback, FreeCallback,
      key_db.data(), &decrypt_verify_result);

  if (err != Rust::GfrStatus::Success) {
    LOG_E() << "Rust FFI decrypt-and-verify failed with status: "
            << static_cast<int>(err);
    return GPG_ERR_GENERAL;
  }

  GFDecryptAndVerifyResult result =
      GfrDecryptAndVerifyResultC2GFDecryptAndVerifyResult(
          decrypt_verify_result);
  Rust::gfr_crypto_free_decrypt_and_verify_result(&decrypt_verify_result);

  data_object->Swap({
      GpgDecryptResult(result.decrypt_result),
      GpgVerifyResult(result.verify_result),
      result.data,
  });

  return GPG_ERR_NO_ERROR;
}

}  // namespace GpgFrontend