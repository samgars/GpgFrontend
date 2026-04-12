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

#include "KeyImportExport.h"

#include "core/GpgCoreRust.h"
#include "core/function/GFKeyDatabase.h"

namespace GpgFrontend {

auto ImportKeyRpgpImpl(GpgContext& ctx, const GFBuffer& in_buffer)
    -> QSharedPointer<GpgImportInformation> {
  if (in_buffer.Empty()) return {};

  Rust::GfrKeyMetadataC out_metadata;
  auto key_db = ctx.KeyDatabase();

  if (key_db == nullptr) {
    LOG_E() << "key database is not initialized";
    return {};
  }

  auto err = Rust::gfr_crypto_extract_metadata(in_buffer.Data(), &out_metadata);
  if (err != Rust::GfrStatus::Success) {
    LOG_E() << "gfr_crypto_extract_metadata error, code: "
            << static_cast<int>(err);
    return {};
  }

  GFKeyMetadata meta;
  meta.fpr = QString::fromUtf8(out_metadata.fpr);
  meta.key_id = QString::fromUtf8(out_metadata.key_id);
  meta.user_id = QString::fromUtf8(out_metadata.user_id);
  meta.created_at = static_cast<qint64>(out_metadata.created_at);
  meta.has_secret = out_metadata.has_secret;
  meta.algo = static_cast<int>(out_metadata.algo);

  meta.can_sign = out_metadata.can_sign;
  meta.can_encrypt = out_metadata.can_encrypt;
  meta.can_auth = out_metadata.can_auth;
  meta.can_certify = out_metadata.can_certify;

  for (size_t i = 0; i < out_metadata.subkey_count; ++i) {
    const auto& subkey_meta = out_metadata.subkeys[i];
    GFSubKeyMetadata sub_meta;
    sub_meta.fpr = QString::fromUtf8(subkey_meta.fpr);
    sub_meta.key_id = QString::fromUtf8(subkey_meta.key_id);
    sub_meta.created_at = static_cast<qint64>(subkey_meta.created_at);
    sub_meta.has_secret = subkey_meta.has_secret;
    sub_meta.algo = static_cast<int>(subkey_meta.algo);

    sub_meta.can_sign = subkey_meta.can_sign;
    sub_meta.can_encrypt = subkey_meta.can_encrypt;
    sub_meta.can_auth = subkey_meta.can_auth;
    sub_meta.can_certify = subkey_meta.can_certify;

    LOG_D() << "imported subkey metadata, fpr: " << sub_meta.fpr
            << ", key_id: " << sub_meta.key_id
            << ", created_at: " << sub_meta.created_at
            << ", has_secret: " << sub_meta.has_secret
            << ", can_sign: " << sub_meta.can_sign
            << ", can_encrypt: " << sub_meta.can_encrypt
            << ", can_auth: " << sub_meta.can_auth
            << ", can_certify: " << sub_meta.can_certify;

    meta.subkeys.push_back(sub_meta);
  }

  Rust::gfr_crypto_free_metadata(&out_metadata);

  LOG_D() << "imported key metadata, fpr: " << meta.fpr
          << ", key_id: " << meta.key_id << ", user_id: " << meta.user_id
          << ", created_at: " << meta.created_at
          << ", has_secret: " << meta.has_secret
          << ", can_sign: " << meta.can_sign
          << ", can_encrypt: " << meta.can_encrypt
          << ", can_auth: " << meta.can_auth
          << ", can_certify: " << meta.can_certify;

  GFKeyBlocks blocks;
  if (meta.has_secret) {
    blocks.secret_key = in_buffer.ConvertToQString();

    char* public_key = nullptr;
    auto err =
        Rust::gfr_crypto_extract_public_key(in_buffer.Data(), &public_key);

    if (err != Rust::GfrStatus::Success) {
      LOG_E() << "gfr_crypto_extract_public_key error, code: "
              << static_cast<int>(err);
      return {};
    }

    blocks.public_key = QString::fromUtf8(public_key);
    Rust::gfr_crypto_free_string(public_key);

  } else {
    blocks.public_key = in_buffer.ConvertToQString();
  }

  key_db->SaveKey(meta, blocks);

  return {};
}

auto ExportKeysRpgpImpl(GpgContext& ctx, const GpgAbstractKeyPtrList& keys,
                        bool secret) -> std::tuple<GpgError, GFBuffer> {
  auto key_db = ctx.KeyDatabase();

  if (key_db == nullptr) {
    LOG_E() << "key database is not initialized";
    return {};
  }

  QContainer<QByteArray> key_blocks;

  for (const auto& key : keys) {
    auto key_block = key_db->GetKeyBlocks(key->Fingerprint());
    if (!key_block) {
      LOG_E() << "failed to get key block for fpr: " << key->Fingerprint();
      continue;
    }

    if (secret && key_block->secret_key.isEmpty()) {
      LOG_W() << "requested secret key export, but secret key block is empty "
                 "for fpr: "
              << key->Fingerprint();
      continue;
    }

    if (!secret && key_block->public_key.isEmpty()) {
      LOG_W() << "requested public key export, but public key block is empty "
                 "for fpr: "
              << key->Fingerprint();
      continue;
    }

    key_blocks.push_back(
        (secret ? key_block->secret_key : key_block->public_key).toUtf8());
  }

  if (key_blocks.empty()) {
    LOG_E() << "no valid key blocks found for export";
    return {};
  }

  char* out_armored_string = nullptr;

  std::vector<char*> key_block_ptrs;
  for (const auto& block : key_blocks) {
    key_block_ptrs.push_back(const_cast<char*>(block.data()));
  }

  auto err = Rust::gfr_export_merged_public_keys(
      key_block_ptrs.data(), key_block_ptrs.size(), &out_armored_string);
  if (err != Rust::GfrStatus::Success) {
    LOG_E() << "gfr_export_merged_public_keys error, code: "
            << static_cast<int>(err);
    return {GPG_ERR_GENERAL, {}};
  }

  auto qs_armored = QString::fromUtf8(out_armored_string);
  Rust::gfr_crypto_free_string(out_armored_string);

  LOG_D() << "exported armored string: " << qs_armored;

  return {GPG_ERR_NO_ERROR, GFBuffer(qs_armored)};
}

}  // namespace GpgFrontend