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

#include "GpgKeyImportExporter.h"

#include "core/GpgCoreRust.h"
#include "core/function/GFKeyDatabase.h"
#include "core/model/GpgData.h"
#include "core/model/GpgImportInformation.h"
#include "core/utils/AsyncUtils.h"
#include "core/utils/GpgUtils.h"

namespace GpgFrontend {

namespace {

auto ImportKeyImpl(GpgContext& ctx, const GFBuffer& in_buffer)
    -> QSharedPointer<GpgImportInformation> {
  if (in_buffer.Empty()) return {};

  GpgData data_in(in_buffer);
  auto err = CheckGpgError(gpgme_op_import(ctx.BinaryContext(), data_in));
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) return {};

  gpgme_import_result_t result;
  result = gpgme_op_import_result(ctx.BinaryContext());
  gpgme_import_status_t status = result->imports;

  auto import_info = SecureCreateSharedObject<GpgImportInformation>(result);
  while (status != nullptr) {
    GpgImportInformation::GpgImportedKey key;
    key.import_status = static_cast<int>(status->status);
    key.fpr = status->fpr;
    import_info->imported_keys.push_back(key);
    status = status->next;
  }
  return import_info;
}

auto ImportKeyRPGPImpl(GpgContext& ctx, const GFBuffer& in_buffer)
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
}  // namespace

GpgKeyImportExporter::GpgKeyImportExporter(int channel)
    : SingletonFunctionObject<GpgKeyImportExporter>(channel),
      ctx_(GpgContext::GetInstance(SingletonFunctionObject::GetChannel())) {}

/**
 * Import key pair
 * @param inBuffer input byte array
 * @return Import information
 */
auto GpgKeyImportExporter::ImportKey(const GFBuffer& in_buffer)
    -> QSharedPointer<GpgImportInformation> {
  if (ctx_.BackendType() == PGPBackendType::kRPGP) {
    return ImportKeyRPGPImpl(ctx_, in_buffer);
  }

  return ImportKeyImpl(ctx_, in_buffer);
}

/**
 * Export keys
 * @param keys keys used
 * @param outBuffer output byte array
 * @return if success
 */
auto GpgKeyImportExporter::ExportKey(const GpgAbstractKeyPtr& key, bool secret,
                                     bool ascii, bool shortest,
                                     bool ssh_mode) const
    -> std::tuple<GpgError, GFBuffer> {
  if (key == nullptr) return {GPG_ERR_CANCELED, {}};

  int mode = 0;
  if (secret) mode |= GPGME_EXPORT_MODE_SECRET;
  if (shortest) mode |= GPGME_EXPORT_MODE_MINIMAL;
  if (ssh_mode) mode |= GPGME_EXPORT_MODE_SSH;

  QContainer<gpgme_key_t> keys_array =
      Convert2RawGpgMEKeyList(GetChannel(), {key});

  GpgData data_out;
  auto* ctx = ascii ? ctx_.DefaultContext() : ctx_.BinaryContext();
  auto err = gpgme_op_export_keys(ctx, keys_array.data(), mode, data_out);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) return {err, {}};

  return {err, data_out.Read2GFBuffer()};
}

/**
 * Export keys
 * @param keys keys used
 * @param outBuffer output byte array
 * @return if success
 */
void GpgKeyImportExporter::ExportKeys(const GpgAbstractKeyPtrList& keys,
                                      bool secret, bool ascii, bool shortest,
                                      bool ssh_mode,
                                      const GpgOperationCallback& cb) const {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (keys.empty()) return GPG_ERR_CANCELED;

        int mode = 0;
        if (secret) mode |= GPGME_EXPORT_MODE_SECRET;
        if (shortest) mode |= GPGME_EXPORT_MODE_MINIMAL;
        if (ssh_mode) mode |= GPGME_EXPORT_MODE_SSH;

        auto keys_array = Convert2RawGpgMEKeyList(GetChannel(), keys);

        // Last entry data_in array has to be nullptr
        keys_array.push_back(nullptr);

        GpgData data_out;
        auto* ctx = ascii ? ctx_.DefaultContext() : ctx_.BinaryContext();
        auto err = gpgme_op_export_keys(ctx, keys_array.data(), mode, data_out);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) return err;

        data_object->Swap({data_out.Read2GFBuffer()});
        return err;
      },
      cb, "gpgme_op_export_keys", "2.1.0");
}

/**
 * Export keys
 * @param keys keys used
 * @param outBuffer output byte array
 * @return if success
 */
void GpgKeyImportExporter::ExportAllKeys(const GpgAbstractKeyPtrList& keys,
                                         bool secret, bool ascii,
                                         const GpgOperationCallback& cb) const {
  RunGpgOperaAsync(
      GetChannel(),
      [=](const DataObjectPtr& data_object) -> GpgError {
        if (keys.empty()) return GPG_ERR_CANCELED;

        int mode = 0;
        auto keys_array = Convert2RawGpgMEKeyList(GetChannel(), keys);

        // Last entry data_in array has to be nullptr
        keys_array.push_back(nullptr);

        GpgData data_out;
        auto* ctx = ascii ? ctx_.DefaultContext() : ctx_.BinaryContext();
        auto err = gpgme_op_export_keys(ctx, keys_array.data(), mode, data_out);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) return err;

        auto buffer = data_out.Read2GFBuffer();

        if (secret) {
          int mode = 0;
          mode |= GPGME_EXPORT_MODE_SECRET;

          GpgData data_out_secret;
          auto err = gpgme_op_export_keys(ctx, keys_array.data(), mode,
                                          data_out_secret);
          if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) return err;

          buffer.Append(data_out_secret.Read2GFBuffer());
        }

        data_object->Swap({buffer});
        return err;
      },
      cb, "gpgme_op_export_keys", "2.1.0");
}

auto GpgKeyImportExporter::ExportSubkey(const QString& fpr, bool ascii) const
    -> std::tuple<GpgError, GFBuffer> {
  int mode = 0;
  mode |= GPGME_EXPORT_MODE_SECRET_SUBKEY;

  auto pattern = fpr;
  if (!fpr.endsWith("!")) pattern += "!";

  GpgData data_out;
  auto* ctx = ascii ? ctx_.DefaultContext() : ctx_.BinaryContext();
  auto err =
      gpgme_op_export(ctx, pattern.toLatin1().constData(), mode, data_out);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) return {err, {}};

  return {err, data_out.Read2GFBuffer()};
}
}  // namespace GpgFrontend
