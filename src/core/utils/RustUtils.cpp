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

#include "RustUtils.h"

namespace GpgFrontend {

auto KeyAlgoId2GfrKeyAlgo(const QString& algo_id) -> Rust::GfrKeyAlgo {
  LOG_D() << "key algo id: " << algo_id;

  if (algo_id == "ed25519") return Rust::GfrKeyAlgo::ED25519;
  if (algo_id == "cv25519") return Rust::GfrKeyAlgo::CV25519;
  if (algo_id == "nistp256") return Rust::GfrKeyAlgo::NISTP256;
  if (algo_id == "nistp384") return Rust::GfrKeyAlgo::NISTP384;
  if (algo_id == "nistp521") return Rust::GfrKeyAlgo::NISTP521;
  if (algo_id == "rsa2048") return Rust::GfrKeyAlgo::RSA2048;
  if (algo_id == "rsa3072") return Rust::GfrKeyAlgo::RSA3072;
  if (algo_id == "rsa4096") return Rust::GfrKeyAlgo::RSA4096;

  return Rust::GfrKeyAlgo::RSA2048;
}

auto GF_CORE_EXPORT GfrKeyAlgo2KeyAlgoName(Rust::GfrKeyAlgo algo) -> QString {
  switch (algo) {
    case Rust::GfrKeyAlgo::ED25519:
      return "ED25519";
    case Rust::GfrKeyAlgo::CV25519:
      return "CV25519";
    case Rust::GfrKeyAlgo::NISTP256:
      return "NIST P-256";
    case Rust::GfrKeyAlgo::NISTP384:
      return "NIST P-384";
    case Rust::GfrKeyAlgo::NISTP521:
      return "NIST P-521";
    case Rust::GfrKeyAlgo::RSA2048:
      return "RSA 2048";
    case Rust::GfrKeyAlgo::RSA3072:
      return "RSA 3072";
    case Rust::GfrKeyAlgo::RSA4096:
      return "RSA 4096";
    default:
      return "Unknown";
  }
}

namespace {

auto ParseEncryptResultMeta(const Rust::GfrEncryptMetadataC& m)
    -> GFEncryptResult {
  GFEncryptResult result;

  for (size_t i = 0; i < m.invalid_recipient_count; ++i) {
    const auto& inv_rec = m.invalid_recipients[i];

    GpgError reason;
    if (inv_rec.reason == Rust::GfrStatus::ErrorNoKey) {
      reason = GPG_ERR_NO_KEY;
    } else if (inv_rec.reason == Rust::GfrStatus::ErrorInvalidData) {
      reason = GPG_ERR_INV_DATA;
    } else {
      reason = GPG_ERR_GENERAL;
    }

    result.invalid_recipients.push_back({
        QString::fromUtf8(inv_rec.fpr),
        reason,
    });
  }

  return result;
}

auto ParseSignResultMeta(const Rust::GfrSignMetadataC& m) -> GFSignResult {
  GFSignResult result;

  for (size_t i = 0; i < m.signature_count; ++i) {
    const auto& sig = m.signatures[i];

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

    result.signatures.push_back({
        QString::fromUtf8(sig.issuer_fpr).toUpper(),
        sig_status,
        sig.created_at,
        sig.pub_algo,
        sig.hash_algo,
    });
  }

  return result;
}

}  // namespace

auto GfrEncryptResultC2GFEncryptResult(const Rust::GfrEncryptResultC& r)
    -> GFEncryptResult {
  GFEncryptResult result = ParseEncryptResultMeta(r.meta);
  result.data = GFBuffer(reinterpret_cast<const char*>(r.data), r.data_len);
  return result;
}

auto GfrDecryptResultC2GFDecryptResult(const Rust::GfrDecryptResultC& r)
    -> GFDecryptResult {
  GFDecryptResult result;

  result.filename = QString::fromUtf8(r.filename);
  for (size_t i = 0; i < r.recipient_count; ++i) {
    const auto& rec = r.recipients[i];
    GpgError status;
    if (rec.status == Rust::GfrRecipientStatus::Success) {
      status = GPG_ERR_NO_ERROR;
    } else if (rec.status == Rust::GfrRecipientStatus::NoKey) {
      status = GPG_ERR_NO_KEY;
    } else {
      status = GPG_ERR_GENERAL;
    }
    result.recipients.push_back({
        QString::fromUtf8(rec.key_id).toUpper(),
        QString::fromUtf8(rec.pub_algo),
        status,
    });
  }
  result.data = GFBuffer(reinterpret_cast<const char*>(r.data), r.data_len);
  return result;
}

auto GfrSignResultC2GFSignResult(const Rust::GfrSignResultC& r)
    -> GFSignResult {
  GFSignResult result = ParseSignResultMeta(r.meta);
  result.data = GFBuffer(reinterpret_cast<const char*>(r.data), r.data_len);
  return result;
}

auto GfrVerifyResultC2GFVerifyResult(const Rust::GfrVerifyResultC& r)
    -> GFVerifyResult {
  GFVerifyResult result;
  result.is_verified = r.is_verified;
  for (size_t i = 0; i < r.signature_count; ++i) {
    const auto& sig = r.signatures[i];

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

    result.signatures.push_back({
        QString::fromUtf8(sig.issuer_fpr).toUpper(),
        sig_status,
        sig.created_at,
        sig.pub_algo,
        sig.hash_algo,
    });
  }
  return result;
}

auto GfrEncryptAndSignResultC2GFEncryptAndSignResult(
    const Rust::GfrEncryptAndSignResultC& r) -> GFEncryptAndSignResult {
  GFEncryptAndSignResult result;
  result.data = GFBuffer(reinterpret_cast<const char*>(r.data), r.data_len);
  result.sign_result = ParseSignResultMeta(r.sign_meta);
  result.encrypt_result = ParseEncryptResultMeta(r.encrypt_meta);
  return result;
}

}  // namespace GpgFrontend
