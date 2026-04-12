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

#include "KeyGenerate.h"

#include "core/GpgCoreRust.h"
#include "core/function/rpgp/RustEngineCallback.h"
#include "core/model/GpgGenerateKeyResult.h"
#include "core/utils/RustUtils.h"

namespace GpgFrontend {
auto GenerateKeyWithSubkeyRpgpImpl(
    GpgKeyImportExporter& kie, const QSharedPointer<KeyGenerateInfo>& p_params,
    const QSharedPointer<KeyGenerateInfo>& s_params,
    const DataObjectPtr& data_object) -> GpgError {
  Rust::GfrKeyConfig key_config;
  key_config.algo = KeyAlgoId2GfrKeyAlgo(p_params->GetAlgo().Id());
  key_config.can_sign = p_params->IsAllowSign();
  key_config.can_encrypt = p_params->IsAllowEncr();
  key_config.can_auth = p_params->IsAllowAuth();
  key_config.has_passphrase = !p_params->IsNoPassPhrase();

  Rust::GfrStatus err = Rust::GfrStatus::Success;
  Rust::GfrKeyGenerateResult kg_result;

  if (s_params != nullptr) {
    std::array<Rust::GfrKeyConfig, 1> s_key_configs;
    s_key_configs[0].algo = KeyAlgoId2GfrKeyAlgo(s_params->GetAlgo().Id());
    s_key_configs[0].can_sign = s_params->IsAllowSign();
    s_key_configs[0].can_encrypt = s_params->IsAllowEncr();
    s_key_configs[0].can_auth = s_params->IsAllowAuth();
    s_key_configs[0].has_passphrase = !s_params->IsNoPassPhrase();

    err = Rust::gfr_crypto_generate_key(
        p_params->GetUserid().toUtf8().constData(), key_config,
        s_key_configs.data(), s_key_configs.size(), FetchPasswordCallback,
        FreeCallback, &kg_result);
  } else {
    err = Rust::gfr_crypto_generate_key(
        p_params->GetUserid().toUtf8().constData(), key_config, nullptr, 0,
        FetchPasswordCallback, FreeCallback, &kg_result);
  }

  if (err != Rust::GfrStatus::Success) {
    data_object->Swap({GpgGenerateKeyResult{}});
    LOG_D() << "gfr_crypto_create_v6_key error, code: "
            << static_cast<int>(err);
    return GPG_ERR_GENERAL;
  }

  auto armored_s_key = QString::fromUtf8(kg_result.secret_key);
  auto armored_p_key = QString::fromUtf8(kg_result.public_key);

  Rust::gfr_crypto_free_key_generate_result(&kg_result);

  auto import_info = kie.ImportKey(GFBuffer(armored_s_key));

  data_object->Swap({
      GpgGenerateKeyResult{QString::fromUtf8(kg_result.fingerprint)},
      GpgGenerateKeyResult{QString::fromUtf8(kg_result.fingerprint)},
  });
  return GPG_ERR_NO_ERROR;
}

auto GenerateKeyRpgpImpl(GpgKeyImportExporter& key_import_exporter,
                         const QSharedPointer<KeyGenerateInfo>& params,
                         const DataObjectPtr& data_object) -> GpgError {
  return GenerateKeyWithSubkeyRpgpImpl(key_import_exporter, params, nullptr,
                                       data_object);
}

}  // namespace GpgFrontend