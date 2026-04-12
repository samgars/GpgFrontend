/*
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

use crate::{
    types::{GfrFreeCb, GfrKeyAlgo, GfrKeyConfig, GfrPasswordFetchCb, GfrStatus},
    utils::fetch_password_internal,
};
use log::{debug, error};
use pgp::{
    composed::{
        ArmorOptions, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
        SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::ecc_curve::ECCCurve,
    types::{KeyDetails, Password},
};
use rand::thread_rng;

pub struct GeneratedKeys {
    pub secret: String,
    pub public: String,
    pub fingerprint: String,
}

pub fn resolve_key_type(algo: &GfrKeyAlgo, can_encrypt: bool) -> Result<KeyType, GfrStatus> {
    match algo {
        GfrKeyAlgo::ED25519 | GfrKeyAlgo::CV25519 => {
            if can_encrypt {
                Ok(KeyType::ECDH(ECCCurve::Curve25519))
            } else {
                Ok(KeyType::Ed25519)
            }
        }

        GfrKeyAlgo::NISTP256 => {
            if can_encrypt {
                Ok(KeyType::ECDH(ECCCurve::P256))
            } else {
                Ok(KeyType::ECDSA(ECCCurve::P256))
            }
        }
        GfrKeyAlgo::NISTP384 => {
            if can_encrypt {
                Ok(KeyType::ECDH(ECCCurve::P384))
            } else {
                Ok(KeyType::ECDSA(ECCCurve::P384))
            }
        }
        GfrKeyAlgo::NISTP521 => {
            if can_encrypt {
                Ok(KeyType::ECDH(ECCCurve::P521))
            } else {
                Ok(KeyType::ECDSA(ECCCurve::P521))
            }
        }

        GfrKeyAlgo::RSA2048 => Ok(KeyType::Rsa(2048)),
        GfrKeyAlgo::RSA3072 => Ok(KeyType::Rsa(3072)),
        GfrKeyAlgo::RSA4096 => Ok(KeyType::Rsa(4096)),

        GfrKeyAlgo::Unknown => Err(GfrStatus::ErrorInvalidInput),
    }
}

pub fn keygen_dynamic(
    uid: &str,
    key_config: &GfrKeyConfig,
    s_key_configs: &[GfrKeyConfig],
) -> anyhow::Result<SignedSecretKey> {
    let primary_type = resolve_key_type(&key_config.algo, false)?;
    let mut subkeys = Vec::new();

    for config in s_key_configs {
        debug!(
            "Configuring subkey with algo: {:?}, can_sign: {}, can_encrypt: {}, can_auth: {}",
            config.algo, config.can_sign, config.can_encrypt, config.can_auth
        );

        let k_type = resolve_key_type(&config.algo, config.can_encrypt)?;
        let mut builder = SubkeyParamsBuilder::default();
        builder
            .key_type(k_type)
            .can_sign(config.can_sign)
            .can_authenticate(config.can_auth)
            .can_encrypt(if config.can_encrypt {
                EncryptionCaps::All
            } else {
                EncryptionCaps::None
            });

        subkeys.push(
            builder
                .build()
                .map_err(|e| anyhow::anyhow!("Subkey build failed: {}", e))?,
        );
    }

    debug!(
        "Generating key with primary algo: {:?}, can_sign: {}, can_encrypt: {}, can_auth: {}, subkey_count: {}",
        key_config.algo,
        key_config.can_sign,
        key_config.can_encrypt,
        key_config.can_auth,
        subkeys.len()
    );

    let signed = SecretKeyParamsBuilder::default()
        .key_type(primary_type)
        .can_certify(true)
        .can_sign(key_config.can_sign)
        .can_encrypt(if key_config.can_encrypt {
            EncryptionCaps::All
        } else {
            EncryptionCaps::None
        })
        .can_authenticate(key_config.can_auth)
        .primary_user_id(uid.into())
        .subkeys(subkeys)
        .build()?
        .generate(thread_rng())?;

    Ok(signed)
}

pub fn create_key_internal(
    user_id: &str,
    key_config: GfrKeyConfig,
    s_key_configs: &[GfrKeyConfig],
    fetch_pwd_cb: Option<GfrPasswordFetchCb>,
    free_cb: Option<GfrFreeCb>,
) -> Result<GeneratedKeys, GfrStatus> {
    debug!(
        "Creating key for user_id: {}, algo: {:?}, can_sign: {}, can_encrypt: {}, can_auth: {}, subkey_count: {}",
        user_id,
        key_config.algo,
        key_config.can_sign,
        key_config.can_encrypt,
        key_config.can_auth,
        s_key_configs.len()
    );

    let mut secret_key =
        keygen_dynamic(user_id, &key_config, s_key_configs).map_err(|e: anyhow::Error| {
            error!("Key generation failed: {}", e);
            GfrStatus::ErrorKeygenFailed
        })?;

    let primary_pwd_bytes = if key_config.has_passphrase {
        fetch_password_internal(
            0, // Index 0 for primary key
            &secret_key.fingerprint().to_string(),
            "Generate Primary Key",
            fetch_pwd_cb,
            free_cb,
        )?
    } else {
        Vec::new()
    };

    if key_config.has_passphrase && primary_pwd_bytes.is_empty() {
        return Err(GfrStatus::ErrorFetchPasswordFailed);
    }

    if !primary_pwd_bytes.is_empty() {
        // Encrypt Primary Key with the primary password
        let primary_password = Password::from(primary_pwd_bytes.as_slice());
        secret_key
            .primary_key
            .set_password(thread_rng(), &primary_password)
            .map_err(|_| GfrStatus::ErrorPasswordFailed)?;

        // Iterate through subkeys to set individual passwords
        for (index, subkey) in secret_key.secret_subkeys.iter_mut().enumerate() {
            // Determine if subkey needs a password based on your own configuration logic.
            // For example, fetching a different password for each subkey:
            let subkey_pwd_bytes = fetch_password_internal(
                ((index + 1) as u32).try_into().unwrap(), // Use a different index for each subkey
                &subkey.key.fingerprint().to_string(),
                "Generate Subkey",
                fetch_pwd_cb,
                free_cb,
            )?;

            // If the subkey password is provided, apply it
            if !subkey_pwd_bytes.is_empty() {
                let sub_password = Password::from(subkey_pwd_bytes.as_slice());
                subkey
                    .key
                    .set_password(thread_rng(), &sub_password)
                    .map_err(|_| GfrStatus::ErrorPasswordFailed)?;
            } else {
                // Handle missing subkey password according to your app logic
                return Err(GfrStatus::ErrorFetchPasswordFailed);
            }
        }
    }

    let fingerprint = secret_key.fingerprint().to_string();

    let armored_s_key = secret_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|_| GfrStatus::ErrorArmorFailed)?;

    let public_key = SignedPublicKey::from(secret_key);
    let armored_p_key = public_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|_| GfrStatus::ErrorArmorFailed)?;

    Ok(GeneratedKeys {
        secret: armored_s_key,
        public: armored_p_key,
        fingerprint,
    })
}
