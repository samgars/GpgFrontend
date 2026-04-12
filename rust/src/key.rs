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
use crate::types::{GfrKeyAlgo, GfrStatus};
use pgp::{
    composed::{ArmorOptions, Deserializable, SignedPublicKey, SignedSecretKey},
    packet::Signature,
    ser::Serialize,
    types::{KeyDetails, PublicParams},
};
pub struct ExtractedSubkey {
    pub fpr: String,
    pub key_id: String,
    pub algo: GfrKeyAlgo,
    pub created_at: u32,
    pub has_secret: bool,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_certify: bool,
    pub can_auth: bool,
}

pub struct ExtractedMetadata {
    pub fpr: String,
    pub key_id: String,
    pub user_id: String,
    pub algo: GfrKeyAlgo,
    pub created_at: u32,
    pub has_secret: bool,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_auth: bool,
    pub can_certify: bool,
    pub subkeys: Vec<ExtractedSubkey>,
}

fn determine_algo(public_params: &PublicParams) -> GfrKeyAlgo {
    match public_params {
        PublicParams::RSA(p) => {
            // Rough estimation of RSA bit size based on modulus bytes
            let bits = p.write_len();
            if bits >= 4096 {
                GfrKeyAlgo::RSA4096
            } else if bits >= 3072 {
                GfrKeyAlgo::RSA3072
            } else {
                GfrKeyAlgo::RSA2048
            }
        }
        PublicParams::Ed25519(_) => GfrKeyAlgo::ED25519,
        PublicParams::ECDH(p) => match p.curve() {
            pgp::crypto::ecc_curve::ECCCurve::Curve25519 => GfrKeyAlgo::CV25519,
            pgp::crypto::ecc_curve::ECCCurve::P256 => GfrKeyAlgo::NISTP256,
            pgp::crypto::ecc_curve::ECCCurve::P384 => GfrKeyAlgo::NISTP384,
            pgp::crypto::ecc_curve::ECCCurve::P521 => GfrKeyAlgo::NISTP521,
            _ => GfrKeyAlgo::Unknown,
        },
        PublicParams::ECDSA(p) => match p.curve() {
            pgp::crypto::ecc_curve::ECCCurve::P256 => GfrKeyAlgo::NISTP256,
            pgp::crypto::ecc_curve::ECCCurve::P384 => GfrKeyAlgo::NISTP384,
            pgp::crypto::ecc_curve::ECCCurve::P521 => GfrKeyAlgo::NISTP521,
            _ => GfrKeyAlgo::Unknown,
        },
        _ => GfrKeyAlgo::Unknown, // Fallback
    }
}

// Helper to extract (can_sign, can_encrypt, can_auth, can_certify) from signatures
fn extract_capabilities(signatures: &[Signature]) -> (bool, bool, bool, bool) {
    let mut can_sign = false;
    let mut can_encrypt = false;
    let mut can_auth = false;
    let mut can_certify = false;

    for sig in signatures {
        // Get the KeyFlags struct directly
        let flags = sig.key_flags();

        // Call the boolean methods provided by the KeyFlags struct
        if flags.sign() {
            can_sign = true;
        }

        // PGP defines two types of encryption flags, checking either is usually sufficient
        if flags.encrypt_comms() || flags.encrypt_storage() {
            can_encrypt = true;
        }

        if flags.authentication() {
            can_auth = true;
        }

        if flags.certify() {
            can_certify = true;
        }
    }

    (can_sign, can_encrypt, can_auth, can_certify)
}

pub fn extract_metadata_internal(key_block: &str) -> Result<ExtractedMetadata, GfrStatus> {
    // Try to parse as secret key first
    let (has_secret, primary_key, users, subkeys_info) =
        if let Ok((sk, _)) = SignedSecretKey::from_string(key_block) {
            let pk = SignedPublicKey::from(sk.clone());
            let mut subs = Vec::new();

            // Extract from secret subkeys to know they have secrets
            for sub in &sk.secret_subkeys {
                let (can_sign, can_encrypt, can_auth, can_certify) =
                    extract_capabilities(&sub.signatures);
                subs.push(ExtractedSubkey {
                    fpr: sub.key.fingerprint().to_string(),
                    key_id: sub.key.legacy_key_id().to_string(),
                    algo: determine_algo(sub.key.public_params()),
                    created_at: sub.key.created_at().as_secs(),
                    has_secret: true,
                    can_sign,
                    can_encrypt,
                    can_auth,
                    can_certify,
                });
            }
            (true, pk.primary_key, pk.details.users, subs)

        // Fallback to public key
        } else if let Ok((pk, _)) = SignedPublicKey::from_string(key_block) {
            let mut subs = Vec::new();

            for sub in &pk.public_subkeys {
                let (can_sign, can_encrypt, can_auth, can_certify) =
                    extract_capabilities(&sub.signatures);
                subs.push(ExtractedSubkey {
                    fpr: sub.key.fingerprint().to_string(),
                    key_id: sub.key.legacy_key_id().to_string(),
                    algo: determine_algo(sub.key.public_params()),
                    created_at: sub.key.created_at().as_secs(),
                    has_secret: false,
                    can_sign,
                    can_encrypt,
                    can_auth,
                    can_certify,
                });
            }
            (false, pk.primary_key, pk.details.users, subs)
        } else {
            return Err(GfrStatus::ErrorInvalidInput);
        };

    let user_id = users
        .first()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .unwrap_or_default();

    let primary_user_sigs = users
        .first()
        .map(|u| u.signatures.as_slice())
        .unwrap_or(&[]);
    let (can_sign, can_encrypt, can_auth, can_certify) = extract_capabilities(primary_user_sigs);

    Ok(ExtractedMetadata {
        fpr: primary_key.fingerprint().to_string(),
        key_id: primary_key.legacy_key_id().to_string(),
        user_id,
        algo: determine_algo(primary_key.public_params()),
        created_at: primary_key.created_at().as_secs(),
        has_secret,
        subkeys: subkeys_info,
        can_sign,
        can_encrypt,
        can_auth,
        can_certify,
    })
}

// Extract a public key armored string from a secret key armored string
pub fn extract_public_key_internal(secret_block: &str) -> Result<String, GfrStatus> {
    // 1. Parse the armored secret key block
    let (secret_key, _) =
        SignedSecretKey::from_string(secret_block).map_err(|_| GfrStatus::ErrorInvalidInput)?;

    // 2. Convert to public key (this strips the secret mathematical materials)
    let public_key = SignedPublicKey::from(secret_key);

    // 3. Export back to ASCII Armor format
    let armored_p_key = public_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|_| GfrStatus::ErrorArmorFailed)?;

    Ok(armored_p_key)
}
