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
    types::{
        GfrFreeCb, GfrPasswordFetchCb, GfrPublicKeyFetchCb, GfrRecipientStatus, GfrSignMode,
        GfrSignatureStatus, GfrStatus,
    },
    utils::fetch_password_internal,
};
use log::debug;
use pgp::{
    armor::Dearmor,
    composed::{
        ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, Message,
        MessageBuilder, SignedPublicKey, SignedSecretKey,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{Packet, PacketParser},
    ser::Serialize,
    types::{KeyDetails, Password, SecretParams},
};
use rand::thread_rng;
use std::{
    ffi::c_void,
    io::{Cursor, Read},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct InvalidRecipientInternal {
    pub fpr: String,
    pub reason: GfrStatus,
}

pub struct EncryptResultInternal {
    pub data: Vec<u8>,
    pub invalid_recipients: Vec<InvalidRecipientInternal>,
}

pub fn encrypt_internal(
    name: &str,
    data: &[u8],
    public_key_blocks: &[&str],
    ascii_armor: bool,
) -> Result<EncryptResultInternal, GfrStatus> {
    let mut rng = thread_rng();

    // 1. Initialize the builder with SEIPDv1 and AES256
    let mut builder = MessageBuilder::from_bytes(name.as_bytes().to_vec(), data.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    let mut has_recipient = false;
    let mut invalid_recipients = Vec::new();

    // 2. Iterate through all provided recipient public key blocks
    for block in public_key_blocks {
        // Try parsing the block as a SignedPublicKey certificate
        match SignedPublicKey::from_string(block) {
            Ok((cert, _)) => {
                let mut added_for_this_cert = false;
                let fpr = cert.primary_key.fingerprint().to_string();

                // 3. Dynamically find a valid encryption subkey
                for subkey in &cert.public_subkeys {
                    if subkey.key.algorithm().can_encrypt() {
                        if builder.encrypt_to_key(&mut rng, subkey).is_ok() {
                            added_for_this_cert = true;
                            has_recipient = true;
                            break;
                        }
                    }
                }

                // Fallback to primary key if no encryption subkeys are found
                if !added_for_this_cert && cert.primary_key.algorithm().can_encrypt() {
                    if builder.encrypt_to_key(&mut rng, &cert.primary_key).is_ok() {
                        added_for_this_cert = true;
                        has_recipient = true;
                    }
                }

                // if no valid encryption key is found for this certificate
                if !added_for_this_cert {
                    invalid_recipients.push(InvalidRecipientInternal {
                        fpr,
                        reason: GfrStatus::ErrorNoKey,
                    });
                }
            }
            Err(_) => {
                // if the block cannot be parsed as a valid PGP public key
                invalid_recipients.push(InvalidRecipientInternal {
                    fpr: String::from("Unknown"),
                    reason: GfrStatus::ErrorInvalidData,
                });
            }
        }
    }

    // if after processing all recipient blocks, we don't have any valid
    // encryption keys, return an error
    if !has_recipient {
        return Err(GfrStatus::ErrorInvalidInput);
    }

    // 4. Generate the final output
    let final_data = if ascii_armor {
        builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .map_err(|_| GfrStatus::ErrorArmorFailed)?
            .into_bytes()
    } else {
        builder
            .to_vec(&mut rng)
            .map_err(|_| GfrStatus::ErrorInternal)?
    };

    Ok(EncryptResultInternal {
        data: final_data,
        invalid_recipients,
    })
}

pub struct RecipientResultInternal {
    pub key_id: String, // PGP PKESK only exposes 16-char Key ID, not full Fingerprint
    pub pub_algo: String,
    pub status: GfrRecipientStatus,
}

pub struct DecryptResultInternal {
    pub data: Vec<u8>,
    pub filename: String,
    pub recipients: Vec<RecipientResultInternal>,
}

// Helper to sniff all intended recipients from the encrypted data
fn sniff_recipients(data: &[u8]) -> Vec<RecipientResultInternal> {
    let mut results = Vec::new();
    let mut dearmored = Vec::new();
    let _ = Dearmor::new(Cursor::new(data)).read_to_end(&mut dearmored);
    let payload = if dearmored.is_empty() {
        data
    } else {
        &dearmored
    };

    let parser = PacketParser::new(Cursor::new(payload));
    for packet_result in parser {
        if let Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) = packet_result {
            if let Ok(id) = pkesk.id() {
                let algo = if let Ok(algo_id) = pkesk.algorithm() {
                    algo_to_string_simple(algo_id)
                } else {
                    String::new()
                };
                results.push(RecipientResultInternal {
                    key_id: id.to_string(),
                    pub_algo: algo,
                    status: GfrRecipientStatus::NoKey, // Default to NoKey until proven otherwise
                });
            }
        }
    }
    results
}

pub fn decrypt_internal(
    channel: i32,
    encrypted_data: &[u8],
    secret_key_block: &str,
    fetch_pwd_cb: Option<GfrPasswordFetchCb>,
    free_cb: Option<GfrFreeCb>,
) -> Result<DecryptResultInternal, GfrStatus> {
    // 1. Parse the provided secret key block
    let (skey, _) =
        SignedSecretKey::from_string(secret_key_block).map_err(|_| GfrStatus::ErrorInvalidInput)?;

    // 2. Sniff the intended recipients from the raw message
    let mut recipients = sniff_recipients(encrypted_data);

    // 3. Try parsing the encrypted data
    let parsed_message = if let Ok((msg, _)) = Message::from_armor(Cursor::new(encrypted_data)) {
        msg
    } else if let Ok(msg) = Message::from_bytes(encrypted_data) {
        msg
    } else {
        return Err(GfrStatus::ErrorInvalidInput);
    };

    // 4. Determine if we need to fetch a password
    let mut needs_password = false;
    let primary_id = skey.primary_key.legacy_key_id().to_string();

    // Helper closure to check if a recipient ID is the special "anonymous" ID that matches any key
    let is_anonymous = |id: &str| id == "0000000000000000";

    // Check primary key first: if any recipient matches the primary key ID (or
    // is anonymous) and the primary key is encrypted, we need a password
    if recipients
        .iter()
        .any(|r| r.key_id == primary_id || is_anonymous(&r.key_id))
        && matches!(skey.primary_key.secret_params(), SecretParams::Encrypted(_))
    {
        needs_password = true;
    }

    // If we don't need a password for the primary key, check the subkeys in the same way
    if !needs_password {
        for subkey in &skey.secret_subkeys {
            let subkey_id = subkey.key.legacy_key_id().to_string();
            if recipients
                .iter()
                .any(|r| r.key_id == subkey_id || is_anonymous(&r.key_id))
                && matches!(subkey.key.secret_params(), SecretParams::Encrypted(_))
            {
                needs_password = true;
                break;
            }
        }
    }

    let mut password = Vec::<u8>::new();

    // If we determined that a password is needed, attempt to fetch it via the callback
    if needs_password {
        let fpr_string = skey.primary_key.fingerprint().to_string();
        password =
            fetch_password_internal(channel, &fpr_string, "Decryption", fetch_pwd_cb, free_cb)?;
    } else {
        debug!("Target secret key is unlocked. Bypassing password callback.");
    }

    // 4. Attempt to decrypt the message
    let pwd_fn = Password::from(password.as_slice());
    let mut decrypted = parsed_message
        .decrypt(&pwd_fn, &skey)
        .map_err(|_| GfrStatus::ErrorDecryptionFailed)?; // Fails if wrong key or wrong password

    // 5. If decryption is successful, update the recipient list status
    let primary_id = skey.primary_key.legacy_key_id().to_string();
    let subkey_ids: Vec<String> = skey
        .secret_subkeys
        .iter()
        .map(|s| s.key.legacy_key_id().to_string())
        .collect();

    for rec in &mut recipients {
        // Match either the primary key ID or any subkey ID
        if rec.key_id == primary_id || subkey_ids.contains(&rec.key_id) {
            rec.status = GfrRecipientStatus::Success;
        }
    }

    // 6. Decompress if necessary
    if decrypted.is_compressed() {
        decrypted = decrypted
            .decompress()
            .map_err(|_| GfrStatus::ErrorInternal)?;
    }

    // 7. Extract the original filename if the underlying packet is a LiteralData packet
    let mut filename = String::new();
    if let pgp::composed::Message::Literal { ref reader, .. } = decrypted {
        // Access the LiteralDataHeader first, then extract the filename
        let header = reader.data_header();
        filename = String::from_utf8_lossy(header.file_name()).to_string();
    }

    // 8. Extract the actual payload
    let payload = decrypted
        .as_data_vec()
        .map_err(|_| GfrStatus::ErrorInternal)?;

    Ok(DecryptResultInternal {
        data: payload,
        filename,
        recipients,
    })
}

pub fn get_message_recipients_internal(data: &[u8]) -> Result<String, GfrStatus> {
    let recipients = sniff_recipients(data);
    let key_ids: Vec<String> = recipients.iter().map(|r| r.key_id.clone()).collect();

    if key_ids.is_empty() {
        return Err(GfrStatus::ErrorInvalidInput); // Not a valid encrypted message
    }

    // Join them with commas for easy FFI transfer (e.g., "A1B2C3D4E5F6G7H8,8H7G6F5E4D3C2B1A")
    Ok(key_ids.join(","))
}

pub struct SignResultInternal {
    pub data: Vec<u8>,
    pub signatures: Vec<SignatureResultInternal>,
}

pub fn sign_internal(
    channel: i32, // New param for context
    name: &str,
    data: &[u8],
    secret_key_blocks: &[&str],
    fetch_cb: Option<GfrPasswordFetchCb>,
    free_cb: Option<GfrFreeCb>,
    mode: GfrSignMode,
    ascii_armor: bool,
) -> Result<SignResultInternal, GfrStatus> {
    if secret_key_blocks.is_empty() {
        return Err(GfrStatus::ErrorInvalidInput);
    }

    // Cleartext strictly requires valid UTF-8 string data
    if mode == GfrSignMode::ClearText && std::str::from_utf8(data).is_err() {
        return Err(GfrStatus::ErrorInvalidInput);
    }

    // 1. Parse ALL secret keys first to ensure they live long enough
    let mut parsed_keys = Vec::with_capacity(secret_key_blocks.len());
    for block in secret_key_blocks {
        let (skey, _) =
            SignedSecretKey::from_string(block).map_err(|_| GfrStatus::ErrorInvalidInput)?;
        parsed_keys.push(skey);
    }

    let mut rng = thread_rng();
    let mut created_signatures = Vec::new();
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    // Helper closure to record the signature info once created
    let mut record_sig = |fpr: String, algo: PublicKeyAlgorithm| {
        created_signatures.push(SignatureResultInternal {
            fpr,
            status: GfrSignatureStatus::Valid,
            created_at: current_time,
            pub_algo: algo_to_string_simple(algo),
            hash_algo: "SHA512".to_string(),
            sig_type: mode,
        });
    };

    // Helper closure to fetch password dynamically for a specific key
    let fetch_pwd_for_key = |is_encrypted: bool, fpr: &str| -> Result<Password, GfrStatus> {
        if is_encrypted {
            let pwd_bytes = fetch_password_internal(channel, fpr, "Signing", fetch_cb, free_cb)?;
            Ok(Password::from(pwd_bytes.as_slice()))
        } else {
            debug!("Target secret key is unlocked. Bypassing password callback for signing.");
            Ok(Password::empty())
        }
    };

    // 2. Route the operation based on the selected mode
    match mode {
        // ---------------------------------------------------------
        // MODE 0: INLINE SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::Inline => {
            let mut builder = MessageBuilder::from_bytes(name.as_bytes().to_vec(), data.to_vec());
            let mut at_least_one_signer = false;

            for skey in &parsed_keys {
                let mut added_for_this_key = false;

                for subkey in &skey.secret_subkeys {
                    if subkey.key.algorithm().can_sign() {
                        let fpr = subkey.key.fingerprint().to_string();
                        let pwd_fn = fetch_pwd_for_key(
                            matches!(subkey.key.secret_params(), SecretParams::Encrypted(_)),
                            &fpr,
                        )?;

                        builder.sign(&subkey.key, pwd_fn, HashAlgorithm::Sha512);
                        record_sig(fpr, subkey.key.algorithm());

                        added_for_this_key = true;
                        at_least_one_signer = true;
                        break;
                    }
                }

                if !added_for_this_key && skey.primary_key.algorithm().can_sign() {
                    let fpr = skey.primary_key.fingerprint().to_string();
                    let fallback_pwd = fetch_pwd_for_key(
                        matches!(skey.primary_key.secret_params(), SecretParams::Encrypted(_)),
                        &fpr,
                    )?;

                    builder.sign(&skey.primary_key, fallback_pwd, HashAlgorithm::Sha512);
                    record_sig(fpr, skey.primary_key.algorithm());

                    at_least_one_signer = true;
                }
            }

            if !at_least_one_signer {
                return Err(GfrStatus::ErrorInvalidInput);
            }

            let final_data = if ascii_armor {
                builder
                    .to_armored_string(&mut rng, ArmorOptions::default())
                    .map_err(|_| GfrStatus::ErrorArmorFailed)?
                    .into_bytes()
            } else {
                builder
                    .to_vec(&mut rng)
                    .map_err(|_| GfrStatus::ErrorInternal)?
            };

            Ok(SignResultInternal {
                data: final_data,
                signatures: created_signatures,
            })
        }

        // ---------------------------------------------------------
        // MODE 1: CLEARTEXT SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::ClearText => {
            let text = std::str::from_utf8(data).unwrap().to_string();

            // Find the first valid signer and generate the cleartext message
            // Note: Cleartext signatures only support ONE signer in this implementation
            // (due to the return statement breaking the loop)
            for skey in &parsed_keys {
                for subkey in &skey.secret_subkeys {
                    if subkey.key.algorithm().can_sign() {
                        let fpr = subkey.key.fingerprint().to_string();
                        let is_encrypted =
                            matches!(subkey.key.secret_params(), SecretParams::Encrypted(_));
                        let pwd = fetch_pwd_for_key(is_encrypted, &fpr)?;

                        if let Ok(msg) =
                            CleartextSignedMessage::sign(&mut rng, &text, &subkey.key, &pwd)
                        {
                            record_sig(fpr, subkey.key.algorithm());
                            let out = msg
                                .to_armored_string(ArmorOptions::default())
                                .map_err(|_| GfrStatus::ErrorArmorFailed)?
                                .into_bytes();
                            return Ok(SignResultInternal {
                                data: out,
                                signatures: created_signatures,
                            });
                        }
                    }
                }

                if skey.primary_key.algorithm().can_sign() {
                    let fpr = skey.primary_key.fingerprint().to_string();
                    let is_encrypted =
                        matches!(skey.primary_key.secret_params(), SecretParams::Encrypted(_));
                    let pwd = fetch_pwd_for_key(is_encrypted, &fpr)?;

                    if let Ok(msg) =
                        CleartextSignedMessage::sign(&mut rng, &text, &skey.primary_key, &pwd)
                    {
                        record_sig(fpr, skey.primary_key.algorithm());
                        let out = msg
                            .to_armored_string(ArmorOptions::default())
                            .map_err(|_| GfrStatus::ErrorArmorFailed)?
                            .into_bytes();
                        return Ok(SignResultInternal {
                            data: out,
                            signatures: created_signatures,
                        });
                    }
                }
            }

            Err(GfrStatus::ErrorInvalidInput)
        }

        // ---------------------------------------------------------
        // MODE 2: DETACHED SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::Detached => {
            // Find the first valid signer and generate the detached signature
            for skey in &parsed_keys {
                for subkey in &skey.secret_subkeys {
                    if subkey.key.algorithm().can_sign() {
                        let fpr = subkey.key.fingerprint().to_string();
                        let is_encrypted =
                            matches!(subkey.key.secret_params(), SecretParams::Encrypted(_));
                        let pwd = fetch_pwd_for_key(is_encrypted, &fpr)?;

                        if let Ok(sig) = DetachedSignature::sign_binary_data(
                            &mut rng,
                            &subkey.key,
                            &pwd,
                            HashAlgorithm::Sha512,
                            data,
                        ) {
                            record_sig(fpr, subkey.key.algorithm());
                            let out = if ascii_armor {
                                sig.to_armored_bytes(None.into())
                                    .map_err(|_| GfrStatus::ErrorArmorFailed)?
                            } else {
                                sig.to_bytes().map_err(|_| GfrStatus::ErrorInternal)?
                            };
                            return Ok(SignResultInternal {
                                data: out,
                                signatures: created_signatures,
                            });
                        }
                    }
                }

                if skey.primary_key.algorithm().can_sign() {
                    let fpr = skey.primary_key.fingerprint().to_string();
                    let is_encrypted =
                        matches!(skey.primary_key.secret_params(), SecretParams::Encrypted(_));
                    let pwd = fetch_pwd_for_key(is_encrypted, &fpr)?;

                    if let Ok(sig) = DetachedSignature::sign_binary_data(
                        &mut rng,
                        &skey.primary_key,
                        &pwd,
                        HashAlgorithm::Sha512,
                        data,
                    ) {
                        record_sig(fpr, skey.primary_key.algorithm());
                        let out = if ascii_armor {
                            sig.to_armored_bytes(None.into())
                                .map_err(|_| GfrStatus::ErrorArmorFailed)?
                        } else {
                            sig.to_bytes().map_err(|_| GfrStatus::ErrorInternal)?
                        };
                        return Ok(SignResultInternal {
                            data: out,
                            signatures: created_signatures,
                        });
                    }
                }
            }

            Err(GfrStatus::ErrorInvalidInput)
        }
    }
}

pub struct VerifyResultInternal {
    pub data: Vec<u8>,
    pub is_verified: bool,
    pub signatures: Vec<SignatureResultInternal>,
}

pub struct SignatureResultInternal {
    pub fpr: String,
    pub status: GfrSignatureStatus,
    pub created_at: u32,
    pub pub_algo: String,
    pub hash_algo: String,
    pub sig_type: GfrSignMode,
}

fn cert_contains_issuer(cert: &SignedPublicKey, issuer_hex: &str) -> bool {
    if cert
        .primary_key
        .fingerprint()
        .to_string()
        .eq_ignore_ascii_case(issuer_hex)
    {
        return true;
    }
    for subkey in &cert.public_subkeys {
        if subkey
            .key
            .fingerprint()
            .to_string()
            .eq_ignore_ascii_case(issuer_hex)
        {
            return true;
        }
    }
    false
}

pub fn algo_to_string_simple(algo: PublicKeyAlgorithm) -> String {
    // Uses the derived Debug trait to get the variant name as a String
    format!("{:?}", algo)
}

fn sniff_signatures(data: &[u8], mode: GfrSignMode) -> Vec<SignatureResultInternal> {
    let mut results = Vec::new();
    let mut dearmored = Vec::new();
    let _ = Dearmor::new(Cursor::new(data)).read_to_end(&mut dearmored);
    let payload = if dearmored.is_empty() {
        data
    } else {
        &dearmored
    };

    let parser = PacketParser::new(Cursor::new(payload));
    for packet_result in parser {
        if let Ok(Packet::Signature(sig)) = packet_result {
            for issuer in sig.issuer_fingerprint() {
                let fpr = issuer.to_string();
                let (hash_algo_id, pub_algo_id) = if let Some(config) = sig.config() {
                    (
                        config.hash_alg.to_string(),
                        algo_to_string_simple(config.pub_alg),
                    )
                } else {
                    (String::new(), String::new())
                };
                if !results
                    .iter()
                    .any(|r: &SignatureResultInternal| r.fpr == fpr)
                {
                    results.push(SignatureResultInternal {
                        fpr: fpr,
                        status: GfrSignatureStatus::NoKey,
                        created_at: sig.created().map(|d| d.as_secs() as u32).unwrap_or(0),
                        pub_algo: pub_algo_id,
                        hash_algo: hash_algo_id,
                        sig_type: mode,
                    });
                }
            }
        }
    }
    results
}

pub fn verify_internal(
    data: &[u8],
    sig_data: &[u8], // Used only for Detached mode
    public_key_blocks: &[&str],
    mode: GfrSignMode,
) -> Result<VerifyResultInternal, GfrStatus> {
    // 1. Parse candidate public keys
    let mut certs = Vec::with_capacity(public_key_blocks.len());
    for block in public_key_blocks {
        if let Ok((cert, _)) = SignedPublicKey::from_string(block) {
            certs.push(cert);
        }
    }

    debug!(
        "Parsed {} public keys for verification, mode: {:?}",
        certs.len(),
        mode
    );

    match mode {
        // ---------------------------------------------------------
        // MODE 0: INLINE SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::Inline => {
            let mut msg = if let Ok((m, _)) = Message::from_armor(Cursor::new(data)) {
                m
            } else if let Ok(m) = Message::from_bytes(data) {
                m
            } else {
                return Err(GfrStatus::ErrorInvalidInput);
            };

            // try to sniff signatures from the message packets first, to build
            // an initial list of issuers and their statuses
            let mut signatures = sniff_signatures(data, mode);
            let mut is_verified = false;

            for cert in &certs {
                // if verification succeeds with this cert, mark all matching
                // issuers as Valid; if it fails, mark them as BadSignature (but
                // only if we previously marked them as NoKey)
                if msg.verify(cert).is_ok() {
                    is_verified = true;
                    let mut found = false;

                    // Update the status of all signatures that match this
                    // cert's primary key or any of its subkeys
                    for sig in &mut signatures {
                        if cert_contains_issuer(cert, &sig.fpr) {
                            sig.status = GfrSignatureStatus::Valid;
                            found = true;
                        }
                    }

                    // If we found a matching issuer in the signatures, we would
                    // have updated its status to Valid.
                    if !found {
                        let fpr: String = cert.primary_key.fingerprint().to_string();
                        signatures.push(SignatureResultInternal {
                            fpr,
                            status: GfrSignatureStatus::Valid,
                            created_at: 0,
                            pub_algo: "None".to_string(),
                            hash_algo: "None".to_string(),
                            sig_type: mode,
                        });
                    }
                } else {
                    for sig in &mut signatures {
                        if cert_contains_issuer(cert, &sig.fpr)
                            && sig.status == GfrSignatureStatus::NoKey
                        {
                            sig.status = GfrSignatureStatus::BadSignature;
                        }
                    }
                }
            }

            let clear_data = msg.as_data_vec().map_err(|_| GfrStatus::ErrorInternal)?;
            Ok(VerifyResultInternal {
                data: clear_data,
                is_verified,
                signatures,
            })
        }

        // ---------------------------------------------------------
        // MODE 1: CLEARTEXT SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::ClearText => {
            debug!("Attempting to parse cleartext signed message for verification");

            let text_str = std::str::from_utf8(data).map_err(|_| GfrStatus::ErrorInvalidInput)?;
            let (msg, _) = CleartextSignedMessage::from_string(text_str)
                .map_err(|_| GfrStatus::ErrorInvalidInput)?;

            debug!(
                "Parsed cleartext signed message with {} signatures",
                msg.signatures().len()
            );

            let mut signatures = Vec::new();
            for sig in msg.signatures().into_iter() {
                for issuer in sig.issuer_fingerprint() {
                    let fpr: String = issuer.to_string();
                    let (hash_algo_id, pub_algo_id) = if let Some(config) = sig.config() {
                        (
                            config.hash_alg.to_string(),
                            algo_to_string_simple(config.pub_alg),
                        )
                    } else {
                        (String::new(), String::new())
                    };
                    if !signatures
                        .iter()
                        .any(|r: &SignatureResultInternal| r.fpr == fpr)
                    {
                        signatures.push(SignatureResultInternal {
                            fpr,
                            status: GfrSignatureStatus::NoKey,
                            created_at: sig.created().map(|d| d.as_secs() as u32).unwrap_or(0),
                            pub_algo: pub_algo_id,
                            hash_algo: hash_algo_id,
                            sig_type: mode,
                        });
                    }
                }
            }

            let mut is_verified = false;
            for cert in &certs {
                let is_cert_valid = msg.verify(cert).is_ok();
                for sig in &mut signatures {
                    if cert_contains_issuer(cert, &sig.fpr) {
                        sig.status = if is_cert_valid {
                            is_verified = true;
                            GfrSignatureStatus::Valid
                        } else {
                            GfrSignatureStatus::BadSignature
                        };
                    }
                }
            }

            let clear_data = msg
                .to_armored_bytes(ArmorOptions::default())
                .unwrap_or_default();
            Ok(VerifyResultInternal {
                data: clear_data,
                is_verified,
                signatures,
            })
        }

        // ---------------------------------------------------------
        // MODE 2: DETACHED SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::Detached => {
            if sig_data.is_empty() {
                return Err(GfrStatus::ErrorInvalidInput);
            }

            let sig_msg =
                if let Ok((s, _)) = DetachedSignature::from_armor_single(Cursor::new(sig_data)) {
                    s
                } else if let Ok(s) = DetachedSignature::from_bytes(sig_data) {
                    s
                } else {
                    return Err(GfrStatus::ErrorInvalidInput);
                };

            // try to sniff signatures from the signature packets first, to build
            // an initial list of issuers and their statuses
            let mut signatures = sniff_signatures(sig_data, mode);
            let mut is_verified = false;

            for cert in &certs {
                let is_cert_valid = sig_msg.verify(cert, data).is_ok();
                for sig in &mut signatures {
                    if cert_contains_issuer(cert, &sig.fpr) {
                        sig.status = if is_cert_valid {
                            is_verified = true;
                            GfrSignatureStatus::Valid
                        } else {
                            GfrSignatureStatus::BadSignature
                        };
                    }
                }
            }

            // Detached verification doesn't extract plaintext, only confirms status
            Ok(VerifyResultInternal {
                data: Vec::new(),
                is_verified,
                signatures,
            })
        }
    }
}

pub fn get_signature_issuers_internal(data: &[u8]) -> Result<(String, String), GfrStatus> {
    let mut recipients = Vec::new();
    let mut issuers = Vec::new();

    // 1. First, attempt to parse as a Cleartext Signed Message
    if let Ok(text_str) = std::str::from_utf8(data) {
        if let Ok((msg, _)) = CleartextSignedMessage::from_string(text_str) {
            for sig in msg.signatures().into_iter() {
                for issuer in sig.issuer_key_id() {
                    issuers.push(issuer.to_string());
                }
            }
            // Cleartext messages only contain signatures, not encrypted recipients
            issuers.sort();
            issuers.dedup();
            return Ok((recipients.join(","), issuers.join(",")));
        }
    }

    // 2. Un-armor if necessary for standard encrypted or detached/inline signed data
    let mut dearmored = Vec::new();
    let _ = Dearmor::new(Cursor::new(data)).read_to_end(&mut dearmored);

    let payload = if dearmored.is_empty() {
        data
    } else {
        &dearmored
    };

    // 3. Parse standard PGP packets
    let parser = PacketParser::new(Cursor::new(payload));

    for packet_result in parser {
        if let Ok(packet) = packet_result {
            match packet {
                // Sniff Recipient (for Encryption)
                Packet::PublicKeyEncryptedSessionKey(pkesk) => {
                    if let Ok(id) = pkesk.id() {
                        recipients.push(id.to_string());
                    }
                }
                // Sniff Signer from OnePassSignature (Appears at the start of inline signatures)
                Packet::OnePassSignature(ops) => {
                    // Match on the version-specific enum to extract the identifier
                    match ops.version_specific() {
                        pgp::packet::OpsVersionSpecific::V3 { key_id } => {
                            // V3 OPS directly contains a KeyId
                            issuers.push(key_id.to_string());
                        }
                        pgp::packet::OpsVersionSpecific::V6 { fingerprint, .. } => {
                            // V6 OPS contains a 32-byte fingerprint. Format it safely as an uppercase HEX string.
                            let fp_str: String =
                                fingerprint.iter().map(|b| format!("{:02X}", b)).collect();
                            issuers.push(fp_str);
                        }
                        _ => {}
                    }
                }
                // Sniff Signer from Signature packet (Used in detached signatures or end of inline)
                Packet::Signature(sig) => {
                    for issuer in sig.issuer_key_id() {
                        issuers.push(issuer.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    // 4. Deduplicate the collected IDs to avoid repeating the same Key ID
    recipients.sort();
    recipients.dedup();

    issuers.sort();
    issuers.dedup();

    Ok((recipients.join(","), issuers.join(",")))
}

// Internal struct combining both signatures created and invalid recipients skipped
pub struct EncryptAndSignResultInternal {
    pub data: Vec<u8>,
    pub signatures: Vec<SignatureResultInternal>,
    pub invalid_recipients: Vec<InvalidRecipientInternal>,
}

pub fn encrypt_and_sign_internal(
    channel: i32, // Added for callback context
    name: &str,
    data: &[u8],
    public_key_blocks: &[&str],
    secret_key_blocks: &[&str],
    fetch_cb: Option<GfrPasswordFetchCb>, // Added
    free_cb: Option<GfrFreeCb>,           // Added
    ascii_armor: bool,
) -> Result<EncryptAndSignResultInternal, GfrStatus> {
    // Check if we have at least one secret key to sign with
    if secret_key_blocks.is_empty() {
        return Err(GfrStatus::ErrorInvalidInput);
    }

    let mut rng = thread_rng();

    // 1. Initialize the builder with the plaintext payload
    let mut builder = MessageBuilder::from_bytes(name.as_bytes().to_vec(), data.to_vec());

    // 2. Process Signers FIRST (Signing must wrap the payload before encryption)
    let mut parsed_skeys = Vec::with_capacity(secret_key_blocks.len());
    for block in secret_key_blocks {
        let (skey, _) =
            SignedSecretKey::from_string(block).map_err(|_| GfrStatus::ErrorInvalidInput)?;
        parsed_skeys.push(skey);
    }

    let mut created_signatures = Vec::new();
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let mut record_sig = |fpr: String, algo: PublicKeyAlgorithm| {
        created_signatures.push(SignatureResultInternal {
            fpr,
            status: GfrSignatureStatus::Valid,
            created_at: current_time,
            pub_algo: algo_to_string_simple(algo),
            hash_algo: "SHA512".to_string(),
            sig_type: GfrSignMode::Inline, // Encrypt+Sign is always Inline nested
        });
    };

    // Helper closure to dynamically fetch password for signing keys
    let fetch_pwd_for_key = |is_encrypted: bool, fpr: &str| -> Result<Password, GfrStatus> {
        if is_encrypted {
            let pwd_bytes = fetch_password_internal(channel, fpr, "Signing", fetch_cb, free_cb)?;
            Ok(Password::from(pwd_bytes.as_slice()))
        } else {
            debug!("Target secret key is unlocked. Bypassing password callback for signing.");
            Ok(Password::empty())
        }
    };

    let mut at_least_one_signer = false;

    // Iterate over each provided signing key
    for skey in &parsed_skeys {
        let mut added_for_this_key = false;

        // Try to find a valid signing subkey
        for subkey in &skey.secret_subkeys {
            if subkey.key.algorithm().can_sign() {
                let fpr = subkey.key.fingerprint().to_string();
                let is_encrypted = matches!(subkey.key.secret_params(), SecretParams::Encrypted(_));

                // Dynamically fetch password if needed
                let pwd_fn = fetch_pwd_for_key(is_encrypted, &fpr)?;

                builder.sign(&subkey.key, pwd_fn, HashAlgorithm::Sha512);
                record_sig(fpr, subkey.key.algorithm());

                added_for_this_key = true;
                at_least_one_signer = true;
                break;
            }
        }

        // Fallback to primary key if no valid subkeys
        if !added_for_this_key && skey.primary_key.algorithm().can_sign() {
            let fpr = skey.primary_key.fingerprint().to_string();
            let is_encrypted =
                matches!(skey.primary_key.secret_params(), SecretParams::Encrypted(_));

            // Dynamically fetch password if needed
            let fallback_pwd = fetch_pwd_for_key(is_encrypted, &fpr)?;

            builder.sign(&skey.primary_key, fallback_pwd, HashAlgorithm::Sha512);
            record_sig(fpr, skey.primary_key.algorithm());

            at_least_one_signer = true;
        }
    }

    if !at_least_one_signer {
        return Err(GfrStatus::ErrorInvalidInput); // Missing valid signing key
    }

    // 3. Transition the Builder into Encryption Mode
    let mut enc_builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    // 4. Process Recipients
    let mut has_recipient = false;
    let mut invalid_recipients = Vec::new();

    for block in public_key_blocks {
        match SignedPublicKey::from_string(block) {
            Ok((cert, _)) => {
                let mut added_for_this_cert = false;
                let fpr = cert.primary_key.fingerprint().to_string();

                for subkey in &cert.public_subkeys {
                    if subkey.key.algorithm().can_encrypt() {
                        if enc_builder.encrypt_to_key(&mut rng, subkey).is_ok() {
                            added_for_this_cert = true;
                            has_recipient = true;
                            break;
                        }
                    }
                }

                if !added_for_this_cert && cert.primary_key.algorithm().can_encrypt() {
                    if enc_builder
                        .encrypt_to_key(&mut rng, &cert.primary_key)
                        .is_ok()
                    {
                        added_for_this_cert = true;
                        has_recipient = true;
                    }
                }

                if !added_for_this_cert {
                    invalid_recipients.push(InvalidRecipientInternal {
                        fpr,
                        reason: GfrStatus::ErrorNoKey,
                    });
                }
            }
            Err(_) => {
                invalid_recipients.push(InvalidRecipientInternal {
                    fpr: String::from("Unknown"),
                    reason: GfrStatus::ErrorInvalidData,
                });
            }
        }
    }

    if !has_recipient {
        return Err(GfrStatus::ErrorInvalidInput); // Missing valid encryption key
    }

    // 5. Finalize the nested payload
    let final_data = if ascii_armor {
        enc_builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .map_err(|_| GfrStatus::ErrorArmorFailed)?
            .into_bytes()
    } else {
        enc_builder
            .to_vec(&mut rng)
            .map_err(|_| GfrStatus::ErrorInternal)?
    };

    Ok(EncryptAndSignResultInternal {
        data: final_data,
        signatures: created_signatures,
        invalid_recipients,
    })
}

// Internal struct for the combined Decrypt + Verify operation
pub struct DecryptAndVerifyResultInternal {
    pub data: Vec<u8>,
    pub filename: String,
    pub recipients: Vec<RecipientResultInternal>,
    pub is_verified: bool,
    pub signatures: Vec<SignatureResultInternal>,
}

pub fn decrypt_and_verify_internal(
    channel: i32, // Added for password callback
    encrypted_data: &[u8],
    secret_key_block: &str,
    fetch_pwd_cb: Option<GfrPasswordFetchCb>,     // Added
    fetch_pubkey_cb: Option<GfrPublicKeyFetchCb>, // Renamed to distinguish from pwd
    free_cb: Option<GfrFreeCb>,                   // Shared free callback
    user_data: *mut c_void,
) -> Result<DecryptAndVerifyResultInternal, GfrStatus> {
    // 1. Parse secret key
    let (skey, _) =
        SignedSecretKey::from_string(secret_key_block).map_err(|_| GfrStatus::ErrorInvalidInput)?;

    // 2. Sniff recipients from outer layer
    let mut recipients = sniff_recipients(encrypted_data);

    let parsed_message = if let Ok((msg, _)) = Message::from_armor(Cursor::new(encrypted_data)) {
        msg
    } else if let Ok(msg) = Message::from_bytes(encrypted_data) {
        msg
    } else {
        return Err(GfrStatus::ErrorInvalidInput);
    };

    // 3. Determine if we need to fetch a password
    let mut needs_password = false;
    let primary_id = skey.primary_key.legacy_key_id().to_string();
    let mut target_fpr_for_pwd = skey.primary_key.fingerprint().to_string();

    // Helper closure to check if a recipient ID is the special "anonymous" ID
    let is_anonymous = |id: &str| id == "0000000000000000";

    if recipients
        .iter()
        .any(|r| r.key_id == primary_id || is_anonymous(&r.key_id))
        && matches!(skey.primary_key.secret_params(), SecretParams::Encrypted(_))
    {
        needs_password = true;
    }

    if !needs_password {
        for subkey in &skey.secret_subkeys {
            let subkey_id = subkey.key.legacy_key_id().to_string();
            if recipients
                .iter()
                .any(|r| r.key_id == subkey_id || is_anonymous(&r.key_id))
                && matches!(subkey.key.secret_params(), SecretParams::Encrypted(_))
            {
                needs_password = true;
                target_fpr_for_pwd = subkey.key.fingerprint().to_string(); // Use specific subkey FPR for prompt
                break;
            }
        }
    }

    let mut password = Vec::<u8>::new();

    // Fetch password dynamically if the key is locked
    if needs_password {
        password = fetch_password_internal(
            channel,
            &target_fpr_for_pwd,
            "Decryption & Verification",
            fetch_pwd_cb,
            free_cb, // Passing the shared free callback
        )?;
    } else {
        debug!("Target secret key is unlocked. Bypassing password callback.");
    }

    // 4. Decrypt outer layer
    let pwd_fn = Password::from(password.as_slice());
    let mut decrypted = parsed_message
        .decrypt(&pwd_fn, &skey)
        .map_err(|_| GfrStatus::ErrorInternal)?;

    // Update recipients
    let subkey_ids: Vec<String> = skey
        .secret_subkeys
        .iter()
        .map(|s| s.key.fingerprint().to_string())
        .collect();

    for rec in &mut recipients {
        if rec.key_id == primary_id || subkey_ids.contains(&rec.key_id) {
            rec.status = GfrRecipientStatus::Success;
        }
    }

    // 5. Decompress if necessary
    if decrypted.is_compressed() {
        decrypted = decrypted
            .decompress()
            .map_err(|_| GfrStatus::ErrorInternal)?;
    }

    // 6. Extract filename from headers BEFORE consuming payload
    let mut filename = String::new();
    if let Some(header) = decrypted.literal_data_header() {
        filename = String::from_utf8_lossy(header.file_name()).to_string();
    }

    let is_signed = decrypted.is_signed();

    // 7. !!! CRITICAL STEP !!!
    // You MUST consume the payload first! This forces the stream reader to reach
    // the end of the message and parse the trailing Signature packets.
    let payload = decrypted
        .as_data_vec()
        .map_err(|_| GfrStatus::ErrorInternal)?;

    // 8. Directly extract parsed signatures from the Message enum
    let mut signatures = Vec::new();
    if let pgp::composed::Message::Signed { ref reader, .. } = decrypted {
        for i in 0..reader.num_signatures() {
            // Because payload is consumed, the trailing signatures are now available
            if let Some(sig) = reader.signature(i) {
                for issuer in sig.issuer_fingerprint() {
                    let fpr = issuer.to_string();
                    let (hash_algo_id, pub_algo_id) = if let Some(config) = sig.config() {
                        (
                            config.hash_alg.to_string(),
                            algo_to_string_simple(config.pub_alg),
                        )
                    } else {
                        (String::new(), String::new())
                    };

                    if !signatures
                        .iter()
                        .any(|r: &SignatureResultInternal| r.fpr == fpr)
                    {
                        signatures.push(SignatureResultInternal {
                            fpr,
                            status: GfrSignatureStatus::NoKey, // Default to NoKey
                            created_at: sig.created().map(|d| d.as_secs() as u32).unwrap_or(0),
                            pub_algo: pub_algo_id,
                            hash_algo: hash_algo_id,
                            sig_type: GfrSignMode::Inline,
                        });
                    }
                }
            }
        }
    }

    // 9. Dynamically Fetch Public Keys via C++ Callback
    let mut certs = Vec::new();
    if let Some(cb) = fetch_pubkey_cb {
        for sig in &signatures {
            let c_fpr = std::ffi::CString::new(sig.fpr.clone()).unwrap_or_default();
            let c_key_block = cb(c_fpr.as_ptr(), user_data);

            if !c_key_block.is_null() {
                if let Ok(key_str) = unsafe { std::ffi::CStr::from_ptr(c_key_block) }.to_str() {
                    if let Ok((cert, _)) = SignedPublicKey::from_string(key_str) {
                        certs.push(cert);
                    }
                }

                // Use the shared free callback to release the public key string memory
                if let Some(f_cb) = free_cb {
                    f_cb(c_key_block as *mut c_void, user_data);
                }
            }
        }
    }

    // 10. Verify Signatures with fetched certs
    let mut is_verified = false;
    if is_signed {
        for cert in &certs {
            let is_cert_valid = decrypted.verify(cert).is_ok();
            for sig in &mut signatures {
                if cert_contains_issuer(cert, &sig.fpr) {
                    sig.status = if is_cert_valid {
                        is_verified = true;
                        GfrSignatureStatus::Valid
                    } else {
                        GfrSignatureStatus::BadSignature
                    };
                }
            }
        }
    }

    Ok(DecryptAndVerifyResultInternal {
        data: payload,
        filename,
        recipients,
        is_verified,
        signatures,
    })
}
