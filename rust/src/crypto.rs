use std::io::{Cursor, Read};

use crate::types::{GfrSignMode, GfrStatus};
use pgp::{
    armor::Dearmor,
    composed::{
        ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, Message,
        MessageBuilder, SignedPublicKey, SignedSecretKey,
    },
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{Packet, PacketParser},
    ser::Serialize,
    types::{KeyDetails, Password},
};
use rand::thread_rng;

pub fn encrypt_text_internal(
    name: &str,
    data: &[u8],
    public_key_blocks: &[&str],
    ascii_armor: bool,
) -> Result<Vec<u8>, GfrStatus> {
    let mut rng = thread_rng();

    // 1. Initialize the builder with SEIPDv1 and AES256
    let mut builder = MessageBuilder::from_bytes(name.as_bytes().to_vec(), data.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    let mut has_recipient = false;

    // 2. Iterate through all provided recipient public key blocks
    for block in public_key_blocks {
        let (cert, _) =
            SignedPublicKey::from_string(block).map_err(|_| GfrStatus::ErrorInvalidInput)?;

        let mut added_for_this_cert = false;

        // 3. Dynamically find a valid encryption subkey
        for subkey in &cert.public_subkeys {
            if subkey.key.algorithm().can_encrypt() {
                builder
                    .encrypt_to_key(&mut rng, subkey)
                    .map_err(|_| GfrStatus::ErrorInternal)?;

                added_for_this_cert = true;
                has_recipient = true;
                break;
            }
        }

        // Fallback to primary key if no encryption subkeys are found
        if !added_for_this_cert && cert.primary_key.algorithm().can_encrypt() {
            builder
                .encrypt_to_key(&mut rng, &cert.primary_key)
                .map_err(|_| GfrStatus::ErrorInternal)?;
            has_recipient = true;
        }
    }

    if !has_recipient {
        return Err(GfrStatus::ErrorInvalidInput);
    }

    // 4. If ASCII armor is requested, output armored string;
    if ascii_armor {
        let armored_str = builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .map_err(|_| GfrStatus::ErrorArmorFailed)?;
        return Ok(armored_str.as_bytes().to_vec());
    }

    // 5. If not ASCII armor, output raw bytes and convert to String (may not be valid UTF-8)
    let raw_str = builder
        .to_vec(&mut rng)
        .map_err(|_| GfrStatus::ErrorInternal)?;
    Ok(raw_str)
}

pub fn decrypt_internal(
    encrypted_data: &[u8],
    secret_key_block: &str,
    password: &str,
) -> Result<(String, Vec<u8>), GfrStatus> {
    // 1. Parse the secret key block
    let (skey, _) =
        SignedSecretKey::from_string(secret_key_block).map_err(|_| GfrStatus::ErrorInvalidInput)?;

    // 2. Try parsing the encrypted data
    // First, try to parse it as an ASCII Armored message
    let parsed_message = if let Ok((msg, _)) = Message::from_armor(Cursor::new(encrypted_data)) {
        msg
    // If armored parsing fails, fallback to binary parsing
    } else if let Ok(msg) = Message::from_bytes(encrypted_data) {
        msg
    } else {
        return Err(GfrStatus::ErrorInvalidInput);
    };

    // 3. Decrypt the message
    // rpgp expects a password provider function and a reference to the secret key
    let pwd_fn = Password::from(password.as_bytes());
    let mut decrypted = parsed_message
        .decrypt(&pwd_fn, &skey)
        .map_err(|_| GfrStatus::ErrorInternal)?;

    // 4. Decompress if necessary
    if decrypted.is_compressed() {
        decrypted = decrypted
            .decompress()
            .map_err(|_| GfrStatus::ErrorInternal)?;
    }

    // 5. Extract the payload and filename
    let payload = decrypted
        .as_data_vec()
        .map_err(|_| GfrStatus::ErrorInternal)?;

    // Attempt to extract the filename if the decrypted message is a LiteralData packet
    let filename = String::new();

    Ok((filename, payload))
}

pub fn get_message_recipients_internal(data: &[u8]) -> Result<String, GfrStatus> {
    let mut key_ids = Vec::new();

    // 1. Try to un-armor the data
    let mut dearmored = Vec::new();
    let mut dearmor_stream = Dearmor::new(Cursor::new(data));

    // Attempt to read. If it fails or finds no armor headers, 'dearmored' remains empty
    let _ = dearmor_stream.read_to_end(&mut dearmored);

    // If it's empty, it means the input is likely already binary (not ASCII armored)
    let payload = if dearmored.is_empty() {
        data
    } else {
        &dearmored
    };

    // 2. Parse the PGP packets sequentially
    let parser = PacketParser::new(Cursor::new(payload));

    for packet_result in parser {
        if let Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) = packet_result {
            // Safely unwrap the Result returned by pkesk.id()
            if let Ok(id) = pkesk.id() {
                // Now `id` is a reference to a KeyId, which can be safely converted to a String
                key_ids.push(id.to_string());
            }
        }
    }

    if key_ids.is_empty() {
        return Err(GfrStatus::ErrorInvalidInput); // Not a valid encrypted message
    }

    // Join them with commas for easy FFI transfer (e.g., "A1B2C3D4E5F6G7H8,8H7G6F5E4D3C2B1A")
    Ok(key_ids.join(","))
}

pub fn sign_internal(
    name: &str,
    data: &[u8],
    secret_key_blocks: &[&str],
    passwords: &[&str],
    mode: GfrSignMode,
    ascii_armor: bool,
) -> Result<Vec<u8>, GfrStatus> {
    if secret_key_blocks.len() != passwords.len() || secret_key_blocks.is_empty() {
        return Err(GfrStatus::ErrorInvalidInput);
    }

    let sign_mode = mode;

    // Cleartext strictly requires valid UTF-8 string data
    if sign_mode == GfrSignMode::ClearText && std::str::from_utf8(data).is_err() {
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

    // 2. Route the operation based on the selected mode
    match sign_mode {
        // ---------------------------------------------------------
        // MODE 0: INLINE SIGNATURE
        // ---------------------------------------------------------
        GfrSignMode::Inline => {
            let mut builder = MessageBuilder::from_bytes(name.as_bytes().to_vec(), data.to_vec());
            let mut at_least_one_signer = false;

            for i in 0..parsed_keys.len() {
                let skey = &parsed_keys[i];
                let mut added_for_this_key = false;

                for subkey in &skey.secret_subkeys {
                    if subkey.key.algorithm().can_sign() {
                        let pwd_fn = Password::from(passwords[i].as_bytes());
                        builder.sign(&subkey.key, pwd_fn, HashAlgorithm::Sha512);
                        added_for_this_key = true;
                        at_least_one_signer = true;
                        break;
                    }
                }

                if !added_for_this_key && skey.primary_key.algorithm().can_sign() {
                    let fallback_pwd = Password::from(passwords[i].as_bytes());
                    builder.sign(&skey.primary_key, fallback_pwd, HashAlgorithm::Sha512);
                    at_least_one_signer = true;
                }
            }

            if !at_least_one_signer {
                return Err(GfrStatus::ErrorInvalidInput);
            }

            if ascii_armor {
                let armored_str = builder
                    .to_armored_string(&mut rng, ArmorOptions::default())
                    .map_err(|_| GfrStatus::ErrorArmorFailed)?;
                return Ok(armored_str.into_bytes());
            }

            let raw_bytes = builder
                .to_vec(&mut rng)
                .map_err(|_| GfrStatus::ErrorInternal)?;
            Ok(raw_bytes)
        }

        GfrSignMode::ClearText => {
            let text = std::str::from_utf8(data).unwrap().to_string();

            // Find the first valid signer and generate the cleartext message
            for i in 0..parsed_keys.len() {
                let skey = &parsed_keys[i];

                for subkey in &skey.secret_subkeys {
                    if subkey.key.algorithm().can_sign() {
                        let pwd = Password::from(passwords[i].as_bytes());
                        // Fix: Pass `&mut rng` as the first argument and `&text` as the second
                        if let Ok(msg) =
                            CleartextSignedMessage::sign(&mut rng, &text, &subkey.key, &pwd)
                        {
                            return Ok(msg
                                .to_armored_string(ArmorOptions::default())
                                .map_err(|_| GfrStatus::ErrorArmorFailed)?
                                .into_bytes());
                        }
                    }
                }

                if skey.primary_key.algorithm().can_sign() {
                    let pwd = Password::from(passwords[i].as_bytes());
                    // Fix: Pass `&mut rng` as the first argument and `&text` as the second
                    if let Ok(msg) =
                        CleartextSignedMessage::sign(&mut rng, &text, &skey.primary_key, &pwd)
                    {
                        return Ok(msg
                            .to_armored_string(ArmorOptions::default())
                            .map_err(|_| GfrStatus::ErrorArmorFailed)?
                            .into_bytes());
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
            for i in 0..parsed_keys.len() {
                let skey = &parsed_keys[i];

                for subkey in &skey.secret_subkeys {
                    if subkey.key.algorithm().can_sign() {
                        let pwd = Password::from(passwords[i].as_bytes());
                        if let Ok(sig) = DetachedSignature::sign_binary_data(
                            &mut rng,
                            &subkey.key,
                            &pwd,
                            HashAlgorithm::Sha512,
                            data,
                        ) {
                            if ascii_armor {
                                let armored = sig
                                    .to_armored_string(None.into())
                                    .map_err(|_| GfrStatus::ErrorArmorFailed)?;
                                return Ok(armored.into_bytes());
                            } else {
                                let raw = sig.to_bytes().map_err(|_| GfrStatus::ErrorInternal)?;
                                return Ok(raw);
                            }
                        }
                    }
                }

                if skey.primary_key.algorithm().can_sign() {
                    let pwd = Password::from(passwords[i].as_bytes());
                    if let Ok(sig) = DetachedSignature::sign_binary_data(
                        &mut rng,
                        &skey.primary_key,
                        &pwd,
                        HashAlgorithm::Sha512,
                        data,
                    ) {
                        if ascii_armor {
                            let armored = sig
                                .to_armored_string(None.into())
                                .map_err(|_| GfrStatus::ErrorArmorFailed)?;
                            return Ok(armored.into_bytes());
                        } else {
                            let raw = sig.to_bytes().map_err(|_| GfrStatus::ErrorInternal)?;
                            return Ok(raw);
                        }
                    }
                }
            }

            Err(GfrStatus::ErrorInvalidInput)
        }
    }
}
