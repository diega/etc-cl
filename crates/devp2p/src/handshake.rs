use k256::ecdsa::SigningKey;
use k256::PublicKey;
use rand::RngCore;

use crate::crypto::ecdh;
use crate::error::Error;
use crate::rlp;

pub const AUTH_VSN: u8 = 4;

pub struct AckMessage {
    pub recipient_ephemeral_pubkey: [u8; 64],
    pub recipient_nonce: [u8; 32],
    pub version: u8,
}

impl AckMessage {
    pub fn from_rlp(data: &[u8]) -> Result<AckMessage, Error> {
        let items: Vec<rlp::RlpItem> = rlp::decode(data)?.into_list()?;

        if items.len() < 3 {
            return Err(Error::Handshake("ack message missing fields".to_string()));
        }

        let pubkey_bytes: Vec<u8> = items[0].clone().into_bytes()?;
        let nonce_bytes: Vec<u8> = items[1].clone().into_bytes()?;
        let version_bytes: Vec<u8> = items[2].clone().into_bytes()?;

        if pubkey_bytes.len() != 64 {
            return Err(Error::Handshake(
                "invalid ephemeral pubkey length".to_string(),
            ));
        }

        if nonce_bytes.len() != 32 {
            return Err(Error::Handshake("invalid nonce length".to_string()));
        }

        let mut recipient_ephemeral_pubkey: [u8; 64] = [0u8; 64];
        recipient_ephemeral_pubkey.copy_from_slice(&pubkey_bytes);

        let mut recipient_nonce: [u8; 32] = [0u8; 32];
        recipient_nonce.copy_from_slice(&nonce_bytes);

        let version: u8 = if version_bytes.is_empty() {
            0
        } else {
            version_bytes[0]
        };

        Ok(AckMessage {
            recipient_ephemeral_pubkey,
            recipient_nonce,
            version,
        })
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let version_bytes: [u8; 1] = [self.version];
        rlp::encode_list(&[
            &self.recipient_ephemeral_pubkey[..],
            &self.recipient_nonce[..],
            &version_bytes[..],
        ])
    }
}

pub fn create_ack_message(ephemeral_key: &SigningKey) -> AckMessage {
    let ephemeral_pubkey = ephemeral_key.verifying_key();
    let ephemeral_pubkey_point = ephemeral_pubkey.to_encoded_point(false);
    let ephemeral_pubkey_bytes: &[u8] = ephemeral_pubkey_point.as_bytes();

    let mut recipient_ephemeral_pubkey: [u8; 64] = [0u8; 64];
    recipient_ephemeral_pubkey.copy_from_slice(&ephemeral_pubkey_bytes[1..65]);

    let recipient_nonce: [u8; 32] = generate_nonce();

    AckMessage {
        recipient_ephemeral_pubkey,
        recipient_nonce,
        version: AUTH_VSN,
    }
}

pub struct AuthMessage {
    pub signature: [u8; 65],
    pub initiator_pubkey: [u8; 64],
    pub nonce: [u8; 32],
    pub version: u8,
}

impl AuthMessage {
    pub fn from_rlp(data: &[u8]) -> Result<AuthMessage, Error> {
        let items: Vec<rlp::RlpItem> = rlp::decode(data)?.into_list()?;

        if items.len() < 4 {
            return Err(Error::Handshake("auth message missing fields".to_string()));
        }

        let sig_bytes: Vec<u8> = items[0].clone().into_bytes()?;
        let pubkey_bytes: Vec<u8> = items[1].clone().into_bytes()?;
        let nonce_bytes: Vec<u8> = items[2].clone().into_bytes()?;
        let version_bytes: Vec<u8> = items[3].clone().into_bytes()?;

        if sig_bytes.len() != 65 {
            return Err(Error::Handshake("invalid signature length".to_string()));
        }

        if pubkey_bytes.len() != 64 {
            return Err(Error::Handshake(
                "invalid initiator pubkey length".to_string(),
            ));
        }

        if nonce_bytes.len() != 32 {
            return Err(Error::Handshake("invalid nonce length".to_string()));
        }

        let mut signature: [u8; 65] = [0u8; 65];
        signature.copy_from_slice(&sig_bytes);

        let mut initiator_pubkey: [u8; 64] = [0u8; 64];
        initiator_pubkey.copy_from_slice(&pubkey_bytes);

        let mut nonce: [u8; 32] = [0u8; 32];
        nonce.copy_from_slice(&nonce_bytes);

        let version: u8 = if version_bytes.is_empty() {
            0
        } else {
            version_bytes[0]
        };

        Ok(AuthMessage {
            signature,
            initiator_pubkey,
            nonce,
            version,
        })
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let version_bytes: [u8; 1] = [self.version];
        rlp::encode_list(&[
            &self.signature[..],
            &self.initiator_pubkey[..],
            &self.nonce[..],
            &version_bytes[..],
        ])
    }
}

pub fn parse_enode_pubkey(enode_url: &str) -> Result<PublicKey, Error> {
    let parsed: url::Url = url::Url::parse(enode_url)
        .map_err(|e| Error::Handshake(format!("invalid enode URL: {}", e)))?;
    let pubkey_hex: &str = parsed.username();

    if pubkey_hex.is_empty() {
        return Err(Error::Handshake("enode URL missing public key".to_string()));
    }

    let pubkey_bytes: Vec<u8> = hex::decode(pubkey_hex)
        .map_err(|e| Error::Handshake(format!("invalid public key hex: {}", e)))?;

    if pubkey_bytes.len() != 64 {
        return Err(Error::Handshake(format!(
            "public key must be 64 bytes, got {}",
            pubkey_bytes.len()
        )));
    }

    let mut uncompressed: [u8; 65] = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..].copy_from_slice(&pubkey_bytes);

    PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| Error::Handshake(format!("invalid public key: {}", e)))
}

pub fn generate_nonce() -> [u8; 32] {
    let mut nonce: [u8; 32] = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn create_auth_message(
    static_key: &SigningKey,
    ephemeral_key: &SigningKey,
    remote_pubkey: &PublicKey,
    nonce: &[u8; 32],
) -> Result<AuthMessage, Error> {
    let static_pubkey = static_key.verifying_key();
    let static_pubkey_point = static_pubkey.to_encoded_point(false);
    let static_pubkey_bytes: &[u8] = static_pubkey_point.as_bytes();

    let mut initiator_pubkey: [u8; 64] = [0u8; 64];
    initiator_pubkey.copy_from_slice(&static_pubkey_bytes[1..65]);

    let shared_secret: [u8; 32] = ecdh(static_key, remote_pubkey);

    let mut xor_result: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        xor_result[i] = shared_secret[i] ^ nonce[i];
    }

    let signature: [u8; 65] = sign_message(ephemeral_key, &xor_result)?;

    Ok(AuthMessage {
        signature,
        initiator_pubkey,
        nonce: *nonce,
        version: AUTH_VSN,
    })
}

fn sign_message(key: &SigningKey, message: &[u8; 32]) -> Result<[u8; 65], Error> {
    use k256::ecdsa::Signature;

    let (sig, recid): (Signature, _) = key
        .sign_prehash_recoverable(message)
        .map_err(|e| Error::Handshake(format!("signing failed: {}", e)))?;

    let mut result: [u8; 65] = [0u8; 65];
    result[..64].copy_from_slice(sig.to_bytes().as_ref());
    result[64] = recid.to_byte();
    Ok(result)
}
