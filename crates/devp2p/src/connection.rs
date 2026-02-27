use k256::ecdsa::SigningKey;
use k256::PublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::constants::{ECIES_OVERHEAD, HANDSHAKE_TIMEOUT};
use crate::crypto::{parse_uncompressed_pubkey, pubkey_to_bytes};
use crate::ecies;
use crate::error::Error;
use crate::frame::FrameCoder;
use crate::handshake;
use crate::session::{HandshakeData, Session, SessionSecrets};

pub async fn connect_as_initiator(
    addr: &str,
    static_key: &SigningKey,
    remote_pubkey: &PublicKey,
) -> Result<Session, Error> {
    let mut stream: TcpStream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Timeout(format!("connection to {} timed out", addr)))?
        .map_err(|e| Error::Handshake(format!("connection to {} failed: {}", addr, e)))?;

    let (auth_eip8, ephemeral_key, nonce) =
        send_auth(&mut stream, static_key, remote_pubkey).await?;
    let (ack_eip8, ack_msg) = receive_ack(&mut stream, static_key).await?;

    debug!(addr, "handshake OK (initiator)");

    let handshake_data = HandshakeData {
        ephemeral_key,
        initiator_nonce: nonce,
        recipient_nonce: ack_msg.recipient_nonce,
        recipient_ephemeral_pubkey: ack_msg.recipient_ephemeral_pubkey,
        auth_message: auth_eip8,
        ack_message: ack_eip8,
    };

    let secrets = SessionSecrets::derive(&handshake_data)?;

    let coder = FrameCoder::new(
        secrets.aes_secret,
        secrets.mac_secret,
        secrets.egress_mac,
        secrets.ingress_mac,
    );

    let remote_pubkey_bytes = pubkey_to_bytes(remote_pubkey);

    Ok(Session::new(stream, coder, remote_pubkey_bytes))
}

pub async fn accept_as_responder(
    mut stream: TcpStream,
    static_key: &SigningKey,
) -> Result<Session, Error> {
    let mut size_buf: [u8; 2] = [0u8; 2];
    timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut size_buf))
        .await
        .map_err(|_| Error::Handshake("handshake timeout reading auth size".to_string()))?
        .map_err(|e| Error::Handshake(format!("failed to read auth size: {}", e)))?;

    let auth_size: u16 = u16::from_be_bytes(size_buf);
    let mut auth_encrypted: Vec<u8> = vec![0u8; auth_size as usize];
    timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut auth_encrypted))
        .await
        .map_err(|_| Error::Handshake("handshake timeout reading auth message".to_string()))?
        .map_err(|e| Error::Handshake(format!("failed to read auth message: {}", e)))?;

    let mut auth_eip8: Vec<u8> = Vec::new();
    auth_eip8.extend_from_slice(&size_buf);
    auth_eip8.extend_from_slice(&auth_encrypted);

    let auth_decrypted = ecies::decrypt(static_key, &auth_encrypted, Some(&size_buf))?;

    let auth_msg = handshake::AuthMessage::from_rlp(&auth_decrypted)?;

    let ephemeral_key: SigningKey = SigningKey::random(&mut rand::thread_rng());
    let ack_msg = handshake::create_ack_message(&ephemeral_key);

    let ack_eip8 = send_ack(&mut stream, &ack_msg, &auth_msg.initiator_pubkey).await?;

    let addr = stream
        .peer_addr()
        .map_or("unknown".to_string(), |a| a.to_string());
    debug!(addr, "handshake OK (responder)");

    let handshake_data = HandshakeData {
        ephemeral_key,
        initiator_nonce: auth_msg.nonce,
        recipient_nonce: ack_msg.recipient_nonce,
        recipient_ephemeral_pubkey: recover_ephemeral_pubkey(&auth_msg, static_key)?,
        auth_message: auth_eip8,
        ack_message: ack_eip8,
    };

    let secrets = SessionSecrets::derive_as_responder(&handshake_data)?;

    let coder = FrameCoder::new(
        secrets.aes_secret,
        secrets.mac_secret,
        secrets.egress_mac,
        secrets.ingress_mac,
    );

    Ok(Session::new(stream, coder, auth_msg.initiator_pubkey))
}

async fn send_auth(
    stream: &mut TcpStream,
    static_key: &SigningKey,
    remote_pubkey: &PublicKey,
) -> Result<(Vec<u8>, SigningKey, [u8; 32]), Error> {
    let ephemeral_key: SigningKey = SigningKey::random(&mut rand::thread_rng());
    let nonce: [u8; 32] = handshake::generate_nonce();

    let auth_message =
        handshake::create_auth_message(static_key, &ephemeral_key, remote_pubkey, &nonce)?;
    let auth_rlp: Vec<u8> = auth_message.to_rlp();

    let mut padding: [u8; 100] = [0u8; 100];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);

    let mut auth_body: Vec<u8> = auth_rlp;
    auth_body.extend_from_slice(&padding);

    let size: u16 = (auth_body.len() + ECIES_OVERHEAD) as u16;
    let size_bytes: [u8; 2] = size.to_be_bytes();

    let encrypted: Vec<u8> = ecies::encrypt(remote_pubkey, &auth_body, Some(&size_bytes));

    let mut auth_eip8: Vec<u8> = Vec::new();
    auth_eip8.extend_from_slice(&size_bytes);
    auth_eip8.extend_from_slice(&encrypted);

    stream.write_all(&auth_eip8).await?;

    Ok((auth_eip8, ephemeral_key, nonce))
}

async fn receive_ack(
    stream: &mut TcpStream,
    static_key: &SigningKey,
) -> Result<(Vec<u8>, handshake::AckMessage), Error> {
    let mut size_buf: [u8; 2] = [0u8; 2];
    timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut size_buf))
        .await
        .map_err(|_| Error::Handshake("handshake timeout reading ack size".to_string()))?
        .map_err(|e| Error::Handshake(format!("failed to read ack size: {}", e)))?;

    let ack_size: u16 = u16::from_be_bytes(size_buf);
    let mut ack_encrypted: Vec<u8> = vec![0u8; ack_size as usize];
    timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut ack_encrypted))
        .await
        .map_err(|_| Error::Handshake("handshake timeout reading ack message".to_string()))?
        .map_err(|e| Error::Handshake(format!("failed to read ack message: {}", e)))?;

    let mut ack_eip8: Vec<u8> = Vec::new();
    ack_eip8.extend_from_slice(&size_buf);
    ack_eip8.extend_from_slice(&ack_encrypted);

    let ack_decrypted = ecies::decrypt(static_key, &ack_encrypted, Some(&size_buf))?;

    let ack_msg = handshake::AckMessage::from_rlp(&ack_decrypted)?;

    Ok((ack_eip8, ack_msg))
}

async fn send_ack(
    stream: &mut TcpStream,
    ack_msg: &handshake::AckMessage,
    remote_pubkey_bytes: &[u8; 64],
) -> Result<Vec<u8>, Error> {
    let remote_pubkey = parse_uncompressed_pubkey(remote_pubkey_bytes)
        .map_err(|_| Error::Handshake("invalid remote pubkey".to_string()))?;

    let ack_rlp: Vec<u8> = ack_msg.to_rlp();

    let mut padding: [u8; 100] = [0u8; 100];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);

    let mut ack_body: Vec<u8> = ack_rlp;
    ack_body.extend_from_slice(&padding);

    let size: u16 = (ack_body.len() + ECIES_OVERHEAD) as u16;
    let size_bytes: [u8; 2] = size.to_be_bytes();

    let encrypted: Vec<u8> = ecies::encrypt(&remote_pubkey, &ack_body, Some(&size_bytes));

    let mut ack_eip8: Vec<u8> = Vec::new();
    ack_eip8.extend_from_slice(&size_bytes);
    ack_eip8.extend_from_slice(&encrypted);

    stream.write_all(&ack_eip8).await?;

    Ok(ack_eip8)
}

fn recover_ephemeral_pubkey(
    auth_msg: &handshake::AuthMessage,
    static_key: &SigningKey,
) -> Result<[u8; 64], Error> {
    use k256::ecdh::diffie_hellman;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let initiator_pubkey = parse_uncompressed_pubkey(&auth_msg.initiator_pubkey)
        .map_err(|_| Error::Handshake("invalid initiator pubkey".to_string()))?;
    let shared_secret =
        diffie_hellman(static_key.as_nonzero_scalar(), initiator_pubkey.as_affine());
    let shared_bytes: &[u8] = shared_secret.raw_secret_bytes();

    let mut message: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        message[i] = shared_bytes[i] ^ auth_msg.nonce[i];
    }

    let sig_bytes: &[u8; 64] = auth_msg.signature[..64]
        .try_into()
        .map_err(|_| Error::Handshake("invalid signature length".to_string()))?;
    let signature = Signature::from_slice(sig_bytes)
        .map_err(|e| Error::Handshake(format!("invalid signature: {}", e)))?;

    let recovery_id = RecoveryId::try_from(auth_msg.signature[64])
        .map_err(|e| Error::Handshake(format!("invalid recovery id: {}", e)))?;

    let recovered_key = VerifyingKey::recover_from_prehash(&message, &signature, recovery_id)
        .map_err(|e| Error::Handshake(format!("failed to recover pubkey: {}", e)))?;

    Ok(pubkey_to_bytes(&recovered_key.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_initiator_responder_handshake() {
        let initiator_key = SigningKey::random(&mut rand::thread_rng());
        let responder_key = SigningKey::random(&mut rand::thread_rng());

        let responder_pubkey: PublicKey = responder_key.verifying_key().into();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept_as_responder(stream, &responder_key).await.unwrap()
        });

        let mut initiator_session =
            connect_as_initiator(&addr.to_string(), &initiator_key, &responder_pubkey)
                .await
                .unwrap();

        let mut responder_session = responder_handle.await.unwrap();

        // Test bidirectional message exchange
        initiator_session
            .write_message(0x10, b"hello from initiator")
            .await
            .unwrap();

        let (msg_id, payload) = responder_session.read_message().await.unwrap();
        assert_eq!(msg_id, 0x10);
        assert_eq!(payload, b"hello from initiator");

        responder_session
            .write_message(0x11, b"hello from responder")
            .await
            .unwrap();

        let (msg_id, payload) = initiator_session.read_message().await.unwrap();
        assert_eq!(msg_id, 0x11);
        assert_eq!(payload, b"hello from responder");
    }
}
