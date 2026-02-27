use k256::ecdsa::SigningKey;
use k256::PublicKey;
use sha3::{Digest, Keccak256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::constants::{FRAME_HEADER_SIZE, FRAME_HEADER_WITH_MAC_SIZE, FRAME_MAC_SIZE};
use crate::crypto::{ecdh, parse_uncompressed_pubkey};
use crate::error::Error;
use crate::frame::FrameCoder;
use crate::p2p;

enum ReadState {
    Header {
        buffer: [u8; FRAME_HEADER_WITH_MAC_SIZE],
        read: usize,
    },
    Body {
        frame_size: usize,
        buffer: Vec<u8>,
        read: usize,
    },
}

pub struct Session {
    pub stream: TcpStream,
    pub coder: FrameCoder,
    pub remote_pubkey: [u8; 64],
    read_state: ReadState,
}

impl Session {
    pub fn new(stream: TcpStream, coder: FrameCoder, remote_pubkey: [u8; 64]) -> Session {
        Session {
            stream,
            coder,
            remote_pubkey,
            read_state: ReadState::Header {
                buffer: [0u8; FRAME_HEADER_WITH_MAC_SIZE],
                read: 0,
            },
        }
    }

    pub async fn write_message(&mut self, msg_id: u8, payload: &[u8]) -> Result<(), Error> {
        let msg: Vec<u8> = p2p::encode_message(msg_id, payload);
        let frame: Vec<u8> = self.coder.encode_frame(&msg);
        self.stream.write_all(&frame).await.map_err(Error::from)
    }

    pub async fn read_message(&mut self) -> Result<(u8, Vec<u8>), Error> {
        // Phase 1: Read header
        let _frame_size = match &mut self.read_state {
            ReadState::Header { buffer, read } => {
                while *read < FRAME_HEADER_WITH_MAC_SIZE {
                    let n = self.stream.read(&mut buffer[*read..]).await?;
                    if n == 0 {
                        return Err(Error::ConnectionClosed);
                    }
                    *read += n;
                }

                let frame_size = self.coder.decode_header(buffer)?;

                let padding_len =
                    (FRAME_HEADER_SIZE - (frame_size % FRAME_HEADER_SIZE)) % FRAME_HEADER_SIZE;
                let padded_size = frame_size + padding_len + FRAME_MAC_SIZE;
                self.read_state = ReadState::Body {
                    frame_size,
                    buffer: vec![0u8; padded_size],
                    read: 0,
                };

                frame_size
            }
            ReadState::Body { frame_size, .. } => *frame_size,
        };

        // Phase 2: Read frame body
        let frame_data = match &mut self.read_state {
            ReadState::Body {
                frame_size,
                buffer,
                read,
            } => {
                let total = buffer.len();
                while *read < total {
                    let n = self.stream.read(&mut buffer[*read..]).await?;
                    if n == 0 {
                        return Err(Error::ConnectionClosed);
                    }
                    *read += n;
                }

                self.coder.decode_frame(buffer, *frame_size)?
            }
            ReadState::Header { .. } => unreachable!(),
        };

        // Reset state for next message
        self.read_state = ReadState::Header {
            buffer: [0u8; FRAME_HEADER_WITH_MAC_SIZE],
            read: 0,
        };

        let (msg_id, payload) = p2p::decode_message(&frame_data)?;

        Ok((msg_id, payload.to_vec()))
    }
}

pub struct SessionSecrets {
    pub aes_secret: [u8; 32],
    pub mac_secret: [u8; 32],
    pub egress_mac: Keccak256,
    pub ingress_mac: Keccak256,
}

pub struct HandshakeData {
    pub ephemeral_key: SigningKey,
    pub initiator_nonce: [u8; 32],
    pub recipient_nonce: [u8; 32],
    pub recipient_ephemeral_pubkey: [u8; 64],
    pub auth_message: Vec<u8>,
    pub ack_message: Vec<u8>,
}

impl SessionSecrets {
    pub fn derive(data: &HandshakeData) -> Result<SessionSecrets, Error> {
        let remote_ephemeral: PublicKey =
            parse_uncompressed_pubkey(&data.recipient_ephemeral_pubkey)
                .map_err(|_| Error::Session("invalid remote ephemeral pubkey".to_string()))?;

        let ephemeral_shared_secret: [u8; 32] = ecdh(&data.ephemeral_key, &remote_ephemeral);

        let nonce_hash: [u8; 32] =
            keccak256_concat(&[&data.recipient_nonce, &data.initiator_nonce]);

        let shared_secret: [u8; 32] = keccak256_concat(&[&ephemeral_shared_secret, &nonce_hash]);

        let aes_secret: [u8; 32] = keccak256_concat(&[&ephemeral_shared_secret, &shared_secret]);

        let mac_secret: [u8; 32] = keccak256_concat(&[&ephemeral_shared_secret, &aes_secret]);

        let mut xor_egress: [u8; 32] = [0u8; 32];
        for i in 0..32 {
            xor_egress[i] = mac_secret[i] ^ data.recipient_nonce[i];
        }

        let mut egress_mac: Keccak256 = Keccak256::new();
        egress_mac.update(xor_egress);
        egress_mac.update(&data.auth_message);

        let mut xor_ingress: [u8; 32] = [0u8; 32];
        for i in 0..32 {
            xor_ingress[i] = mac_secret[i] ^ data.initiator_nonce[i];
        }

        let mut ingress_mac: Keccak256 = Keccak256::new();
        ingress_mac.update(xor_ingress);
        ingress_mac.update(&data.ack_message);

        Ok(SessionSecrets {
            aes_secret,
            mac_secret,
            egress_mac,
            ingress_mac,
        })
    }

    pub fn derive_as_responder(data: &HandshakeData) -> Result<SessionSecrets, Error> {
        let remote_ephemeral: PublicKey =
            parse_uncompressed_pubkey(&data.recipient_ephemeral_pubkey)
                .map_err(|_| Error::Session("invalid remote ephemeral pubkey".to_string()))?;

        let ephemeral_shared_secret: [u8; 32] = ecdh(&data.ephemeral_key, &remote_ephemeral);

        let nonce_hash: [u8; 32] =
            keccak256_concat(&[&data.recipient_nonce, &data.initiator_nonce]);

        let shared_secret: [u8; 32] = keccak256_concat(&[&ephemeral_shared_secret, &nonce_hash]);

        let aes_secret: [u8; 32] = keccak256_concat(&[&ephemeral_shared_secret, &shared_secret]);

        let mac_secret: [u8; 32] = keccak256_concat(&[&ephemeral_shared_secret, &aes_secret]);

        // As responder, roles are inverted
        let mut xor_egress: [u8; 32] = [0u8; 32];
        for i in 0..32 {
            xor_egress[i] = mac_secret[i] ^ data.initiator_nonce[i];
        }

        let mut egress_mac: Keccak256 = Keccak256::new();
        egress_mac.update(xor_egress);
        egress_mac.update(&data.ack_message);

        let mut xor_ingress: [u8; 32] = [0u8; 32];
        for i in 0..32 {
            xor_ingress[i] = mac_secret[i] ^ data.recipient_nonce[i];
        }

        let mut ingress_mac: Keccak256 = Keccak256::new();
        ingress_mac.update(xor_ingress);
        ingress_mac.update(&data.auth_message);

        Ok(SessionSecrets {
            aes_secret,
            mac_secret,
            egress_mac,
            ingress_mac,
        })
    }
}

fn keccak256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher: Keccak256 = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}
