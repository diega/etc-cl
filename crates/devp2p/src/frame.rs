use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes256, Aes256Enc};
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha3::{Digest, Keccak256};

use crate::constants::{
    FRAME_HEADER_SIZE, FRAME_MAC_SIZE, MAX_FRAME_SIZE, RLP_EMPTY_BYTES, RLP_EMPTY_LIST_2,
};
use crate::error::Error;

type Aes256Ctr = ctr::Ctr64BE<Aes256>;

pub struct FrameCoder {
    mac_secret: [u8; 32],
    egress_mac: Keccak256,
    ingress_mac: Keccak256,
    egress_aes: Aes256Ctr,
    ingress_aes: Aes256Ctr,
}

impl FrameCoder {
    pub fn new(
        aes_secret: [u8; 32],
        mac_secret: [u8; 32],
        egress_mac: Keccak256,
        ingress_mac: Keccak256,
    ) -> FrameCoder {
        let zero_iv: [u8; 16] = [0u8; 16];

        let egress_aes: Aes256Ctr = Aes256Ctr::new(&aes_secret.into(), &zero_iv.into());
        let ingress_aes: Aes256Ctr = Aes256Ctr::new(&aes_secret.into(), &zero_iv.into());

        FrameCoder {
            mac_secret,
            egress_mac,
            ingress_mac,
            egress_aes,
            ingress_aes,
        }
    }

    pub fn encode_frame(&mut self, data: &[u8]) -> Vec<u8> {
        let frame_size: usize = data.len();

        let mut header: [u8; FRAME_HEADER_SIZE] = [0u8; FRAME_HEADER_SIZE];
        header[0] = ((frame_size >> 16) & 0xff) as u8;
        header[1] = ((frame_size >> 8) & 0xff) as u8;
        header[2] = (frame_size & 0xff) as u8;
        header[3] = RLP_EMPTY_LIST_2;
        header[4] = RLP_EMPTY_BYTES;
        header[5] = RLP_EMPTY_BYTES;

        self.egress_aes.apply_keystream(&mut header);

        let header_mac: [u8; FRAME_MAC_SIZE] =
            update_header_mac(&self.mac_secret, &mut self.egress_mac, &header);

        let padding_len: usize =
            (FRAME_HEADER_SIZE - (frame_size % FRAME_HEADER_SIZE)) % FRAME_HEADER_SIZE;
        let mut frame_data: Vec<u8> = data.to_vec();
        frame_data.resize(frame_size + padding_len, 0);

        self.egress_aes.apply_keystream(&mut frame_data);

        let frame_mac: [u8; FRAME_MAC_SIZE] =
            update_body_mac(&self.mac_secret, &mut self.egress_mac, &frame_data);

        let mut result: Vec<u8> = Vec::with_capacity(
            FRAME_HEADER_SIZE + FRAME_MAC_SIZE + frame_data.len() + FRAME_MAC_SIZE,
        );
        result.extend_from_slice(&header);
        result.extend_from_slice(&header_mac);
        result.extend_from_slice(&frame_data);
        result.extend_from_slice(&frame_mac);

        result
    }

    pub fn decode_header(&mut self, data: &[u8]) -> Result<usize, Error> {
        if data.len() < FRAME_HEADER_SIZE + FRAME_MAC_SIZE {
            return Err(Error::Frame("header too short".to_string()));
        }

        let mut header: [u8; FRAME_HEADER_SIZE] = [0u8; FRAME_HEADER_SIZE];
        header.copy_from_slice(&data[0..FRAME_HEADER_SIZE]);

        let received_mac: &[u8] = &data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + FRAME_MAC_SIZE];

        let expected_mac: [u8; FRAME_MAC_SIZE] =
            update_header_mac(&self.mac_secret, &mut self.ingress_mac, &header);

        if received_mac != expected_mac {
            return Err(Error::Frame("header MAC mismatch".to_string()));
        }

        self.ingress_aes.apply_keystream(&mut header);

        let frame_size: usize =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | (header[2] as usize);

        if frame_size > MAX_FRAME_SIZE {
            return Err(Error::FrameTooLarge(frame_size));
        }

        Ok(frame_size)
    }

    pub fn decode_frame(&mut self, data: &[u8], frame_size: usize) -> Result<Vec<u8>, Error> {
        let padding_len: usize =
            (FRAME_HEADER_SIZE - (frame_size % FRAME_HEADER_SIZE)) % FRAME_HEADER_SIZE;
        let padded_size: usize = frame_size + padding_len;

        if data.len() < padded_size + FRAME_MAC_SIZE {
            return Err(Error::Frame("frame data too short".to_string()));
        }

        let mut frame_data: Vec<u8> = data[0..padded_size].to_vec();
        let received_mac: &[u8] = &data[padded_size..padded_size + FRAME_MAC_SIZE];

        let expected_mac: [u8; FRAME_MAC_SIZE] =
            update_body_mac(&self.mac_secret, &mut self.ingress_mac, &frame_data);

        if received_mac != expected_mac {
            return Err(Error::Frame("frame MAC mismatch".to_string()));
        }

        self.ingress_aes.apply_keystream(&mut frame_data);

        frame_data.truncate(frame_size);

        Ok(frame_data)
    }
}

fn update_header_mac(
    mac_secret: &[u8; 32],
    mac_state: &mut Keccak256,
    header: &[u8; FRAME_HEADER_SIZE],
) -> [u8; FRAME_MAC_SIZE] {
    let mac_cipher: Aes256Enc = Aes256Enc::new(mac_secret.into());

    let current_digest: [u8; 32] = mac_state.clone().finalize().into();

    let mut seed: [u8; FRAME_MAC_SIZE] = [0u8; FRAME_MAC_SIZE];
    seed.copy_from_slice(&current_digest[0..FRAME_MAC_SIZE]);

    mac_cipher.encrypt_block((&mut seed).into());

    for i in 0..FRAME_HEADER_SIZE {
        seed[i] ^= header[i];
    }

    mac_state.update(seed);

    let final_digest: [u8; 32] = mac_state.clone().finalize().into();

    let mut result: [u8; FRAME_MAC_SIZE] = [0u8; FRAME_MAC_SIZE];
    result.copy_from_slice(&final_digest[0..FRAME_MAC_SIZE]);

    result
}

fn update_body_mac(
    mac_secret: &[u8; 32],
    mac_state: &mut Keccak256,
    frame_data: &[u8],
) -> [u8; FRAME_MAC_SIZE] {
    mac_state.update(frame_data);

    let mac_cipher: Aes256Enc = Aes256Enc::new(mac_secret.into());

    let current_digest: [u8; 32] = mac_state.clone().finalize().into();
    let mut seed: [u8; FRAME_MAC_SIZE] = [0u8; FRAME_MAC_SIZE];
    seed.copy_from_slice(&current_digest[0..FRAME_MAC_SIZE]);

    mac_cipher.encrypt_block((&mut seed).into());

    for i in 0..FRAME_MAC_SIZE {
        seed[i] ^= current_digest[i];
    }

    mac_state.update(seed);

    let final_digest: [u8; 32] = mac_state.clone().finalize().into();
    let mut result: [u8; FRAME_MAC_SIZE] = [0u8; FRAME_MAC_SIZE];
    result.copy_from_slice(&final_digest[0..FRAME_MAC_SIZE]);

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Keccak256;

    #[test]
    fn test_frame_roundtrip() {
        let aes_secret = [0x42u8; 32];
        let mac_secret = [0x43u8; 32];

        let mut encoder =
            FrameCoder::new(aes_secret, mac_secret, Keccak256::new(), Keccak256::new());

        // Decoder's ingress must match encoder's egress
        let mut decoder =
            FrameCoder::new(aes_secret, mac_secret, Keccak256::new(), Keccak256::new());

        let payload = b"hello, devp2p world!";
        let frame = encoder.encode_frame(payload);

        let frame_size = decoder
            .decode_header(&frame[..FRAME_HEADER_SIZE + FRAME_MAC_SIZE])
            .unwrap();
        assert_eq!(frame_size, payload.len());

        let decoded = decoder
            .decode_frame(&frame[FRAME_HEADER_SIZE + FRAME_MAC_SIZE..], frame_size)
            .unwrap();
        assert_eq!(decoded, payload);
    }
}
