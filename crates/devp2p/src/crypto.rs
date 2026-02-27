use k256::ecdh::diffie_hellman;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;

pub fn pubkey_to_node_id(signing_key: &SigningKey) -> [u8; 64] {
    let public_key: PublicKey = signing_key.verifying_key().into();
    let pubkey_point = public_key.to_encoded_point(false);
    let mut node_id = [0u8; 64];
    node_id.copy_from_slice(&pubkey_point.as_bytes()[1..65]);
    node_id
}

pub fn ecdh(private_key: &SigningKey, public_key: &PublicKey) -> [u8; 32] {
    let shared = diffie_hellman(private_key.as_nonzero_scalar(), public_key.as_affine());
    let bytes: &[u8] = shared.raw_secret_bytes();

    let mut result: [u8; 32] = [0u8; 32];
    result.copy_from_slice(bytes);
    result
}

pub fn parse_uncompressed_pubkey(bytes: &[u8; 64]) -> Result<PublicKey, &'static str> {
    let mut uncompressed: [u8; 65] = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..].copy_from_slice(bytes);
    PublicKey::from_sec1_bytes(&uncompressed).map_err(|_| "invalid public key")
}

pub fn pubkey_to_bytes(pubkey: &PublicKey) -> [u8; 64] {
    let point = pubkey.to_encoded_point(false);
    let bytes: &[u8] = point.as_bytes();
    let mut result: [u8; 64] = [0u8; 64];
    result.copy_from_slice(&bytes[1..65]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_to_node_id_roundtrip() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let node_id = pubkey_to_node_id(&key);
        let pubkey = parse_uncompressed_pubkey(&node_id).unwrap();
        let back = pubkey_to_bytes(&pubkey);
        assert_eq!(node_id, back);
    }

    #[test]
    fn test_ecdh_shared_secret() {
        let key_a = SigningKey::random(&mut rand::thread_rng());
        let key_b = SigningKey::random(&mut rand::thread_rng());

        let pub_a: PublicKey = key_a.verifying_key().into();
        let pub_b: PublicKey = key_b.verifying_key().into();

        let secret_ab = ecdh(&key_a, &pub_b);
        let secret_ba = ecdh(&key_b, &pub_a);

        assert_eq!(secret_ab, secret_ba);
    }
}
