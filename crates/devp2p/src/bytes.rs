pub fn encode_u16(value: u16) -> Vec<u8> {
    if value == 0 {
        vec![]
    } else if value < 256 {
        vec![value as u8]
    } else {
        value.to_be_bytes().to_vec()
    }
}

pub fn decode_u16(bytes: &[u8]) -> u16 {
    match bytes.len() {
        0 => 0,
        1 => bytes[0] as u16,
        _ => ((bytes[0] as u16) << 8) | (bytes[1] as u16),
    }
}

pub fn encode_u32(value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let bytes: [u8; 4] = value.to_be_bytes();
    let start: usize = bytes.iter().position(|&b| b != 0).unwrap_or(4);
    bytes[start..].to_vec()
}

pub fn decode_u32(bytes: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for &b in bytes {
        result = (result << 8) | (b as u32);
    }
    result
}

pub fn encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let bytes: [u8; 8] = value.to_be_bytes();
    let start: usize = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    bytes[start..].to_vec()
}

pub fn decode_u64(bytes: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for &b in bytes {
        result = (result << 8) | (b as u64);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u16_roundtrip() {
        for v in [0u16, 1, 127, 128, 255, 256, 30303, u16::MAX] {
            assert_eq!(decode_u16(&encode_u16(v)), v);
        }
    }

    #[test]
    fn test_u32_roundtrip() {
        for v in [0u32, 1, 255, 256, 65536, 1_000_000, u32::MAX] {
            assert_eq!(decode_u32(&encode_u32(v)), v);
        }
    }

    #[test]
    fn test_u64_roundtrip() {
        for v in [0u64, 1, 255, 65536, 1_000_000_000, u64::MAX] {
            assert_eq!(decode_u64(&encode_u64(v)), v);
        }
    }

    #[test]
    fn test_zero_encoding() {
        assert!(encode_u16(0).is_empty());
        assert!(encode_u32(0).is_empty());
        assert!(encode_u64(0).is_empty());
    }

    #[test]
    fn test_minimal_encoding() {
        assert_eq!(encode_u16(1), vec![1]);
        assert_eq!(encode_u32(1), vec![1]);
        assert_eq!(encode_u64(1), vec![1]);
        assert_eq!(encode_u16(255), vec![255]);
        assert_eq!(encode_u16(256), vec![1, 0]);
    }
}
