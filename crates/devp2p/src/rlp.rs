use crate::error::Error;

const MAX_RLP_DEPTH: usize = 16;

mod consts {
    pub const SINGLE_BYTE_MAX: u8 = 0x7f;
    pub const SHORT_STRING_PREFIX: u8 = 0x80;
    pub const LONG_STRING_PREFIX: u8 = 0xb7;
    pub const SHORT_STRING_MAX: u8 = 0xb7;
    pub const LONG_STRING_MAX: u8 = 0xbf;
    pub const SHORT_LIST_PREFIX: u8 = 0xc0;
    pub const LONG_LIST_PREFIX: u8 = 0xf7;
}

#[derive(Debug, Clone, PartialEq)]
pub enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

impl RlpItem {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RlpItem::Bytes(bytes) => encode_bytes(bytes),
            RlpItem::List(items) => {
                let mut payload: Vec<u8> = Vec::new();
                for item in items {
                    payload.extend(item.encode());
                }
                encode_list_payload(&payload)
            }
        }
    }

    pub fn into_list(self) -> Result<Vec<RlpItem>, Error> {
        match self {
            RlpItem::List(items) => Ok(items),
            RlpItem::Bytes(_) => Err(Error::Rlp("expected list, got bytes".to_string())),
        }
    }

    pub fn into_bytes(self) -> Result<Vec<u8>, Error> {
        match self {
            RlpItem::Bytes(bytes) => Ok(bytes),
            RlpItem::List(_) => Err(Error::Rlp("expected bytes, got list".to_string())),
        }
    }
}

pub fn encode_list(items: &[&[u8]]) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    for item in items {
        payload.extend(encode_bytes(item));
    }
    encode_list_payload(&payload)
}

pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] <= consts::SINGLE_BYTE_MAX {
        vec![bytes[0]]
    } else if bytes.len() < 56 {
        let mut result: Vec<u8> = vec![consts::SHORT_STRING_PREFIX + bytes.len() as u8];
        result.extend_from_slice(bytes);
        result
    } else {
        let len_bytes: Vec<u8> = encode_length(bytes.len());
        let mut result: Vec<u8> = vec![consts::LONG_STRING_PREFIX + len_bytes.len() as u8];
        result.extend(len_bytes);
        result.extend_from_slice(bytes);
        result
    }
}

pub fn encode_list_payload(payload: &[u8]) -> Vec<u8> {
    if payload.len() < 56 {
        let mut result: Vec<u8> = vec![consts::SHORT_LIST_PREFIX + payload.len() as u8];
        result.extend_from_slice(payload);
        result
    } else {
        let len_bytes: Vec<u8> = encode_length(payload.len());
        let mut result: Vec<u8> = vec![consts::LONG_LIST_PREFIX + len_bytes.len() as u8];
        result.extend(len_bytes);
        result.extend_from_slice(payload);
        result
    }
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 256 {
        vec![len as u8]
    } else if len < 65536 {
        vec![(len >> 8) as u8, len as u8]
    } else if len < 16777216 {
        vec![(len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

pub fn decode(data: &[u8]) -> Result<RlpItem, Error> {
    if data.is_empty() {
        return Err(Error::Rlp("empty data".to_string()));
    }

    let (item, _consumed) = decode_with_depth(data, 0)?;
    Ok(item)
}

fn decode_with_depth(data: &[u8], depth: usize) -> Result<(RlpItem, usize), Error> {
    if depth > MAX_RLP_DEPTH {
        return Err(Error::Rlp("RLP nesting too deep".to_string()));
    }

    if data.is_empty() {
        return Err(Error::Rlp("empty data".to_string()));
    }

    let first: u8 = data[0];

    if first <= consts::SINGLE_BYTE_MAX {
        Ok((RlpItem::Bytes(vec![first]), 1))
    } else if first <= consts::SHORT_STRING_MAX {
        let len: usize = (first - consts::SHORT_STRING_PREFIX) as usize;
        if data.len() < 1 + len {
            return Err(Error::Rlp("data too short for bytes".to_string()));
        }
        let bytes: Vec<u8> = data[1..1 + len].to_vec();
        Ok((RlpItem::Bytes(bytes), 1 + len))
    } else if first <= consts::LONG_STRING_MAX {
        let len_of_len: usize = (first - consts::LONG_STRING_PREFIX) as usize;
        if data.len() < 1 + len_of_len {
            return Err(Error::Rlp("data too short for length".to_string()));
        }
        let len: usize = decode_length(&data[1..1 + len_of_len]);
        if data.len() < 1 + len_of_len + len {
            return Err(Error::Rlp("data too short for long bytes".to_string()));
        }
        let bytes: Vec<u8> = data[1 + len_of_len..1 + len_of_len + len].to_vec();
        Ok((RlpItem::Bytes(bytes), 1 + len_of_len + len))
    } else if first <= consts::LONG_LIST_PREFIX {
        let len: usize = (first - consts::SHORT_LIST_PREFIX) as usize;
        if data.len() < 1 + len {
            return Err(Error::Rlp("data too short for list".to_string()));
        }
        let payload: &[u8] = &data[1..1 + len];
        let items: Vec<RlpItem> = decode_list_payload(payload, depth + 1)?;
        Ok((RlpItem::List(items), 1 + len))
    } else {
        let len_of_len: usize = (first - consts::LONG_LIST_PREFIX) as usize;
        if data.len() < 1 + len_of_len {
            return Err(Error::Rlp("data too short for list length".to_string()));
        }
        let len: usize = decode_length(&data[1..1 + len_of_len]);
        if data.len() < 1 + len_of_len + len {
            return Err(Error::Rlp("data too short for long list".to_string()));
        }
        let payload: &[u8] = &data[1 + len_of_len..1 + len_of_len + len];
        let items: Vec<RlpItem> = decode_list_payload(payload, depth + 1)?;
        Ok((RlpItem::List(items), 1 + len_of_len + len))
    }
}

fn decode_list_payload(payload: &[u8], depth: usize) -> Result<Vec<RlpItem>, Error> {
    let mut items: Vec<RlpItem> = Vec::new();
    let mut offset: usize = 0;

    while offset < payload.len() {
        let (item, consumed) = decode_with_depth(&payload[offset..], depth)?;
        items.push(item);
        offset += consumed;
    }

    Ok(items)
}

fn decode_length(bytes: &[u8]) -> usize {
    let mut result: usize = 0;
    for byte in bytes {
        result = (result << 8) | (*byte as usize);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_single_byte() {
        let item = RlpItem::Bytes(vec![0x42]);
        let encoded = item.encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn test_encode_decode_short_string() {
        let item = RlpItem::Bytes(b"hello".to_vec());
        let encoded = item.encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn test_encode_decode_empty_bytes() {
        let item = RlpItem::Bytes(vec![]);
        let encoded = item.encode();
        assert_eq!(encoded, vec![0x80]);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn test_encode_decode_list() {
        let item = RlpItem::List(vec![
            RlpItem::Bytes(b"cat".to_vec()),
            RlpItem::Bytes(b"dog".to_vec()),
        ]);
        let encoded = item.encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn test_encode_decode_nested_list() {
        let item = RlpItem::List(vec![
            RlpItem::List(vec![RlpItem::Bytes(vec![1])]),
            RlpItem::Bytes(vec![2]),
        ]);
        let encoded = item.encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn test_encode_list_helper() {
        let items: &[&[u8]] = &[b"cat", b"dog"];
        let encoded = encode_list(items);
        let decoded = decode(&encoded).unwrap();
        let list = decoded.into_list().unwrap();
        assert_eq!(list[0].clone().into_bytes().unwrap(), b"cat");
        assert_eq!(list[1].clone().into_bytes().unwrap(), b"dog");
    }

    #[test]
    fn test_long_string() {
        let long_data = vec![0xAA; 100];
        let item = RlpItem::Bytes(long_data.clone());
        let encoded = item.encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.into_bytes().unwrap(), long_data);
    }
}
