pub mod hex_u64 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", val))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
    }
}

pub mod hex_u64_opt {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match val {
            Some(v) => serializer.serialize_str(&format!("0x{:x}", v)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                Ok(Some(
                    u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)?,
                ))
            }
            None => Ok(None),
        }
    }
}

pub mod hex_u256 {
    use alloy_primitives::U256;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let buf = val.to_be_bytes::<32>();
        let hex = hex::encode(buf);
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            serializer.serialize_str("0x0")
        } else {
            serializer.serialize_str(&format!("0x{}", trimmed))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        U256::from_str_radix(s, 16).map_err(serde::de::Error::custom)
    }
}

pub mod hex_u256_opt {
    use alloy_primitives::U256;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Option<U256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match val {
            Some(v) => {
                let buf = v.to_be_bytes::<32>();
                let hex = hex::encode(buf);
                let trimmed = hex.trim_start_matches('0');
                if trimmed.is_empty() {
                    serializer.serialize_str("0x0")
                } else {
                    serializer.serialize_str(&format!("0x{}", trimmed))
                }
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                Ok(Some(
                    U256::from_str_radix(s, 16).map_err(serde::de::Error::custom)?,
                ))
            }
            None => Ok(None),
        }
    }
}

pub mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(val)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

pub mod hex_bytes_vec {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Vec<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(val.len()))?;
        for item in val {
            seq.serialize_element(&format!("0x{}", hex::encode(item)))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                hex::decode(s).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

pub mod hex_h256 {
    use alloy_primitives::B256;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &B256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(val.as_slice())))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<B256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(B256::from_slice(&bytes))
    }
}

pub mod hex_h256_opt {
    use alloy_primitives::B256;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Option<B256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match val {
            Some(v) => serializer.serialize_str(&format!("0x{}", hex::encode(v.as_slice()))),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<B256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                Ok(Some(B256::from_slice(&bytes)))
            }
            None => Ok(None),
        }
    }
}

pub mod hex_h160 {
    use alloy_primitives::Address;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Address, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(val.as_slice())))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 20 {
            return Err(serde::de::Error::custom(format!(
                "expected 20 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Address::from_slice(&bytes))
    }
}

pub mod hex_h160_opt {
    use alloy_primitives::Address;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Option<Address>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match val {
            Some(v) => serializer.serialize_str(&format!("0x{}", hex::encode(v.as_slice()))),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 20 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 20 bytes, got {}",
                        bytes.len()
                    )));
                }
                Ok(Some(Address::from_slice(&bytes)))
            }
            None => Ok(None),
        }
    }
}

pub mod hex_nonce {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &[u8; 8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(val)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 8], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 8 {
            return Err(serde::de::Error::custom(format!(
                "expected 8 bytes for nonce, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

pub mod hex_nonce_opt {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Option<[u8; 8]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match val {
            Some(v) => serializer.serialize_str(&format!("0x{}", hex::encode(v))),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 8]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 8 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 8 bytes for nonce, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

pub mod hex_bloom {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &[u8; 256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(val)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 256], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 256 {
            return Err(serde::de::Error::custom(format!(
                "expected 256 bytes for bloom, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 256];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}
