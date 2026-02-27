use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use hickory_resolver::TokioResolver;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::seq::SliceRandom;
use sha3::{Digest, Keccak256};

use crate::error::Error;
use crate::rlp;
use crate::types::NodeInfo;

pub struct DnsDiscovery {
    resolver: TokioResolver,
    domain: String,
    pubkey: VerifyingKey,
}

impl DnsDiscovery {
    pub fn new(url: &str) -> Result<Self, Error> {
        let (pubkey, domain) = parse_enrtree_url(url)?;

        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| Error::Dns(format!("failed to create resolver: {}", e)))?
            .build();

        Ok(Self {
            resolver,
            domain,
            pubkey,
        })
    }

    pub async fn discover_nodes(&self) -> Result<Vec<NodeInfo>, Error> {
        let root = self.fetch_root().await?;
        let nodes = self.crawl_tree(&root.enr_root).await?;

        let mut nodes = nodes;
        nodes.shuffle(&mut rand::thread_rng());
        Ok(nodes)
    }

    async fn fetch_root(&self) -> Result<RootRecord, Error> {
        let txt = self.query_txt(&self.domain).await?;
        let root = parse_root_record(&txt)?;

        verify_root_signature(&txt, &root.signature, &self.pubkey)?;

        Ok(root)
    }

    async fn crawl_tree(&self, hash: &str) -> Result<Vec<NodeInfo>, Error> {
        let mut nodes: Vec<NodeInfo> = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: Vec<String> = vec![hash.to_string()];

        while let Some(current) = queue.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            let subdomain = format!("{}.{}", current, self.domain);
            let txt = match self.query_txt(&subdomain).await {
                Ok(t) => t,
                Err(_) => continue,
            };

            if txt.starts_with("enrtree-branch:") {
                let children = parse_branch_record(&txt)?;
                for child in children {
                    if !visited.contains(&child) {
                        queue.push(child);
                    }
                }
            } else if let Some(node) = try_parse_enr(&txt) {
                nodes.push(node);
            }
        }

        Ok(nodes)
    }

    async fn query_txt(&self, name: &str) -> Result<String, Error> {
        let response = self
            .resolver
            .txt_lookup(name)
            .await
            .map_err(|e| Error::Dns(format!("DNS lookup failed for {}: {}", name, e)))?;

        let mut result = String::new();
        for record in response.iter() {
            for data in record.txt_data() {
                if let Ok(s) = std::str::from_utf8(data) {
                    result.push_str(s);
                }
            }
        }

        if result.is_empty() {
            Err(Error::Dns(format!("empty TXT record for {}", name)))
        } else {
            Ok(result)
        }
    }
}

fn try_parse_enr(txt: &str) -> Option<NodeInfo> {
    if !txt.starts_with("enr:") {
        return None;
    }
    parse_enr_record(txt).ok()
}

fn parse_enrtree_url(url: &str) -> Result<(VerifyingKey, String), Error> {
    let rest = url
        .strip_prefix("enrtree://")
        .ok_or_else(|| Error::Dns("URL must start with enrtree://".to_string()))?;

    let (pubkey_b32, domain) = rest
        .split_once('@')
        .ok_or_else(|| Error::Dns("URL must contain @ separator".to_string()))?;

    let pubkey_bytes = BASE32_NOPAD
        .decode(pubkey_b32.as_bytes())
        .map_err(|e| Error::Dns(format!("invalid base32 pubkey: {}", e)))?;

    if pubkey_bytes.len() != 33 {
        return Err(Error::Dns(format!(
            "pubkey must be 33 bytes (compressed), got {}",
            pubkey_bytes.len()
        )));
    }

    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|e| Error::Dns(format!("invalid pubkey: {}", e)))?;

    Ok((verifying_key, domain.to_string()))
}

struct RootRecord {
    enr_root: String,
    signature: Vec<u8>,
}

fn parse_root_record(txt: &str) -> Result<RootRecord, Error> {
    if !txt.starts_with("enrtree-root:v1 ") {
        return Err(Error::Dns("invalid root record prefix".to_string()));
    }

    let mut enr_root: Option<String> = None;
    let mut sig: Option<Vec<u8>> = None;

    for part in txt.split_whitespace().skip(1) {
        if let Some(value) = part.strip_prefix("e=") {
            enr_root = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("sig=") {
            sig = Some(
                URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|e| Error::Dns(format!("invalid signature base64: {}", e)))?,
            );
        }
    }

    Ok(RootRecord {
        enr_root: enr_root.ok_or_else(|| Error::Dns("missing e= in root record".to_string()))?,
        signature: sig.ok_or_else(|| Error::Dns("missing sig= in root record".to_string()))?,
    })
}

fn verify_root_signature(
    txt: &str,
    sig_bytes: &[u8],
    expected_pubkey: &VerifyingKey,
) -> Result<(), Error> {
    let signed_content = txt
        .split(" sig=")
        .next()
        .ok_or_else(|| Error::Dns("missing sig= in root record".to_string()))?;

    let hash = Keccak256::digest(signed_content.as_bytes());

    if sig_bytes.len() != 65 {
        return Err(Error::Dns(format!(
            "signature must be 65 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let signature = Signature::from_slice(&sig_bytes[..64])
        .map_err(|e| Error::Dns(format!("invalid signature: {}", e)))?;

    let recovery_id = RecoveryId::try_from(sig_bytes[64] % 4)
        .map_err(|e| Error::Dns(format!("invalid recovery id: {}", e)))?;

    let recovered_key = VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id)
        .map_err(|e| Error::Dns(format!("signature recovery failed: {}", e)))?;

    if recovered_key != *expected_pubkey {
        return Err(Error::Dns(
            "signature verification failed: pubkey mismatch".to_string(),
        ));
    }

    Ok(())
}

fn parse_branch_record(txt: &str) -> Result<Vec<String>, Error> {
    let content = txt
        .strip_prefix("enrtree-branch:")
        .ok_or_else(|| Error::Dns("invalid branch record".to_string()))?;

    Ok(content
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

fn parse_enr_record(txt: &str) -> Result<NodeInfo, Error> {
    let encoded = txt
        .strip_prefix("enr:")
        .ok_or_else(|| Error::Dns("invalid ENR prefix".to_string()))?;

    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| Error::Dns(format!("base64 decode failed: {}", e)))?;

    if decoded.len() < 3 {
        return Err(Error::Dns("ENR too short".to_string()));
    }

    let rlp_item = rlp::decode(&decoded)?;
    let items = rlp_item.into_list()?;

    if items.len() < 4 {
        return Err(Error::Dns("ENR has too few items".to_string()));
    }

    let mut ip: Option<Ipv4Addr> = None;
    let mut tcp_port: Option<u16> = None;
    let mut udp_port: Option<u16> = None;
    let mut secp256k1: Option<Vec<u8>> = None;

    let mut i = 2;
    while i + 1 < items.len() {
        let key = items[i].clone().into_bytes().unwrap_or_default();
        let value = items[i + 1].clone().into_bytes().unwrap_or_default();

        match key.as_slice() {
            b"ip" if value.len() == 4 => {
                ip = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            b"tcp" => {
                tcp_port = Some(crate::bytes::decode_u16(&value));
            }
            b"udp" => {
                udp_port = Some(crate::bytes::decode_u16(&value));
            }
            b"secp256k1" if value.len() == 33 => {
                secp256k1 = Some(value);
            }
            _ => {}
        }

        i += 2;
    }

    let ip = ip.ok_or_else(|| Error::Dns("ENR missing ip field".to_string()))?;
    let tcp_port = tcp_port.ok_or_else(|| Error::Dns("ENR missing tcp field".to_string()))?;
    let udp = udp_port.unwrap_or(tcp_port);
    let compressed_pubkey =
        secp256k1.ok_or_else(|| Error::Dns("ENR missing secp256k1 field".to_string()))?;

    let pubkey = decompress_pubkey(&compressed_pubkey)?;

    let addr = SocketAddr::new(ip.into(), tcp_port);

    Ok(NodeInfo {
        pubkey,
        addr,
        tcp_port,
        udp_port: udp,
    })
}

fn decompress_pubkey(compressed: &[u8]) -> Result<[u8; 64], Error> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;
    use k256::PublicKey;

    let point = EncodedPoint::from_bytes(compressed)
        .map_err(|e| Error::Dns(format!("invalid compressed pubkey: {}", e)))?;

    let pubkey = PublicKey::from_encoded_point(&point);
    if pubkey.is_none().into() {
        return Err(Error::Dns("failed to decompress pubkey".to_string()));
    }

    let uncompressed = pubkey.unwrap().to_encoded_point(false);
    let bytes = uncompressed.as_bytes();

    if bytes.len() != 65 {
        return Err(Error::Dns(
            "unexpected uncompressed pubkey length".to_string(),
        ));
    }

    let mut result = [0u8; 64];
    result.copy_from_slice(&bytes[1..65]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_enrtree_url() {
        let url = "enrtree://AJE62Q4DUX4QMMXEHCSSCSC65TDHZYSMONSD64P3WULVLSF6MRQ3K@all.classic.blockd.info";
        let (pubkey, domain) = parse_enrtree_url(url).expect("valid enrtree URL should parse");
        assert_eq!(domain, "all.classic.blockd.info");
        let encoded = pubkey.to_encoded_point(true);
        assert_eq!(encoded.as_bytes().len(), 33);
    }

    #[test]
    fn test_parse_root_record() {
        let txt = "enrtree-root:v1 e=BKQKWNOAZ5MKNNRUDOXYRWLB3I l=FDXN3SN67NA5DKA4J2GOK7BVQI seq=11498 sig=nlNO_6PGROhPqHk5yQlWnjME81VhhDbU96W5uGN1hh0cvmxV_CcRL8gwSwrv9nsXr-f6JYFiSJbwIAs0k6J2cwA";
        let root = parse_root_record(txt).unwrap();
        assert_eq!(root.enr_root, "BKQKWNOAZ5MKNNRUDOXYRWLB3I");
        assert_eq!(root.signature.len(), 65);
    }

    #[test]
    fn test_parse_branch_record() {
        let txt = "enrtree-branch:ABC,DEF,GHI";
        let children = parse_branch_record(txt).unwrap();
        assert_eq!(children, vec!["ABC", "DEF", "GHI"]);
    }

    #[test]
    fn test_parse_enr_record() {
        let txt = "enr:-KO4QOwWYvQJevu5nxXj0jSve9fBWs4B2pOaLC-fuVYGziBbApmi_BrrGtU1hFdCqNfxTmX87tnSgq5wce0VBwP9Z4KGAZeZOgIgg2V0aMfGhL5G1XyAgmlkgnY0gmlwhEJ1_CqJc2VjcDI1NmsxoQO4nhkOuVYDl85-ocdzSkHpX5ieSXlm3enmKIzuuSBqbIRzbmFwwIN0Y3CCdmSDdWRwgnZk";
        let node = parse_enr_record(txt).unwrap();
        assert_eq!(node.addr.ip(), Ipv4Addr::new(66, 117, 252, 42));
        assert_eq!(node.tcp_port, 30308);
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_dns_discovery() {
        let url = "enrtree://AJE62Q4DUX4QMMXEHCSSCSC65TDHZYSMONSD64P3WULVLSF6MRQ3K@all.classic.blockd.info";
        let discovery = DnsDiscovery::new(url).expect("valid URL");
        let nodes = discovery
            .discover_nodes()
            .await
            .expect("DNS discovery should succeed");
        assert!(!nodes.is_empty(), "Should discover at least one node");
    }
}
