use serde::Serialize;

use crate::bytes::decode_u16;
use crate::error::Error;
use crate::rlp;

pub const HELLO_MSG_ID: u8 = 0x00;
pub const DISCONNECT_MSG_ID: u8 = 0x01;
pub const PING_MSG_ID: u8 = 0x02;
pub const PONG_MSG_ID: u8 = 0x03;

pub const P2P_VERSION: u8 = 5;

#[derive(Clone)]
pub struct Capability {
    pub name: String,
    pub version: u8,
}

impl Capability {
    pub fn new(name: &str, version: u8) -> Capability {
        Capability {
            name: name.to_string(),
            version,
        }
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let version_bytes: [u8; 1] = [self.version];
        rlp::encode_list(&[self.name.as_bytes(), &version_bytes])
    }

    pub fn from_rlp(data: &[u8]) -> Result<Capability, Error> {
        let items: Vec<rlp::RlpItem> = rlp::decode(data)?.into_list()?;

        if items.len() < 2 {
            return Err(Error::Protocol("capability missing fields".to_string()));
        }

        let name_bytes: Vec<u8> = items[0].clone().into_bytes()?;
        let version_bytes: Vec<u8> = items[1].clone().into_bytes()?;

        let name: String = String::from_utf8(name_bytes)
            .map_err(|_| Error::Protocol("invalid capability name".to_string()))?;

        let version: u8 = if version_bytes.is_empty() {
            0
        } else {
            version_bytes[0]
        };

        Ok(Capability { name, version })
    }
}

pub struct HelloMessage {
    pub protocol_version: u8,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u16,
    pub node_id: [u8; 64],
}

impl HelloMessage {
    pub fn new(
        client_id: &str,
        capabilities: Vec<Capability>,
        listen_port: u16,
        node_id: [u8; 64],
    ) -> HelloMessage {
        HelloMessage {
            protocol_version: P2P_VERSION,
            client_id: client_id.to_string(),
            capabilities,
            listen_port,
            node_id,
        }
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let version_bytes: [u8; 1] = [self.protocol_version];
        let port_bytes: [u8; 2] = self.listen_port.to_be_bytes();

        let mut caps_payload: Vec<u8> = Vec::new();
        for cap in &self.capabilities {
            caps_payload.extend(cap.to_rlp());
        }
        let caps_rlp: Vec<u8> = rlp::encode_list_payload(&caps_payload);

        let port_trimmed: &[u8] = if self.listen_port == 0 {
            &[]
        } else if port_bytes[0] == 0 {
            &port_bytes[1..2]
        } else {
            &port_bytes
        };

        let mut result: Vec<u8> = Vec::new();
        result.extend(rlp::encode_bytes(&version_bytes));
        result.extend(rlp::encode_bytes(self.client_id.as_bytes()));
        result.extend(&caps_rlp);
        result.extend(rlp::encode_bytes(port_trimmed));
        result.extend(rlp::encode_bytes(&self.node_id));

        rlp::encode_list_payload(&result)
    }

    pub fn from_rlp(data: &[u8]) -> Result<HelloMessage, Error> {
        let items: Vec<rlp::RlpItem> = rlp::decode(data)?.into_list()?;

        if items.len() < 5 {
            return Err(Error::Protocol("hello message missing fields".to_string()));
        }

        let version_bytes: Vec<u8> = items[0].clone().into_bytes()?;
        let protocol_version: u8 = if version_bytes.is_empty() {
            0
        } else {
            version_bytes[0]
        };

        let client_id_bytes: Vec<u8> = items[1].clone().into_bytes()?;
        let client_id: String = String::from_utf8(client_id_bytes)
            .map_err(|_| Error::Protocol("invalid client id".to_string()))?;

        let capabilities: Vec<Capability> = parse_capabilities(&items[2])?;

        let port_bytes: Vec<u8> = items[3].clone().into_bytes()?;
        let listen_port: u16 = decode_u16(&port_bytes);

        let node_id_bytes: Vec<u8> = items[4].clone().into_bytes()?;
        if node_id_bytes.len() != 64 {
            return Err(Error::Protocol("invalid node id length".to_string()));
        }

        let mut node_id: [u8; 64] = [0u8; 64];
        node_id.copy_from_slice(&node_id_bytes);

        Ok(HelloMessage {
            protocol_version,
            client_id,
            capabilities,
            listen_port,
            node_id,
        })
    }
}

fn parse_capabilities(item: &rlp::RlpItem) -> Result<Vec<Capability>, Error> {
    let cap_items: Vec<rlp::RlpItem> = item.clone().into_list()?;
    let mut capabilities: Vec<Capability> = Vec::new();

    for cap_item in cap_items {
        let cap_data: Vec<u8> = cap_item.encode();
        let cap: Capability = Capability::from_rlp(&cap_data)?;
        capabilities.push(cap);
    }

    Ok(capabilities)
}

pub fn encode_message(msg_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(1 + payload.len());
    if msg_id == 0 {
        result.push(0x80);
    } else {
        result.push(msg_id);
    }
    result.extend_from_slice(payload);
    result
}

pub fn decode_message(data: &[u8]) -> Result<(u8, &[u8]), Error> {
    if data.is_empty() {
        return Err(Error::Protocol("empty message".to_string()));
    }

    let first_byte: u8 = data[0];
    let msg_id: u8 = if first_byte == 0x80 { 0 } else { first_byte };
    let payload: &[u8] = &data[1..];

    Ok((msg_id, payload))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectReason {
    Requested,
    TcpError,
    ProtocolBreach,
    UselessPeer,
    TooManyPeers,
    AlreadyConnected,
    IncompatibleVersion,
    InvalidIdentity,
    ClientQuitting,
    UnexpectedIdentity,
    SameIdentity,
    PingTimeout,
    SubprotocolError,
    Unknown(u8),
}

impl DisconnectReason {
    #[allow(clippy::wrong_self_convention)]
    pub fn to_rlp(&self) -> Vec<u8> {
        let code: u8 = match self {
            DisconnectReason::Requested => 0,
            DisconnectReason::TcpError => 1,
            DisconnectReason::ProtocolBreach => 2,
            DisconnectReason::UselessPeer => 3,
            DisconnectReason::TooManyPeers => 4,
            DisconnectReason::AlreadyConnected => 5,
            DisconnectReason::IncompatibleVersion => 6,
            DisconnectReason::InvalidIdentity => 7,
            DisconnectReason::ClientQuitting => 8,
            DisconnectReason::UnexpectedIdentity => 9,
            DisconnectReason::SameIdentity => 10,
            DisconnectReason::PingTimeout => 11,
            DisconnectReason::SubprotocolError => 16,
            DisconnectReason::Unknown(n) => *n,
        };
        rlp::encode_list(&[&[code][..]])
    }

    pub fn from_rlp(payload: &[u8]) -> DisconnectReason {
        if payload.is_empty() {
            return DisconnectReason::Unknown(0xff);
        }

        let items: Vec<rlp::RlpItem> = match rlp::decode(payload) {
            Ok(item) => match item.into_list() {
                Ok(list) => list,
                Err(_) => return DisconnectReason::Unknown(0xff),
            },
            Err(_) => return DisconnectReason::Unknown(0xff),
        };

        if items.is_empty() {
            return DisconnectReason::Requested;
        }

        let code_bytes: Vec<u8> = match items[0].clone().into_bytes() {
            Ok(bytes) => bytes,
            Err(_) => return DisconnectReason::Unknown(0xff),
        };

        if code_bytes.is_empty() {
            return DisconnectReason::Requested;
        }

        let code: u8 = code_bytes[0];

        Self::from_code(code)
    }

    pub fn from_code(code: u8) -> DisconnectReason {
        match code {
            0 => DisconnectReason::Requested,
            1 => DisconnectReason::TcpError,
            2 => DisconnectReason::ProtocolBreach,
            3 => DisconnectReason::UselessPeer,
            4 => DisconnectReason::TooManyPeers,
            5 => DisconnectReason::AlreadyConnected,
            6 => DisconnectReason::IncompatibleVersion,
            7 => DisconnectReason::InvalidIdentity,
            8 => DisconnectReason::ClientQuitting,
            9 => DisconnectReason::UnexpectedIdentity,
            10 => DisconnectReason::SameIdentity,
            11 => DisconnectReason::PingTimeout,
            16 => DisconnectReason::SubprotocolError,
            n => DisconnectReason::Unknown(n),
        }
    }

    pub fn description(&self) -> String {
        let (code, desc) = match self {
            DisconnectReason::Requested => (0, "Disconnect requested"),
            DisconnectReason::TcpError => (1, "TCP sub-system error"),
            DisconnectReason::ProtocolBreach => (2, "Breach of protocol"),
            DisconnectReason::UselessPeer => (3, "Useless peer"),
            DisconnectReason::TooManyPeers => (4, "Too many peers"),
            DisconnectReason::AlreadyConnected => (5, "Already connected"),
            DisconnectReason::IncompatibleVersion => (6, "Incompatible P2P protocol version"),
            DisconnectReason::InvalidIdentity => (7, "Invalid node identity"),
            DisconnectReason::ClientQuitting => (8, "Client quitting"),
            DisconnectReason::UnexpectedIdentity => (9, "Unexpected identity"),
            DisconnectReason::SameIdentity => (10, "Connected to self"),
            DisconnectReason::PingTimeout => (11, "Ping timeout"),
            DisconnectReason::SubprotocolError => (16, "Subprotocol-specific error"),
            DisconnectReason::Unknown(n) => (*n, "Unknown reason"),
        };
        format!("{} (code {})", desc, code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_message() {
        let payload = b"test payload";

        // msg_id 0 encodes as 0x80
        let encoded = encode_message(0, payload);
        assert_eq!(encoded[0], 0x80);
        let (id, dec_payload) = decode_message(&encoded).unwrap();
        assert_eq!(id, 0);
        assert_eq!(dec_payload, payload);

        // msg_id 1 stays as 1
        let encoded = encode_message(1, payload);
        assert_eq!(encoded[0], 1);
        let (id, dec_payload) = decode_message(&encoded).unwrap();
        assert_eq!(id, 1);
        assert_eq!(dec_payload, payload);
    }

    #[test]
    fn test_hello_message_roundtrip() {
        let node_id = [0xAA; 64];
        let hello = HelloMessage::new(
            "test-client/1.0",
            vec![Capability::new("eth", 68)],
            30303,
            node_id,
        );

        let encoded = hello.to_rlp();
        let decoded = HelloMessage::from_rlp(&encoded).unwrap();

        assert_eq!(decoded.protocol_version, P2P_VERSION);
        assert_eq!(decoded.client_id, "test-client/1.0");
        assert_eq!(decoded.capabilities.len(), 1);
        assert_eq!(decoded.capabilities[0].name, "eth");
        assert_eq!(decoded.capabilities[0].version, 68);
        assert_eq!(decoded.listen_port, 30303);
        assert_eq!(decoded.node_id, node_id);
    }

    #[test]
    fn test_disconnect_reason_roundtrip() {
        let reason = DisconnectReason::TooManyPeers;
        let encoded = reason.to_rlp();
        let decoded = DisconnectReason::from_rlp(&encoded);
        assert_eq!(decoded, reason);
    }
}
