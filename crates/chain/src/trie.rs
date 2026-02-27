use alloy_primitives::B256;
use sha3::{Digest, Keccak256};

use crate::types::{rlp_encode_bytes, rlp_encode_u64};

/// Compute the ordered trie root (MPT hash) for a list of RLP-encoded items.
///
/// This is the algorithm used by Ethereum to compute `transactions_root` and
/// `receipts_root`. Keys are RLP-encoded indices, values are the raw items.
///
/// Implementation follows go-ethereum's `DeriveSha` + `StackTrie`.
pub fn ordered_trie_root(items: &[Vec<u8>]) -> B256 {
    if items.is_empty() {
        return empty_trie_hash();
    }

    let mut trie = StackTrie::new();

    // Insert in ascending RLP-key order: 1..=127, 0, 128..
    // This is required because RLP(0) = 0x80 which sorts after RLP(1..127).
    for (i, item) in items.iter().enumerate().take(items.len().min(128)).skip(1) {
        let key = rlp_encode_u64(i as u64);
        trie.update(&key, item);
    }
    if !items.is_empty() {
        let key = rlp_encode_u64(0);
        trie.update(&key, &items[0]);
    }
    for (i, item) in items.iter().enumerate().skip(128) {
        let key = rlp_encode_u64(i as u64);
        trie.update(&key, item);
    }

    trie.root_hash()
}

/// The hash of an empty trie: keccak256(RLP("")) = keccak256([0x80]).
pub fn empty_trie_hash() -> B256 {
    B256::from_slice(&Keccak256::digest([0x80]))
}

// ---------------------------------------------------------------------------
// StackTrie — simplified port of go-ethereum's StackTrie
// ---------------------------------------------------------------------------

const EMPTY: u8 = 0;
const BRANCH: u8 = 1;
const EXT: u8 = 2;
const LEAF: u8 = 3;
const HASHED: u8 = 4;

struct StNode {
    typ: u8,
    key: Vec<u8>, // nibble path (hex encoding, no terminator)
    val: Vec<u8>, // value (leaf) or hash/rlp blob (hashed)
    children: [Option<Box<StNode>>; 16],
}

impl StNode {
    fn new_empty() -> Self {
        Self {
            typ: EMPTY,
            key: Vec::new(),
            val: Vec::new(),
            children: Default::default(),
        }
    }

    fn new_leaf(key: Vec<u8>, val: Vec<u8>) -> Self {
        Self {
            typ: LEAF,
            key,
            val,
            children: Default::default(),
        }
    }

    fn new_ext(key: Vec<u8>, child: StNode) -> Self {
        let mut children: [Option<Box<StNode>>; 16] = Default::default();
        children[0] = Some(Box::new(child));
        Self {
            typ: EXT,
            key,
            val: Vec::new(),
            children,
        }
    }

    fn diff_index(&self, key: &[u8]) -> usize {
        for (i, &nibble) in self.key.iter().enumerate() {
            if i >= key.len() || nibble != key[i] {
                return i;
            }
        }
        self.key.len()
    }
}

struct StackTrie {
    root: StNode,
}

impl StackTrie {
    fn new() -> Self {
        Self {
            root: StNode::new_empty(),
        }
    }

    fn update(&mut self, key: &[u8], value: &[u8]) {
        let hex_key = key_to_hex(key);
        // Take ownership of root, insert, put back
        let mut root = std::mem::replace(&mut self.root, StNode::new_empty());
        Self::insert(&mut root, &hex_key, value.to_vec(), true);
        self.root = root;
    }

    fn root_hash(&mut self) -> B256 {
        Self::hash_node(&mut self.root, true);
        if self.root.val.len() == 32 {
            B256::from_slice(&self.root.val)
        } else {
            // Root node is < 32 bytes: hash it anyway (root is always hashed)
            B256::from_slice(&Keccak256::digest(&self.root.val))
        }
    }

    fn insert(st: &mut StNode, key: &[u8], value: Vec<u8>, _is_root: bool) {
        match st.typ {
            EMPTY => {
                st.typ = LEAF;
                st.key = key.to_vec();
                st.val = value;
            }
            BRANCH => {
                let idx = key[0] as usize;

                // Hash elder siblings that won't receive more insertions
                for i in (0..idx).rev() {
                    if let Some(ref mut child) = st.children[i] {
                        if child.typ != HASHED {
                            Self::hash_node(child, false);
                        }
                        break;
                    }
                }

                if st.children[idx].is_none() {
                    st.children[idx] = Some(Box::new(StNode::new_leaf(key[1..].to_vec(), value)));
                } else {
                    let child = st.children[idx].as_mut().unwrap();
                    Self::insert(child, &key[1..], value, false);
                }
            }
            EXT => {
                let diffidx = st.diff_index(key);

                if diffidx == st.key.len() {
                    // Keys match the extension, recurse into child
                    let child = st.children[0].as_mut().unwrap();
                    Self::insert(child, &key[diffidx..], value, false);
                    return;
                }

                // Need to split the extension
                let orig_child = if diffidx < st.key.len() - 1 {
                    // Break on non-last byte: create intermediate extension
                    let mut n = StNode::new_ext(
                        st.key[diffidx + 1..].to_vec(),
                        *st.children[0].take().unwrap(),
                    );
                    Self::hash_node(&mut n, false);
                    n
                } else {
                    // Break on last byte: reuse child directly
                    let mut n = *st.children[0].take().unwrap();
                    Self::hash_node(&mut n, false);
                    n
                };

                if diffidx == 0 {
                    // Convert extension to branch
                    st.children[0] = None;
                    st.typ = BRANCH;

                    let orig_idx = st.key[0] as usize;
                    let new_idx = key[0] as usize;
                    st.children[orig_idx] = Some(Box::new(orig_child));
                    st.children[new_idx] =
                        Some(Box::new(StNode::new_leaf(key[1..].to_vec(), value)));
                    st.key.clear();
                } else {
                    // Keep common prefix as extension, add branch child
                    let mut branch = StNode::new_empty();
                    branch.typ = BRANCH;

                    let orig_idx = st.key[diffidx] as usize;
                    let new_idx = key[diffidx] as usize;
                    branch.children[orig_idx] = Some(Box::new(orig_child));
                    branch.children[new_idx] = Some(Box::new(StNode::new_leaf(
                        key[diffidx + 1..].to_vec(),
                        value,
                    )));

                    st.children[0] = Some(Box::new(branch));
                    st.key.truncate(diffidx);
                }
            }
            LEAF => {
                let diffidx = st.diff_index(key);
                // Duplicate keys indicate corrupted peer data; treat as no-op
                // rather than crashing the node.
                if diffidx >= st.key.len() {
                    return;
                }

                let orig_idx = st.key[diffidx] as usize;
                let new_idx = key[diffidx] as usize;

                // Create leaf for the original value
                let mut orig_leaf =
                    StNode::new_leaf(st.key[diffidx + 1..].to_vec(), std::mem::take(&mut st.val));
                Self::hash_node(&mut orig_leaf, false);

                let new_leaf = StNode::new_leaf(key[diffidx + 1..].to_vec(), value);

                if diffidx == 0 {
                    // Convert leaf to branch
                    st.typ = BRANCH;
                    st.children[orig_idx] = Some(Box::new(orig_leaf));
                    st.children[new_idx] = Some(Box::new(new_leaf));
                    st.key.clear();
                } else {
                    // Convert leaf to ext + branch
                    st.typ = EXT;
                    let mut branch = StNode::new_empty();
                    branch.typ = BRANCH;
                    branch.children[orig_idx] = Some(Box::new(orig_leaf));
                    branch.children[new_idx] = Some(Box::new(new_leaf));
                    st.children[0] = Some(Box::new(branch));
                    st.key.truncate(diffidx);
                }
            }
            HASHED => unreachable!("insert into hashed node: ordering invariant violated"),
            _ => unreachable!("invalid node type {}", st.typ),
        }
    }

    /// Hash a node, converting it to HASHED type. After this call,
    /// `st.val` contains either the 32-byte hash or the raw RLP blob
    /// (if < 32 bytes and not root).
    fn hash_node(st: &mut StNode, is_root: bool) {
        let blob = match st.typ {
            HASHED => return,
            EMPTY => {
                st.typ = HASHED;
                // empty trie root hash
                st.val = Keccak256::digest([0x80]).to_vec();
                return;
            }
            BRANCH => {
                // Hash all children first
                for c in st.children.iter_mut().flatten() {
                    if c.typ != HASHED {
                        Self::hash_node(c, false);
                    }
                }
                // Encode branch: RLP list of 17 items (16 children + empty value)
                encode_branch(&st.children)
            }
            EXT => {
                // Hash child
                let child = st.children[0].as_mut().unwrap();
                Self::hash_node(child, false);

                // Encode: [compact_key, child_ref]
                let compact_key = hex_to_compact(&st.key, false);
                let child_val = &child.val;
                encode_short_node(&compact_key, child_val, child_val.len() >= 32)
            }
            LEAF => {
                // Encode: [compact_key_with_term, value]
                let mut key_with_term = st.key.clone();
                key_with_term.push(16); // terminator
                let compact_key = hex_to_compact(&key_with_term, true);
                encode_leaf_node(&compact_key, &st.val)
            }
            _ => unreachable!("invalid node type {} in hash_node", st.typ),
        };

        st.typ = HASHED;
        st.key.clear();
        for c in st.children.iter_mut() {
            *c = None;
        }

        // If blob < 32 bytes and not root, inline it; otherwise hash
        if blob.len() < 32 && !is_root {
            st.val = blob;
        } else {
            st.val = Keccak256::digest(&blob).to_vec();
        }
    }
}

// ---------------------------------------------------------------------------
// Key encoding helpers
// ---------------------------------------------------------------------------

/// Convert raw key bytes to hex nibbles (no terminator).
fn key_to_hex(key: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(key.len() * 2);
    for &b in key {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    nibbles
}

/// Convert hex nibbles to compact (hex-prefix) encoding.
/// `has_term` indicates if this is a leaf (terminator flag).
fn hex_to_compact(hex: &[u8], has_term: bool) -> Vec<u8> {
    // Strip terminator if present
    let hex = if !hex.is_empty() && hex[hex.len() - 1] == 16 {
        &hex[..hex.len() - 1]
    } else {
        hex
    };

    let terminator = if has_term { 1u8 } else { 0u8 };
    let odd = hex.len() & 1 == 1;

    let mut buf = Vec::with_capacity(hex.len() / 2 + 1);

    if odd {
        // First byte: flag nibble + first hex nibble
        buf.push((terminator << 5) | (1 << 4) | hex[0]);
        let mut i = 1;
        while i < hex.len() {
            buf.push((hex[i] << 4) | hex[i + 1]);
            i += 2;
        }
    } else {
        // First byte: flag nibble + zero padding
        buf.push(terminator << 5);
        let mut i = 0;
        while i < hex.len() {
            buf.push((hex[i] << 4) | hex[i + 1]);
            i += 2;
        }
    }
    buf
}

// ---------------------------------------------------------------------------
// RLP node encoding helpers
// ---------------------------------------------------------------------------

/// RLP-encode a single byte string.
fn rlp_bytes(data: &[u8]) -> Vec<u8> {
    rlp_encode_bytes(data)
}

/// Build an RLP list prefix for a payload of given size.
fn rlp_list_prefix(payload_len: usize) -> Vec<u8> {
    if payload_len < 56 {
        vec![0xc0 + payload_len as u8]
    } else {
        let len_bytes = minimal_be_bytes(payload_len);
        let mut prefix = vec![0xf7 + len_bytes.len() as u8];
        prefix.extend_from_slice(&len_bytes);
        prefix
    }
}

fn minimal_be_bytes(v: usize) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

/// Encode a branch node: RLP list of 17 elements.
/// Children 0-15 are node references, child 16 is the value (empty for our use).
fn encode_branch(children: &[Option<Box<StNode>>; 16]) -> Vec<u8> {
    // Compute payload: 16 children + 1 empty value
    let mut payload = Vec::new();
    for child in children.iter() {
        match child {
            Some(c) => {
                debug_assert_eq!(c.typ, HASHED, "branch child not hashed");
                if c.val.len() >= 32 {
                    // Hash reference: encode as bytes string
                    payload.extend_from_slice(&rlp_bytes(&c.val));
                } else {
                    // Inline node: write raw (already RLP)
                    payload.extend_from_slice(&c.val);
                }
            }
            None => {
                // Empty string = 0x80
                payload.push(0x80);
            }
        }
    }
    // 17th element: empty value
    payload.push(0x80);

    let mut result = rlp_list_prefix(payload.len());
    result.extend_from_slice(&payload);
    result
}

/// Encode an extension or leaf node: RLP list [key, val].
fn encode_short_node(compact_key: &[u8], child_val: &[u8], val_is_hash: bool) -> Vec<u8> {
    let key_enc = rlp_bytes(compact_key);
    let val_enc = if val_is_hash {
        rlp_bytes(child_val)
    } else {
        // Raw inline node
        child_val.to_vec()
    };

    let payload_len = key_enc.len() + val_enc.len();
    let mut result = rlp_list_prefix(payload_len);
    result.extend_from_slice(&key_enc);
    result.extend_from_slice(&val_enc);
    result
}

/// Encode a leaf node: RLP list [compact_key, value].
/// Value is always encoded as an RLP bytes string.
fn encode_leaf_node(compact_key: &[u8], value: &[u8]) -> Vec<u8> {
    let key_enc = rlp_bytes(compact_key);
    let val_enc = rlp_bytes(value);

    let payload_len = key_enc.len() + val_enc.len();
    let mut result = rlp_list_prefix(payload_len);
    result.extend_from_slice(&key_enc);
    result.extend_from_slice(&val_enc);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie() {
        let root = ordered_trie_root(&[]);
        // keccak256(RLP("")) = keccak256(0x80)
        let expected = B256::from_slice(&Keccak256::digest([0x80]));
        assert_eq!(root, expected);
    }

    #[test]
    fn single_item() {
        // A trie with one item: key=RLP(0)=0x80, value=item
        // The trie is a single leaf node.
        let item = vec![0xc0]; // empty RLP list as a dummy tx
        let root = ordered_trie_root(&[item]);
        // Manually: leaf with compact_key for hex nibbles of 0x80 = [8,0] + terminator
        // compact([8,0,16], leaf=true) = [0x20, 0x80] (even length, term flag=0x20)
        // leaf = RLP([0x20, 0x80], [0xc0])
        // = list([rlp_bytes([0x20, 0x80]), rlp_bytes([0xc0])])
        // = list([0x82, 0x20, 0x80, 0xc0])  -- wait, 0xc0 as single byte >= 0x80
        // rlp_bytes([0xc0]) = [0x81, 0xc0]
        // payload = [0x82, 0x20, 0x80, 0x81, 0xc0] (5 bytes)
        // list prefix = [0xc5]
        // blob = [0xc5, 0x82, 0x20, 0x80, 0x81, 0xc0] (6 bytes < 32)
        // Root must be hashed (always hash root)
        let expected = B256::from_slice(&Keccak256::digest([0xc5, 0x82, 0x20, 0x80, 0x81, 0xc0]));
        assert_eq!(root, expected);
    }

    #[test]
    fn known_etc_block_1() {
        // ETC block 1 has exactly one transaction.
        // transactions_root from ETC mainnet block 1:
        // 0x2f07d72eaf3baab438a498ab579e9d0a8e0e2f043fa80d37a00e1bba397c2109
        // tx RLP (block 1): legacy tx, RLP-encoded
        // We can verify against the known root once we have the real tx data.
        // For now, just verify the algorithm is deterministic.
        let items = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let root1 = ordered_trie_root(&items);
        let root2 = ordered_trie_root(&items);
        assert_eq!(root1, root2);
        assert_ne!(root1, B256::ZERO);
    }

    #[test]
    fn two_items() {
        // Two items: keys RLP(0)=0x80 and RLP(1)=0x01
        // Insertion order: index 1 first (key=0x01), then index 0 (key=0x80)
        let items = vec![vec![0xaa], vec![0xbb]];
        let root = ordered_trie_root(&items);
        assert_ne!(root, B256::ZERO);
    }

    #[test]
    fn three_items() {
        let items = vec![vec![0x01], vec![0x02], vec![0x03]];
        let root = ordered_trie_root(&items);
        assert_ne!(root, B256::ZERO);
    }

    #[test]
    fn many_items_no_panic() {
        // Test with 200 items (exercises the 128+ path)
        let items: Vec<Vec<u8>> = (0..200u64)
            .map(|i| {
                let mut v = vec![0xf8, 0x40]; // fake RLP prefix
                v.extend_from_slice(&i.to_be_bytes());
                v
            })
            .collect();
        let root = ordered_trie_root(&items);
        assert_ne!(root, B256::ZERO);
    }

    #[test]
    fn hex_to_compact_even() {
        // [1, 2, 3, 4] even, no term → [0x00, 0x12, 0x34]
        assert_eq!(hex_to_compact(&[1, 2, 3, 4], false), vec![0x00, 0x12, 0x34]);
    }

    #[test]
    fn hex_to_compact_odd() {
        // [1, 2, 3] odd, no term → [0x11, 0x23]
        assert_eq!(hex_to_compact(&[1, 2, 3], false), vec![0x11, 0x23]);
    }

    #[test]
    fn hex_to_compact_leaf_even() {
        // [0, 1, 16] even (strip term), leaf → [0x20, 0x01]
        assert_eq!(hex_to_compact(&[0, 1, 16], true), vec![0x20, 0x01]);
    }

    #[test]
    fn hex_to_compact_leaf_odd() {
        // [1, 16] odd (strip term), leaf → [0x31]
        assert_eq!(hex_to_compact(&[1, 16], true), vec![0x31]);
    }
}
