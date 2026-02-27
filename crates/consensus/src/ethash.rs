use alloy_primitives::{B256, U256};
use sha3::{Digest, Keccak256, Keccak512};

/// Default ethash epoch length (blocks per epoch).
const EPOCH_LENGTH_DEFAULT: u64 = 30_000;
/// ECIP-1099 epoch length (blocks per epoch after Thanos fork).
const EPOCH_LENGTH_ECIP1099: u64 = 60_000;
/// ECIP-1099 (Thanos) activation block.
const ECIP1099_BLOCK: u64 = 11_700_000;

/// Initial cache size in bytes.
const CACHE_INIT_BYTES: u64 = 1 << 24; // 16 MB
/// Cache growth per epoch in bytes.
const CACHE_GROWTH_BYTES: u64 = 1 << 17; // 128 KB

/// Initial dataset (DAG) size in bytes.
const DATASET_INIT_BYTES: u64 = 1 << 30; // 1 GB
/// Dataset growth per epoch in bytes.
const DATASET_GROWTH_BYTES: u64 = 1 << 23; // 8 MB

/// Hash length used in ethash (64 bytes).
const HASH_BYTES: usize = 64;
/// Word size in bytes.
const WORD_BYTES: usize = 4;
/// Number of dataset parents for each cache item.
const CACHE_ROUNDS: usize = 3;
/// Number of accesses in hashimoto.
const ACCESSES: usize = 64;
/// Mix size in bytes.
const MIX_BYTES: usize = 128;

/// Compute the epoch length for a given block number (ECIP-1099).
pub fn epoch_length(block_number: u64) -> u64 {
    if block_number >= ECIP1099_BLOCK {
        EPOCH_LENGTH_ECIP1099
    } else {
        EPOCH_LENGTH_DEFAULT
    }
}

/// Compute the epoch number for a given block number.
pub fn epoch(block_number: u64) -> u64 {
    block_number / epoch_length(block_number)
}

/// Compute the seed hash for a given epoch and epoch length.
///
/// Mirrors go-ethereum: iterations = (epoch * epoch_length + 1) / 30000
/// This ensures backwards compatibility across the ECIP-1099 transition.
pub fn seed_hash(epoch: u64, ep_length: u64) -> B256 {
    let block = epoch * ep_length + 1;
    let iterations = block / EPOCH_LENGTH_DEFAULT;
    let mut seed = [0u8; 32];
    for _ in 0..iterations {
        seed = Keccak256::digest(seed).into();
    }
    B256::from(seed)
}

/// Check if a number is prime.
fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n < 4 {
        return true;
    }
    if n.is_multiple_of(2) {
        return false;
    }
    let mut i = 3u64;
    while i * i <= n {
        if n.is_multiple_of(i) {
            return false;
        }
        i += 2;
    }
    true
}

/// Compute the cache size for a given epoch.
pub fn cache_size(epoch: u64) -> usize {
    let mut sz = CACHE_INIT_BYTES + CACHE_GROWTH_BYTES * epoch;
    sz -= HASH_BYTES as u64;
    while !is_prime(sz / HASH_BYTES as u64) {
        sz -= 2 * HASH_BYTES as u64;
    }
    sz as usize
}

/// Compute the dataset (DAG) size for a given epoch.
pub fn dataset_size(epoch: u64) -> usize {
    let mut sz = DATASET_INIT_BYTES + DATASET_GROWTH_BYTES * epoch;
    sz -= MIX_BYTES as u64;
    while !is_prime(sz / MIX_BYTES as u64) {
        sz -= 2 * MIX_BYTES as u64;
    }
    sz as usize
}

/// Generate the ethash cache for a given epoch and epoch length.
pub fn make_cache(epoch: u64, ep_length: u64) -> Vec<u8> {
    let size = cache_size(epoch);
    let seed = seed_hash(epoch, ep_length);
    let n = size / HASH_BYTES;

    let mut cache = vec![0u8; size];

    // Sequentially produce the initial dataset.
    let hash: [u8; 64] = Keccak512::digest(seed.as_slice()).into();
    cache[..HASH_BYTES].copy_from_slice(&hash);

    for i in 1..n {
        let start = i * HASH_BYTES;
        let prev_start = (i - 1) * HASH_BYTES;
        let prev = &cache[prev_start..prev_start + HASH_BYTES];
        let h: [u8; 64] = Keccak512::digest(prev).into();
        cache[start..start + HASH_BYTES].copy_from_slice(&h);
    }

    // Perform CACHE_ROUNDS rounds of RandMemoHash.
    for _ in 0..CACHE_ROUNDS {
        for i in 0..n {
            let start = i * HASH_BYTES;

            let v = u32::from_le_bytes([
                cache[start],
                cache[start + 1],
                cache[start + 2],
                cache[start + 3],
            ]) as usize
                % n;

            let prev_idx = if i == 0 { n - 1 } else { i - 1 };

            // XOR prev and cache[v]
            let mut xored = [0u8; HASH_BYTES];
            for j in 0..HASH_BYTES {
                xored[j] = cache[prev_idx * HASH_BYTES + j] ^ cache[v * HASH_BYTES + j];
            }

            let h: [u8; 64] = Keccak512::digest(xored).into();
            cache[start..start + HASH_BYTES].copy_from_slice(&h);
        }
    }

    cache
}

/// Number of dataset parents per item (256 FNV rounds).
const DATASET_PARENTS: u32 = 256;
/// Number of u32 words in a hash (64 bytes / 4).
const HASH_WORDS: usize = HASH_BYTES / WORD_BYTES; // 16

/// Compute a single dataset item from the cache (light evaluation).
///
/// Mirrors go-ethereum's `generateDatasetItem`.
fn calc_dataset_item(cache: &[u8], index: u32) -> [u8; HASH_BYTES] {
    let rows = (cache.len() / HASH_BYTES) as u32;

    // Initialize mix from cache row, XOR index into first word.
    let row_offset = ((index % rows) as usize) * HASH_BYTES;
    let mut mix = [0u8; HASH_BYTES];
    mix.copy_from_slice(&cache[row_offset..row_offset + HASH_BYTES]);

    // XOR index into first little-endian u32 word.
    let first_word = u32::from_le_bytes([mix[0], mix[1], mix[2], mix[3]]) ^ index;
    mix[0..4].copy_from_slice(&first_word.to_le_bytes());

    mix = Keccak512::digest(mix).into();

    // Convert to u32 words for FNV mixing.
    let mut int_mix = [0u32; HASH_WORDS];
    for i in 0..HASH_WORDS {
        int_mix[i] =
            u32::from_le_bytes([mix[i * 4], mix[i * 4 + 1], mix[i * 4 + 2], mix[i * 4 + 3]]);
    }

    // FNV with 256 pseudorandom cache nodes.
    for i in 0..DATASET_PARENTS {
        let parent = fnv(index ^ i, int_mix[(i as usize) % HASH_WORDS]) % rows;
        let parent_offset = (parent as usize) * HASH_WORDS;
        // Read parent row as u32 words directly from cache bytes.
        let byte_offset = parent_offset * WORD_BYTES;
        let mut parent_words = [0u32; HASH_WORDS];
        for w in 0..HASH_WORDS {
            parent_words[w] = u32::from_le_bytes([
                cache[byte_offset + w * 4],
                cache[byte_offset + w * 4 + 1],
                cache[byte_offset + w * 4 + 2],
                cache[byte_offset + w * 4 + 3],
            ]);
        }
        fnv_hash(&mut int_mix, &parent_words);
    }

    // Flatten back to bytes and final keccak512.
    for i in 0..HASH_WORDS {
        mix[i * 4..(i + 1) * 4].copy_from_slice(&int_mix[i].to_le_bytes());
    }

    Keccak512::digest(mix).into()
}

/// FNV hash function for a single pair of u32 words.
fn fnv(v1: u32, v2: u32) -> u32 {
    v1.wrapping_mul(0x01000193) ^ v2
}

/// FNV hash: element-wise FNV of mix with data.
fn fnv_hash(mix: &mut [u32; HASH_WORDS], data: &[u32; HASH_WORDS]) {
    for i in 0..HASH_WORDS {
        mix[i] = mix[i].wrapping_mul(0x01000193) ^ data[i];
    }
}

/// Number of u32 words in MIX_BYTES (128 / 4 = 32).
const MIX_WORDS: usize = MIX_BYTES / WORD_BYTES;

/// Hashimoto-light: compute PoW using cache only (no full DAG).
///
/// Returns (mix_hash, result) where result must be <= target for valid PoW.
/// Mirrors go-ethereum's `hashimoto` + `hashimotoLight`.
pub fn hashimoto_light(
    header_hash: &B256,
    nonce: u64,
    full_size: usize,
    cache: &[u8],
) -> (B256, B256) {
    let rows = (full_size / MIX_BYTES) as u32;

    // Combine header hash and nonce → keccak512 seed.
    let mut seed_buf = [0u8; 40];
    seed_buf[..32].copy_from_slice(header_hash.as_ref());
    seed_buf[32..].copy_from_slice(&nonce.to_le_bytes());
    let seed: [u8; 64] = Keccak512::digest(seed_buf).into();

    let seed_head = u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]);

    // Start the mix with replicated seed (128 bytes = 2× 64-byte seed).
    // mix[i] = seed_as_u32[i % 16]
    let mut mix = [0u32; MIX_WORDS]; // 32 words
    for i in 0..MIX_WORDS {
        mix[i] = u32::from_le_bytes([
            seed[(i % 16) * 4],
            seed[(i % 16) * 4 + 1],
            seed[(i % 16) * 4 + 2],
            seed[(i % 16) * 4 + 3],
        ]);
    }

    // Mix in random dataset nodes (64 accesses).
    let mut temp = [0u32; MIX_WORDS];
    for i in 0..ACCESSES {
        let parent = fnv((i as u32) ^ seed_head, mix[i % MIX_WORDS]) % rows;
        // Fetch MIX_BYTES/HASH_BYTES (=2) consecutive dataset items into temp.
        for j in 0..(MIX_BYTES / HASH_BYTES) {
            let item = calc_dataset_item(cache, 2 * parent + j as u32);
            for w in 0..HASH_WORDS {
                temp[j * HASH_WORDS + w] = u32::from_le_bytes([
                    item[w * 4],
                    item[w * 4 + 1],
                    item[w * 4 + 2],
                    item[w * 4 + 3],
                ]);
            }
        }
        // FNV mix with temp.
        for k in 0..MIX_WORDS {
            mix[k] = mix[k].wrapping_mul(0x01000193) ^ temp[k];
        }
    }

    // Compress mix: 32 words → 8 words via nested FNV.
    let mut cmix = [0u32; 8];
    for i in 0..MIX_WORDS / 4 {
        cmix[i] = fnv(
            fnv(fnv(mix[i * 4], mix[i * 4 + 1]), mix[i * 4 + 2]),
            mix[i * 4 + 3],
        );
    }

    // Convert compressed mix to bytes.
    let mut digest = [0u8; 32];
    for i in 0..8 {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&cmix[i].to_le_bytes());
    }

    let mix_hash = B256::from(digest);

    // Result = keccak256(seed ++ digest).
    let mut result_input = [0u8; 64 + 32];
    result_input[..64].copy_from_slice(&seed);
    result_input[64..].copy_from_slice(&digest);
    let result = B256::from_slice(&Keccak256::digest(result_input));

    (mix_hash, result)
}

/// Compute the PoW target from difficulty: target = 2^256 / difficulty.
pub fn difficulty_to_target(difficulty: &U256) -> U256 {
    if difficulty.is_zero() {
        return U256::MAX;
    }
    U256::MAX / *difficulty
}

/// Verify that a block's PoW is valid using light (cache-only) verification.
///
/// Checks:
/// 1. hashimoto_light(seal_hash, nonce) produces the correct mix_hash
/// 2. The result hash is <= target (2^256 / difficulty)
pub fn verify_pow(header: &chain::types::BlockHeader, cache: &[u8]) -> Result<(), EthashError> {
    let seal_hash = header.seal_hash();
    let nonce = u64::from_be_bytes(header.nonce);
    let full_size = dataset_size(epoch(header.number));

    let (mix_hash, result) = hashimoto_light(&seal_hash, nonce, full_size, cache);

    // Check mix hash.
    if mix_hash != header.mix_hash {
        return Err(EthashError::MixHashMismatch {
            expected: header.mix_hash,
            computed: mix_hash,
        });
    }

    // Check difficulty target.
    let target = difficulty_to_target(&header.difficulty);
    let result_u256 = U256::from_be_slice(result.as_ref());
    if result_u256 > target {
        return Err(EthashError::DifficultyNotMet {
            target,
            result: result_u256,
        });
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum EthashError {
    #[error("mix hash mismatch: expected {expected:?}, computed {computed:?}")]
    MixHashMismatch { expected: B256, computed: B256 },
    #[error("difficulty not met: result {result} > target {target}")]
    DifficultyNotMet { target: U256, result: U256 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_computation() {
        // Pre-Thanos: epoch_length = 30000
        assert_eq!(epoch(0), 0);
        assert_eq!(epoch(29_999), 0);
        assert_eq!(epoch(30_000), 1);
        assert_eq!(epoch(30_001), 1);
    }

    #[test]
    fn epoch_computation_post_thanos() {
        // Post-Thanos (block >= 11_700_000): epoch_length = 60000
        assert_eq!(epoch_length(11_700_000), 60_000);
        assert_eq!(epoch(11_700_000), 195); // 11_700_000 / 60_000
        assert_eq!(epoch(24_052_499), 400); // 24_052_499 / 60_000
    }

    #[test]
    fn seed_hash_epoch_0() {
        let s = seed_hash(0, EPOCH_LENGTH_DEFAULT);
        assert_eq!(s, B256::ZERO);
    }

    #[test]
    fn seed_hash_epoch_1() {
        let s = seed_hash(1, EPOCH_LENGTH_DEFAULT);
        let expected = B256::from_slice(&Keccak256::digest([0u8; 32]));
        assert_eq!(s, expected);
    }

    #[test]
    fn cache_size_epoch_0() {
        let size = cache_size(0);
        assert!(size > 0);
        assert_eq!(size % HASH_BYTES, 0);
    }

    #[test]
    fn dataset_size_epoch_0() {
        let size = dataset_size(0);
        assert!(size > 0);
        assert_eq!(size % MIX_BYTES, 0);
    }

    #[test]
    fn make_cache_deterministic() {
        let c1 = make_cache(0, EPOCH_LENGTH_DEFAULT);
        let c2 = make_cache(0, EPOCH_LENGTH_DEFAULT);
        assert_eq!(c1, c2);
    }

    #[test]
    fn difficulty_to_target_basic() {
        let target = difficulty_to_target(&U256::from(1));
        assert_eq!(target, U256::MAX);

        let target = difficulty_to_target(&U256::from(2));
        assert_eq!(target, U256::MAX / U256::from(2));
    }

    /// Verify ethash against ETC mainnet block 1.
    #[test]
    fn verify_pow_etc_mainnet_block_1() {
        use alloy_primitives::Address;

        // Block 1 header data from ETC mainnet.
        let header = chain::types::BlockHeader {
            parent_hash: B256::from_slice(
                &hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                    .unwrap(),
            ),
            uncle_hash: B256::from_slice(
                &hex::decode("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
                    .unwrap(),
            ),
            coinbase: Address::from_slice(
                &hex::decode("05a56e2d52c817161883f50c441c3228cfe54d9f").unwrap(),
            ),
            state_root: B256::from_slice(
                &hex::decode("d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3")
                    .unwrap(),
            ),
            transactions_root: B256::from_slice(
                &hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                    .unwrap(),
            ),
            receipts_root: B256::from_slice(
                &hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                    .unwrap(),
            ),
            logs_bloom: [0u8; 256],
            difficulty: U256::from(0x3ff800000u64),
            number: 1,
            gas_limit: 5000,
            gas_used: 0,
            timestamp: 1438269988,
            extra_data: hex::decode("476574682f76312e302e302f6c696e75782f676f312e342e32").unwrap(),
            mix_hash: B256::from_slice(
                &hex::decode("969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f59")
                    .unwrap(),
            ),
            nonce: <[u8; 8]>::try_from(hex::decode("539bd4979fef1ec4").unwrap().as_slice())
                .unwrap(),
            base_fee: None,
        };

        // Generate epoch 0 cache and verify PoW.
        let seal = header.seal_hash();
        let cache = make_cache(0, EPOCH_LENGTH_DEFAULT);
        let full_size = dataset_size(0);
        let nonce = u64::from_be_bytes(header.nonce);

        let (computed_mix, result) = hashimoto_light(&seal, nonce, full_size, &cache);
        assert_eq!(computed_mix, header.mix_hash, "mix hash mismatch");

        // Verify difficulty target.
        let target = difficulty_to_target(&header.difficulty);
        let result_u256 = U256::from_be_slice(result.as_ref());
        assert!(
            result_u256 <= target,
            "result {result_u256} > target {target}"
        );

        // Also verify via the high-level verify_pow function.
        verify_pow(&header, &cache).expect("verify_pow should pass for real block");
    }
}
