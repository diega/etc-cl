/// Maximum number of uncles per block.
pub const MAX_UNCLES: usize = 2;

/// Maximum uncle depth (uncle block number must be within this many blocks of the including block).
pub const MAX_UNCLE_DEPTH: u64 = 7;

/// Minimum difficulty for ETC.
pub const MIN_DIFFICULTY: u64 = 131_072;

/// Difficulty bound divisor.
pub const DIFFICULTY_BOUND_DIVISOR: u64 = 2048;
