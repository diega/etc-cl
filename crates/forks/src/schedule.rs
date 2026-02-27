/// ETC hard fork activations by block number (mainnet).
///
/// Only forks that affect CL consensus logic are listed here.
/// The full fork schedule is managed by the EL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fork {
    Homestead,
    Atlantis, // Spurious Dragon equivalent (ECIP-1054), also Byzantium difficulty (EIP-100)
}

/// Block numbers at which each fork activates on ETC mainnet.
impl Fork {
    pub fn activation_block(&self) -> u64 {
        match self {
            Fork::Homestead => 1_150_000,
            Fork::Atlantis => 8_772_000,
        }
    }
}

/// Returns true if the given fork is active at the given block number.
pub fn is_active(fork: Fork, block_number: u64) -> bool {
    block_number >= fork.activation_block()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn homestead_activation() {
        assert!(!is_active(Fork::Homestead, 1_149_999));
        assert!(is_active(Fork::Homestead, 1_150_000));
    }

    #[test]
    fn atlantis_activation() {
        assert!(!is_active(Fork::Atlantis, 8_771_999));
        assert!(is_active(Fork::Atlantis, 8_772_000));
    }
}
