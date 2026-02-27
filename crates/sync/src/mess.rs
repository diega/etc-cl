use alloy_primitives::{B256, U256};
use eth_rpc::EthClient;
use tracing::{debug, warn};

// MESS (ECBP-1100) polynomial constants
// Reference: https://github.com/ethereumclassic/ECIPs/blob/master/_specs/ecip-1100.md

/// x_cap = 25132 (floor(8000*pi))
const MESS_XCAP: u64 = 25132;

/// Denominator for the polynomial curve function.
const MESS_DENOMINATOR: u64 = 128;

/// Height = DENOMINATOR * ampl * 2 = 128 * 15 * 2 = 3840
const MESS_HEIGHT: u64 = 128 * 15 * 2;

/// Minimum number of connected peers before MESS can be active.
pub const MIN_MESS_PEERS: usize = 5;

/// Head is considered stale if older than this many seconds.
pub const STALE_HEAD_THRESHOLD: u64 = 390;

/// ECBP-1100 activation block. `None` = not hardcoded.
pub const ECBP1100_ACTIVATION: Option<u64> = None;

/// Configuration for MESS, combining the hardcoded activation block
/// with an optional user-provided CLI flag.
pub struct MessConfig {
    pub activation_block: Option<u64>,
    pub flag: Option<bool>,
}

impl MessConfig {
    /// Whether MESS is enabled at a given block number.
    ///
    /// Logic:
    /// 1. If `flag == Some(false)` → OFF (explicit override)
    /// 2. If activation_block is set (and flag != false) → ON from that block
    /// 3. If `flag == Some(true)` (and no activation block) → ON always
    /// 4. Otherwise → OFF
    pub fn is_enabled_at(&self, block_number: u64) -> bool {
        if self.flag == Some(false) {
            return false;
        }
        if let Some(activation) = self.activation_block {
            return block_number >= activation;
        }
        self.flag == Some(true)
    }

    /// Whether MESS is fully disabled (will never activate).
    pub fn is_disabled(&self) -> bool {
        self.flag == Some(false) || (self.activation_block.is_none() && self.flag.is_none())
    }
}

/// Calculate the antigravity value for a given time delta in seconds.
///
/// Formula (integer arithmetic, matching Go reference):
///   128 + (3*x² - 2*x³/xcap) * height / xcap²
///
/// Where x is capped to `MESS_XCAP`.
/// Result range: 128 (no penalty) to 3968 (maximum, ~7 hours).
pub fn antigravity(time_delta_secs: u64) -> U256 {
    let x = time_delta_secs.min(MESS_XCAP);
    let x = U256::from(x);
    let xcap = U256::from(MESS_XCAP);
    let height = U256::from(MESS_HEIGHT);
    let denom = U256::from(MESS_DENOMINATOR);

    // 3 * x²
    let x_sq = x * x;
    let term_a = U256::from(3) * x_sq;

    // 2 * x³ / xcap
    let x_cu = x_sq * x;
    let term_b = (U256::from(2) * x_cu) / xcap;

    // (term_a - term_b) * height / xcap²
    let numerator = (term_a - term_b) * height;
    let xcap_sq = xcap * xcap;
    let curve = numerator / xcap_sq;

    denom + curve
}

/// Check whether a proposed reorg is allowed under MESS.
///
/// The check is: `proposed_subchain_td * 128 >= antigravity(time_delta) * local_subchain_td`
pub fn is_reorg_allowed(
    local_subchain_td: &U256,
    proposed_subchain_td: &U256,
    time_since_ancestor: u64,
) -> bool {
    let ag = antigravity(time_since_ancestor);
    let want = ag * *local_subchain_td;
    let got = *proposed_subchain_td * U256::from(MESS_DENOMINATOR);
    got >= want
}

/// Whether MESS should be active given current network conditions.
/// Requires enough peers and a non-stale head.
pub fn should_be_active(peer_count: usize, head_timestamp: u64, now: u64) -> bool {
    peer_count >= MIN_MESS_PEERS && now.saturating_sub(head_timestamp) <= STALE_HEAD_THRESHOLD
}

/// Find the common ancestor between two chain branches by querying the EL.
///
/// Returns `Some((hash, number, timestamp, td))` of the common ancestor,
/// or `None` if anything goes wrong (fail-open: caller should allow the reorg).
pub async fn find_common_ancestor(
    eth_client: &EthClient,
    hash_a: B256,
    hash_b: B256,
) -> Option<(B256, u64, u64, U256)> {
    if hash_a == hash_b {
        let block = eth_client.get_block_by_hash(hash_a).await.ok()?;
        return Some((
            block.hash,
            block.number,
            block.timestamp,
            block.total_difficulty?,
        ));
    }

    let mut a = eth_client.get_block_by_hash(hash_a).await.ok()?;
    let mut b = eth_client.get_block_by_hash(hash_b).await.ok()?;

    // Equalize heights: walk the taller one back (capped to avoid unbounded RPCs)
    const MAX_HEIGHT_STEPS: u64 = 1000;
    let mut height_steps: u64 = 0;
    while a.number > b.number {
        height_steps += 1;
        if height_steps > MAX_HEIGHT_STEPS {
            warn!(
                "MESS: height equalization exceeded {} steps, giving up",
                MAX_HEIGHT_STEPS
            );
            return None;
        }
        debug!(walking = "a", number = a.number, "MESS: equalizing heights");
        a = eth_client.get_block_by_hash(a.parent_hash).await.ok()?;
    }
    while b.number > a.number {
        height_steps += 1;
        if height_steps > MAX_HEIGHT_STEPS {
            warn!(
                "MESS: height equalization exceeded {} steps, giving up",
                MAX_HEIGHT_STEPS
            );
            return None;
        }
        debug!(walking = "b", number = b.number, "MESS: equalizing heights");
        b = eth_client.get_block_by_hash(b.parent_hash).await.ok()?;
    }

    // Walk both back until they match
    let mut steps: u64 = 0;
    while a.hash != b.hash {
        steps += 1;
        if steps > 10_000 {
            warn!("MESS: common ancestor search exceeded 10000 steps, giving up");
            return None;
        }
        a = eth_client.get_block_by_hash(a.parent_hash).await.ok()?;
        b = eth_client.get_block_by_hash(b.parent_hash).await.ok()?;
    }

    Some((a.hash, a.number, a.timestamp, a.total_difficulty?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn antigravity_at_zero() {
        // At x=0, antigravity should be just the denominator (128)
        assert_eq!(antigravity(0), U256::from(128));
    }

    #[test]
    fn antigravity_at_xcap() {
        // At x=xcap, the polynomial reaches maximum:
        // 128 + (3*xcap² - 2*xcap³/xcap) * height / xcap²
        // = 128 + (3*xcap² - 2*xcap²) * height / xcap²
        // = 128 + xcap² * height / xcap²
        // = 128 + height
        // = 128 + 3840 = 3968
        assert_eq!(antigravity(MESS_XCAP), U256::from(3968));
    }

    #[test]
    fn antigravity_beyond_xcap() {
        // Beyond xcap should be same as at xcap (capped)
        assert_eq!(antigravity(MESS_XCAP + 1000), U256::from(3968));
        assert_eq!(antigravity(100_000), U256::from(3968));
    }

    #[test]
    fn antigravity_monotonic() {
        // Should be monotonically increasing
        let mut prev = antigravity(0);
        for x in (1..=MESS_XCAP).step_by(100) {
            let curr = antigravity(x);
            assert!(
                curr >= prev,
                "antigravity not monotonic at x={}: {} < {}",
                x,
                curr,
                prev
            );
            prev = curr;
        }
    }

    #[test]
    fn reorg_allowed_no_time() {
        // With 0 time delta, antigravity = 128, so any TD >= local is allowed
        assert!(is_reorg_allowed(&U256::from(1000), &U256::from(1000), 0,));
        assert!(is_reorg_allowed(&U256::from(1000), &U256::from(1001), 0,));
    }

    #[test]
    fn reorg_rejected_high_antigravity() {
        // At max antigravity (3968), proposed needs 3968/128 = 31x the local TD
        assert!(!is_reorg_allowed(
            &U256::from(1000),
            &U256::from(1000),
            MESS_XCAP,
        ));
        // Even 30x isn't enough
        assert!(!is_reorg_allowed(
            &U256::from(1000),
            &U256::from(30_000),
            MESS_XCAP,
        ));
        // But 31x is
        assert!(is_reorg_allowed(
            &U256::from(1000),
            &U256::from(31_000),
            MESS_XCAP,
        ));
    }

    #[test]
    fn mess_config_disabled_by_flag() {
        let cfg = MessConfig {
            activation_block: Some(100),
            flag: Some(false),
        };
        assert!(!cfg.is_enabled_at(200));
        assert!(cfg.is_disabled());
    }

    #[test]
    fn mess_config_enabled_by_activation() {
        let cfg = MessConfig {
            activation_block: Some(100),
            flag: None,
        };
        assert!(!cfg.is_enabled_at(99));
        assert!(cfg.is_enabled_at(100));
        assert!(cfg.is_enabled_at(200));
        assert!(!cfg.is_disabled());
    }

    #[test]
    fn mess_config_enabled_by_flag_only() {
        let cfg = MessConfig {
            activation_block: None,
            flag: Some(true),
        };
        assert!(cfg.is_enabled_at(0));
        assert!(cfg.is_enabled_at(999_999));
        assert!(!cfg.is_disabled());
    }

    #[test]
    fn mess_config_disabled_by_default() {
        let cfg = MessConfig {
            activation_block: None,
            flag: None,
        };
        assert!(!cfg.is_enabled_at(0));
        assert!(!cfg.is_enabled_at(999_999));
        assert!(cfg.is_disabled());
    }

    #[test]
    fn mess_config_activation_with_true_flag() {
        // flag=true + activation block = ON from that block
        let cfg = MessConfig {
            activation_block: Some(100),
            flag: Some(true),
        };
        assert!(!cfg.is_enabled_at(99));
        assert!(cfg.is_enabled_at(100));
    }

    #[test]
    fn should_be_active_checks() {
        let now = 1000;
        // Not enough peers
        assert!(!should_be_active(4, now - 10, now));
        // Enough peers, recent head
        assert!(should_be_active(5, now - 10, now));
        // Enough peers, stale head
        assert!(!should_be_active(5, now - 391, now));
        // Exactly at threshold
        assert!(should_be_active(5, now - 390, now));
    }
}
