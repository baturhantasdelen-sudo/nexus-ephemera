//! In-memory idempotency cache for the broker daemon.
//!
//! A hit returns the cached outcome and does not dispatch again. The cache
//! dies with the process. It is not a durable store and not an authenticator.
//! The idempotency key is not part of the binding digest.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::broker::{BrokerError, TransactionReceipt};
use crate::ipc::IpcError;

pub(crate) const CACHE_CAP: usize = 256;
pub(crate) const KEY_MAX: usize = 128;

#[derive(Clone)]
pub(crate) enum CachedBody {
    /// Dispatch has started. A retry must not start a second one.
    Pending,
    Done {
        receipt: TransactionReceipt,
        incomplete: bool,
    },
    /// Never expire an uncertain side effect automatically. Reconciliation or
    /// process restart is required; capacity exhaustion rejects new work.
    Inconclusive,
}

struct Entry {
    endpoint: String,
    payload_hash: String,
    stored: Instant,
    body: CachedBody,
}

pub(crate) enum Lookup {
    Miss,
    Full,
    Conflict,
    Replay(Result<TransactionReceipt, IpcError>),
}

pub(crate) struct IdempotencyCache {
    ttl: Duration,
    cap: usize,
    map: HashMap<String, Entry>,
}

impl IdempotencyCache {
    pub(crate) fn new(ttl: Duration, cap: usize) -> Self {
        Self {
            ttl,
            cap,
            map: HashMap::new(),
        }
    }

    pub(crate) fn lookup(&mut self, key: &str, endpoint: &str, payload_hash: &str) -> Lookup {
        self.sweep();
        match self.map.get(key) {
            None if self.map.len() >= self.cap => Lookup::Full,
            None => Lookup::Miss,
            Some(entry) if entry.endpoint == endpoint && entry.payload_hash == payload_hash => {
                Lookup::Replay(entry.body.replay())
            }
            Some(_) => Lookup::Conflict,
        }
    }

    pub(crate) fn commit(
        &mut self,
        key: &str,
        endpoint: &str,
        payload_hash: &str,
        body: CachedBody,
    ) {
        self.sweep();
        if self.map.contains_key(key) || self.map.len() < self.cap {
            self.map.insert(
                key.to_string(),
                Entry {
                    endpoint: endpoint.to_string(),
                    payload_hash: payload_hash.to_string(),
                    stored: Instant::now(),
                    body,
                },
            );
        }
    }

    fn sweep(&mut self) {
        let ttl = self.ttl;
        self.map.retain(|_, entry| {
            matches!(entry.body, CachedBody::Inconclusive | CachedBody::Pending)
                || entry.stored.elapsed() < ttl
        });
    }
}

impl CachedBody {
    fn replay(&self) -> Result<TransactionReceipt, IpcError> {
        match self {
            Self::Done {
                receipt,
                incomplete: false,
            } => Ok(receipt.clone()),
            Self::Done {
                receipt,
                incomplete: true,
            } => Err(IpcError::CleanupIncomplete(receipt.clone())),
            Self::Pending | Self::Inconclusive => Err(IpcError::Inconclusive),
        }
    }

    pub(crate) fn from_outcome(
        outcome: &Result<TransactionReceipt, IpcError>,
    ) -> Option<CachedBody> {
        match outcome {
            Ok(receipt) => Some(Self::Done {
                receipt: receipt.clone(),
                incomplete: false,
            }),
            Err(IpcError::CleanupIncomplete(receipt)) => Some(Self::Done {
                receipt: receipt.clone(),
                incomplete: true,
            }),
            Err(IpcError::Inconclusive | IpcError::TimedOut)
            | Err(IpcError::Broker(BrokerError::Transport(_) | BrokerError::Inconclusive)) => {
                Some(Self::Inconclusive)
            }
            _ => None,
        }
    }
}

pub(crate) fn valid_key(key: &str) -> bool {
    (1..=KEY_MAX).contains(&key.len()) && key.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use crate::broker::SealReport;

    use super::*;

    fn receipt(hash: &str) -> TransactionReceipt {
        TransactionReceipt {
            target_endpoint: "https://provider.example/charge".into(),
            payload_hash: hash.into(),
            binding_digest_hex: "digest-must-stay-out-of-errors".into(),
            transport_status: 204,
            seal_report: SealReport::Retained,
            idempotency_key: "same-key".into(),
        }
    }

    #[test]
    fn replay_does_not_require_a_second_dispatch_and_conflict_does_not_match() {
        let mut cache = IdempotencyCache::new(Duration::from_secs(30), 8);
        assert!(matches!(
            cache.lookup("same-key", "https://provider.example/charge", "hash-a"),
            Lookup::Miss
        ));
        cache.commit(
            "same-key",
            "https://provider.example/charge",
            "hash-a",
            CachedBody::Done {
                receipt: receipt("hash-a"),
                incomplete: false,
            },
        );
        let Lookup::Replay(Ok(replayed)) =
            cache.lookup("same-key", "https://provider.example/charge", "hash-a")
        else {
            panic!("expected replay");
        };
        assert_eq!(replayed.payload_hash, "hash-a");
        assert!(matches!(
            cache.lookup("same-key", "https://provider.example/charge", "hash-b"),
            Lookup::Conflict
        ));
        assert!(matches!(
            cache.lookup("same-key", "https://other.example/charge", "hash-a"),
            Lookup::Conflict
        ));
    }

    #[test]
    fn cleanup_incomplete_replays_without_leaking_the_digest() {
        let mut cache = IdempotencyCache::new(Duration::from_secs(30), 8);
        let mut stored = receipt("hash-a");
        stored.seal_report = SealReport::Partial;
        cache.commit(
            "same-key",
            "https://provider.example/charge",
            "hash-a",
            CachedBody::Done {
                receipt: stored,
                incomplete: true,
            },
        );
        let Lookup::Replay(Err(err)) =
            cache.lookup("same-key", "https://provider.example/charge", "hash-a")
        else {
            panic!("expected cleanup replay");
        };
        let shown = err.to_string();
        assert!(matches!(err, IpcError::CleanupIncomplete(_)));
        assert!(!shown.contains("digest-must-stay-out-of-errors"));
    }

    #[test]
    fn expired_key_is_not_a_replay_and_a_full_cache_refuses_a_new_key() {
        let mut cache = IdempotencyCache::new(Duration::from_millis(1), 1);
        cache.commit(
            "same-key",
            "https://provider.example/charge",
            "hash-a",
            CachedBody::Done {
                receipt: receipt("hash-a"),
                incomplete: false,
            },
        );
        thread::sleep(Duration::from_millis(5));
        assert!(matches!(
            cache.lookup("same-key", "https://provider.example/charge", "hash-a"),
            Lookup::Miss
        ));

        let mut limited = IdempotencyCache::new(Duration::from_secs(30), 1);
        limited.commit(
            "one",
            "https://provider.example/charge",
            "hash-a",
            CachedBody::Done {
                receipt: receipt("hash-a"),
                incomplete: false,
            },
        );
        assert!(matches!(
            limited.lookup("two", "https://provider.example/charge", "hash-a"),
            Lookup::Full
        ));
    }
    #[test]
    fn uncertain_side_effect_never_expires_or_allows_key_rebinding() {
        let mut cache = IdempotencyCache::new(Duration::ZERO, 1);
        cache.commit("key", "endpoint", "hash", CachedBody::Inconclusive);
        assert!(matches!(
            cache.lookup("key", "endpoint", "hash"),
            Lookup::Replay(Err(IpcError::Inconclusive))
        ));
        assert!(matches!(
            cache.lookup("key", "other", "hash"),
            Lookup::Conflict
        ));
        assert!(matches!(
            cache.lookup("new", "endpoint", "hash"),
            Lookup::Full
        ));
    }

    #[test]
    fn pending_and_inconclusive_reject_a_second_dispatch() {
        let mut cache = IdempotencyCache::new(Duration::from_millis(1), 4);
        cache.commit("key", "endpoint", "hash", CachedBody::Pending);
        thread::sleep(Duration::from_millis(5));
        assert!(matches!(
            cache.lookup("key", "endpoint", "hash"),
            Lookup::Replay(Err(IpcError::Inconclusive))
        ));
        cache.commit("key", "endpoint", "hash", CachedBody::Inconclusive);
        assert!(matches!(
            cache.lookup("key", "endpoint", "hash"),
            Lookup::Replay(Err(IpcError::Inconclusive))
        ));
        assert!(matches!(
            cache.lookup("key", "endpoint", "other-hash"),
            Lookup::Conflict
        ));
    }
}
