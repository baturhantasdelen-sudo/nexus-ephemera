//! Bounded, process-local evidence of fixed outcome labels.
//! No durability, authentication or protection from a compromised process.
use sha2::{Digest, Sha256};
use std::sync::Mutex;
const CAP: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Dispatch,
    Inconclusive,
    Other,
}
impl Event {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Dispatch => b"dispatch",
            Self::Inconclusive => b"inconclusive",
            Self::Other => b"other",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub sequence: u64,
    pub event: Event,
    pub digest: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub anchor: [u8; 32],
    pub records: Vec<Record>,
    pub head: [u8; 32],
    pub saturated: bool,
}
fn digest(previous: [u8; 32], sequence: u64, event: Event) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"nexus-audit-v1");
    h.update(previous);
    h.update(sequence.to_le_bytes());
    h.update(event.bytes());
    h.finalize().into()
}
impl Snapshot {
    pub fn verify(&self) -> bool {
        let mut previous = self.anchor;
        let mut sequence = None;
        for r in &self.records {
            if sequence.is_some_and(|s: u64| s.checked_add(1) != Some(r.sequence))
                || r.digest != digest(previous, r.sequence, r.event)
            {
                return false;
            }
            previous = r.digest;
            sequence = Some(r.sequence);
        }
        previous == self.head
    }
}
struct Ring {
    prev: [u8; 32],
    anchor: [u8; 32],
    records: std::collections::VecDeque<Record>,
    sequence: u64,
    saturated: bool,
}
impl Ring {
    const fn empty() -> Self {
        Self {
            prev: [0; 32],
            anchor: [0; 32],
            records: std::collections::VecDeque::new(),
            sequence: 0,
            saturated: false,
        }
    }
    fn append(&mut self, event: Event) {
        let Some(sequence) = self.sequence.checked_add(1) else {
            self.saturated = true;
            return;
        };
        let next = digest(self.prev, sequence, event);
        if self.records.len() == CAP {
            self.anchor = self.records.pop_front().expect("full ring").digest;
        }
        self.records.push_back(Record {
            sequence,
            event,
            digest: next,
        });
        self.prev = next;
        self.sequence = sequence;
    }
}
static RING: Mutex<Ring> = Mutex::new(Ring::empty());
/// Only fixed labels are admitted; unknown input is represented as Other.
pub fn note(label: &str) {
    let event = match label {
        "dispatch" => Event::Dispatch,
        "inconclusive" => Event::Inconclusive,
        _ => Event::Other,
    };
    RING.lock().unwrap_or_else(|e| e.into_inner()).append(event);
}
pub fn snapshot() -> Snapshot {
    let ring = RING.lock().unwrap_or_else(|e| e.into_inner());
    Snapshot {
        anchor: ring.anchor,
        records: ring.records.iter().cloned().collect(),
        head: ring.prev,
        saturated: ring.saturated,
    }
}
#[cfg(feature = "fuzz")]
pub fn chain_len() -> usize {
    RING.lock()
        .unwrap_or_else(|e| e.into_inner())
        .sequence
        .try_into()
        .unwrap_or(usize::MAX)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_chain_is_verifiable_after_eviction() {
        let mut r = Ring::empty();
        for _ in 0..CAP + 3 {
            r.append(Event::Dispatch);
        }
        let mut s = Snapshot {
            anchor: r.anchor,
            records: r.records.iter().cloned().collect(),
            head: r.prev,
            saturated: false,
        };
        assert_eq!(s.records.len(), CAP);
        assert!(s.verify());
        s.records[0].event = Event::Other;
        assert!(!s.verify());
    }
}
