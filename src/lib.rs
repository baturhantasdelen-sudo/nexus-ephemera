//! Nexus Ephemera — otonom, çevrimdışı keşif ve şifreli mesh kütüphanesi.

#![forbid(unsafe_code)]

pub mod apoptosis;
pub use apoptosis::WipeStatus;
pub mod broker;
pub mod context;
pub mod crypto;
pub mod exposure;
pub(crate) mod idempotency;
pub mod ipc;
pub mod mesh;
pub mod metrics;
pub mod scout;
