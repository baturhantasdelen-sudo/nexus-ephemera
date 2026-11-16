//! Nexus Ephemera — otonom, çevrimdışı keşif ve şifreli mesh kütüphanesi.

#![forbid(unsafe_code)]

pub mod apoptosis;
pub mod audit;
pub use apoptosis::WipeStatus;
pub mod adapters;
pub mod broker;
pub mod context;
pub mod crypto;
pub mod enterprise;
pub mod enterprise_runtime;
pub mod exposure;
#[cfg(feature = "reference-pilots")]
pub mod field;
pub(crate) mod idempotency;
pub mod ipc;
pub mod mesh;
pub mod metrics;
pub mod operations;
pub mod packaging;
pub mod scout;
