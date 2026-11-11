//! Nexus Ephemera — otonom, çevrimdışı keşif ve şifreli mesh kütüphanesi.

#![forbid(unsafe_code)]

pub mod apoptosis;
pub use apoptosis::WipeStatus;
pub mod crypto;
pub mod mesh;
pub mod scout;
