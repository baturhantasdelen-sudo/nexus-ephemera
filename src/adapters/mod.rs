//! Pilot support-agent boundary and the GitHub issue provider.
//!
//! The agent can open one issue on the policy repository. Transfers, deletes,
//! and infrastructure calls are `TargetDenied`. The GitHub token stays in this
//! transport and is not a receipt field, an audit field, or a MAC.

#![forbid(unsafe_code)]

pub mod github;
pub mod github_production;
