//! Events emitted on every state change so indexers and explorers get
//! push-style updates (README: design decisions). Defined with
//! `#[contractevent]` so the event schemas are exported in the contract
//! spec for downstream consumers.

use soroban_sdk::{contractevent, Address, Symbol};

use crate::types::{VerificationRecord, VerifierInfo};

/// Emitted when a verifier publishes or overwrites a verification record.
#[contractevent(topics = ["attest"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attest {
    #[topic]
    pub contract: Address,
    #[topic]
    pub verifier: Address,
    pub record: VerificationRecord,
}

/// Emitted when a verification is revoked. `reason` is a
/// machine-readable code (e.g. `imgcompr` for a compromised build image).
#[contractevent(topics = ["revoke"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Revoke {
    #[topic]
    pub contract: Address,
    #[topic]
    pub revoked_by: Address,
    pub reason: Symbol,
}

/// Emitted when governance adds, updates, or deactivates a verifier.
#[contractevent(topics = ["verifier"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierSet {
    #[topic]
    pub verifier: Address,
    pub info: VerifierInfo,
}

/// Emitted when the admin address is rotated.
#[contractevent(topics = ["admin"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRotated {
    pub new_admin: Address,
}
