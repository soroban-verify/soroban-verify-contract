use soroban_sdk::{contracterror, contracttype, Address, BytesN, String};

/// Multi-dimensional trust level assigned to a verification result.
///
/// Ordered so that numeric comparison is meaningful for downstream
/// consumers: a lending protocol can require
/// `trust_level >= TrustLevel::Auditable` before listing a collateral
/// token contract. (RFP: image trust is a signal, not a binary.)
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TrustLevel {
    /// 🔴 Rebuild failed, bytes mismatched, or the verification was
    /// revoked after the fact (e.g. a trusted image was later found
    /// compromised).
    Failed = 0,
    /// 🟠 Reproduced, but inside an arbitrary deployer-supplied image.
    /// Reproducibility alone is not faithfulness to source: a hostile
    /// image can deterministically rewrite bytes and still pass
    /// byte-comparison.
    DeployerSupplied = 1,
    /// 🟡 Reproduced inside a publicly auditable, pinned image.
    Auditable = 2,
    /// 🟢 Reproduced inside an SDF-allowlisted trusted image.
    Trusted = 3,
}

/// A verification claim attested on-chain by a registered verifier.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationRecord {
    /// SHA-256 hash of the on-chain Wasm the rebuild was compared against.
    pub wasm_hash: BytesN<32>,
    /// Source repository the contract claims to be built from.
    pub repo_url: String,
    /// Exact commit the rebuild was performed at.
    pub commit_sha: String,
    /// Trust tier of the build environment (SEP-58 reproducible builds).
    pub trust_level: TrustLevel,
    /// The verifier that attested this record. Overwritten by the
    /// contract on `attest` so a verifier cannot impersonate another.
    pub verifier: Address,
    /// Optional reference to a SEP-55 signed CI attestation binding the
    /// workflow run to the commit and Wasm artifact. Empty string if none.
    pub sep55_attestation_ref: String,
    /// Ledger timestamp at which the attestation was recorded. Set by
    /// the contract on `attest`, not trusted from the caller.
    pub timestamp: u64,
}

/// Metadata about a registered verifier. The registry is multi-verifier
/// from day one so it can outlive any single operator.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierInfo {
    /// Human-readable operator name (e.g. "soroban-verify hosted service").
    pub name: String,
    /// Ed25519 public key the verifier signs off-chain artifacts with
    /// (SEP-55 attestations, API responses).
    pub pubkey: BytesN<32>,
    /// Inactive verifiers keep their history but can no longer attest
    /// or revoke.
    pub active: bool,
}

/// Storage keys. Verifications and verifiers live in persistent storage;
/// the admin lives in instance storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// `Verification(contract_id)` → `VerificationRecord`
    Verification(Address),
    /// `Verifier(address)` → `VerifierInfo`
    Verifier(Address),
    /// Multi-sig admin address (governance).
    Admin,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// `init` has already been called.
    AlreadyInitialized = 1,
    /// `init` has not been called yet.
    NotInitialized = 2,
    /// Caller is not a registered, active verifier.
    UnauthorizedVerifier = 3,
    /// No verification record exists for the given contract.
    VerificationNotFound = 4,
}
