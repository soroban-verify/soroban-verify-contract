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

/// Optional conflict-resolution policy that governance can configure
/// for the canonical `Verification(contract_id)` record.
///
/// The default value (`LastWriteWins`) preserves the existing behaviour
/// so deployments prior to this feature keep working unchanged. Once
/// governance sets a different policy, it applies to *subsequent*
/// attestations for that contract — historical canonical records
/// already published under a prior policy are not backfilled, since
/// the on-chain evidence lives on either way
/// (`VerifierAttestation` is always written).
///
/// Spec-traceability: addresses the gap the README documents as
/// "among active verifiers, attestation is last-write-wins per
/// contract". Once independent verifiers exist, downstream consumers
/// (lending protocols, etc.) need a way to distinguish a single-
/// verifier attestation from a multi-verifier consensus or from a
/// contested result.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationPolicy {
    /// (default) Most-recent `attest` wins. Equivalent to the
    /// pre-M5 behaviour.
    LastWriteWins,
    /// Canonical record is published only once at least `n`
    /// *active*, independent verifiers have attested to the same
    /// `wasm_hash` for the contract. While the quorum has not yet
    /// been reached, the canonical entry remains absent so
    /// downstream consumers see "contested / under-verified"
    /// rather than a misleading single-verifier claim.
    MinQuorum(u32),
    /// The canonical record's `trust_level` is the minimum across
    /// all currently-active per-verifier attestations. Recomputed
    /// when a verifier is deactivated (on subsequent attestations to
    /// the affected contracts).
    LowestTrust,
}

/// Storage keys. Verifications and verifier attestations live in
/// persistent storage; the admin and the active policy live in
/// instance storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// `Verification(contract_id)` → canonical `VerificationRecord`.
    /// What a downstream consumer reads via `get_verification`.
    Verification(Address),
    /// `Verifier(address)` → `VerifierInfo`.
    Verifier(Address),
    /// Multi-sig admin address (governance).
    Admin,
    /// Instance storage → active `VerificationPolicy` (governance).
    Policy,
    /// Persistent: per-(contract, verifier) attestation record. Always
    /// written on `attest` alongside the canonical record, so the
    /// policy aggregates have a source of truth even when only
    /// `LastWriteWins` is in effect. Stored independently because
    /// `MinQuorum` / `LowestTrust` need to see *all* active
    /// verifiers, not just the last writer.
    VerifierAttestation(Address, Address),
    /// Persistent: `Vec<Address>` of verifiers that have ever
    /// attested to `contract_id`. Kept across policy changes and
    /// across verifier deactivations so we can recompute aggregates
    /// from a stable evidence trail.
    ContractVerifiers(Address),
    /// Persistent: reverse index of contracts a verifier has ever
    /// attested to. Lets `set_verifier` recompute policy state
    /// quickly on deactivation under `LowestTrust`.
    VerifierContracts(Address),
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// `init` has already been called.
    AlreadyInitialized = 1,
    /// `init` has not been called yet.
    NotInitialized = 2,
    /// Caller is not a registered, active verifier (or admin, where
    /// allowed).
    UnauthorizedVerifier = 3,
    /// No verification record exists for the given contract.
    VerificationNotFound = 4,
    /// `set_policy(MinQuorum(0))` — a zero quorum would deadlock
    /// reads and is rejected at the gate.
    InvalidPolicy = 5,
}
