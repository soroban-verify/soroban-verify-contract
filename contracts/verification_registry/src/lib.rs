//! # Verification Registry
//!
//! On-chain source of truth for `soroban-verify` verification results.
//! Any wallet, explorer, or other smart contract can query verification
//! status trustlessly, without trusting the hosted service's servers.
//!
//! Design decisions (see repo README, "Part 1 — Contract Layer"):
//! - Trust level is stored on-chain as an ordered enum, not a binary
//!   verified/unverified flag.
//! - Revocation is first-class: a revoked record stays in storage with
//!   `TrustLevel::Failed` so downstream consumers see the downgrade
//!   rather than an absence. Revocation forces the canonical record
//!   to Failed regardless of the active conflict-resolution policy.
//! - The verifier role is multi-party from day one; governance (admin)
//!   registers and deactivates verifiers. By default, attestation is
//!   last-write-wins per contract; governance may switch to a
//!   quorum or lowest-trust policy that aggregates per-verifier
//!   attestations into the canonical record.
//! - Events are emitted on every state change for indexers/explorers.

#![no_std]

mod events;
mod types;

#[cfg(test)]
mod test;

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

pub use types::{DataKey, Error, TrustLevel, VerificationPolicy, VerificationRecord, VerifierInfo};

/// Average seconds per Stellar ledger (~5 s). `86_400 / 5 = 17_280`.
const DAY_IN_LEDGERS: u32 = 17280;
/// How far each persistent write extends the entry's TTL.
const BUMP_AMOUNT: u32 = 90 * DAY_IN_LEDGERS;
/// Extend only when the remaining TTL has dropped below this threshold.
const LIFETIME_THRESHOLD: u32 = BUMP_AMOUNT - DAY_IN_LEDGERS;

#[contract]
pub struct VerificationRegistry;

#[contractimpl]
impl VerificationRegistry {
    /// One-time constructor. `admin` is expected to be a multi-sig
    /// governance address.
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .extend_ttl(LIFETIME_THRESHOLD, BUMP_AMOUNT);
        Ok(())
    }

    /// Publish a verification result for `contract_id`.
    ///
    /// Verifier-role gated: `verifier` must authorize the call and be a
    /// registered, active verifier. The contract stamps `record.verifier`
    /// and `record.timestamp` itself, so a verifier can neither
    /// impersonate another verifier nor backdate an attestation.
    ///
    /// The active `VerificationPolicy` (see `set_policy`) is applied
    /// before the canonical `Verification(contract_id)` entry is
    /// written:
    /// - `LastWriteWins` (default): the new record becomes canonical.
    /// - `MinQuorum(n)`: the canonical is published only once `n`
    ///   independent active verifiers have attested to the same
    ///   `wasm_hash`. While the quorum is not yet met the canonical
    ///   entry remains absent.
    /// - `LowestTrust`: the canonical's `trust_level` is the minimum
    ///   across all currently-active per-verifier attestations; the
    ///   record carrying that minimum is selected.
    pub fn attest(
        env: Env,
        verifier: Address,
        contract_id: Address,
        mut record: VerificationRecord,
    ) -> Result<(), Error> {
        verifier.require_auth();
        Self::require_active_verifier(&env, &verifier)?;

        record.verifier = verifier.clone();
        record.timestamp = env.ledger().timestamp();

        let policy = Self::current_policy(&env);

        // Always store the per-verifier attestation so the policy
        // aggregates have a complete evidence trail even when only
        // `LastWriteWins` is in effect. Bumping TTLs matches the rest
        // of the persistent-write path.
        let att_key = DataKey::VerifierAttestation(contract_id.clone(), verifier.clone());
        env.storage().persistent().set(&att_key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&att_key, LIFETIME_THRESHOLD, BUMP_AMOUNT);

        // Maintain reverse mappings so `set_verifier(active = false)`
        // can recompute aggregates in O(active contracts) under
        // `LowestTrust`.
        Self::add_verifier_to_set(
            &env,
            &DataKey::ContractVerifiers(contract_id.clone()),
            &verifier,
        );
        Self::add_verifier_to_set(
            &env,
            &DataKey::VerifierContracts(verifier.clone()),
            &contract_id,
        );

        // Apply the active policy.
        let canonical = match policy {
            VerificationPolicy::LastWriteWins => Some(record.clone()),
            VerificationPolicy::MinQuorum(n) => {
                Self::compute_min_quorum(&env, &contract_id, n, &record)
            }
            VerificationPolicy::LowestTrust => Self::compute_lowest_trust(&env, &contract_id),
        };

        let verify_key = DataKey::Verification(contract_id.clone());
        match canonical {
            Some(c) => {
                env.storage().persistent().set(&verify_key, &c);
                env.storage()
                    .persistent()
                    .extend_ttl(&verify_key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
            }
            None => {
                // Don't clobber an existing canonical if the policy did
                // not produce one (e.g. `MinQuorum` not met yet).
            }
        }
        env.storage()
            .instance()
            .extend_ttl(LIFETIME_THRESHOLD, BUMP_AMOUNT);

        events::Attest {
            contract: contract_id,
            verifier: record.verifier.clone(),
            record,
        }
        .publish(&env);
        Ok(())
    }

    /// Query verification status. Anyone — including other contracts —
    /// can call this trustlessly. Returns `None` if no verification has
    /// ever been attested for `contract_id`.
    pub fn get_verification(env: Env, contract_id: Address) -> Option<VerificationRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Verification(contract_id))
    }

    /// Downgrade/revoke an existing verification (e.g. a trusted build
    /// image is later found compromised).
    ///
    /// Callable by any active verifier or by the admin. The record is
    /// kept in storage with `TrustLevel::Failed` — downstream consumers
    /// must see the downgrade, not an absence. `reason` is a
    /// machine-readable code carried in the emitted event for indexers.
    ///
    /// Revocation bypasses the active conflict-resolution policy
    /// (`MinQuorum` / `LowestTrust`): the canonical record is forced
    /// to `Failed` immediately so wallets and lending protocols see
    /// the compromise without waiting for a quorum to re-form.
    pub fn revoke(
        env: Env,
        revoked_by: Address,
        contract_id: Address,
        reason: Symbol,
    ) -> Result<(), Error> {
        revoked_by.require_auth();
        if Self::require_active_verifier(&env, &revoked_by).is_err() {
            Self::require_admin(&env, &revoked_by)?;
        }

        let key = DataKey::Verification(contract_id.clone());
        // Safety-hatch semantics: revoke must publish a Failed
        // canonical even when the active policy (e.g. `MinQuorum`)
        // has not yet produced one. If a canonical exists, force it
        // to Failed. Otherwise fall back to any per-verifier
        // attestation on the contract so the new Failed canonical
        // still carries provenance (repo_url / commit_sha / wasm_hash).
        // Only when there is no evidence at all do we surface the
        // missing-record error.
        let mut record: VerificationRecord = match env.storage().persistent().get(&key) {
            Some(r) => r,
            None => {
                let verifiers: Vec<Address> = env
                    .storage()
                    .persistent()
                    .get(&DataKey::ContractVerifiers(contract_id.clone()))
                    .unwrap_or_else(|| Vec::new(&env));
                let vlen = verifiers.len();
                let mut vi: u32 = 0;
                let mut fallback: Option<VerificationRecord> = None;
                while vi < vlen {
                    if let Some(v) = verifiers.get(vi) {
                        let att_key = DataKey::VerifierAttestation(contract_id.clone(), v.clone());
                        let candidate: Option<VerificationRecord> =
                            env.storage().persistent().get(&att_key);
                        if candidate.is_some() {
                            fallback = candidate;
                            break;
                        }
                    }
                    vi += 1;
                }
                fallback.ok_or(Error::VerificationNotFound)?
            }
        };

        record.trust_level = TrustLevel::Failed;
        record.timestamp = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);

        // Also force the per-verifier record (if any) to `Failed` so
        // future `LowestTrust` recomputes do not resurrect a pre-
        // revocation trust level for this verifier.
        let att_key = DataKey::VerifierAttestation(contract_id.clone(), revoked_by.clone());
        if env.storage().persistent().has(&att_key) {
            let mut per_v: VerificationRecord = env.storage().persistent().get(&att_key).unwrap();
            per_v.trust_level = TrustLevel::Failed;
            per_v.timestamp = env.ledger().timestamp();
            env.storage().persistent().set(&att_key, &per_v);
            env.storage()
                .persistent()
                .extend_ttl(&att_key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
        }

        events::Revoke {
            contract: contract_id,
            revoked_by,
            reason,
        }
        .publish(&env);
        Ok(())
    }

    /// Governance: register, update, or deactivate a verifier key.
    /// Deactivation (`info.active = false`) preserves the verifier's
    /// history while removing its ability to attest or revoke, and
    /// causes an immediate `LowestTrust` recompute for every contract
    /// the verifier previously attested to.
    pub fn set_verifier(env: Env, verifier: Address, info: VerifierInfo) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();

        let key = DataKey::Verifier(verifier.clone());
        env.storage().persistent().set(&key, &info);
        env.storage()
            .persistent()
            .extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);

        // If we're deactivating an active verifier, recompute every
        // contract they previously attested to. Under `LowestTrust`
        // the min across remaining active verifiers changes; we
        // recompute the canonical so downstream consumers see the new
        // aggregate immediately. Under `LastWriteWins` / `MinQuorum`
        // this is a no-op — once published, historical canonical
        // records are stable evidence.
        if !info.active {
            Self::recompute_contracts_after_deactivation(&env, &verifier);
        }

        events::VerifierSet { verifier, info }.publish(&env);
        Ok(())
    }

    /// Look up a registered verifier's metadata.
    pub fn get_verifier(env: Env, verifier: Address) -> Option<VerifierInfo> {
        env.storage().persistent().get(&DataKey::Verifier(verifier))
    }

    /// Governance: rotate the admin address.
    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        events::AdminRotated { new_admin }.publish(&env);
        Ok(())
    }

    /// The current governance address.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        Self::admin(&env)
    }

    /// Governance: configure the conflict-resolution policy applied
    /// to canonical records. Defaults to `LastWriteWins`.
    ///
    /// Accepts any `VerificationPolicy` variant except `MinQuorum(0)`,
    /// which would deadlock reads (`VerifyingNotFound`-or-cycle)
    /// and is rejected with `InvalidPolicy`.
    pub fn set_policy(env: Env, policy: VerificationPolicy) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();

        if let VerificationPolicy::MinQuorum(n) = &policy {
            if *n == 0 {
                return Err(Error::InvalidPolicy);
            }
        }

        env.storage().instance().set(&DataKey::Policy, &policy);
        env.storage()
            .instance()
            .extend_ttl(LIFETIME_THRESHOLD, BUMP_AMOUNT);

        events::PolicyChanged { new_policy: policy }.publish(&env);
        Ok(())
    }

    /// Read the active conflict-resolution policy. Defaults to
    /// `LastWriteWins` for registries deployed before this feature
    /// shipped and therefore have no `DataKey::Policy` entry.
    pub fn get_policy(env: Env) -> VerificationPolicy {
        Self::current_policy(&env)
    }

    /// Read-only helper for the active policy. Takes `&Env` so the
    /// helper methods can probe policy state without owning `Env`.
    fn current_policy(env: &Env) -> VerificationPolicy {
        env.storage()
            .instance()
            .get(&DataKey::Policy)
            .unwrap_or(VerificationPolicy::LastWriteWins)
    }

    /// Permissionless: refresh the TTL of an existing verification
    /// record so it does not expire. Errors with `VerificationNotFound`
    /// if no attestation has ever been published for `contract_id`.
    pub fn bump_ttl(env: Env, contract_id: Address) -> Result<(), Error> {
        let key = DataKey::Verification(contract_id);
        if !env.storage().persistent().has(&key) {
            return Err(Error::VerificationNotFound);
        }
        env.storage()
            .persistent()
            .extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
        env.storage()
            .instance()
            .extend_ttl(LIFETIME_THRESHOLD, BUMP_AMOUNT);
        Ok(())
    }

    /// Permissionless: refresh the TTL of an existing verifier entry.
    /// Errors with `UnauthorizedVerifier` (repurposed) when no verifier
    /// is registered at `verifier`.
    pub fn bump_verifier_ttl(env: Env, verifier: Address) -> Result<(), Error> {
        let key = DataKey::Verifier(verifier);
        if !env.storage().persistent().has(&key) {
            return Err(Error::UnauthorizedVerifier);
        }
        env.storage()
            .persistent()
            .extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
        env.storage()
            .instance()
            .extend_ttl(LIFETIME_THRESHOLD, BUMP_AMOUNT);
        Ok(())
    }

    fn admin(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    fn require_admin(env: &Env, who: &Address) -> Result<(), Error> {
        if Self::admin(env)? != *who {
            return Err(Error::UnauthorizedVerifier);
        }
        Ok(())
    }

    fn require_active_verifier(env: &Env, verifier: &Address) -> Result<(), Error> {
        let info: VerifierInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier(verifier.clone()))
            .ok_or(Error::UnauthorizedVerifier)?;
        if !info.active {
            return Err(Error::UnauthorizedVerifier);
        }
        Ok(())
    }

    fn is_active_verifier(env: &Env, verifier: &Address) -> bool {
        let info: Option<VerifierInfo> = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier(verifier.clone()));
        match info {
            Some(i) => i.active,
            None => false,
        }
    }

    /// Add `verifier` to the `Vec<Address>` stored at `key` if not
    /// already present. Maintains the TTL bump so the reverse indices
    /// never expire.
    fn add_verifier_to_set(env: &Env, key: &DataKey, verifier: &Address) {
        let mut set: Vec<Address> = env
            .storage()
            .persistent()
            .get(key)
            .unwrap_or_else(|| Vec::new(env));
        if !Self::vec_contains(&set, verifier) {
            set.push_back(verifier.clone());
            env.storage().persistent().set(key, &set);
        }
        env.storage()
            .persistent()
            .extend_ttl(key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
    }

    fn vec_contains(vec: &Vec<Address>, target: &Address) -> bool {
        let len = vec.len();
        let mut i: u32 = 0;
        while i < len {
            if let Some(v) = vec.get(i) {
                if &v == target {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn recompute_contracts_after_deactivation(env: &Env, verifier: &Address) {
        let contracts: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierContracts(verifier.clone()))
            .unwrap_or_else(|| Vec::new(env));

        let len = contracts.len();
        let mut i: u32 = 0;
        while i < len {
            if let Some(contract_id) = contracts.get(i) {
                Self::recompute_canonical(env, &contract_id);
            }
            i += 1;
        }
    }

    /// Recompute the canonical record for `contract_id`. Behavior
    /// depends on the active policy:
    /// - `LastWriteWins` / `MinQuorum`: no-op (once published, a
    ///   canonical is stable evidence; auto-revoking it would
    ///   silently lose provenance).
    /// - `LowestTrust`: aggregate the remaining active per-verifier
    ///   records and write the new minimum.
    fn recompute_canonical(env: &Env, contract_id: &Address) {
        let policy = Self::current_policy(env);
        match policy {
            VerificationPolicy::LastWriteWins | VerificationPolicy::MinQuorum(_) => {
                // No-op: see contractdocs above.
            }
            VerificationPolicy::LowestTrust => {
                let new_min = Self::compute_lowest_trust(env, contract_id);
                let canonical_key = DataKey::Verification(contract_id.clone());
                if let Some(c) = new_min {
                    env.storage().persistent().set(&canonical_key, &c);
                    env.storage().persistent().extend_ttl(
                        &canonical_key,
                        LIFETIME_THRESHOLD,
                        BUMP_AMOUNT,
                    );
                }
                // If `compute_lowest_trust` returns `None` (no
                // remaining active verifiers), leave the existing
                // canonical in place — better to keep the
                // historical record than to silently delete it.
            }
        }
    }

    /// Canonical under `MinQuorum(n)`: published only if at least `n`
    /// active, independent verifiers have attested to the same
    /// `wasm_hash` as the just-attested record.
    fn compute_min_quorum(
        env: &Env,
        contract_id: &Address,
        n: u32,
        just_attested: &VerificationRecord,
    ) -> Option<VerificationRecord> {
        let verifiers: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::ContractVerifiers(contract_id.clone()))
            .unwrap_or_else(|| Vec::new(env));

        let target_hash = just_attested.wasm_hash.clone();
        let mut count: u32 = 0;
        let vlen = verifiers.len();
        let mut vi: u32 = 0;
        while vi < vlen {
            if let Some(v) = verifiers.get(vi) {
                if !Self::is_active_verifier(env, &v) {
                    vi += 1;
                    continue;
                }
                let att_key = DataKey::VerifierAttestation(contract_id.clone(), v.clone());
                let r: Option<VerificationRecord> = env.storage().persistent().get(&att_key);
                if let Some(record) = r {
                    if record.wasm_hash == target_hash {
                        count += 1;
                    }
                }
            }
            vi += 1;
        }

        if count >= n {
            Some(just_attested.clone())
        } else {
            // Don't clobber an existing canonical if the quorum is
            // not yet met.
            None
        }
    }

    /// Canonical under `LowestTrust`: the attestation record with
    /// the lowest `trust_level` across all currently-active
    /// per-verifier records.
    fn compute_lowest_trust(env: &Env, contract_id: &Address) -> Option<VerificationRecord> {
        let verifiers: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::ContractVerifiers(contract_id.clone()))
            .unwrap_or_else(|| Vec::new(env));

        let mut min: Option<VerificationRecord> = None;
        let vlen = verifiers.len();
        let mut vi: u32 = 0;
        while vi < vlen {
            if let Some(v) = verifiers.get(vi) {
                if !Self::is_active_verifier(env, &v) {
                    vi += 1;
                    continue;
                }
                let att_key = DataKey::VerifierAttestation(contract_id.clone(), v.clone());
                let r: Option<VerificationRecord> = env.storage().persistent().get(&att_key);
                if let Some(record) = r {
                    min = Some(match min {
                        None => record,
                        Some(prev) if record.trust_level < prev.trust_level => record,
                        Some(prev) => prev,
                    });
                }
            }
            vi += 1;
        }
        min
    }
}
