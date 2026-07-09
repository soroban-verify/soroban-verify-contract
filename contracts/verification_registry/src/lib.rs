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
//!   rather than an absence.
//! - The verifier role is multi-party from day one; governance (admin)
//!   registers and deactivates verifiers. Among active verifiers,
//!   attestation is last-write-wins per contract.
//! - Events are emitted on every state change for indexers/explorers.

#![no_std]

mod events;
mod types;

#[cfg(test)]
mod test;

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

pub use types::{DataKey, Error, TrustLevel, VerificationRecord, VerifierInfo};

/// Assuming ~5s per ledger.
const DAY_IN_LEDGERS: u32 = 17280;
/// How far each write extends the entry's TTL.
const BUMP_AMOUNT: u32 = 90 * DAY_IN_LEDGERS;
/// Extend only when the remaining TTL has dropped below this.
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
    pub fn attest(
        env: Env,
        verifier: Address,
        contract_id: Address,
        mut record: VerificationRecord,
    ) -> Result<(), Error> {
        verifier.require_auth();
        Self::require_active_verifier(&env, &verifier)?;

        record.verifier = verifier;
        record.timestamp = env.ledger().timestamp();

        let key = DataKey::Verification(contract_id.clone());
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
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
        let mut record: VerificationRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::VerificationNotFound)?;

        record.trust_level = TrustLevel::Failed;
        record.timestamp = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);

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
    /// history while removing its ability to attest or revoke.
    pub fn set_verifier(env: Env, verifier: Address, info: VerifierInfo) -> Result<(), Error> {
        let admin = Self::admin(&env)?;
        admin.require_auth();

        let key = DataKey::Verifier(verifier.clone());
        env.storage().persistent().set(&key, &info);
        env.storage()
            .persistent()
            .extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
        env.storage()
            .instance()
            .extend_ttl(LIFETIME_THRESHOLD, BUMP_AMOUNT);

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
}
