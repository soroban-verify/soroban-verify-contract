#![cfg(test)]

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events, Ledger},
    vec, Address, BytesN, Env, IntoVal, String,
};

use crate::{
    Error, TrustLevel, VerificationPolicy, VerificationRecord, VerificationRegistry,
    VerificationRegistryClient, VerifierInfo,
};

struct Setup {
    env: Env,
    client: VerificationRegistryClient<'static>,
    admin: Address,
    verifier: Address,
}

fn setup() -> Setup {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(VerificationRegistry, ());
    let client = VerificationRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);

    let verifier = Address::generate(&env);
    client.set_verifier(&verifier, &verifier_info(&env, true));

    Setup {
        env,
        client,
        admin,
        verifier,
    }
}

fn verifier_info(env: &Env, active: bool) -> VerifierInfo {
    VerifierInfo {
        name: String::from_str(env, "soroban-verify hosted service"),
        pubkey: BytesN::from_array(env, &[7u8; 32]),
        active,
    }
}

fn sample_record(env: &Env, verifier: &Address) -> VerificationRecord {
    VerificationRecord {
        wasm_hash: BytesN::from_array(env, &[1u8; 32]),
        repo_url: String::from_str(env, "https://github.com/org/project"),
        commit_sha: String::from_str(env, "abc123def4567890abc123def4567890abc123de"),
        trust_level: TrustLevel::Trusted,
        verifier: verifier.clone(),
        sep55_attestation_ref: String::from_str(env, "sep55:run/42"),
        timestamp: 0,
        // SEP-58 build environment fields populated by the hosted
        // verifier in production. Empty string is acceptable for tests
        // that intentionally model legacy records.
        build_image_digest: String::from_str(
            env,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        toolchain_version: String::from_str(env, "stable-1.78.0"),
    }
}

// --- init ---

#[test]
fn init_sets_admin_and_cannot_be_repeated() {
    let s = setup();
    assert_eq!(s.client.get_admin(), s.admin);

    let other = Address::generate(&s.env);
    assert_eq!(
        s.client.try_init(&other),
        Err(Ok(Error::AlreadyInitialized))
    );
}

#[test]
fn uninitialized_registry_rejects_governance_calls() {
    let env = Env::default();
    env.mock_all_auths();
    let client = VerificationRegistryClient::new(&env, &env.register(VerificationRegistry, ()));

    assert_eq!(client.try_get_admin(), Err(Ok(Error::NotInitialized)));
    let verifier = Address::generate(&env);
    assert_eq!(
        client.try_set_verifier(&verifier, &verifier_info(&env, true)),
        Err(Ok(Error::NotInitialized))
    );
}

// --- attest / get_verification ---

#[test]
fn attest_stores_record_and_stamps_verifier_and_timestamp() {
    let s = setup();
    s.env.ledger().with_mut(|li| li.timestamp = 1_720_000_000);

    let subject = Address::generate(&s.env);
    // Malicious input: claims a different verifier and a bogus timestamp.
    let mut record = sample_record(&s.env, &Address::generate(&s.env));
    record.timestamp = 99;

    s.client.attest(&s.verifier, &subject, &record);

    let stored = s.client.get_verification(&subject).unwrap();
    assert_eq!(stored.verifier, s.verifier);
    assert_eq!(stored.timestamp, 1_720_000_000);
    assert_eq!(stored.trust_level, TrustLevel::Trusted);
    assert_eq!(stored.wasm_hash, record.wasm_hash);
    assert_eq!(stored.repo_url, record.repo_url);
    assert_eq!(stored.commit_sha, record.commit_sha);
}

#[test]
fn attest_emits_event() {
    let s = setup();
    s.env.ledger().with_mut(|li| li.timestamp = 42);
    let subject = Address::generate(&s.env);
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));

    // What the contract should have stored and emitted after stamping.
    let mut stored = sample_record(&s.env, &s.verifier);
    stored.timestamp = 42;

    // Note: env.events().all() only retains events from the most recent
    // invocation, so no contract calls may happen between attest and here.
    let events = s.env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        vec![
            &s.env,
            (
                s.client.address.clone(),
                (symbol_short!("attest"), subject, s.verifier.clone()).into_val(&s.env),
                stored.into_val(&s.env),
            )
        ]
    );
}

#[test]
fn attest_rejects_unregistered_and_inactive_verifiers() {
    let s = setup();
    let subject = Address::generate(&s.env);

    let stranger = Address::generate(&s.env);
    assert_eq!(
        s.client
            .try_attest(&stranger, &subject, &sample_record(&s.env, &stranger)),
        Err(Ok(Error::UnauthorizedVerifier))
    );

    // Deactivated verifiers keep history but lose the ability to attest.
    s.client
        .set_verifier(&s.verifier, &verifier_info(&s.env, false));
    assert_eq!(
        s.client
            .try_attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier)),
        Err(Ok(Error::UnauthorizedVerifier))
    );
}

#[test]
fn attest_is_last_write_wins_across_verifiers() {
    let s = setup();
    let subject = Address::generate(&s.env);
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));

    let second = Address::generate(&s.env);
    s.client.set_verifier(&second, &verifier_info(&s.env, true));
    let mut downgraded = sample_record(&s.env, &second);
    downgraded.trust_level = TrustLevel::Auditable;
    s.client.attest(&second, &subject, &downgraded);

    let stored = s.client.get_verification(&subject).unwrap();
    assert_eq!(stored.verifier, second);
    assert_eq!(stored.trust_level, TrustLevel::Auditable);
}

#[test]
fn get_verification_returns_none_when_never_attested() {
    let s = setup();
    let subject = Address::generate(&s.env);
    assert_eq!(s.client.get_verification(&subject), None);
}

// --- revoke ---

#[test]
fn revoke_downgrades_record_but_keeps_provenance() {
    let s = setup();
    s.env.ledger().with_mut(|li| li.timestamp = 100);
    let subject = Address::generate(&s.env);
    let record = sample_record(&s.env, &s.verifier);
    s.client.attest(&s.verifier, &subject, &record);

    s.env.ledger().with_mut(|li| li.timestamp = 200);
    s.client
        .revoke(&s.verifier, &subject, &symbol_short!("imgcompr"));

    // Downstream consumers must see the downgrade, not an absence.
    let stored = s.client.get_verification(&subject).unwrap();
    assert_eq!(stored.trust_level, TrustLevel::Failed);
    assert_eq!(stored.timestamp, 200);
    assert_eq!(stored.repo_url, record.repo_url);
    assert_eq!(stored.commit_sha, record.commit_sha);
    assert_eq!(stored.verifier, s.verifier);
}

#[test]
fn revoke_emits_event_with_reason() {
    let s = setup();
    let subject = Address::generate(&s.env);
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));
    s.client
        .revoke(&s.verifier, &subject, &symbol_short!("imgcompr"));

    let events = s.env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        vec![
            &s.env,
            (
                s.client.address.clone(),
                (symbol_short!("revoke"), subject, s.verifier.clone()).into_val(&s.env),
                symbol_short!("imgcompr").into_val(&s.env),
            )
        ]
    );
}

#[test]
fn admin_can_revoke() {
    let s = setup();
    let subject = Address::generate(&s.env);
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));

    s.client
        .revoke(&s.admin, &subject, &symbol_short!("govact"));
    assert_eq!(
        s.client.get_verification(&subject).unwrap().trust_level,
        TrustLevel::Failed
    );
}

#[test]
fn revoke_rejects_strangers_and_missing_records() {
    let s = setup();
    let subject = Address::generate(&s.env);
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));

    let stranger = Address::generate(&s.env);
    assert_eq!(
        s.client
            .try_revoke(&stranger, &subject, &symbol_short!("nope")),
        Err(Ok(Error::UnauthorizedVerifier))
    );

    let never_attested = Address::generate(&s.env);
    assert_eq!(
        s.client
            .try_revoke(&s.verifier, &never_attested, &symbol_short!("nope")),
        Err(Ok(Error::VerificationNotFound))
    );
}

// --- governance ---

#[test]
fn set_verifier_requires_admin_auth() {
    let s = setup();
    let new_verifier = Address::generate(&s.env);
    s.client
        .set_verifier(&new_verifier, &verifier_info(&s.env, true));

    // The recorded authorization must be the admin's.
    let (auth_addr, _invocation) = s.env.auths().first().unwrap().clone();
    assert_eq!(auth_addr, s.admin);

    assert_eq!(
        s.client.get_verifier(&new_verifier),
        Some(verifier_info(&s.env, true))
    );
    assert_eq!(s.client.get_verifier(&Address::generate(&s.env)), None);
}

#[test]
fn set_admin_rotates_governance() {
    let s = setup();
    let new_admin = Address::generate(&s.env);
    s.client.set_admin(&new_admin);
    assert_eq!(s.client.get_admin(), new_admin);

    // Old admin is no longer authorized to revoke as admin.
    let subject = Address::generate(&s.env);
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));
    assert_eq!(
        s.client
            .try_revoke(&s.admin, &subject, &symbol_short!("nope")),
        Err(Ok(Error::UnauthorizedVerifier))
    );
}

// --- bump_ttl (permissionless TTL refresh) ---

#[test]
fn bump_ttl_succeeds_on_existing_record() {
    let s = setup();
    let subject = Address::generate(&s.env);
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));

    // Permissionless — clear any auths recorded by `attest` and
    // confirm `bump_ttl` itself does not record any.
    s.env.auths().clear();
    s.client.bump_ttl(&subject);
    assert!(s.env.auths().is_empty());

    // The verification record is still there afterwards.
    assert!(s.client.get_verification(&subject).is_some());
}

#[test]
fn bump_ttl_fails_on_missing_record() {
    let s = setup();
    let never_attested = Address::generate(&s.env);
    assert_eq!(
        s.client.try_bump_ttl(&never_attested),
        Err(Ok(Error::VerificationNotFound))
    );
}

#[test]
fn bump_verifier_ttl_succeeds_on_existing_verifier() {
    let s = setup();
    s.env.auths().clear();
    s.client.bump_verifier_ttl(&s.verifier);
    assert!(s.env.auths().is_empty());
    assert!(s.client.get_verifier(&s.verifier).is_some());
}

#[test]
fn bump_verifier_ttl_fails_on_missing_verifier() {
    let s = setup();
    let ghost = Address::generate(&s.env);
    s.env.auths().clear();
    assert_eq!(
        s.client.try_bump_verifier_ttl(&ghost),
        Err(Ok(Error::UnauthorizedVerifier))
    );
}

// --- trust levels ---

#[test]
fn trust_levels_are_ordered_for_composability() {
    // A lending protocol can require `trust_level >= Auditable`.
    assert!(TrustLevel::Trusted > TrustLevel::Auditable);
    assert!(TrustLevel::Auditable > TrustLevel::DeployerSupplied);
    assert!(TrustLevel::DeployerSupplied > TrustLevel::Failed);
    assert!(TrustLevel::Auditable >= TrustLevel::Auditable);
}

// --- VerificationPolicy ---

#[test]
fn policy_defaults_to_last_write_wins() {
    let s = setup();
    assert_eq!(s.client.get_policy(), VerificationPolicy::LastWriteWins);
}

#[test]
fn set_policy_records_admin_auth_and_updates_get_policy() {
    let s = setup();
    s.client.set_policy(&VerificationPolicy::MinQuorum(3));

    // The admin's auth must be recorded.
    let (auth_addr, _invocation) = s.env.auths().first().unwrap().clone();
    assert_eq!(auth_addr, s.admin);

    assert_eq!(s.client.get_policy(), VerificationPolicy::MinQuorum(3));
}

#[test]
fn set_policy_rejects_zero_quorum() {
    let s = setup();
    assert_eq!(
        s.client.try_set_policy(&VerificationPolicy::MinQuorum(0)),
        Err(Ok(Error::InvalidPolicy))
    );
    // Policy unchanged after the rejected call.
    assert_eq!(s.client.get_policy(), VerificationPolicy::LastWriteWins);
}

#[test]
fn set_policy_emits_policy_changed_event() {
    let s = setup();
    s.client.set_policy(&VerificationPolicy::LowestTrust);

    // Note: env.events().all() only retains events from the most
    // recent invocation, so no contract calls may happen between
    // set_policy and the assertion.
    let events = s.env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        vec![
            &s.env,
            (
                s.client.address.clone(),
                (symbol_short!("policy"),).into_val(&s.env),
                VerificationPolicy::LowestTrust.into_val(&s.env),
            )
        ]
    );
}

#[test]
fn min_quorum_waits_for_n_agreements() {
    let s = setup();
    s.client.set_policy(&VerificationPolicy::MinQuorum(2));

    let subject = Address::generate(&s.env);

    // One verifier attests with wasm_hash=1: not enough for n=2.
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));
    assert_eq!(s.client.get_verification(&subject), None);

    // Second active verifier attests with the same wasm_hash (1).
    // Their record uses a different trust_level / repo to confirm the
    // quorum rule is on wasm_hash equality, not on record equality.
    let second = Address::generate(&s.env);
    s.client.set_verifier(&second, &verifier_info(&s.env, true));
    let mut second_record = sample_record(&s.env, &second);
    second_record.repo_url = String::from_str(&s.env, "https://github.com/other/project");
    second_record.trust_level = TrustLevel::Auditable;
    s.client.attest(&second, &subject, &second_record);

    let canonical = s.client.get_verification(&subject).unwrap();
    assert_eq!(canonical.wasm_hash, second_record.wasm_hash);
    // The canonical record is one of the agreeing attestations.
    assert_eq!(canonical.trust_level, TrustLevel::Auditable);
    assert_eq!(canonical.verifier, second);
}

#[test]
fn min_quorum_does_not_publish_when_verifiers_disagree() {
    let s = setup();
    s.client.set_policy(&VerificationPolicy::MinQuorum(2));

    let subject = Address::generate(&s.env);

    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));

    let second = Address::generate(&s.env);
    s.client.set_verifier(&second, &verifier_info(&s.env, true));
    let mut disagreeing = sample_record(&s.env, &second);
    // Different wasm_hash from the first verifier's record.
    disagreeing.wasm_hash = BytesN::from_array(&s.env, &[2u8; 32]);
    s.client.attest(&second, &subject, &disagreeing);

    // Both verifiers agree on different wasm_hashes; neither has
    // quorum (1 each). No canonical.
    assert_eq!(s.client.get_verification(&subject), None);
}

#[test]
fn lowest_trust_picks_min_trust_across_active_verifiers() {
    let s = setup();
    s.client.set_policy(&VerificationPolicy::LowestTrust);

    let subject = Address::generate(&s.env);

    // Verifier 1 attests Trusted.
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));
    let canonical = s.client.get_verification(&subject).unwrap();
    assert_eq!(canonical.trust_level, TrustLevel::Trusted);

    // Verifier 2 attests Failed — but Failed is the floor of the
    // ordering, so the canonical should flip to a record carrying
    // Failed.
    let second = Address::generate(&s.env);
    s.client.set_verifier(&second, &verifier_info(&s.env, true));
    let mut low_record = sample_record(&s.env, &second);
    low_record.trust_level = TrustLevel::Failed;
    s.client.attest(&second, &subject, &low_record);

    let canonical = s.client.get_verification(&subject).unwrap();
    assert_eq!(canonical.trust_level, TrustLevel::Failed);
    assert_eq!(canonical.verifier, second);

    // Verifier 3 attests Auditable — min stays at Failed (the floor)
    // because one verifiable still attests Failed.
    let third = Address::generate(&s.env);
    s.client.set_verifier(&third, &verifier_info(&s.env, true));
    let mut mid_record = sample_record(&s.env, &third);
    mid_record.trust_level = TrustLevel::Auditable;
    s.client.attest(&third, &subject, &mid_record);

    let canonical = s.client.get_verification(&subject).unwrap();
    assert_eq!(canonical.trust_level, TrustLevel::Failed);
}

#[test]
fn revoke_forces_canonical_to_failed_across_policies() {
    let s = setup();
    // Even under MinQuorum, revocation must be a safety hatch.
    s.client.set_policy(&VerificationPolicy::MinQuorum(3));
    let subject = Address::generate(&s.env);
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));
    // Pre-revoke canonical is absent (only one verifier, far from
    // n=3). Revoke is still meaningful because it canonically marks
    // the attestation as compromised.
    s.client
        .revoke(&s.verifier, &subject, &symbol_short!("imgcompr"));

    let canonical = s.client.get_verification(&subject).unwrap();
    assert_eq!(canonical.trust_level, TrustLevel::Failed);
    // Repo URL / commit are preserved (provenance).
    assert_eq!(
        canonical.repo_url,
        String::from_str(&s.env, "https://github.com/org/project")
    );
}

#[test]
fn set_verifier_deactivation_recomputes_lowest_trust() {
    let s = setup();
    s.client.set_policy(&VerificationPolicy::LowestTrust);
    let subject = Address::generate(&s.env);

    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));
    let second = Address::generate(&s.env);
    s.client.set_verifier(&second, &verifier_info(&s.env, true));
    let mut low_record = sample_record(&s.env, &second);
    low_record.trust_level = TrustLevel::Failed;
    low_record.wasm_hash = BytesN::from_array(&s.env, &[3u8; 32]);
    s.client.attest(&second, &subject, &low_record);
    // Canonical is Failed (the floor).
    assert_eq!(
        s.client.get_verification(&subject).unwrap().trust_level,
        TrustLevel::Failed
    );

    // Deactivate the verifier attesting at Failed. Canonical should
    // recompute to the remaining-attesters' min (Trusted).
    s.client
        .set_verifier(&second, &verifier_info(&s.env, false));
    let canonical = s.client.get_verification(&subject).unwrap();
    assert_eq!(canonical.trust_level, TrustLevel::Trusted);
    assert_eq!(canonical.verifier, s.verifier);
}

// --- verifier enumeration ---

#[test]
fn list_verifiers_returns_all_registered_verifiers() {
    let s = setup();

    // The default `setup` already registered `s.verifier`.
    let all = s.client.list_verifiers();
    assert_eq!(all.len(), 1);
    assert_eq!(all.get(0).unwrap(), s.verifier);

    // Add more verifiers.
    let second = Address::generate(&s.env);
    s.client.set_verifier(&second, &verifier_info(&s.env, true));
    let third = Address::generate(&s.env);
    s.client.set_verifier(&third, &verifier_info(&s.env, false));

    let all = s.client.list_verifiers();
    assert_eq!(all.len(), 3);
    // Order should be: s.verifier, second, third.
    assert_eq!(all.get(0).unwrap(), s.verifier);
    assert_eq!(all.get(1).unwrap(), second);
    assert_eq!(all.get(2).unwrap(), third);
}

#[test]
fn list_verifiers_does_not_duplicate_on_reregister() {
    let s = setup();

    // Re-register the same verifier (e.g. update its info).
    s.client
        .set_verifier(&s.verifier, &verifier_info(&s.env, true));

    let all = s.client.list_verifiers();
    // Still only one entry.
    assert_eq!(all.len(), 1);
    assert_eq!(all.get(0).unwrap(), s.verifier);
}

#[test]
fn list_active_verifiers_returns_only_active() {
    let s = setup();

    // Default `setup` has 1 active verifier.
    let active = s.client.list_active_verifiers();
    assert_eq!(active.len(), 1);

    let second = Address::generate(&s.env);
    s.client.set_verifier(&second, &verifier_info(&s.env, true));
    let active = s.client.list_active_verifiers();
    assert_eq!(active.len(), 2);

    // Deactivate the first verifier.
    s.client
        .set_verifier(&s.verifier, &verifier_info(&s.env, false));
    let active = s.client.list_active_verifiers();
    assert_eq!(active.len(), 1);
    assert_eq!(active.get(0).unwrap(), second);

    // `list_verifiers` still returns both (history preserved).
    let all = s.client.list_verifiers();
    assert_eq!(all.len(), 2);
}

#[test]
fn list_verifiers_empty_before_any_registration() {
    let env = Env::default();
    env.mock_all_auths();
    let client = VerificationRegistryClient::new(&env, &env.register(VerificationRegistry, ()));
    let admin = Address::generate(&env);
    client.init(&admin);

    // No verifiers registered yet.
    assert_eq!(client.list_verifiers().len(), 0);
    assert_eq!(client.list_active_verifiers().len(), 0);
}

#[test]
fn set_verifier_deactivation_is_noop_under_last_write_wins() {
    let s = setup();
    let subject = Address::generate(&s.env);
    s.client
        .attest(&s.verifier, &subject, &sample_record(&s.env, &s.verifier));
    let prior = s.client.get_verification(&subject).unwrap();

    // Deactivate. Under LastWriteWins the canonical must NOT change.
    s.client
        .set_verifier(&s.verifier, &verifier_info(&s.env, false));
    let after = s.client.get_verification(&subject).unwrap();
    assert_eq!(prior.trust_level, after.trust_level);
    assert_eq!(prior.wasm_hash, after.wasm_hash);
}
