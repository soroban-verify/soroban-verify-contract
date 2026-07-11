#![cfg(test)]

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events, Ledger},
    vec, Address, BytesN, Env, IntoVal, String,
};

use crate::{
    Error, TrustLevel, VerificationRecord, VerificationRegistry, VerificationRegistryClient,
    VerifierInfo,
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

// --- trust levels ---

#[test]
fn trust_levels_are_ordered_for_composability() {
    // A lending protocol can require `trust_level >= Auditable`.
    assert!(TrustLevel::Trusted > TrustLevel::Auditable);
    assert!(TrustLevel::Auditable > TrustLevel::DeployerSupplied);
    assert!(TrustLevel::DeployerSupplied > TrustLevel::Failed);
    assert!(TrustLevel::Auditable >= TrustLevel::Auditable);
}
