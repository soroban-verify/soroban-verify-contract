# `verification_registry`

The **on-chain source of truth for verification results**. Any wallet, explorer, or other smart contract can query verification status trustlessly, without trusting the hosted service's servers.

## Storage model

| Key | Value | Storage |
|---|---|---|
| `Verification(ContractId)` | `VerificationRecord { wasm_hash, repo_url, commit_sha, trust_level, verifier, sep55_attestation_ref, timestamp, build_image_digest, toolchain_version }` | persistent |
| `Verifier(Address)` | `VerifierInfo { name, pubkey, active }` | persistent |
| `Admin` | Multi-sig admin address (governance) | instance |
| `VerifierList` | `Vec<Address>` of all ever-registered verifiers (history preserved on deactivation) | instance |

The two `build_image_digest` / `toolchain_version` fields are SEP-58 build-environment metadata. Empty string is tolerated for legacy records; the hosted verifier always populates them. See `types.rs` for the SEP-58 spec pointers.

## Interface

```rust
/// One-time constructor. `admin` is expected to be a multi-sig address.
fn init(env: Env, admin: Address) -> Result<(), Error>;

/// Publish a verification result (verifier-role gated).
/// The contract stamps `record.verifier` and `record.timestamp` itself,
/// so a verifier can neither impersonate another nor backdate a claim.
fn attest(env: Env, verifier: Address, contract_id: Address, record: VerificationRecord) -> Result<(), Error>;

/// Anyone — including other contracts — can query trustlessly.
fn get_verification(env: Env, contract_id: Address) -> Option<VerificationRecord>;

/// Downgrade or revoke (e.g. a trusted image is later found compromised).
/// Callable by any active verifier or the admin.
fn revoke(env: Env, revoked_by: Address, contract_id: Address, reason: Symbol) -> Result<(), Error>;

/// Governance: add/update/deactivate verifier keys.
fn set_verifier(env: Env, verifier: Address, info: VerifierInfo) -> Result<(), Error>;
fn get_verifier(env: Env, verifier: Address) -> Option<VerifierInfo>;

/// View: return all ever-registered verifier addresses (incl. deactivated).
/// Useful for wallet/explorer UIs and governance audits.
fn list_verifiers(env: Env) -> Vec<Address>;

/// View: return only currently active verifier addresses.
/// Useful for downstream contracts checking multi-verifier quorum.
fn list_active_verifiers(env: Env) -> Vec<Address>;

/// Governance: rotate the admin address.
fn set_admin(env: Env, new_admin: Address) -> Result<(), Error>;
fn get_admin(env: Env) -> Result<Address, Error>;

/// Permissionless: refresh the TTL of an existing verification record
/// (for high-value, long-lived attestations whose verifier doesn't want
/// to re-attest just to keep storage alive). Errors with
/// `VerificationNotFound` when `contract_id` has no on-chain record.
fn bump_ttl(env: Env, contract_id: Address) -> Result<(), Error>;

/// Permissionless: refresh the TTL of an existing verifier entry.
/// Errors with `UnauthorizedVerifier` when `verifier` is not registered.
fn bump_verifier_ttl(env: Env, verifier: Address) -> Result<(), Error>;
```

## Conflict-resolution policy

A downstream consumer (e.g. a lending protocol checking `trust_level >= Auditable`) needs to be able to tell the difference between a single-verifier attestation, a multi-verifier consensus, and a contested result. Governance can configure a `VerificationPolicy` for the canonical `Verification(contract_id)` record.

| Variant | Default? | Semantics |
|---|---|---|
| `LastWriteWins` | yes | Most-recent `attest` becomes the canonical record. Equivalent to the pre-M5 behaviour. Preserved as the default so deployments prior to this feature remain bit-for-bit compatible. |
| `MinQuorum(u32)` | no | Canonical is published only once at least *n* `n` active, independent verifiers have attested to the same `wasm_hash`. While the quorum is not met, `get_verification` returns `None` — downstream consumers see "contested / under-verified" rather than a misleading single-verifier claim. `MinQuorum(0)` is rejected at the gate with `InvalidPolicy`. |
| `LowestTrust` | no | The canonical record's `trust_level` is the minimum across all currently-active per-verifier attestations; the record carrying that minimum is selected. When a verifier is later deactivated (`set_verifier(active=false)`) the canonical is recomputed against the remaining active attestations. |

Once a policy is set, it applies to *subsequent* attestations for that contract. Historical canonical records already published under a prior policy are not backfilled, because the per-verifier evidence lives on either way (`VerifierAttestation` is always written alongside the canonical).

`revoke` is intentionally a safety hatch: regardless of the active policy, it forces the canonical record to `TrustLevel::Failed` immediately (and the revoking verifier's per-verifier record to `Failed`), so wallets and lending protocols see a compromised attestation without waiting for a quorum to re-form.

## Trust levels

`TrustLevel` is an ordered enum, not a boolean — mirroring the RFP's requirement that image trust be treated as a signal:

| Value | Tier | Meaning |
|---|---|---|
| 3 | 🟢 `Trusted` | Reproduced inside an SDF-allowlisted trusted image |
| 2 | 🟡 `Auditable` | Reproduced inside a publicly auditable, pinned image |
| 1 | 🟠 `DeployerSupplied` | Reproduced, but inside an arbitrary image |
| 0 | 🔴 `Failed` | Rebuild failed, bytes mismatched, or verification revoked |

The ordering makes on-chain composition trivial: a lending protocol can require `trust_level >= Auditable` on a collateral token contract before listing it.

## Design decisions

- **Revocation is first-class.** A revoked verification stays in storage with `TrustLevel::Failed` — downstream consumers see the downgrade, not an absence. The machine-readable reason is carried in the `revoke` event for indexers.
- **Multi-verifier from day one.** Governance registers independent verifiers so the registry outlives any single operator and other verification services can attest into the same registry. Among active verifiers, attestation is last-write-wins per contract.
- **The contract stamps `verifier` and `timestamp`** on every attestation; callers cannot forge either field.
- **Events on every state change** (`attest`, `revoke`, `verifier`, `admin`), defined with `#[contractevent]` so schemas are exported in the contract spec for indexers and explorers.

## Errors

| Code | Name | Raised when |
|---|---|---|
| 1 | `AlreadyInitialized` | `init` called twice |
| 2 | `NotInitialized` | governance call before `init` |
| 3 | `UnauthorizedVerifier` | caller is not a registered, active verifier (or admin, where allowed) |
| 4 | `VerificationNotFound` | `revoke` on a contract with no record |
| 5 | `InvalidPolicy` | `set_policy(MinQuorum(0))` rejected |

## Build & test

```bash
cargo test                                    # full test suite
cargo build --target wasm32v1-none --release  # deployable Wasm
# or: stellar contract build
```

## Deploy (testnet)

```bash
stellar keys generate deployer --network testnet --fund

stellar contract deploy \
  --wasm ../../target/wasm32v1-none/release/verification_registry.wasm \
  --source deployer --network testnet \
  -- init --admin <ADMIN_ADDRESS>
```
