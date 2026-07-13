# Security

## Disclosure Policy

If you discover a security vulnerability in `soroban-verify-contract`, please
report it privately before disclosing it publicly.

- **Contact:** Open a GitHub Security Advisory at
  https://github.com/soroban-verify/soroban-verify-contract/security/advisories/new
- **Response time:** We aim to acknowledge reports within 72 hours and provide
  an initial assessment within 5 business days.
- **Disclosure timeline:** We will coordinate a public disclosure date with you
  once a fix has been prepared and tested.

We ask that you **do not** file a public GitHub issue for security-sensitive
bugs. Instead, use the private advisory process linked above.

## Scope

The following components are in scope for security reports:

- **Contract layer** (`contracts/verification_registry/`) — Soroban smart
  contract logic, storage model, access control, and governance.
- **Build engine** (future milestones) — sandbox environment for rebuilding
  Wasm from source inside a pinned container.
- **API layer** (future milestones) — public REST API, submission endpoints,
  and database.

Out of scope:

- Third-party dependencies (report those upstream).
- Operational issues unrelated to the codebase (e.g. compromised GitHub
  credentials).
- Theoretical attacks requiring unrealistic ledger conditions.

---

## Mainnet Deployment Checklist

Before deploying the registry contract to **Stellar mainnet**, the following
security requirements **must** be met:

### 1. Admin is a Multi-Sig Address

- [ ] **The admin address passed to `init()` MUST be a Soroban multi-sig**
      (e.g. 3-of-5), **not** a single hot key.
- [ ] A single-key admin is a **critical single point of failure**:
      - A compromised key can register arbitrary verifiers.
      - A compromised key can revoke any verification.
      - A compromised key can silently rotate the admin to an attacker-controlled
        address.
- [ ] Use `stellar lab` or the Soroban CLI to create and configure a multi-sig
      account before deploying.

### 2. Key Ceremony for Admin Setup

- [ ] Admin keys should be generated on **air-gapped hardware** or hardware
      security modules (HSMs).
- [ ] Each signer key should be held by a **different entity or individual**
      to distribute trust.
- [ ] The multi-sig policy should require **at least a majority** (e.g. 3-of-5)
      to approve any governance action.
- [ ] Store backup key material in a secure, geographically distributed manner
      (e.g. independent safety deposit boxes).

### 3. Timelock for Admin Rotation

- [ ] **Before mainnet**, design and deploy a timelock mechanism for
      `set_admin()` so that admin rotation cannot happen instantaneously.
- [ ] Recommended minimum timelock: **7 days** (≈ 120,960 ledgers).
- [ ] The timelock should give the current admin a window to detect and abort
      a compromised rotation via `cancel_admin_rotation()` or equivalent.
- [ ] The timelock design should be documented at
      `contracts/verification_registry/README.md` once implemented.

### 4. Contract Audit

- [ ] The registry contract **must** pass a professional security audit through
      the [Soroban Audit Bank](https://sorobanauditbank.dev/) before mainnet
      deployment.
- [ ] All findings from the audit must be resolved or explicitly accepted with
      documented rationale before mainnet.
- [ ] After audit, consider a **bug bounty program** to incentivize ongoing
      security research.

### 5. Verifier Onboarding

- [ ] Approve verifier operators only after **due diligence** (reputation,
      operational security, infrastructure review).
- [ ] Document the verifier onboarding and offboarding process.
- [ ] Maintain ability to **deactivate** a verifier whose key is compromised
      (via `set_verifier(active = false)`).

### 6. Monitoring & Incident Response

- [ ] Monitor contract events (`AdminRotated`, `VerifierSet`, `Revoke`) on
      mainnet for anomalous activity.
- [ ] Have a documented incident response plan covering:
      - Verifier key compromise
      - Admin key compromise
      - Build-image compromise
      - Emergency revocation of a verified contract

---

## Timelock Design (Medium-Term)

The long-term goal is to add an **optional `timelock_ledgers` parameter** to
`set_admin()`:

```rust
pub fn set_admin(env: Env, new_admin: Address, timelock_ledgers: Option<u32>) -> Result<(), Error>
```

- When `timelock_ledgers` is `Some(n)`, the rotation enters a **pending state**
  stored in instance storage.
- The new admin is only activated after `n` ledgers have elapsed from the
  pending timestamp.
- A `cancel_admin_rotation()` function lets the current admin abort a
  compromised rotation during the timelock window.
- When `timelock_ledgers` is `None`, the rotation takes effect immediately
  (current behaviour — recommended only for testnets or emergency recovery).

This design prevents a single compromised key from instantly taking over
governance, while preserving an emergency fast-path when the key ceremony
is followed.

---

## Build Sandbox Security (Future Milestones)

When the build engine is implemented, the sandbox will:

- Execute untrusted build scripts inside a **pinned, read-only container
  image** with no network access.
- Drop all capabilities before executing the build.
- Use a **cgroup-based resource limit** (CPU, memory, disk I/O) to prevent
  resource exhaustion.
- Kill any process that exceeds the configured timeout.
- Discard the container filesystem after each build (no state persistence).

---

## Vulnerability Management Lifecycle

1. **Report** — via GitHub Security Advisory
2. **Triage** — determine severity and impacted components
3. **Fix** — develop and test the fix on a private fork
4. **Release** — publish a patched version and coordinate disclosure
5. **Announce** — public disclosure with CVE identifier (if applicable)
