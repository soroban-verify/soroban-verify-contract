# Contributing to soroban-verify

Thanks for helping build open, trustless Soroban contract verification.

This repository currently focuses on **M1 — the on-chain verification registry**
(`contracts/verification_registry`). Later milestones add the build engine, public
API, and explorer integrations. Contributions are welcome at every layer.

README links here for sandbox setup, testnet faucet usage, and the PR checklist.

## Development environment

### Prerequisites

- **Rust** toolchain (stable) via [rustup](https://rustup.rs/)
- Wasm target used by Soroban contracts:

```bash
rustup target add wasm32v1-none
```

- **stellar-cli** (any one of):

```bash
# Homebrew (macOS/Linux)
brew install stellar/tap/stellar-cli

# Cargo
cargo install --locked stellar-cli --features opt

# Or download a release binary from:
# https://github.com/stellar/stellar-cli/releases
```

- Optional: `make` for the root `Makefile` targets

### Clone and enter the workspace

```bash
git clone https://github.com/soroban-verify/soroban-verify-contract.git
cd soroban-verify-contract
```

### Common Makefile targets

| Target | Purpose |
|---|---|
| `make build` | `cargo build --target wasm32v1-none --release` |
| `make test` | `cargo test` |
| `make fmt` | `cargo fmt --all` |
| `make fmt-check` | `cargo fmt --all --check` |
| `make clippy` | `cargo clippy --all-targets -- -D warnings` |
| `make clean` | `cargo clean` |
| `make all` | `fmt-check` + `clippy` + `test` + `build` |

You can also work inside the contract crate:

```bash
cd contracts/verification_registry
cargo test
cargo build --target wasm32v1-none --release
# or, with stellar-cli:
stellar contract build
```

## Testnet sandbox

### 1. Create and fund a key

`stellar keys generate … --fund` uses the Friendbot **testnet faucet** automatically:

```bash
stellar keys generate deployer --network testnet --fund
```

If you already have a key and only need funds:

```bash
stellar keys fund deployer --network testnet
```

### 2. Build the Wasm

From the repository root:

```bash
make build
# artifact (typical path):
# target/wasm32v1-none/release/verification_registry.wasm
```

### 3. Deploy to testnet

```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/verification_registry.wasm \
  --source deployer \
  --network testnet \
  -- \
  init --admin <ADMIN_ADDRESS>
```

Use the admin address you intend for governance (often the deployer identity’s
public key for local experiments). See
[`contracts/verification_registry/README.md`](contracts/verification_registry/README.md)
for the storage model and function reference.

### 4. Invoke contract functions

```bash
stellar contract invoke \
  --id <CONTRACT_ID> \
  --source deployer \
  --network testnet \
  -- \
  get_admin
```

Replace the trailing function name and args with any exported method
(`get_verification`, `set_verifier`, `attest`, …). Prefer dry-runs and testnet
only until M6 mainnet readiness.

## Pull request checklist

Before requesting review, confirm:

- [ ] `cargo fmt --all --check` passes (`make fmt-check`)
- [ ] `cargo clippy --all-targets -- -D warnings` passes (`make clippy`)
- [ ] `cargo test` passes (`make test`)
- [ ] New behavior has corresponding tests
- [ ] **Spec-traceability:** if behavior traces to SEP-58 / SEP-55 / the SCF RFP,
      cite it in code comments or the PR description
- [ ] README (or layer README) updated when a public interface changes
- [ ] No unnecessary dependencies added (Wasm size budget respected)
- [ ] PR description states the problem, approach, and test evidence

Suggested local gate:

```bash
make all
```

## Issue taxonomy

Every issue and PR should carry:

1. **Layer label** — e.g. `contract`, `backend`, `frontend`, `docs`, `tooling`
2. **Difficulty label** — e.g. `good first issue`, intermediate, core
3. **Acceptance criteria** — observable, testable outcomes
4. **Spec pointer** — SEP-58 / SEP-55 section, RFP requirement, or documented design decision

Project norm: **if a behavior is not traceable to a spec, an RFP requirement, or a
documented design decision, that is a docs bug.**

## Where to start

- Issues labelled `good first issue` (and layer-specific variants)
- Contract tests and interface hardening under `contracts/verification_registry`
- Documentation and contributor experience (you are here)

## License

By contributing, you agree that your contributions are licensed under the
repository’s **Apache-2.0** license.
