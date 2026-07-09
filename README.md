# soroban-verify

**An open-source, hosted contract verification service for Soroban — the Sourcify / solana-verify equivalent for the Stellar ecosystem, built on SEP-58 reproducible builds.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Stellar](https://img.shields.io/badge/Built_on-Stellar%20%2F%20Soroban-black.svg)](https://stellar.org/soroban)

---

## The Problem

Every mature smart-contract ecosystem has solved contract verification:

| Ecosystem | Solution |
|---|---|
| Ethereum / EVM | Sourcify, Etherscan verification |
| Solana | solana-verify |
| **Stellar / Soroban** | **Nothing production-ready** |

Today, when a user or protocol interacts with a Soroban contract on mainnet, there is **no trustless way to confirm that the deployed Wasm bytecode actually corresponds to the published source code**. Users are trusting a hash they cannot independently reproduce. Auditors audit source code, but nothing binds that source to the bytes running on-chain. Explorers like Stellar Expert display raw Wasm with no provenance signal.

This is a known, ecosystem-acknowledged gap. The Stellar Community Fund has published an **active RFP** explicitly requesting a hosted public verification service, and **SEP-58** (draft, in active review since May 2026) now defines the metadata vocabulary a Soroban contract embeds — or surfaces off-chain — so that any verifier with the source can rebuild the Wasm and confirm the bytes match. SEP-58 deliberately leaves the **service implementation, build infrastructure, and explorer integrations to ecosystem teams**.

`soroban-verify` is that service layer.

## What It Does

1. **Anyone submits** a claim: *"Contract `C…XYZ` on mainnet was built from commit `abc123` of repo `github.com/org/project`."*
2. The service **rebuilds the Wasm from source** inside a pinned, containerized build environment.
3. It **byte-compares** the rebuilt Wasm against the on-chain Wasm hash.
4. It assigns a **multi-dimensional trust level** — not a binary verified/unverified flag:
   - 🟢 **Trusted build** — reproduced inside an SDF-allowlisted trusted image
   - 🟡 **Auditable build** — reproduced inside a publicly auditable, pinned image
   - 🟠 **Deployer-supplied build** — reproduced, but inside an arbitrary image (reproducibility alone is not faithfulness to source: a hostile image can deterministically rewrite bytes and still pass byte-comparison)
   - 🔴 **Failed / mismatch**
5. The result is **published via a public REST API** and **attested on-chain** in the verification registry contract, so explorers, wallets, CI pipelines, and other Soroban contracts can query verification status trustlessly.
6. Optionally, verification claims are strengthened with **SEP-55 signed CI attestations**, which bind a specific workflow run to a commit and a Wasm artifact.

## Why This Matters for Stellar

- **$2B+ in tokenized RWAs** and institutional stablecoins (USDC, EURC, PYUSD, MGUSD) now live on Stellar. Institutions cannot allocate against unverifiable bytecode.
- The February 2026 oracle compromise affecting the YieldBlox pool showed how much the ecosystem currently leans on goodwill instead of verifiable infrastructure.
- SDF has drawn an explicit boundary: **SDF builds the CLI, trusted images, and Stellar Lab integrations in-house — the hosted public verification service is scoped for ecosystem teams to build.** This project lives exactly inside that boundary, complementing rather than duplicating SDF work.

## Architecture

```
                           │ Soroban RPC
┌──────────────────────────▼─────────────────────────────────┐
│              CONTRACT LAYER (Soroban / Rust)                │
│   On-chain Verification Registry: attested results,         │
│   trust levels, revocations — queryable by any contract     │
└─────────────────────────────────────────────────────────────┘
```

### Part 1 — Contract Layer: The Verification Registry

**Directory:** [`/contracts`](contracts/) · **Stack:** Rust, `soroban-sdk`, deployed on Stellar mainnet + testnet

A Soroban smart contract that serves as the **on-chain source of truth for verification results**. This is what turns `soroban-verify` from "a website you trust" into ecosystem infrastructure: any wallet, explorer, or *other smart contract* can query verification status without trusting our servers.

See [`contracts/verification_registry/README.md`](contracts/verification_registry/README.md) for the storage model, function reference, and design decisions.

**Composability example:** a lending protocol can require `trust_level >= Auditable` on any collateral token contract before listing it — verification becomes a DeFi primitive, not just a UI badge.

## Development

```bash
# Contracts
cd contracts/verification_registry
cargo test                                    # run the test suite
cargo build --target wasm32v1-none --release  # build the deployable Wasm
# or, with stellar-cli installed:
stellar contract build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for sandbox setup, testnet faucet usage, and the PR checklist.

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| **M1 — Registry contract** | `verification_registry` on testnet, full test suite, audit prep | 🔨 In progress |
| **M2 — Build engine MVP** | Sandboxed rebuild + byte-compare for the trusted-image tier, CLI submission | Planned |
| **M3 — Public API + explorer** | Read API, submission wizard, explorer index, badges | Planned |
| **M4 — Trust tiers + SEP-55** | Auditable/arbitrary image tiers, CI attestation verification, revocation flows | Planned |
| **M5 — Ecosystem integration** | Stellar Expert / wallet integration support, multi-verifier federation on the registry | Planned |
| **M6 — Mainnet + sustainability** | Mainnet registry deployment, hosted service SLA, governance handoff plan | Planned |

## Contributing

This project is intentionally structured for **community maintenance** — decoupled layers, each contributable without deep knowledge of the others.

### Where to start

- 🟢 **Good first issues** — labelled per layer: `contract/good-first-issue`, `backend/good-first-issue`, `frontend/good-first-issue`
- 🟡 **Help wanted** — build-image hardening, additional toolchain version support, explorer UX
- 🔴 **Core** — sandbox security model, registry governance, SEP-58/SEP-55 spec-tracking (specs are drafts and will evolve)

### Issue taxonomy

Every issue carries: a layer label, a difficulty label, acceptance criteria, and pointers to the relevant spec section (SEP-58 / SEP-55) or RFP requirement it traces to. Spec-traceability is a project norm: **if a behavior isn't traceable to a spec, an RFP requirement, or a documented design decision, it's a bug in our docs.**

## Maintenance Commitment

- **Spec tracking:** SEP-58 is a draft under active review; this project commits to tracking spec revisions within one release cycle.
- **Security:** the build sandbox executes untrusted code by design — a `SECURITY.md` disclosure policy and hardening checklist are maintained from day one, and the registry contract will go through the Soroban Audit Bank before mainnet.
- **Neutrality:** the registry contract supports multiple independent verifiers so the on-chain layer is public infrastructure, not a moat for the hosted service.
- **Docs as a deliverable:** every milestone ships with integration docs for downstream consumers (explorers, wallets, protocols).

## Ecosystem Alignment

- Responds directly to the **active SCF RFP** for a hosted Soroban verification service
- Implements **SEP-58** (reproducible build metadata) and consumes **SEP-55** (signed CI attestations)
- Complements — never duplicates — SDF-owned tooling (`stellar-cli`, Stellar Lab, trusted images), per the RFP's explicit internal/external boundary
- Fills the same role **Sourcify** fills for EVM and **solana-verify** fills for Solana

## License

Apache-2.0 — permissive by design; verification infrastructure only works as a public good.
