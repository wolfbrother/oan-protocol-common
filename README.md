<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# OAN Protocol Common

Common Rust protocol crates for OpenAgenet (OAN), an open infrastructure
project for the Internet of Agents (IoA). This repository holds the reusable
protocol layer behind OAN's DID-based resource identity, `did:oan` identifiers,
resource packages, trust evidence, semantic discovery support, and service-node
security primitives.

These crates are shared by the Root, Registrar, Discovery, CDN, Trust Indexer,
SDK, official operations, and future third-party implementations. They should
stay runtime-light and reusable rather than becoming service applications.

## Purpose

`oan-protocol-common` provides low-level, runtime-independent protocol building
blocks:

- `did:oan` types, parsing, generation, and validation
- protocol data models and version constants
- DID Document and credential structures
- canonical JSON, hashing, signing, and verification helpers
- trusted invocation envelope structures
- discovery response and resource package models
- capability-tree and semantic recommender helpers
- publication event models for Root-to-CDN distribution
- service-security helpers for signed infrastructure calls
- common error types and validation results
- test vectors and schema-oriented helpers where appropriate

The crate set should remain lightweight and avoid coupling the protocol layer to
specific service runtimes.

## Workspace Crates

The current workspace contains:

- `crates/oan-core`: common identifiers, protocol constants, lifecycle enums,
  and shared validation primitives.
- `crates/oan-did-oan`: `did:oan` parsing, generation, and subject-code checks.
- `crates/oan-crypto`: algorithm-neutral signing and verification helpers,
  including Ed25519 and SM2-oriented support.
- `crates/oan-credentials`: credential structures used by Root authorization
  and trusted invocation flows.
- `crates/oan-bulletin`: on-chain bulletin projection models for governance
  state shared with the Trust Indexer.
- `crates/oan-package`: ResourcePackage, resource metadata, Root proof, and
  package verification logic.
- `crates/oan-storage`: shared storage abstractions and SQLite/PostgreSQL
  helpers used by service repositories.
- `crates/oan-protocol`: request and response models for current OAN service
  APIs.
- `crates/oan-client`: Rust client helpers for OAN service calls.
- `crates/oan-service-security`: signed service-to-service request helpers.
- `crates/oan-publication-events`: Root/CDN publication event models.
- `crates/oan-semantic-recommender`: capability tree, semantic aliases, and
  registration/discovery assistance logic.

Supporting material also lives under `docs/` and `schemas/agent-contract/`.

## License

This core protocol repository is licensed under `Apache-2.0`. Brand and
official OpenAgenet (OAN) identity rights are reserved separately.

## Out of Scope

The common protocol layer should not contain:

- Axum HTTP handlers
- Tokio service orchestration
- SQL database logic
- full Root, Registrar, Discovery, or CDN implementations
- deployment scripts
- business-agent workflows
- UI or CLI application logic

Those belong in organization-owned implementation, SDK, adapter, and deployment
repositories.

## Publishing Model

Each crate should be publishable to crates.io with explicit versions. Local
workspace dependencies should include both `path` and `version` so crates can be
developed together and published independently.

Official release readiness, verification, and operational gates are maintained
separately by official operators.

## Local Checks

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -j 1
```
