# compliance-controls

Compliance controls as Rust types for the pleme-io platform.

## Purpose

Encodes compliance controls (NIST 800-53, CIS AWS, FedRAMP, PCI-DSS, SOC2) as Rust types.
Maps pangea-sim's 10 security invariants to specific compliance control IDs.
Defines baselines (sets of controls that must ALL be satisfied).
Non-compliance is expressible as a type error.

## Crate Layout

| File | Contents |
|------|----------|
| `src/controls.rs` | `Control` enum, `NistControl`, `CisControl`, `PciControl`, `Soc2Control`, convenience constructors |
| `src/baselines.rs` | `Baseline` struct, pre-defined baselines: FedRAMP Moderate, CIS AWS v3, SOC2 Type II, PCI DSS v4 |
| `src/invariant_mapping.rs` | Bidirectional invariant-to-control mapping, coverage analysis |
| `src/violation.rs` | `Violation` struct for reporting non-compliance |
| `tests/compliance_tests.rs` | 14 integration tests proving the type system |

## Key Types

- `Control` -- top-level enum across all frameworks
- `NistControl` -- NIST 800-53 Rev 5 with family, number, optional enhancement
- `Baseline` -- named set of controls that must all pass
- `BaselineCoverage` -- coverage report (covered/uncovered/percentage)
- `Violation` -- a specific control failure with context

## Invariants (from pangea-sim)

`NoPublicSsh`, `AllEbsEncrypted`, `ImdsV2Required`, `NoPublicS3`,
`IamLeastPrivilege`, `NoDefaultVpcUsage`, `AllSubnetsPrivate`,
`EncryptionAtRest`, `LoggingEnabled`, `TaggingComplete`

## Commands

| Command | What |
|---------|------|
| `cargo test` | Run all 14 compliance tests |
| `cargo clippy` | Lint with pedantic warnings |
| `cargo doc --open` | Generate and view API docs |

## Conventions

- Edition 2024, rust-version 1.89.0
- All types derive `Serialize`/`Deserialize` for cross-crate integration
- Clippy pedantic enabled
- No shell scripts -- Rust only
