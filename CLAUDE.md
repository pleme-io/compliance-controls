# compliance-controls

Compliance controls as Rust types for the pleme-io platform.

## Declare Once, Prove Once, Render Anywhere

Compliance controls are Rust types. Proofs attach to types, not platforms.
The 7 rendering backends (Terraform, Pulumi, Crossplane, Ansible, Pangea,
Steampipe) all share the same control types, invariant mappings, and BLAKE3
certification. Adding a new backend inherits ALL existing compliance proofs.

pangea-sim proves the entire compliance chain at zero cost -- no cloud API
called. 856 tests across 6 crates verify structure, invariants, compliance,
and certification before any infrastructure exists.

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

### Control (src/controls.rs)

```rust
enum Control {
    Nist(NistControl),
    Cis(CisControl),
    FedRamp(FedRampLevel, NistControl),
    PciDss(PciControl),
    Soc2(Soc2Control),
}

struct NistControl {
    family: NistFamily,       // 19 families: AC, AU, CM, IA, SC, SI, AT, CA, CP, IR, MA, MP, PE, PL, PM, PS, RA, SA, SR
    number: u8,
    enhancement: Option<u8>,  // e.g., Some(4) for SC-7(4)
}

struct CisControl {
    benchmark: CisBenchmark,  // AwsV3, LinuxL1, LinuxL2, KubernetesV1
    section: String,
}

enum FedRampLevel { Low, Moderate, High }

struct PciControl { requirement: String }  // e.g., "1.2.1"
struct Soc2Control { criteria: String }    // e.g., "CC6.1"
```

All types derive `Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize`.

### Convenience constructors (src/controls.rs)

| Function | Creates |
|----------|---------|
| `nist(family, number)` | `Control::Nist(NistControl::new(family, number))` |
| `nist_enh(family, number, enh)` | `Control::Nist(NistControl::enhanced(family, number, enh))` |
| `cis_aws(section)` | `Control::Cis(CisControl { benchmark: AwsV3, section })` |
| `fedramp(level, family, number)` | `Control::FedRamp(level, NistControl::new(family, number))` |
| `pci(requirement)` | `Control::PciDss(PciControl { requirement })` |
| `soc2(criteria)` | `Control::Soc2(Soc2Control { criteria })` |

### Baseline (src/baselines.rs)

```rust
struct Baseline {
    name: &'static str,
    description: &'static str,
    controls: Vec<Control>,
}
```

Methods:
- `is_satisfied_by(&self, satisfied: &[Control]) -> bool` -- all controls present
- `unsatisfied(&self, satisfied: &[Control]) -> Vec<&Control>` -- missing controls

### Pre-defined baselines

| Function | Name | Controls |
|----------|------|----------|
| `fedramp_moderate()` | FedRAMP Moderate | AC-3, AC-4, AC-6, AC-6(1), AC-14, AC-17, AU-2, AU-3, AU-12, CM-2, CM-6, CM-8, SC-3, SC-7, SC-7(4), SC-7(5), SC-12, SC-13, SC-28, SC-28(1), SI-4, SI-7, IA-3, IA-5 |
| `cis_aws_v3()` | CIS AWS v3.0 | 2.1.1, 2.2.1, 5.1, 5.2, 5.3, EC2.21 |
| `soc2_type_ii()` | SOC 2 Type II | CC6.1, CC6.6, CC7.1, CC7.2 |
| `pci_dss_v4()` | PCI DSS 4.0 | 1.2.1, 1.2.5, 2.2.1, 3.4.1, 4.2.1 |

### Invariant Mapping (src/invariant_mapping.rs)

| Invariant | Controls |
|-----------|----------|
| `NoPublicSsh` | AC-17, SC-7(4), CIS 5.2, SOC2 CC6.1, PCI 1.2.1 |
| `AllEbsEncrypted` | SC-28(1), SC-13, CIS 2.2.1, SOC2 CC6.1, PCI 3.4.1 |
| `ImdsV2Required` | SC-3, CIS EC2.21 |
| `NoPublicS3` | AC-3, AC-14, CIS 2.1.1, SOC2 CC6.1 |
| `IamLeastPrivilege` | AC-6, AC-6(1), SOC2 CC6.1 |
| `NoDefaultVpcUsage` | SC-7, CIS 5.1 |
| `AllSubnetsPrivate` | SC-7(5), AC-4, PCI 1.2.5 |
| `EncryptionAtRest` | SC-28, SC-12, PCI 3.4.1 |
| `LoggingEnabled` | AU-2, AU-12, SI-4, SOC2 CC7.1, SOC2 CC7.2 |
| `TaggingComplete` | CM-8, CM-2 |

Key functions:
- `controls_for_invariant(name: &str) -> Vec<Control>` -- forward mapping
- `invariants_for_nist(family, number) -> Vec<&str>` -- reverse NIST mapping
- `all_nist_controls() -> Vec<NistControl>` -- all unique NIST controls (15+)
- `all_controls_covered() -> Vec<Control>` -- all controls across all frameworks
- `baseline_coverage(baseline) -> BaselineCoverage` -- coverage report

### BaselineCoverage (src/invariant_mapping.rs)

```rust
struct BaselineCoverage {
    baseline_name: &'static str,
    total: usize,
    covered_count: usize,
    uncovered_count: usize,
    covered: Vec<Control>,
    uncovered: Vec<Control>,
}
```

Methods: `percentage() -> f64`, `is_fully_covered() -> bool`.

### Violation (src/violation.rs)

```rust
struct Violation {
    control: Control,
    invariant: String,
    resource_type: String,
    message: String,
}
```

Implements `Display`: `[NoPublicSsh] AC-17: SSH port 22 open to 0.0.0.0/0 (aws_security_group)`.

## How to Add New Controls

1. Add the control type to `Control` enum in `src/controls.rs` (if new framework)
2. Add a convenience constructor function
3. Map invariants to the new control in `src/invariant_mapping.rs` `controls_for_invariant()`
4. Optionally create a baseline in `src/baselines.rs`
5. Add tests in `tests/compliance_tests.rs`

## How to Add New Invariants

1. Add the invariant name to `ALL_INVARIANTS` in `src/invariant_mapping.rs`
2. Add a match arm in `controls_for_invariant()` mapping it to controls
3. Implement the invariant struct in `pangea-sim/src/invariants/mod.rs`
4. Add the name mapping in `pangea-sim/src/compliance.rs` `invariant_name_to_pascal()`

## How to Add New Baselines

1. Add a function in `src/baselines.rs` returning `Baseline`
2. Populate `controls` with the required control set
3. Add coverage test in `tests/compliance_tests.rs`

## Integration with Other Crates

| Crate | How |
|-------|-----|
| `pangea-sim` | Feature-gated `compliance` enables `verify_baseline(tf_json, baseline)` using this crate |
| `kensa` | Uses `Control` types for NIST 800-53 + OSCAL compliance engine |
| `tameshi` | Attestation layers compose compliance proofs via BLAKE3 Merkle trees |

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
