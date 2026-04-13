# compliance-controls

Compliance controls as Rust types. Non-compliance becomes a compile error.

## Declare Once, Prove Once, Render Anywhere

Compliance controls are Rust types. Proofs attach to types, not platforms.
The `Backend` trait has 7 rendering implementations (Terraform, Pulumi,
Crossplane, Ansible, Pangea, Steampipe) -- all share the same control types,
the same invariant mappings, the same BLAKE3 certification. Adding a new
backend inherits ALL existing compliance proofs.

The simulation platform (pangea-sim) proves compliance at zero cost: simulate
infrastructure → check 10 invariants → verify baselines across 5 frameworks
→ certify with BLAKE3 → deploy. No cloud API called until deployment is
proven correct and compliant.

## The Thesis

Traditional compliance is audit-after-deploy: build infrastructure, hire auditors,
discover gaps, remediate, repeat. This crate inverts the model. Compliance controls
from NIST 800-53, CIS AWS, FedRAMP, PCI-DSS, and SOC 2 are encoded as Rust types.
Security invariants from pangea-sim map to specific control IDs. Baselines define
which controls must ALL be satisfied. If an invariant fails, the controls it covers
are violated -- and the system reports exactly which compliance requirements are unmet.

The result: compliance is verified at simulation time, before any cloud API is called.
Non-compliant infrastructure is structurally impossible when the proof chain is complete.

## The Control Enum

All compliance frameworks are unified under a single `Control` enum:

```rust
enum Control {
    Nist(NistControl),           // NIST 800-53 Rev 5
    Cis(CisControl),             // CIS Benchmarks (AWS v3, Linux, K8s)
    FedRamp(FedRampLevel, NistControl), // FedRAMP (Low/Moderate/High wrapping NIST)
    PciDss(PciControl),          // PCI DSS 4.0
    Soc2(Soc2Control),           // SOC 2 Type II
}
```

### NIST 800-53 Rev 5

```rust
struct NistControl {
    family: NistFamily,    // AC, AU, CM, IA, SC, SI, AT, CA, CP, IR, MA, MP, PE, PL, PM, PS, RA, SA, SR
    number: u8,            // e.g., 17 for AC-17
    enhancement: Option<u8>, // e.g., Some(4) for SC-7(4)
}
```

19 NIST families are supported. Controls display as `AC-17` or `SC-7(4)`.

### Other Frameworks

| Type | Key Field | Example |
|------|-----------|---------|
| `CisControl` | `benchmark: CisBenchmark`, `section: String` | CIS AWS v3, section "5.2" |
| `PciControl` | `requirement: String` | PCI DSS 4.0, requirement "1.2.1" |
| `Soc2Control` | `criteria: String` | SOC 2, criteria "CC6.1" |
| `FedRampLevel` | `Low`, `Moderate`, `High` | Wraps a NistControl |

## Invariant-to-Control Mapping

Each of pangea-sim's 10 security invariants maps to specific compliance controls
via `controls_for_invariant()`:

| Invariant | NIST | CIS AWS | SOC 2 | PCI DSS |
|-----------|------|---------|-------|---------|
| `NoPublicSsh` | AC-17, SC-7(4) | 5.2 | CC6.1 | 1.2.1 |
| `AllEbsEncrypted` | SC-28(1), SC-13 | 2.2.1 | CC6.1 | 3.4.1 |
| `ImdsV2Required` | SC-3 | EC2.21 | -- | -- |
| `NoPublicS3` | AC-3, AC-14 | 2.1.1 | CC6.1 | -- |
| `IamLeastPrivilege` | AC-6, AC-6(1) | -- | CC6.1 | -- |
| `NoDefaultVpcUsage` | SC-7 | 5.1 | -- | -- |
| `AllSubnetsPrivate` | SC-7(5), AC-4 | -- | -- | 1.2.5 |
| `EncryptionAtRest` | SC-28, SC-12 | -- | -- | 3.4.1 |
| `LoggingEnabled` | AU-2, AU-12, SI-4 | -- | CC7.1, CC7.2 | -- |
| `TaggingComplete` | CM-8, CM-2 | -- | -- | -- |

The reverse mapping `invariants_for_nist(family, number)` answers: "which invariants
satisfy NIST SC-7?" -- returns `["NoDefaultVpcUsage", "AllSubnetsPrivate", "NoPublicSsh"]`.

## Baselines

A `Baseline` is a named set of controls that must ALL be satisfied:

```rust
struct Baseline {
    name: &'static str,
    description: &'static str,
    controls: Vec<Control>,
}
```

### Pre-defined Baselines

| Baseline | Function | Controls | Frameworks |
|----------|----------|----------|------------|
| FedRAMP Moderate | `fedramp_moderate()` | 23 | NIST 800-53 (AC, AU, CM, SC, SI, IA) |
| CIS AWS v3.0 | `cis_aws_v3()` | 6 | CIS AWS Foundations Benchmark |
| SOC 2 Type II | `soc2_type_ii()` | 4 | SOC 2 common criteria (CC6, CC7) |
| PCI DSS 4.0 | `pci_dss_v4()` | 5 | PCI DSS network + encryption |

### Coverage Analysis

`baseline_coverage(baseline)` returns a `BaselineCoverage` report:

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

Methods: `percentage()` (0.0-100.0), `is_fully_covered()` (bool).

The 10 invariants cover 15+ unique NIST controls. FedRAMP Moderate coverage exceeds 50%.

## Violations

When a control is not satisfied, a `Violation` captures the details:

```rust
struct Violation {
    control: Control,
    invariant: String,
    resource_type: String,
    message: String,
}
```

Display format: `[NoPublicSsh] AC-17: SSH port 22 open to 0.0.0.0/0 (aws_security_group)`.

## Usage

```rust
use compliance_controls::*;

// Check which controls an invariant satisfies
let controls = controls_for_invariant("NoPublicSsh");
// -> [AC-17, SC-7(4), CIS 5.2, SOC2 CC6.1, PCI 1.2.1]

// Check if invariants cover a baseline
let baseline = fedramp_moderate();
let all = all_controls_covered();
let coverage = baseline_coverage(&baseline);
println!("{}: {:.1}% covered", coverage.baseline_name, coverage.percentage());

// Check baseline satisfaction
if baseline.is_satisfied_by(&all) {
    println!("FedRAMP Moderate: PASS");
} else {
    for control in baseline.unsatisfied(&all) {
        println!("MISSING: {:?}", control);
    }
}

// Reverse lookup: which invariants cover SC-7?
let invariants = invariants_for_nist(NistFamily::SC, 7);
// -> ["NoDefaultVpcUsage", "AllSubnetsPrivate", "NoPublicSsh"]
```

## Integration

| Crate | Relationship |
|-------|-------------|
| `pangea-sim` | Upstream: defines the 10 invariants. `compliance` feature enables `verify_baseline()` |
| `kensa` | Downstream: compliance engine uses control types for NIST 800-53 + OSCAL validation |
| `tameshi` | Downstream: attestation layers compose with compliance proofs via BLAKE3 Merkle trees |

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
