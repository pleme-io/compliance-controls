# Compliance as Types

## Declare Once, Prove Once, Render Anywhere

Compliance controls are Rust types. Proofs attach to types, not platforms.
The `Backend` trait has 7 rendering implementations -- every backend shares
the same Control enum, the same invariant mappings, the same BLAKE3
certification. Adding a new backend inherits ALL existing compliance proofs.

pangea-sim proves the entire chain at zero cost: simulate → check 10
invariants across 10,000+ random configs → verify baselines across 5
frameworks → certify with BLAKE3 → deploy. No cloud API called. 856 tests
across 6 crates prove zero-cost infrastructure verification.

## The Thesis: Non-Compliance as a Compile Error

Traditional compliance follows a discover-and-remediate cycle:

1. Build infrastructure
2. Deploy to cloud
3. Run audit tools (Checkov, Prowler, ScoutSuite)
4. Discover non-compliant resources
5. File tickets, remediate
6. Re-audit
7. Repeat until compliant (or until the auditor leaves)

This is structurally broken. The feedback loop is measured in days or weeks.
Non-compliance exists in production while waiting for remediation. Audit tools
check after the damage is done.

The compliance-controls crate inverts this model entirely. Compliance controls
from five major frameworks become Rust types. Security invariants become
functions from Terraform JSON to `Result`. Baselines become sets of controls
that must ALL pass. The entire verification runs at simulation time -- before
any cloud API is called, before any infrastructure exists.

**Non-compliant infrastructure cannot be expressed in the type system.**

## How Controls Become Type Constraints

A compliance control is not a checkbox on a spreadsheet. It is a typed value
in a closed enum:

```rust
enum Control {
    Nist(NistControl),                    // NIST 800-53 Rev 5
    Cis(CisControl),                      // CIS Benchmarks
    FedRamp(FedRampLevel, NistControl),   // FedRAMP (wraps NIST)
    PciDss(PciControl),                   // PCI DSS 4.0
    Soc2(Soc2Control),                    // SOC 2 Type II
}
```

There is no `Control::Unknown`. There is no `Control::Skip`. Every control
that exists in the system is one of the five framework variants. The Rust
compiler enforces exhaustive matching -- any code that handles controls must
handle ALL variants or it will not compile.

A `NistControl` is not a string like `"SC-7"`. It is a struct with a typed
family enum (19 variants), a number, and an optional enhancement:

```rust
struct NistControl {
    family: NistFamily,       // AC, AU, CM, IA, SC, SI, AT, CA, CP, IR, MA, MP, PE, PL, PM, PS, RA, SA, SR
    number: u8,
    enhancement: Option<u8>,
}
```

`NistFamily::XY` (a non-existent family) is a compile error. `NistControl`
with family `NistFamily::SC`, number `7`, enhancement `Some(4)` is exactly
NIST SC-7(4) -- "Fail-safe boundary protection for external telecommunications
services." No ambiguity. No typos. No misinterpretation.

## The Proof Chain

The full proof chain from baseline definition to certification:

```
Baseline (set of required Controls)
  -> controls_for_invariant() maps invariants to controls
    -> pangea-sim invariants check Terraform JSON
      -> verify_baseline() runs invariants, collects control-level results
        -> certify_invariant() produces BLAKE3-hashed ProofResult
          -> certify_simulation() produces tamper-evident SimulationCertificate
            -> verify_certificate() confirms no tampering
              -> tameshi attestation layers compose into deployment gates
```

### Step 1: Define the Baseline

A baseline is a named set of controls. FedRAMP Moderate requires 23 NIST
controls. If even ONE is missing, the baseline is not satisfied:

```rust
fn fedramp_moderate() -> Baseline {
    Baseline {
        name: "FedRAMP Moderate",
        description: "NIST 800-53 Rev 5 controls required for FedRAMP Moderate",
        controls: vec![
            nist(AC, 3),        // Access enforcement
            nist(AC, 4),        // Information flow enforcement
            nist(AC, 6),        // Least privilege
            nist_enh(AC, 6, 1), // Least privilege: authorized access
            nist(AC, 14),       // Permitted actions without identification
            nist(AC, 17),       // Remote access
            nist(AU, 2),        // Event logging
            nist(AU, 3),        // Content of audit records
            nist(AU, 12),       // Audit record generation
            nist(CM, 2),        // Baseline configuration
            nist(CM, 6),        // Configuration settings
            nist(CM, 8),        // System component inventory
            nist(SC, 3),        // Security function isolation
            nist(SC, 7),        // Boundary protection
            nist_enh(SC, 7, 4), // Boundary protection: external telecommunications
            nist_enh(SC, 7, 5), // Boundary protection: deny by default
            nist(SC, 12),       // Cryptographic key establishment
            nist(SC, 13),       // Cryptographic protection
            nist(SC, 28),       // Protection of information at rest
            nist_enh(SC, 28, 1),// Protection at rest: cryptographic protection
            nist(SI, 4),        // System monitoring
            nist(SI, 7),        // Software, firmware, and information integrity
            nist(IA, 3),        // Authenticator management
            nist(IA, 5),        // Authenticator management
        ],
    }
}
```

### Step 2: Map Invariants to Controls

Each security invariant from pangea-sim covers specific controls:

```rust
fn controls_for_invariant(invariant: &str) -> Vec<Control> {
    match invariant {
        "NoPublicSsh" => vec![
            nist(AC, 17),       // Remote access -- SSH must not be open
            nist_enh(SC, 7, 4), // Boundary protection -- external telecom
            cis_aws("5.2"),     // CIS: no SSH from 0.0.0.0/0
            soc2("CC6.1"),      // SOC2: logical access
            pci("1.2.1"),       // PCI: restrict inbound traffic
        ],
        // ... 9 more invariants, each with their control mappings
    }
}
```

This mapping is the critical bridge. When `NoPublicSsh` passes (no security
group rule allows SSH from 0.0.0.0/0), it simultaneously satisfies AC-17,
SC-7(4), CIS 5.2, SOC2 CC6.1, and PCI 1.2.1. One invariant, five controls
across four frameworks. The type system ensures the mapping is exhaustive
and unambiguous.

### Step 3: Verify Against Terraform JSON

pangea-sim's `verify_baseline()` takes synthesized Terraform JSON and a
baseline, runs the mapped invariants, and produces a `ComplianceResult`:

```rust
fn verify_baseline(tf_json: &Value, baseline: &Baseline) -> ComplianceResult {
    // For each control in the baseline:
    //   1. Find which invariants cover it
    //   2. Run those invariants against the Terraform JSON
    //   3. Record pass/fail per control
    // Returns: total controls, satisfied, violated, per-control results
}
```

The result is not a percentage or a score. It is a typed struct with exactly
which controls passed, which failed, and why. `all_satisfied: bool` is the
gate. If it is `false`, the infrastructure does not meet the baseline.

### Step 4: Certify with BLAKE3

When invariants pass, pangea-sim's certification module creates
cryptographic proof:

```
certify_invariant(name, tf_json, passed, count)
  -> ProofResult {
       input_hash: BLAKE3(serialized tf_json),
       proof_hash: BLAKE3("name:passed:count:input_hash")
     }

certify_simulation(architecture, proofs)
  -> SimulationCertificate {
       certificate_hash: BLAKE3(serialized proofs vector)
     }
```

The certificate hash covers ALL proofs. Changing any proof -- flipping a
`passed` flag, altering an input hash, adding or removing a proof --
changes the certificate hash. `verify_certificate()` recomputes the hash
and compares. Tampering is detectable.

### Step 5: Tameshi Attestation

The tameshi crate composes these certificates into multi-layer Merkle trees.
Each layer type (infrastructure, compliance, secret access) contributes to
a master signature. The two-phase composition (untested -> tested -> secure)
ensures compliance proofs are included in the deployment chain.

sekiban (K8s admission webhook) gates deployments on valid signatures.
kensa (compliance engine) orchestrates the validation pipeline.
inshou (Nix gate) verifies before system rebuilds.

## How Tameshi Proves No Tampering

The tameshi attestation chain is a BLAKE3 Merkle tree:

```
Master Signature (BLAKE3)
  |
  +-- Infrastructure Layer (BLAKE3 of all resource hashes)
  |
  +-- Compliance Layer (BLAKE3 of all proof hashes)
  |     |
  |     +-- SimulationCertificate.certificate_hash
  |     +-- Per-invariant ProofResult.proof_hash
  |
  +-- Secret Access Layer (BLAKE3 of secret value hashes -- never stores values)
```

Each layer is independently verifiable. The master signature composes all
layers. Any modification at any depth invalidates the chain upward.

sekiban runs as a K8s admission webhook. Before any deployment is admitted
to the cluster, it verifies the tameshi signature chain. If the compliance
layer is missing, modified, or invalid -- the deployment is rejected.
Non-compliant code never reaches the cluster.

## Traditional vs. Type-Driven Compliance

| Aspect | Traditional | Type-Driven |
|--------|-------------|-------------|
| **When** | After deployment | Before deployment (simulation time) |
| **Cost** | Cloud resources + auditor hours | Zero (pure computation) |
| **Feedback** | Days/weeks | Milliseconds (cargo test) |
| **Coverage** | Sampled (spot checks) | Exhaustive (10,000+ random configs via proptest) |
| **Proof** | Audit report (point in time) | BLAKE3 certificate (tamper-evident, content-addressed) |
| **Remediation** | Manual ticket workflow | Fix code, re-run simulation |
| **Drift** | Discovered by next audit | Impossible (infrastructure matches types by construction) |
| **Frameworks** | One at a time | All five simultaneously (one invariant, multiple controls) |
| **Gate** | Advisory (can be overridden) | Hard gate (sekiban webhook rejects non-compliant deploys) |
| **Continuous** | Periodic re-audit | Every CI run, every commit |

## The Complete Stack

```
compliance-controls (this crate)
  Defines: Control enum, baselines, invariant mappings
  |
  v
pangea-sim (simulation engine)
  Uses: compliance-controls (feature: compliance)
  Does: verify_baseline(tf_json, baseline) -> ComplianceResult
  Does: certify_simulation(arch, proofs) -> SimulationCertificate
  |
  v
tameshi (attestation)
  Uses: ProofResult, SimulationCertificate
  Does: Compose into BLAKE3 Merkle layers, two-phase master signature
  |
  v
kensa (compliance engine)
  Uses: Control types, OSCAL dimensions
  Does: Orchestrate validation pipeline, pre-deploy checks
  |
  v
sekiban (K8s webhook)
  Uses: tameshi signatures
  Does: Admit/reject deployments based on signature validity
```

Every layer is Rust. Every type is closed. Every proof is content-addressed.
The compiler enforces what the auditor used to check.
