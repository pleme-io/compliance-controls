use compliance_controls::*;
use std::collections::HashSet;

// 1. Every invariant maps to at least 1 NIST control
#[test]
fn every_invariant_maps_to_at_least_one_nist_control() {
    for inv in ALL_INVARIANTS {
        let controls = controls_for_invariant(inv);
        let has_nist = controls.iter().any(|c| matches!(c, Control::Nist(_)));
        assert!(has_nist, "Invariant {inv} has no NIST control mapping");
    }
}

// 2. Every invariant maps to at least 1 control total
#[test]
fn every_invariant_maps_to_at_least_one_control() {
    for inv in ALL_INVARIANTS {
        let controls = controls_for_invariant(inv);
        assert!(
            !controls.is_empty(),
            "Invariant {inv} has no control mappings"
        );
    }
}

// 3. All 10 invariants are in ALL_INVARIANTS
#[test]
fn all_ten_invariants_present() {
    let expected = [
        "NoPublicSsh",
        "AllEbsEncrypted",
        "ImdsV2Required",
        "NoPublicS3",
        "IamLeastPrivilege",
        "NoDefaultVpcUsage",
        "AllSubnetsPrivate",
        "EncryptionAtRest",
        "LoggingEnabled",
        "TaggingComplete",
    ];
    assert_eq!(ALL_INVARIANTS.len(), 10);
    for inv in &expected {
        assert!(
            ALL_INVARIANTS.contains(inv),
            "Missing invariant: {inv}"
        );
    }
}

// 4. No duplicate controls within a single invariant mapping
#[test]
fn no_duplicate_controls_per_invariant() {
    for inv in ALL_INVARIANTS {
        let controls = controls_for_invariant(inv);
        let unique: HashSet<_> = controls.iter().collect();
        assert_eq!(
            controls.len(),
            unique.len(),
            "Invariant {inv} has duplicate controls"
        );
    }
}

// 5. Reverse mapping: SC-7 is covered by NoDefaultVpcUsage + AllSubnetsPrivate + NoPublicSsh
#[test]
fn reverse_mapping_sc7() {
    let invariants = invariants_for_nist(NistFamily::SC, 7);
    assert!(
        invariants.contains(&"NoDefaultVpcUsage"),
        "SC-7 should be covered by NoDefaultVpcUsage"
    );
    assert!(
        invariants.contains(&"AllSubnetsPrivate"),
        "SC-7 should be covered by AllSubnetsPrivate (via SC-7(5))"
    );
    assert!(
        invariants.contains(&"NoPublicSsh"),
        "SC-7 should be covered by NoPublicSsh (via SC-7(4))"
    );
}

// 6. FedRAMP Moderate coverage percentage (should be significant)
#[test]
fn fedramp_moderate_coverage_significant() {
    let baseline = fedramp_moderate();
    let coverage = baseline_coverage(&baseline);
    assert!(
        coverage.percentage() >= 50.0,
        "FedRAMP Moderate coverage should be >= 50%, got {:.1}%",
        coverage.percentage()
    );
}

// 7. CIS AWS coverage percentage
#[test]
fn cis_aws_coverage_significant() {
    let baseline = cis_aws_v3();
    let coverage = baseline_coverage(&baseline);
    assert!(
        coverage.percentage() >= 50.0,
        "CIS AWS coverage should be >= 50%, got {:.1}%",
        coverage.percentage()
    );
}

// 8. All NIST controls covered count (should be 15+)
#[test]
fn nist_controls_covered_at_least_fifteen() {
    let controls = all_nist_controls();
    assert!(
        controls.len() >= 15,
        "Should cover at least 15 NIST controls, got {}",
        controls.len()
    );
}

// 9. Baseline satisfaction check works
#[test]
fn baseline_satisfaction_check() {
    // Construct a baseline from controls we know are covered by invariants
    let known_covered = Baseline {
        name: "Test Baseline",
        description: "Controls known to be covered by invariants",
        controls: vec![
            nist(NistFamily::AC, 3),
            nist(NistFamily::AC, 17),
            cis_aws("5.2"),
            soc2("CC6.1"),
        ],
    };
    let all = all_controls_covered();

    // Full satisfaction
    assert!(
        known_covered.is_satisfied_by(&all),
        "Test baseline should be satisfied when all invariant controls are provided"
    );

    // Partial satisfaction -- only one control should not satisfy the baseline
    let partial = vec![soc2("CC6.1")];
    assert!(
        !known_covered.is_satisfied_by(&partial),
        "Test baseline should NOT be satisfied with only one control"
    );

    // Unsatisfied returns the right count
    let unsatisfied = known_covered.unsatisfied(&partial);
    assert_eq!(
        unsatisfied.len(),
        known_covered.controls.len() - 1,
        "Should have all but one control unsatisfied"
    );

    // Real baselines have gaps -- CIS AWS includes 5.3 which no invariant covers
    let cis = cis_aws_v3();
    let cis_unsatisfied = cis.unsatisfied(&all);
    assert!(
        !cis_unsatisfied.is_empty(),
        "CIS AWS should have some unsatisfied controls (e.g., 5.3)"
    );
}

// 10. Violation display formatting
#[test]
fn violation_display_formatting() {
    let v = Violation {
        control: nist(NistFamily::AC, 17),
        invariant: "NoPublicSsh".to_string(),
        resource_type: "aws_security_group".to_string(),
        message: "SSH port 22 open to 0.0.0.0/0".to_string(),
    };
    let display = format!("{v}");
    assert!(display.contains("NoPublicSsh"));
    assert!(display.contains("AC-17"));
    assert!(display.contains("SSH port 22 open to 0.0.0.0/0"));
    assert!(display.contains("aws_security_group"));
}

// 11. Control serialization roundtrip
#[test]
fn control_serialization_roundtrip() {
    let controls = vec![
        nist(NistFamily::AC, 3),
        nist_enh(NistFamily::SC, 7, 4),
        cis_aws("5.2"),
        pci("1.2.1"),
        soc2("CC6.1"),
    ];
    for control in &controls {
        let json = serde_json::to_string(control).expect("serialize");
        let deserialized: Control = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(control, &deserialized, "Roundtrip failed for {json}");
    }
}

// 12. NistControl Display formatting (e.g., "SC-7(5)")
#[test]
fn nist_control_display_formatting() {
    let plain = NistControl::new(NistFamily::SC, 7);
    assert_eq!(plain.to_string(), "SC-7");

    let enhanced = NistControl::enhanced(NistFamily::SC, 7, 5);
    assert_eq!(enhanced.to_string(), "SC-7(5)");

    let ac = NistControl::new(NistFamily::AC, 17);
    assert_eq!(ac.to_string(), "AC-17");
}

// 13. Convenience constructors produce correct variants
#[test]
fn convenience_constructors() {
    assert!(matches!(nist(NistFamily::AC, 3), Control::Nist(_)));
    assert!(matches!(nist_enh(NistFamily::SC, 7, 4), Control::Nist(_)));
    assert!(matches!(cis_aws("5.2"), Control::Cis(_)));
    assert!(matches!(
        fedramp(FedRampLevel::Moderate, NistFamily::AC, 3),
        Control::FedRamp(_, _)
    ));
    assert!(matches!(pci("1.2.1"), Control::PciDss(_)));
    assert!(matches!(soc2("CC6.1"), Control::Soc2(_)));
}

// 14. baseline_coverage returns correct counts
#[test]
fn baseline_coverage_correct_counts() {
    let baseline = fedramp_moderate();
    let coverage = baseline_coverage(&baseline);

    assert_eq!(coverage.total, baseline.controls.len());
    assert_eq!(
        coverage.covered_count + coverage.uncovered_count,
        coverage.total
    );
    assert_eq!(coverage.covered.len(), coverage.covered_count);
    assert_eq!(coverage.uncovered.len(), coverage.uncovered_count);

    // Percentage math
    let expected_pct = (coverage.covered_count as f64 / coverage.total as f64) * 100.0;
    assert!(
        (coverage.percentage() - expected_pct).abs() < f64::EPSILON,
        "Percentage mismatch"
    );
}
