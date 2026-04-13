use crate::controls::*;

/// Map a pangea-sim invariant name to the compliance controls it satisfies.
#[must_use]
pub fn controls_for_invariant(invariant: &str) -> Vec<Control> {
    use NistFamily::*;
    match invariant {
        "NoPublicSsh" => vec![
            nist(AC, 17),
            nist_enh(SC, 7, 4),
            cis_aws("5.2"),
            soc2("CC6.1"),
            pci("1.2.1"),
        ],
        "AllEbsEncrypted" => vec![
            nist_enh(SC, 28, 1),
            nist(SC, 13),
            cis_aws("2.2.1"),
            soc2("CC6.1"),
            pci("3.4.1"),
        ],
        "ImdsV2Required" => vec![nist(SC, 3), cis_aws("EC2.21")],
        "NoPublicS3" => vec![nist(AC, 3), nist(AC, 14), cis_aws("2.1.1"), soc2("CC6.1")],
        "IamLeastPrivilege" => vec![nist(AC, 6), nist_enh(AC, 6, 1), soc2("CC6.1")],
        "NoDefaultVpcUsage" => vec![nist(SC, 7), cis_aws("5.1")],
        "AllSubnetsPrivate" => vec![nist_enh(SC, 7, 5), nist(AC, 4), pci("1.2.5")],
        "EncryptionAtRest" => vec![nist(SC, 28), nist(SC, 12), pci("3.4.1")],
        "LoggingEnabled" => vec![
            nist(AU, 2),
            nist(AU, 12),
            nist(SI, 4),
            soc2("CC7.1"),
            soc2("CC7.2"),
        ],
        "TaggingComplete" => vec![nist(CM, 8), nist(CM, 2)],
        _ => vec![],
    }
}

/// All invariant names.
pub const ALL_INVARIANTS: &[&str] = &[
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

/// Reverse mapping: which invariants satisfy a given NIST control?
#[must_use]
pub fn invariants_for_nist(family: NistFamily, number: u8) -> Vec<&'static str> {
    let target = Control::Nist(NistControl::new(family, number));
    ALL_INVARIANTS
        .iter()
        .filter(|inv| {
            controls_for_invariant(inv).iter().any(|c| match (c, &target) {
                (Control::Nist(a), Control::Nist(b)) => {
                    a.family == b.family && a.number == b.number
                }
                _ => false,
            })
        })
        .copied()
        .collect()
}

/// All unique NIST controls covered by the 10 invariants.
#[must_use]
pub fn all_nist_controls() -> Vec<NistControl> {
    let mut controls = std::collections::HashSet::new();
    for inv in ALL_INVARIANTS {
        for c in controls_for_invariant(inv) {
            if let Control::Nist(n) = c {
                controls.insert(n);
            }
        }
    }
    let mut sorted: Vec<_> = controls.into_iter().collect();
    sorted.sort_by(|a, b| {
        a.family
            .to_string()
            .cmp(&b.family.to_string())
            .then(a.number.cmp(&b.number))
            .then(a.enhancement.cmp(&b.enhancement))
    });
    sorted
}

/// All controls (any framework) covered by the 10 invariants.
#[must_use]
pub fn all_controls_covered() -> Vec<Control> {
    let mut controls = Vec::new();
    for inv in ALL_INVARIANTS {
        for c in controls_for_invariant(inv) {
            if !controls.contains(&c) {
                controls.push(c);
            }
        }
    }
    controls
}

/// Check if a baseline is fully covered by the 10 invariants.
#[must_use]
pub fn baseline_coverage(baseline: &crate::baselines::Baseline) -> BaselineCoverage {
    let all_covered = all_controls_covered();
    let covered: Vec<_> = baseline
        .controls
        .iter()
        .filter(|c| all_covered.contains(c))
        .cloned()
        .collect();
    let uncovered: Vec<_> = baseline
        .controls
        .iter()
        .filter(|c| !all_covered.contains(c))
        .cloned()
        .collect();
    BaselineCoverage {
        baseline_name: baseline.name,
        total: baseline.controls.len(),
        covered_count: covered.len(),
        uncovered_count: uncovered.len(),
        covered,
        uncovered,
    }
}

/// Coverage report for a baseline.
#[derive(Debug)]
pub struct BaselineCoverage {
    pub baseline_name: &'static str,
    pub total: usize,
    pub covered_count: usize,
    pub uncovered_count: usize,
    pub covered: Vec<Control>,
    pub uncovered: Vec<Control>,
}

impl BaselineCoverage {
    /// Coverage percentage (0.0 to 100.0).
    #[must_use]
    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.covered_count as f64 / self.total as f64) * 100.0
        }
    }

    /// Whether all controls in the baseline are covered.
    #[must_use]
    pub fn is_fully_covered(&self) -> bool {
        self.uncovered_count == 0
    }
}
