use crate::controls::*;

/// A compliance baseline -- a named set of controls that must ALL be satisfied.
#[derive(Debug, Clone)]
pub struct Baseline {
    pub name: &'static str,
    pub description: &'static str,
    pub controls: Vec<Control>,
}

impl Baseline {
    /// Check if a set of satisfied controls covers this baseline.
    #[must_use]
    pub fn is_satisfied_by(&self, satisfied: &[Control]) -> bool {
        self.controls.iter().all(|c| satisfied.contains(c))
    }

    /// Return controls NOT satisfied by the given set.
    #[must_use]
    pub fn unsatisfied(&self, satisfied: &[Control]) -> Vec<&Control> {
        self.controls
            .iter()
            .filter(|c| !satisfied.contains(c))
            .collect()
    }
}

/// FedRAMP Moderate baseline (subset relevant to infrastructure).
#[must_use]
pub fn fedramp_moderate() -> Baseline {
    use NistFamily::*;
    Baseline {
        name: "FedRAMP Moderate",
        description: "NIST 800-53 Rev 5 controls required for FedRAMP Moderate",
        controls: vec![
            nist(AC, 3),
            nist(AC, 4),
            nist(AC, 6),
            nist_enh(AC, 6, 1),
            nist(AC, 14),
            nist(AC, 17),
            nist(AU, 2),
            nist(AU, 3),
            nist(AU, 12),
            nist(CM, 2),
            nist(CM, 6),
            nist(CM, 8),
            nist(SC, 3),
            nist(SC, 7),
            nist_enh(SC, 7, 4),
            nist_enh(SC, 7, 5),
            nist(SC, 12),
            nist(SC, 13),
            nist(SC, 28),
            nist_enh(SC, 28, 1),
            nist(SI, 4),
            nist(SI, 7),
            nist(IA, 3),
            nist(IA, 5),
        ],
    }
}

/// CIS AWS Foundations Benchmark v3.0 (network + encryption controls).
#[must_use]
pub fn cis_aws_v3() -> Baseline {
    Baseline {
        name: "CIS AWS Foundations v3.0",
        description: "CIS AWS Foundations Benchmark v3.0 network and encryption controls",
        controls: vec![
            cis_aws("2.1.1"),
            cis_aws("2.2.1"),
            cis_aws("5.1"),
            cis_aws("5.2"),
            cis_aws("5.3"),
            cis_aws("EC2.21"),
        ],
    }
}

/// SOC 2 Type II (security criteria).
#[must_use]
pub fn soc2_type_ii() -> Baseline {
    Baseline {
        name: "SOC 2 Type II",
        description: "SOC 2 Type II common criteria for security",
        controls: vec![soc2("CC6.1"), soc2("CC6.6"), soc2("CC7.1"), soc2("CC7.2")],
    }
}

/// PCI DSS 4.0 (network + encryption).
#[must_use]
pub fn pci_dss_v4() -> Baseline {
    Baseline {
        name: "PCI DSS 4.0",
        description: "PCI DSS 4.0 network segmentation and encryption",
        controls: vec![
            pci("1.2.1"),
            pci("1.2.5"),
            pci("2.2.1"),
            pci("3.4.1"),
            pci("4.2.1"),
        ],
    }
}
