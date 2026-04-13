use serde::{Deserialize, Serialize};

/// A compliance control from any framework.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum Control {
    Nist(NistControl),
    Cis(CisControl),
    FedRamp(FedRampLevel, NistControl),
    PciDss(PciControl),
    Soc2(Soc2Control),
}

/// NIST 800-53 Rev 5 control.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct NistControl {
    pub family: NistFamily,
    pub number: u8,
    pub enhancement: Option<u8>,
}

impl NistControl {
    #[must_use]
    pub const fn new(family: NistFamily, number: u8) -> Self {
        Self {
            family,
            number,
            enhancement: None,
        }
    }

    #[must_use]
    pub const fn enhanced(family: NistFamily, number: u8, enh: u8) -> Self {
        Self {
            family,
            number,
            enhancement: Some(enh),
        }
    }
}

impl std::fmt::Display for NistControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.enhancement {
            Some(e) => write!(f, "{}-{}({})", self.family, self.number, e),
            None => write!(f, "{}-{}", self.family, self.number),
        }
    }
}

/// NIST 800-53 control families.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum NistFamily {
    /// Access Control
    AC,
    /// Audit and Accountability
    AU,
    /// Configuration Management
    CM,
    /// Identification and Authentication
    IA,
    /// System and Communications Protection
    SC,
    /// System and Information Integrity
    SI,
    /// Awareness and Training
    AT,
    /// Assessment, Authorization, and Monitoring
    CA,
    /// Contingency Planning
    CP,
    /// Incident Response
    IR,
    /// Maintenance
    MA,
    /// Media Protection
    MP,
    /// Physical and Environmental Protection
    PE,
    /// Planning
    PL,
    /// Program Management
    PM,
    /// Personnel Security
    PS,
    /// Risk Assessment
    RA,
    /// System and Services Acquisition
    SA,
    /// Supply Chain Risk Management
    SR,
}

impl std::fmt::Display for NistFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// CIS Benchmark control.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct CisControl {
    pub benchmark: CisBenchmark,
    /// Section identifier, e.g., "5.2", "2.2.1", "EC2.21".
    pub section: String,
}

/// CIS Benchmark type.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum CisBenchmark {
    AwsV3,
    LinuxL1,
    LinuxL2,
    KubernetesV1,
}

/// FedRAMP impact level.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum FedRampLevel {
    Low,
    Moderate,
    High,
}

/// PCI DSS 4.0 control.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct PciControl {
    /// Requirement identifier, e.g., "1.2.1", "3.4.1", "4.2.1".
    pub requirement: String,
}

/// SOC 2 Type II criteria.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Soc2Control {
    /// Criteria identifier, e.g., "CC6.1", "CC6.6", "CC7.1".
    pub criteria: String,
}

// -- Convenience constructors ------------------------------------------------

/// Create a NIST 800-53 control.
#[must_use]
pub fn nist(family: NistFamily, number: u8) -> Control {
    Control::Nist(NistControl::new(family, number))
}

/// Create a NIST 800-53 control with an enhancement.
#[must_use]
pub fn nist_enh(family: NistFamily, number: u8, enh: u8) -> Control {
    Control::Nist(NistControl::enhanced(family, number, enh))
}

/// Create a CIS AWS Foundations Benchmark v3.0 control.
#[must_use]
pub fn cis_aws(section: &str) -> Control {
    Control::Cis(CisControl {
        benchmark: CisBenchmark::AwsV3,
        section: section.to_string(),
    })
}

/// Create a FedRAMP control (wraps a NIST control with an impact level).
#[must_use]
pub fn fedramp(level: FedRampLevel, family: NistFamily, number: u8) -> Control {
    Control::FedRamp(level, NistControl::new(family, number))
}

/// Create a PCI DSS 4.0 control.
#[must_use]
pub fn pci(requirement: &str) -> Control {
    Control::PciDss(PciControl {
        requirement: requirement.to_string(),
    })
}

/// Create a SOC 2 Type II control.
#[must_use]
pub fn soc2(criteria: &str) -> Control {
    Control::Soc2(Soc2Control {
        criteria: criteria.to_string(),
    })
}
