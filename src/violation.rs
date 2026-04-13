use crate::controls::Control;
use serde::{Deserialize, Serialize};

/// A compliance violation -- a control that was not satisfied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub control: Control,
    pub invariant: String,
    pub resource_type: String,
    pub message: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}: {} ({})",
            self.invariant,
            self.control_display(),
            self.message,
            self.resource_type
        )
    }
}

impl Violation {
    fn control_display(&self) -> String {
        match &self.control {
            Control::Nist(n) => n.to_string(),
            Control::Cis(c) => format!("CIS {}", c.section),
            Control::FedRamp(l, n) => format!("FedRAMP {l:?} {n}"),
            Control::PciDss(p) => format!("PCI {}", p.requirement),
            Control::Soc2(s) => format!("SOC2 {}", s.criteria),
        }
    }
}
