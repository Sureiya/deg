//! The evidence-strength lattice.
//!
//! Strength is *computed by the kernel* from checked evidence and rule caps.
//! A user can never write a strength onto an evidence term or a proof line.

use std::fmt;

/// Ordered evidence strength. `Speculative` is the bottom, `Exact` the top.
///
/// ```text
/// Speculative < Heuristic < Observational < Deterministic < Exact
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Strength {
    Speculative = 0,
    Heuristic = 1,
    Observational = 2,
    Deterministic = 3,
    Exact = 4,
}

impl Strength {
    pub const BOTTOM: Strength = Strength::Speculative;
    pub const TOP: Strength = Strength::Exact;

    /// Lattice join (least upper bound).
    pub fn join(self, other: Strength) -> Strength {
        self.max(other)
    }

    /// Lattice meet (greatest lower bound). This is the `min` used when a
    /// conclusion inherits the weakest premise.
    pub fn meet(self, other: Strength) -> Strength {
        self.min(other)
    }

    pub fn is_sealable_at(self, threshold: Strength) -> bool {
        self >= threshold
    }

    /// Statistical claims can never exceed Observational, by construction.
    pub fn statistical_cap(self) -> Strength {
        self.min(Strength::Observational)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Strength::Speculative => "speculative",
            Strength::Heuristic => "heuristic",
            Strength::Observational => "observational",
            Strength::Deterministic => "deterministic",
            Strength::Exact => "exact",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Strength::Speculative => "SPEC",
            Strength::Heuristic => "HEUR",
            Strength::Observational => "OBS",
            Strength::Deterministic => "DET",
            Strength::Exact => "EXACT",
        }
    }

    pub fn parse(s: &str) -> Option<Strength> {
        match s.to_ascii_lowercase().as_str() {
            "speculative" | "spec" => Some(Strength::Speculative),
            "heuristic" | "heur" => Some(Strength::Heuristic),
            "observational" | "obs" => Some(Strength::Observational),
            "deterministic" | "det" => Some(Strength::Deterministic),
            "exact" => Some(Strength::Exact),
            _ => None,
        }
    }
}

impl fmt::Display for Strength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_the_designed_lattice() {
        assert!(Strength::Speculative < Strength::Heuristic);
        assert!(Strength::Heuristic < Strength::Observational);
        assert!(Strength::Observational < Strength::Deterministic);
        assert!(Strength::Deterministic < Strength::Exact);
    }

    #[test]
    fn meet_is_the_bottleneck() {
        let s = Strength::Exact
            .meet(Strength::Deterministic)
            .meet(Strength::Observational);
        assert_eq!(s, Strength::Observational);
    }

    #[test]
    fn statistical_cap_is_observational() {
        assert_eq!(Strength::Exact.statistical_cap(), Strength::Observational);
        assert_eq!(Strength::Heuristic.statistical_cap(), Strength::Heuristic);
    }
}
