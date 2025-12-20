pub mod missing_owner;
pub mod reentrancy;
pub mod unauthorized_access;
pub mod integer_overflow;
pub mod type_cosplay;
pub mod pda_sharing;
pub mod invalid_sysvar_accounts;
pub mod closing_accounts;
pub mod bump_seed_canonicalization;
pub mod duplicate_mutable_accounts;
pub mod arbitrary_cpi;
pub mod account_initialization;
pub mod initialization_frontrunning;
pub mod account_data_matching;
pub mod improper_instruction_introspection;
pub mod account_reloading;
pub mod precision_loss;
pub mod insecure_randomness;
pub mod seed_collision;

#[cfg(test)]
pub mod test_utils;

// Common traits and types for analyzers
use crate::models::*;
use anyhow::Result;
use std::fmt;

#[allow(dead_code)]
pub trait Analyzer {
    fn analyze(&self, program: &Program) -> Result<Vec<Finding>>;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Finding {
    pub severity: Severity,
    pub certainty: Certainty,
    pub message: String,
    pub location: Location,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    //Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Certainty {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Location {
    pub file: String,
    pub line: usize,
    pub column: usize,
} 