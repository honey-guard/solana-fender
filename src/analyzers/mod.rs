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
pub mod account_data_matching;

// Common traits and types for analyzers
use crate::models::*;
use anyhow::Result;

#[allow(dead_code)]
pub trait Analyzer {
    fn analyze(&self, program: &Program) -> Result<Vec<Finding>>;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Finding {
    pub severity: Severity,
    pub certainty: Certainty,
    pub message: String,
    pub location: Location,
}

#[derive(Debug)]
pub enum Severity {
    Critical,
    High,
    Medium,
    //Low,
    //Info,
}

#[derive(Debug)]
pub enum Certainty {
    High,
    Medium,
    Low,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Location {
    pub file: String,
    pub line: usize,
    pub column: usize,
} 