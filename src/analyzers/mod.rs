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


pub use missing_owner::*;
pub use reentrancy::ReentrancyAnalyzer;
pub use unauthorized_access::UnauthorizedAccessAnalyzer;
pub use integer_overflow::IntegerOverflowAnalyzer;
pub use closing_accounts::ClosingAccounts;
pub use bump_seed_canonicalization::MissingBumpSeedCanonicalization;
pub use duplicate_mutable_accounts::DuplicateMutableAccounts;
pub use arbitrary_cpi::ArbitraryCpi;
pub use account_initialization::AccountInitialization;
pub use account_data_matching::AccountDataMatching;
pub use invalid_sysvar_accounts::InvalidSysvarAccounts;

// Common traits and types for analyzers
use crate::models::*;
use anyhow::Result;

pub trait Analyzer {
    fn analyze(&self, program: &Program) -> Result<Vec<Finding>>;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
}

#[derive(Debug)]
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
pub struct Location {
    pub file: String,
    pub line: usize,
    pub column: usize,
} 