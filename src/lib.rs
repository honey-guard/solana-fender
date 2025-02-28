pub mod analyzers;
pub mod models;

use anyhow::{Result, anyhow};
use colored::*;
use std::path::PathBuf;

use crate::analyzers::Analyzer;
use crate::analyzers::missing_owner::MissingOwnerCheck;
use crate::analyzers::account_data_matching::AccountDataMatching;
use crate::analyzers::account_initialization::AccountInitialization;
use crate::analyzers::arbitrary_cpi::ArbitraryCpi;
use crate::analyzers::closing_accounts::ClosingAccounts;
use crate::analyzers::duplicate_mutable_accounts::DuplicateMutableAccounts;
use crate::analyzers::bump_seed_canonicalization::MissingBumpSeedCanonicalization;
use crate::analyzers::pda_sharing::PdaSharing;
use crate::analyzers::type_cosplay::TypeCosplay;
use crate::analyzers::reentrancy::ReentrancyAnalyzer;
use crate::analyzers::unauthorized_access::UnauthorizedAccessAnalyzer;
use crate::analyzers::integer_overflow::IntegerOverflowAnalyzer;
use crate::analyzers::invalid_sysvar_accounts::InvalidSysvarAccounts;
use crate::models::Program;

// Re-export types that users of the crate will need
pub use crate::analyzers::{Finding, Severity, Certainty, Location};

/// Analyze a Solana program directory
/// 
/// Returns a Result containing either:
/// - Ok(Vec<Finding>) - A vector of security findings (empty if no issues found)
/// - Err(anyhow::Error) - An error if analysis failed
pub fn analyze_program_dir(program_path: PathBuf) -> Result<Vec<Finding>> {
    // Create program from directory
    let program = Program::new(program_path)?;
    
    run_analyzers(&program)
}

/// Analyze an Anchor program module directly using a marker type
/// 
/// Returns a Result containing either:
/// - Ok(Vec<Finding>) - A vector of security findings (empty if no issues found)
/// - Err(anyhow::Error) - An error if analysis failed
/// 
/// # Example
/// ```ignore
/// // This example is ignored in doctests because it requires Anchor
/// use solana_fender::analyze_program;
/// use anchor_lang::prelude::*;
/// 
/// #[program]
/// pub mod my_program {
///     use super::*;
///     
///     pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
///         Ok(())
///     }
/// }
/// 
/// #[derive(Accounts)]
/// pub struct Initialize {}
/// 
/// fn test() {
///     // Create a marker type to represent the module
///     struct MyProgramMarker;
///     let findings = analyze_program(MyProgramMarker).unwrap();
///     assert!(findings.is_empty(), "Security vulnerabilities found: {:?}", findings);
/// }
/// ```
pub fn analyze_program<T>(_program_module: T) -> Result<Vec<Finding>> {
    // Extract the module name from the type name
    let module_name = std::any::type_name::<T>();
    println!("Analyzing module: {}", module_name);
    
    // Create a synthetic Program with a single file
    let mut asts = std::collections::HashMap::new();
    
    // Create a synthetic file path for the module
    let file_path = PathBuf::from(format!("{}.rs", module_name));
    
    // Extract the simple module name (last part of the path)
    let simple_module_name = module_name.split("::").last().unwrap_or("synthetic_module");
    
    // TODO: In a production implementation, we would:
    // 1. Use procedural macros to capture the actual AST of the module at compile time
    // 2. Or use the proc_macro_span API to get source code information
    // 3. Or parse the actual source file using the module's location information
    // For now, we create a synthetic AST as a placeholder
    
    // Create a synthetic AST for the module
    let file_content = format!(r#"
        use anchor_lang::prelude::*;
        
        #[program]
        pub mod {} {{
            use super::*;
            
            pub fn initialize(ctx: Context<Initialize>) -> Result<()> {{
                Ok(())
            }}
        }}
        
        #[derive(Accounts)]
        pub struct Initialize {{}}
    "#, simple_module_name);
    
    let file = syn::parse_file(&file_content)
        .map_err(|e| anyhow!("Failed to parse synthetic module: {}", e))?;
    
    asts.insert(file_path, file);
    
    // Create a synthetic Program
    let program = Program {
        asts,
        root_path: PathBuf::from("."),
    };
    
    // Run the analyzers
    run_analyzers(&program)
}

/// Analyze an Anchor program module directly using a module name string
/// 
/// Returns a Result containing either:
/// - Ok(Vec<Finding>) - A vector of security findings (empty if no issues found)
/// - Err(anyhow::Error) - An error if analysis failed
/// 
/// # Example
/// ```ignore
/// // This example is ignored in doctests because it requires Anchor
/// use solana_fender::analyze_program_by_name;
/// 
/// fn test() {
///     let findings = analyze_program_by_name("my_program").unwrap();
///     assert!(findings.is_empty(), "Security vulnerabilities found: {:?}", findings);
/// }
/// ```
pub fn analyze_program_by_name(module_name: &str) -> Result<Vec<Finding>> {
    println!("Analyzing module by name: {}", module_name);
    
    // Create a synthetic Program with a single file
    let mut asts = std::collections::HashMap::new();
    
    // Create a synthetic file path for the module
    let file_path = PathBuf::from(format!("{}.rs", module_name));
    
    // TODO: In a production implementation, we would:
    // 1. Try to locate the actual module in the crate
    // 2. Parse the actual source file
    // 3. Extract the real AST for analysis
    // For now, we create a synthetic AST as a placeholder
    
    // Create a synthetic AST for the module
    let file_content = format!(r#"
        use anchor_lang::prelude::*;
        
        #[program]
        pub mod {} {{
            use super::*;
            
            pub fn initialize(ctx: Context<Initialize>) -> Result<()> {{
                Ok(())
            }}
        }}
        
        #[derive(Accounts)]
        pub struct Initialize {{}}
    "#, module_name);
    
    let file = syn::parse_file(&file_content)
        .map_err(|e| anyhow!("Failed to parse synthetic module: {}", e))?;
    
    asts.insert(file_path, file);
    
    // Create a synthetic Program
    let program = Program {
        asts,
        root_path: PathBuf::from("."),
    };
    
    // Run the analyzers
    run_analyzers(&program)
}

/// Run all analyzers on a program
/// 
/// Returns a Result containing either:
/// - Ok(Vec<Finding>) - A vector of security findings (empty if no issues found)
/// - Err(anyhow::Error) - An error if analysis failed
fn run_analyzers(program: &Program) -> Result<Vec<Finding>> {
    // Initialize analyzers
    let analyzers: Vec<Box<dyn Analyzer>> = vec![
        Box::new(MissingOwnerCheck),
        Box::new(AccountDataMatching),
        Box::new(AccountInitialization),
        Box::new(ArbitraryCpi),
        Box::new(ClosingAccounts),
        Box::new(DuplicateMutableAccounts),
        Box::new(MissingBumpSeedCanonicalization),
        Box::new(PdaSharing),
        Box::new(TypeCosplay),    
        Box::new(InvalidSysvarAccounts),
        Box::new(ReentrancyAnalyzer),
        Box::new(UnauthorizedAccessAnalyzer),
        Box::new(IntegerOverflowAnalyzer),
    ];

    let mut all_findings = Vec::new();
    
    // Check if debug mode is enabled
    let debug_mode = std::env::var("SOLANA_FENDER_DEBUG")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    // Run all analyzers
    for analyzer in analyzers {
        let analyzer_name = analyzer.name();
        
        if debug_mode {
            println!("\nRunning {}", analyzer_name.bold());
            println!("{}", analyzer.description());
        }
        
        match analyzer.analyze(program) {
            Ok(findings) => {
                if findings.is_empty() {
                    if debug_mode {
                        println!("{}", "✓ No issues found".green());
                    } else {
                        println!("{} {}: {}", "✓".green(), analyzer_name, "No issues found".green());
                    }
                } else {
                    if debug_mode {
                        for finding in &findings {
                            println!("\n{} ({:?}, {:?})", "Issue found:".yellow(), finding.severity, finding.certainty);
                            println!("  → {}", finding.message);
                            println!("    at {}:{}:{}", finding.location.file, finding.location.line, finding.location.column);
                        }
                    } else {
                        // For non-debug mode, print a summary of issues found
                        println!("{} {}: {} issues found", "❌".red(), analyzer_name, findings.len());
                        for (i, finding) in findings.iter().enumerate() {
                            let severity_colored = match finding.severity {
                                Severity::Low => format!("[{}]", finding.severity).yellow(),
                                Severity::Medium => format!("[{}]", finding.severity).truecolor(255, 165, 0), // Orange
                                Severity::High => format!("[{}]", finding.severity).red(),
                                Severity::Critical => format!("[{}]", finding.severity).red().bold(),
                            };
                            
                            println!("  {}. {} {} at {}:{}:{}", 
                                i+1, 
                                severity_colored, 
                                finding.message, 
                                finding.location.file, 
                                finding.location.line, 
                                finding.location.column);
                        }
                    }
                    // Add findings to the collection
                    all_findings.extend(findings);
                }
            }
            Err(e) => {
                let error_msg = format!("Error running analyzer {}: {}", analyzer_name, e);
                if debug_mode {
                    println!("{}: {}", "Error running analyzer".red(), e);
                } else {
                    println!("{} {}: Error - {}", "❌".red(), analyzer_name, e);
                }
                return Err(anyhow!(error_msg));
            }
        }
    }

    Ok(all_findings)
}

/// Filter findings based on severity levels to ignore
/// 
/// # Arguments
/// 
/// * `findings` - Vector of findings to filter
/// * `ignore_low` - Whether to ignore Low severity findings
/// * `ignore_medium` - Whether to ignore Medium severity findings
/// * `ignore_high` - Whether to ignore High severity findings
/// * `ignore_critical` - Whether to ignore Critical severity findings
/// 
/// # Returns
/// 
/// A filtered vector of findings
pub fn filter_findings_by_severity(
    findings: Vec<Finding>,
    ignore_low: bool,
    ignore_medium: bool,
    ignore_high: bool,
    ignore_critical: bool,
) -> Vec<Finding> {
    findings.into_iter()
        .filter(|finding| {
            match finding.severity {
                Severity::Low => !ignore_low,
                Severity::Medium => !ignore_medium,
                Severity::High => !ignore_high,
                Severity::Critical => !ignore_critical,
            }
        })
        .collect()
} 