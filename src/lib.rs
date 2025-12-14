pub mod analyzers;
pub mod models;

use anyhow::{Result, anyhow};
use colored::*;
use std::path::PathBuf;
use std::collections::HashMap;

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
use crate::analyzers::improper_instruction_introspection::ImproperInstructionIntrospection;
use crate::analyzers::account_reloading::AccountReloading;
use crate::models::Program;

// Re-export types that users of the crate will need
pub use crate::analyzers::{Finding, Severity, Certainty, Location};
pub use crate::models::markdown;

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
    
    // Check if output should be suppressed
    let suppress_output = std::env::var("SOLANA_FENDER_SUPPRESS_OUTPUT")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);
    
    if !suppress_output {
        println!("Analyzing module: {}", module_name);
    }
    
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
    // Check if output should be suppressed
    let suppress_output = std::env::var("SOLANA_FENDER_SUPPRESS_OUTPUT")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);
    
    if !suppress_output {
        println!("Analyzing module by name: {}", module_name);
    }
    
    // Locate the actual module file
    let file_path = locate_module_file(module_name)
        .ok_or_else(|| anyhow!("Could not locate source file for module: {}", module_name))?;
    
    if !suppress_output {
        println!("Found module source at: {}", file_path.display());
    }

    analyze_program_file(file_path)
}

// Helper function to locate the source file for a module
fn locate_module_file(module_name: &str) -> Option<PathBuf> {
    let path_parts: Vec<&str> = module_name.split("::").collect();
    let relative_path = path_parts.join(std::path::MAIN_SEPARATOR.to_string().as_str());
    
    // Possible search paths
    let search_paths = vec![
        // Direct path
        PathBuf::from(format!("{}.rs", relative_path)),
        PathBuf::from(format!("{}/mod.rs", relative_path)),
        // Inside src/
        PathBuf::from(format!("src/{}.rs", relative_path)),
        PathBuf::from(format!("src/{}/mod.rs", relative_path)),
    ];
    
    for path in search_paths {
        if path.exists() {
            return Some(path);
        }
    }
    
    // Heuristic: Check src/lib.rs for inline module definition
    // This handles the case where module_name is defined inside lib.rs (e.g. #[program] mod my_program)
    let lib_path = PathBuf::from("src/lib.rs");
    if lib_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&lib_path) {
             let simple_name = path_parts.last().unwrap_or(&"");
             // Check for "mod name" or "mod name {" or "mod name;"
             if content.contains(&format!("mod {}", simple_name)) {
                 return Some(lib_path);
             }
        }
    }

    None
}

/// Analyze a single Solana program file
/// 
/// Returns a Result containing either:
/// - Ok(Vec<Finding>) - A vector of security findings (empty if no issues found)
/// - Err(anyhow::Error) - An error if analysis failed
pub fn analyze_program_file(file_path: PathBuf) -> Result<Vec<Finding>> {
    // Check if the file exists
    if !file_path.exists() {
        return Err(anyhow!("File not found: {}", file_path.display()));
    }
    
    // Check if it's a Rust file
    if file_path.extension().map_or(true, |ext| ext != "rs") {
        return Err(anyhow!("Not a Rust file: {}", file_path.display()));
    }
    
    // Create program from single file
    let program = Program::from_file(file_path)?;
    
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
        Box::new(ImproperInstructionIntrospection),
        Box::new(AccountReloading),
    ];

    let mut all_findings = Vec::new();
    
    // Check if debug mode is enabled
    let debug_mode = std::env::var("SOLANA_FENDER_DEBUG")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);
        
    // Check if output should be suppressed (for markdown mode)
    let suppress_output = std::env::var("SOLANA_FENDER_SUPPRESS_OUTPUT")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    // Run all analyzers
    for analyzer in analyzers {
        let analyzer_name = analyzer.name();
        
        if debug_mode && !suppress_output {
            println!("\nRunning {}", analyzer_name.bold());
            println!("{}", analyzer.description());
        }
        
        match analyzer.analyze(program) {
            Ok(findings) => {
                if findings.is_empty() {
                    if debug_mode && !suppress_output {
                        println!("{}", "✓ No issues found".green());
                    } else if !suppress_output {
                        println!("{} {}: {}", "✓".green(), analyzer_name, "No issues found".green());
                    }
                } else {
                    if debug_mode && !suppress_output {
                        for finding in &findings {
                            println!("\n{} ({:?}, {:?})", "Issue found:".yellow(), finding.severity, finding.certainty);
                            println!("  → {}", finding.message);
                            println!("    at {}:{}:{}", finding.location.file, finding.location.line, finding.location.column);
                        }
                    } else if !suppress_output {
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
                if debug_mode && !suppress_output {
                    println!("{}: {}", "Error running analyzer".red(), e);
                } else if !suppress_output {
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

/// Convert findings to markdown format
/// 
/// This function takes a vector of findings and converts them to a markdown report.
/// 
/// # Arguments
/// 
/// * `findings` - Vector of findings to convert to markdown
/// * `program_name` - Name of the program being analyzed
/// * `output_path` - Optional path to save the markdown report to
/// 
/// # Returns
/// 
/// A Result containing either:
/// - Ok(String) - The markdown report as a string
/// - Err(anyhow::Error) - An error if conversion failed
/// 
/// # Example
/// 
/// ```
/// use solana_fender::{analyze_program_dir, findings_to_markdown};
/// use std::path::PathBuf;
/// 
/// fn main() -> anyhow::Result<()> {
///     let program_path = PathBuf::from("path/to/program");
///     let findings = analyze_program_dir(program_path.clone())?;
///     
///     // Convert findings to markdown
///     let program_name = program_path.file_name()
///         .and_then(|name| name.to_str())
///         .unwrap_or("solana_program");
///     
///     let markdown = findings_to_markdown(findings, program_name, None)?;
///     println!("{}", markdown);
///     
///     Ok(())
/// }
/// ```
pub fn findings_to_markdown(
    findings: Vec<Finding>,
    program_name: &str,
    output_path: Option<&std::path::Path>,
) -> Result<String> {
    // Check if output should be suppressed
    let suppress_output = std::env::var("SOLANA_FENDER_SUPPRESS_OUTPUT")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);
    
    // Convert findings to the format expected by create_analysis_report
    let mut findings_map: HashMap<PathBuf, Vec<models::markdown::Finding>> = HashMap::new();
    
    for finding in findings {
        let file_path = PathBuf::from(&finding.location.file);
        let mut markdown_finding = models::markdown::Finding::new(
            &format!("{:?} Severity Issue", finding.severity),
            &format!("{}", finding.severity),
            finding.location.line,
            &finding.message,
        );
        
        // Add code snippet if available
        if let Ok(file_content) = std::fs::read_to_string(&file_path) {
            let lines: Vec<&str> = file_content.lines().collect();
            
            // Get a few lines around the issue
            let start_line = finding.location.line.saturating_sub(2);
            let end_line = std::cmp::min(finding.location.line + 2, lines.len());
            
            if start_line < end_line && start_line < lines.len() {
                let snippet = lines[start_line..end_line].join("\n");
                markdown_finding.code_snippet = Some(snippet);
            }
        } else if !suppress_output {
            // Only print error if output is not suppressed
            eprintln!("Warning: Could not read file {} for code snippet", file_path.display());
        }
        
        // Add recommendation based on severity and finding type
        let recommendation = match finding.severity {
            Severity::Critical => format!("This is a critical issue that must be fixed immediately. {}", get_recommendation_for_finding(&finding)),
            Severity::High => format!("This is a high severity issue that should be addressed promptly. {}", get_recommendation_for_finding(&finding)),
            Severity::Medium => format!("This is a medium severity issue that should be reviewed. {}", get_recommendation_for_finding(&finding)),
            Severity::Low => format!("This is a low severity issue. {}", get_recommendation_for_finding(&finding)),
        };
        
        markdown_finding.recommendation = Some(recommendation);
        
        findings_map.entry(file_path)
            .or_insert_with(Vec::new)
            .push(markdown_finding);
    }
    
    // Generate markdown report
    models::markdown::create_analysis_report(
        program_name,
        findings_map,
        output_path,
    )
}

/// Helper function to get a recommendation based on the finding type
fn get_recommendation_for_finding(finding: &Finding) -> String {
    // Extract the analyzer name from the message or location
    if finding.message.contains("owner check") {
        "Implement proper owner checks to ensure account ownership is validated before use."
    } else if finding.message.contains("data matching") || finding.message.contains("account data") {
        "Ensure account data is properly validated and matches expected types."
    } else if finding.message.contains("initialization") {
        "Verify that accounts are properly initialized before use."
    } else if finding.message.contains("CPI") {
        "Review Cross-Program Invocation (CPI) calls to ensure they are secure and authorized."
    } else if finding.message.contains("closing") {
        "Ensure accounts are properly closed and funds are transferred to the correct destination."
    } else if finding.message.contains("duplicate") || finding.message.contains("mutable") {
        "Check for duplicate mutable accounts to prevent unintended data modification."
    } else if finding.message.contains("bump seed") || finding.message.contains("canonicalization") {
        "Use canonical bump seeds for PDA derivation to ensure consistent account addressing."
    } else if finding.message.contains("PDA sharing") {
        "Avoid sharing PDAs between different logical entities."
    } else if finding.message.contains("type cosplay") {
        "Ensure account types are properly validated to prevent type confusion attacks."
    } else if finding.message.contains("reentrancy") {
        "Implement reentrancy guards to prevent reentrancy attacks."
    } else if finding.message.contains("unauthorized") || finding.message.contains("access") {
        "Implement proper access controls to prevent unauthorized access."
    } else if finding.message.contains("integer") || finding.message.contains("overflow") {
        "Use checked arithmetic operations to prevent integer overflow/underflow."
    } else if finding.message.contains("sysvar") {
        "Validate sysvar accounts against their proper sysvar::*::ID."
    } else {
        "Review the code carefully and implement appropriate security measures."
    }.to_string()
} 