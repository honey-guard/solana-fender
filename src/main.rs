mod analyzers;
mod models;

use anyhow::Result;
use clap::{Parser, ArgAction};
use std::path::PathBuf;
use solana_fender::{Severity, analyze_program_dir, analyze_program_file, findings_to_markdown};
use std::collections::HashMap;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
/// Static security analyzer for Solana programs
/// 
/// This tool scans Solana programs for common security vulnerabilities.
/// It automatically ignores /target directories during scanning.
struct Args {
    /// Path to the Solana program directory to analyze
    #[arg(short, long, group = "target")]
    program: Option<PathBuf>,

    /// Path to a single Solana program file to analyze
    #[arg(short, long, group = "target")]
    file: Option<PathBuf>,

    /// Ignore findings with Low severity
    #[arg(long, action = ArgAction::SetTrue)]
    ignore_low: bool,

    /// Ignore findings with Medium severity
    #[arg(long, action = ArgAction::SetTrue)]
    ignore_medium: bool,

    /// Ignore findings with High severity
    #[arg(long, action = ArgAction::SetTrue)]
    ignore_high: bool,

    /// Ignore findings with Critical severity
    #[arg(long, action = ArgAction::SetTrue)]
    ignore_critical: bool,
    
    /// Show detailed debug output
    #[arg(long, action = ArgAction::SetTrue)]
    debug: bool,

    /// Output results in markdown format
    #[arg(long, action = ArgAction::SetTrue)]
    markdown: bool,

    /// Path to save markdown output (if not specified, prints to stdout)
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Set the debug mode for the library
    std::env::set_var("SOLANA_FENDER_DEBUG", args.debug.to_string());
    
    // Set a new environment variable to control output suppression when using markdown
    std::env::set_var("SOLANA_FENDER_SUPPRESS_OUTPUT", args.markdown.to_string());
    
    // Ensure either program or file is provided
    if args.program.is_none() && args.file.is_none() {
        eprintln!("Error: Either --program or --file must be specified");
        std::process::exit(1);
    }
    
    // Use the library function to analyze the program or file
    let mut findings = if let Some(program_path) = args.program.as_ref() {
        analyze_program_dir(program_path.clone())?
    } else if let Some(file_path) = args.file.as_ref() {
        analyze_program_file(file_path.clone())?
    } else {
        unreachable!("Either program or file must be provided due to clap group constraint");
    };
    
    // Filter findings based on severity ignore flags
    findings.retain(|finding| {
        match finding.severity {
            Severity::Low => !args.ignore_low,
            Severity::Medium => !args.ignore_medium,
            Severity::High => !args.ignore_high,
            Severity::Critical => !args.ignore_critical,
        }
    });

    // Handle markdown output if requested
    if args.markdown {
        // Get the program name from the path
        let program_name = if let Some(program_path) = args.program.as_ref() {
            program_path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("solana_program")
        } else if let Some(file_path) = args.file.as_ref() {
            file_path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("solana_file")
        } else {
            "solana_program"
        };

        // Use the library function to convert findings to markdown
        let markdown_output = findings_to_markdown(
            findings.clone(),
            program_name,
            args.output.as_deref(),
        )?;
        
        // If no output file is specified, print to stdout
        if args.output.is_none() {
            println!("{}", markdown_output);
        }
    }
    
    // Return success if no findings, otherwise exit with error code
    if findings.is_empty() {
        Ok(())
    } else {
        // Only print a summary message if not in markdown mode
        if !args.markdown {
            println!("\nFound {} security issues in the program", findings.len());
        }
        std::process::exit(1);
    }
}
