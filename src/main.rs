mod analyzers;
mod models;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use colored::*;

use crate::analyzers::{
    Analyzer, MissingOwnerCheck, AccountDataMatching,
    AccountInitialization, ArbitraryCpi, ClosingAccounts, DuplicateMutableAccounts,
    MissingBumpSeedCanonicalization, PdaSharing, TypeCosplay, 
    ReentrancyAnalyzer, UnauthorizedAccessAnalyzer, IntegerOverflowAnalyzer, InvalidSysvarAccounts
};
use crate::models::Program;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Path to the Solana program directory to analyze
    #[arg(short, long)]
    program: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Create program from directory
    let program = Program::new(args.program.clone())?;
    
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

    // Run all analyzers
    for analyzer in analyzers {
        println!("\nRunning {}", analyzer.name().bold());
        println!("{}", analyzer.description());
        
        match analyzer.analyze(&program) {
            Ok(findings) => {
                if findings.is_empty() {
                    println!("{}", "✓ No issues found".green());
                } else {
                    for finding in findings {
                        println!("\n{} ({:?}, {:?})", "Issue found:".yellow(), finding.severity, finding.certainty);
                        println!("  → {}", finding.message);
                        println!("    at {}:{}:{}", finding.location.file, finding.location.line, finding.location.column);
                    }
                }
            }
            Err(e) => {
                println!("{}: {}", "Error running analyzer".red(), e);
            }
        }
    }

    Ok(())
}
