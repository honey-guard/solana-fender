mod analyzers;
mod models;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Path to the Solana program directory to analyze
    #[arg(short, long)]
    program: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Use the library function to analyze the program
    let findings = solana_fender::analyze_program_dir(args.program)?;
    
    // Return success if no findings, otherwise exit with error code
    if findings.is_empty() {
        Ok(())
    } else {
        // We've already printed the findings in the analyze function
        std::process::exit(1);
    }
}
