use std::path::PathBuf;
use syn::File;
use std::collections::HashMap;
use anyhow::Result;
use walkdir::WalkDir;
use quote::quote;
use anyhow::anyhow;

// Export the markdown module
pub mod markdown;

#[derive(Debug)]
pub struct Program {
    pub asts: HashMap<PathBuf, File>,
    pub root_path: std::path::PathBuf,
}

impl Program {
    #[allow(dead_code)]
    pub fn new(path: PathBuf) -> Result<Self> {
        let mut asts = HashMap::new();
        
        // Find all Rust files in the directory
        let rust_files = find_rust_files(&path)?;
        
        // Parse each file
        for file_path in rust_files {
            let content = std::fs::read_to_string(&file_path)?;
            println!("Parsing file: {}", file_path.display());
            //println!("File content: \n{}", content);
            
            match syn::parse_file(&content) {
                Ok(ast) => {
                    let rel_path = file_path.strip_prefix(&path)
                        .unwrap_or(&file_path)
                        .to_path_buf();
                    asts.insert(rel_path, ast);
                }
                Err(e) => {
                    eprintln!("Error parsing {}: {}", file_path.display(), e);
                }
            }
        }
        
        Ok(Program {
            asts,
            root_path: path,
        })
    }

    /// Create a Program from an Anchor program module
    #[allow(dead_code)]
    pub fn from_module<T>(_program_module: T) -> Result<Self> {
        let mut asts = HashMap::new();
        
        // Get the module name
        let module_name = std::any::type_name::<T>();
        
        // Create a synthetic file path for the module
        let file_path = PathBuf::from(format!("{}.rs", module_name));
        
        // For now, we'll create a minimal AST with a placeholder
        // In a real implementation, we would extract the AST from the module
        // using reflection or other techniques
        
        // Create a synthetic module structure
        let module_content = quote! {
            use anchor_lang::prelude::*;
            
            #[program]
            pub mod synthetic_module {
                use super::*;
                
                // Placeholder for actual module content
                // This would be populated with the actual module content in a real implementation
            }
            
            #[derive(Accounts)]
            pub struct Initialize {}
        };
        
        let file = syn::parse2::<File>(module_content)
            .map_err(|e| anyhow!("Failed to parse module: {}", e))?;
        
        asts.insert(file_path.clone(), file);
        
        Ok(Program {
            asts,
            root_path: PathBuf::from("."),
        })
    }

    /// Create a Program from a single Rust file
    pub fn from_file(file_path: PathBuf) -> Result<Self> {
        let mut asts = HashMap::new();
        
        // Read and parse the file
        let content = std::fs::read_to_string(&file_path)?;
        println!("Parsing file: {}", file_path.display());
        
        match syn::parse_file(&content) {
            Ok(ast) => {
                // Get the parent directory as the root path
                let root_path = file_path.parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("."));
                
                // Use the file name as the relative path
                let file_name = file_path.file_name()
                    .map(|n| PathBuf::from(n))
                    .unwrap_or_else(|| PathBuf::from("unknown.rs"));
                
                asts.insert(file_name, ast);
                
                Ok(Program {
                    asts,
                    root_path,
                })
            },
            Err(e) => Err(anyhow!("Error parsing {}: {}", file_path.display(), e)),
        }
    }
}

// Helper function to find all Rust files in a directory
#[allow(dead_code)]
fn find_rust_files(path: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut rust_files = Vec::new();
    
    let debug_mode = std::env::var("SOLANA_FENDER_DEBUG").unwrap_or_default() == "true";
    
    for entry in WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            // Skip target directories
            let is_target = e.path().components().any(|c| c.as_os_str() == "target");
            if is_target && debug_mode {
                println!("Skipping target directory: {}", e.path().display());
            }
            !is_target
        }) {
            if entry.path().extension().map_or(false, |ext| ext == "rs") {
                rust_files.push(entry.path().to_path_buf());
            }
        }
    
    Ok(rust_files)
} 