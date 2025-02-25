use std::path::PathBuf;
use syn::File;
use std::collections::HashMap;
use anyhow::Result;
use walkdir::WalkDir;

#[derive(Debug)]
pub struct Program {
    pub asts: HashMap<PathBuf, File>,
    pub root_path: std::path::PathBuf,
}

impl Program {
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
}

// Helper function to find all Rust files in a directory
fn find_rust_files(path: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut rust_files = Vec::new();
    
    for entry in WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok()) {
            if entry.path().extension().map_or(false, |ext| ext == "rs") {
                rust_files.push(entry.path().to_path_buf());
            }
        }
    
    Ok(rust_files)
} 