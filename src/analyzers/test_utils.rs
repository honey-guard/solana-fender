use crate::models::Program;
use std::path::PathBuf;
use std::collections::HashMap;
use syn::parse_file;

pub fn create_program(content: &str) -> Program {
    let ast = parse_file(content).expect("Failed to parse code");
    let mut asts = HashMap::new();
    asts.insert(PathBuf::from("test.rs"), ast);
    Program {
        asts,
        root_path: PathBuf::from("."),
    }
}
