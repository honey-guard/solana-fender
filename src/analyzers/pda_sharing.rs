use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ExprMethodCall, spanned::Spanned, Attribute, ItemFn, ExprArray};
use quote::ToTokens;

pub struct PdaSharing;

impl Analyzer for PdaSharing {
    fn name(&self) -> &'static str {
        "PDA Sharing"
    }

    fn description(&self) -> &'static str {
        "Reuse of a PDA across multiple authority domains can lead to unauthorized data or funds access. \
         PDAs should include sufficient unique identifiers in their seeds."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (path, ast) in &program.asts {
            let mut visitor = PdaSharingVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                current_pda_seeds: Vec::new(),
                current_array: None,
            };
            syn::visit::visit_file(&mut visitor, ast);
        }
        
        Ok(findings)
    }
}

struct PdaSharingVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    current_pda_seeds: Vec<String>,
    current_array: Option<Vec<String>>,
}

impl<'a, 'ast> Visit<'ast> for PdaSharingVisitor<'a> {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        // Track PDA seed definitions in attributes
        if attr.path().is_ident("seeds") {
            if let Ok(expr) = attr.parse_args::<syn::Expr>() {
                if let syn::Expr::Array(array) = expr {
                    self.analyze_seed_array(&array);
                }
            }
        }
    }

    fn visit_expr_array(&mut self, array: &'ast ExprArray) {
        // Track array expressions that might be used as seeds
        let seeds: Vec<String> = array.elems.iter()
            .filter_map(|e| Some(e.to_token_stream().to_string()))
            .collect();
        self.current_array = Some(seeds);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        // Check for with_signer calls
        if expr.method.to_string() == "with_signer" {
            // If we have a current array, analyze it
            if let Some(seeds) = &self.current_array {
                let has_insufficient_seeds = seeds.iter().all(|seed| {
                    let seed_lower = seed.to_lowercase();
                    seed_lower.contains("mint") || 
                    seed_lower.contains("bump") || 
                    seed_lower.contains("&[") // For bump arrays
                });

                if has_insufficient_seeds {
                    let span = expr.method.span();
                    self.findings.push(Finding {
                        severity: Severity::High,
                        certainty: Certainty::High,
                        message: "PDA seeds used for signing are insufficient for unique authority. Seeds only contain mint and bump, allowing potential unauthorized access.".to_string(),
                        location: Location {
                            file: self.file_path.clone(),
                            line: span.start().line,
                            column: span.start().column,
                        },
                    });
                }
            }
        }
        
        // Clear current array after checking
        self.current_array = None;
        
        // Visit the receiver and arguments
        syn::visit::visit_expr(&mut *self, &expr.receiver);
        for arg in &expr.args {
            syn::visit::visit_expr(&mut *self, arg);
        }
    }

    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Clear state when entering a new function
        self.current_pda_seeds.clear();
        self.current_array = None;
        
        // Visit the function body
        syn::visit::visit_item_fn(self, func);
    }
}

impl<'a> PdaSharingVisitor<'a> {
    fn analyze_seed_array(&mut self, array: &ExprArray) {
        self.current_pda_seeds = array.elems.iter()
            .filter_map(|e| Some(e.to_token_stream().to_string()))
            .collect();
            
        let has_insufficient_seeds = self.current_pda_seeds.iter().all(|seed| {
            let seed_lower = seed.to_lowercase();
            seed_lower.contains("mint") || 
            seed_lower.contains("bump") || 
            seed_lower.contains("&[")
        });

        if has_insufficient_seeds {
            let span = array.span();
            self.findings.push(Finding {
                severity: Severity::High,
                certainty: Certainty::High,
                message: "PDA seeds are insufficient for unique authority. Seeds only contain mint and bump, allowing potential unauthorized access.".to_string(),
                location: Location {
                    file: self.file_path.clone(),
                    line: span.start().line,
                    column: span.start().column,
                },
            });
        }
    }
} 