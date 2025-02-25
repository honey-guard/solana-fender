use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, Expr, ExprPath, ItemFn, FnArg, Pat, PatType, spanned::Spanned};
use std::collections::HashSet;

pub struct MissingBumpSeedCanonicalization;

impl Analyzer for MissingBumpSeedCanonicalization {
    fn name(&self) -> &'static str {
        "Missing Bump Seed Canonicalization"
    }

    fn description(&self) -> &'static str {
        "PDA derivation should use canonical bump seeds to ensure consistent account addressing."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (path, ast) in &program.asts {
            let mut visitor = BumpSeedVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                current_function: None,
                functions_with_bump_param: HashSet::new(),
                create_program_address_calls: Vec::new(),
                find_program_address_calls: Vec::new(),
            };
            syn::visit::visit_file(&mut visitor, ast);
        }
        
        Ok(findings)
    }
}

struct BumpSeedVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    current_function: Option<String>,
    functions_with_bump_param: HashSet<String>,
    create_program_address_calls: Vec<(usize, usize)>, // (line, column)
    find_program_address_calls: Vec<(usize, usize)>,   // (line, column)
}

impl<'a, 'ast> Visit<'ast> for BumpSeedVisitor<'a> {
    fn visit_item_fn(&mut self, item_fn: &'ast ItemFn) {
        // Store the current function name
        let fn_name = item_fn.sig.ident.to_string();
        self.current_function = Some(fn_name.clone());
        
        // Check if the function has a bump parameter
        let mut has_bump_param = false;
        for input in &item_fn.sig.inputs {
            if let FnArg::Typed(PatType { pat, .. }) = input {
                if let Pat::Ident(pat_ident) = &**pat {
                    if pat_ident.ident == "bump" {
                        has_bump_param = true;
                        self.functions_with_bump_param.insert(fn_name.clone());
                    }
                }
            }
        }
        
        // Clear the call lists for this function
        self.create_program_address_calls.clear();
        self.find_program_address_calls.clear();
        
        // Visit the function body
        syn::visit::visit_item_fn(self, item_fn);
        
        // If the function has a bump parameter, check for create_program_address without find_program_address
        if has_bump_param {
            if !self.create_program_address_calls.is_empty() && self.find_program_address_calls.is_empty() {
                for (line, column) in &self.create_program_address_calls {
                    self.findings.push(Finding {
                        severity: Severity::Medium,
                        certainty: Certainty::Medium,
                        message: "Using create_program_address with a bump parameter without canonical bump validation. Consider using find_program_address to derive the canonical bump.".to_string(),
                        location: Location {
                            file: self.file_path.clone(),
                            line: *line,
                            column: *column,
                        },
                    });
                }
            }
        }
        
        // Reset the current function
        self.current_function = None;
    }
    
    // Visit all expressions to catch any pattern of create_program_address or find_program_address
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            // Check for method calls like Pubkey::create_program_address or Pubkey::find_program_address
            Expr::MethodCall(method_call) => {
                let method_name = method_call.method.to_string();
                
                if method_name == "create_program_address" {
                    if let Expr::Path(ExprPath { path, .. }) = &*method_call.receiver {
                        if path.segments.last().map_or(false, |seg| seg.ident == "Pubkey") {
                            let span = method_call.method.span();
                            self.create_program_address_calls.push((span.start().line, span.start().column));
                            
                            // If we're in a function with a bump parameter, add a finding
                            if self.current_function.as_ref().map_or(false, |fn_name| self.functions_with_bump_param.contains(fn_name)) {
                                self.findings.push(Finding {
                                    severity: Severity::Medium,
                                    certainty: Certainty::Medium,
                                    message: "Using create_program_address with a bump parameter without canonical bump validation. Consider using find_program_address to derive the canonical bump.".to_string(),
                                    location: Location {
                                        file: self.file_path.clone(),
                                        line: span.start().line,
                                        column: span.start().column,
                                    },
                                });
                            }
                        }
                    }
                } else if method_name == "find_program_address" {
                    if let Expr::Path(ExprPath { path, .. }) = &*method_call.receiver {
                        if path.segments.last().map_or(false, |seg| seg.ident == "Pubkey") {
                            let span = method_call.method.span();
                            self.find_program_address_calls.push((span.start().line, span.start().column));
                        }
                    }
                }
            },
            
            // Check for path expressions that might contain "create_program_address" or "find_program_address"
            Expr::Path(path_expr) => {
                let path_str = path_expr.path.segments.iter()
                    .map(|seg| seg.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                
                if path_str.contains("create_program_address") {
                    let span = path_expr.span();
                    self.create_program_address_calls.push((span.start().line, span.start().column));
                } else if path_str.contains("find_program_address") {
                    let span = path_expr.span();
                    self.find_program_address_calls.push((span.start().line, span.start().column));
                }
            },
            
            // Check for call expressions that might be create_program_address or find_program_address
            Expr::Call(call_expr) => {
                if let Expr::Path(path_expr) = &*call_expr.func {
                    let path_str = path_expr.path.segments.iter()
                        .map(|seg| seg.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::");
                    
                    if path_str.contains("create_program_address") {
                        let span = path_expr.span();
                        self.create_program_address_calls.push((span.start().line, span.start().column));
                    } else if path_str.contains("find_program_address") {
                        let span = path_expr.span();
                        self.find_program_address_calls.push((span.start().line, span.start().column));
                    }
                }
            },
            
            _ => {}
        }
        
        // Continue visiting nested expressions
        syn::visit::visit_expr(self, expr);
    }
} 