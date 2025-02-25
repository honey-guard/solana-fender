use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, Expr, ExprCall, ExprMethodCall, ExprPath, spanned::Spanned, ItemFn, ItemStruct};
use quote::ToTokens;

pub struct ArbitraryCpi;

impl Analyzer for ArbitraryCpi {
    fn name(&self) -> &'static str {
        "Arbitrary CPI"
    }

    fn description(&self) -> &'static str {
        "Cross-Program Invocations (CPIs) to arbitrary programs can lead to security vulnerabilities \
         if not properly validated. When a program implements a CPI, it should validate that the target \
         program ID matches the expected program ID to prevent calling arbitrary programs."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (path, ast) in &program.asts {
            let mut visitor = ArbitraryCpiVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                in_function: None,
                has_program_id_check: false,
                uses_anchor_program_type: false,
                current_struct_name: None,
            };
            syn::visit::visit_file(&mut visitor, ast);
        }
        
        Ok(findings)
    }
}

struct ArbitraryCpiVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    in_function: Option<String>,
    has_program_id_check: bool,
    uses_anchor_program_type: bool,
    current_struct_name: Option<String>,
}

impl<'a, 'ast> Visit<'ast> for ArbitraryCpiVisitor<'a> {
    fn visit_item_struct(&mut self, item_struct: &'ast ItemStruct) {
        let old_struct_name = self.current_struct_name.clone();
        self.current_struct_name = Some(item_struct.ident.to_string());
        
        // Check if the struct uses Anchor's Program type for token_program
        for field in &item_struct.fields {
            if let Some(ident) = &field.ident {
                if ident.to_string().contains("program") || ident.to_string().contains("token_program") {
                    let field_type = field.ty.to_token_stream().to_string();
                    if field_type.contains("Program<") {
                        self.uses_anchor_program_type = true;
                    }
                }
            }
        }
        
        // Visit the struct fields
        syn::visit::visit_item_struct(&mut *self, item_struct);
        
        // Restore previous state
        self.current_struct_name = old_struct_name;
    }

    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Save the current function name
        let func_name = func.sig.ident.to_string();
        let old_function = self.in_function.clone();
        let old_has_check = self.has_program_id_check;
        
        self.in_function = Some(func_name);
        self.has_program_id_check = false;
        
        // Visit the function body
        syn::visit::visit_block(&mut *self, &func.block);
        
        // Restore previous state
        self.in_function = old_function;
        self.has_program_id_check = old_has_check;
    }

    fn visit_expr_call(&mut self, expr: &'ast ExprCall) {
        // Check for invoke or invoke_signed calls
        if let Expr::Path(ExprPath { path, .. }) = &*expr.func {
            let path_str = path.segments.iter()
                .map(|seg| seg.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            
            if path_str.contains("invoke") || path_str.contains("invoke_signed") {
                if !self.has_program_id_check && !self.uses_anchor_program_type {
                    let span = expr.func.span();
                    self.findings.push(Finding {
                        severity: Severity::Medium,
                        certainty: Certainty::Medium,
                        message: format!("Potential arbitrary CPI detected without program ID validation. \
                                         Programs should validate the target program ID before making CPIs."),
                        location: Location {
                            file: self.file_path.clone(),
                            line: span.start().line,
                            column: span.start().column,
                        },
                    });
                }
            }
        }
        
        // Continue visiting the expression
        syn::visit::visit_expr_call(&mut *self, expr);
    }
    
    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        // Check for invoke or invoke_signed method calls
        let method_name = expr.method.to_string();
        
        // Check for CPI methods
        if method_name == "invoke" || method_name == "invoke_signed" {
            if !self.has_program_id_check && !self.uses_anchor_program_type {
                let span = expr.method.span();
                self.findings.push(Finding {
                    severity: Severity::Medium,
                    certainty: Certainty::Medium,
                    message: format!("Potential arbitrary CPI detected without program ID validation. \
                                     Programs should validate the target program ID before making CPIs."),
                    location: Location {
                        file: self.file_path.clone(),
                        line: span.start().line,
                        column: span.start().column,
                    },
                });
            }
        }
        
        // Check for Anchor's CPI methods which are safe by default
        if method_name == "transfer" || method_name == "transfer_ctx" || 
           method_name == "mint_to" || method_name == "burn" {
            // These are typically safe Anchor CPI methods
            self.has_program_id_check = true;
        }
        
        // Continue visiting the expression
        syn::visit::visit_expr_method_call(&mut *self, expr);
    }
    
    fn visit_expr(&mut self, expr: &'ast Expr) {
        // Look for program ID checks
        match expr {
            Expr::Binary(binary) => {
                let expr_str = binary.to_token_stream().to_string();
                // Check for common program ID validation patterns
                if (expr_str.contains("==") || expr_str.contains("!=")) && 
                   (expr_str.contains("program_id") || expr_str.contains("key") || 
                    expr_str.contains("ID") || expr_str.contains("id") ||
                    expr_str.contains("token_program")) {
                    self.has_program_id_check = true;
                }
            },
            Expr::MethodCall(method_call) => {
                let method_name = method_call.method.to_string();
                // Check for Anchor's Program type or other validation methods
                if method_name == "to_account_info" || 
                   method_name == "key" || 
                   method_name == "validate_program" ||
                   method_name == "to_account_metas" {
                    self.has_program_id_check = true;
                }
            },
            Expr::If(expr_if) => {
                // Check if condition contains program ID validation
                let condition_str = expr_if.cond.to_token_stream().to_string();
                if (condition_str.contains("==") || condition_str.contains("!=")) && 
                   (condition_str.contains("program_id") || condition_str.contains("key") || 
                    condition_str.contains("ID") || condition_str.contains("id") ||
                    condition_str.contains("token_program")) {
                    self.has_program_id_check = true;
                }
            },
            _ => {}
        }
        
        // Continue visiting the expression
        syn::visit::visit_expr(&mut *self, expr);
    }
} 