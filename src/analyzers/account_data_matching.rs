use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, Expr, ItemFn, Pat, Local, ExprMethodCall};
use std::collections::HashMap;

/// Analyzer that detects account data unpacking without proper authorization checks
pub struct AccountDataMatching;

impl Analyzer for AccountDataMatching {
    fn name(&self) -> &'static str {
        "Account Data Matching"
    }

    fn description(&self) -> &'static str {
        "Unpacking account structures without verifying authorization might allow an attacker to \
         view or modify account data unintentionally."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (path, ast) in &program.asts {
            let mut visitor = AccountDataMatchingVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                token_vars: HashMap::new(),
                has_owner_check: false,
            };
            syn::visit::visit_file(&mut visitor, ast);
        }
        
        Ok(findings)
    }
}

struct AccountDataMatchingVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    token_vars: HashMap<String, (usize, usize)>, // Variable name -> (line, column)
    has_owner_check: bool,
}

impl<'a, 'ast> Visit<'ast> for AccountDataMatchingVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Reset state for each function
        self.token_vars.clear();
        self.has_owner_check = false;
        
        // Visit the function body
        syn::visit::visit_item_fn(self, func);
        
        // After visiting the function, check if there are any token variables without owner checks
        if !self.token_vars.is_empty() && !self.has_owner_check {
            for (_var_name, (line, column)) in &self.token_vars {
                self.findings.push(Finding {
                    severity: Severity::Low,
                    certainty: Certainty::Low,
                    message: format!("Token account unpacked without verifying the owner matches the authority"),
                    location: Location {
                        file: self.file_path.clone(),
                        line: *line,
                        column: *column,
                    },
                });
            }
        }
    }
    
    fn visit_local(&mut self, local: &'ast Local) {
        // Look for let token = SplTokenAccount::unpack(...) pattern
        if let Pat::Ident(pat_ident) = &local.pat {
            let var_name = pat_ident.ident.to_string();
            
            if let Some(init) = &local.init {
                match &*init.expr {
                    Expr::Call(call) => {
                        // Check for SplTokenAccount::unpack call
                        if let Expr::Path(path) = &*call.func {
                            let path_str = path_to_string(&path.path);
                            if path_str.ends_with("SplTokenAccount::unpack") {
                                let span = path.path.segments.last().unwrap().ident.span();
                                self.token_vars.insert(
                                    var_name,
                                    (span.start().line, span.start().column)
                                );
                            }
                        }
                    },
                    Expr::Try(expr_try) => {
                        // Handle the ? operator case
                        if let Expr::Call(call) = &*expr_try.expr {
                            if let Expr::Path(path) = &*call.func {
                                let path_str = path_to_string(&path.path);
                                if path_str.ends_with("SplTokenAccount::unpack") {
                                    let span = path.path.segments.last().unwrap().ident.span();
                                    self.token_vars.insert(
                                        var_name,
                                        (span.start().line, span.start().column)
                                    );
                                }
                            }
                        }
                    },
                    Expr::MethodCall(method_call) => {
                        // Check for unpack method call
                        if method_call.method.to_string() == "unpack" {
                            self.token_vars.insert(
                                var_name,
                                (method_call.method.span().start().line, method_call.method.span().start().column)
                            );
                        }
                    },
                    _ => {}
                }
            }
        }
        
        // Continue visiting
        syn::visit::visit_local(self, local);
    }
    
    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        // Check for unpack method call
        if expr.method.to_string() == "unpack" {
            // This is a simplified approach - in a real implementation, we would need to
            // track the variable this is assigned to
            let span = expr.method.span();
            self.token_vars.insert(
                "token".to_string(), // Assuming the variable is named "token"
                (span.start().line, span.start().column)
            );
        }
        
        // Continue visiting
        syn::visit::visit_expr_method_call(self, expr);
    }
    
    fn visit_expr_if(&mut self, expr_if: &'ast syn::ExprIf) {
        // Look for owner check patterns
        if let Expr::Binary(binary) = &*expr_if.cond {
            // Check for authority.key != token.owner or similar patterns
            if is_owner_check(&binary.left, &binary.right) {
                self.has_owner_check = true;
            }
        }
        
        // Continue visiting
        syn::visit::visit_expr_if(self, expr_if);
    }
}

// Helper function to convert a Path to a string
fn path_to_string(path: &syn::Path) -> String {
    path.segments.iter()
        .map(|seg| seg.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

// Helper function to check if an expression pair represents an owner check
fn is_owner_check(left: &Expr, right: &Expr) -> bool {
    // Check for patterns like:
    // ctx.accounts.authority.key != &token.owner
    // &token.owner != ctx.accounts.authority.key
    
    let is_authority_key_left = contains_authority_key(left);
    let is_token_owner_left = contains_token_owner(left);
    let is_authority_key_right = contains_authority_key(right);
    let is_token_owner_right = contains_token_owner(right);
    
    (is_authority_key_left && is_token_owner_right) || 
    (is_token_owner_left && is_authority_key_right)
}

// Helper function to check if an expression contains authority.key
fn contains_authority_key(expr: &Expr) -> bool {
    match expr {
        Expr::Field(field) => {
            if let syn::Member::Named(ident) = &field.member {
                if ident.to_string() == "key" {
                    if let Expr::Field(inner_field) = &*field.base {
                        if let syn::Member::Named(inner_ident) = &inner_field.member {
                            return inner_ident.to_string() == "authority" || 
                                   inner_ident.to_string().contains("authority");
                        }
                    }
                }
            }
            false
        }
        Expr::Reference(reference) => contains_authority_key(&reference.expr),
        _ => false,
    }
}

// Helper function to check if an expression contains token.owner
fn contains_token_owner(expr: &Expr) -> bool {
    match expr {
        Expr::Field(field) => {
            if let syn::Member::Named(ident) = &field.member {
                if ident.to_string() == "owner" {
                    if let Expr::Path(path) = &*field.base {
                        let path_str = path_to_string(&path.path);
                        return path_str == "token" || path_str.contains("token");
                    }
                }
            }
            false
        }
        Expr::Reference(reference) => contains_token_owner(&reference.expr),
        _ => false,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_account_data_matching_vulnerable() {
        let code = r#"
        pub fn unpack_without_check(ctx: Context<Initialize>) -> Result<()> {
            let token = SplTokenAccount::unpack(&ctx.accounts.token_account.data.borrow())?;
            // No owner check
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = AccountDataMatching;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Token account unpacked without verifying the owner matches the authority"));
    }

    #[test]
    fn test_account_data_matching_secure() {
        let code = r#"
        pub fn unpack_with_check(ctx: Context<Initialize>) -> Result<()> {
            let token = SplTokenAccount::unpack(&ctx.accounts.token_account.data.borrow())?;
            if ctx.accounts.authority.key != &token.owner {
                return Err(error!(ErrorCode::Unauthorized));
            }
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = AccountDataMatching;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
