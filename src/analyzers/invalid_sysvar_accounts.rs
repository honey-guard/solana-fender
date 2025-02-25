use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ExprCall, Expr, ItemStruct, Type, ImplItemFn, spanned::Spanned};
use std::collections::HashSet;

pub struct InvalidSysvarAccounts;

impl Analyzer for InvalidSysvarAccounts {
    fn name(&self) -> &'static str {
        "Invalid Sysvar Accounts"
    }

    fn description(&self) -> &'static str {
        "Sysvar accounts should be validated against their proper sysvar::*::ID"
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (path, ast) in &program.asts {
            let mut visitor = SysvarAccountsVisitor {
                sysvar_accounts: HashSet::new(),
                validated_accounts: HashSet::new(),
                used_accounts: HashSet::new(),
                current_file: path.to_string_lossy().to_string(),
                findings: &mut findings,
                in_function: false,
            };
            syn::visit::visit_file(&mut visitor, ast);
        }
        
        Ok(findings)
    }
}

struct SysvarAccountsVisitor<'a> {
    sysvar_accounts: HashSet<String>,
    validated_accounts: HashSet<String>,
    used_accounts: HashSet<String>,
    current_file: String,
    findings: &'a mut Vec<Finding>,
    in_function: bool,
}

impl<'a, 'ast> Visit<'ast> for SysvarAccountsVisitor<'a> {
    fn visit_item_struct(&mut self, item_struct: &'ast ItemStruct) {
        // Look for account structures
        for field in &item_struct.fields {
            if let Type::Path(type_path) = &field.ty {
                let type_name = type_path.path.segments.last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                
                // Check for AccountInfo fields that might be sysvars
                if type_name == "AccountInfo" {
                    if let Some(ident) = &field.ident {
                        let field_name = ident.to_string();
                        if field_name.contains("rent") || 
                           field_name.contains("clock") || 
                           field_name.contains("epoch") || 
                           field_name.contains("instructions") {
                            self.sysvar_accounts.insert(field_name);
                        }
                    }
                }
            }
        }
    }

    fn visit_expr_call(&mut self, expr: &'ast ExprCall) {
        if let Expr::Path(expr_path) = &*expr.func {
            if let Some(last_seg) = expr_path.path.segments.last() {
                // Check for require_eq! or require! macros
                if last_seg.ident == "require_eq" || last_seg.ident == "require" {
                    // Look for validation against sysvar::*::ID
                    if expr.args.len() >= 2 {
                        let mut validated_account = None;
                        let mut has_sysvar_id = false;

                        // Check first argument for account.key()
                        if let Some(first_arg) = expr.args.first() {
                            if let Expr::MethodCall(method_call) = first_arg {
                                if method_call.method == "key" {
                                    if let Expr::Field(field_expr) = &*method_call.receiver {
                                        if let Expr::Path(path) = &*field_expr.base {
                                            validated_account = path.path.segments.last()
                                                .map(|s| s.ident.to_string());
                                        }
                                    }
                                }
                            }
                        }

                        // Check second argument for sysvar::*::ID
                        if let Some(second_arg) = expr.args.get(1) {
                            if let Expr::Path(path) = second_arg {
                                let path_str = path.path.segments.iter()
                                    .map(|seg| seg.ident.to_string())
                                    .collect::<Vec<_>>()
                                    .join("::");
                                has_sysvar_id = path_str.contains("sysvar") && path_str.ends_with("ID");
                            }
                        }

                        // If we found both a validated account and a sysvar ID, mark it as validated
                        if let Some(account_name) = validated_account {
                            if has_sysvar_id {
                                self.validated_accounts.insert(account_name);
                            }
                        }
                    }
                }
                // Track any usage of sysvar accounts in function calls (like msg!)
                else {
                    for arg in &expr.args {
                        self.visit_expr(arg);
                    }
                }
            }
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        // Track any usage of sysvar accounts
        match expr {
            Expr::Field(field_expr) => {
                if let Expr::Path(path) = &*field_expr.base {
                    let account_name = path.path.segments.last()
                        .map(|s| s.ident.to_string())
                        .unwrap_or_default();
                    if self.sysvar_accounts.contains(&account_name) {
                        self.used_accounts.insert(account_name);
                    }
                }
            }
            _ => syn::visit::visit_expr(self, expr),
        }
    }

    fn visit_impl_item_fn(&mut self, f: &'ast ImplItemFn) {
        self.in_function = true;
        self.used_accounts.clear();
        self.validated_accounts.clear();
        
        // Visit the function body
        syn::visit::visit_impl_item_fn(self, f);
        
        // After visiting the function, check for unvalidated sysvar accounts
        for account in &self.used_accounts {
            if !self.validated_accounts.contains(account) {
                self.findings.push(Finding {
                    severity: Severity::High,
                    certainty: Certainty::High,
                    message: format!("Sysvar account '{}' is used without validation against its proper sysvar::*::ID", account),
                    location: Location {
                        file: self.current_file.clone(),
                        line: f.sig.span().start().line,
                        column: f.sig.span().start().column,
                    },
                });
            }
        }
        
        self.in_function = false;
    }
} 