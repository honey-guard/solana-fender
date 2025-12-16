use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, Expr, ExprCall, ExprMethodCall, ExprPath, ExprStruct, spanned::Spanned, ItemFn};
use quote::ToTokens;
use std::collections::HashSet;

pub struct AccountReloading;

impl Analyzer for AccountReloading {
    fn name(&self) -> &'static str {
        "Account Reloading"
    }

    fn description(&self) -> &'static str {
        "Accounts modified within a Cross-Program Invocation (CPI) are not automatically updated \
         in the caller's context. If the program continues to use the account data after the CPI, \
         it must explicitly reload the account to avoid using stale data."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (path, ast) in &program.asts {
            let mut visitor = AccountReloadingVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                stale_accounts: HashSet::new(),
            };
            syn::visit::visit_file(&mut visitor, ast);
        }

        Ok(findings)
    }
}

struct AccountReloadingVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    // Stores the string representation of accounts that are potentially stale (e.g., "ctx.accounts.vault")
    stale_accounts: HashSet<String>,
}

impl<'a, 'ast> Visit<'ast> for AccountReloadingVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Reset state for each function
        let old_stale_accounts = self.stale_accounts.clone();
        self.stale_accounts.clear();

        // Visit the function body
        syn::visit::visit_block(self, &func.block);

        // Restore state (though typically functions are top-level so this doesn't matter much)
        self.stale_accounts = old_stale_accounts;
    }

    fn visit_expr_call(&mut self, expr: &'ast ExprCall) {
        // Check for CpiContext::new or CpiContext::new_with_signer
        if let Expr::Path(ExprPath { path, .. }) = &*expr.func {
            let path_str = path.to_token_stream().to_string().replace(" ", "");
            if path_str.contains("CpiContext::new") {
                // The second argument is the accounts struct
                if let Some(accounts_arg) = expr.args.iter().nth(1) {
                    self.extract_accounts_from_cpi(accounts_arg);
                }
            }
        }

        // Continue visiting nested expressions
        syn::visit::visit_expr_call(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        let method_name = expr.method.to_string();

        // Check for reload() calls
        if method_name == "reload" {
            let receiver_str = self.get_normalized_expr_string(&expr.receiver);
            self.stale_accounts.remove(&receiver_str);
        } else if method_name == "to_account_info" {
            // Ignore to_account_info() calls as they are often used to pass accounts around
            // We handle them in extract_accounts_from_cpi
        } else {
            // Check if the receiver is a stale account being used
            let receiver_str = self.get_normalized_expr_string(&expr.receiver);
            if self.stale_accounts.contains(&receiver_str) {
                // Found usage of stale account
                self.report_finding(expr.span());
            }
        }

        // Continue visiting
        syn::visit::visit_expr_method_call(self, expr);
    }

    fn visit_expr_path(&mut self, _expr: &'ast ExprPath) {
        // Check if a stale account is being accessed directly (e.g. reading a field)
        // This is tricky because `ctx.accounts.vault.data` is an ExprField, not just ExprPath
        // But the base might be visited.
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        // We need to catch field access like `ctx.accounts.vault.data`
        match expr {
            Expr::Field(field_expr) => {
                let base_str = self.get_normalized_expr_string(&field_expr.base);
                if self.stale_accounts.contains(&base_str) {
                     // Found usage of stale account
                     self.report_finding(expr.span());
                }
            },
            _ => {}
        }

        // Default traversal
        syn::visit::visit_expr(self, expr);
    }
}

impl<'a> AccountReloadingVisitor<'a> {
    fn extract_accounts_from_cpi(&mut self, expr: &Expr) {
        // We expect a struct literal here
        if let Expr::Struct(ExprStruct { fields, .. }) = expr {
            for field in fields {
                // The value of the field is the account being passed
                let val = &field.expr;
                let val_str = self.get_normalized_expr_string(val);

                // If the value is like `ctx.accounts.vault.to_account_info()`, we want `ctx.accounts.vault`
                // If it's just `ctx.accounts.vault`, we use that.

                if val_str.ends_with(".to_account_info()") {
                    let account_path = val_str.trim_end_matches(".to_account_info()");
                    if !account_path.is_empty() {
                        self.stale_accounts.insert(account_path.to_string());
                    }
                } else if val_str.ends_with(".clone()") {
                     let account_path = val_str.trim_end_matches(".clone()");
                     if !account_path.is_empty() {
                        self.stale_accounts.insert(account_path.to_string());
                     }
                } else {
                    // Just the variable name
                     if !val_str.is_empty() {
                        self.stale_accounts.insert(val_str);
                     }
                }
            }
        }
    }

    fn get_normalized_expr_string(&self, expr: &Expr) -> String {
        expr.to_token_stream().to_string().replace(" ", "")
    }

    fn report_finding(&mut self, span: proc_macro2::Span) {
        self.findings.push(Finding {
            severity: Severity::High,
            certainty: Certainty::Medium,
            message: "Account modified in a CPI is used subsequently without reloading. \
                     Call `.reload()?` on the account after the CPI and before using it again.".to_string(),
            location: Location {
                file: self.file_path.clone(),
                line: span.start().line,
                column: span.start().column,
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_account_reloading_vulnerable() {
        let code = r#"
        pub fn update_cpi_noreload(ctx: Context<UpdateCPI>, new_input: u8) -> Result<()> {
            let cpi_context = CpiContext::new(
                ctx.accounts.update_account.to_account_info(),
                update_account::cpi::accounts::Update {
                    authority: ctx.accounts.authority.to_account_info(),
                    metadata: ctx.accounts.metadata.to_account_info(),
                },
            );

            update_account::cpi::update(cpi_context, new_input)?;

            // Vulnerable usage: using metadata after CPI without reload
            let data = ctx.accounts.metadata.data;
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = AccountReloading;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_account_reloading_secure() {
        let code = r#"
        pub fn update_cpi_reload(ctx: Context<UpdateCPI>, new_input: u8) -> Result<()> {
            let cpi_context = CpiContext::new(
                ctx.accounts.update_account.to_account_info(),
                update_account::cpi::accounts::Update {
                    authority: ctx.accounts.authority.to_account_info(),
                    metadata: ctx.accounts.metadata.to_account_info(),
                },
            );

            update_account::cpi::update(cpi_context, new_input)?;

            ctx.accounts.metadata.reload()?;

            // Secure usage: metadata was reloaded
            let data = ctx.accounts.metadata.data;
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = AccountReloading;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_account_reloading_no_usage() {
        let code = r#"
        pub fn update_cpi_no_usage(ctx: Context<UpdateCPI>, new_input: u8) -> Result<()> {
            let cpi_context = CpiContext::new(
                ctx.accounts.update_account.to_account_info(),
                update_account::cpi::accounts::Update {
                    authority: ctx.accounts.authority.to_account_info(),
                    metadata: ctx.accounts.metadata.to_account_info(),
                },
            );

            update_account::cpi::update(cpi_context, new_input)?;

            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = AccountReloading;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
