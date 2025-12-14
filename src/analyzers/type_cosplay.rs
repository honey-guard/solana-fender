use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, spanned::Spanned};
use quote::ToTokens;
use std::collections::HashSet;

pub struct TypeCosplay;

impl Analyzer for TypeCosplay {
    fn name(&self) -> &'static str {
        "Type Cosplay"
    }

    fn description(&self) -> &'static str {
        "Account types should be properly validated to prevent type confusion attacks."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (path, ast) in &program.asts {
            let mut visitor = TypeCosplayVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                borsh_structs: HashSet::new(),
                structs_with_discriminant: HashSet::new(),
                structs_with_discriminant_check: HashSet::new(),
                uses_anchor_account: false,
                current_function_has_discriminant_check: false,
            };
            
            // First pass: collect all structs
            visitor.visit_file(ast);
            
            // Second pass: analyze for vulnerabilities
            visitor.analyze_vulnerabilities();
        }
        
        Ok(findings)
    }
}

struct TypeCosplayVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    borsh_structs: HashSet<String>,
    structs_with_discriminant: HashSet<String>,
    structs_with_discriminant_check: HashSet<String>,
    uses_anchor_account: bool,
    current_function_has_discriminant_check: bool,
}

impl<'a> TypeCosplayVisitor<'a> {
    fn analyze_vulnerabilities(&mut self) {
        // If using Anchor's Account trait, we're safe
        if self.uses_anchor_account {
            return;
        }
        
        // Check for Borsh structs without discriminant
        for struct_name in &self.borsh_structs {
            if !self.structs_with_discriminant.contains(struct_name) && 
               !self.structs_with_discriminant_check.contains(struct_name) {
                self.findings.push(Finding {
                    severity: Severity::Low,
                    certainty: Certainty::Low,
                    message: format!(
                        "Struct {} uses Borsh serialization without a discriminator field. This could enable type confusion attacks. Add a discriminator field or use the Account trait.",
                        struct_name
                    ),
                    location: Location {
                        file: self.file_path.clone(),
                        line: 1,
                        column: 0,
                    },
                });
            }
        }
    }

    fn check_account_data_usage(&mut self, expr: &syn::Expr, span: proc_macro2::Span) {
        if self.current_function_has_discriminant_check {
            return;
        }

        let expr_str = expr.to_token_stream().to_string();

        // Check for patterns like &ctx.accounts.user.data.borrow()
        if expr_str.contains("data") && expr_str.contains("borrow") {
            self.findings.push(Finding {
                severity: Severity::High,
                certainty: Certainty::High,
                message: "Unsafe try_from_slice on raw account data detected without proper type validation. This could lead to type confusion attacks. Use proper discriminator checks or the Account trait.".to_string(),
                location: Location {
                    file: self.file_path.clone(),
                    line: span.start().line,
                    column: span.start().column,
                },
            });
        }
    }
}

impl<'a, 'ast> Visit<'ast> for TypeCosplayVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast syn::ItemFn) {
        // Check if function body has discriminant check
        let mut checker = DiscriminantCheckFinder { has_check: false };
        checker.visit_block(&func.block);
        self.current_function_has_discriminant_check = checker.has_check;

        // Visit function body
        syn::visit::visit_item_fn(self, func);

        self.current_function_has_discriminant_check = false;
    }

    fn visit_item_struct(&mut self, item_struct: &'ast syn::ItemStruct) {
        let struct_name = item_struct.ident.to_string();
        
        // Check if this struct uses Anchor's Account trait
        let uses_account_attr = item_struct.attrs.iter().any(|attr| {
            attr.path().segments.iter().any(|seg| seg.ident == "account")
        });
        
        if uses_account_attr {
            self.uses_anchor_account = true;
            return;
        }
        
        // Check if this struct uses Borsh serialization
        let has_borsh_derive = item_struct.attrs.iter().any(|attr| {
            let attr_str = attr.to_token_stream().to_string();
            attr_str.contains("derive") && 
            (attr_str.contains("BorshDeserialize") || attr_str.contains("BorshSerialize"))
        });
        
        if has_borsh_derive {
            self.borsh_structs.insert(struct_name.clone());
            
            // Check if this struct has a discriminator field
            match &item_struct.fields {
                syn::Fields::Named(fields) => {
                    for field in &fields.named {
                        if let Some(ident) = &field.ident {
                            if ident.to_string() == "discriminant" {
                                self.structs_with_discriminant.insert(struct_name);
                                break;
                            }
                        }
                    }
                },
                _ => {}
            }
        }
    }
    
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        // First visit any child expressions
        syn::visit::visit_expr(self, expr);
        
        match expr {
            // Check for try_from_slice calls
            syn::Expr::Call(call) => {
                if let syn::Expr::Path(path) = &*call.func {
                    let segments: Vec<String> = path.path.segments.iter().map(|s| s.ident.to_string()).collect();
                    if let Some(last) = segments.last() {
                        if last == "try_from_slice" {
                            // Check if this is a call on account data
                            if let Some(arg) = call.args.first() {
                                self.check_account_data_usage(arg, call.span());
                            }
                        }
                    }
                }
            },
            syn::Expr::MethodCall(method_call) => {
                if method_call.method.to_string() == "try_from_slice" {
                    self.check_account_data_usage(&method_call.receiver, method_call.span());
                }
            },
            // Check for discriminant validation (for struct tracking)
            syn::Expr::Binary(bin_expr) => {
                self.check_binary_for_struct_discriminant(bin_expr);
            },
            _ => {}
        }
    }
    
    fn visit_expr_if(&mut self, if_expr: &'ast syn::ExprIf) {
        // First visit any child expressions
        syn::visit::visit_expr_if(self, if_expr);
        
        // Check for discriminant validation in if conditions
        if let syn::Expr::Binary(bin_expr) = &*if_expr.cond {
            self.check_binary_for_struct_discriminant(bin_expr);
        }
    }
}

impl<'a> TypeCosplayVisitor<'a> {
    fn check_binary_for_struct_discriminant(&mut self, bin_expr: &syn::ExprBinary) {
        // Helper to check one side of binary expr
        let check_side = |expr: &syn::Expr| -> Option<String> {
            if let syn::Expr::Field(field_expr) = expr {
                if field_expr.member.to_token_stream().to_string() == "discriminant" {
                    if let syn::Expr::Path(path) = &*field_expr.base {
                        return path.path.segments.last()
                            .map(|seg| seg.ident.to_string());
                    }
                }
            }
            None
        };

        if let Some(struct_name) = check_side(&*bin_expr.left) {
            self.structs_with_discriminant_check.insert(struct_name);
        }
        if let Some(struct_name) = check_side(&*bin_expr.right) {
            self.structs_with_discriminant_check.insert(struct_name);
        }
    }
}

struct DiscriminantCheckFinder {
    has_check: bool,
}

impl<'ast> Visit<'ast> for DiscriminantCheckFinder {
    fn visit_expr_binary(&mut self, bin_expr: &'ast syn::ExprBinary) {
        let left_str = bin_expr.left.to_token_stream().to_string();
        let right_str = bin_expr.right.to_token_stream().to_string();

        if left_str.contains("discriminant") || right_str.contains("discriminant") {
            self.has_check = true;
        }
        
        // Also check recursive if we want, but binary op usually is the check.
        // But we should visit children in case check is nested?
        // Usually discriminant check is `a == b`.
    }
    // We don't need to visit everything, just binary expressions in the block.
    // But `visit_block` calls `visit_stmt` which calls `visit_expr`.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_type_cosplay_vulnerable() {
        let code = r#"
        pub fn update(ctx: Context<Update>, data: Vec<u8>) -> Result<()> {
            let account_info = &ctx.accounts.my_account;
            let user = User::try_from_slice(&account_info.data.borrow())?;
            // Using user...
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = TypeCosplay;
        let findings = analyzer.analyze(&program).unwrap();
        
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("try_from_slice"));
    }

    #[test]
    fn test_type_cosplay_secure() {
        let code = r#"
        pub fn update(ctx: Context<Update>, data: Vec<u8>) -> Result<()> {
            let account_info = &ctx.accounts.my_account;
            let user = User::try_from_slice(&account_info.data.borrow())?;
            if user.discriminant != AccountDiscriminant::User {
                return Err(error!(ErrorCode::InvalidAccountType));
            }
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = TypeCosplay;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
