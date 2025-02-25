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
                    severity: Severity::High,
                    certainty: Certainty::High,
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
}

impl<'a, 'ast> Visit<'ast> for TypeCosplayVisitor<'a> {
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
                    let path_str = path.path.to_token_stream().to_string();
                    
                    if path_str.ends_with("::try_from_slice") {
                        // Check if this is a call on account data
                        if let Some(arg) = call.args.first() {
                            self.check_account_data_usage(arg, call.span());
                        }
                    }
                }
            },
            syn::Expr::MethodCall(method_call) => {
                if method_call.method.to_string() == "try_from_slice" {
                    self.check_account_data_usage(&method_call.receiver, method_call.span());
                }
            },
            // Check for discriminant validation
            syn::Expr::Binary(bin_expr) => {
                // Look for expressions like: user.discriminant == AccountDiscriminant::User
                if let syn::Expr::Field(field_expr) = &*bin_expr.left {
                    if field_expr.member.to_token_stream().to_string() == "discriminant" {
                        if let syn::Expr::Path(path) = &*field_expr.base {
                            let struct_name = path.path.segments.last()
                                .map(|seg| seg.ident.to_string())
                                .unwrap_or_default();
                            
                            if !struct_name.is_empty() {
                                self.structs_with_discriminant_check.insert(struct_name);
                            }
                        }
                    }
                }
                
                if let syn::Expr::Field(field_expr) = &*bin_expr.right {
                    if field_expr.member.to_token_stream().to_string() == "discriminant" {
                        if let syn::Expr::Path(path) = &*field_expr.base {
                            let struct_name = path.path.segments.last()
                                .map(|seg| seg.ident.to_string())
                                .unwrap_or_default();
                            
                            if !struct_name.is_empty() {
                                self.structs_with_discriminant_check.insert(struct_name);
                            }
                        }
                    }
                }
            },
            _ => {}
        }
    }
    
    fn visit_expr_if(&mut self, if_expr: &'ast syn::ExprIf) {
        // First visit any child expressions
        syn::visit::visit_expr_if(self, if_expr);
        
        // Check for discriminant validation in if conditions
        if let syn::Expr::Binary(bin_expr) = &*if_expr.cond {
            // Look for expressions like: user.discriminant != AccountDiscriminant::User
            if let syn::Expr::Field(field_expr) = &*bin_expr.left {
                if field_expr.member.to_token_stream().to_string() == "discriminant" {
                    if let syn::Expr::Path(path) = &*field_expr.base {
                        let struct_name = path.path.segments.last()
                            .map(|seg| seg.ident.to_string())
                            .unwrap_or_default();
                        
                        if !struct_name.is_empty() {
                            self.structs_with_discriminant_check.insert(struct_name);
                        }
                    }
                }
            }
            
            if let syn::Expr::Field(field_expr) = &*bin_expr.right {
                if field_expr.member.to_token_stream().to_string() == "discriminant" {
                    if let syn::Expr::Path(path) = &*field_expr.base {
                        let struct_name = path.path.segments.last()
                            .map(|seg| seg.ident.to_string())
                            .unwrap_or_default();
                        
                        if !struct_name.is_empty() {
                            self.structs_with_discriminant_check.insert(struct_name);
                        }
                    }
                }
            }
        }
    }
    
    fn visit_file(&mut self, file: &'ast syn::File) {
        // Check for try_from_slice usage on account data
        for item in &file.items {
            if let syn::Item::Fn(func) = item {
                let func_name = func.sig.ident.to_string();
                
                // Look for patterns like in the insecure example
                if func_name.contains("update") || func_name.contains("process") {
                    let mut has_try_from_slice = false;
                    let mut has_discriminant_check = false;
                    
                    // Traverse the function body
                    for stmt in &func.block.stmts {
                        if let syn::Stmt::Local(local) = stmt {
                            if let Some(init) = &local.init {
                                if let syn::Expr::Call(call) = &*init.expr {
                                    if let syn::Expr::Path(path) = &*call.func {
                                        let path_str = path.path.to_token_stream().to_string();
                                        if path_str.ends_with("::try_from_slice") {
                                            has_try_from_slice = true;
                                            
                                            // Check if this is a call on account data
                                            if let Some(arg) = call.args.first() {
                                                let arg_str = arg.to_token_stream().to_string();
                                                if arg_str.contains("data") && arg_str.contains("borrow") {
                                                    // This is a try_from_slice on account data
                                                    self.findings.push(Finding {
                                                        severity: Severity::High,
                                                        certainty: Certainty::High,
                                                        message: "Unsafe try_from_slice on raw account data detected without proper type validation. This could lead to type confusion attacks. Use proper discriminator checks or the Account trait.".to_string(),
                                                        location: Location {
                                                            file: self.file_path.clone(),
                                                            line: call.span().start().line,
                                                            column: call.span().start().column,
                                                        },
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else if let syn::Stmt::Expr(expr, _) = stmt {
                            if let syn::Expr::If(if_expr) = expr {
                                if let syn::Expr::Binary(bin_expr) = &*if_expr.cond {
                                    // Check for discriminant validation
                                    let left_str = bin_expr.left.to_token_stream().to_string();
                                    let right_str = bin_expr.right.to_token_stream().to_string();
                                    
                                    if left_str.contains("discriminant") || right_str.contains("discriminant") {
                                        has_discriminant_check = true;
                                    }
                                }
                            }
                        }
                    }
                    
                    // If we have try_from_slice without discriminant check, it's a vulnerability
                    if has_try_from_slice && !has_discriminant_check {
                        self.findings.push(Finding {
                            severity: Severity::High,
                            certainty: Certainty::High,
                            message: format!(
                                "Function {} uses try_from_slice without proper type validation. This could enable type confusion attacks. Add discriminant checks or use the Account trait.",
                                func_name
                            ),
                            location: Location {
                                file: self.file_path.clone(),
                                line: func.span().start().line,
                                column: func.span().start().column,
                            },
                        });
                    }
                }
            }
        }
        
        // Visit all items in the file
        syn::visit::visit_file(self, file);
    }
}

impl<'a> TypeCosplayVisitor<'a> {
    fn check_account_data_usage(&mut self, expr: &syn::Expr, span: proc_macro2::Span) {
        let expr_str = expr.to_token_stream().to_string();
        
        // Check for patterns like &ctx.accounts.user.data.borrow()
        if expr_str.contains("data") && expr_str.contains("borrow") {
            self.findings.push(Finding {
                severity: Severity::High,
                certainty: Certainty::High,
                message: "Unsafe try_from_slice on raw account data detected. This could lead to type confusion attacks. Use proper type validation, discriminators, or Account trait.".to_string(),
                location: Location {
                    file: self.file_path.clone(),
                    line: span.start().line,
                    column: span.start().column,
                },
            });
        }
    }
} 