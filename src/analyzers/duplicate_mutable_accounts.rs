use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ItemStruct, ItemFn, Type, ExprBinary, BinOp};
use quote::ToTokens;
use std::collections::HashMap;

pub struct DuplicateMutableAccounts;

impl Analyzer for DuplicateMutableAccounts {
    fn name(&self) -> &'static str {
        "Duplicate Mutable Accounts"
    }

    fn description(&self) -> &'static str {
        "When there are two or more accounts with mutable data, a check must be in place to ensure \
         mutation of each account is differentiated properly, to avoid unintended data modification of other accounts."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut account_structs = HashMap::new();
        
        // First pass: collect all account structs
        for (_path, ast) in &program.asts {
            let mut collector = AccountStructCollector {
                account_structs: &mut account_structs,
            };
            syn::visit::visit_file(&mut collector, ast);
        }
        
        // Second pass: check for key comparisons in functions
        for (path, ast) in &program.asts {
            let mut visitor = DuplicateMutableAccountsVisitor {
                checked_structs: HashMap::new(),
            };
            syn::visit::visit_file(&mut visitor, ast);
            
            // Add findings for unchecked structs
            for (name, is_checked) in &visitor.checked_structs {
                if !is_checked {
                    if let Some(item_struct) = account_structs.get(name) {
                        let span = item_struct.ident.span();
                        findings.push(Finding {
                            severity: Severity::Medium,
                            certainty: Certainty::Medium,
                            message: format!("Struct '{}' has multiple Account fields without constraints to prevent duplicate accounts", name),
                            location: Location {
                                file: path.to_string_lossy().to_string(),
                                line: span.start().line,
                                column: span.start().column,
                            },
                        });
                    }
                }
            }
        }
        
        Ok(findings)
    }
}

struct AccountStructCollector<'a> {
    account_structs: &'a mut HashMap<String, ItemStruct>,
}

impl<'a, 'ast> Visit<'ast> for AccountStructCollector<'a> {
    fn visit_item_struct(&mut self, item_struct: &'ast ItemStruct) {
        // Check if this is an Accounts struct (has #[derive(Accounts)] attribute)
        for attr in &item_struct.attrs {
            if let Some(path) = attr.path().segments.first() {
                if path.ident == "derive" {
                    let tokens = attr.to_token_stream().to_string();
                    if tokens.contains("Accounts") {
                        self.account_structs.insert(item_struct.ident.to_string(), item_struct.clone());
                        return;
                    }
                }
            }
        }
    }
}

struct DuplicateMutableAccountsVisitor {
    checked_structs: HashMap<String, bool>,
}

impl<'ast> Visit<'ast> for DuplicateMutableAccountsVisitor {
    fn visit_item_struct(&mut self, item_struct: &'ast ItemStruct) {
        // Check if this is an Accounts struct (has #[derive(Accounts)] attribute)
        let has_accounts_derive = item_struct.attrs.iter().any(|attr| {
            if let Some(path) = attr.path().segments.first() {
                if path.ident == "derive" {
                    let tokens = attr.to_token_stream().to_string();
                    return tokens.contains("Accounts");
                }
            }
            false
        });

        if has_accounts_derive {
            let struct_name = item_struct.ident.to_string();
            
            // Check if this struct is already marked as checked
            if let Some(true) = self.checked_structs.get(&struct_name) {
                return;
            }
            
            // Check if there are at least 2 Account<'info, ...> fields
            let mut account_fields = Vec::new();
            
            for field in &item_struct.fields {
                if let Type::Path(type_path) = &field.ty {
                    if let Some(segment) = type_path.path.segments.first() {
                        if segment.ident == "Account" {
                            if let Some(name) = &field.ident {
                                account_fields.push(name.clone());
                            }
                        }
                    }
                }
            }
            
            // If we have at least 2 Account fields, check for constraints
            if account_fields.len() >= 2 {
                let mut has_constraint = false;
                
                // Check if any field has a constraint attribute that compares keys
                for field in &item_struct.fields {
                    for attr in &field.attrs {
                        let attr_str = attr.to_token_stream().to_string();
                        // Check for constraint attributes with key comparisons
                        if attr_str.contains("constraint") && 
                           (attr_str.contains("key()") || attr_str.contains("key ()")) && 
                           (attr_str.contains("!=") || attr_str.contains("==") || 
                            attr_str.contains("<") || attr_str.contains(">")) {
                            has_constraint = true;
                            break;
                        }
                    }
                    if has_constraint {
                        break;
                    }
                }
                
                // Also check struct attributes
                if !has_constraint {
                    for attr in &item_struct.attrs {
                        let attr_str = attr.to_token_stream().to_string();
                        // Check for constraint attributes with key comparisons
                        if attr_str.contains("constraint") && 
                           (attr_str.contains("key()") || attr_str.contains("key ()")) && 
                           (attr_str.contains("!=") || attr_str.contains("==") || 
                            attr_str.contains("<") || attr_str.contains(">")) {
                            has_constraint = true;
                            break;
                        }
                    }
                }
                
                // If no constraint found, mark this struct as needing a check
                if !has_constraint {
                    self.checked_structs.insert(struct_name, false);
                } else {
                    // If constraint found, mark as checked
                    self.checked_structs.insert(struct_name, true);
                }
            }
        }
    }
    
    fn visit_expr_binary(&mut self, expr: &'ast ExprBinary) {
        // Check for key comparisons in binary expressions
        if matches!(expr.op, BinOp::Eq(_) | BinOp::Ne(_) | BinOp::Lt(_) | BinOp::Gt(_) | BinOp::Le(_) | BinOp::Ge(_)) {
            let left_str = expr.left.to_token_stream().to_string();
            let right_str = expr.right.to_token_stream().to_string();
            
            // Check if either side contains a key() call
            if (left_str.contains(".key()") || left_str.contains(". key ()")) && 
               (right_str.contains(".key()") || right_str.contains(". key ()")) {
                // Find the context struct this comparison is in
                if let Some(struct_name) = self.find_context_struct_for_expr(expr) {
                    self.checked_structs.insert(struct_name, true);
                }
            }
        }
        
        // Continue visiting the expression
        syn::visit::visit_expr_binary(self, expr);
    }
    
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Check function parameters for Context<StructName>
        let mut context_struct = None;
        for input in &func.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = input {
                let ty_str = pat_type.ty.to_token_stream().to_string();
                if ty_str.contains("Context") {
                    // Extract struct name from Context<StructName>
                    if let Some(start) = ty_str.find('<') {
                        if let Some(end) = ty_str.find('>') {
                            let struct_name = ty_str[start+1..end].trim().to_string();
                            context_struct = Some(struct_name);
                        }
                    }
                }
            }
        }
        
        // Store the context struct for this function
        if let Some(struct_name) = &context_struct {
            CURRENT_CONTEXT_STRUCT.with(|cell| {
                *cell.borrow_mut() = Some(struct_name.clone());
            });
        }
        
        // Visit the function body to find key comparisons
        syn::visit::visit_block(self, &func.block);
        
        // Clear the context struct
        CURRENT_CONTEXT_STRUCT.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
    
    fn visit_file(&mut self, file: &'ast syn::File) {
        // First visit all functions and impl blocks to check for key comparisons
        for item in &file.items {
            match item {
                syn::Item::Fn(item_fn) => self.visit_item_fn(item_fn),
                syn::Item::Impl(item_impl) => {
                    for impl_item in &item_impl.items {
                        if let syn::ImplItem::Fn(impl_fn) = impl_item {
                            // Similar to visit_item_fn but for impl methods
                            let mut context_struct = None;
                            for input in &impl_fn.sig.inputs {
                                if let syn::FnArg::Typed(pat_type) = input {
                                    let ty_str = pat_type.ty.to_token_stream().to_string();
                                    if ty_str.contains("Context") {
                                        // Extract struct name from Context<StructName>
                                        if let Some(start) = ty_str.find('<') {
                                            if let Some(end) = ty_str.find('>') {
                                                let struct_name = ty_str[start+1..end].trim().to_string();
                                                context_struct = Some(struct_name);
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // Store the context struct for this function
                            if let Some(struct_name) = &context_struct {
                                CURRENT_CONTEXT_STRUCT.with(|cell| {
                                    *cell.borrow_mut() = Some(struct_name.clone());
                                });
                            }
                            
                            // Visit the function body to find key comparisons
                            syn::visit::visit_block(self, &impl_fn.block);
                            
                            // Clear the context struct
                            CURRENT_CONTEXT_STRUCT.with(|cell| {
                                *cell.borrow_mut() = None;
                            });
                        }
                    }
                },
                _ => {}
            }
        }
        
        // Then visit all structs to collect them
        for item in &file.items {
            if let syn::Item::Struct(item_struct) = item {
                self.visit_item_struct(item_struct);
            }
        }
    }
}

// Thread-local storage for the current context struct
thread_local! {
    static CURRENT_CONTEXT_STRUCT: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

impl DuplicateMutableAccountsVisitor {
    // Helper method to find the context struct for an expression
    fn find_context_struct_for_expr(&self, _expr: &ExprBinary) -> Option<String> {
        CURRENT_CONTEXT_STRUCT.with(|cell| {
            cell.borrow().clone()
        })
    }
} 