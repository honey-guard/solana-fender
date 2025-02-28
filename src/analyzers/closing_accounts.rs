use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ExprMethodCall, Expr, ItemFn, ExprCall, spanned::Spanned, UseTree, ItemMod, ExprAssign, ExprLoop, Member, ExprBinary, BinOp, UnOp, ExprLit, Lit, ExprForLoop};
use quote::ToTokens;

pub struct ClosingAccounts;

impl Analyzer for ClosingAccounts {
    fn name(&self) -> &'static str {
        "Closing Accounts"
    }

    fn description(&self) -> &'static str {
        "Account closing operations should properly set discriminator and validate authorization \
         before zeroing lamports to prevent account reinitialization attacks."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // First pass: check if there's a force_defund function that checks discriminator
        let mut has_force_defund_check = false;
        
        for (_, ast) in &program.asts {
            let mut visitor = ClosingAccountsVisitor {
                findings: &mut Vec::new(), // Temporary findings vector
                file_path: String::new(),
                in_close_context: false,
                has_discriminator_import: false,
                has_discriminator_write: false,
                has_discriminator_check: false,
                has_data_zeroing: false,
                current_fn_name: String::new(),
                in_program_mod: false,
                current_mod_name: String::new(),
                current_expr_span: None,
                found_zero_assignment: false,
                in_zeroing_loop: false,
                in_data_mut_context: false,
                has_byte_assignment: false,
                in_deref_mut_context: false,
                in_iter_mut_context: false,
                method_chain_depth: 0,
                has_anchor_close_attribute: false,
                in_close_function: false,
                has_for_loop_zeroing: false,
                has_force_defund_check: false,
            };
            syn::visit::visit_file(&mut visitor, ast);
            
            // Check if this file has a force_defund function that checks discriminator
            if visitor.has_discriminator_check && visitor.current_fn_name.contains("force_defund") {
                has_force_defund_check = true;
                break;
            }
        }
        
        // Second pass: analyze for vulnerabilities
        for (path, ast) in &program.asts {
            let mut visitor = ClosingAccountsVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                in_close_context: false,
                has_discriminator_import: false,
                has_discriminator_write: false,
                has_discriminator_check: false,
                has_data_zeroing: false,
                current_fn_name: String::new(),
                in_program_mod: false,
                current_mod_name: String::new(),
                current_expr_span: None,
                found_zero_assignment: false,
                in_zeroing_loop: false,
                in_data_mut_context: false,
                has_byte_assignment: false,
                in_deref_mut_context: false,
                in_iter_mut_context: false,
                method_chain_depth: 0,
                has_anchor_close_attribute: false,
                in_close_function: false,
                has_for_loop_zeroing: false,
                has_force_defund_check: has_force_defund_check,
            };
            
            syn::visit::visit_file(&mut visitor, ast);
        }
        
        Ok(findings)
    }
}

struct ClosingAccountsVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    in_close_context: bool,
    has_discriminator_import: bool,
    has_discriminator_write: bool,
    has_discriminator_check: bool,
    has_data_zeroing: bool,
    current_fn_name: String,
    in_program_mod: bool,
    current_mod_name: String,
    current_expr_span: Option<proc_macro2::Span>,
    found_zero_assignment: bool,
    in_zeroing_loop: bool,
    in_data_mut_context: bool,
    has_byte_assignment: bool,
    in_deref_mut_context: bool,
    in_iter_mut_context: bool,
    method_chain_depth: i32,
    has_anchor_close_attribute: bool,
    in_close_function: bool,
    has_for_loop_zeroing: bool,
    has_force_defund_check: bool,
}

impl<'a, 'ast> Visit<'ast> for ClosingAccountsVisitor<'a> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let is_program = i.attrs.iter().any(|attr| {
            attr.path().segments.last().map_or(false, |s| s.ident == "program")
        });
        
        if is_program {
            self.in_program_mod = true;
            self.current_mod_name = i.ident.to_string();
            if let Some((_, items)) = &i.content {
                for item in items {
                    syn::visit::visit_item(self, item);
                }
            }
            self.in_program_mod = false;
        } else {
            syn::visit::visit_item_mod(self, i);
        }
    }

    fn visit_use_tree(&mut self, i: &'ast UseTree) {
        match i {
            UseTree::Path(path) => {
                if path.ident.to_string() == "CLOSED_ACCOUNT_DISCRIMINATOR" {
                    self.has_discriminator_import = true;
                }
            }
            UseTree::Group(group) => {
                for tree in &group.items {
                    self.visit_use_tree(tree);
                }
            }
            _ => {}
        }
        
        // Also check for imports that might contain the discriminator
        if let UseTree::Path(path) = i {
            let path_str = path.ident.to_string();
            if path_str.contains("__private") || path_str.contains("anchor_lang") {
                self.has_discriminator_import = true;
            }
        }
    }

    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        if !self.in_program_mod {
            return;
        }

        self.current_fn_name = i.sig.ident.to_string();
        
        // Check if this is a close function
        let is_close_fn = self.current_fn_name.contains("close") || 
                         self.current_mod_name.contains("close") || 
                         self.current_mod_name.contains("closing");
        
        if is_close_fn {
            self.in_close_context = true;
            self.in_close_function = true;
            
            // Reset state for this function
            self.has_discriminator_write = false;
            self.has_discriminator_check = false;
            self.has_data_zeroing = false;
            self.found_zero_assignment = false;
            self.current_expr_span = Some(i.span());
            self.has_anchor_close_attribute = false;
            self.has_for_loop_zeroing = false;
            
            syn::visit::visit_block(&mut *self, &i.block);
            
            // Only flag if we found a zero assignment without proper cleanup
            if self.found_zero_assignment && !self.has_anchor_close_attribute {
                // Check if this is the secure pattern
                let is_secure = 
                    // Either we have discriminator check and we're in force_defund
                    (self.has_discriminator_check && self.current_fn_name.contains("force_defund")) ||
                    // Or we have both discriminator write and data zeroing AND discriminator check
                    (self.has_discriminator_write && (self.has_data_zeroing || self.has_for_loop_zeroing) && self.has_discriminator_check) ||
                    // Or we have both discriminator write and data zeroing AND there's a force_defund function that checks discriminator
                    (self.has_discriminator_write && (self.has_data_zeroing || self.has_for_loop_zeroing) && self.has_force_defund_check);
                
                if !is_secure {
                    let missing_checks = if !self.has_discriminator_write && !self.has_data_zeroing && !self.has_for_loop_zeroing {
                        "discriminator setting and data zeroing"
                    } else if !self.has_discriminator_write {
                        "discriminator setting"
                    } else if !self.has_data_zeroing && !self.has_for_loop_zeroing {
                        "data zeroing"
                    } else if !self.has_discriminator_check && !self.has_force_defund_check {
                        "discriminator checking before closing"
                    } else {
                        "" // No issues found
                    };
                    
                    if !missing_checks.is_empty() {
                        self.findings.push(Finding {
                            severity: Severity::Medium,
                            certainty: Certainty::Low,
                            message: format!("Function '{}' in module '{}' zeroes account lamports without proper cleanup - vulnerable to reinitialization attacks. Missing: {}",
                                self.current_fn_name,
                                self.current_mod_name,
                                missing_checks
                            ),
                            location: Location {
                                file: self.file_path.clone(),
                                line: self.current_expr_span.map_or(i.span().start().line, |s| s.start().line),
                                column: self.current_expr_span.map_or(i.span().start().column, |s| s.start().column),
                            },
                        });
                    }
                }
            }
            
            self.in_close_context = false;
            self.in_close_function = false;
        } else {
            syn::visit::visit_item_fn(self, i);
        }
    }

    fn visit_expr_assign(&mut self, expr: &'ast ExprAssign) {
        if self.in_close_context {
            // Check for assignment to 0
            if let Expr::Lit(lit) = &*expr.right {
                if let Lit::Int(int_lit) = &lit.lit {
                    if int_lit.base10_digits() == "0" {
                        // Check if we're assigning to a lamports field through borrow_mut
                        if let Expr::Field(field) = &*expr.left {
                            if let Member::Named(ident) = &field.member {
                                if ident == "lamports" {
                                    self.found_zero_assignment = true;
                                    self.current_expr_span = Some(expr.span());
                                }
                            }
                        }
                        
                        // Also check for unary expressions (dereferencing)
                        if let Expr::Unary(unary) = &*expr.left {
                            if let Expr::Field(field) = &*unary.expr {
                                if let Member::Named(ident) = &field.member {
                                    if ident == "lamports" {
                                        self.found_zero_assignment = true;
                                        self.current_expr_span = Some(expr.span());
                                    }
                                }
                            }
                            
                            // Check for double dereference of lamports
                            if let Expr::Unary(inner_unary) = &*unary.expr {
                                if let Expr::MethodCall(method_call) = &*inner_unary.expr {
                                    if method_call.method == "borrow_mut" {
                                        // Check if the receiver is a lamports field
                                        if let Expr::Field(field) = &*method_call.receiver {
                                            if let Member::Named(ident) = &field.member {
                                                if ident == "lamports" {
                                                    self.found_zero_assignment = true;
                                                    self.current_expr_span = Some(expr.span());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Check for byte assignment in data zeroing context
                        if (self.in_data_mut_context || self.in_deref_mut_context) && (self.in_zeroing_loop || self.has_for_loop_zeroing) {
                            self.has_byte_assignment = true;
                            self.has_data_zeroing = true;
                        }

                        // Also check for direct byte assignment via deref
                        if let Expr::Unary(unary) = &*expr.left {
                            if matches!(unary.op, UnOp::Deref(_)) {
                                if (self.in_zeroing_loop || self.has_for_loop_zeroing) && 
                                   (self.in_data_mut_context || self.in_deref_mut_context || self.in_iter_mut_context) {
                                    self.has_byte_assignment = true;
                                    self.has_data_zeroing = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_assign(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        if self.in_close_context {
            let method_name = expr.method.to_string();
            self.method_chain_depth += 1;
            
            match method_name.as_str() {
                "try_borrow_mut_data" => {
                    self.in_data_mut_context = true;
                },
                "deref_mut" => {
                    self.in_deref_mut_context = true;
                },
                "iter_mut" => {
                    self.in_iter_mut_context = true;
                    // If we're in a chain after deref_mut and in a loop, this is data zeroing
                    if self.in_deref_mut_context && (self.in_zeroing_loop || self.has_for_loop_zeroing) && self.in_data_mut_context {
                        self.has_data_zeroing = true;
                    }
                },
                "write_all" => {
                    // Check for write_all with CLOSED_ACCOUNT_DISCRIMINATOR
                    if let Some(arg) = expr.args.first() {
                        if let Expr::Reference(reference) = arg {
                            if let Expr::Path(path) = &*reference.expr {
                                let path_str = path.path.to_token_stream().to_string();
                                if path_str.contains("CLOSED_ACCOUNT_DISCRIMINATOR") {
                                    self.has_discriminator_write = true;
                                }
                            }
                        }
                    }
                },
                "copy_from_slice" => {
                    // Check for discriminator comparison
                    if let Some(arg) = expr.args.first() {
                        if let Expr::Index(index) = arg {
                            if let Expr::Field(field) = &*index.expr {
                                if let Member::Named(ident) = &field.member {
                                    if ident == "data" {
                                        self.has_discriminator_check = true;
                                    }
                                }
                            }
                        }
                    }
                },
                _ => {}
            }
            
            syn::visit::visit_expr_method_call(self, expr);
            
            self.method_chain_depth -= 1;
            if self.method_chain_depth == 0 {
                // Reset context flags only when we're done with the entire chain
                self.in_data_mut_context = false;
                self.in_deref_mut_context = false;
                self.in_iter_mut_context = false;
            }
        } else {
            syn::visit::visit_expr_method_call(self, expr);
        }
    }

    fn visit_expr_binary(&mut self, expr: &'ast ExprBinary) {
        if self.in_close_context {
            // Check for discriminator comparison
            if let BinOp::Ne(_) | BinOp::Eq(_) = expr.op {
                // Check for discriminator != CLOSED_ACCOUNT_DISCRIMINATOR
                if let Expr::Path(path) = &*expr.right {
                    let path_str = path.path.to_token_stream().to_string();
                    if path_str.contains("CLOSED_ACCOUNT_DISCRIMINATOR") {
                        self.has_discriminator_check = true;
                    }
                }
                // Also check the other way around
                if let Expr::Path(path) = &*expr.left {
                    let path_str = path.path.to_token_stream().to_string();
                    if path_str.contains("CLOSED_ACCOUNT_DISCRIMINATOR") {
                        self.has_discriminator_check = true;
                    }
                }
                
                // Check for array comparison which might be discriminator check
                if let Expr::Array(_) = &*expr.left {
                    if let Expr::Array(_) = &*expr.right {
                        // Two arrays being compared, likely discriminator check
                        self.has_discriminator_check = true;
                    }
                }
            }
        }
        syn::visit::visit_expr_binary(self, expr);
    }

    fn visit_expr_loop(&mut self, expr: &'ast ExprLoop) {
        if self.in_close_context {
            self.in_zeroing_loop = true;
            syn::visit::visit_expr_loop(self, expr);
            self.in_zeroing_loop = false;
        } else {
            syn::visit::visit_expr_loop(self, expr);
        }
    }
    
    fn visit_expr_for_loop(&mut self, expr: &'ast ExprForLoop) {
        if self.in_close_context {
            // Check if this is a for loop over data bytes
            let pat_str = expr.pat.to_token_stream().to_string();
            let expr_str = expr.expr.to_token_stream().to_string();
            
            if (pat_str.contains("byte") || pat_str.contains("b")) && 
               (expr_str.contains("data") || expr_str.contains("iter_mut")) {
                self.has_for_loop_zeroing = true;
                self.has_data_zeroing = true;
            }
            
            syn::visit::visit_expr_for_loop(self, expr);
        } else {
            syn::visit::visit_expr_for_loop(self, expr);
        }
    }
    
    fn visit_expr_call(&mut self, expr: &'ast ExprCall) {
        // Check for calls to functions that might be related to account closing
        if let Expr::Path(path) = &*expr.func {
            let path_str = path.path.to_token_stream().to_string();
            if path_str.contains("close") {
                self.has_anchor_close_attribute = true;
            }
        }
        
        syn::visit::visit_expr_call(self, expr);
    }
    
    fn visit_expr_lit(&mut self, expr: &'ast ExprLit) {
        // Check for string literals that might contain discriminator
        if let Lit::Str(str_lit) = &expr.lit {
            let value = str_lit.value();
            if value.contains("discriminator") || value.contains("CLOSED_ACCOUNT_DISCRIMINATOR") {
                self.has_discriminator_check = true;
            }
        }
        
        syn::visit::visit_expr_lit(self, expr);
    }
} 