use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ExprMethodCall, ItemFn, Expr, ExprCall, ExprPath, ExprIf, ExprBinary, BinOp};
use syn::spanned::Spanned;
use quote::ToTokens;

pub use super::type_cosplay::TypeCosplay;
pub use super::pda_sharing::PdaSharing;

pub struct MissingOwnerCheck;

// Implement Missing Owner Check
impl Analyzer for MissingOwnerCheck {
    fn name(&self) -> &'static str {
        "Missing Owner Check"
    }

    fn description(&self) -> &'static str {
        "Owner checks verify whether an account is owned by the expected program. \
         Missing these checks can lead to processing invalid accounts."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Analyze each file in the program
        for (path, ast) in &program.asts {
            let mut visitor = OwnerCheckVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                has_program_owner_check: false,
                has_token_owner_check: false,
                has_data_access: false,
                current_function: None,
                spl_token_imports: false,
                unpack_locations: Vec::new(),
            };
            syn::visit::visit_file(&mut visitor, ast);
        }
        
        Ok(findings)
    }
}

// Visitor struct for the analyzer
struct OwnerCheckVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    has_program_owner_check: bool,  // Check for program ownership (token.owner == spl_token::ID)
    has_token_owner_check: bool,    // Check for token ownership (authority.key == token.owner)
    has_data_access: bool,
    current_function: Option<String>,
    spl_token_imports: bool,
    unpack_locations: Vec<(usize, usize)>, // Line, column of unpack calls
}

impl<'a, 'ast> Visit<'ast> for OwnerCheckVisitor<'a> {
    // Check for SPL token imports
    fn visit_use_path(&mut self, path: &'ast syn::UsePath) {
        let path_str = path.to_token_stream().to_string();
        if path_str.contains("spl_token") {
            self.spl_token_imports = true;
        }
        syn::visit::visit_use_path(self, path);
    }

    // Track function entry and exit
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Save previous state
        let prev_program_owner_check = self.has_program_owner_check;
        let prev_token_owner_check = self.has_token_owner_check;
        let prev_has_data_access = self.has_data_access;
        let prev_function = self.current_function.clone();
        let prev_unpack_locations = self.unpack_locations.clone();
        
        // Set new state for this function
        self.has_program_owner_check = false;
        self.has_token_owner_check = false;
        self.has_data_access = false;
        self.current_function = Some(func.sig.ident.to_string());
        self.unpack_locations.clear();
        
        // Visit the function body
        syn::visit::visit_item_fn(self, func);
        
        // Check if we have data access without proper owner checks in this function
        if self.has_data_access && self.spl_token_imports && !self.unpack_locations.is_empty() {
            // We need both types of owner checks for SPL token accounts
            if !self.has_program_owner_check {
                // Report findings for each unpack location that doesn't have a program owner check
                for (line, column) in &self.unpack_locations {
                    self.findings.push(Finding {
                        severity: Severity::Medium,
                        certainty: Certainty::Medium,
                        message: format!("SPL Token account data accessed without program owner check (token.owner == spl_token::ID)"),
                        location: Location {
                            file: self.file_path.clone(),
                            line: *line,
                            column: *column,
                        },
                    });
                }
            }
        }
        
        // Restore previous state
        self.has_program_owner_check = prev_program_owner_check;
        self.has_token_owner_check = prev_token_owner_check;
        self.has_data_access = prev_has_data_access;
        self.current_function = prev_function;
        self.unpack_locations = prev_unpack_locations;
    }

    // Check for data access methods
    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        let method_name = expr.method.to_string();
        
        // Check for account data access methods
        if method_name == "data" || method_name == "try_borrow_data" || method_name == "borrow" {
            self.has_data_access = true;
        }
        
        syn::visit::visit_expr_method_call(self, expr);
    }

    // Check for unpack calls which indicate SPL token account access
    fn visit_expr_call(&mut self, expr: &'ast ExprCall) {
        if let Expr::Path(ExprPath { path, .. }) = &*expr.func {
            let path_str = path.segments.iter()
                .map(|seg| seg.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            
            // Check for SplTokenAccount::unpack calls
            if path_str.contains("unpack") && self.spl_token_imports {
                self.has_data_access = true;
                
                // Store the location of the unpack call
                let span = expr.func.span();
                self.unpack_locations.push((span.start().line, span.start().column));
            }
        }
        
        syn::visit::visit_expr_call(self, expr);
    }

    // Check for owner comparisons in if conditions
    fn visit_expr_if(&mut self, expr: &'ast ExprIf) {
        if let Expr::Binary(ExprBinary { left, op, right, .. }) = &*expr.cond {
            // Check if this is a comparison operation
            if matches!(op, BinOp::Eq(_) | BinOp::Ne(_)) {
                let left_str = left.to_token_stream().to_string();
                let right_str = right.to_token_stream().to_string();
                
                // Check for program owner checks (token.owner == spl_token::ID)
                if left_str.contains("owner") || right_str.contains("owner") {
                    // Check for token program owner checks
                    if left_str.contains("spl_token") || right_str.contains("spl_token") || 
                        left_str.contains("ID") || right_str.contains("ID") {
                        self.has_program_owner_check = true;
                    }
                    
                    // Check for token owner checks (authority.key == token.owner)
                    if ((left_str.contains("token") && left_str.contains("owner")) || 
                        (right_str.contains("token") && right_str.contains("owner"))) &&
                       (left_str.contains("authority") || right_str.contains("authority") ||
                        left_str.contains("key") || right_str.contains("key")) {
                        self.has_token_owner_check = true;
                    }
                }
            }
        }
        
        // Visit the if body to check for owner checks inside
        syn::visit::visit_expr_if(self, expr);
    }

    // Check for binary expressions that might be owner checks
    fn visit_expr_binary(&mut self, expr: &'ast ExprBinary) {
        let left_str = expr.left.to_token_stream().to_string();
        let right_str = expr.right.to_token_stream().to_string();
        
        // Check if this is a comparison involving owner
        if matches!(expr.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            if left_str.contains("owner") || right_str.contains("owner") {
                // Check for program owner checks (token.owner == spl_token::ID)
                if left_str.contains("spl_token") || right_str.contains("spl_token") || 
                   left_str.contains("ID") || right_str.contains("ID") {
                    self.has_program_owner_check = true;
                }
                
                // Check for token owner checks (authority.key == token.owner)
                if ((left_str.contains("token") && left_str.contains("owner")) || 
                    (right_str.contains("token") && right_str.contains("owner"))) &&
                   (left_str.contains("authority") || right_str.contains("authority") ||
                    left_str.contains("key") || right_str.contains("key")) {
                    self.has_token_owner_check = true;
                }
            }
        }
        
        syn::visit::visit_expr_binary(self, expr);
    }
}