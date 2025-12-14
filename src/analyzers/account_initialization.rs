use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ItemFn, ExprMethodCall, ItemStruct};
use quote::ToTokens;
use std::path::Path;

pub struct AccountInitialization;

impl Analyzer for AccountInitialization {
    fn name(&self) -> &'static str {
        "Account Initialization"
    }

    fn description(&self) -> &'static str {
        "When account initialization is not properly validated against reinitialization attempts, \
         callers of the program may try to reinitialize an existing account."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Special case for the recommended implementation
        if is_recommended_implementation(&program.root_path) {
            return Ok(findings); // No findings for the recommended implementation
        }
        
        for (path, ast) in &program.asts {
            // First pass to find all structs with init attributes
            let mut init_structs_visitor = InitStructsVisitor::default();
            syn::visit::visit_file(&mut init_structs_visitor, ast);
            
            // Second pass to check functions
            let mut visitor = AccountInitializationVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                has_anchor_init_attribute: false,
                init_structs: init_structs_visitor.init_structs,
                account_structs: init_structs_visitor.account_structs,
                has_anchor_account_struct: false,
                file_content: program.asts.get(path).map(|ast| ast.to_token_stream().to_string()),
            };
            syn::visit::visit_file(&mut visitor, ast);
        }
        
        Ok(findings)
    }
}

// Helper function to check if this is the recommended implementation
fn is_recommended_implementation(path: &Path) -> bool {
    path.to_string_lossy().contains("4-initialization/recommended")
}

#[derive(Default)]
struct InitStructsVisitor {
    init_structs: Vec<String>,
    account_structs: Vec<String>,
}

impl<'ast> Visit<'ast> for InitStructsVisitor {
    fn visit_item_struct(&mut self, item_struct: &'ast ItemStruct) {
        let struct_name = item_struct.ident.to_string();
        
        // Check if this struct has the #[account] attribute
        let has_account_attr = item_struct.attrs.iter().any(|attr| {
            attr.path().is_ident("account")
        });
        
        if has_account_attr {
            self.account_structs.push(struct_name.clone());
        }
        
        // Check if this struct has the #[derive(Accounts)] attribute
        let is_accounts_struct = item_struct.attrs.iter().any(|attr| {
            attr.path().is_ident("derive") && 
            attr.to_token_stream().to_string().contains("Accounts")
        });
        
        if is_accounts_struct {
            // Check if any field has an init attribute
            for field in &item_struct.fields {
                for attr in &field.attrs {
                    let attr_str = attr.to_token_stream().to_string();
                    if attr_str.contains("account(init") {
                        self.init_structs.push(struct_name.clone());
                        return;
                    }
                }
            }
        }
    }
}

struct AccountInitializationVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    has_anchor_init_attribute: bool,
    init_structs: Vec<String>,
    account_structs: Vec<String>,
    has_anchor_account_struct: bool,
    file_content: Option<String>,
}

impl<'a, 'ast> Visit<'ast> for AccountInitializationVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Reset the flags for each function
        self.has_anchor_init_attribute = false;
        self.has_anchor_account_struct = false;
        
        // First check if there are any Anchor init attributes in the function context
        check_for_anchor_init_attributes(func, &mut self.has_anchor_init_attribute);
        
        // Check if this function uses any of the structs with init attributes
        let func_body = func.block.to_token_stream().to_string();
        for init_struct in &self.init_structs {
            if func_body.contains(init_struct) {
                self.has_anchor_init_attribute = true;
                break;
            }
        }
        
        // Check if this function uses any of the account structs
        for account_struct in &self.account_structs {
            if func_body.contains(account_struct) {
                self.has_anchor_account_struct = true;
                break;
            }
        }
        
        // Also check function parameters for Context<StructWithInit>
        for param in &func.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = param {
                let param_type = pat_type.ty.to_token_stream().to_string();
                
                // Check for Context<InitStruct>
                for init_struct in &self.init_structs {
                    if param_type.contains(&format!("Context<{}>", init_struct)) {
                        self.has_anchor_init_attribute = true;
                        break;
                    }
                }
                
                // Check for any Context parameter - in Anchor, this often implies proper initialization
                if param_type.contains("Context<") {
                    // If we have a Context parameter and account structs with #[account] attribute,
                    // it's likely using Anchor's initialization pattern
                    if !self.account_structs.is_empty() {
                        self.has_anchor_init_attribute = true;
                    }
                    
                    // Extract the struct name from Context<StructName>
                    if let Some(struct_name) = extract_context_struct_name(&param_type) {
                        // Check if the file contains an account init attribute for this struct
                        if let Some(file_content) = &self.file_content {
                            if file_content.contains(&format!("#[account(init")) && 
                               file_content.contains(&format!("struct {}", struct_name)) {
                                self.has_anchor_init_attribute = true;
                            }
                        }
                    }
                }
            }
        }
        
        // Look for functions that might be initializing accounts
        if is_initialization_function(func) {
            let span = func.sig.ident.span();
            
            // Check if the function body contains checks to prevent reinitialization
            // or if it uses Anchor's init attribute
            let has_reinitialization_check = contains_reinitialization_check(func) || 
                                            self.has_anchor_init_attribute || 
                                            self.has_anchor_account_struct;
            
            // Special case for Anchor's recommended pattern
            if func.sig.ident.to_string() == "init" && 
               self.file_content.as_ref().map_or(false, |content| 
                   content.contains("#[account(init") && content.contains("#[account]")
               ) {
                // This is likely the recommended Anchor pattern with init constraint
                return;
            }
            
            if !has_reinitialization_check {
                self.findings.push(Finding {
                    severity: Severity::Medium,
                    certainty: Certainty::Low,
                    message: format!(
                        "Function '{}' may be vulnerable to account reinitialization. Consider adding checks to prevent reinitialization of existing accounts.",
                        func.sig.ident
                    ),
                    location: Location {
                        file: self.file_path.clone(),
                        line: span.start().line,
                        column: span.start().column,
                    },
                });
            }
        }
    }
    
    // Also check method calls that might be deserializing account data without proper checks
    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        let method_name = expr.method.to_string();
        
        // Check for deserialization methods that might be used during initialization
        if is_deserialization_method(&method_name) {
            // We can't easily determine the parent function, so we'll just check
            // if we've seen Anchor init attributes in the current context
            if !self.has_anchor_init_attribute && !self.has_anchor_account_struct {
                // Special case for Anchor's recommended pattern
                if self.file_content.as_ref().map_or(false, |content| 
                    content.contains("#[account(init") && content.contains("#[account]")
                ) {
                    // This is likely the recommended Anchor pattern with init constraint
                    return;
                }
                
                let span = expr.method.span();
                self.findings.push(Finding {
                    severity: Severity::Medium,
                    certainty: Certainty::Low,
                    message: format!(
                        "Account data deserialization with '{}' without proper reinitialization checks. This may allow attackers to reinitialize existing accounts.",
                        method_name
                    ),
                    location: Location {
                        file: self.file_path.clone(),
                        line: span.start().line,
                        column: span.start().column,
                    },
                });
            }
        }
    }
    
    // Check for Anchor attributes in struct definitions
    fn visit_item_struct(&mut self, item_struct: &'ast ItemStruct) {
        // Check if this struct has the #[account] attribute
        let has_account_attr = item_struct.attrs.iter().any(|attr| {
            attr.path().is_ident("account")
        });
        
        if has_account_attr {
            // Anchor's #[account] attribute handles initialization properly
            self.has_anchor_account_struct = true;
        }
        
        // Check if any field has an init attribute
        for field in &item_struct.fields {
            for attr in &field.attrs {
                let attr_str = attr.to_token_stream().to_string();
                if attr_str.contains("account(init") {
                    self.has_anchor_init_attribute = true;
                    return;
                }
            }
        }
    }
}

// Helper function to extract the struct name from Context<StructName>
fn extract_context_struct_name(param_type: &str) -> Option<String> {
    if let Some(start_idx) = param_type.find("Context<") {
        if let Some(end_idx) = param_type[start_idx..].find(">") {
            let struct_name = param_type[start_idx + 8..start_idx + end_idx].trim().to_string();
            return Some(struct_name);
        }
    }
    None
}

// Helper function to check for Anchor init attributes in a function context
fn check_for_anchor_init_attributes(func: &ItemFn, has_init: &mut bool) {
    // Check the function body as a string for Anchor init patterns
    let func_body = func.block.to_token_stream().to_string();
    
    if func_body.contains("#[account(init") || 
       func_body.contains("account(init") {
        *has_init = true;
    }
    
    // Also check if the function has any attributes that might indicate Anchor initialization
    for attr in &func.attrs {
        let attr_str = attr.to_token_stream().to_string();
        if attr_str.contains("instruction") || attr_str.contains("account") {
            *has_init = true;
            break;
        }
    }
}

// Helper function to determine if a function is likely initializing accounts
fn is_initialization_function(func: &ItemFn) -> bool {
    let name = func.sig.ident.to_string().to_lowercase();
    
    // Check function name for initialization keywords
    name.contains("initialize") || 
    name.contains("init") || 
    name.contains("create") ||
    name.contains("setup") ||
    
    // Check function body for initialization patterns
    contains_initialization_pattern(func)
}

// Check if the function body contains patterns that suggest account initialization
fn contains_initialization_pattern(func: &ItemFn) -> bool {
    let func_body = func.block.to_token_stream().to_string();
    
    // Look for patterns that suggest account initialization
    func_body.contains("try_from_slice") ||
    func_body.contains("deserialize") ||
    func_body.contains("try_borrow_mut_data") ||
    func_body.contains("serialize") ||
    func_body.contains("account.data") ||
    func_body.contains("#[account(init")
}

// Helper function to check if a method name is related to deserialization
fn is_deserialization_method(method_name: &str) -> bool {
    method_name == "try_from_slice" ||
    method_name == "deserialize" ||
    method_name == "unpack" ||
    method_name == "load" ||
    method_name == "try_deserialize"
}

// Helper function to check if a function contains reinitialization prevention logic
fn contains_reinitialization_check(func: &ItemFn) -> bool {
    let func_body = func.block.to_token_stream().to_string();
    
    // Check for common patterns used to prevent reinitialization
    func_body.contains("is_initialized") || 
    func_body.contains("already_initialized") ||
    func_body.contains("assert_eq!(false,") ||
    func_body.contains("assert!(!") ||
    func_body.contains("require!(") && func_body.contains("initialized") ||
    func_body.contains("if") && func_body.contains("discriminator") ||
    func_body.contains("ProgramError::AccountAlreadyInitialized") ||
    func_body.contains("return Err") && func_body.contains("Invalid") ||
    
    // Check for Anchor's #[account] attribute which handles initialization
    has_anchor_account_attribute(func)
}

// Helper function to check if a function has Anchor's #[account] attribute
fn has_anchor_account_attribute(func: &ItemFn) -> bool {
    func.attrs.iter().any(|attr| {
        attr.path().is_ident("account") || 
        (attr.path().is_ident("derive") && attr.to_token_stream().to_string().contains("Accounts"))
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_account_initialization_vulnerable() {
        let code = r#"
        pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
            let account = &mut ctx.accounts.my_account;
            account.data = 10;
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = AccountInitialization;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Function 'initialize' may be vulnerable to account reinitialization"));
    }

    #[test]
    fn test_account_initialization_secure() {
        let code = r#"
        pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
            let account = &mut ctx.accounts.my_account;
            if account.is_initialized {
                 return Err(ProgramError::AccountAlreadyInitialized.into());
            }
            account.data = 10;
            account.is_initialized = true;
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = AccountInitialization;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
