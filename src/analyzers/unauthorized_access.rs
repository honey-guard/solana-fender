use super::{Analyzer, Finding, Location, Severity, Certainty};
use crate::models::Program;
use syn::{visit::Visit, ItemFn, ItemStruct, spanned::Spanned, Meta, Type};
use anyhow::Result;
use std::collections::HashMap;

pub struct UnauthorizedAccessAnalyzer;

struct AuthorizationVisitor {
    findings: Vec<Finding>,
    current_file: std::path::PathBuf,
    // Track which structs are used in functions with is_signer checks
    structs_with_runtime_checks: HashMap<String, bool>,
    // Track which structs have Signer type fields
    structs_with_signer_type: HashMap<String, bool>,
}

impl<'ast> Visit<'ast> for AuthorizationVisitor {
    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        // Check for #[instruction] attribute or being in a #[program] module
        let is_instruction = function.attrs.iter().any(|attr| {
            attr.path().is_ident("instruction")
        });

        // If not an instruction, check if it might be an Anchor instruction
        // by looking at the function signature and context parameter
        let might_be_anchor_instruction = if !is_instruction {
            // Check if the function is inside a module marked with #[program]
            let in_program_module = function.attrs.iter().any(|attr| {
                attr.path().is_ident("program")
            });
            
            // Check if the function takes a Context parameter
            let has_context_param = function.sig.inputs.iter().any(|arg| {
                if let syn::FnArg::Typed(pat_type) = arg {
                    if let syn::Type::Path(type_path) = &*pat_type.ty {
                        let type_str = quote::quote!(#type_path).to_string();
                        type_str.contains("Context<") || type_str.contains("Context <")
                    } else {
                        false
                    }
                } else {
                    false
                }
            });
            
            in_program_module || has_context_param
        } else {
            false
        };

        if !is_instruction && !might_be_anchor_instruction {
            return;
        }

        // Check for authority validation
        let has_check = has_authority_check(&function.block);
        
        // Extract the account struct name from the Context parameter if it exists
        let mut struct_name = None;
        for arg in &function.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = arg {
                if let syn::Type::Path(type_path) = &*pat_type.ty {
                    let type_str = quote::quote!(#type_path).to_string();
                    if type_str.contains("Context<") || type_str.contains("Context <") {
                        // Extract the struct name from Context<StructName>
                        struct_name = extract_struct_name_from_context(&type_str);
                        if let Some(name) = &struct_name {
                            if has_check {
                                // Mark this struct as having a runtime check
                                self.structs_with_runtime_checks.insert(name.clone(), true);
                            }
                        }
                    }
                }
            }
        }
        
        // Check if the struct has a Signer type field
        let has_signer_type_field = if let Some(name) = &struct_name {
            self.structs_with_signer_type.get(name).copied().unwrap_or(false)
        } else {
            false
        };
        
        // Only report an issue if there's no runtime check AND no Signer type field
        if !has_check && !has_signer_type_field {
            self.findings.push(Finding {
                severity: Severity::Low,
                certainty: Certainty::Low,
                message: format!(
                    "The instruction '{}' does not validate the caller's authority. \
                     Consider adding an explicit check like 'if !ctx.accounts.authority.is_signer {{ return Err(...) }}'.",
                    function.sig.ident
                ),
                location: Location {
                    file: self.current_file.to_string_lossy().to_string(),
                    line: function.span().start().line,
                    column: function.span().start().column,
                },
            });
        }
    }

    fn visit_item_struct(&mut self, structure: &'ast ItemStruct) {
        // Check for #[derive(Accounts)] attribute which is common in Anchor programs
        let is_accounts_struct = structure.attrs.iter().any(|attr| {
            if let Meta::List(meta_list) = &attr.meta {
                if attr.path().is_ident("derive") {
                    let tokens = &meta_list.tokens;
                    let tokens_str = quote::quote!(#tokens).to_string();
                    tokens_str.contains("Accounts")
                } else {
                    false
                }
            } else {
                false
            }
        });

        if !is_accounts_struct {
            return;
        }

        // Skip if this struct is used in a function with runtime checks
        let struct_name = structure.ident.to_string();
        if self.structs_with_runtime_checks.get(&struct_name).is_some() {
            return;
        }

        // Check if any field is named "authority" or similar but doesn't use Signer type
        let mut has_authority_field = false;
        let mut authority_field_uses_signer = false;

        for field in &structure.fields {
            let field_name = field.ident.as_ref().map(|i| i.to_string().to_lowercase());
            
            if let Some(name) = field_name {
                if name.contains("authority") || name.contains("owner") || name.contains("admin") || name == "signer" {
                    has_authority_field = true;
                    
                    // Check if the field uses Signer type
                    if is_signer_type(&field.ty) {
                        authority_field_uses_signer = true;
                        // Mark this struct as having a Signer type field
                        self.structs_with_signer_type.insert(struct_name.clone(), true);
                        break;  // Found a properly typed authority field, no need to check further
                    }
                }
            }
        }

        if has_authority_field && !authority_field_uses_signer {
            self.findings.push(Finding {
                severity: Severity::High,
                certainty: Certainty::Medium,
                message: format!(
                    "The account struct '{}' has an authority field that doesn't use the Signer type. \
                     Consider using 'Signer<'info>' instead of 'AccountInfo<'info>' for authority fields.",
                    structure.ident
                ),
                location: Location {
                    file: self.current_file.to_string_lossy().to_string(),
                    line: structure.span().start().line,
                    column: structure.span().start().column,
                },
            });
        }
    }
}

fn has_authority_check(block: &syn::Block) -> bool {
    struct AuthorityCheckVisitor {
        has_check: bool,
    }

    impl<'ast> Visit<'ast> for AuthorityCheckVisitor {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            let method_name = call.method.to_string();
            if method_name == "is_signer" {
                self.has_check = true;
            }
        }

        fn visit_expr_field(&mut self, field: &syn::ExprField) {
            let field_name = match &field.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(_) => String::new(),
            };
            
            if field_name == "is_signer" {
                self.has_check = true;
            }
        }

        // Check for if statements that might contain is_signer checks
        fn visit_expr_if(&mut self, if_expr: &syn::ExprIf) {
            // Visit the condition to check for is_signer
            syn::visit::visit_expr(&mut *self, &if_expr.cond);
            
            // If we haven't found a check yet, visit the if body
            if !self.has_check {
                syn::visit::visit_block(&mut *self, &if_expr.then_branch);
            }
            
            // If we still haven't found a check and there's an else, visit it
            if !self.has_check {
                if let Some((_, else_expr)) = &if_expr.else_branch {
                    syn::visit::visit_expr(&mut *self, else_expr);
                }
            }
        }
        
        // Check for binary expressions that might contain is_signer checks
        fn visit_expr_binary(&mut self, binary: &syn::ExprBinary) {
            // Visit both sides of the binary expression
            syn::visit::visit_expr(&mut *self, &binary.left);
            syn::visit::visit_expr(&mut *self, &binary.right);
        }
        
        // Check for unary expressions that might contain is_signer checks (e.g., !is_signer)
        fn visit_expr_unary(&mut self, unary: &syn::ExprUnary) {
            syn::visit::visit_expr(&mut *self, &unary.expr);
        }
    }

    let mut visitor = AuthorityCheckVisitor { has_check: false };
    visitor.visit_block(block);
    visitor.has_check
}

fn is_signer_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        let path_segments = &type_path.path.segments;
        
        // Check if the type is directly "Signer"
        if path_segments.iter().any(|segment| segment.ident == "Signer") {
            return true;
        }
        
        // Convert to string for more flexible matching
        let path_str = quote::quote!(#type_path).to_string();
        path_str.contains("Signer<") || 
        path_str.contains("signer::Signer") || 
        path_str.contains(":: Signer") ||
        path_str.contains("anchor_lang :: prelude :: Signer")
    } else {
        false
    }
}

// Helper function to extract struct name from Context<StructName>
fn extract_struct_name_from_context(type_str: &str) -> Option<String> {
    // Try different patterns that might appear in the AST representation
    let patterns = [
        ("Context < ", " >"),
        ("Context<", ">"),
    ];
    
    for (start_pattern, end_pattern) in patterns.iter() {
        if let Some(start_idx) = type_str.find(start_pattern) {
            let start_pos = start_idx + start_pattern.len();
            if let Some(end_idx) = type_str[start_pos..].find(end_pattern) {
                let struct_name = type_str[start_pos..start_pos + end_idx].trim().to_string();
                return Some(struct_name);
            }
        }
    }
    
    None
}

impl Analyzer for UnauthorizedAccessAnalyzer {
    fn name(&self) -> &'static str {
        "Signer Authorization Check"
    }

    fn description(&self) -> &'static str {
        "Checks for missing signer verification in instructions that could lead to unauthorized access"
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Create visitor
        let mut visitor = AuthorizationVisitor {
            findings: Vec::new(),
            current_file: std::path::PathBuf::new(),
            structs_with_runtime_checks: HashMap::new(),
            structs_with_signer_type: HashMap::new(),
        };

        // First pass: collect all structs and their properties
        for (path, ast) in &program.asts {
            visitor.current_file = path.clone();
            visitor.visit_file(ast);
        }

        // Clear findings from the first pass
        visitor.findings.clear();

        // Second pass to analyze and report findings
        for (path, ast) in &program.asts {
            visitor.current_file = path.clone();
            visitor.visit_file(ast);
        }

        findings.extend(visitor.findings);
        Ok(findings)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_unauthorized_access_vulnerable() {
        // Vulnerable: authority field is AccountInfo, not Signer
        let code = r#"
        #[derive(Accounts)]
        pub struct Vulnerable<'info> {
            pub authority: AccountInfo<'info>,
        }

        #[instruction]
        pub fn update(ctx: Context<Vulnerable>) -> Result<()> {
            // No runtime check for is_signer
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = UnauthorizedAccessAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        // The analyzer has 2 findings potential:
        // 1. Instruction without check.
        // 2. Struct with authority field not being Signer.
        // The code logic checks:
        // `if !has_check && !has_signer_type_field` -> Report instruction issue.
        // `if has_authority_field && !authority_field_uses_signer` -> Report struct issue.

        // In this case:
        // `authority` is AccountInfo (not Signer).
        // `update` has no `is_signer` check.

        // So we expect findings.
        assert!(findings.len() >= 1);
        assert!(findings[0].message.contains("does not validate the caller's authority") ||
                findings[0].message.contains("authority field that doesn't use the Signer type"));
    }

    #[test]
    fn test_unauthorized_access_secure_signer_type() {
        let code = r#"
        #[derive(Accounts)]
        pub struct SecureType<'info> {
            pub authority: Signer<'info>,
        }

        #[instruction]
        pub fn update(ctx: Context<SecureType>) -> Result<()> {
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = UnauthorizedAccessAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_unauthorized_access_secure_runtime_check() {
        let code = r#"
        #[derive(Accounts)]
        pub struct SecureCheck<'info> {
            pub authority: AccountInfo<'info>,
        }

        #[instruction]
        pub fn update(ctx: Context<SecureCheck>) -> Result<()> {
            if !ctx.accounts.authority.is_signer {
                return Err(ErrorCode::Unauthorized.into());
            }
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = UnauthorizedAccessAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        // `visit_item_struct` logic:
        // "Skip if this struct is used in a function with runtime checks"
        // `structs_with_runtime_checks` is populated in `visit_item_fn`.
        // The analyzer does 2 passes.
        // Pass 1: visit file. Populates `structs_with_runtime_checks` (if instruction has check).
        // Then it clears findings.
        // Pass 2: visit file. Checks struct.

        // In pass 1:
        // `visit_item_fn` (`update`). Has check. `struct_name` = "SecureCheck".
        // `structs_with_runtime_checks` -> insert "SecureCheck".

        // In pass 2:
        // `visit_item_struct` (`SecureCheck`).
        // Checks `structs_with_runtime_checks.get("SecureCheck")`. Found. Returns.
        // `visit_item_fn` (`update`).
        // `has_check` is true.
        // `has_signer_type_field` is false (from map).
        // `if !has_check && !has_signer_type_field`. False. No finding.

        assert_eq!(findings.len(), 0);
    }
}
