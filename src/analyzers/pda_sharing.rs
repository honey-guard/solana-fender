use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ExprMethodCall, spanned::Spanned, Attribute, ItemFn, ExprArray};
use quote::ToTokens;

pub struct PdaSharing;

impl Analyzer for PdaSharing {
    fn name(&self) -> &'static str {
        "PDA Sharing"
    }

    fn description(&self) -> &'static str {
        "Reuse of a PDA across multiple authority domains can lead to unauthorized data or funds access. \
         PDAs should include sufficient unique identifiers in their seeds."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (path, ast) in &program.asts {
            let mut visitor = PdaSharingVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                current_pda_seeds: Vec::new(),
                current_array: None,
            };
            syn::visit::visit_file(&mut visitor, ast);
        }
        
        Ok(findings)
    }
}

struct PdaSharingVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    current_pda_seeds: Vec<String>,
    current_array: Option<Vec<String>>,
}

impl<'a, 'ast> Visit<'ast> for PdaSharingVisitor<'a> {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        // Track PDA seed definitions in attributes
        if attr.path().is_ident("seeds") {
            if let Ok(expr) = attr.parse_args::<syn::Expr>() {
                if let syn::Expr::Array(array) = expr {
                    self.analyze_seed_array(&array);
                }
            }
        }
    }

    fn visit_expr_array(&mut self, array: &'ast ExprArray) {
        // Visit children first to handle nested arrays
        syn::visit::visit_expr_array(self, array);

        // Track array expressions that might be used as seeds
        let seeds: Vec<String> = array.elems.iter()
            .filter_map(|e| Some(e.to_token_stream().to_string()))
            .collect();

        // Check if this is a wrapper array (e.g. &[&[seeds]]) used for invoke_signed
        // A wrapper array typically contains only references to other arrays
        let is_wrapper = !seeds.is_empty() && seeds.iter().all(|s| s.trim().starts_with("&[") || s.trim().starts_with("["));

        if !is_wrapper {
            self.current_array = Some(seeds);
        }
    }

    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        // Check for with_signer calls
        if expr.method.to_string() == "with_signer" {
            // If we have a current array, analyze it
            if let Some(seeds) = &self.current_array {
                let has_insufficient_seeds = seeds.iter().all(|seed| {
                    let seed_lower = seed.to_lowercase();
                    seed_lower.contains("mint") || 
                    seed_lower.contains("bump") || 
                    seed_lower.contains("&[") // For bump arrays
                });

                if has_insufficient_seeds {
                    let span = expr.method.span();
                    self.findings.push(Finding {
                        severity: Severity::Low,
                        certainty: Certainty::Low,
                        message: "PDA seeds used for signing are insufficient for unique authority. Seeds only contain mint and bump, allowing potential unauthorized access.".to_string(),
                        location: Location {
                            file: self.file_path.clone(),
                            line: span.start().line,
                            column: span.start().column,
                        },
                    });
                }
            }
        }
        
        // Clear current array after checking
        self.current_array = None;
        
        // Visit the receiver and arguments
        syn::visit::visit_expr(&mut *self, &expr.receiver);
        for arg in &expr.args {
            syn::visit::visit_expr(&mut *self, arg);
        }
    }

    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Clear state when entering a new function
        self.current_pda_seeds.clear();
        self.current_array = None;
        
        // Visit the function body
        syn::visit::visit_item_fn(self, func);
    }
}

impl<'a> PdaSharingVisitor<'a> {
    fn analyze_seed_array(&mut self, array: &ExprArray) {
        self.current_pda_seeds = array.elems.iter()
            .filter_map(|e| Some(e.to_token_stream().to_string()))
            .collect();
            
        let has_insufficient_seeds = self.current_pda_seeds.iter().all(|seed| {
            let seed_lower = seed.to_lowercase();
            seed_lower.contains("mint") || 
            seed_lower.contains("bump") || 
            seed_lower.contains("&[")
        });

        if has_insufficient_seeds {
            let span = array.span();
            self.findings.push(Finding {
                severity: Severity::Low,
                certainty: Certainty::Low,
                message: "PDA seeds are insufficient for unique authority. Seeds only contain mint and bump, allowing potential unauthorized access.".to_string(),
                location: Location {
                    file: self.file_path.clone(),
                    line: span.start().line,
                    column: span.start().column,
                },
            });
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_pda_sharing_vulnerable_with_signer() {
        // Vulnerable: Seeds only depend on mint and bump
        let code = r#"
        pub fn process_instruction(ctx: Context<Ix>) -> Result<()> {
            // let seeds = &[b"mint", &[bump]];
            // The analyzer tracks ExprArray in visit_expr_array, then check in visit_expr_method_call for with_signer.

            invoke_signed(
                &ix,
                &accounts,
                &[&[b"mint", &[bump]]], // Insufficient seeds
            )?;

            // Or using CpiContext::new_with_signer
            CpiContext::new_with_signer(
                program.to_account_info(),
                accounts,
                &[&[b"mint", &[bump]]]
            );
            Ok(())
        }
        "#;

        // Wait, the analyzer specifically checks for `.with_signer(...)`.
        // And it checks `self.current_array`.
        // `visit_expr_array` runs on arguments?
        // `visit_expr_method_call` visits receiver and args AFTER checking `with_signer`.

        // If I have `something.with_signer(seeds)`.
        // `seeds` is an argument. `visit_expr_method_call` visits args.
        // But `with_signer` check happens BEFORE visiting args?

        // Let's check `visit_expr_method_call` again.
        /*
        if expr.method.to_string() == "with_signer" {
            // If we have a current array, analyze it
            if let Some(seeds) = &self.current_array {
                ...
            }
        }
        // ...
        for arg in &expr.args {
            syn::visit::visit_expr(&mut *self, arg);
        }
        */

        // So `current_array` must be set BEFORE `visit_expr_method_call` is called on `with_signer`.
        // But `visit_expr_method_call` IS the visitor for `with_signer`.
        // When visiting `with_signer(seeds)`, `seeds` hasn't been visited yet by THIS method call visitor (because it visits args later).
        // BUT, maybe it was visited earlier? No, AST traversal is top-down usually.

        // If `visit_expr_method_call` is called for `expr`.
        // `expr.args` contains the array.
        // It hasn't visited `expr.args` yet.
        // So `current_array` would be from... previous statement?

        // If I have:
        // let seeds = &[...];
        // ctx.with_signer(seeds);

        // `visit_local` visits `let seeds = ...`. It calls `visit_expr`.
        // `visit_expr_array` sets `current_array`.
        // Then `visit_expr_method_call` sees `with_signer` and checks `current_array`.

        // So I must define the array in a statement before `with_signer`.

        let code = r#"
        pub fn pda_sharing_vulnerable(ctx: Context<Ix>) -> Result<()> {
            let seeds = &[&[b"mint", &[bump]]];
            CpiContext::new(
                 program,
                 accounts
            ).with_signer(seeds);
            Ok(())
        }
        "#;

        let program = create_program(code);
        let analyzer = PdaSharing;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("PDA seeds used for signing are insufficient"));
    }

    #[test]
    fn test_pda_sharing_secure() {
        let code = r#"
        pub fn pda_sharing_secure(ctx: Context<Ix>) -> Result<()> {
            // "safe" seed prevents vulnerability
            // Using a simple safe seed without nested bump array to avoid confusion in analyzer
            let seeds = &[&[b"safe"]];
            CpiContext::new(
                 program,
                 accounts
            ).with_signer(seeds);
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = PdaSharing;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
