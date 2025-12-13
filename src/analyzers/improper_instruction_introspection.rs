use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ExprCall, Expr, Lit, spanned::Spanned};

pub struct ImproperInstructionIntrospection;

impl Analyzer for ImproperInstructionIntrospection {
    fn name(&self) -> &'static str {
        "Improper Instruction Introspection"
    }

    fn description(&self) -> &'static str {
        "Using absolute indices to access instructions in a transaction can lead to vulnerabilities \
         where an attacker can manipulate the transaction layout to bypass checks. \
         Use relative indices (e.g., via `get_instruction_relative`) or ensure explicit correlation checks."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (path, ast) in &program.asts {
            let mut visitor = ImproperInstructionIntrospectionVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
            };
            syn::visit::visit_file(&mut visitor, ast);
        }

        Ok(findings)
    }
}

struct ImproperInstructionIntrospectionVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
}

impl<'a, 'ast> Visit<'ast> for ImproperInstructionIntrospectionVisitor<'a> {
    fn visit_expr_call(&mut self, expr: &'ast ExprCall) {
        // Check for load_instruction_at_checked calls
        if let Expr::Path(expr_path) = &*expr.func {
            let path_str = expr_path.path.segments.iter()
                .map(|seg| seg.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");

            if path_str.contains("load_instruction_at_checked") {
                // Check the first argument (index)
                if let Some(arg) = expr.args.first() {
                     if let Expr::Lit(expr_lit) = arg {
                        if let Lit::Int(lit_int) = &expr_lit.lit {
                             // Check if it's a literal integer (absolute index)
                             // We are concerned about 0 or fixed indices.
                             // Using a hardcoded index is generally what we want to flag.

                             let span = expr.func.span();
                             self.findings.push(Finding {
                                severity: Severity::High,
                                certainty: Certainty::High,
                                message: format!("Potential improper instruction introspection detected. \
                                                 Using absolute index '{}' to access instructions may be unsafe. \
                                                 Consider using relative indexing or validating the instruction correlation.", lit_int),
                                location: Location {
                                    file: self.file_path.clone(),
                                    line: span.start().line,
                                    column: span.start().column,
                                },
                            });
                        }
                     }
                }
            }
        }

        // Continue visiting the expression
        syn::visit::visit_expr_call(self, expr);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Program;
    use std::path::PathBuf;
    use std::collections::HashMap;

    #[test]
    fn test_improper_instruction_introspection() {
        let code = r#"
            use solana_program::sysvar::instructions::load_instruction_at_checked;

            // Case 1: Unsafe usage with absolute index
            fn unsafe_function(ctx: Context<Mint>) -> Result<()> {
                // This uses an absolute index '0', which is dangerous
                let ix = load_instruction_at_checked(0, ctx.accounts.instructions)?;
                Ok(())
            }

            // Case 2: Properly done case - Using relative index
            fn safe_relative(ctx: Context<Mint>) -> Result<()> {
                 // This uses relative indexing, which preserves correlation
                 // The analyzer should NOT flag this
                 let ix = get_instruction_relative(-1, ctx.accounts.instructions)?;
                 Ok(())
            }

            // Case 3: Properly done case - Variable index (assumed validated)
            fn safe_variable_index(ctx: Context<Mint>, index: usize) -> Result<()> {
                // This uses a variable index, not a hardcoded literal
                // The analyzer should NOT flag this as it only targets literals
                let ix = load_instruction_at_checked(index, ctx.accounts.instructions)?;
                Ok(())
            }
        "#;

        let file = syn::parse_file(code).unwrap();
        let mut asts = HashMap::new();
        asts.insert(PathBuf::from("test.rs"), file);

        let program = Program {
            asts,
            root_path: PathBuf::from("."),
        };

        let analyzer = ImproperInstructionIntrospection;
        let findings = analyzer.analyze(&program).unwrap();

        // Verify we only have 1 finding (from Case 1)
        assert_eq!(findings.len(), 1, "Expected exactly 1 finding, found {}", findings.len());

        // Verify the finding corresponds to the unsafe usage
        let finding = &findings[0];
        assert!(finding.message.contains("Using absolute index '0'"));

        // Verify no findings for the safe cases implicitly by the count check
    }
}
