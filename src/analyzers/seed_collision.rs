use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, Attribute, Expr, ExprCall, ExprPath, spanned::Spanned, Lit};
use quote::ToTokens;

pub struct SeedCollision;

impl Analyzer for SeedCollision {
    fn name(&self) -> &'static str {
        "Seed Collision"
    }

    fn description(&self) -> &'static str {
        "PDA derivations should start with a unique static string literal (prefix) to prevent seed collisions \
         between different PDAs in the same program. Failing to use a prefix can lead to different logical \
         PDAs deriving to the same address."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (path, ast) in &program.asts {
            let mut visitor = SeedCollisionVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
            };
            syn::visit::visit_file(&mut visitor, ast);
        }

        Ok(findings)
    }
}

struct SeedCollisionVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
}

impl<'a, 'ast> Visit<'ast> for SeedCollisionVisitor<'a> {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        // Check for #[account(seeds = [...])]
        if attr.path().is_ident("account") {
            if let Ok(nested) = attr.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated) {
                for meta in nested {
                     if let syn::Meta::NameValue(nv) = meta {
                        if nv.path.is_ident("seeds") {
                            if let Expr::Array(array) = nv.value {
                                self.check_seeds_array(&array, attr.span());
                            }
                        }
                     }
                }
            } else {
                // Fallback for simple parsing if complex parsing fails (though Anchor usually matches above)
                // Sometimes attributes are like #[account(seeds = [b"prefix", ...])]
                // The previous parser might fail if there are other attributes mixed in specific ways
            }
        }

        // Handle "seeds" attribute directly if used (unlikely in Anchor but possible in other contexts)
        if attr.path().is_ident("seeds") {
             if let Ok(expr) = attr.parse_args::<Expr>() {
                if let Expr::Array(array) = expr {
                    self.check_seeds_array(&array, attr.span());
                }
             }
        }
    }

    fn visit_expr_call(&mut self, expr: &'ast ExprCall) {
        // Check for Pubkey::find_program_address(seeds, program_id)
        // or Pubkey::create_program_address(seeds, program_id)
        if let Expr::Path(ExprPath { path, .. }) = &*expr.func {
             let path_str = path.to_token_stream().to_string().replace(" ", "");
             if path_str.contains("find_program_address") || path_str.contains("create_program_address") {
                 if let Some(seeds_arg) = expr.args.first() {
                     // The first argument is the seeds array/slice
                     // It might be a reference `&[...]` or just `[...]`
                     self.check_seeds_expr(seeds_arg, expr.span());
                 }
             }
        }

        syn::visit::visit_expr_call(self, expr);
    }
}

impl<'a> SeedCollisionVisitor<'a> {
    fn check_seeds_expr(&mut self, expr: &Expr, span: proc_macro2::Span) {
        // Handle `&[b"seed", ...]`
        if let Expr::Reference(expr_ref) = expr {
             self.check_seeds_expr(&expr_ref.expr, span);
             return;
        }

        // Handle `[b"seed", ...]` (ExprArray)
        if let Expr::Array(array) = expr {
             self.check_seeds_array(array, span);
        }

        // Handle `vec![b"seed", ...]` (Macro) - harder to parse, maybe skip for now or try string matching
        // If it's a variable, we can't easily check static analysis without data flow.
        // But for `find_program_address(&[b"prefix", ...])`, we catch it.
    }

    fn check_seeds_array(&mut self, array: &syn::ExprArray, span: proc_macro2::Span) {
        if array.elems.is_empty() {
            // Empty seeds? weird but maybe not a collision issue if intended.
            return;
        }

        // Check if the FIRST element is a literal string/byte string
        let first_elem = &array.elems[0];

        if !self.is_literal_string_or_bytes(first_elem) {
             self.findings.push(Finding {
                severity: Severity::Medium,
                certainty: Certainty::High,
                message: "PDA seeds should start with a hardcoded string literal (prefix) to prevent collisions. \
                         Example: seeds = [b\"my_seed\", user_pubkey.as_ref()].".to_string(),
                location: Location {
                    file: self.file_path.clone(),
                    line: span.start().line,
                    column: span.start().column,
                },
            });
        }
    }

    fn is_literal_string_or_bytes(&self, expr: &Expr) -> bool {
        // Check for b"string" or "string".as_bytes()

        // Case 1: Byte string literal b"..."
        if let Expr::Lit(lit) = expr {
            if let Lit::ByteStr(_) = &lit.lit {
                return true;
            }
            // "string" literal? Anchor seeds usually require bytes.
            // But sometimes people use "string".as_bytes()
        }

        // Case 2: Method call "string".as_bytes()
        if let Expr::MethodCall(method) = expr {
            if method.method == "as_bytes" {
                if let Expr::Lit(lit) = &*method.receiver {
                     if let Lit::Str(_) = &lit.lit {
                         return true;
                     }
                }
            }
        }

        // Case 3: Reference to literal `&b"string"` (sometimes happens in array construction)
        if let Expr::Reference(expr_ref) = expr {
            return self.is_literal_string_or_bytes(&expr_ref.expr);
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_seed_collision_vulnerable_anchor() {
        let code = r#"
        #[derive(Accounts)]
        pub struct Context<'info> {
            #[account(
                seeds = [user.key().as_ref(), other.key().as_ref()],
                bump
            )]
            pub pda: Account<'info, MyData>,
            pub user: Signer<'info>,
            pub other: AccountInfo<'info>,
        }
        "#;
        let program = create_program(code);
        let analyzer = SeedCollision;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("should start with a hardcoded string literal"));
    }

    #[test]
    fn test_seed_collision_secure_anchor() {
        let code = r#"
        #[derive(Accounts)]
        pub struct Context<'info> {
            #[account(
                seeds = [b"my_prefix", user.key().as_ref()],
                bump
            )]
            pub pda: Account<'info, MyData>,
        }
        "#;
        let program = create_program(code);
        let analyzer = SeedCollision;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_seed_collision_vulnerable_manual() {
        // Updated to use inline array
        let code = r#"
        fn derive(ctx: Context<Ix>) -> Result<()> {
            let (key, bump) = Pubkey::find_program_address(&[ctx.accounts.user.key.as_ref()], &program_id);
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = SeedCollision;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_seed_collision_secure_manual() {
        // Updated to use inline array
        let code = r#"
        fn derive(ctx: Context<Ix>) -> Result<()> {
            let (key, bump) = Pubkey::find_program_address(&[b"prefix", ctx.accounts.user.key.as_ref()], &program_id);
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = SeedCollision;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_seed_collision_secure_as_bytes() {
        let code = r#"
        #[derive(Accounts)]
        pub struct Context<'info> {
            #[account(
                seeds = ["my_prefix".as_bytes(), user.key().as_ref()],
                bump
            )]
            pub pda: Account<'info, MyData>,
        }
        "#;
        let program = create_program(code);
        let analyzer = SeedCollision;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
