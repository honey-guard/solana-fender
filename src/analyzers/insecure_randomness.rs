use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ExprBinary, ExprMethodCall, BinOp, spanned::Spanned, ExprPath};
use quote::ToTokens;

pub struct InsecureRandomnessAnalyzer;

impl Analyzer for InsecureRandomnessAnalyzer {
    fn name(&self) -> &'static str {
        "Insecure Randomness"
    }

    fn description(&self) -> &'static str {
        "Using predictable on-chain data (like block hashes, timestamps, or slot numbers) for randomness \
         is insecure because validators can manipulate these values to some extent. \
         For high-value applications, use a verifiable randomness function (VRF) like Oracle."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (path, ast) in &program.asts {
            let mut visitor = InsecureRandomnessVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
            };
            syn::visit::visit_file(&mut visitor, ast);
        }

        Ok(findings)
    }
}

struct InsecureRandomnessVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
}

impl<'a, 'ast> Visit<'ast> for InsecureRandomnessVisitor<'a> {
    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        let path_str = path.path.to_token_stream().to_string();

        // Check for direct usage of predictable sysvars
        if path_str.contains("SlotHashes") || path_str.contains("RecentBlockhashes") {
             self.findings.push(Finding {
                severity: Severity::Medium,
                certainty: Certainty::High,
                message: format!("Usage of '{}' detected. These sysvars are predictable and should not be used for randomness.", path_str),
                location: Location {
                    file: self.file_path.clone(),
                    line: path.span().start().line,
                    column: path.span().start().column,
                },
            });
        }

        // Don't call default visit_expr_path as it visits path segments which we don't need to visit individually usually
        // But if we want to be safe we can.
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_binary(&mut self, binary: &'ast ExprBinary) {
        // Check for modulo operator which often indicates randomness generation
        if let BinOp::Rem(_) = binary.op {
            let left_str = binary.left.to_token_stream().to_string();

            // Check if the left side uses Clock timestamp or slot
            // match both "Clock::get()?.unix_timestamp" and "clock.unix_timestamp"
            // we look for the field name "unix_timestamp" or "slot"
            if left_str.contains("unix_timestamp") || left_str.contains("slot") {
                 self.findings.push(Finding {
                    severity: Severity::Medium,
                    certainty: Certainty::Medium,
                    message: "Using Clock timestamp or slot for randomness (detected modulo operation) is insecure as it can be manipulated by validators.".to_string(),
                    location: Location {
                        file: self.file_path.clone(),
                        line: binary.span().start().line,
                        column: binary.span().start().column,
                    },
                });
            }
        }

        // Continue visiting children
        syn::visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let method_name = call.method.to_string();
        let receiver_str = call.receiver.to_token_stream().to_string();

        if (receiver_str.contains("Clock") || receiver_str.contains("sysvar")) &&
           (method_name == "unix_timestamp" || method_name == "slot") {
             // We only flag this if we see a modulo operation in the parent,
             // but `visit_expr_binary` handles that.
        }

        syn::visit::visit_expr_method_call(self, call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_insecure_randomness_timestamp_modulo() {
        let code = r#"
        pub fn gamble(ctx: Context<Gamble>) -> Result<()> {
            let clock = Clock::get()?;
            let random = clock.unix_timestamp % 100;
            if random == 0 {
                msg!("Winner!");
            }
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = InsecureRandomnessAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Using Clock timestamp or slot for randomness"));
    }

    #[test]
    fn test_insecure_randomness_slothashes() {
        // We use a slightly different code pattern to make sure it's parsed as we expect
        // Using explicit Sysvar usage
        let code = r#"
        use solana_program::sysvar::slot_hashes::SlotHashes;
        pub fn gamble() {
            // This should trigger visit_expr_path for SlotHashes::get
            let x = SlotHashes::get();
            // This should trigger visit_expr_path for SlotHashes
            let y: SlotHashes = Default::default();
        }
        "#;

        let program = create_program(code);
        let analyzer = InsecureRandomnessAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();

        assert!(!findings.is_empty());
        assert!(findings[0].message.contains("Usage of '"));
        assert!(findings[0].message.contains("SlotHashes"));
    }

    #[test]
    fn test_secure_randomness_oracle() {
         let code = r#"
        pub fn gamble(ctx: Context<Gamble>) -> Result<()> {
            let randomness = oracle::get_randomness()?;
            let result = randomness[0] % 100;
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = InsecureRandomnessAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
