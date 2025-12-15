use super::{Analyzer, Finding, Location, Severity, Certainty};
use crate::models::Program;
use syn::{visit::Visit, Expr, BinOp, spanned::Spanned};
use anyhow::Result;

pub struct PrecisionLossAnalyzer;

impl Analyzer for PrecisionLossAnalyzer {
    fn name(&self) -> &'static str {
        "Precision Loss"
    }

    fn description(&self) -> &'static str {
        "Checks for integer division before multiplication which causes precision loss. \
         Example: (a / b) * c should be (a * c) / b."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (path, ast) in &program.asts {
            let mut visitor = PrecisionLossVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
            };
            syn::visit::visit_file(&mut visitor, ast);
        }

        Ok(findings)
    }
}

struct PrecisionLossVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
}

impl<'a, 'ast> Visit<'ast> for PrecisionLossVisitor<'a> {
    fn visit_expr_binary(&mut self, expr: &'ast syn::ExprBinary) {
        // Check for (a / b) * c
        if let BinOp::Mul(_) = expr.op {
            // Check left side: (a / b) * c
            // Sometimes it's wrapped in Paren, so we need to unwrap parens
            if is_expr_div(&expr.left) {
                self.report_finding(expr);
            }

            // Check right side: c * (a / b)
            if is_expr_div(&expr.right) {
                self.report_finding(expr);
            }
        }

        // Continue visiting
        syn::visit::visit_expr_binary(&mut *self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        // Check for checked_div followed by checked_mul
        // Pattern: something.checked_div(x).unwrap().checked_mul(y)
        // Or: something.checked_div(x)?.checked_mul(y)

        let method_name = expr.method.to_string();

        if method_name == "checked_mul" || method_name == "saturating_mul" || method_name == "wrapping_mul" {
            // Check receiver
            let receiver = &*expr.receiver;

            // Receiver could be a method call (checked_div) or an unwrapped/question-marked method call
            if is_result_of_div(receiver) {
                self.report_finding(expr);
            }
        }

        // Continue visiting
        syn::visit::visit_expr_method_call(&mut *self, expr);
    }
}

impl<'a> PrecisionLossVisitor<'a> {
    fn report_finding(&mut self, expr: &impl Spanned) {
        self.findings.push(Finding {
            severity: Severity::Medium,
            certainty: Certainty::High,
            message: format!("Potential precision loss detected. Integer division before multiplication \
                             can lose precision. Consider changing (a / b) * c to (a * c) / b."),
            location: Location {
                file: self.file_path.clone(),
                line: expr.span().start().line,
                column: expr.span().start().column,
            },
        });
    }
}

fn is_expr_div(expr: &Expr) -> bool {
    match expr {
        Expr::Binary(bin) => matches!(bin.op, BinOp::Div(_)),
        Expr::Paren(paren) => is_expr_div(&paren.expr),
        _ => false,
    }
}

fn is_result_of_div(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(call) => {
            let name = call.method.to_string();
            if name == "checked_div" || name == "div" || name == "saturating_div" || name == "wrapping_div" {
                return true;
            }
            // If it's unwrap() or expect(), check the receiver of that
            if name == "unwrap" || name == "expect" {
                return is_result_of_div(&*call.receiver);
            }
            false
        },
        Expr::Try(try_expr) => {
            // Handle '?' operator: expr?
            is_result_of_div(&*try_expr.expr)
        },
        Expr::Paren(paren) => {
             is_result_of_div(&*paren.expr)
        },
        _ => false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_precision_loss_binary_op() {
        let code = r#"
        pub fn calculate(amount: u64) -> u64 {
            let x = 100;
            let y = 50;
            // Vulnerable: (amount / x) * y
            let result = amount / x * y;
            result
        }
        "#;
        let program = create_program(code);
        let analyzer = PrecisionLossAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Precision loss") || findings[0].message.contains("precision loss"));
    }

    #[test]
    fn test_precision_loss_parentheses() {
        let code = r#"
        pub fn calculate(amount: u64) -> u64 {
            let x = 100;
            let y = 50;
            // Vulnerable: (amount / x) * y
            let result = (amount / x) * y;
            result
        }
        "#;
        let program = create_program(code);
        let analyzer = PrecisionLossAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1, "Expected 1 finding, got {}", findings.len());
    }

    #[test]
    fn test_precision_loss_checked() {
        let code = r#"
        pub fn calculate(amount: u64) -> Option<u64> {
            let x = 100;
            let y = 50;
            // Vulnerable: amount.checked_div(x)?.checked_mul(y)
            let result = amount.checked_div(x)?.checked_mul(y)?;
            Some(result)
        }
        "#;
        let program = create_program(code);
        let analyzer = PrecisionLossAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1, "Expected 1 finding, got {}", findings.len());
    }

    #[test]
    fn test_precision_loss_unwrap() {
        let code = r#"
        pub fn calculate(amount: u64) -> u64 {
            let x = 100;
            let y = 50;
            // Vulnerable: amount.checked_div(x).unwrap().checked_mul(y)
            let result = amount.checked_div(x).unwrap().checked_mul(y).unwrap();
            result
        }
        "#;
        let program = create_program(code);
        let analyzer = PrecisionLossAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1, "Expected 1 finding, got {}", findings.len());
    }

    #[test]
    fn test_no_precision_loss_mult_first() {
        let code = r#"
        pub fn calculate(amount: u64) -> u64 {
            let x = 100;
            let y = 50;
            // Safe: (amount * y) / x
            let result = amount * y / x;
            result
        }
        "#;
        let program = create_program(code);
        let analyzer = PrecisionLossAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_no_precision_loss_checked_mult_first() {
        let code = r#"
        pub fn calculate(amount: u64) -> Option<u64> {
            let x = 100;
            let y = 50;
            // Safe: amount.checked_mul(y)?.checked_div(x)
            let result = amount.checked_mul(y)?.checked_div(x)?;
            Some(result)
        }
        "#;
        let program = create_program(code);
        let analyzer = PrecisionLossAnalyzer;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
