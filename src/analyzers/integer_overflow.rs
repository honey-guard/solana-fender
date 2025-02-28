use super::{Analyzer, Finding, Location, Severity, Certainty};
use crate::models::Program;
use syn::{visit::Visit, BinOp, Expr, spanned::Spanned};
use anyhow::Result;

pub struct IntegerOverflowAnalyzer;

struct OverflowVisitor {
    findings: Vec<Finding>,
    current_file: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for OverflowVisitor {
    fn visit_expr_binary(&mut self, expr: &'ast syn::ExprBinary) {
        // Check for arithmetic operations on numeric types
        if is_arithmetic_op(&expr.op) {
            if !is_checked_arithmetic(expr) {
                self.findings.push(Finding {
                    severity: Severity::Medium,
                    certainty: Certainty::High,
                    message: format!(
                        "Unchecked arithmetic operation found: {}. \
                         Consider using checked_add, checked_mul, etc., or SafeMath.",
                        expr_to_string(expr)
                    ),
                    location: Location {
                        file: self.current_file.to_string_lossy().to_string(),
                        line: expr.span().start().line,
                        column: expr.span().start().column,
                    },
                });
            }
        }
    }
}

fn is_arithmetic_op(op: &BinOp) -> bool {
    matches!(op,
        BinOp::Add(_) |
        BinOp::Sub(_) |
        BinOp::Mul(_) |
        BinOp::Div(_)
    )
}

fn is_checked_arithmetic(expr: &syn::ExprBinary) -> bool {
    // Check if the operation is wrapped in a checked_* call
    if let Expr::MethodCall(method_call) = &*expr.left {
        let method_name = method_call.method.to_string();
        method_name.starts_with("checked_") ||
        method_name.starts_with("saturating_") ||
        method_name.starts_with("wrapping_")
    } else {
        false
    }
}

fn expr_to_string(expr: &syn::ExprBinary) -> String {
    fn path_to_string(expr: &syn::Expr) -> String {
        if let syn::Expr::Path(path) = expr {
            path.path.segments.last()
                .map(|seg| seg.ident.to_string())
                .unwrap_or_default()
        } else {
            expr_to_string_inner(expr)
        }
    }

    fn expr_to_string_inner(expr: &syn::Expr) -> String {
        match expr {
            syn::Expr::Binary(bin) => {
                format!("{} {} {}", 
                    path_to_string(&*bin.left),
                    op_to_string(&bin.op),
                    path_to_string(&*bin.right)
                )
            },
            syn::Expr::Lit(lit) => format!("{:?}", lit.lit),
            _ => "...".to_string(),
        }
    }

    fn op_to_string(op: &syn::BinOp) -> &'static str {
        match op {
            syn::BinOp::Add(_) => "+",
            syn::BinOp::Sub(_) => "-",
            syn::BinOp::Mul(_) => "*",
            syn::BinOp::Div(_) => "/",
            _ => "?",
        }
    }

    expr_to_string_inner(&syn::Expr::Binary(expr.clone()))
}

impl Analyzer for IntegerOverflowAnalyzer {
    fn name(&self) -> &'static str {
        "Integer Overflow Check"
    }

    fn description(&self) -> &'static str {
        "Checks for potential integer overflow vulnerabilities in arithmetic operations"
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Analyze each file in the program
        for (path, ast) in &program.asts {
            let mut visitor = OverflowVisitor {
                findings: Vec::new(),
                current_file: path.clone(),
            };
            visitor.visit_file(ast);
            findings.extend(visitor.findings);
        }

        Ok(findings)
    }
} 