use super::{Analyzer, Finding, Location, Severity, Certainty};
use crate::models::Program;
use syn::{visit::Visit, ItemFn, Attribute, spanned::Spanned};
use anyhow::Result;

pub struct ReentrancyAnalyzer;

struct ReentrancyVisitor {
    findings: Vec<Finding>,
    current_file: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for ReentrancyVisitor {
    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        // Check for #[instruction] attribute
        let is_instruction = function.attrs.iter().any(|attr| {
            attr.path().is_ident("instruction")
        });

        if !is_instruction {
            return;
        }

        // Check for CPI calls without proper checks
        let has_cpi = contains_cpi_calls(&function.block);
        let has_reentry_guard = has_reentry_protection(&function.attrs);

        if has_cpi && !has_reentry_guard {
            self.findings.push(Finding {
                severity: Severity::High,
                certainty: Certainty::Low,
                message: format!(
                    "The instruction '{}' contains CPI calls without reentrancy protection. \
                     Consider adding a reentrancy guard or ensuring state updates occur before external calls.",
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
}

fn contains_cpi_calls(block: &syn::Block) -> bool {
    struct CPIVisitor {
        has_cpi: bool,
    }

    impl<'ast> Visit<'ast> for CPIVisitor {
        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let path_str = path.path.segments.last()
                    .map(|seg| seg.ident.to_string())
                    .unwrap_or_default();
                
                if path_str.contains("invoke") || path_str.contains("cpi") {
                    self.has_cpi = true;
                }
            }
        }
    }

    let mut visitor = CPIVisitor { has_cpi: false };
    visitor.visit_block(block);
    visitor.has_cpi
}

fn has_reentry_protection(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("reentry_guard") || 
        attr.path().is_ident("access_control")
    })
}

impl Analyzer for ReentrancyAnalyzer {
    fn name(&self) -> &'static str {
        "Reentrancy Check"
    }

    fn description(&self) -> &'static str {
        "Checks for potential reentrancy vulnerabilities in instructions with CPI calls"
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Analyze each file in the program
        for (path, ast) in &program.asts {
            let mut visitor = ReentrancyVisitor {
                findings: Vec::new(),
                current_file: path.clone(),
            };
            visitor.visit_file(ast);
            findings.extend(visitor.findings);
        }

        Ok(findings)
    }
} 