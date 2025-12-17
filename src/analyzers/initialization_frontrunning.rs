use super::{Analyzer, Finding, Severity, Certainty, Location};
use crate::models::Program;
use anyhow::Result;
use syn::{visit::Visit, ItemStruct, ItemFn, Attribute};
use quote::ToTokens;
use std::collections::HashMap;

pub struct InitializationFrontrunning;

impl Analyzer for InitializationFrontrunning {
    fn name(&self) -> &'static str {
        "Initialization Frontrunning"
    }

    fn description(&self) -> &'static str {
        "Global accounts (singletons) initialized with static seeds should be protected by authority checks \
         to prevent front-running attacks where an attacker initializes the account with their own values."
    }

    fn analyze(&self, program: &Program) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Global map of vulnerable structs across all files
        let mut global_vulnerable_structs = HashMap::new();

        // First pass: Find structs with vulnerable static seed initializations in ALL files
        for (path, ast) in &program.asts {
            let mut struct_visitor = SingletonStructVisitor {
                vulnerable_structs: HashMap::new(),
                file_path: path.to_string_lossy().to_string(),
            };
            syn::visit::visit_file(&mut struct_visitor, ast);

            // Merge into global map
            global_vulnerable_structs.extend(struct_visitor.vulnerable_structs);
        }

        // Second pass: Find functions using these structs and check for manual validation in ALL files
        for (path, ast) in &program.asts {
            let mut fn_visitor = InitializationVisitor {
                findings: &mut findings,
                file_path: path.to_string_lossy().to_string(),
                vulnerable_structs: &global_vulnerable_structs,
            };
            syn::visit::visit_file(&mut fn_visitor, ast);
        }

        Ok(findings)
    }
}

// Stores info about a struct that might be vulnerable
#[derive(Clone)]
struct VulnerableStructInfo {
    struct_name: String,
    account_field: String,
    location: Location,
}

struct SingletonStructVisitor {
    // Map of Struct Name -> Info
    vulnerable_structs: HashMap<String, VulnerableStructInfo>,
    file_path: String,
}

impl<'ast> Visit<'ast> for SingletonStructVisitor {
    fn visit_item_struct(&mut self, item_struct: &'ast ItemStruct) {
        // Check if it derives Accounts
        let is_accounts = item_struct.attrs.iter().any(|attr| {
             let s = attr.to_token_stream().to_string();
             s.contains("derive") && s.contains("Accounts")
        });

        if !is_accounts {
            return;
        }

        let struct_name = item_struct.ident.to_string();

        for field in &item_struct.fields {
            // Check for #[account(init, ...)]
            let account_attr = field.attrs.iter().find(|attr| {
                attr.path().is_ident("account")
            });

            if let Some(attr) = account_attr {
                let attr_str = attr.to_token_stream().to_string();

                // Must be an initialization
                if !attr_str.contains("init") {
                    continue;
                }

                // Check seeds
                if let Some(seeds) = parse_seeds_from_attr(attr) {
                    if is_static_seeds(&seeds) {
                        // It's a singleton initialization.
                        // Check if there is a constraint protecting it.
                        // We look for constraints that check "signer" or "authority" against a known value.
                        // Or just ANY constraint that is not the seeds/bump/space constraint.

                        if !has_authority_constraint(&attr_str) {
                            let field_name = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                            let span = field.ident.as_ref().map(|i| i.span()).unwrap_or_else(|| item_struct.ident.span());

                            self.vulnerable_structs.insert(struct_name.clone(), VulnerableStructInfo {
                                struct_name: struct_name.clone(),
                                account_field: field_name,
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
    }
}

struct InitializationVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    file_path: String,
    vulnerable_structs: &'a HashMap<String, VulnerableStructInfo>,
}

impl<'a, 'ast> Visit<'ast> for InitializationVisitor<'a> {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        // Check if this function uses one of the vulnerable structs in Context
        let mut context_struct_name = None;

        for input in &func.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = input {
                let ty_str = pat_type.ty.to_token_stream().to_string();
                if ty_str.contains("Context") {
                     if let Some(start) = ty_str.find('<') {
                        if let Some(end) = ty_str.find('>') {
                            let name = ty_str[start+1..end].trim().to_string();
                            context_struct_name = Some(name);
                        }
                    }
                }
            }
        }

        if let Some(struct_name) = context_struct_name {
            if let Some(info) = self.vulnerable_structs.get(&struct_name) {
                // We found a function using a vulnerable struct.
                // Check if the function body has manual checks.

                let body_str = func.block.to_token_stream().to_string();
                let has_manual_check = body_str.contains("require!") ||
                                       (body_str.contains("if") && (body_str.contains("return Err") || body_str.contains("return err")));

                // We can be more specific: does it check equality with a privileged account?
                let looks_like_auth_check = has_manual_check && (
                    body_str.contains("==") || body_str.contains("!=")
                ) && (
                    body_str.contains("authority") || body_str.contains("admin") || body_str.contains("program_data") || body_str.contains("owner")
                );

                if !looks_like_auth_check {
                    // Use location from the struct definition, but modify message to indicate usage in this function?
                    // The finding should point to the struct field because that's where the vulnerability is rooted (missing constraint).
                    // But maybe user wants to know which function triggers it.
                    // The standard practice in this repo seems to be pointing to where the vulnerability is defined or used.
                    // Since we iterate functions, let's report it for each usage, but point to the struct location?
                    // Or point to the function?
                    // If we point to the struct, we might report duplicates if used in multiple functions.
                    // Let's point to the struct location as it is the source of the issue (missing constraint).
                    // To avoid duplicates, we might want to track reported structs.
                    // But `findings` is a Vec.

                    // Actually, if we are analyzing per function, it's better to report "Function X uses insecure struct Y".
                    // But the Finding message in my previous code was about "Global account initialized...".
                    // Let's stick to the struct location.

                    self.findings.push(Finding {
                        severity: Severity::Medium,
                        certainty: Certainty::Medium,
                        message: format!(
                            "Global account '{}' initialized in function '{}' using static seeds without apparent authority validation. \
                             Ensure only authorized users can initialize this singleton to prevent front-running.",
                            info.account_field,
                            func.sig.ident
                        ),
                        location: info.location.clone(),
                    });
                }
            }
        }
    }
}

// Helpers

fn parse_seeds_from_attr(attr: &Attribute) -> Option<String> {
    let attr_str = attr.to_token_stream().to_string();
    if let Some(idx) = attr_str.find("seeds") {
        if let Some(start) = attr_str[idx..].find('[') {
            let start_pos = idx + start;
            let mut depth = 0;
            for (i, c) in attr_str[start_pos..].char_indices() {
                if c == '[' { depth += 1; }
                else if c == ']' {
                    depth -= 1;
                    if depth == 0 {
                        return Some(attr_str[start_pos..=start_pos+i].to_string());
                    }
                }
            }
        }
    }
    None
}

fn is_static_seeds(seeds: &str) -> bool {
    // Remove the outer brackets
    let inner = seeds.trim_start_matches('[').trim_end_matches(']');

    for part in inner.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }

        // Allowed: b"literal", "literal", &[...], literal numbers
        let is_byte_string = part.starts_with("b\"") || part.starts_with("b'");
        let is_string = part.starts_with('"') || part.starts_with('\'');

        // Check for numeric literals (digits)
        // This covers 1, 100, etc.
        let is_number = part.chars().all(|c| c.is_digit(10));

        // Check for byte array ref &[...] (often used for nested seeds in tests but anchor seeds are usually flat or bytes)
        // If it starts with `&`, it might be a reference. `&[u8; 1]`?
        // Anchor seeds usually take `&[u8]`.
        // If it is `&[1,2,3]`, it is static.
        // If it is `&var`, it is dynamic.
        // This simple parser might fail on complex expressions.

        if !is_byte_string && !is_string && !is_number {
            // If it's not a string/byte-string/number, assume it's a variable or function call
            return false;
        }
    }
    true
}

fn has_authority_constraint(attr_str: &str) -> bool {
    if let Some(idx) = attr_str.find("constraint") {
        let suffix = &attr_str[idx..];
        if suffix.contains("program_data") ||
           suffix.contains("upgrade_authority") ||
           suffix.contains("admin") ||
           (suffix.contains("signer") && (suffix.contains("==") || suffix.contains("!="))) ||
           (suffix.contains("authority") && (suffix.contains("==") || suffix.contains("!="))) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::test_utils::create_program;

    #[test]
    fn test_initialization_frontrunning_vulnerable() {
        let code = r#"
        #[derive(Accounts)]
        pub struct InitializeInsecure<'info> {
            #[account(mut)]
            pub signer: Signer<'info>,
            #[account(
                init,
                payer = signer,
                space = 8 + 8,
                seeds = [b"config"],
                bump
            )]
            pub global_config: Account<'info, GlobalConfig>,
            pub system_program: Program<'info, System>,
        }

        pub fn initialize(ctx: Context<InitializeInsecure>) -> Result<()> {
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = InitializationFrontrunning;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Global account 'global_config' initialized in function 'initialize' using static seeds"));
    }

    #[test]
    fn test_initialization_frontrunning_secure_constraint() {
        let code = r#"
        #[derive(Accounts)]
        pub struct InitializeSecure<'info> {
            #[account(mut)]
            pub signer: Signer<'info>,
            #[account(
                init,
                payer = signer,
                space = 8 + 8,
                seeds = [b"config"],
                bump,
                constraint = signer.key() == program_data.upgrade_authority_address.unwrap_or_default()
            )]
            pub global_config: Account<'info, GlobalConfig>,
            #[account(seeds = [crate::ID.as_ref()], bump, seeds::program = bpf_loader_upgradeable::id())]
            pub program_data: Account<'info, ProgramData>,
            pub system_program: Program<'info, System>,
        }

        pub fn initialize(ctx: Context<InitializeSecure>) -> Result<()> {
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = InitializationFrontrunning;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_initialization_frontrunning_dynamic_seeds() {
        let code = r#"
        #[derive(Accounts)]
        pub struct InitializeDynamic<'info> {
            #[account(mut)]
            pub signer: Signer<'info>,
            #[account(
                init,
                payer = signer,
                space = 8 + 8,
                seeds = [b"user", signer.key().as_ref()],
                bump
            )]
            pub user_account: Account<'info, UserAccount>,
            pub system_program: Program<'info, System>,
        }

        pub fn initialize(ctx: Context<InitializeDynamic>) -> Result<()> {
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = InitializationFrontrunning;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_initialization_frontrunning_numeric_seeds() {
        // Test with numeric static seeds
        let code = r#"
        #[derive(Accounts)]
        pub struct InitializeNumeric<'info> {
            #[account(mut)]
            pub signer: Signer<'info>,
            #[account(
                init,
                payer = signer,
                space = 8 + 8,
                seeds = [b"version", 1],
                bump
            )]
            pub versioned_config: Account<'info, Config>,
            pub system_program: Program<'info, System>,
        }

        pub fn initialize(ctx: Context<InitializeNumeric>) -> Result<()> {
            Ok(())
        }
        "#;
        let program = create_program(code);
        let analyzer = InitializationFrontrunning;
        let findings = analyzer.analyze(&program).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Global account 'versioned_config'"));
    }
}
