use anchor_lang::prelude::*;

declare_id!("CZZthf5HLnBBh2ACvdee7TBaqJAJ8J93hP2ZwC8yFm1T");

#[program]
pub mod anchor_example_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}


#[cfg(test)]
mod tests {
    use super::*;
    use solana_fender;

    #[test]
    fn test_security() {
        // Pass a marker type that represents the anchor_example_program module
        // This allows solana_fender to analyze the module directly
        struct AnchorExampleProgramMarker;
        let findings = solana_fender::analyze_program(AnchorExampleProgramMarker).unwrap();
        assert!(findings.is_empty(), "Security vulnerabilities found: {:?}", findings);
    }
    
    #[test]
    fn test_security_with_module_name() {
        // You can also use a string to represent the module name
        // This is useful when you want to analyze a module that's not in the current crate
        let findings = solana_fender::analyze_program_by_name("anchor_example_program").unwrap();
        assert!(findings.is_empty(), "Security vulnerabilities found: {:?}", findings);
    }
}