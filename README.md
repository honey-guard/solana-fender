# Solana Fender

![License: MIT](https://img.shields.io/badge/License-MIT-red.svg) [![Crates.io](https://img.shields.io/crates/v/solana_fender?color=blue)](https://crates.io/crates/solana_fender) <img alt="GitHub Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/honey-guard/solana-fender/rust.yml">

Solana static analysis tool built in rust for anchor programs. Can be used as a rust crate for unit testing or as a CLI tool.

## CLI Tool 

### ⚙️ Installation

#### Install via Cargo ( Recommended )

```bash
cargo install solana_fender
```

#### Install via Source

```bash
git clone https://github.com/honey-guard/solana-fender.git
cd solana-fender
cargo build
```

### Usage

Tip: Clone [sealevel-attacks](https://github.com/coral-xyz/sealevel-attacks) as a test case to sample this program.

#### Cargo
```bash
solana_fender --program <path-to-program>
```

#### Source
```bash
cargo run -- --program <path-to-program>
```

## Unit Testing Crate Usage

You can also use Solana Fender as a development dependency in your Anchor projects to run security checks as part of your unit tests.

### Add as a Dev Dependency

Add Solana Fender to your program's `Cargo.toml`:

```toml
[dev-dependencies]
solana_fender = "0.2.0"  # Replace with the latest version
```

### Example Usage in Tests

Check `/examples` for more examples.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use solana_fender;

    #[test]
    fn test_security() {
        // Pass a marker type that represents your program module
        struct MyProgramMarker;
        let findings = solana_fender::analyze_program(MyProgramMarker).unwrap();
        assert!(findings.is_empty(), "Security vulnerabilities found: {:?}", findings);
    }
    
    #[test]
    fn test_security_with_module_name() {
        // Alternatively, use a string to represent the module name
        let findings = solana_fender::analyze_program_by_name("my_program").unwrap();
        assert!(findings.is_empty(), "Security vulnerabilities found: {:?}", findings);
    }
}
```

This allows you to integrate security checks directly into your test suite, ensuring that your program remains secure as you develop it.
