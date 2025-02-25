# Solana Fender
![License: MIT](https://img.shields.io/badge/License-MIT-red.svg) [![Crates.io](https://img.shields.io/crates/v/solana_fender?color=blue)](https://crates.io/crates/solana_fender) <img alt="GitHub Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/honey-guard/solana-fender/rust.yml">

Solana static analysis tool built in rust for anchor programs.

## ⚙️ Installation

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

## Usage

Tip: Clone [sealevel-attacks](https://github.com/coral-xyz/sealevel-attacks) as a test case to sample this program.

#### Cargo
```bash
solana_fender --program <path-to-program>
```

#### Source
```bash
cargo run -- --program <path-to-program>
```
