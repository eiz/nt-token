# nt-token

[![CI](https://github.com/eiz/nt-token/actions/workflows/ci.yml/badge.svg)](https://github.com/eiz/nt-token/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/nt-token.svg)](https://crates.io/crates/nt-token)
[![docs.rs](https://docs.rs/nt-token/badge.svg)](https://docs.rs/nt-token)
[![license](https://img.shields.io/crates/l/nt-token.svg)](LICENSE)

Memory-safe, ergonomic helpers for working with Windows access tokens and security identifiers (SIDs) – built on top of the `windows` crate.

```rust
use nt_token::{OwnedToken, Sid};
use windows::Win32::Security::TOKEN_QUERY;

fn main() -> windows::core::Result<()> {
    let token = OwnedToken::from_current_process(TOKEN_QUERY)?;
    println!("elevated = {}", token.is_elevated()?);
    println!("integrity level = 0x{:x}", token.integrity_level()?);

    for g in token.groups()? {
        println!("group → {}", g);
    }
    Ok(())
}
```

---

<sub>AI DISCLAIMER: Parts of this project were originally scaffolded with assistance from OpenAI's "o3" model and have since been heavily reviewed. No warranty, express or implied.</sub>

