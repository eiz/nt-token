use nt_token::OwnedToken;
use windows::{Win32::Security::TOKEN_QUERY, core::Result};

// Simple smoke-test: open the current process token and print some data. If
// anything panics or returns an `Err`, the test will fail.
#[test]
fn current_process_token_info() -> Result<()> {
    let tok = OwnedToken::from_current_process(TOKEN_QUERY)?;
    let user = tok.user()?;
    let (name, domain) = user.account()?;

    println!("user = {domain}\\{name}");
    println!("elevated = {}", tok.is_elevated()?);
    println!("IL RID  = 0x{:x}", tok.integrity_level()?);

    for g in tok.groups()? {
        let (name, domain) = g.account()?;
        println!("group -> {g} ({domain}\\{name})");
    }

    Ok(())
}
