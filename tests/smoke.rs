use nt_token::{OwnedToken, Privilege};
use windows::{
    Win32::Security::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY},
    core::Result,
};

// Simple smoke-test: open the current process token and print some data. If
// anything panics or returns an `Err`, the test will fail.
fn print_token_info(tok: &OwnedToken) -> Result<()> {
    let user = tok.user()?;
    let (name, domain) = user.account()?;

    println!("user       = {domain}\\{name}");
    println!("elevated   = {}", tok.is_elevated()?);
    println!("IL RID    = 0x{:x}", tok.integrity_level()?);

    for g in tok.groups()? {
        let (name, domain) = g.account()?;
        let attrs = g.attributes();
        println!("group      -> {g} ({domain}\\{name}) ({attrs:08x})");
    }

    for p in tok.privileges()? {
        println!("privilege  -> {} ({:?})", p.name()?, p.is_enabled());
    }

    Ok(())
}

#[test]
fn current_process_token_info() -> Result<()> {
    let tok = OwnedToken::from_current_process(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)?;
    println!("=== Current Process Token ===");
    print_token_info(&tok)?;

    match tok.linked_token() {
        Ok(linked) => {
            println!("\n=== Linked Token ===");
            print_token_info(&linked)?;
        }
        Err(e) => {
            println!("\n(no linked token: {e:?})");
        }
    }

    tok.adjust_privileges(&[Privilege::enabled("SeIncreaseWorkingSetPrivilege")?])?;
    Ok(())
}
