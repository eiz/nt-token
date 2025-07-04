use nt_token::{Group, OwnedToken, Privilege, Sid, Token};
use windows::{
    Win32::Security::{
        CREATE_RESTRICTED_TOKEN_FLAGS, DISABLE_MAX_PRIVILEGE, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_DUPLICATE, TOKEN_QUERY, TokenImpersonation, WinBuiltinAdministratorsSid,
    },
    core::Result,
};

// Simple smoke-test: open the current process token and print some data. If
// anything panics or returns an `Err`, the test will fail.
fn print_token_info(tok: &Token) -> Result<()> {
    let user = tok.user()?;
    let (name, domain) = user.account()?;

    println!("user              = {user} ({domain}\\{name})");
    println!("elevated          = {}", tok.is_elevated()?);
    println!("primary token     = {}", tok.is_primary()?);
    if let Ok(is_admin) = tok.check_membership(&Sid::well_known(WinBuiltinAdministratorsSid)?) {
        println!("is admin          = {is_admin}");
    } else {
        println!("is admin          = (failed to check)");
    }
    println!("IL RID            = 0x{:x}", tok.integrity_level()?);
    println!("has restrictions  = {}", tok.has_restrictions()?);
    println!("virt allowed      = {}", tok.virtualization_allowed()?);
    println!("virt enabled      = {}", tok.virtualization_enabled()?);
    println!("ui access         = {}", tok.ui_access()?);
    println!("app container     = {}", tok.is_app_container()?);

    // App-container details (if present).
    match tok.app_container_sid()? {
        Some(ac_sid) => {
            let (ac_name, ac_domain) = ac_sid.account().unwrap_or_default();
            println!("app container SID = {ac_sid} ({ac_domain}\\{ac_name})");
        }
        None => println!("app container SID = (none)"),
    }

    println!("app container #   = {}", tok.app_container_number()?);

    let owner = tok.owner()?;
    let (owner_name, owner_domain) = owner.account().unwrap_or_default();
    println!("owner             = {owner} ({owner_domain}\\{owner_name})");

    let pg = tok.primary_group()?;
    let (pg_name, pg_domain) = pg.account().unwrap_or_default();
    println!("primary group     = {pg} ({pg_domain}\\{pg_name})");
    println!(
        "elevation type    = {}",
        match tok.elevation_type()?.0 {
            1 => "default",
            2 => "full",
            3 => "limited",
            _ => "unknown",
        }
    );

    for g in tok.groups()? {
        let (name, domain) = g.account()?;
        let attrs = g.attributes();
        println!("{:<25} -> {g} ({domain}\\{name}) ({attrs:08x})", "groups");
    }

    fn print_group_collection(label: &str, res: Result<Vec<Group>>) {
        match res {
            Ok(list) => {
                for g in list {
                    let (name, domain) = g.account().unwrap_or_default();
                    let attrs = g.attributes();
                    println!("{:<25} -> {g} ({domain}\\{name}) ({attrs:08x})", label);
                }
            }
            Err(e) => {
                println!("(failed to get {}: {:?})", label, e);
            }
        }
    }

    print_group_collection("capabilities", tok.capabilities());
    print_group_collection("logon SID", tok.logon_sid());
    print_group_collection("restricted SIDs", tok.restricted_sids());
    print_group_collection("device groups", tok.device_groups());
    print_group_collection("restricted device groups", tok.restricted_device_groups());

    for p in tok.privileges()? {
        println!(
            "{:<25} -> {} ({:?})",
            "privileges",
            p.name()?,
            p.is_enabled()
        );
    }

    Ok(())
}

#[test]
fn current_process_token_info() -> Result<()> {
    let tok = OwnedToken::from_current_process(TOKEN_QUERY | TOKEN_DUPLICATE)?;
    let impersonation = tok.duplicate(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TokenImpersonation)?;
    println!("=== Current Process Token ===");
    print_token_info(&tok)?;
    println!("=== Current Process Token (Impersonation) ===");
    print_token_info(&impersonation)?;

    match impersonation.linked_token() {
        Ok(linked) => {
            println!("\n=== Linked Token ===");
            print_token_info(&linked)?;
        }
        Err(e) => {
            println!("\n(no linked token: {e:?})");
        }
    }

    impersonation.adjust_privileges(&[Privilege::enabled("SeIncreaseWorkingSetPrivilege")?])?;
    Ok(())
}

#[test]
fn restricted_token() -> Result<()> {
    let tok = OwnedToken::from_current_process(TOKEN_QUERY | TOKEN_DUPLICATE)?
        .duplicate(TOKEN_QUERY | TOKEN_DUPLICATE, TokenImpersonation)?;
    let linked = tok.linked_token()?;
    let restricted = linked.create_restricted_token(
        DISABLE_MAX_PRIVILEGE,
        &[Group::disabled(Sid::well_known(
            WinBuiltinAdministratorsSid,
        )?)],
        &[],
        &[],
    )?;
    println!("=== New Restricted Token ===");
    print_token_info(&restricted)?;
    Ok(())
}
