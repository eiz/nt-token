//! Safe, ergonomic wrappers for Windows **access tokens** and **SIDs** using the `windows` crate.
//!
//! The design intentionally mirrors `PathBuf`/`Path`:
//! * **`OwnedToken`** – owns the underlying `HANDLE` and closes it on `Drop`.
//! * **`TokenRef`** – a transparent, zero‑cost view; every high‑level API lives here.
//! * **`Deref` implementation** lets you call `token.is_elevated()` directly on an `OwnedToken`.
//!
//! ```toml
//! [dependencies]
//! windows = { version = "0.57", features = [
//!     "Win32_Foundation", "Win32_Security",
//!     "Win32_System_Threading", "Win32_System_Memory",
//! ] }
//! ```
//!
//! ## Quick example
//! ```rust
//! use nt_token::{OwnedToken, Sid};
//! use windows::Win32::Security::TOKEN_QUERY;
//!
//! # fn main() -> windows::core::Result<()> {
//! let tok = OwnedToken::from_current_process(TOKEN_QUERY)?;
//! println!("elevated = {}",  tok.is_elevated()?);       // <‑‑ via Deref
//! println!("IL RID  = 0x{:x}", tok.integrity_level()?);
//! for g in tok.groups()? { println!("group → {g}"); }
//! # Ok(()) }
//! ```
//!
//! ---
//! **Highlights**
//! * `TokenRef` is `#[repr(transparent)]`, `Copy`, and has **no lifetime parameter**.
//! * `OwnedToken: Deref<Target = TokenRef>` – zero‑cost cast (same layout).
//! * `Sid` covers canonical formatting, parsing, well‑known SIDs, and name lookup.
//!
//! Feel free to extend with more `GetTokenInformation` variants – the pattern is identical.

use std::{ffi::c_void, ops::Deref};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree, PSID},
        Security::{
            Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
            CreateWellKnownSid, DuplicateTokenEx, GetLengthSid, GetSidSubAuthority,
            GetSidSubAuthorityCount, GetTokenInformation, LookupAccountSidW, SID_NAME_USE,
            SecurityImpersonation, TOKEN_ACCESS_MASK, TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE,
            TOKEN_GROUPS, TOKEN_LINKED_TOKEN, TOKEN_MANDATORY_LABEL, TOKEN_USER, TokenElevation,
            TokenElevationType, TokenGroups, TokenIntegrityLevel, TokenLinkedToken, TokenPrimary,
            TokenUser, WELL_KNOWN_SID_TYPE,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
    core::{Error, PCWSTR, PWSTR, Result},
};

// NEW: helper to accept the common ERROR_INSUFFICIENT_BUFFER probe failure
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;

#[inline]
fn buffer_probe(res: Result<()>) -> Result<()> {
    match res {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => Ok(()),
        Err(e) => Err(e),
    }
}

/* ------------------------------------------------------------------------- */
/* OwnedToken                                                                */
/* ------------------------------------------------------------------------- */

/// RAII owner for a Windows access‑token `HANDLE`.
#[derive(Debug)]
#[repr(transparent)]
pub struct OwnedToken {
    handle: HANDLE,
}

impl OwnedToken {
    /// Open the current process token with the requested access rights.
    pub fn from_current_process(access: TOKEN_ACCESS_MASK) -> Result<Self> {
        unsafe {
            let mut h = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), access, &mut h)?;
            Ok(Self { handle: h })
        }
    }
}

impl Drop for OwnedToken {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle).ok() };
    }
}

impl Deref for OwnedToken {
    type Target = TokenRef;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(self as *const OwnedToken as *const TokenRef) }
    }
}

/* ------------------------------------------------------------------------- */
/* TokenRef                                                                  */
/* ------------------------------------------------------------------------- */

/// Borrowed, zero‑cost view of a token `HANDLE` (like `Path`).
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct TokenRef {
    handle: HANDLE,
}

impl TokenRef {
    /// Raw handle (borrowed).
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Duplicate the referenced token.
    pub fn duplicate(&self, access: TOKEN_ACCESS_MASK) -> Result<OwnedToken> {
        unsafe {
            let mut dup = HANDLE::default();
            DuplicateTokenEx(
                self.handle,
                access,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut dup,
            )?;
            Ok(OwnedToken { handle: dup })
        }
    }

    /// Is the token elevated (Vista+ UAC)?
    pub fn is_elevated(&self) -> Result<bool> {
        unsafe {
            let mut elev: TOKEN_ELEVATION = std::mem::zeroed();
            let mut ret = 0u32;
            GetTokenInformation(
                self.handle,
                TokenElevation,
                Some(&mut elev as *mut _ as *mut c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret,
            )?;
            Ok(elev.TokenIsElevated != 0)
        }
    }

    /// Return integrity‑level RID (e.g. `0x1000 == medium`).
    pub fn integrity_level(&self) -> Result<u32> {
        unsafe {
            let mut len = 0u32;
            // Probe once – an ERROR_INSUFFICIENT_BUFFER reply just tells us how much to allocate.
            buffer_probe(GetTokenInformation(
                self.handle,
                TokenIntegrityLevel,
                None,
                0,
                &mut len,
            ))?;
            let mut buf = vec![0u8; len as usize];
            GetTokenInformation(
                self.handle,
                TokenIntegrityLevel,
                Some(buf.as_mut_ptr() as *mut c_void),
                len,
                &mut len,
            )?;
            let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            Sid::from_ptr(label.Label.Sid)?.rid()
        }
    }

    /// Enumerate group SIDs.
    pub fn groups(&self) -> Result<Vec<Sid>> {
        unsafe {
            let mut len = 0u32;
            // Probe for required buffer length (an insufficient-buffer error is expected).
            buffer_probe(GetTokenInformation(
                self.handle,
                TokenGroups,
                None,
                0,
                &mut len,
            ))?;
            let mut buf = vec![0u8; len as usize];
            GetTokenInformation(
                self.handle,
                TokenGroups,
                Some(buf.as_mut_ptr() as *mut c_void),
                len,
                &mut len,
            )?;
            let groups = &*(buf.as_ptr() as *const TOKEN_GROUPS);
            let slice =
                std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize);
            slice.iter().map(|ga| Sid::from_ptr(ga.Sid)).collect()
        }
    }

    /// For filtered admin tokens, return the linked administrator token.
    pub fn linked_token(&self) -> Result<OwnedToken> {
        unsafe {
            let mut linked: TOKEN_LINKED_TOKEN = std::mem::zeroed();
            let mut ret = 0u32;
            GetTokenInformation(
                self.handle,
                TokenLinkedToken,
                Some(&mut linked as *mut _ as *mut c_void),
                std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
                &mut ret,
            )?;
            Ok(OwnedToken {
                handle: linked.LinkedToken,
            })
        }
    }

    /// Retrieve the token's elevation type (default, limited, or full).
    pub fn elevation_type(&self) -> Result<TOKEN_ELEVATION_TYPE> {
        unsafe {
            let mut et: TOKEN_ELEVATION_TYPE = std::mem::zeroed();
            let mut ret = 0u32;
            GetTokenInformation(
                self.handle,
                TokenElevationType,
                Some(&mut et as *mut _ as *mut c_void),
                std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
                &mut ret,
            )?;
            Ok(et)
        }
    }

    /// Return the token's primary user SID.
    pub fn user(&self) -> Result<Sid> {
        unsafe {
            let mut len = 0u32;
            // probe for buffer size
            buffer_probe(GetTokenInformation(
                self.handle,
                TokenUser,
                None,
                0,
                &mut len,
            ))?;
            let mut buf = vec![0u8; len as usize];
            GetTokenInformation(
                self.handle,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut c_void),
                len,
                &mut len,
            )?;
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            Sid::from_ptr(tu.User.Sid)
        }
    }
}

impl<'a> From<&'a OwnedToken> for TokenRef {
    fn from(tok: &'a OwnedToken) -> Self {
        TokenRef { handle: tok.handle }
    }
}

/* ------------------------------------------------------------------------- */
/* Sid                                                                       */
/* ------------------------------------------------------------------------- */

/// Owned and immutable security identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sid {
    buf: Vec<u8>,
}

impl Sid {
    /// Parse canonical string form ("S‑1‑…").
    pub fn parse(s: &str) -> Result<Self> {
        unsafe {
            let mut psid = PSID::default();
            // Convert Rust string to a nul-terminated UTF-16 wide string.
            let mut wide: Vec<u16> = s.encode_utf16().collect();
            wide.push(0); // trailing NUL
            ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut psid)?;
            let len = GetLengthSid(psid);
            let slice = std::slice::from_raw_parts(psid.0 as *const u8, len as usize);
            let v = slice.to_vec();
            LocalFree(HLOCAL(psid.0 as *mut c_void));
            Ok(Self { buf: v })
        }
    }

    /// Canonical string representation.
    pub fn to_string(&self) -> Result<String> {
        unsafe {
            let mut pwstr = PWSTR::null();
            ConvertSidToStringSidW(PSID(self.buf.as_ptr() as *mut c_void), &mut pwstr)?;
            let s = pwstr.to_string()?;
            LocalFree(HLOCAL(pwstr.0 as *mut c_void));
            Ok(s)
        }
    }

    /// Resolve account & domain names.
    pub fn account(&self) -> Result<(String, String)> {
        unsafe {
            let mut name_len = 0u32;
            let mut dom_len = 0u32;
            let mut use_ty = SID_NAME_USE(0);
            buffer_probe(LookupAccountSidW(
                PCWSTR::null(),
                PSID(self.buf.as_ptr() as *mut _),
                PWSTR::null(),
                &mut name_len,
                PWSTR::null(),
                &mut dom_len,
                &mut use_ty,
            ))?;
            let mut name = vec![0u16; name_len as usize];
            let mut dom = vec![0u16; dom_len as usize];
            LookupAccountSidW(
                PCWSTR::null(),
                PSID(self.buf.as_ptr() as *mut _),
                PWSTR(name.as_mut_ptr()),
                &mut name_len,
                PWSTR(dom.as_mut_ptr()),
                &mut dom_len,
                &mut use_ty,
            )?;
            Ok((
                String::from_utf16_lossy(&name[..name_len as usize]),
                String::from_utf16_lossy(&dom[..dom_len as usize]),
            ))
        }
    }

    /// Build a Windows well‑known SID.
    pub fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Result<Self> {
        unsafe {
            let mut size = 0u32;
            buffer_probe(CreateWellKnownSid(
                kind,
                PSID::default(),
                PSID::default(),
                &mut size,
            ))?;
            let mut buf = vec![0u8; size as usize];
            CreateWellKnownSid(
                kind,
                PSID::default(),
                PSID(buf.as_mut_ptr() as *mut _),
                &mut size,
            )?;
            Ok(Self { buf })
        }
    }

    /* -------------- helpers --------------------------------------------- */
    pub(crate) unsafe fn from_ptr(psid: PSID) -> Result<Self> {
        unsafe {
            let len = GetLengthSid(psid);
            if len == 0 {
                return Err(Error::from_win32());
            }
            let slice = std::slice::from_raw_parts(psid.0 as *const u8, len as usize);
            Ok(Self {
                buf: slice.to_vec(),
            })
        }
    }

    /// Last sub‑authority (RID).
    pub fn rid(&self) -> Result<u32> {
        unsafe {
            let cnt_ptr = GetSidSubAuthorityCount(PSID(self.buf.as_ptr() as *mut c_void));
            if cnt_ptr.is_null() {
                return Err(Error::from_win32());
            }
            let rid_ptr = GetSidSubAuthority(
                PSID(self.buf.as_ptr() as *mut c_void),
                (*cnt_ptr as u32) - 1,
            );
            if rid_ptr.is_null() {
                return Err(Error::from_win32());
            }
            Ok(*rid_ptr)
        }
    }
}

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_string() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "<invalid sid>"),
        }
    }
}
