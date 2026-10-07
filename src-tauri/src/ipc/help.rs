//! Opening the Windows page where a manual recommendation is carried out.
//!
//! Most findings SENTRY reports are not ones it will change for the user, and
//! their advice reads "...in Windows Security, under Virus & threat protection
//! settings". That is three menus deep. This command takes the user there.
//!
//! It changes nothing. The argument is a value from a fixed enum, and the
//! target handed to the shell is a `&'static str` chosen by a `match` on that
//! enum -- there is no string from the webview, a finding or a feed anywhere in
//! the path, so this cannot be used to launch something of the caller's
//! choosing. That is the same discipline as `apply_fix`: a closed list of named
//! verbs rather than a pass-through.

use crate::findings::HelpTarget;

/// Open the Windows settings page for a finding's manual fix.
#[tauri::command]
pub fn open_help_target(target: HelpTarget) -> Result<(), String> {
    open(target).map_err(|e| {
        log::warn!("could not open {}: {e}", target.target());
        format!(
            "Windows would not open that settings page. Open it yourself: {}",
            target.label().trim_start_matches("Open ")
        )
    })
}

#[cfg(windows)]
fn open(target: HelpTarget) -> Result<(), String> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    // The literal from the enum, never anything else.
    let wide: Vec<u16> = std::ffi::OsStr::new(target.target())
        .encode_wide()
        .chain(once(0))
        .collect();

    // SAFETY: both pointers are to NUL-terminated buffers that outlive the
    // call, and a null window handle is valid here.
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR::null(),
            PCWSTR(wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    // ShellExecuteW returns a pseudo-HINSTANCE: anything above 32 is success,
    // and the value at or below 32 is the error code.
    let code = result.0 as usize;
    if code > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecuteW returned {code}"))
    }
}

#[cfg(not(windows))]
fn open(_target: HelpTarget) -> Result<(), String> {
    Err("not Windows".into())
}
