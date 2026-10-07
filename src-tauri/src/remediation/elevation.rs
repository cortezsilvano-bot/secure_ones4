//! Whether this process is running as an administrator.
//!
//! Checked before a change is attempted rather than after it fails. Windows
//! surfaces a policy refusal through the raw WMI path as a bare
//! `WBEM_E_FAILED` with no indication that rights are the problem, so without
//! this check the user would see "Defender refused (error 0x80041001)" when the
//! truthful message is "this needs administrator rights".

/// True when the current process has an elevated token.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            // Unable to ask: assume not elevated, which is the safe direction.
            // Claiming elevation we do not have would produce a confusing
            // failure later instead of a clear message now.
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;

        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();

        let _ = CloseHandle(token);

        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_check_answers_without_panicking() {
        // The value depends on how the process was started, so only that the
        // call is safe and total is asserted here.
        let _ = is_elevated();
    }
}
