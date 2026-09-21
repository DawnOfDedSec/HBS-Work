//! Privilege handling: elevation detection and (Windows) a polite UAC
//! self-relaunch. When the user declines, the scan continues
//! degraded — elevation is never required (spec §4.2).

#[cfg(unix)]
pub fn is_elevated() -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Offer a UAC relaunch. Returns true when a child process was
/// launched elevated and the caller should exit; false means continue
/// in the current (possibly unprivileged) context.
#[cfg(unix)]
pub fn request_relaunch(no_elevate: bool) -> bool {
    // There is no UAC on Linux: root detection only, never a prompt.
    !no_elevate && false
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: token handles are closed on every path; GetTokenInformation
    // writes into a correctly-sized TOKEN_ELEVATION struct.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

/// Offer a UAC relaunch via the standard `runas` verb — no bypass,
/// the user always sees and decides the consent dialog. Returns true
/// when an elevated child was launched and the caller should exit(0);
/// false when declined (or already elevated / --no-elevate): continue
/// degraded.
#[cfg(windows)]
pub fn request_relaunch(no_elevate: bool) -> bool {
    if no_elevate || is_elevated() {
        return false;
    }
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW;

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut params = std::env::args().skip(1).collect::<Vec<_>>();
    params.retain(|a| a != "--elevated-child");
    let params = params.join(" ");
    let wide_exe: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let wide_params: Vec<u16> = if params.is_empty() {
        vec![0]
    } else {
        params.encode_utf16().chain(Some(0)).collect()
    };

    // SAFETY: all pointers are NUL-terminated wide strings valid for the
    // duration of the call; ShellExecuteW does not retain them.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            wide_exe.as_ptr(),
            wide_params.as_ptr(),
            std::ptr::null(),
            SW_SHOW,
        )
    };
    // Values > 32 mean success (the UAC prompt was confirmed).
    (result as usize) > 32
}
