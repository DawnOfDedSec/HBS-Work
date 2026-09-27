//! Native, read-only local account/group enumeration via `windows-sys`.
//!
//! Server Core images without PowerShell can still answer "who can log
//! in?" through the NetAPI account APIs, which need no external process.
//! Everything here is read-only and returns `None` on any failure.
//!
//! On non-Windows targets the helpers are inert stubs returning `None`.

/// Enumerate local user account names (`NetUserEnum`, normal accounts).
pub fn native_enum_local_users() -> Option<Vec<String>> {
    #[cfg(windows)]
    {
        imp::enum_users()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Enumerate local group names (`NetLocalGroupEnum`).
pub fn native_enum_local_groups() -> Option<Vec<String>> {
    #[cfg(windows)]
    {
        imp::enum_groups()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Enumerate member names of a local group (`NetLocalGroupGetMembers`,
/// level 2 -> `DOMAIN\name`).
pub fn native_local_group_members(group: &str) -> Option<Vec<String>> {
    #[cfg(windows)]
    {
        imp::group_members(group)
    }
    #[cfg(not(windows))]
    {
        let _ = group;
        None
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetLocalGroupEnum, NetLocalGroupGetMembers, NetUserEnum,
        FILTER_NORMAL_ACCOUNT, LOCALGROUP_INFO_0, LOCALGROUP_MEMBERS_INFO_2, MAX_PREFERRED_LENGTH,
        USER_INFO_0,
    };

    /// Owns a NetAPI-allocated buffer and frees it exactly once.
    struct NetBuffer(*mut u8);

    impl Drop for NetBuffer {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: buffer was allocated by a NetAPI call and is
                // freed once, here.
                unsafe { NetApiBufferFree(self.0 as *const c_void) };
            }
        }
    }

    /// Read a NUL-terminated UTF-16 string from a NetAPI `PWSTR`.
    fn wide_ptr_to_string(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        // SAFETY: NetAPI returns NUL-terminated strings; we stop at the
        // first NUL without reading past it.
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
            if len > 32_768 {
                return None;
            }
        }
        // SAFETY: `ptr` is valid for `len` u16 elements as established above.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        Some(String::from_utf16_lossy(slice))
    }

    pub fn enum_users() -> Option<Vec<String>> {
        let mut raw: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let mut resume = 0u32;
        // SAFETY: null server means the local computer. `raw` is an
        // out-pointer initialized by the API on success. Read-only.
        let status = unsafe {
            NetUserEnum(
                std::ptr::null(),
                0,
                FILTER_NORMAL_ACCOUNT,
                &mut raw,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        if status != 0 || raw.is_null() {
            return None;
        }
        let buffer = NetBuffer(raw);
        let rows = buffer.0 as *const USER_INFO_0;
        let mut names = Vec::with_capacity(read as usize);
        for i in 0..read as usize {
            // SAFETY: the API returned `read` contiguous USER_INFO_0 rows.
            let name = wide_ptr_to_string(unsafe { (*rows.add(i)).usri0_name });
            if let Some(name) = name {
                names.push(name);
            }
        }
        Some(names)
    }

    pub fn enum_groups() -> Option<Vec<String>> {
        let mut raw: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let mut resume = 0usize;
        // SAFETY: null server = local computer; read-only enumeration.
        let status = unsafe {
            NetLocalGroupEnum(
                std::ptr::null(),
                0,
                &mut raw,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        if status != 0 || raw.is_null() {
            return None;
        }
        let buffer = NetBuffer(raw);
        let rows = buffer.0 as *const LOCALGROUP_INFO_0;
        let mut names = Vec::with_capacity(read as usize);
        for i in 0..read as usize {
            // SAFETY: the API returned `read` contiguous rows.
            let name = wide_ptr_to_string(unsafe { (*rows.add(i)).lgrpi0_name });
            if let Some(name) = name {
                names.push(name);
            }
        }
        Some(names)
    }

    pub fn group_members(group: &str) -> Option<Vec<String>> {
        let group_w: Vec<u16> = group.encode_utf16().chain(std::iter::once(0)).collect();
        let mut raw: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let mut resume = 0usize;
        // SAFETY: `group_w` is a NUL-terminated wide string that outlives
        // the call; null server = local computer. Level 2 returns
        // DOMAIN\name plus SID. Read-only.
        let status = unsafe {
            NetLocalGroupGetMembers(
                std::ptr::null(),
                group_w.as_ptr(),
                2,
                &mut raw,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        if status != 0 || raw.is_null() {
            return None;
        }
        let buffer = NetBuffer(raw);
        let rows = buffer.0 as *const LOCALGROUP_MEMBERS_INFO_2;
        let mut names = Vec::with_capacity(read as usize);
        for i in 0..read as usize {
            // SAFETY: the API returned `read` contiguous rows.
            let name = wide_ptr_to_string(unsafe { (*rows.add(i)).lgrmi2_domainandname });
            if let Some(name) = name {
                names.push(name);
            }
        }
        Some(names)
    }
}
