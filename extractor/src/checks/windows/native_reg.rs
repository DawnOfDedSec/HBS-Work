//! Native, read-only Windows registry access via `windows-sys`.
//!
//! This is the last-resort evidence source for registry checks when both
//! `reg query` and PowerShell are absent (Server Core / Nano Server
//! images ship neither). It never spawns a process, never writes, and
//! every helper returns `None` on any failure — a missing key, a denied
//! read, a wrong type, or a malformed path all degrade the caller rather
//! than panicking.
//!
//! Only `HKLM`/`HKEY_LOCAL_MACHINE` and `HKCU`/`HKEY_CURRENT_USER` roots
//! are supported, in the native and `KEY_WOW64_32KEY` registry views.
//!
//! On non-Windows targets the helpers are inert stubs returning `None`
//! so the crate still compiles and the catalog audit stays portable.

/// Which registry view a read targets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegView {
    /// The process-native view (64-bit view for a 64-bit process).
    Default,
    /// The 32-bit `WOW6432Node` view (`KEY_WOW64_32KEY`).
    Wow64_32,
    /// The explicit 64-bit view (`KEY_WOW64_64KEY`).
    Wow64_64,
}

#[cfg(windows)]
mod imp {
    use super::RegView;
    use windows_sys::core::{PCWSTR, PWSTR};
    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, HKEY,
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
        REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ, REG_SZ,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn utf16_to_string(raw: &[u16]) -> String {
        let end = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
        String::from_utf16_lossy(&raw[..end])
    }

    /// Split `HKLM\Software\...` into (root handle, subkey). The hive
    /// prefix is matched case-insensitively, mirroring the registry's own
    /// case-insensitive semantics.
    fn parse_path(path: &str) -> Option<(HKEY, String)> {
        let path = path.trim().trim_end_matches('\\');
        let (hive, rest) = path.split_once('\\')?;
        let root = match hive.to_ascii_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            _ => return None,
        };
        if rest.is_empty() {
            return None;
        }
        Some((root, rest.to_string()))
    }

    fn view_flag(view: RegView) -> u32 {
        match view {
            RegView::Default => 0,
            RegView::Wow64_32 => KEY_WOW64_32KEY,
            RegView::Wow64_64 => KEY_WOW64_64KEY,
        }
    }

    /// RAII wrapper that always closes a successfully opened key.
    struct RegKey(HKEY);

    impl Drop for RegKey {
        fn drop(&mut self) {
            // SAFETY: the handle was returned by a successful
            // RegOpenKeyExW and is closed exactly once here.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open_key(path: &str, view: RegView) -> Option<RegKey> {
        let (root, subkey) = parse_path(path)?;
        let subkey_w = to_wide(&subkey);
        let mut handle: HKEY = std::ptr::null_mut();
        // SAFETY: `subkey_w` is a NUL-terminated wide string that outlives
        // the call; `handle` is a valid out-pointer. Read-only access with
        // the requested view. No other pointers are dereferenced.
        let rc = unsafe {
            RegOpenKeyExW(
                root,
                subkey_w.as_ptr() as PCWSTR,
                0,
                KEY_READ | view_flag(view),
                &mut handle,
            )
        };
        (rc == ERROR_SUCCESS && !handle.is_null()).then_some(RegKey(handle))
    }

    /// Read one value's raw bytes plus its registry type. Uses the
    /// documented two-call size pattern: first query the size/type with a
    /// null buffer, then read into an exactly sized buffer.
    fn query_raw(key: &RegKey, name: &str) -> Option<(Vec<u8>, u32)> {
        let name_w = to_wide(name);
        let mut value_type: u32 = 0;
        let mut len: u32 = 0;
        // SAFETY: null data pointer with a valid size out-pointer is the
        // documented size-query form; nothing is written to `key`.
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                name_w.as_ptr() as PCWSTR,
                std::ptr::null(),
                &mut value_type,
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let mut read_len = len;
        let mut read_type = value_type;
        // SAFETY: `buf` is sized from the preceding query; `read_len` is
        // its capacity. The API writes at most `read_len` bytes and
        // updates the type in place.
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                name_w.as_ptr() as PCWSTR,
                std::ptr::null(),
                &mut read_type,
                buf.as_mut_ptr(),
                &mut read_len,
            )
        };
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA {
            return None;
        }
        buf.truncate(read_len as usize);
        Some((buf, read_type))
    }

    pub fn dword(path: &str, name: &str, view: RegView) -> Option<u32> {
        let key = open_key(path, view)?;
        let (buf, value_type) = query_raw(&key, name)?;
        match value_type {
            REG_DWORD | REG_DWORD_BIG_ENDIAN => {
                let bytes: [u8; 4] = buf.get(..4)?.try_into().ok()?;
                Some(if value_type == REG_DWORD_BIG_ENDIAN {
                    u32::from_be_bytes(bytes)
                } else {
                    u32::from_le_bytes(bytes)
                })
            }
            // Some values are stored as numeric strings (e.g. legacy
            // CachedLogonsCount); accept them like `reg query` does.
            REG_SZ | REG_EXPAND_SZ => {
                let raw = utf16_to_string(&buf.iter().map(|b| *b as u16).collect::<Vec<_>>());
                parse_numeric(raw.trim())
            }
            _ => None,
        }
    }

    fn parse_numeric(raw: &str) -> Option<u32> {
        if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            raw.parse().ok()
        }
    }

    pub fn string(path: &str, name: &str, view: RegView) -> Option<String> {
        let key = open_key(path, view)?;
        let (buf, value_type) = query_raw(&key, name)?;
        if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
            return None;
        }
        // REG_SZ bytes are UTF-16LE code units.
        let units: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(utf16_to_string(&units))
    }

    pub fn enum_subkeys(path: &str, view: RegView) -> Option<Vec<String>> {
        let key = open_key(path, view)?;
        let mut names = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut len: u32 = 256;
            let mut buf = vec![0u16; len as usize];
            // SAFETY: `buf` holds `len` wide characters; `len` is updated
            // to the character count written (excluding NUL). All other
            // out-pointers are null, which the API documents as optional.
            let rc = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    buf.as_mut_ptr() as PWSTR,
                    &mut len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if rc == ERROR_MORE_DATA || rc == 122 {
                // `len` now reports the required size in characters
                // (including NUL); retry once with a larger buffer.
                let mut big = vec![0u16; len as usize + 1];
                let mut big_len = big.len() as u32;
                // SAFETY: as above, with a buffer sized by the API.
                let rc = unsafe {
                    RegEnumKeyExW(
                        key.0,
                        index,
                        big.as_mut_ptr() as PWSTR,
                        &mut big_len,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if rc == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if rc != ERROR_SUCCESS {
                    break;
                }
                names.push(utf16_to_string(&big[..big_len as usize]));
                index += 1;
                continue;
            }
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                break;
            }
            names.push(utf16_to_string(&buf[..len as usize]));
            index += 1;
        }
        Some(names)
    }

    pub fn enum_values(path: &str, view: RegView) -> Option<Vec<(String, u32)>> {
        let key = open_key(path, view)?;
        let mut values = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut len: u32 = 256;
            let mut buf = vec![0u16; len as usize];
            let mut value_type: u32 = 0;
            // SAFETY: `buf` holds `len` wide characters. Data pointers are
            // null because only the name and type are requested; the API
            // documents that combination. `key` is a live handle.
            let rc = unsafe {
                RegEnumValueW(
                    key.0,
                    index,
                    buf.as_mut_ptr() as PWSTR,
                    &mut len,
                    std::ptr::null(),
                    &mut value_type,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if rc == ERROR_MORE_DATA || rc == 122 {
                let mut big = vec![0u16; len as usize + 1];
                let mut big_len = big.len() as u32;
                let mut big_type: u32 = 0;
                // SAFETY: as above with an API-sized buffer.
                let rc = unsafe {
                    RegEnumValueW(
                        key.0,
                        index,
                        big.as_mut_ptr() as PWSTR,
                        &mut big_len,
                        std::ptr::null(),
                        &mut big_type,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if rc == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if rc != ERROR_SUCCESS {
                    break;
                }
                values.push((utf16_to_string(&big[..big_len as usize]), big_type));
                index += 1;
                continue;
            }
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                break;
            }
            values.push((utf16_to_string(&buf[..len as usize]), value_type));
            index += 1;
        }
        Some(values)
    }
}

/// Read a DWORD from `path`/`name` in the process-native view.
pub fn native_reg_dword(path: &str, name: &str) -> Option<u32> {
    native_reg_dword_view(path, name, RegView::Default)
}

/// Read a string (`REG_SZ`/`REG_EXPAND_SZ`) from `path`/`name` in the
/// process-native view.
pub fn native_reg_sz(path: &str, name: &str) -> Option<String> {
    native_reg_sz_view(path, name, RegView::Default)
}

/// Enumerate immediate subkey names of `path` in the native view.
pub fn native_reg_enum_subkeys(path: &str) -> Option<Vec<String>> {
    native_reg_enum_subkeys_view(path, RegView::Default)
}

/// Enumerate immediate value `(name, type)` pairs of `path` in the
/// native view. The type is the raw `REG_*` constant.
pub fn native_reg_enum_values(path: &str) -> Option<Vec<(String, u32)>> {
    native_reg_enum_values_view(path, RegView::Default)
}

/// [`native_reg_dword`] with an explicit registry view.
pub fn native_reg_dword_view(path: &str, name: &str, view: RegView) -> Option<u32> {
    #[cfg(windows)]
    {
        imp::dword(path, name, view)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, name, view);
        None
    }
}

/// [`native_reg_sz`] with an explicit registry view.
pub fn native_reg_sz_view(path: &str, name: &str, view: RegView) -> Option<String> {
    #[cfg(windows)]
    {
        imp::string(path, name, view)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, name, view);
        None
    }
}

/// [`native_reg_enum_subkeys`] with an explicit registry view.
pub fn native_reg_enum_subkeys_view(path: &str, view: RegView) -> Option<Vec<String>> {
    #[cfg(windows)]
    {
        imp::enum_subkeys(path, view)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, view);
        None
    }
}

/// [`native_reg_enum_values`] with an explicit registry view.
pub fn native_reg_enum_values_view(path: &str, view: RegView) -> Option<Vec<(String, u32)>> {
    #[cfg(windows)]
    {
        imp::enum_values(path, view)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, view);
        None
    }
}
