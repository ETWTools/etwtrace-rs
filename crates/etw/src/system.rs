//! Tokens and privileges, Windows and volume paths, file version resources, error messages and Ctrl+C.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID};
use windows_sys::Win32::Security::{AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation};
use windows_sys::Win32::Storage::FileSystem::{FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetFileVersionInfoSizeW, GetFileVersionInfoW, GetLogicalDrives, GetVolumePathNamesForVolumeNameW, QueryDosDeviceW, VerQueryValueW};
use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows_sys::Win32::System::Diagnostics::Debug::{FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW};
use windows_sys::Win32::System::Performance::QueryPerformanceFrequency;
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::core::BOOL;

use crate::buffer::AlignedBuffer;
use crate::wide::{from_multi_wide, from_wide, to_wide};

const MAX_PATH: usize = 260;
const LONG_PATH: usize = 32_768;

/// Enables a privilege the process token holds but has not enabled.  Returns false if the token lacks it.
#[must_use]
pub fn enable_privilege(name: &str) -> bool {
    let Some(token) = Token::open(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) else {
        return false;
    };

    let name = to_wide(name);
    let mut luid = LUID::default();
    // SAFETY: the name is null terminated; luid is a valid out pointer.
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &raw mut luid) } == 0 {
        return false;
    }

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: the token was opened with TOKEN_ADJUST_PRIVILEGES; the new state is valid and no previous state is wanted.
    let adjusted = unsafe { AdjustTokenPrivileges(token.0, 0, &raw const privileges, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
    // AdjustTokenPrivileges succeeds even when the token does not hold the privilege; the last error says so.
    // SAFETY: no preconditions.
    adjusted != 0 && unsafe { GetLastError() } == 0
}

/// Returns whether the process runs elevated, or None if the token cannot be queried.
#[must_use]
pub fn is_elevated() -> Option<bool> {
    let token = Token::open(TOKEN_QUERY)?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    let size = u32::try_from(size_of::<TOKEN_ELEVATION>()).ok()?;
    // SAFETY: the token was opened with TOKEN_QUERY; the output buffer is a TOKEN_ELEVATION of `size` bytes.
    let ok = unsafe { GetTokenInformation(token.0, TokenElevation, (&raw mut elevation).cast(), size, &raw mut returned) };
    (ok != 0).then_some(elevation.TokenIsElevated != 0)
}

/// QueryPerformanceFrequency: ticks per second of the QueryPerformanceCounter clock.
#[must_use]
pub fn qpc_frequency() -> i64 {
    let mut frequency = 0i64;
    // SAFETY: the out pointer is valid; the call cannot fail on Windows XP and later.
    unsafe { QueryPerformanceFrequency(&raw mut frequency) };
    frequency
}

/// GetLogicalDrives: bit N is set if drive letter 'A' + N exists.
#[must_use]
pub fn logical_drives() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetLogicalDrives() }
}

/// QueryDosDevice: the device a DOS device name (e.g. "C:" or "Volume{...}") refers to, e.g. "\Device\HarddiskVolume3".
#[must_use]
pub fn query_dos_device(name: &str) -> Option<String> {
    let name = to_wide(name);
    let mut target = vec![0u16; LONG_PATH];
    let capacity = u32::try_from(target.len()).ok()?;
    // SAFETY: the name is null terminated and the target buffer holds `capacity` characters.
    let length = unsafe { QueryDosDeviceW(name.as_ptr(), target.as_mut_ptr(), capacity) };
    if length == 0 {
        return None;
    }

    from_multi_wide(&target).into_iter().next()
}

/// Each volume's device name with a trailing backslash (e.g. "\Device\HarddiskVolume3\") and its first mount path
/// (e.g. "C:\", or "" if it has none), in the order FindFirstVolume / FindNextVolume list them.
#[must_use]
pub fn volume_devices() -> Vec<(String, String)> {
    let mut volumes = Vec::new();
    let mut name = vec![0u16; MAX_PATH];
    let capacity = u32::try_from(name.len()).unwrap_or(0);
    // SAFETY: the buffer holds `capacity` characters.
    let find = unsafe { FindFirstVolumeW(name.as_mut_ptr(), capacity) };
    if find == INVALID_HANDLE_VALUE {
        return volumes;
    }

    loop {
        // Volume names look like \\?\Volume{GUID}\; QueryDosDevice wants Volume{GUID}.
        let volume = from_wide(&name);
        let device = volume.strip_prefix(r"\\?\").and_then(|rest| rest.strip_suffix('\\')).and_then(query_dos_device);
        if let Some(device) = device {
            let path = volume_path_names(&volume).into_iter().next().unwrap_or_default();
            volumes.push((device + "\\", path));
        }

        // SAFETY: `find` came from FindFirstVolumeW and is not closed yet; the buffer holds `capacity` characters.
        if unsafe { FindNextVolumeW(find, name.as_mut_ptr(), capacity) } == 0 {
            break;
        }
    }

    // SAFETY: `find` came from FindFirstVolumeW and is closed once.
    unsafe { FindVolumeClose(find) };
    volumes
}

fn volume_path_names(volume: &str) -> Vec<String> {
    let volume = to_wide(volume);
    let mut paths = vec![0u16; LONG_PATH];
    let capacity = u32::try_from(paths.len()).unwrap_or(0);
    let mut returned = 0u32;
    // SAFETY: the volume name is null terminated and the buffer holds `capacity` characters.
    let ok = unsafe { GetVolumePathNamesForVolumeNameW(volume.as_ptr(), paths.as_mut_ptr(), capacity, &raw mut returned) };
    if ok == 0 { Vec::new() } else { from_multi_wide(&paths) }
}

/// GetWindowsDirectory, e.g. "C:\WINDOWS".
#[must_use]
pub fn windows_directory() -> Option<String> {
    let mut buffer = vec![0u16; MAX_PATH];
    let capacity = u32::try_from(buffer.len()).ok()?;
    // SAFETY: the buffer holds `capacity` characters.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), capacity) };
    (length != 0 && length < capacity).then(|| from_wide(&buffer))
}

/// GetSystemDirectory, e.g. "C:\WINDOWS\system32".
#[must_use]
pub fn system_directory() -> Option<String> {
    let mut buffer = vec![0u16; MAX_PATH];
    let capacity = u32::try_from(buffer.len()).ok()?;
    // SAFETY: the buffer holds `capacity` characters.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity) };
    (length != 0 && length < capacity).then(|| from_wide(&buffer))
}

/// What a file's version resource says it was originally called.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionNames {
    /// The file has no version resource.
    NoVersionInfo,
    /// The file has one, but it could not be read.
    Unreadable,
    /// For each language and code page of the resource: its OriginalFilename, else its InternalName, else None.
    Names(Vec<Option<String>>),
}

/// Reads the OriginalFilename (or InternalName) of each translation in a file's version resource.
#[must_use]
pub fn file_version_names(path: &Path) -> VersionNames {
    let path = to_wide(path);
    let mut ignored = 0u32;
    // SAFETY: the path is null terminated.
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &raw mut ignored) };
    let Ok(length) = usize::try_from(size) else {
        return VersionNames::Unreadable;
    };

    if length == 0 {
        return VersionNames::NoVersionInfo;
    }

    let mut data = AlignedBuffer::new(length);
    // SAFETY: the path is null terminated and the buffer holds `size` bytes.
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, data.as_mut_ptr().cast()) } == 0 {
        return VersionNames::Unreadable;
    }

    let translations: Vec<(u16, u16)> = query_version_value(&data, r"\VarFileInfo\Translation")
        .map(|(offset, bytes)| {
            data.bytes()
                .get(offset..offset.saturating_add(bytes))
                .unwrap_or_default()
                .as_chunks::<4>()
                .0
                .iter()
                .map(|&[a, b, c, d]| (u16::from_le_bytes([a, b]), u16::from_le_bytes([c, d])))
                .collect()
        })
        .unwrap_or_default();

    VersionNames::Names(
        translations
            .iter()
            .map(|(language, code_page)| {
                ["OriginalFilename", "InternalName"].iter().find_map(|field| {
                    let key = format!(r"\StringFileInfo\{language:04x}{code_page:04x}\{field}");
                    let (offset, chars) = query_version_value(&data, &key)?;
                    let text = data.wide_at(offset, chars);
                    (!text.is_empty()).then_some(text)
                })
            })
            .collect(),
    )
}

/// VerQueryValue: the offset of a value within the version data, and its length (bytes for binary values, characters
/// for strings).
fn query_version_value(data: &AlignedBuffer, key: &str) -> Option<(usize, usize)> {
    let key = to_wide(key);
    let mut value: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut length = 0u32;
    // SAFETY: the data came from GetFileVersionInfoW and the key is null terminated; the value pointer it returns points
    // into the data (checked below before use).
    let ok = unsafe { VerQueryValueW(data.as_ptr().cast(), key.as_ptr(), &raw mut value, &raw mut length) };
    if ok == 0 || length == 0 || value.is_null() {
        return None;
    }

    let offset = (value as usize).checked_sub(data.as_ptr() as usize)?;
    (offset < data.len()).then_some((offset, usize::try_from(length).ok()?))
}

/// The system's message for a Win32 error or HRESULT, or None if it has none.
#[must_use]
pub fn error_message(code: u32) -> Option<String> {
    let mut buffer = vec![0u16; 1024];
    let capacity = u32::try_from(buffer.len()).ok()?;
    // SAFETY: the buffer holds `capacity` characters; with IGNORE_INSERTS no arguments are read.
    let length = unsafe { FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, std::ptr::null(), code, 0, buffer.as_mut_ptr(), capacity, std::ptr::null()) };
    let length = usize::try_from(length).ok()?;
    let message = String::from_utf16_lossy(buffer.get(..length)?);
    let message = message.trim_end();
    (!message.is_empty()).then(|| message.to_owned())
}

/// Ctrl+C (and Ctrl+Break) handling: while a `CtrlC` is alive, those keys set a flag instead of ending the process.
pub struct CtrlC(());

static CTRL_C_PRESSED: AtomicBool = AtomicBool::new(false);

impl CtrlC {
    /// Starts catching Ctrl+C.  Returns None if the console handler cannot be installed.
    #[must_use]
    pub fn catch() -> Option<Self> {
        CTRL_C_PRESSED.store(false, Ordering::SeqCst);
        // SAFETY: the handler is a plain function that only stores to a static atomic.
        (unsafe { SetConsoleCtrlHandler(Some(on_console_control), 1) } != 0).then_some(Self(()))
    }

    /// True once Ctrl+C has been pressed.
    #[must_use]
    pub fn pressed(&self) -> bool {
        CTRL_C_PRESSED.load(Ordering::SeqCst)
    }
}

impl Drop for CtrlC {
    fn drop(&mut self) {
        // SAFETY: removes the handler installed by catch().
        unsafe { SetConsoleCtrlHandler(Some(on_console_control), 0) };
    }
}

unsafe extern "system" fn on_console_control(control_type: u32) -> BOOL {
    if control_type == CTRL_C_EVENT || control_type == CTRL_BREAK_EVENT {
        CTRL_C_PRESSED.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}

/// A process token handle, closed on drop.
struct Token(HANDLE);

impl Token {
    fn open(access: u32) -> Option<Self> {
        // SAFETY: no preconditions (it returns a pseudo handle that need not be closed).
        let process = unsafe { GetCurrentProcess() };
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the process handle is valid and token is a valid out pointer.
        (unsafe { OpenProcessToken(process, access, &raw mut token) } != 0).then_some(Self(token))
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}
