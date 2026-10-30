//! UTF-16 strings for Win32 calls.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

/// A null terminated UTF-16 copy of the string.
pub(crate) fn to_wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// The text up to the first null (or the whole buffer, if it has none).
pub(crate) fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(buffer.get(..end).unwrap_or(buffer))
}

/// The null separated strings of a buffer that ends with an empty one (a Win32 'multi-sz').
pub(crate) fn from_multi_wide(buffer: &[u16]) -> Vec<String> {
    buffer.split(|&c| c == 0).take_while(|s| !s.is_empty()).map(String::from_utf16_lossy).collect()
}
