//! The Win32 calls EtwTrace makes, behind safe functions:
//!
//! * [`session`]: starting, querying and stopping ETW sessions, enabling providers, and the session and system-wide
//!   settings of `TraceSetInformation` / `TraceQueryInformation` (as raw byte buffers the caller builds and parses).
//! * [`consumer`]: reading trace files and real-time sessions with `OpenTrace` / `ProcessTrace`, as borrowed
//!   [`EventRecord`] views that are only valid during the callback (so nothing is copied).
//! * [`relogger`]: rewriting traces through the OS relogger (`ITraceRelogger`), with events injected along the way.
//! * [`system`]: tokens and privileges, volumes and drive letters, file version resources, event metadata from TDH, and
//!   Ctrl+C.
//!
//! This is the only crate in the workspace with unsafe code.  Each unsafe block is one Win32 call or pointer access,
//! with a SAFETY comment, and every public function is safe to call.

mod buffer;
pub mod consumer;
pub mod relogger;
pub mod session;
pub mod system;
mod wide;

use std::fmt;

pub use consumer::{EventRecord, TraceInfo};
pub use relogger::{NewEvent, RelogContext, RelogHandler};

/// A Win32 or COM error code, displayed as the system's message for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub u32);

impl Error {
    /// The Win32 error code (or HRESULT, for COM calls).
    #[must_use]
    pub const fn code(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match system::error_message(self.0) {
            Some(message) => f.write_str(&message),
            None => write!(f, "error 0x{:X}", self.0),
        }
    }
}

impl std::error::Error for Error {}

/// Converts a Win32 status (0 for success) to a result.
fn check(status: u32) -> Result<(), Error> {
    if status == 0 { Ok(()) } else { Err(Error(status)) }
}

/// A GUID, laid out like the Win32 GUID.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Makes a GUID from its usual text form written as one number, e.g. `0x3d6fa8d1_fe05_11d0_9dda_00c04fd7ba7c`.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        let [a0, a1, a2, a3, b0, b1, c0, c1, d0, d1, d2, d3, d4, d5, d6, d7] = value.to_be_bytes();
        Self {
            data1: u32::from_be_bytes([a0, a1, a2, a3]),
            data2: u16::from_be_bytes([b0, b1]),
            data3: u16::from_be_bytes([c0, c1]),
            data4: [d0, d1, d2, d3, d4, d5, d6, d7],
        }
    }

    /// The 16 bytes of the GUID as Win32 stores it in memory (the first three fields little endian).
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        let [a0, a1, a2, a3] = self.data1.to_le_bytes();
        let [b0, b1] = self.data2.to_le_bytes();
        let [c0, c1] = self.data3.to_le_bytes();
        let [d0, d1, d2, d3, d4, d5, d6, d7] = self.data4;
        [a0, a1, a2, a3, b0, b1, c0, c1, d0, d1, d2, d3, d4, d5, d6, d7]
    }

    pub(crate) const fn from_sys(guid: windows_sys::core::GUID) -> Self {
        Self {
            data1: guid.data1,
            data2: guid.data2,
            data3: guid.data3,
            data4: guid.data4,
        }
    }

    pub(crate) const fn to_sys(self) -> windows_sys::core::GUID {
        windows_sys::core::GUID {
            data1: self.data1,
            data2: self.data2,
            data3: self.data3,
            data4: self.data4,
        }
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [d0, d1, d2, d3, d4, d5, d6, d7] = self.data4;
        write!(f, "{:08x}-{:04x}-{:04x}-{d0:02x}{d1:02x}-{d2:02x}{d3:02x}{d4:02x}{d5:02x}{d6:02x}{d7:02x}", self.data1, self.data2, self.data3)
    }
}

#[cfg(test)]
mod tests {
    use super::Guid;

    #[test]
    fn guid_round_trips_through_text_and_bytes() {
        let guid = Guid::from_u128(0x3d6f_a8d1_fe05_11d0_9dda_00c0_4fd7_ba7c);
        assert_eq!(guid.to_string(), "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c");
        assert_eq!(guid.to_bytes(), [0xd1, 0xa8, 0x6f, 0x3d, 0x05, 0xfe, 0xd0, 0x11, 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c]);
    }
}
