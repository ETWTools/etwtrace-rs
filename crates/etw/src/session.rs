//! ETW sessions: starting, querying and stopping them, enabling providers, and the session and system-wide settings
//! of `TraceSetInformation` / `TraceQueryInformation`.  Those settings are passed as byte buffers that the caller
//! builds and parses; their formats are documented next to `TRACE_QUERY_INFO_CLASS` in evntrace.h.

use std::mem::size_of;
use std::path::Path;

use windows_sys::Win32::Foundation::{ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_ENABLE_PROPERTY_STACK_TRACE, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_PROPERTIES, EnableTraceEx2, QueryAllTracesW, StartTraceW, TraceQueryInformation, TraceSetInformation, WNODE_FLAG_TRACED_GUID,
};

use crate::buffer::AlignedBuffer;
use crate::wide::to_wide;
use crate::{Error, Guid, check};

/// The kernel's own session, the only one (before Windows 8) that can have kernel events.
pub const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";

/// SystemTraceControlGuid: the Wnode GUID that makes a session the NT Kernel Logger.
pub const SYSTEM_TRACE_CONTROL_GUID: Guid = Guid::from_u128(0x9e81_4aad_3204_11d2_9a82_0060_08a8_6939);

/// EVENT_TRACE_FILE_MODE_SEQUENTIAL: write the log file sequentially, stopping at its maximum size (if any).
pub const FILE_MODE_SEQUENTIAL: u32 = 0x0000_0001;
/// EVENT_TRACE_REAL_TIME_MODE: deliver events to real-time consumers instead of a file.
pub const REAL_TIME_MODE: u32 = 0x0000_0100;
/// EVENT_TRACE_INDEPENDENT_SESSION_MODE: other sessions' providers do not affect this one.
pub const INDEPENDENT_SESSION_MODE: u32 = 0x0800_0000;

/// ERROR_WMI_INSTANCE_NOT_FOUND: there is no session by that name.
pub const ERROR_WMI_INSTANCE_NOT_FOUND: u32 = 4201;
/// ERROR_ALREADY_EXISTS: a session by that name is running.
pub const ERROR_ALREADY_EXISTS: u32 = 183;
/// ERROR_ACCESS_DENIED: the caller is not elevated (or lacks a privilege).
pub const ERROR_ACCESS_DENIED: u32 = 5;

// A properties buffer: EVENT_TRACE_PROPERTIES, room for the session name and the log file name (as ETW returns them on
// queries), then an optional enable flag extension.
const PROPERTIES_SIZE: usize = size_of::<EVENT_TRACE_PROPERTIES>();
const MAX_NAME_CHARS: usize = 1024;
const NAME_BYTES: usize = MAX_NAME_CHARS * 2;
const LOGGER_NAME_OFFSET: usize = PROPERTIES_SIZE;
const LOG_FILE_NAME_OFFSET: usize = LOGGER_NAME_OFFSET + NAME_BYTES;
const EXTENSION_OFFSET: usize = LOG_FILE_NAME_OFFSET + NAME_BYTES;
const _: () = assert!(EXTENSION_OFFSET.is_multiple_of(8) && EXTENSION_OFFSET < 0x1_0000);

/// EnableFlags value saying the flags are in an extension at the (16-bit) offset in its low bits
/// (TRACE_ENABLE_FLAG_EXTENSION with EVENT_TRACE_FLAG_EXTENSION and a length of 0xFF, meaning 'see its header').
const ENABLE_FLAGS_EXTENSION: u32 = 0x80FF_0000;

const MAX_SESSIONS: usize = 64;
const MAX_QUERY_BYTES: usize = 16 * 1024 * 1024;

/// How to start a session.
#[derive(Clone, Copy, Debug)]
pub struct SessionConfig<'a> {
    pub name: &'a str,
    /// The file the session writes, or None for a real-time session.
    pub file: Option<&'a Path>,
    pub buffer_size_kb: u32,
    pub minimum_buffers: u32,
    pub maximum_buffers: u32,
    pub maximum_file_mb: u32,
    pub flush_timer_seconds: u32,
    pub log_file_mode: u32,
    /// The Wnode GUID: [`SYSTEM_TRACE_CONTROL_GUID`] for the NT Kernel Logger, None otherwise.
    pub guid: Option<Guid>,
    /// Kernel enable flags (EVENT_TRACE_FLAG_*), used when `extension` is empty.
    pub enable_flags: u32,
    /// An enable flag extension (a TRACE_ENABLE_FLAG_EXT_HEADER followed by its items, as 32-bit words), which is how
    /// a kernel session gets group masks beyond the classic enable flags, and its stack list, when it starts.
    pub extension: &'a [u32],
}

/// Starts a session and returns its handle.
pub fn start_session(config: &SessionConfig<'_>) -> Result<u64, Error> {
    let name = to_wide(config.name);
    let file = config.file.map(to_wide);
    if name.len() > MAX_NAME_CHARS || file.as_ref().is_some_and(|file| file.len() > MAX_NAME_CHARS) {
        return Err(Error(ERROR_BAD_LENGTH));
    }

    let extension: Vec<u8> = config.extension.iter().flat_map(|word| word.to_le_bytes()).collect();
    let size = EXTENSION_OFFSET.checked_add(extension.len()).ok_or(Error(ERROR_BAD_LENGTH))?;
    let mut properties = EVENT_TRACE_PROPERTIES::default();
    properties.Wnode.BufferSize = u32::try_from(size).map_err(|_| Error(ERROR_BAD_LENGTH))?;
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.Wnode.ClientContext = 1; // Timestamps from QueryPerformanceCounter.
    if let Some(guid) = config.guid {
        properties.Wnode.Guid = guid.to_sys();
    }

    properties.BufferSize = config.buffer_size_kb;
    properties.MinimumBuffers = config.minimum_buffers;
    properties.MaximumBuffers = config.maximum_buffers;
    properties.MaximumFileSize = config.maximum_file_mb;
    properties.LogFileMode = config.log_file_mode;
    properties.FlushTimer = config.flush_timer_seconds;
    properties.EnableFlags = if config.extension.is_empty() { config.enable_flags } else { ENABLE_FLAGS_EXTENSION | offset_u32(EXTENSION_OFFSET) };
    properties.LoggerNameOffset = offset_u32(LOGGER_NAME_OFFSET);
    properties.LogFileNameOffset = if file.is_some() { offset_u32(LOG_FILE_NAME_OFFSET) } else { 0 };

    let mut buffer = AlignedBuffer::new(size);
    write_properties(&mut buffer, 0, properties);
    let written = buffer.write_wide(LOGGER_NAME_OFFSET, &name) && file.as_ref().is_none_or(|file| buffer.write_wide(LOG_FILE_NAME_OFFSET, file)) && buffer.write(EXTENSION_OFFSET, &extension);
    if !written {
        return Err(Error(ERROR_BAD_LENGTH));
    }

    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
    // SAFETY: the buffer is 8-byte aligned and holds an EVENT_TRACE_PROPERTIES whose Wnode.BufferSize, name offsets and
    // extension offset all lie within the buffer; `name` is null terminated; both outlive the call.
    let status = unsafe { StartTraceW(&raw mut handle, name.as_ptr(), buffer.as_mut_ptr().cast()) };
    check(status)?;
    Ok(handle.Value)
}

/// Stops a session (and flushes its file).
pub fn stop_session(name: &str) -> Result<(), Error> {
    control(name, EVENT_TRACE_CONTROL_STOP).map(|_| ())
}

/// Returns the handle (TRACEHANDLE) of a running session.  Its low 16 bits are the logger ID.
pub fn query_session(name: &str) -> Result<u64, Error> {
    let properties = control(name, EVENT_TRACE_CONTROL_QUERY)?;
    // SAFETY: HistoricalContext is the 64-bit view of the union, which ControlTrace fills with the session's handle.
    Ok(unsafe { properties.Wnode.Anonymous1.HistoricalContext })
}

/// Returns the names of the running sessions.
pub fn active_session_names() -> Result<Vec<String>, Error> {
    let slot_size = EXTENSION_OFFSET;
    let mut buffer = AlignedBuffer::new(EXTENSION_OFFSET * MAX_SESSIONS);
    let mut properties = EVENT_TRACE_PROPERTIES::default();
    properties.Wnode.BufferSize = offset_u32(slot_size);
    properties.LoggerNameOffset = offset_u32(LOGGER_NAME_OFFSET);
    properties.LogFileNameOffset = offset_u32(LOG_FILE_NAME_OFFSET);

    let offsets: Vec<usize> = (0..MAX_SESSIONS).filter_map(|i| i.checked_mul(slot_size)).collect();
    let mut pointers = Vec::with_capacity(MAX_SESSIONS);
    for &offset in &offsets {
        write_properties(&mut buffer, offset, properties);
        pointers.push(buffer.as_mut_ptr().wrapping_add(offset).cast::<EVENT_TRACE_PROPERTIES>());
    }

    let mut count = 0u32;
    // SAFETY: each pointer is an 8-byte aligned EVENT_TRACE_PROPERTIES with room for both names within its
    // Wnode.BufferSize, inside `buffer`, which outlives the call; the array has MAX_SESSIONS entries.
    let status = unsafe { QueryAllTracesW(pointers.as_mut_ptr(), offset_u32(MAX_SESSIONS), &raw mut count) };
    if status != 0 && status != ERROR_MORE_DATA {
        return Err(Error(status));
    }

    let count = usize::try_from(count).unwrap_or(0).min(MAX_SESSIONS);
    Ok(offsets
        .iter()
        .take(count)
        .filter_map(|&offset| offset.checked_add(LOGGER_NAME_OFFSET))
        .map(|name| buffer.wide_at(name, MAX_NAME_CHARS))
        .collect())
}

/// Enables a (user mode) provider in a session, optionally with stacks on its events.
pub fn enable_provider(session: u64, provider: Guid, level: u8, match_any_keyword: u64, match_all_keyword: u64, stacks: bool) -> Result<(), Error> {
    let parameters = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
        EnableProperty: if stacks { EVENT_ENABLE_PROPERTY_STACK_TRACE } else { 0 },
        ..ENABLE_TRACE_PARAMETERS::default()
    };
    let provider = provider.to_sys();
    // SAFETY: the GUID and parameters (which have no filters) are valid for the duration of the call.
    let status = unsafe {
        EnableTraceEx2(
            CONTROLTRACE_HANDLE { Value: session },
            &raw const provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            level,
            match_any_keyword,
            match_all_keyword,
            0,
            &raw const parameters,
        )
    };
    check(status)
}

/// TraceSetInformation: sets one of a session's settings (or a system-wide one, with session 0).
pub fn set_information(session: u64, information_class: i32, data: &[u8]) -> Result<(), Error> {
    let length = u32::try_from(data.len()).map_err(|_| Error(ERROR_BAD_LENGTH))?;
    let buffer = AlignedBuffer::from_bytes(data);
    // SAFETY: the buffer holds `length` bytes, aligned for any information structure, and outlives the call.
    let status = unsafe { TraceSetInformation(CONTROLTRACE_HANDLE { Value: session }, information_class, buffer.as_ptr().cast(), length) };
    check(status)
}

/// TraceQueryInformation: reads one of a session's settings (or a system-wide one, with session 0).  The buffer starts
/// as a copy of `input` (some queries take a parameter in it) and grows from `capacity` bytes if ETW asks for more.
/// Returns the buffer and the length ETW said it returned (which some classes leave at 0).
pub fn query_information(session: u64, information_class: i32, input: &[u8], capacity: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut capacity = capacity.max(input.len()).max(4);
    loop {
        let mut buffer = AlignedBuffer::new(capacity);
        buffer.write(0, input);
        let length = u32::try_from(capacity).map_err(|_| Error(ERROR_BAD_LENGTH))?;
        let mut returned = 0u32;
        // SAFETY: the buffer holds `length` writable bytes, aligned for any information structure, and outlives the call.
        let status = unsafe { TraceQueryInformation(CONTROLTRACE_HANDLE { Value: session }, information_class, buffer.as_mut_ptr().cast(), length, &raw mut returned) };
        let returned = usize::try_from(returned).unwrap_or(0);
        let too_small = matches!(status, ERROR_INSUFFICIENT_BUFFER | ERROR_MORE_DATA | ERROR_BAD_LENGTH);
        if too_small && capacity < MAX_QUERY_BYTES {
            capacity = returned.max(capacity.saturating_mul(2)).min(MAX_QUERY_BYTES);
            continue;
        }

        check(status)?;
        return Ok((buffer.bytes().to_vec(), returned));
    }
}

fn control(name: &str, code: u32) -> Result<EVENT_TRACE_PROPERTIES, Error> {
    let mut properties = EVENT_TRACE_PROPERTIES::default();
    properties.Wnode.BufferSize = offset_u32(EXTENSION_OFFSET);
    properties.LoggerNameOffset = offset_u32(LOGGER_NAME_OFFSET);
    properties.LogFileNameOffset = offset_u32(LOG_FILE_NAME_OFFSET);
    let mut buffer = AlignedBuffer::new(EXTENSION_OFFSET);
    write_properties(&mut buffer, 0, properties);
    let name = to_wide(name);
    // SAFETY: the buffer is an 8-byte aligned EVENT_TRACE_PROPERTIES with room for both names within its
    // Wnode.BufferSize; `name` is null terminated; both outlive the call.
    let status = unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, name.as_ptr(), buffer.as_mut_ptr().cast(), code) };
    check(status)?;
    Ok(read_properties(&buffer))
}

/// Copies properties into the buffer at an offset that is a multiple of 8 (and fits; callers size the buffer).
fn write_properties(buffer: &mut AlignedBuffer, offset: usize, properties: EVENT_TRACE_PROPERTIES) {
    let fits = offset.checked_add(PROPERTIES_SIZE).is_some_and(|end| end <= buffer.len());
    if fits && offset.is_multiple_of(8) {
        let target = buffer.as_mut_ptr().wrapping_add(offset).cast::<EVENT_TRACE_PROPERTIES>();
        // SAFETY: the target is 8-byte aligned (the buffer is, and so is the offset) and in bounds (checked above).
        unsafe { target.write(properties) };
    }
}

fn read_properties(buffer: &AlignedBuffer) -> EVENT_TRACE_PROPERTIES {
    if buffer.len() < PROPERTIES_SIZE {
        return EVENT_TRACE_PROPERTIES::default();
    }

    // SAFETY: the buffer is 8-byte aligned and holds at least PROPERTIES_SIZE initialized bytes, and any bit pattern is
    // a valid EVENT_TRACE_PROPERTIES (integers, a GUID and a handle value).
    unsafe { buffer.as_ptr().cast::<EVENT_TRACE_PROPERTIES>().read() }
}

/// Offsets and sizes here are small constants, so they always fit.
fn offset_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
