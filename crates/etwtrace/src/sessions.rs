//! Starting and stopping the sessions 'record' and 'probe' use, the way TraceEvent's TraceEventSession does for the
//! kernel: the group masks go in the enable flag extension of EVENT_TRACE_PROPERTIES (which is how event groups that
//! have no classic enable flag, like PMC sampling and handles, are turned on when the session starts), and so does the
//! stack list.

use std::path::Path;
use std::time::Duration;

use etw::session::{self, KERNEL_LOGGER_NAME, SessionConfig};

use crate::AppError;
use crate::profile_sources::TIMER_ID;

/// A running session, stopped when dropped.
pub struct Session {
    name: String,
    pub handle: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = session::stop_session(&self.name);
    }
}

const BUFFER_KB: u32 = 64;
// TRACE_ENABLE_FLAG_EXT_ITEM types.
const ETW_EXT_ENABLE_FLAGS: u32 = 1; // The PERFINFO_GROUPMASK.
const ETW_EXT_STACKWALK_FILTER: u32 = 3; // Hook IDs of the events that get stacks, one per dword.

/// Starts the NT Kernel Logger with the given group masks and stacks on the events with the given hook IDs, writing to
/// `file` (or real-time, for None).  With the profile or PMC profile groups it also sets the SampledProfile interval, as
/// TraceEvent does.
pub fn start_kernel(file: Option<&Path>, buffer_mb: u32, group_masks: [u32; 8], stacks: &[u16], cpu_sample_msec: f32) -> Result<Session, AppError> {
    let [mask0, mask1, ..] = group_masks;
    let profiling = mask0 & crate::kernel_config::keywords::PROFILE != 0 || mask1 & 0x400 != 0;
    if profiling {
        set_cpu_sample_interval(cpu_sample_msec)?;
    }

    // The stack list goes in with the group masks, as KernelTraceControl's StartKernelSession does, rather than being
    // set once the session runs (TraceStackTracingInfo): starting the kernel logger includes its rundown, which takes
    // long enough (about 150 ms) for thousands of context switches that would get no stacks.
    let stacks: Vec<u32> = stacks.iter().map(|&hook_id| u32::from(hook_id)).collect();
    let mut extension = vec![0]; // The TRACE_ENABLE_FLAG_EXT_HEADER, once the items are in.
    push_extension_item(&mut extension, ETW_EXT_ENABLE_FLAGS, &group_masks);
    let mut items = 1u32;
    if !stacks.is_empty() {
        push_extension_item(&mut extension, ETW_EXT_STACKWALK_FILTER, &stacks);
        items = 2;
    }

    let length = extension_length(extension.len());
    if let Some(header) = extension.first_mut() {
        *header = length | items.wrapping_shl(16);
    }

    let minimum_buffers = buffer_mb.saturating_mul(1024).checked_div(BUFFER_KB).unwrap_or(0);
    let config = SessionConfig {
        name: KERNEL_LOGGER_NAME,
        file,
        buffer_size_kb: BUFFER_KB,
        minimum_buffers,
        maximum_buffers: maximum_buffers(minimum_buffers),
        maximum_file_mb: 0,
        flush_timer_seconds: if file.is_some() { 60 } else { 1 },
        log_file_mode: session::INDEPENDENT_SESSION_MODE | if file.is_some() { session::FILE_MODE_SEQUENTIAL } else { session::REAL_TIME_MODE },
        guid: Some(session::SYSTEM_TRACE_CONTROL_GUID),
        enable_flags: 0,
        extension: &extension,
    };
    start(&config)
}

/// Starts a user mode session writing to `file`, sized like TraceEvent's default.
pub fn start_user(name: &str, file: &Path) -> Result<Session, AppError> {
    let processors = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let buffer_mb = u32::try_from(processors.saturating_mul(2)).unwrap_or(u32::MAX).max(64);
    let minimum_buffers = buffer_mb.saturating_mul(1024).checked_div(BUFFER_KB).unwrap_or(0);
    let config = SessionConfig {
        name,
        file: Some(file),
        buffer_size_kb: BUFFER_KB,
        minimum_buffers,
        maximum_buffers: maximum_buffers(minimum_buffers),
        maximum_file_mb: 0,
        flush_timer_seconds: 60,
        log_file_mode: session::INDEPENDENT_SESSION_MODE | session::FILE_MODE_SEQUENTIAL,
        guid: None,
        enable_flags: 0,
        extension: &[],
    };
    start(&config)
}

/// Starts a session, first stopping one left running by that name.
fn start(config: &SessionConfig<'_>) -> Result<Session, AppError> {
    let mut result = session::start_session(config);
    if result.is_err_and(|e| e.code() == session::ERROR_ALREADY_EXISTS) {
        let _ = session::stop_session(config.name);
        std::thread::sleep(Duration::from_millis(100));
        result = session::start_session(config);
    }

    match result {
        Ok(handle) => Ok(Session { name: config.name.to_owned(), handle }),
        Err(e) if e.code() == session::ERROR_ACCESS_DENIED => Err(AppError::new("Error Starting ETW:  Access Denied (Administrator rights required to start ETW)")),
        Err(e) => Err(e.into()),
    }
}

/// TraceEvent's buffer limit: a quarter more than the minimum, plus 10.
fn maximum_buffers(minimum: u32) -> u32 {
    minimum.saturating_mul(5).checked_div(4).unwrap_or(0).saturating_add(10)
}

/// Appends an item of the enable flag extension: a TRACE_ENABLE_FLAG_EXT_ITEM (the item's length in dwords, including
/// itself, then its type), then its data.
fn push_extension_item(extension: &mut Vec<u32>, item_type: u32, data: &[u32]) {
    extension.push(extension_length(data.len().saturating_add(1)) | item_type.wrapping_shl(16));
    extension.extend_from_slice(data);
}

/// A length in dwords, for the 16-bit length fields of the extension's headers.
fn extension_length(dwords: usize) -> u32 {
    u32::from(u16::try_from(dwords).unwrap_or(u16::MAX))
}

/// The SampledProfile interval (system-wide; 'record' puts the old one back).  It needs SeSystemProfilePrivilege.
fn set_cpu_sample_interval(msec: f32) -> Result<(), AppError> {
    let _ = etw::system::enable_privilege("SeSystemProfilePrivilege");
    let interval = f64::from(msec) * 10_000.0 + 0.5; // 100ns units.
    if interval >= f64::from(i32::MAX) || interval as i32 > 10_000_000 {
        return Err(AppError::new("CPU Sampling interval is too large."));
    }

    if crate::pmc::set_profile_interval(TIMER_ID, interval as i32).is_err() && msec != 1.0 {
        return Err(AppError::new(format!("Can't set CPU sampling to {}MSec.", crate::text::fixed(f64::from(msec), 3))));
    }

    Ok(())
}

pub fn require_elevated_and_kernel_logger_free() -> Result<(), AppError> {
    if etw::system::is_elevated() != Some(true) {
        return Err(AppError::new("This command needs an elevated (Administrator) prompt."));
    }

    let names = session::active_session_names()?;
    if names.iter().any(|name| crate::text::eq_ignore_case(name, KERNEL_LOGGER_NAME)) {
        return Err(AppError::new(
            "The NT Kernel Logger session is already in use (by PerfView, xperf, or a previous run?).  Stop it with: logman stop \"NT Kernel Logger\" -ets",
        ));
    }

    Ok(())
}
