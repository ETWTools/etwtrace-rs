//! Reading events: from trace files (several at once are merged in time order) or from a real-time session, with
//! `OpenTrace` / `ProcessTrace`.  Each event is handed to a callback as an [`EventRecord`], a view of ETW's own
//! EVENT_RECORD that is only valid during the callback, so nothing is copied.

use std::ffi::c_void;
use std::path::Path;

use windows_sys::Win32::Foundation::{ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER, GetLastError};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_HEADER_FLAG_CLASSIC_HEADER, EVENT_HEADER_FLAG_PROCESSOR_INDEX, EVENT_RECORD, EVENT_TRACE_LOGFILEW, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_RAW_TIMESTAMP, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, TRACE_LOGFILE_HEADER, TdhGetEventInformation, TdhGetManifestEventInformation,
};

use crate::buffer::AlignedBuffer;
use crate::wide::to_wide;
use crate::{Error, Guid, check};

/// INVALID_PROCESSTRACE_HANDLE, as OpenTrace returns it to a 64-bit process.
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;

/// The callback ProcessTrace calls (through `on_event`) for each event.
type Handler<'f> = &'f mut dyn FnMut(&EventRecord<'_>);

/// One event, as ETW delivers it.  Timestamps are raw QueryPerformanceCounter values (the trace's clock).
#[derive(Clone, Copy)]
pub struct EventRecord<'a> {
    raw: &'a EVENT_RECORD,
}

impl<'a> EventRecord<'a> {
    pub(crate) const fn new(raw: &'a EVENT_RECORD) -> Self {
        Self { raw }
    }

    /// The provider; for classic (MOF) events, such as the kernel's, the event class GUID.
    #[must_use]
    pub const fn provider(&self) -> Guid {
        Guid::from_sys(self.raw.EventHeader.ProviderId)
    }

    #[must_use]
    pub const fn id(&self) -> u16 {
        self.raw.EventHeader.EventDescriptor.Id
    }

    #[must_use]
    pub const fn version(&self) -> u8 {
        self.raw.EventHeader.EventDescriptor.Version
    }

    /// The opcode; for classic events, the event type.
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        self.raw.EventHeader.EventDescriptor.Opcode
    }

    #[must_use]
    pub const fn level(&self) -> u8 {
        self.raw.EventHeader.EventDescriptor.Level
    }

    /// EVENT_HEADER_FLAG_* bits.
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.raw.EventHeader.Flags
    }

    /// The thread that logged the event (0xFFFFFFFF if the kernel did not say).
    #[must_use]
    pub const fn thread_id(&self) -> u32 {
        self.raw.EventHeader.ThreadId
    }

    /// The process that logged the event (0xFFFFFFFF if the kernel did not say).
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.raw.EventHeader.ProcessId
    }

    #[must_use]
    pub const fn timestamp(&self) -> i64 {
        self.raw.EventHeader.TimeStamp
    }

    /// The processor that logged the event (GetEventProcessorIndex).
    #[must_use]
    pub fn processor_index(&self) -> u16 {
        let context = &self.raw.BufferContext.Anonymous;
        if u32::from(self.flags()) & EVENT_HEADER_FLAG_PROCESSOR_INDEX != 0 {
            // SAFETY: the header flag says ETW filled in the 16-bit processor index view of the union.
            unsafe { context.ProcessorIndex }
        } else {
            // SAFETY: otherwise the union holds the 8-bit processor number (and an alignment byte).
            u16::from(unsafe { context.Anonymous.ProcessorNumber })
        }
    }

    /// True if the event was logged by 64-bit code (pointers in its payload are 8 bytes).
    #[must_use]
    pub fn is_64_bit(&self) -> bool {
        u32::from(self.raw.EventHeader.Flags) & EVENT_HEADER_FLAG_64_BIT_HEADER != 0
    }

    /// True if the event was logged by 32-bit code.
    #[must_use]
    pub fn is_32_bit(&self) -> bool {
        u32::from(self.raw.EventHeader.Flags) & EVENT_HEADER_FLAG_32_BIT_HEADER != 0
    }

    /// True for classic (MOF style) events, such as the kernel's.
    #[must_use]
    pub fn is_classic(&self) -> bool {
        u32::from(self.raw.EventHeader.Flags) & EVENT_HEADER_FLAG_CLASSIC_HEADER != 0
    }

    /// The event's payload.
    #[must_use]
    pub fn user_data(&self) -> &'a [u8] {
        let length = usize::from(self.raw.UserDataLength);
        if length == 0 || self.raw.UserData.is_null() {
            return &[];
        }

        // SAFETY: ETW provides UserDataLength readable bytes at UserData for as long as the record is valid, which 'a
        // covers.
        unsafe { std::slice::from_raw_parts(self.raw.UserData.cast::<u8>(), length) }
    }

    /// The extended data items (EVENT_HEADER_EXT_TYPE_*, data) attached to the event, such as stacks of user mode
    /// events and the PMC counter values of context switches.
    pub fn extended_data(&self) -> impl Iterator<Item = (u16, &'a [u8])> + 'a {
        let count = usize::from(self.raw.ExtendedDataCount);
        let items = if count == 0 || self.raw.ExtendedData.is_null() {
            &[]
        } else {
            // SAFETY: ETW provides ExtendedDataCount items at ExtendedData for as long as the record is valid.
            unsafe { std::slice::from_raw_parts(self.raw.ExtendedData, count) }
        };

        items.iter().map(|item| {
            let size = usize::from(item.DataSize);
            let data = if size == 0 || item.DataPtr == 0 {
                &[][..]
            } else {
                // SAFETY: each item's DataPtr points at DataSize readable bytes for as long as the record is valid.
                unsafe { std::slice::from_raw_parts(item.DataPtr as *const u8, size) }
            };
            (item.ExtType, data)
        })
    }

    /// The event's schema (a TRACE_EVENT_INFO) from TDH: from the MOF class for classic events, from the registered
    /// manifest for others.  None if TDH does not know the event.
    #[must_use]
    pub fn metadata(&self) -> Option<Vec<u8>> {
        let mut size = 0u32;
        let status = self.tdh_event_information(None, &mut size);
        if status != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return None;
        }

        let mut buffer = AlignedBuffer::new(usize::try_from(size).ok()?);
        if self.tdh_event_information(Some(&mut buffer), &mut size) != 0 {
            return None;
        }

        let length = usize::try_from(size).ok()?.min(buffer.len());
        buffer.bytes().get(..length).map(<[u8]>::to_vec)
    }

    fn tdh_event_information(&self, buffer: Option<&mut AlignedBuffer>, size: &mut u32) -> u32 {
        let target = buffer.map_or(std::ptr::null_mut(), |buffer| buffer.as_mut_ptr().cast());
        if self.is_classic() {
            // SAFETY: the record is valid; the target is null (with size 0) or an aligned buffer of `size` bytes.
            unsafe { TdhGetEventInformation(self.raw, 0, std::ptr::null(), target, size) }
        } else {
            let header = &self.raw.EventHeader;
            // SAFETY: as above; the GUID and descriptor are read only during the call.
            unsafe { TdhGetManifestEventInformation(&raw const header.ProviderId, &raw const header.EventDescriptor, target, size) }
        }
    }
}

/// What a trace file's header says about it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TraceInfo {
    /// When the session started and stopped, as FILETIMEs (100ns units since 1601, UTC).
    pub start_time: i64,
    pub end_time: i64,
    /// Ticks per second of the timestamps.
    pub perf_freq: i64,
    /// 1 for QueryPerformanceCounter timestamps, 2 for system time, 3 for CPU cycles.
    pub clock_type: u32,
    pub pointer_size: u32,
    pub number_of_processors: u32,
    pub events_lost: u32,
    pub buffers_lost: u32,
}

impl TraceInfo {
    fn from_header(header: &TRACE_LOGFILE_HEADER) -> Self {
        // SAFETY: for a log file opened for processing, ETW fills the union with the StartBuffers / PointerSize /
        // EventsLost / CpuSpeedInMHz view (the GUID view is for real-time delivery).
        let extra = unsafe { header.Anonymous2.Anonymous };
        Self {
            start_time: header.StartTime,
            end_time: header.EndTime,
            perf_freq: header.PerfFreq,
            clock_type: header.ReservedFlags,
            pointer_size: extra.PointerSize,
            number_of_processors: header.NumberOfProcessors,
            events_lost: extra.EventsLost,
            buffers_lost: header.BuffersLost,
        }
    }
}

/// Reads trace files, merged in time order, calling `callback` for every event.  Returns each file's header info.
pub fn process_files<F>(paths: &[&Path], mut callback: F) -> Result<Vec<TraceInfo>, Error>
where
    F: FnMut(&EventRecord<'_>),
{
    let mut handler: Handler<'_> = &mut callback;
    let context: *mut c_void = (&raw mut handler).cast();
    let names: Vec<Vec<u16>> = paths.iter().map(to_wide).collect();
    let mut handles = Vec::with_capacity(names.len());
    let mut infos = Vec::with_capacity(names.len());
    let mut result = Ok(());
    for name in &names {
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LogFileName: name.as_ptr().cast_mut(),
            ..EVENT_TRACE_LOGFILEW::default()
        };
        match open(&mut logfile, PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP, context) {
            Ok(handle) => {
                handles.push(handle);
                infos.push(TraceInfo::from_header(&logfile.LogfileHeader));
            }
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }

    if result.is_ok() {
        result = process(&handles);
    }

    close(&handles);
    result.map(|()| infos)
}

/// Reads a trace file's header without processing its events.
pub fn file_info(path: &Path) -> Result<TraceInfo, Error> {
    let name = to_wide(path);
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LogFileName: name.as_ptr().cast_mut(),
        ..EVENT_TRACE_LOGFILEW::default()
    };
    let mode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    let handle = open(&mut logfile, mode, std::ptr::null_mut())?;
    let info = TraceInfo::from_header(&logfile.LogfileHeader);
    close(&[handle]);
    Ok(info)
}

/// Reads a real-time session, calling `callback` for every event, until the session stops.
pub fn process_session<F>(session_name: &str, mut callback: F) -> Result<(), Error>
where
    F: FnMut(&EventRecord<'_>),
{
    let mut handler: Handler<'_> = &mut callback;
    let context: *mut c_void = (&raw mut handler).cast();
    let name = to_wide(session_name);
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: name.as_ptr().cast_mut(),
        ..EVENT_TRACE_LOGFILEW::default()
    };
    let mode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_REAL_TIME;
    let handle = open(&mut logfile, mode, context)?;
    let result = process(&[handle]);
    close(&[handle]);
    result
}

/// OpenTrace.  `context` must point at a [`Handler`] that outlives the processing of the returned handle.
fn open(logfile: &mut EVENT_TRACE_LOGFILEW, mode: u32, context: *mut c_void) -> Result<PROCESSTRACE_HANDLE, Error> {
    logfile.Anonymous1.ProcessTraceMode = mode;
    logfile.Anonymous2.EventRecordCallback = Some(on_event);
    logfile.Context = context;
    // SAFETY: the log file or logger name it points at is null terminated and outlives the call; the callback and
    // context are valid for as long as the handle is processed (see the callers).
    let handle = unsafe { OpenTraceW(logfile) };
    if handle.Value == INVALID_PROCESSTRACE_HANDLE {
        // SAFETY: no preconditions.
        return Err(Error(unsafe { GetLastError() }));
    }

    Ok(handle)
}

fn process(handles: &[PROCESSTRACE_HANDLE]) -> Result<(), Error> {
    let count = u32::try_from(handles.len()).unwrap_or(u32::MAX);
    // SAFETY: the handles came from OpenTrace and are not closed yet; null start and end times mean 'everything'.
    let status = unsafe { ProcessTrace(handles.as_ptr(), count, std::ptr::null(), std::ptr::null()) };
    if status == ERROR_CANCELLED { Ok(()) } else { check(status) }
}

fn close(handles: &[PROCESSTRACE_HANDLE]) {
    for &handle in handles {
        // SAFETY: each handle came from OpenTrace and is closed once.
        unsafe { CloseTrace(handle) };
    }
}

/// The EVENT_RECORD callback: hands the event to the [`Handler`] that UserContext points at.
unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    // SAFETY: ProcessTrace passes a valid record that lives until this call returns.
    let Some(record) = (unsafe { record.as_ref() }) else {
        return;
    };

    let handler = record.UserContext.cast::<Handler<'_>>();
    // SAFETY: UserContext is the Context given to OpenTrace: a Handler on the stack of process_files or
    // process_session, which stays alive, and is not otherwise touched, while ProcessTrace runs on that same thread.
    if let Some(handler) = unsafe { handler.as_mut() } {
        handler(&EventRecord::new(record));
    }
}
