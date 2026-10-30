//! Rewriting traces with the OS relogger (`ITraceRelogger`, the COM object behind `CLSID_TraceRelogger`): it reads a
//! trace file and calls back for each event, which the callback writes to the output (or not), and before which it can
//! write new events.  This is how 'record' merges its session files and adds the image identity, volume mapping and
//! event metadata events that let a trace be read on another machine.
//!
//! The relogger takes only one trace file: a second `AddLogfileTraceStream` fails with E_INVALIDARG (seen on Windows
//! build 26300, and with TraceEvent's relogger too).  So to merge several files, the first is relogged and the others are
//! read first, into clones of their events, which the relogger then writes in time order among the first file's events.
//!
//! windows-sys has no COM interfaces, so the three interfaces used are declared here by vtable, as in relogger.h.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{E_INVALIDARG, RPC_E_CHANGED_MODE, SysAllocString, SysFreeString};
use windows_sys::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows_sys::Win32::System::Diagnostics::Etw::{CLSID_TraceRelogger, EVENT_DESCRIPTOR, EVENT_RECORD};
use windows_sys::core::{BSTR, GUID, HRESULT};

use crate::consumer::EventRecord;
use crate::wide::to_wide;
use crate::{Error, Guid};

const S_OK: HRESULT = 0;
const E_NOINTERFACE: HRESULT = 0x8000_4002_u32 as HRESULT;
const E_POINTER: HRESULT = 0x8000_4003_u32 as HRESULT;

const IID_IUNKNOWN: GUID = GUID::from_u128(0x0000_0000_0000_0000_c000_0000_0000_0046);
const IID_ITRACE_RELOGGER: GUID = GUID::from_u128(0xf754_ad43_3bcc_4286_8009_9c5d_a214_e84e);
const IID_ITRACE_EVENT_CALLBACK: GUID = GUID::from_u128(0x3ed2_5501_593f_43e9_8f38_3ab4_6f5a_4a52);

/// The EventTrace provider, whose events (the trace header and its extensions) describe the trace file they are in.
const EVENT_TRACE: Guid = Guid::from_u128(0x68fd_d900_4a3e_11d1_84f4_0000_f804_64e3);

/// An event to add to the output.
#[derive(Clone, Copy, Debug)]
pub struct NewEvent<'a> {
    pub provider: Guid,
    pub id: u16,
    pub version: u8,
    pub level: u8,
    pub opcode: u8,
    /// EVENT_HEADER_FLAG_* bits (e.g. classic header, 64-bit header).
    pub flags: u16,
    pub timestamp: i64,
    pub processor_index: u16,
    pub process_id: u32,
    pub thread_id: u32,
    pub payload: &'a [u8],
}

/// What the relogger calls back with, for each event of the inputs in time order.
pub trait RelogHandler {
    /// Decides what happens to `event`: [`RelogContext::keep`] writes it to the output, and [`RelogContext::inject`]
    /// writes new events (before it, if called first).  Errors are kept and returned by [`relog`].
    fn on_event(&mut self, event: &EventRecord<'_>, relog: &mut RelogContext<'_>);
}

/// Writes events to the output during [`RelogHandler::on_event`].
pub struct RelogContext<'a> {
    relogger: *mut RawRelogger,
    /// The event being processed: the relogger's, or a clone of an event of a later input.
    current: *mut RawTraceEvent,
    stream: u64,
    error: &'a mut Option<Error>,
}

impl RelogContext<'_> {
    /// Writes the event being processed to the output.
    pub fn keep(&mut self) {
        let vtbl = relogger_vtbl(self.relogger);
        // SAFETY: both pointers are the live objects the relogger passed to OnEvent, which is still running.
        let status = unsafe { (vtbl.inject)(self.relogger, self.current) };
        self.note(status);
    }

    /// Writes a new event to the output.
    pub fn inject(&mut self, event: &NewEvent<'_>) {
        let status = self.try_inject(event, false);
        self.note(status);
    }

    /// Writes a new event made from a copy of the event being processed, so it keeps that event's header flags (the
    /// relogger writes events it creates with kernel event GUIDs as 32-bit; copies of 64-bit events stay 64-bit).  The
    /// copy also keeps the event's time, processor and IDs: `event.flags`, `timestamp`, `processor_index`,
    /// `process_id` and `thread_id` are ignored.
    pub fn inject_copy(&mut self, event: &NewEvent<'_>) {
        let status = self.try_inject(event, true);
        self.note(status);
    }

    fn try_inject(&self, event: &NewEvent<'_>, copy: bool) -> HRESULT {
        let relogger_vtbl = relogger_vtbl(self.relogger);
        let mut created: *mut RawTraceEvent = std::ptr::null_mut();
        let status = if copy {
            // SAFETY: the current event is live for the duration of OnEvent; `created` is a valid out pointer.
            unsafe { (event_vtbl(self.current).clone)(self.current, &raw mut created) }
        } else {
            // SAFETY: the relogger is live; `created` is a valid out pointer.
            unsafe { (relogger_vtbl.create_event_instance)(self.relogger, self.stream, u32::from(event.flags), &raw mut created) }
        };
        if status < 0 {
            return status;
        }

        if created.is_null() {
            return E_POINTER;
        }

        let descriptor = EVENT_DESCRIPTOR {
            Id: event.id,
            Version: event.version,
            Channel: 0,
            Level: event.level,
            Opcode: event.opcode,
            Task: 0,
            Keyword: 0,
        };
        let provider = event.provider.to_sys();
        let timestamp = event.timestamp;
        let length = u32::try_from(event.payload.len()).unwrap_or(u32::MAX);
        let vtbl = event_vtbl(created);
        // SAFETY (for each call below): `created` is the live event made above, used only by this thread, and every
        // pointer argument points at a local that outlives the call.  The payload outlives the Inject call below, by
        // which time the relogger has copied it.
        let mut steps: Vec<HRESULT> = Vec::with_capacity(7);
        // SAFETY: as above.
        steps.push(unsafe { (vtbl.set_event_descriptor)(created, &raw const descriptor) });
        // SAFETY: as above.
        steps.push(unsafe { (vtbl.set_provider_id)(created, &raw const provider) });
        // SAFETY: as above.
        steps.push(unsafe { (vtbl.set_payload)(created, event.payload.as_ptr(), length) });
        if !copy {
            // A copy keeps the copied event's time, processor and IDs: the relogger fails setting them on copies.
            // SAFETY: as above.
            steps.push(unsafe { (vtbl.set_time_stamp)(created, &raw const timestamp) });
            // SAFETY: as above.
            steps.push(unsafe { (vtbl.set_processor_index)(created, u32::from(event.processor_index)) });
            // SAFETY: as above.
            steps.push(unsafe { (vtbl.set_process_id)(created, event.process_id) });
            // SAFETY: as above.
            steps.push(unsafe { (vtbl.set_thread_id)(created, event.thread_id) });
        }

        let mut status = steps.into_iter().find(|&step| step < 0).unwrap_or(S_OK);
        if status >= 0 {
            // SAFETY: both objects are live.
            status = unsafe { (relogger_vtbl.inject)(self.relogger, created) };
        }

        // SAFETY: releases the reference CreateEventInstance returned.
        unsafe { (vtbl.release)(created) };
        status
    }

    fn note(&mut self, status: HRESULT) {
        if status < 0 && self.error.is_none() {
            *self.error = Some(Error(status as u32));
        }
    }

    /// A clone of the event being processed, which outlives the callback and the relogger.
    fn clone_current(&mut self) -> Option<ClonedEvent> {
        let mut created: *mut RawTraceEvent = std::ptr::null_mut();
        // SAFETY: the current event is live for the duration of OnEvent; `created` is a valid out pointer.
        let status = unsafe { (event_vtbl(self.current).clone)(self.current, &raw mut created) };
        self.note(status);
        if status < 0 || created.is_null() {
            return None;
        }

        let clone = ClonedEvent::new(created);
        if clone.is_none() {
            self.note(E_POINTER);
        }

        clone
    }
}

/// Reads the input traces and writes `output`, calling `handler` for every event in time order.  The first input is
/// relogged; the others are read into memory first (so they should be small) and their events handed to `handler` among
/// the first's, without their EventTrace events.  The output has the first input's trace header, and so its time span
/// (from when the first input's session started to when it stopped); readers count earlier events from its start.
pub fn relog<H: RelogHandler>(inputs: &[&Path], output: &Path, handler: &mut H) -> Result<(), Error> {
    let _com = ComApartment::enter()?;
    let (first, others) = inputs.split_first().ok_or(Error(E_INVALIDARG as u32))?;
    let mut later = Vec::new();
    for (index, input) in others.iter().enumerate() {
        // Reading a trace with the relogger writes one too; this one gets only the input's header.
        let scratch = scratch_path(output, index);
        let mut collector = Collector::default();
        let result = relog_file(input, &scratch, &mut collector, VecDeque::new());
        let _ = std::fs::remove_file(&scratch);
        result?;
        later.append(&mut collector.events);
    }

    later.sort_by_key(|event| event.timestamp); // Stable, so events of one input keep their order.
    relog_file(first, output, handler, later.into())
}

/// Relogs one trace file, handing `later` (events of other inputs, in time order) to the handler among its events.
fn relog_file<H: RelogHandler>(input: &Path, output: &Path, handler: &mut H, later: VecDeque<ClonedEvent>) -> Result<(), Error> {
    let relogger = Relogger::create()?;
    let stream = relogger.add_logfile(input)?;
    relogger.set_output(output)?;
    let callback = Box::into_raw(Box::new(Callback {
        vtbl: &CALLBACK_VTBL,
        references: AtomicU32::new(1),
        handler: std::ptr::from_mut(handler).cast(),
        dispatch: dispatch::<H>,
        stream,
        later,
        error: None,
    }));

    let mut result = relogger.register(callback);
    if result.is_ok() {
        result = relogger.process();
    }

    // Releasing the relogger releases its reference to the callback, which must outlive it.
    drop(relogger);
    // SAFETY: `callback` came from Box::into_raw above and the relogger, the only other holder, is gone.
    let references = unsafe { (*callback).references.load(Ordering::SeqCst) };
    // SAFETY: as above.
    let error = unsafe { (*callback).error };
    if references == 1 {
        // SAFETY: no one else references the callback now, so it can be freed (once).
        drop(unsafe { Box::from_raw(callback) });
    }

    result?;
    error.map_or(Ok(()), Err)
}

/// Where reading the `index`th later input writes its (unused) output.
fn scratch_path(output: &Path, index: usize) -> PathBuf {
    let mut path = output.as_os_str().to_owned();
    path.push(format!(".input{index}.tmp"));
    PathBuf::from(path)
}

/// Keeps clones of an input's events, except its EventTrace events.
#[derive(Default)]
struct Collector {
    events: Vec<ClonedEvent>,
}

impl RelogHandler for Collector {
    fn on_event(&mut self, event: &EventRecord<'_>, relog: &mut RelogContext<'_>) {
        if event.provider() != EVENT_TRACE
            && let Some(clone) = relog.clone_current()
        {
            self.events.push(clone);
        }
    }
}

/// A clone of an event (an ITraceEvent reference, released on drop), which a relogger other than the one that read it
/// can write.
struct ClonedEvent {
    event: *mut RawTraceEvent,
    timestamp: i64,
}

impl ClonedEvent {
    /// Takes over the reference to `event`, a live clone.
    fn new(event: *mut RawTraceEvent) -> Option<Self> {
        let mut clone = Self { event, timestamp: 0 };
        clone.timestamp = clone.record()?.EventHeader.TimeStamp;
        Some(clone)
    }

    fn record(&self) -> Option<&EVENT_RECORD> {
        let mut record: *mut EVENT_RECORD = std::ptr::null_mut();
        // SAFETY: the event is live while `self` holds its reference; `record` is a valid out pointer.
        let status = unsafe { (event_vtbl(self.event).get_event_record)(self.event, &raw mut record) };
        if status < 0 {
            return None;
        }

        // SAFETY: on success the record belongs to the event, which lives as long as `self`.
        unsafe { record.as_ref() }
    }
}

impl Drop for ClonedEvent {
    fn drop(&mut self) {
        // SAFETY: releases the reference Clone returned, once.
        unsafe { (event_vtbl(self.event).release)(self.event) };
    }
}

/// COM for this thread, for the lifetime of the value.
struct ComApartment {
    uninitialize: bool,
}

impl ComApartment {
    fn enter() -> Result<Self, Error> {
        // SAFETY: no preconditions; balanced by CoUninitialize on drop when it succeeds.
        let status = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
        if status == RPC_E_CHANGED_MODE {
            return Ok(Self { uninitialize: false }); // The thread is already in an apartment, which serves as well.
        }

        if status < 0 {
            return Err(Error(status as u32));
        }

        Ok(Self { uninitialize: true })
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            // SAFETY: balances the successful CoInitializeEx.
            unsafe { CoUninitialize() };
        }
    }
}

/// An ITraceRelogger reference, released on drop.
struct Relogger(*mut RawRelogger);

impl Relogger {
    fn create() -> Result<Self, Error> {
        let clsid = CLSID_TraceRelogger;
        let iid = IID_ITRACE_RELOGGER;
        let mut relogger: *mut c_void = std::ptr::null_mut();
        // SAFETY: valid CLSID, IID and out pointer.
        let status = unsafe { CoCreateInstance(&raw const clsid, std::ptr::null_mut(), CLSCTX_INPROC_SERVER, &raw const iid, &raw mut relogger) };
        if status < 0 || relogger.is_null() {
            return Err(Error(if status < 0 { status as u32 } else { E_POINTER as u32 }));
        }

        Ok(Self(relogger.cast()))
    }

    fn vtbl(&self) -> &'static RawReloggerVtbl {
        relogger_vtbl(self.0)
    }

    fn add_logfile(&self, path: &Path) -> Result<u64, Error> {
        let name = Bstr::new(path)?;
        let mut stream = 0u64;
        // SAFETY: the BSTR outlives the call (the relogger copies it) and `stream` is a valid out pointer.
        hresult(unsafe { (self.vtbl().add_logfile_trace_stream)(self.0, name.0, std::ptr::null_mut(), &raw mut stream) })?;
        Ok(stream)
    }

    fn set_output(&self, path: &Path) -> Result<(), Error> {
        let name = Bstr::new(path)?;
        // SAFETY: the BSTR outlives the call.
        hresult(unsafe { (self.vtbl().set_output_filename)(self.0, name.0) })
    }

    fn register(&self, callback: *mut Callback) -> Result<(), Error> {
        // SAFETY: the callback is a live COM object (it starts with its vtable) that outlives the relogger.
        hresult(unsafe { (self.vtbl().register_callback)(self.0, callback.cast()) })
    }

    fn process(&self) -> Result<(), Error> {
        // SAFETY: the relogger is live; it calls the registered callback on this thread until it returns.
        hresult(unsafe { (self.vtbl().process_trace)(self.0) })
    }
}

impl Drop for Relogger {
    fn drop(&mut self) {
        // SAFETY: releases the reference CoCreateInstance returned, once.
        unsafe { (self.vtbl().release)(self.0) };
    }
}

/// A BSTR, freed on drop.
struct Bstr(BSTR);

impl Bstr {
    fn new(path: &Path) -> Result<Self, Error> {
        let wide = to_wide(path);
        // SAFETY: the string is null terminated; SysAllocString copies it.
        let bstr = unsafe { SysAllocString(wide.as_ptr()) };
        if bstr.is_null() { Err(Error(E_POINTER as u32)) } else { Ok(Self(bstr)) }
    }
}

impl Drop for Bstr {
    fn drop(&mut self) {
        // SAFETY: the BSTR came from SysAllocString and is freed once.
        unsafe { SysFreeString(self.0) };
    }
}

fn hresult(status: HRESULT) -> Result<(), Error> {
    if status < 0 { Err(Error(status as u32)) } else { Ok(()) }
}

// The interfaces, as in relogger.h.  Each object starts with a pointer to its vtable.

#[repr(C)]
struct RawRelogger {
    vtbl: *const RawReloggerVtbl,
}

#[repr(C)]
#[allow(dead_code, reason = "The vtable must list every method, used or not.")]
struct RawReloggerVtbl {
    query_interface: unsafe extern "system" fn(*mut RawRelogger, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut RawRelogger) -> u32,
    release: unsafe extern "system" fn(*mut RawRelogger) -> u32,
    add_logfile_trace_stream: unsafe extern "system" fn(*mut RawRelogger, BSTR, *mut c_void, *mut u64) -> HRESULT,
    add_realtime_trace_stream: unsafe extern "system" fn(*mut RawRelogger, BSTR, *mut c_void, *mut u64) -> HRESULT,
    register_callback: unsafe extern "system" fn(*mut RawRelogger, *mut c_void) -> HRESULT,
    inject: unsafe extern "system" fn(*mut RawRelogger, *mut RawTraceEvent) -> HRESULT,
    create_event_instance: unsafe extern "system" fn(*mut RawRelogger, u64, u32, *mut *mut RawTraceEvent) -> HRESULT,
    process_trace: unsafe extern "system" fn(*mut RawRelogger) -> HRESULT,
    set_output_filename: unsafe extern "system" fn(*mut RawRelogger, BSTR) -> HRESULT,
    set_compression_mode: unsafe extern "system" fn(*mut RawRelogger, u8) -> HRESULT,
    cancel: unsafe extern "system" fn(*mut RawRelogger) -> HRESULT,
}

#[repr(C)]
struct RawTraceEvent {
    vtbl: *const RawTraceEventVtbl,
}

#[repr(C)]
#[allow(dead_code, reason = "The vtable must list every method, used or not.")]
struct RawTraceEventVtbl {
    query_interface: unsafe extern "system" fn(*mut RawTraceEvent, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut RawTraceEvent) -> u32,
    release: unsafe extern "system" fn(*mut RawTraceEvent) -> u32,
    clone: unsafe extern "system" fn(*mut RawTraceEvent, *mut *mut RawTraceEvent) -> HRESULT,
    get_user_context: unsafe extern "system" fn(*mut RawTraceEvent, *mut *mut c_void) -> HRESULT,
    get_event_record: unsafe extern "system" fn(*mut RawTraceEvent, *mut *mut EVENT_RECORD) -> HRESULT,
    set_payload: unsafe extern "system" fn(*mut RawTraceEvent, *const u8, u32) -> HRESULT,
    set_event_descriptor: unsafe extern "system" fn(*mut RawTraceEvent, *const EVENT_DESCRIPTOR) -> HRESULT,
    set_process_id: unsafe extern "system" fn(*mut RawTraceEvent, u32) -> HRESULT,
    set_processor_index: unsafe extern "system" fn(*mut RawTraceEvent, u32) -> HRESULT,
    set_thread_id: unsafe extern "system" fn(*mut RawTraceEvent, u32) -> HRESULT,
    set_thread_times: unsafe extern "system" fn(*mut RawTraceEvent, u32, u32) -> HRESULT,
    set_activity_id: unsafe extern "system" fn(*mut RawTraceEvent, *const GUID) -> HRESULT,
    set_time_stamp: unsafe extern "system" fn(*mut RawTraceEvent, *const i64) -> HRESULT,
    set_provider_id: unsafe extern "system" fn(*mut RawTraceEvent, *const GUID) -> HRESULT,
}

/// Our ITraceEventCallback.  The relogger holds a reference while it lives; `relog_file` frees it afterwards.
#[repr(C)]
struct Callback {
    vtbl: *const CallbackVtbl,
    references: AtomicU32,
    /// The `&mut H` that `relog_file` was given, and the function that calls it with the type restored.
    handler: *mut c_void,
    dispatch: unsafe fn(*mut c_void, &EventRecord<'_>, &mut RelogContext<'_>),
    stream: u64,
    /// Events of other inputs, in time order, not yet handed to the handler.
    later: VecDeque<ClonedEvent>,
    error: Option<Error>,
}

#[repr(C)]
struct CallbackVtbl {
    query_interface: unsafe extern "system" fn(*mut Callback, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut Callback) -> u32,
    release: unsafe extern "system" fn(*mut Callback) -> u32,
    on_begin_process_trace: unsafe extern "system" fn(*mut Callback, *mut RawTraceEvent, *mut RawRelogger) -> HRESULT,
    on_finalize_process_trace: unsafe extern "system" fn(*mut Callback, *mut RawRelogger) -> HRESULT,
    on_event: unsafe extern "system" fn(*mut Callback, *mut RawTraceEvent, *mut RawRelogger) -> HRESULT,
}

static CALLBACK_VTBL: CallbackVtbl = CallbackVtbl {
    query_interface: callback_query_interface,
    add_ref: callback_add_ref,
    release: callback_release,
    on_begin_process_trace: callback_on_begin,
    on_finalize_process_trace: callback_on_finalize,
    on_event: callback_on_event,
};

/// Calls the handler with its type restored.
///
/// # Safety
/// `handler` must be the `&mut H` that [`relog_file`] put in the callback, still borrowed by it.
unsafe fn dispatch<H: RelogHandler>(handler: *mut c_void, event: &EventRecord<'_>, relog: &mut RelogContext<'_>) {
    // SAFETY: per the contract, the pointer is a live, exclusively borrowed H.
    if let Some(handler) = unsafe { handler.cast::<H>().as_mut() } {
        handler.on_event(event, relog);
    }
}

/// Hands the handler an event: the relogger's current one, or a clone of another input's.
///
/// # Safety
/// `event` must be live for the duration of the call, `record` must be its record, and `relogger` the live relogger
/// that is calling back.
unsafe fn handle(callback: &mut Callback, event: *mut RawTraceEvent, record: &EVENT_RECORD, relogger: *mut RawRelogger) {
    let mut context = RelogContext {
        relogger,
        current: event,
        stream: callback.stream,
        error: &mut callback.error,
    };
    // SAFETY: `handler` is the &mut H `relog_file` was given, borrowed for as long as ProcessTrace runs.
    unsafe { (callback.dispatch)(callback.handler, &EventRecord::new(record), &mut context) };
}

/// Hands the handler the events of other inputs that come before `timestamp` (all of them, for None).
///
/// # Safety
/// As for [`handle`]: `relogger` is the live relogger that is calling back.
unsafe fn handle_later(callback: &mut Callback, timestamp: Option<i64>, relogger: *mut RawRelogger) {
    while callback.later.front().is_some_and(|event| timestamp.is_none_or(|timestamp| event.timestamp <= timestamp)) {
        let Some(event) = callback.later.pop_front() else {
            break;
        };

        if let Some(record) = event.record() {
            // SAFETY: the clone lives until the end of this iteration; the caller vouches for the relogger.
            unsafe { handle(callback, event.event, record, relogger) };
        }
    }
}

unsafe extern "system" fn callback_query_interface(this: *mut Callback, iid: *const GUID, object: *mut *mut c_void) -> HRESULT {
    if object.is_null() {
        return E_POINTER;
    }

    // SAFETY: the caller passes a valid IID (or null, which matches nothing).
    let iid = unsafe { iid.as_ref() };
    let known = iid.is_some_and(|iid| same_guid(iid, &IID_IUNKNOWN) || same_guid(iid, &IID_ITRACE_EVENT_CALLBACK));
    let result = if known {
        // SAFETY: `this` is our live callback.
        unsafe { callback_add_ref(this) };
        this.cast()
    } else {
        std::ptr::null_mut()
    };
    // SAFETY: checked non-null above; the caller provides the out pointer.
    unsafe { object.write(result) };
    if known { S_OK } else { E_NOINTERFACE }
}

unsafe extern "system" fn callback_add_ref(this: *mut Callback) -> u32 {
    // SAFETY: `this` is our live callback (COM rules: callers hold a reference).
    unsafe { (*this).references.fetch_add(1, Ordering::SeqCst).wrapping_add(1) }
}

unsafe extern "system" fn callback_release(this: *mut Callback) -> u32 {
    // The object is freed by `relog_file`, not here (it outlives the relogger), so this only counts.
    // SAFETY: `this` is our live callback.
    unsafe { (*this).references.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1) }
}

unsafe extern "system" fn callback_on_begin(_this: *mut Callback, _header: *mut RawTraceEvent, _relogger: *mut RawRelogger) -> HRESULT {
    S_OK
}

/// After the last event of the first input: the events of other inputs that come after it.
unsafe extern "system" fn callback_on_finalize(this: *mut Callback, relogger: *mut RawRelogger) -> HRESULT {
    if relogger.is_null() {
        return E_POINTER;
    }

    // SAFETY: the relogger calls back on the thread running ProcessTrace inside `relog_file`, one call at a time, so
    // this is the only reference to the callback while it runs.
    let Some(callback) = (unsafe { this.as_mut() }) else {
        return E_POINTER;
    };
    // SAFETY: the relogger is the live one calling back.
    unsafe { handle_later(callback, None, relogger) };
    S_OK
}

unsafe extern "system" fn callback_on_event(this: *mut Callback, event: *mut RawTraceEvent, relogger: *mut RawRelogger) -> HRESULT {
    if this.is_null() || event.is_null() || relogger.is_null() {
        return E_POINTER;
    }

    let mut record: *mut EVENT_RECORD = std::ptr::null_mut();
    // SAFETY: `event` is the live event the relogger passes for the duration of this call.
    let status = unsafe { (event_vtbl(event).get_event_record)(event, &raw mut record) };
    // SAFETY: on success the record is valid until this call returns.
    let Some(record) = (unsafe { record.as_ref() }) else {
        return if status < 0 { status } else { E_POINTER };
    };

    // SAFETY: the relogger calls back on the thread running ProcessTrace inside `relog_file`, one call at a time, so
    // this is the only reference to the callback while it runs.
    let callback = unsafe { &mut *this };
    // SAFETY: the relogger is the live one calling back.
    unsafe { handle_later(callback, Some(record.EventHeader.TimeStamp), relogger) };
    // SAFETY: as above, and `event` is live (with `record`) during this call.
    unsafe { handle(callback, event, record, relogger) };
    S_OK
}

/// The vtable of a live ITraceRelogger.  (COM objects never change their vtable, which lives as long as the module.)
fn relogger_vtbl(relogger: *mut RawRelogger) -> &'static RawReloggerVtbl {
    // SAFETY: callers pass a live ITraceRelogger, whose first field points at its vtable.
    let vtbl = unsafe { (*relogger).vtbl };
    // SAFETY: the vtable is a static table in the relogger's module, which stays loaded while COM is initialized.
    unsafe { &*vtbl }
}

/// The vtable of a live ITraceEvent.
fn event_vtbl(event: *mut RawTraceEvent) -> &'static RawTraceEventVtbl {
    // SAFETY: callers pass a live ITraceEvent, whose first field points at its vtable.
    let vtbl = unsafe { (*event).vtbl };
    // SAFETY: as for relogger_vtbl.
    unsafe { &*vtbl }
}

fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
