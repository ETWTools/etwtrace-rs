//! 'report': one pass over the raw events of a trace that prints event counts and stack coverage, then a summary of
//! each kind of data the trace has.  Open the trace in PerfView or WPA to look at the stacks themselves.
//!
//! The events are decoded here (no TraceEvent), but the numbers follow TraceEvent's view of the trace so the report
//! matches TraceEvent's: the same files are read (X.etl with X.kernel*.etl, X.clr*.etl and X.user*.etl beside it),
//! with the same relative times, process IDs and file names.

mod common;
mod cpu;
mod event;
mod io;
mod memory;
mod network;
mod payload;
mod process;
mod state;

use std::path::{Path, PathBuf};

use common::{FileNames, ModuleMap, Out, ProcessNames, StackCoverage, StackKind, outln};
use event::{Event, FileOp, Kind};
use state::{Clock, DriveMapping, ThreadProcesses};

use crate::AppError;
use crate::text::{self, file_name_without_extension};

/// Prints the report of a trace file.
pub fn print(etl_file: &str) -> Result<(), AppError> {
    let text = run(etl_file)?;
    crate::console::write(&text);
    Ok(())
}

/// Reads the trace and returns the report's text.
pub fn run(etl_file: &str) -> Result<String, AppError> {
    if !Path::new(etl_file).is_file() {
        return Err(AppError::new(format!("File not found: {etl_file}")));
    }

    let files = merge_all_files(etl_file);
    if files.is_empty() {
        return Err(AppError::new(format!("Could not find file     {etl_file}")));
    }

    let mut infos = Vec::with_capacity(files.len());
    for file in &files {
        infos.push(etw::consumer::file_info(file).map_err(|e| AppError::new(format!("{}: {e}", file.display())))?);
    }

    let first = infos.first().copied().unwrap_or_default();
    let mut frequency = if first.perf_freq != 0 { first.perf_freq } else { etw::system::qpc_frequency() };
    if first.clock_type == 2 {
        frequency = 10_000_000; // System time: 100ns ticks.
    }

    let full_name = std::path::absolute(etl_file).unwrap_or_else(|_| PathBuf::from(etl_file));
    let session_files = [".kernel.etl", ".user.etl"].map(|extension| change_extension(&full_name, extension));
    let mut report = Report::new(Shared {
        clock: Clock::new(frequency),
        threads: ThreadProcesses::default(),
        drives: DriveMapping::default(),
        stacks: StackCoverage::default(),
        processes: ProcessNames::default(),
        modules: ModuleMap::default(),
        files: FileNames::new(session_files),
        scratch: String::new(),
        image_path: String::new(),
    });

    let paths: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
    etw::consumer::process_files(&paths, |record| report.on_record(record)).map_err(|e| AppError::new(e.to_string()))?;

    let mut out = Out::default();
    let lost = infos.iter().fold(0i64, |sum, info| sum.wrapping_add(i64::from(info.events_lost as i32)));
    outln!(
        out,
        "{etl_file}: {} s, {} CPUs, {} events lost",
        text::fixed(session_seconds(&infos, frequency), 1),
        first.number_of_processors as i32,
        text::count(lost)
    );
    outln!(out);
    report.print(&mut out);
    Ok(out.into_string())
}

/// What the summaries share: TraceEvent's view of the trace (clock, thread to process map, drive letters), stack
/// coverage, and process, module and file names, which are learned from the trace as it is read (some only at its end).
pub struct Shared {
    pub clock: Clock,
    pub threads: ThreadProcesses,
    pub drives: DriveMapping,
    pub stacks: StackCoverage,
    pub processes: ProcessNames,
    pub modules: ModuleMap,
    pub files: FileNames,
    /// A reused buffer for decoding strings.
    pub scratch: String,
    /// The current image load or rundown event's path with drive letters (ImageSummary needs it too).
    pub image_path: String,
}

impl Shared {
    pub fn expect_stack_walk(&mut self, event: &Event<'_>, kind: StackKind) {
        self.stacks.expect_stack_walk(event.processor, self.clock.clamp(event.timestamp), kind);
    }

    pub fn relative_msec(&self, event: &Event<'_>) -> f64 {
        self.clock.relative_msec(event.timestamp)
    }
}

/// The report, in the order its parts print.
struct Report {
    shared: Shared,
    cpu: cpu::CpuSummary,
    counters: cpu::ContextSwitchCounterSummary,
    processes: process::ProcessSummary,
    threads: process::ThreadSummary,
    images: process::ImageSummary,
    file_io: io::FileIOSummary,
    disk_io: io::DiskIOSummary,
    registry: io::RegistrySummary,
    network: network::NetworkSummary,
    dns: network::DnsSummary,
    virtual_alloc: memory::VirtualAllocSummary,
    page_faults: memory::PageFaultSummary,
    mem_info: memory::MemInfoSummary,
    handles: process::HandleSummary,
    reference_set: memory::ReferenceSetSummary,
}

impl Report {
    fn new(shared: Shared) -> Self {
        Self {
            shared,
            cpu: cpu::CpuSummary::new(),
            counters: cpu::ContextSwitchCounterSummary::default(),
            processes: process::ProcessSummary::default(),
            threads: process::ThreadSummary::default(),
            images: process::ImageSummary::default(),
            file_io: io::FileIOSummary::default(),
            disk_io: io::DiskIOSummary::default(),
            registry: io::RegistrySummary::default(),
            network: network::NetworkSummary::default(),
            dns: network::DnsSummary::default(),
            virtual_alloc: memory::VirtualAllocSummary::default(),
            page_faults: memory::PageFaultSummary::default(),
            mem_info: memory::MemInfoSummary::default(),
            handles: process::HandleSummary::default(),
            reference_set: memory::ReferenceSetSummary::default(),
        }
    }

    fn on_record(&mut self, record: &etw::EventRecord<'_>) {
        let kind = Kind::of(record);
        if kind == Kind::Other {
            return;
        }

        let event = Event::new(kind, *record, &self.shared.threads);
        self.track(&event);
        self.on_shared(&event);
        self.dispatch(&event);
    }

    /// What TraceEvent's own state learns from the event before anyone sees it.
    fn track(&mut self, event: &Event<'_>) {
        let shared = &mut self.shared;
        let p = event.payload;
        match event.kind {
            Kind::TraceHeader => shared.clock.on_header(event.timestamp),
            Kind::ThreadStart | Kind::ThreadDCStart => shared.threads.on_start(event.thread_id, event.process_id),
            Kind::ThreadStop | Kind::ThreadDCStop => {
                shared.threads.on_end(event.thread_id, event.process_id, event.timestamp);
            }
            Kind::SystemPaths => shared.drives.add_system_drive(&p.utf16(p.skip_utf16(0))),
            Kind::VolumeMapping => shared.drives.add(p.utf16(0), p.utf16(p.skip_utf16(0))),
            _ => {}
        }
    }

    /// The shared state the summaries read.
    fn on_shared(&mut self, event: &Event<'_>) {
        let shared = &mut self.shared;
        let p = event.payload;
        match event.kind {
            Kind::StackWalk => {
                let time = shared.clock.clamp(p.i64(0));
                shared.stacks.on_stack_walk(event.processor, time);
            }
            Kind::ThreadStart | Kind::ThreadDCStart => shared.processes.on_thread(event.thread_id, event.process_id),
            Kind::ProcessStart | Kind::ProcessDCStart => {
                let image = process::kernel_image_name(event);
                shared.drives.map_to_user_into(&image, &mut shared.scratch);
                shared.processes.on_process(event.process_id, file_name_without_extension(&shared.scratch).to_owned());
            }
            Kind::ImageLoad | Kind::ImageDCStart => {
                process::kernel_image_file_name(event, &mut shared.scratch);
                shared.drives.map_to_user_into(&shared.scratch, &mut shared.image_path);
                let (base, size) = process::image_range(p);
                shared.modules.add(event.process_id, base, size, file_name_without_extension(&shared.image_path));
            }
            Kind::ImageUnload => shared.modules.remove(event.process_id, process::image_range(p).0),
            Kind::FileName => {
                p.utf16_into(p.host(4, 1), &mut shared.scratch);
                shared.files.on_name(p.pointer(0), &shared.scratch, &mut shared.drives);
            }
            Kind::FileOp(FileOp::Create) => {
                // TraceEvent's FileIOCreate layout (the kernel provider's version; 3 and up moved the thread ID).
                let old = event.version <= 2;
                let file_object = p.pointer(if old { p.host(8, 2) } else { p.host(4, 1) });
                p.utf16_into(if old { p.host(24, 3) } else { p.host(24, 2) }, &mut shared.scratch);
                shared.files.on_create(file_object, &shared.scratch, &mut shared.drives);
            }
            _ => {}
        }
    }

    fn dispatch(&mut self, event: &Event<'_>) {
        let shared = &mut self.shared;
        self.cpu.on_event(event, shared);
        self.counters.on_event(event, shared);
        self.processes.on_event(event, shared);
        self.threads.on_event(event, shared);
        self.images.on_event(event, shared);
        self.file_io.on_event(event, shared);
        self.disk_io.on_event(event, shared);
        self.registry.on_event(event, shared);
        self.network.on_event(event);
        self.dns.on_event(event, shared);
        self.virtual_alloc.on_event(event, shared);
        self.page_faults.on_event(event, shared);
        self.mem_info.on_event(event, shared);
        self.handles.on_event(event, shared);
        self.reference_set.on_event(event, shared);
    }

    fn print(&mut self, out: &mut Out) {
        let shared = &self.shared;
        shared.stacks.print(out);
        self.cpu.print(shared, out);
        self.counters.print(shared, out);
        self.processes.print(out);
        self.threads.print(shared, out);
        self.images.print(shared, out);
        self.file_io.print(shared, out);
        self.disk_io.print(shared, out);
        self.registry.print(shared, out);
        self.network.print(shared, out);
        self.dns.print(shared, out);
        self.virtual_alloc.print(shared, out);
        self.page_faults.print(shared, out);
        self.mem_info.print(shared, out);
        self.handles.print(shared, out);
        self.reference_set.print(shared, out);
    }
}

/// TraceEvent's session duration: from the earliest file's start to the latest file's end, through its QPC conversions
/// (which truncate twice).
fn session_seconds(infos: &[etw::TraceInfo], frequency: i64) -> f64 {
    let start = infos.iter().map(|info| info.start_time).min().unwrap_or(0);
    let end = infos.iter().map(|info| info.end_time).max().unwrap_or(0);
    let end_qpc = (end.wrapping_sub(start) as f64 / 10_000_000.0 * frequency as f64) as i64;
    let ticks = (end_qpc as f64 * 10_000_000.0 / frequency as f64) as i64;
    ticks as f64 / 10_000_000.0
}

/// Path.ChangeExtension, as a string.
fn change_extension(path: &Path, extension: &str) -> String {
    let text = path.to_string_lossy();
    let name_start = text.rfind(['\\', '/']).map_or(0, |index| index.saturating_add(1));
    let stem_end = text.rfind('.').filter(|&dot| dot >= name_start).unwrap_or(text.len());
    format!("{}{extension}", text.get(..stem_end).unwrap_or(&text))
}

/// TraceEvent's GetMergeAllLogFiles: X.etl and the X.kernel*.etl, X.clr*.etl and X.user*.etl files beside it, which
/// TraceEvent reads (merged in time order) when asked for X.etl.
fn merge_all_files(etl_file: &str) -> Vec<PathBuf> {
    let base = file_name_without_extension(etl_file);
    let directory = match etl_file.rfind(['\\', '/']) {
        Some(index) => etl_file.get(..index).filter(|dir| !dir.is_empty()).unwrap_or("\\").to_owned(),
        None if etl_file.len() >= 2 && etl_file.as_bytes().get(1) == Some(&b':') => etl_file.get(..2).unwrap_or(".").to_owned(),
        None => ".".to_owned(),
    };

    let patterns = [format!("{base}.etl"), format!("{base}.kernel*.etl"), format!("{base}.clr*.etl"), format!("{base}.user*.etl")];
    // By pattern, then in directory order.
    let mut files: Vec<(usize, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(&directory).into_iter().flatten().filter_map(Result::ok) {
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }

        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        for (index, pattern) in patterns.iter().enumerate() {
            if wildcard_match(pattern, &name) {
                files.push((index, Path::new(&directory).join(name.as_ref())));
            }
        }
    }

    files.sort_by_key(|&(index, _)| index);
    files.into_iter().map(|(_, path)| path).collect()
}

/// A Win32 style wildcard match ('*' any run, '?' any one character), ignoring case.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let at = |text: &str, index: usize| text.get(index..).and_then(|rest| rest.chars().next());
    let (mut p, mut n) = (0usize, 0usize);
    // Where the last '*' is, and how much of the name it has matched so far.
    let mut star: Option<(usize, usize)> = None;
    loop {
        match (at(pattern, p), at(name, n)) {
            (Some('*'), _) => {
                star = Some((p, n));
                p = p.saturating_add(1);
            }
            (Some(expected), Some(actual)) if expected == '?' || text::fold_char(expected) == text::fold_char(actual) => {
                p = p.saturating_add(expected.len_utf8());
                n = n.saturating_add(actual.len_utf8());
            }
            (None, None) => return true,
            _ => {
                // Let the last '*' match one more character, if there is one.
                let Some((star_p, star_n)) = star else { return false };
                let Some(skipped) = at(name, star_n) else { return false };
                n = star_n.saturating_add(skipped.len_utf8());
                star = Some((star_p, n));
                p = star_p.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{change_extension, wildcard_match};
    use std::path::Path;

    #[test]
    fn wildcards() {
        assert!(wildcard_match("trace.kernel*.etl", "Trace.kernel.etl"));
        assert!(wildcard_match("trace.kernel*.etl", "trace.kernel2.etl"));
        assert!(!wildcard_match("trace.kernel*.etl", "trace.kernel.etlx"));
        assert!(wildcard_match("trace.etl", "TRACE.ETL"));
        assert!(!wildcard_match("trace.etl", "trace2.etl"));
        assert!(wildcard_match("tr?ce*.etl", "TRÄCE-1.ETL"));
        assert!(!wildcard_match("ä?.etl", "Ä.etl"));
    }

    #[test]
    fn extensions() {
        assert_eq!(change_extension(Path::new(r"C:\x\a.b.etl"), ".kernel.etl"), r"C:\x\a.b.kernel.etl");
        assert_eq!(change_extension(Path::new(r"C:\x.y\a"), ".user.etl"), r"C:\x.y\a.user.etl");
    }
}
