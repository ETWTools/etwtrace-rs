//! Processes, threads, images (all always recorded) and handles (-handle).

use super::Shared;
use super::common::{Out, ProcessTally, StackKind, Tally, outln};
use super::event::{Event, Kind};
use super::payload::Payload;
use crate::hash::FxMap;
use crate::text::{self, file_name, pad_left, pad_right, truncate_utf16, utf16_len};

/// The process event's image name (an ANSI file name such as "notepad.exe"), as TraceEvent's KernelImageFileName.
pub fn kernel_image_name(event: &Event<'_>) -> String {
    if event.version >= 1 { event.payload.utf8(image_name_offset(event)) } else { String::new() }
}

/// The image name follows the user's SID, which follows fields that changed with the event's version.
fn image_name_offset(event: &Event<'_>) -> usize {
    let p = event.payload;
    let sid = match event.version {
        4.. => p.host(28, 2),
        3 => p.host(24, 2),
        _ => p.host(20, 1),
    };
    p.skip_sid(sid)
}

/// An image event's file name, before drive letters are mapped, into a reused buffer.
pub fn kernel_image_file_name(event: &Event<'_>, name: &mut String) {
    let p = event.payload;
    match event.version {
        2.. => p.utf16_into(p.host(44, 3), name),
        1 => p.utf16_into(p.host(12, 2), name),
        0 => name.clear(),
    }
}

/// An image event's base address and size.  (TraceEvent reads the size as an int, which then sign extends.)
pub fn image_range(payload: Payload<'_>) -> (u64, u64) {
    let size = payload.pointer(payload.host(4, 1)) as i32;
    (payload.pointer(0), i64::from(size) as u64)
}

/// How many processes were running when the trace started (the process rundown), and the ones that started or exited
/// during it, with their command lines and exit codes.  Creation stacks need -process.
#[derive(Default)]
pub struct ProcessSummary {
    running: i64,
    started: Vec<ProcessEvent>,
    exited: Vec<ProcessEvent>,
}

struct ProcessEvent {
    msec: f64,
    label: String,
    detail: String,
    exit_code: i32,
}

const MAX_LISTED: usize = 10;
const MAX_COMMAND_LINE: usize = 100;

impl ProcessSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        let p = event.payload;
        match event.kind {
            Kind::ProcessDCStart => self.running = self.running.wrapping_add(1),
            Kind::ProcessStart => {
                shared.expect_stack_walk(event, StackKind::ProcessStart);
                let mut command_line = if event.version >= 2 { p.utf16(p.skip_utf8(image_name_offset(event))) } else { String::new() };
                if utf16_len(&command_line) > MAX_COMMAND_LINE {
                    command_line = truncate_utf16(&command_line, MAX_COMMAND_LINE.saturating_sub(3)) + "...";
                }

                // The parent is named now, while its process ID still means it.
                let parent = if event.version >= 1 { p.i32(p.host(8, 1)) } else { p.pointer(p.host(4, 1)) as i32 };
                let detail = format!("{} {command_line}", pad_right(&shared.processes.label(parent), 28));
                let label = shared.processes.label(event.process_id);
                self.started.push(ProcessEvent {
                    msec: shared.relative_msec(event),
                    label,
                    detail,
                    exit_code: 0,
                });
            }
            Kind::ProcessStop => {
                let exit_code = if event.version >= 1 { p.i32(p.host(16, 1)) } else { 0 };
                let label = shared.processes.label(event.process_id);
                self.exited.push(ProcessEvent {
                    msec: shared.relative_msec(event),
                    label,
                    detail: String::new(),
                    exit_code,
                });
            }
            _ => {}
        }
    }

    pub fn print(&self, out: &mut Out) {
        if self.running == 0 && self.started.is_empty() && self.exited.is_empty() {
            return;
        }

        let failed: Vec<&ProcessEvent> = self.exited.iter().filter(|exit| exit.exit_code != 0).collect();
        outln!(out);
        outln!(
            out,
            "Processes: {} running at the start, {} started, {} exited ({} with a non-zero exit code)",
            text::count(self.running),
            text::count(count_of(self.started.len())),
            text::count(count_of(self.exited.len())),
            text::count(count_of(failed.len()))
        );
        if !self.started.is_empty() {
            outln!(out, "  {}  {} {} command line", pad_left("started s", 10), pad_right("process", 28), pad_right("parent", 28));
            for start in self.started.iter().take(MAX_LISTED) {
                outln!(out, "  {}  {} {}", pad_left(&seconds(start.msec), 10), pad_right(&start.label, 28), start.detail);
            }

            print_more(out, self.started.len());
        }

        if !failed.is_empty() {
            outln!(out, "  {}  {} exit code", pad_left("exited s", 10), pad_right("process", 28));
            for exit in failed.iter().take(MAX_LISTED) {
                outln!(out, "  {}  {} {}", pad_left(&seconds(exit.msec), 10), pad_right(&exit.label, 28), exit_code(exit.exit_code));
            }

            print_more(out, failed.len());
        }
    }
}

fn count_of(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

fn seconds(msec: f64) -> String {
    text::fixed(msec / 1000.0, 3)
}

/// Exit codes that look like NTSTATUS or HRESULT values (e.g. 0xC000013A, Ctrl+C) in hex, others in decimal.
fn exit_code(code: i32) -> String {
    if (0..0x10000).contains(&code) { code.to_string() } else { format!("0x{:08X}", code as u32) }
}

fn print_more(out: &mut Out, count: usize) {
    if count > MAX_LISTED {
        outln!(out, "  ... and {} more", text::count(count_of(count.saturating_sub(MAX_LISTED))));
    }
}

/// How many threads were running when the trace started, and how many were created and exited during it, by process.
/// Creation stacks (the creating thread's) need -thread.
#[derive(Default)]
pub struct ThreadSummary {
    running: i64,
    created: ProcessTally,
    exited: ProcessTally,
}

impl ThreadSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        match event.kind {
            Kind::ThreadDCStart => self.running = self.running.wrapping_add(1),
            Kind::ThreadStart => {
                // The IDs are the new thread's; the event (and its stack) is the creating thread's.
                shared.expect_stack_walk(event, StackKind::ThreadStart);
                self.created.add(event.process_id, event.thread_id, 1);
            }
            Kind::ThreadStop => self.exited.add(event.process_id, event.thread_id, 1),
            _ => {}
        }
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        if self.running == 0 && self.created.total == 0 && self.exited.total == 0 {
            return;
        }

        outln!(out);
        outln!(
            out,
            "Threads: {} running at the start, {} created, {} exited",
            text::count(self.running),
            text::count(self.created.total),
            text::count(self.exited.total)
        );
        if self.created.total.wrapping_add(self.exited.total) > 0 {
            let created = self.created.by_process(&shared.processes);
            let exited = self.exited.by_process(&shared.processes);
            Tally::print_table(out, "process", text::count, 8, &[("created", &created), ("exited", &exited)]);
        }
    }
}

/// How many images were loaded when the trace started, and the loads and unloads during it, by image and by process.
/// Load stacks need -image.
pub struct ImageSummary {
    at_start: i64,
    loads: Tally,
    loads_by_process: ProcessTally,
    unloads: i64,
}

impl Default for ImageSummary {
    fn default() -> Self {
        Self {
            at_start: 0,
            loads: Tally::ignoring_case(),
            loads_by_process: ProcessTally::default(),
            unloads: 0,
        }
    }
}

impl ImageSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        match event.kind {
            Kind::ImageDCStart => self.at_start = self.at_start.wrapping_add(1),
            Kind::ImageLoad => {
                shared.expect_stack_walk(event, StackKind::ImageLoad);
                self.loads.add(file_name(&shared.image_path), 1);
                self.loads_by_process.add(event.process_id, event.thread_id, 1);
            }
            Kind::ImageUnload => self.unloads = self.unloads.wrapping_add(1),
            _ => {}
        }
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        if self.at_start == 0 && self.loads.total() == 0 && self.unloads == 0 {
            return;
        }

        outln!(out);
        outln!(
            out,
            "Images: {} loaded at the start (all processes), {} loads and {} unloads during the trace",
            text::count(self.at_start),
            text::count(self.loads.total()),
            text::count(self.unloads)
        );
        if self.loads.total() > 0 {
            self.loads.print(out, "loads", "image", text::count, 8);
            self.loads_by_process.by_process(&shared.processes).print(out, "loads", "process", text::count, 8);
        }
    }
}

/// Handles created, duplicated and closed, by object type and by process.  A duplicate counts for the process that gets
/// the new handle.  The object type names are only logged at the end of the trace (the type rundown).
#[derive(Default)]
pub struct HandleSummary {
    by_type: FxMap<i32, [i64; 3]>,
    by_process: [ProcessTally; 3],
    type_names: FxMap<i32, String>,
}

const CREATED: usize = 0;
const DUPLICATED: usize = 1;
const CLOSED: usize = 2;
const COLUMN_NAMES: [&str; 3] = ["created", "duplicated", "closed"];

impl HandleSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        let p = event.payload;
        match event.kind {
            Kind::HandleCreate => self.on_handle(event, i32::from(p.i16(p.host(8, 1))), event.process_id, CREATED, shared),
            Kind::HandleClose => self.on_handle(event, i32::from(p.i16(p.host(8, 1))), event.process_id, CLOSED, shared),
            Kind::HandleDuplicate => {
                self.on_handle(event, i32::from(p.i16(p.host(16, 1))), p.i32(p.host(12, 1)), DUPLICATED, shared);
            }
            Kind::ObjectTypeName => {
                self.type_names.insert(i32::from(p.i16(0)), p.utf16(4));
            }
            _ => {}
        }
    }

    fn on_handle(&mut self, event: &Event<'_>, object_type: i32, process_id: i32, column: usize, shared: &mut Shared) {
        shared.expect_stack_walk(event, StackKind::Handle);
        if let Some(count) = self.by_type.entry(object_type).or_default().get_mut(column) {
            *count = count.wrapping_add(1);
        }

        if let Some(tally) = self.by_process.get_mut(column) {
            tally.add(process_id, event.thread_id, 1);
        }
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        let [created, duplicated, closed] = self.by_process.each_ref().map(|tally| tally.total);
        if created.wrapping_add(duplicated).wrapping_add(closed) == 0 {
            return;
        }

        outln!(out);
        outln!(
            out,
            "Handles: {} created, {} duplicated, {} closed (net {})",
            text::count(created),
            text::count(duplicated),
            text::count(closed),
            text::count(created.wrapping_add(duplicated).wrapping_sub(closed))
        );

        let mut by_type = [Tally::new(), Tally::new(), Tally::new()];
        for (object_type, counts) in &self.by_type {
            let name = self.type_names.get(object_type).cloned().unwrap_or_else(|| format!("type {object_type}"));
            for (tally, &count) in by_type.iter_mut().zip(counts) {
                tally.add(&name, count);
            }
        }

        print_handle_table(out, "object type", &by_type);
        let by_process = self.by_process.each_ref().map(|tally| tally.by_process(&shared.processes));
        print_handle_table(out, "process", &by_process);
    }
}

/// The created, duplicated and closed columns plus the net change, for the keys that created the most.
fn print_handle_table(out: &mut Out, key_header: &str, columns: &[Tally; 3]) {
    let [created, duplicated, closed] = columns;
    let mut net = Tally::new();
    net.add_tally(created, 1);
    net.add_tally(duplicated, 1);
    net.add_tally(closed, -1);
    let [created_name, duplicated_name, closed_name] = COLUMN_NAMES;
    Tally::print_table(out, key_header, text::count, 8, &[(created_name, created), (duplicated_name, duplicated), (closed_name, closed), ("net", &net)]);
}
