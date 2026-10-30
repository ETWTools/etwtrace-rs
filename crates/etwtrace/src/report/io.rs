//! File I/O (-fileio), disk I/O (-diskio and -fileio) and registry (-registry) summaries.

use std::collections::BTreeMap;

use super::Shared;
use super::common::{CaseInsensitiveCounts, DotNetOrder, Operations, Out, ProcessTally, StackKind, Tally, outln};
use super::event::{Event, FileOp, Kind};
use crate::hash::FxMap;
use crate::text;

/// File I/O operations by kind, and bytes read and written by file and by process.
#[derive(Default)]
pub struct FileIOSummary {
    operations: [i64; FileOp::COUNT],
    /// Bytes by file key (or file object), with the file object last seen for it.
    transfers: FxMap<u64, (u64, i64)>,
    bytes_read: i64,
    bytes_written: i64,
    by_process: ProcessTally,
}

impl FileIOSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        let Kind::FileOp(op) = event.kind else {
            return;
        };

        if let Some(count) = self.operations.get_mut(op.index()) {
            *count = count.wrapping_add(1);
        }

        shared.expect_stack_walk(event, StackKind::FileIO);
        if op != FileOp::Read && op != FileOp::Write {
            return;
        }

        let p = event.payload;
        let old = event.version <= 2;
        let file_object = p.pointer(if old { p.host(16, 2) } else { p.host(12, 1) });
        let file_key = p.pointer(if old { p.host(20, 3) } else { p.host(16, 2) });
        let size = i64::from(p.i32(if old { p.host(24, 4) } else { p.host(24, 3) }));
        if op == FileOp::Read {
            self.bytes_read = self.bytes_read.wrapping_add(size);
        } else {
            self.bytes_written = self.bytes_written.wrapping_add(size);
        }

        let key = if file_key != 0 { file_key } else { file_object };
        let transfer = self.transfers.entry(key).or_insert((0, 0));
        *transfer = (file_object, transfer.1.wrapping_add(size));
        self.by_process.add(event.process_id, event.thread_id, size);
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        let mut operations = Tally::new();
        for (op, &count) in FileOp::ALL.iter().zip(&self.operations) {
            if count > 0 {
                operations.add(op.name(), count);
            }
        }

        if operations.total() == 0 {
            return;
        }

        let mut by_file = Tally::new();
        for (&key, &(file_object, bytes)) in &self.transfers {
            by_file.add(&shared.files.name_of(key, file_object), bytes);
        }

        outln!(out);
        outln!(out, "File I/O: {} operations ({})", text::count(operations.total()), operations.describe(12));
        outln!(out, "  {} read, {} written", text::bytes(self.bytes_read), text::bytes(self.bytes_written));
        by_file.print(out, "read+written", "file", text::bytes, 8);
        self.by_process.by_process(&shared.processes).print(out, "read+written", "process", text::bytes, 8);
    }
}

/// Disk reads, writes and flushes with their sizes and times (from when the I/O was issued until it completed), and
/// bytes by file and by process.  Stacks are on the events logged when an I/O is issued (the "init" events, -diskio
/// only), since the completions are logged in whatever context completes them.
#[derive(Default)]
pub struct DiskIOSummary {
    reads: Operations,
    writes: Operations,
    flushes: Operations,
    bytes_by_file: FxMap<u64, i64>,
    bytes_by_disk: BTreeMap<i32, i64>,
    by_process: ProcessTally,
}

impl DiskIOSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        let p = event.payload;
        match event.kind {
            Kind::DiskRead | Kind::DiskWrite => {
                let size = i64::from(p.i32(8));
                let msec = shared.clock.msec(p.i64(p.host(32, 2)));
                let operations = if event.kind == Kind::DiskRead { &mut self.reads } else { &mut self.writes };
                operations.add(size, msec);
                let file = self.bytes_by_file.entry(p.pointer(24)).or_insert(0);
                *file = file.wrapping_add(size);
                let disk = self.bytes_by_disk.entry(p.i32(0)).or_insert(0);
                *disk = disk.wrapping_add(size);
                self.by_process.add(event.process_id, event.thread_id, size);
            }
            Kind::DiskFlush => self.flushes.add(0, shared.clock.msec(p.i64(8))),
            Kind::DiskInit => shared.expect_stack_walk(event, StackKind::DiskIO),
            _ => {}
        }
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        if self.reads.count.wrapping_add(self.writes.count).wrapping_add(self.flushes.count) == 0 {
            return;
        }

        let mut by_file = Tally::new();
        for (&key, &bytes) in &self.bytes_by_file {
            by_file.add(&shared.files.name_of(key, 0), bytes);
        }

        outln!(out);
        outln!(out, "Disk I/O: {}, {}, {}", self.reads.describe("reads", true), self.writes.describe("writes", true), self.flushes.describe("flushes", false));
        if self.bytes_by_disk.len() > 1 {
            let disks: Vec<String> = self.bytes_by_disk.iter().map(|(disk, &bytes)| format!("disk {disk} {}", text::bytes(bytes))).collect();
            outln!(out, "  By disk: {}", disks.join(", "));
        }

        if by_file.total() > 0 {
            by_file.print(out, "read+written", "file", text::bytes, 8);
            self.by_process.by_process(&shared.processes).print(out, "read+written", "process", text::bytes, 8);
        }
    }
}

/// Registry operations by kind, the ones that returned an error or warning status, and operations by key and by
/// process.
///
/// Operations name their key by the address of its key control block (KCB), whose name is in the KCB events: KCBCreate
/// and KCBDelete during the trace, and the KCB rundown at its end for the rest.  So counts are kept by KCB until its
/// name is known (when it is deleted, or at the end).  Open and Create name the KCB of the key the path is relative to,
/// and the path; value operations name the key's KCB and the value.  (TraceEvent's Status property always returns 0,
/// so TraceEvent reads the status from the payload, as this does.)
pub struct RegistrySummary {
    operations: [i64; REGISTRY_OPCODES],
    /// Operations by (non-zero) status code.
    statuses: FxMap<i32, i64>,
    keys: Tally,
    by_process: ProcessTally,
    kcb_names: FxMap<u64, String>,
    /// Operation counts by KCB, then by the path relative to it ("" for the key itself), until the KCB's name is known.
    pending: DotNetOrder<u64, CaseInsensitiveCounts>,
    path: String,
    folded: String,
}

const REGISTRY_OPCODES: usize = 28;
const STATUS_OFFSET: usize = 8;
const KCB_OFFSET: usize = 16;
const CREATE_OPCODE: u8 = 10;
const OPEN_OPCODE: u8 = 11;

impl Default for RegistrySummary {
    fn default() -> Self {
        Self {
            operations: [0; REGISTRY_OPCODES],
            statuses: FxMap::default(),
            keys: Tally::ignoring_case(),
            by_process: ProcessTally::default(),
            kcb_names: FxMap::default(),
            pending: DotNetOrder::default(),
            path: String::new(),
            folded: String::new(),
        }
    }
}

impl RegistrySummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        let p = event.payload;
        let kcb = if event.version >= 2 { p.pointer(KCB_OFFSET) } else { 0 };
        let name_offset = KCB_OFFSET.saturating_add(p.pointer_size());
        match event.kind {
            Kind::Registry => self.on_operation(event, kcb, name_offset, shared),
            Kind::KcbName => {
                self.kcb_names.insert(kcb, p.utf16(name_offset));
            }
            Kind::KcbDelete => {
                // The KCB's name is known now, and its address may be reused for another key after this.
                if let Some(counts) = self.pending.remove(&kcb) {
                    let name = p.utf16(name_offset);
                    let name = if name.is_empty() { self.kcb_names.get(&kcb).cloned() } else { Some(name) };
                    self.add_key_counts(kcb, name.as_deref(), &counts);
                }

                self.kcb_names.remove(&kcb);
            }
            _ => {}
        }
    }

    fn on_operation(&mut self, event: &Event<'_>, kcb: u64, name_offset: usize, shared: &mut Shared) {
        shared.expect_stack_walk(event, StackKind::Registry);
        if let Some(count) = self.operations.get_mut(usize::from(event.opcode)) {
            *count = count.wrapping_add(1);
        }

        self.by_process.add(event.process_id, event.thread_id, 1);
        if event.version < 2 {
            return; // Older layouts have no status or KCB.
        }

        let status = event.payload.i32(STATUS_OFFSET);
        if status != 0 {
            let count = self.statuses.entry(status).or_insert(0);
            *count = count.wrapping_add(1);
        }

        if event.opcode == CREATE_OPCODE || event.opcode == OPEN_OPCODE {
            event.payload.utf16_into(name_offset, &mut self.path);
        } else {
            self.path.clear();
        }

        if let Some(counts) = self.pending.get_or_insert_with(kcb, CaseInsensitiveCounts::default) {
            counts.increment(&self.path, &mut self.folded);
        }
    }

    fn add_key_counts(&mut self, kcb: u64, kcb_name: Option<&str>, counts: &CaseInsensitiveCounts) {
        for (path, count) in counts.iter() {
            let key = if kcb == 0 {
                if path.is_empty() { "(no key)".to_owned() } else { path.to_owned() } // An absolute path, or nothing.
            } else {
                let name = kcb_name.filter(|name| !name.is_empty()).unwrap_or("(key name not in trace)");
                if path.is_empty() { name.to_owned() } else { format!("{name}\\{path}") }
            };
            self.keys.add(&key, count);
        }
    }

    pub fn print(&mut self, shared: &Shared, out: &mut Out) {
        let mut operations = Tally::new();
        for (opcode, &count) in self.operations.iter().enumerate() {
            if count > 0 {
                operations.add(operation_name(opcode), count);
            }
        }

        if operations.total() == 0 {
            return;
        }

        let pending = std::mem::take(&mut self.pending);
        for (&kcb, counts) in pending.iter() {
            let name = self.kcb_names.get(&kcb).cloned();
            self.add_key_counts(kcb, name.as_deref(), counts);
        }

        outln!(out);
        outln!(out, "Registry: {} operations ({})", text::count(operations.total()), operations.describe(12));
        let mut statuses = Tally::new();
        for (&status, &count) in &self.statuses {
            statuses.add(&status_name(status), count);
        }

        if statuses.total() > 0 {
            outln!(out, "  {} returned an error or warning: {}", text::count(statuses.total()), statuses.describe(8));
        }

        self.keys.print(out, "operations", "key", text::count, 8);
        self.by_process.by_process(&shared.processes).print(out, "operations", "process", text::count, 8);
    }
}

fn operation_name(opcode: usize) -> &'static str {
    match opcode {
        10 => "Create",
        11 => "Open",
        12 => "Delete",
        13 => "Query",
        14 => "SetValue",
        15 => "DeleteValue",
        16 => "QueryValue",
        17 => "EnumerateKey",
        18 => "EnumerateValueKey",
        19 => "QueryMultipleValue",
        20 => "SetInformation",
        21 => "Flush",
        26 => "Virtualize",
        27 => "Close",
        _ => "?",
    }
}

fn status_name(status: i32) -> String {
    match status as u32 {
        0xC000_0034 => "not found".to_owned(),
        0xC000_003A => "path not found".to_owned(),
        0xC000_0022 => "access denied".to_owned(),
        0xC000_0023 => "buffer too small".to_owned(),
        0x8000_0005 => "buffer overflow".to_owned(),
        0x8000_001A => "no more entries".to_owned(),
        0xC000_000D => "invalid parameter".to_owned(),
        0xC000_007C => "no token".to_owned(),
        other => format!("0x{other:08X}"),
    }
}
