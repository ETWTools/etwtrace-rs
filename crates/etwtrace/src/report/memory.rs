//! VirtualAlloc (-virtualalloc, -refset), page faults (-pagefaults; hard faults also with -fileio and -refset), memory
//! info (-meminfo, -refset) and the reference set (-refset).

use super::Shared;
use super::common::{Operations, Out, ProcessTally, StackKind, Tally, outln};
use super::event::{Event, Kind};
use crate::hash::{FxMap, FxSet};
use crate::text::{self, pad_left};

const PAGE_SIZE: i64 = 4096;

/// Memory committed and reserved by VirtualAlloc, and decommitted and released by VirtualFree, in total and by process.
#[derive(Default)]
pub struct VirtualAllocSummary {
    /// Bytes, one per column: committed, reserved, decommitted, released.
    by_process: [ProcessTally; 4],
    allocs: i64,
    frees: i64,
}

const MEM_COMMIT: i32 = 0x1000;
const MEM_RESERVE: i32 = 0x2000;
const MEM_DECOMMIT: i32 = 0x4000;
const MEM_RELEASE: i32 = 0x8000;
const VIRTUAL_ALLOC_COLUMNS: [&str; 4] = ["committed", "reserved", "decommitted", "released"];

impl VirtualAllocSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        let (stack_kind, flags) = match event.kind {
            Kind::VirtualAlloc => {
                self.allocs = self.allocs.wrapping_add(1);
                (StackKind::VirtualAlloc, [(MEM_COMMIT, 0), (MEM_RESERVE, 1)])
            }
            Kind::VirtualFree => {
                self.frees = self.frees.wrapping_add(1);
                (StackKind::VirtualFree, [(MEM_DECOMMIT, 2), (MEM_RELEASE, 3)])
            }
            _ => return,
        };

        shared.expect_stack_walk(event, stack_kind);
        let p = event.payload;
        let length = p.pointer(p.host(4, 1)) as i64;
        let event_flags = p.i32(p.host(0xC, 2));
        for (flag, column) in flags {
            if event_flags & flag != 0
                && let Some(tally) = self.by_process.get_mut(column)
            {
                tally.add(event.process_id, event.thread_id, length);
            }
        }
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        if self.allocs.wrapping_add(self.frees) == 0 {
            return;
        }

        let [committed, reserved, decommitted, released] = self.by_process.each_ref().map(|tally| text::bytes(tally.total));
        outln!(out);
        outln!(
            out,
            "VirtualAlloc: {} allocations (committed {committed}, reserved {reserved}), {} frees (decommitted {decommitted}, released {released})",
            text::count(self.allocs),
            text::count(self.frees)
        );
        let tallies = self.by_process.each_ref().map(|tally| tally.by_process(&shared.processes));
        let columns: Vec<(&str, &Tally)> = VIRTUAL_ALLOC_COLUMNS.iter().copied().zip(tallies.iter()).collect();
        Tally::print_table(out, "process", text::bytes, 8, &columns);
    }
}

/// Page faults by kind and by process.  Hard faults, whose page was read from a file: the reads with their sizes and
/// times, by file and by process.
#[derive(Default)]
pub struct PageFaultSummary {
    kinds: [i64; 6],
    faults_by_process: ProcessTally,
    hard_faults: Operations,
    hard_fault_bytes_by_file: FxMap<u64, i64>,
    hard_fault_bytes_by_process: ProcessTally,
}

const FAULT_NAMES: [&str; 6] = ["transition", "demand zero", "copy on write", "guard page", "hard", "access violation"];

impl PageFaultSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        match event.kind {
            Kind::PageFault(opcode) => {
                shared.expect_stack_walk(event, StackKind::PageFault);
                if let Some(count) = self.kinds.get_mut(usize::from(opcode.saturating_sub(10))) {
                    *count = count.wrapping_add(1);
                }

                self.faults_by_process.add(event.process_id, event.thread_id, 1);
            }
            Kind::HardFault => {
                shared.expect_stack_walk(event, StackKind::HardFault);
                let p = event.payload;
                let bytes = i64::from(p.i32(p.host(28, 2)));
                let msec = shared.clock.msec(event.timestamp.wrapping_sub(p.i64(0)));
                self.hard_faults.add(bytes, msec);
                let file = self.hard_fault_bytes_by_file.entry(p.pointer(p.host(20, 1))).or_insert(0);
                *file = file.wrapping_add(bytes);
                self.hard_fault_bytes_by_process.add(event.process_id, event.thread_id, bytes);
            }
            _ => {}
        }
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        let mut kinds = Tally::new();
        for (name, &count) in FAULT_NAMES.iter().zip(&self.kinds) {
            if count > 0 {
                kinds.add(name, count);
            }
        }

        if kinds.total() > 0 {
            outln!(out);
            outln!(out, "Page faults: {} ({})", text::count(kinds.total()), kinds.describe(12));
            self.faults_by_process.by_process(&shared.processes).print(out, "faults", "process", text::count, 8);
        }

        if self.hard_faults.count > 0 {
            let mut by_file = Tally::new();
            for (&key, &bytes) in &self.hard_fault_bytes_by_file {
                by_file.add(&shared.files.name_of(key, 0), bytes);
            }

            outln!(out);
            outln!(out, "Hard faults: {}", self.hard_faults.describe("reads", true));
            by_file.print(out, "read", "file", text::bytes, 8);
            self.hard_fault_bytes_by_process.by_process(&shared.processes).print(out, "read", "process", text::bytes, 8);
        }
    }
}

/// Snapshots of the system's memory and of every process's working set and commit, every half second.  A snapshot is a
/// system event, then process events of up to 256 processes each.
///
/// The system event's payload is page counts (pointer sized) that start like SYSTEM_MEMORY_LIST_INFORMATION (zero,
/// free, modified, modified no-write and bad pages, standby and repurposed pages by priority 0-7, modified pages headed
/// for the page file), then paged pool, two counts not identified yet, and committed pages.  This layout (version 3)
/// was checked against the Memory performance counters.  The process events have pseudo processes: -1 is the system
/// cache working set and -2 paged pool.
pub struct MemInfoSummary {
    system_snapshots: i64,
    process_snapshots: i64,
    first: Option<[i64; SYSTEM_FIELDS]>,
    last: [i64; SYSTEM_FIELDS],
    min_available: i64,
    max_committed: i64,
    snapshot: Vec<ProcessMemory>,
    last_process_event_msec: f64,
}

struct ProcessMemory {
    process_id: i32,
    working_set: i64,
    private_working_set: i64,
    commit: i64,
}

const SYSTEM_FIELDS: usize = 26;
const ZERO: usize = 0;
const FREE: usize = 1;
const MODIFIED: usize = 2;
const STANDBY: usize = 5;
const PRIORITIES: usize = 8;
const PAGED_POOL: usize = 22;
const COMMITTED: usize = 25;
const SNAPSHOT_GAP_MSEC: f64 = 100.0;

impl Default for MemInfoSummary {
    fn default() -> Self {
        Self {
            system_snapshots: 0,
            process_snapshots: 0,
            first: None,
            last: [0; SYSTEM_FIELDS],
            min_available: i64::MAX,
            max_committed: 0,
            snapshot: Vec::new(),
            last_process_event_msec: f64::NEG_INFINITY,
        }
    }
}

impl MemInfoSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &Shared) {
        match event.kind {
            Kind::SystemMemInfo => self.on_system(event),
            Kind::ProcessMemInfo => self.on_processes(event, shared),
            _ => {}
        }
    }

    fn on_system(&mut self, event: &Event<'_>) {
        self.system_snapshots = self.system_snapshots.wrapping_add(1);
        let p = event.payload;
        if event.version < 3 || p.len() < SYSTEM_FIELDS.saturating_mul(p.pointer_size()) {
            return; // A layout not checked yet.
        }

        let mut pages = [0i64; SYSTEM_FIELDS];
        for (i, page) in pages.iter_mut().enumerate() {
            *page = p.pointer(i.saturating_mul(p.pointer_size())) as i64;
        }

        self.first.get_or_insert(pages);
        self.last = pages;
        self.min_available = self.min_available.min(available(&pages));
        self.max_committed = self.max_committed.max(field(&pages, COMMITTED));
    }

    fn on_processes(&mut self, event: &Event<'_>, shared: &Shared) {
        // The events of one snapshot come together; the next snapshot is half a second later.
        let msec = shared.relative_msec(event);
        if msec - self.last_process_event_msec > SNAPSHOT_GAP_MSEC {
            self.snapshot.clear();
            self.process_snapshots = self.process_snapshots.wrapping_add(1);
        }

        self.last_process_event_msec = msec;
        let p = event.payload;
        let count = usize::try_from(p.i32(0)).unwrap_or(0);
        let element_size = if event.version >= 2 { p.host(36, 8) } else { p.host(20, 4) };
        let fits = p.len().saturating_sub(4).checked_div(element_size).unwrap_or(0);
        for i in 0..count.min(fits) {
            let base = i.saturating_mul(element_size).saturating_add(4);
            self.snapshot.push(ProcessMemory {
                process_id: p.i32(base),
                working_set: p.pointer(base.saturating_add(4)) as i64,
                commit: p.pointer(p.host(base.saturating_add(8), 1)) as i64,
                private_working_set: p.pointer(p.host(base.saturating_add(16), 3)) as i64,
            });
        }
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        if self.system_snapshots == 0 && self.process_snapshots == 0 {
            return;
        }

        outln!(out);
        outln!(out, "Memory info: {} system and {} process snapshots", text::count(self.system_snapshots), text::count(self.process_snapshots));
        if let Some(first) = &self.first {
            let last = &self.last;
            outln!(
                out,
                "  Available (zero, free and standby pages): {} at the start, {} at the end, {} at the least",
                pages(available(first)),
                pages(available(last)),
                pages(self.min_available)
            );
            outln!(
                out,
                "  Committed: {} at the start, {} at the end, {} at the most",
                pages(field(first, COMMITTED)),
                pages(field(last, COMMITTED)),
                pages(self.max_committed)
            );
            outln!(
                out,
                "  At the end: zero {}, free {}, standby {}, modified {}, paged pool {}",
                pages(field(last, ZERO)),
                pages(field(last, FREE)),
                pages(standby(last)),
                pages(field(last, MODIFIED)),
                pages(field(last, PAGED_POOL))
            );
        }

        if !self.snapshot.is_empty() {
            outln!(out, "  Largest working sets in the last snapshot:");
            outln!(out, "  {} {} {}  process", pad_left("working set", 12), pad_left("private WS", 12), pad_left("commit", 12));
            let mut largest: Vec<&ProcessMemory> = self.snapshot.iter().collect();
            largest.sort_by_key(|process| std::cmp::Reverse(process.working_set));
            for process in largest.into_iter().take(8) {
                outln!(
                    out,
                    "  {} {} {}  {}",
                    pad_left(&pages(process.working_set), 12),
                    pad_left(&pages(process.private_working_set), 12),
                    pad_left(&pages(process.commit), 12),
                    label(process.process_id, shared)
                );
            }
        }
    }
}

fn field(pages: &[i64; SYSTEM_FIELDS], index: usize) -> i64 {
    pages.get(index).copied().unwrap_or(0)
}

fn standby(pages: &[i64; SYSTEM_FIELDS]) -> i64 {
    pages.iter().skip(STANDBY).take(PRIORITIES).fold(0i64, |sum, &count| sum.wrapping_add(count))
}

fn available(pages: &[i64; SYSTEM_FIELDS]) -> i64 {
    field(pages, ZERO).wrapping_add(field(pages, FREE)).wrapping_add(standby(pages))
}

fn pages(count: i64) -> String {
    text::bytes(count.wrapping_mul(PAGE_SIZE))
}

fn label(process_id: i32, shared: &Shared) -> String {
    match process_id {
        -1 => "(system cache)".to_owned(),
        -2 => "(paged pool)".to_owned(),
        id if id < 0 => format!("(kernel {id})"),
        id => shared.processes.label(id),
    }
}

/// The pages processes touched during the trace.  Reference set tracing empties working sets and logs a page access
/// event when a page comes back, so the distinct physical pages in those events are what each process (and the
/// system) actually used.
#[derive(Default)]
pub struct ReferenceSetSummary {
    accesses: i64,
    pages: FxSet<u64>,
    pages_by_kind: [i64; 16],
    pages_by_process: FxMap<i32, FxSet<u64>>,
}

const PAGE_KINDS: [&str; 14] = [
    "ProcessPrivate",
    "File",
    "PageFileMapped",
    "PageTable",
    "PagedPool",
    "NonPagedPool",
    "SystemPTE",
    "SessionPrivate",
    "MetaFile",
    "AwePage",
    "DriverLockPage",
    "KernelStack",
    "WSMetaData",
    "LargePage",
];

impl ReferenceSetSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        if event.kind != Kind::PageAccess {
            return;
        }

        self.accesses = self.accesses.wrapping_add(1);
        shared.expect_stack_walk(event, StackKind::PageAccess);
        let p = event.payload;
        let page = p.pointer(8);
        if self.pages.insert(page)
            && let Some(count) = self.pages_by_kind.get_mut(usize::from(p.u8(0) & 0xF))
        {
            *count = count.wrapping_add(1);
        }

        self.pages_by_process.entry(event.process_id).or_default().insert(page);
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        if self.accesses == 0 {
            return;
        }

        let mut by_kind = Tally::new();
        for (kind, &count) in self.pages_by_kind.iter().enumerate() {
            if count > 0 {
                by_kind.add(PAGE_KINDS.get(kind).copied().unwrap_or("?"), count.wrapping_mul(PAGE_SIZE));
            }
        }

        let mut by_process = Tally::new();
        for (&process_id, pages) in &self.pages_by_process {
            by_process.add(&shared.processes.label(process_id), count_of(pages.len()).wrapping_mul(PAGE_SIZE));
        }

        let distinct = count_of(self.pages.len());
        outln!(out);
        outln!(
            out,
            "Reference set: {} page accesses touched {} distinct pages ({})",
            text::count(self.accesses),
            text::count(distinct),
            text::bytes(distinct.wrapping_mul(PAGE_SIZE))
        );
        by_kind.print(out, "touched", "page kind", text::bytes, 8);
        by_process.print(out, "touched", "process (its distinct pages, so they can add up to more than the total)", text::bytes, 8);
    }
}

fn count_of(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}
