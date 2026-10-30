//! The pieces the summaries share: report text, tallies, stack coverage, and process, module and file names learned
//! from the trace as it is read (some only at its end).

use std::cmp::Ordering;
use std::fmt::{self, Write};

use super::state::DriveMapping;
use crate::hash::FxMap;
use crate::text::{self, fold_case, fold_case_into, ordinal_cmp, pad_left, pad_right};

/// The report's text, written in full at the end.
#[derive(Default)]
pub struct Out(String);

impl Out {
    pub fn line(&mut self, args: fmt::Arguments<'_>) {
        let _ = self.0.write_fmt(args);
        self.0.push('\n');
    }

    pub fn blank(&mut self) {
        self.0.push('\n');
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// `outln!(out)` writes an empty line; `outln!(out, "...", args)` a formatted one.
macro_rules! outln {
    ($out:expr) => {
        $out.blank()
    };
    ($out:expr, $($arg:tt)*) => {
        $out.line(format_args!($($arg)*))
    };
}
pub(crate) use outln;

/// Adds up an amount per key and prints the largest (a tally).  Keys can compare ignoring case, in which case a key
/// keeps the spelling it was first added with.
pub struct Tally {
    ignore_case: bool,
    index: FxMap<String, usize>,
    entries: Vec<(String, i64)>,
    total: i64,
    /// A reused buffer for the folded key, when ignoring case.
    folded: String,
}

impl Default for Tally {
    fn default() -> Self {
        Self::new()
    }
}

impl Tally {
    pub fn new() -> Self {
        Self {
            ignore_case: false,
            index: FxMap::default(),
            entries: Vec::new(),
            total: 0,
            folded: String::new(),
        }
    }

    pub fn ignoring_case() -> Self {
        Self { ignore_case: true, ..Self::new() }
    }

    pub fn total(&self) -> i64 {
        self.total
    }

    pub fn add(&mut self, key: &str, amount: i64) {
        let index_key = if self.ignore_case {
            fold_case_into(key, &mut self.folded);
            self.folded.as_str()
        } else {
            key
        };
        match self.index.get(index_key).copied().and_then(|slot| self.entries.get_mut(slot)) {
            Some(entry) => entry.1 = entry.1.wrapping_add(amount),
            None => {
                self.index.insert(index_key.to_owned(), self.entries.len());
                self.entries.push((key.to_owned(), amount));
            }
        }

        self.total = self.total.wrapping_add(amount);
    }

    /// Adds another tally's amounts times the multiplier (e.g. -1 to subtract them).
    pub fn add_tally(&mut self, other: &Self, multiplier: i64) {
        for (key, amount) in &other.entries {
            self.add(key, amount.wrapping_mul(multiplier));
        }
    }

    pub fn get(&self, key: &str) -> i64 {
        let slot = if self.ignore_case { self.index.get(&fold_case(key)) } else { self.index.get(key) };
        slot.and_then(|&slot| self.entries.get(slot)).map_or(0, |entry| entry.1)
    }

    /// The `count` largest entries: by amount, then key (ordinal).
    pub fn largest(&self, count: usize) -> Vec<(&str, i64)> {
        let mut entries: Vec<(&str, i64)> = self.entries.iter().map(|(key, amount)| (key.as_str(), *amount)).collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| ordinal_cmp(a.0, b.0)));
        entries.truncate(count);
        entries
    }

    /// "key count, key count, ..." for the largest entries.
    pub fn describe(&self, count: usize) -> String {
        let parts: Vec<String> = self.largest(count).into_iter().map(|(key, amount)| format!("{key} {}", text::count(amount))).collect();
        parts.join(", ")
    }

    /// The largest entries: the formatted amount, its share of the total, and the key.
    pub fn print(&self, out: &mut Out, amount_header: &str, key_header: &str, format: fn(i64) -> String, count: usize) {
        outln!(out, "  {}      %  {key_header}", pad_left(amount_header, 12));
        for (key, amount) in self.largest(count) {
            outln!(out, "  {} {}  {key}", pad_left(&format(amount), 12), pad_left(&text::percent(amount, self.total), 6));
        }
    }

    /// Several amounts per key, one column each, for the keys with the largest amounts in the first column.
    pub fn print_table(out: &mut Out, key_header: &str, format: fn(i64) -> String, count: usize, columns: &[(&str, &Self)]) {
        let mut header = String::from(" ");
        for (name, _) in columns {
            header.push(' ');
            header.push_str(&pad_left(name, 12));
        }

        outln!(out, "{header}  {key_header}");
        let Some((_, first)) = columns.first() else {
            return;
        };

        for (key, _) in first.largest(count) {
            let mut row = String::from(" ");
            for (_, amounts) in columns {
                row.push(' ');
                row.push_str(&pad_left(&format(amounts.get(key)), 12));
            }

            outln!(out, "{row}  {key}");
        }
    }
}

/// Counts operations and adds up their bytes and durations.
#[derive(Default)]
pub struct Operations {
    pub count: i64,
    pub bytes: i64,
    total_msec: f64,
    max_msec: f64,
}

impl Operations {
    pub fn add(&mut self, bytes: i64, msec: f64) {
        self.count = self.count.wrapping_add(1);
        self.bytes = self.bytes.wrapping_add(bytes);
        self.total_msec += msec;
        self.max_msec = dotnet_max(self.max_msec, msec);
    }

    /// E.g. "1,234 reads of 12.3 MB (0.42 ms average, 8.1 ms max)".
    pub fn describe(&self, what: &str, with_bytes: bool) -> String {
        let count = format!("{} {what}", text::count(self.count));
        if self.count == 0 {
            return count;
        }

        let average = text::fixed(self.total_msec / self.count as f64, 2);
        let max = text::fixed(self.max_msec, 1);
        let bytes = if with_bytes { format!(" of {}", text::bytes(self.bytes)) } else { String::new() };
        format!("{count}{bytes} ({average} ms average, {max} ms max)")
    }
}

/// Math.Max, which (unlike f64::max) returns NaN if either value is NaN.
fn dotnet_max(a: f64, b: f64) -> f64 {
    if a > b || a.is_nan() { a } else { b }
}

/// Names processes, and knows each thread's process (from thread starts and the start rundown).  Events whose process
/// was not known yet when they were read are placed through this at the end.
#[derive(Default)]
pub struct ProcessNames {
    thread_process: FxMap<i32, i32>,
    names: FxMap<i32, String>,
}

impl ProcessNames {
    pub fn on_thread(&mut self, thread_id: i32, process_id: i32) {
        self.thread_process.insert(thread_id, process_id);
    }

    pub fn on_process(&mut self, process_id: i32, name: String) {
        self.names.insert(process_id, name);
    }

    pub fn process_of(&self, thread_id: i32) -> i32 {
        self.thread_process.get(&thread_id).copied().unwrap_or(-1)
    }

    /// "name (ID)", "? (ID)" if the name is not known, or "(unknown process)" for -1.
    pub fn label(&self, process_id: i32) -> String {
        if process_id == -1 {
            return "(unknown process)".to_owned();
        }

        format!("{} ({process_id})", self.names.get(&process_id).map_or("?", String::as_str))
    }
}

/// Adds up an amount per process.  Amounts from events whose process was not known yet are kept by thread and given to
/// the thread's process when the totals are read.
#[derive(Default)]
pub struct ProcessTally {
    pub total: i64,
    by_process: FxMap<i32, i64>,
    by_thread: FxMap<i32, i64>,
}

impl ProcessTally {
    pub fn add(&mut self, process_id: i32, thread_id: i32, amount: i64) {
        self.total = self.total.wrapping_add(amount);
        let (map, key) = if process_id != -1 { (&mut self.by_process, process_id) } else { (&mut self.by_thread, thread_id) };
        let slot = map.entry(key).or_insert(0);
        *slot = slot.wrapping_add(amount);
    }

    /// The totals keyed by process label.
    pub fn by_process(&self, processes: &ProcessNames) -> Tally {
        let mut totals = self.by_process.clone();
        for (&thread_id, &amount) in &self.by_thread {
            let slot = totals.entry(processes.process_of(thread_id)).or_insert(0);
            *slot = slot.wrapping_add(amount);
        }

        let mut tally = Tally::new();
        for (process_id, amount) in totals {
            tally.add(&processes.label(process_id), amount);
        }

        tally
    }
}

/// The kinds of events counted for stack coverage, in the order they print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackKind {
    SampledProfile,
    CSwitch,
    CSwitchToIdle,
    ReadyThread,
    PmcInterrupt,
    ProcessStart,
    ThreadStart,
    ImageLoad,
    FileIO,
    DiskIO,
    Registry,
    Dns,
    VirtualAlloc,
    VirtualFree,
    PageFault,
    HardFault,
    Handle,
    PageAccess,
}

const STACK_KIND_NAMES: [&str; 18] = [
    "SampledProfile",
    "CSwitch",
    "CSwitch to idle",
    "ReadyThread",
    "PmcInterrupt",
    "ProcessStart",
    "ThreadStart",
    "ImageLoad",
    "FileIO",
    "DiskIO",
    "Registry",
    "DNS",
    "VirtualAlloc",
    "VirtualFree",
    "PageFault",
    "HardFault",
    "Handle",
    "PageAccess",
];

/// Events on one processor still waiting for their StackWalk event, oldest first.  The stack follows its event almost
/// immediately, but an interrupt (e.g. a PMC overflow) can log another event and stack in between, so a few are kept.
#[derive(Clone, Copy, Default)]
struct Pending {
    entries: [(i64, u8); PENDING_PER_PROCESSOR],
    len: usize,
}

const PENDING_PER_PROCESSOR: usize = 8;

/// Counts events of each kind and how many of them have a stack.  A kernel event's stack is a separate StackWalk event
/// that carries the event's time and is logged on the same processor right after it.  (The kernel and user mode
/// halves of a stack can be separate StackWalk events; only the first is matched.)  User mode providers attach stacks
/// to the event itself.
#[derive(Default)]
pub struct StackCoverage {
    counts: [(i64, i64); 18],
    pending: Vec<Pending>,
}

impl StackCoverage {
    /// Counts a kernel event that may be followed by a StackWalk event.  `time` is the event's clamped timestamp.
    pub fn expect_stack_walk(&mut self, processor: usize, time: i64, kind: StackKind) {
        self.count(kind, false);
        if self.pending.len() <= processor {
            self.pending.resize(processor.saturating_add(1), Pending::default());
        }

        let Some(pending) = self.pending.get_mut(processor) else {
            return;
        };

        if pending.len == PENDING_PER_PROCESSOR {
            pending.entries.rotate_left(1);
            pending.len = PENDING_PER_PROCESSOR.saturating_sub(1);
        }

        if let Some(entry) = pending.entries.get_mut(pending.len) {
            *entry = (time, kind as u8);
            pending.len = pending.len.saturating_add(1);
        }
    }

    pub fn count(&mut self, kind: StackKind, has_stack: bool) {
        if let Some((events, with_stack)) = self.counts.get_mut(kind as usize) {
            *events = events.wrapping_add(1);
            if has_stack {
                *with_stack = with_stack.wrapping_add(1);
            }
        }
    }

    /// A StackWalk event: gives the stack to the latest pending event on its processor with the same time.
    pub fn on_stack_walk(&mut self, processor: usize, event_time: i64) {
        let Some(pending) = self.pending.get_mut(processor) else {
            return;
        };

        let len = pending.len;
        let found = pending.entries.get(..len).and_then(|entries| entries.iter().rposition(|&(time, _)| time == event_time));
        let Some(index) = found else {
            return;
        };

        let kind = pending.entries.get(index).map_or(0, |&(_, kind)| usize::from(kind));
        if let Some(rest) = pending.entries.get_mut(index..len) {
            rest.rotate_left(1);
        }

        pending.len = len.saturating_sub(1);
        if let Some((_, with_stack)) = self.counts.get_mut(kind) {
            *with_stack = with_stack.wrapping_add(1);
        }
    }

    pub fn print(&self, out: &mut Out) {
        outln!(out, "  Event                     Count  With stack");
        for (name, &(events, with_stack)) in STACK_KIND_NAMES.iter().zip(&self.counts) {
            if events > 0 {
                outln!(out, "  {} {}  {}", pad_right(name, 15), pad_left(&text::count(events), 14), pad_left(&text::percent(with_stack, events), 10));
            }
        }
    }
}

/// Finds the module that contains a code address, from the image load and rundown events.  Kernel mode images are
/// logged against process 0.
#[derive(Default)]
pub struct ModuleMap {
    images: FxMap<i32, Vec<Image>>,
    names: Vec<String>,
    name_ids: FxMap<String, u32>,
}

struct Image {
    base: u64,
    size: u64,
    name: u32,
}

const KERNEL_ADDRESS_START: u64 = 0xFFFF_8000_0000_0000;

impl ModuleMap {
    pub fn add(&mut self, process_id: i32, base: u64, size: u64, name: &str) {
        let id = match self.name_ids.get(name) {
            Some(&id) => id,
            None => {
                let id = u32::try_from(self.names.len()).unwrap_or(u32::MAX);
                self.names.push(name.to_owned());
                self.name_ids.insert(name.to_owned(), id);
                id
            }
        };
        self.images.entry(process_id).or_default().push(Image { base, size, name: id });
    }

    pub fn remove(&mut self, process_id: i32, base: u64) {
        self.images.entry(process_id).or_default().retain(|image| image.base != base);
    }

    /// The module containing the address (its name ID), or None ("?", e.g. JIT compiled code).
    pub fn find(&self, process_id: i32, address: u64) -> Option<u32> {
        let process_id = if address >= KERNEL_ADDRESS_START { 0 } else { process_id };
        self.images.get(&process_id)?.iter().find(|image| address.wrapping_sub(image.base) < image.size).map(|image| image.name)
    }

    pub fn name(&self, id: Option<u32>) -> &str {
        id.and_then(|id| self.names.get(usize::try_from(id).ok()?)).map_or("?", String::as_str)
    }
}

/// File names by file key (and by file object, for files opened during the trace), for the file I/O, disk I/O and hard
/// fault events, which only have the key.  Names of files open before the trace started are only logged at its end
/// (the file rundown), so names are looked up when printing.  The session files 'record' wrote the trace to are marked,
/// since ETW writing them shows up in file and disk I/O too.  A rundown can name hundreds of thousands of files, so the
/// names are kept in an arena.
pub struct FileNames {
    session_files: [String; 2],
    names: StringArena,
    key_names: FxMap<u64, ArenaString>,
    object_names: FxMap<u64, ArenaString>,
    /// A reused buffer for the name being added.
    mapped: String,
}

impl FileNames {
    pub fn new(session_files: [String; 2]) -> Self {
        Self {
            session_files,
            names: StringArena::default(),
            key_names: FxMap::default(),
            object_names: FxMap::default(),
            mapped: String::new(),
        }
    }

    /// A FileIO Name, FileCreate, FileDelete or FileRundown event: the file key's name, before drive letters are mapped.
    pub fn on_name(&mut self, file_key: u64, kernel_name: &str, drives: &mut DriveMapping) {
        let previous = self.key_names.get(&file_key).copied();
        let name = self.add(kernel_name, drives, previous);
        self.key_names.insert(file_key, name);
    }

    /// A FileIO Create event: the file object's name, before drive letters are mapped.
    pub fn on_create(&mut self, file_object: u64, kernel_name: &str, drives: &mut DriveMapping) {
        let previous = self.object_names.get(&file_object).copied();
        let name = self.add(kernel_name, drives, previous);
        self.object_names.insert(file_object, name);
    }

    /// Stores the name with drive letters, unless it is the same as the previous one (as it usually is when the rundown
    /// names a file again).
    fn add(&mut self, kernel_name: &str, drives: &mut DriveMapping, previous: Option<ArenaString>) -> ArenaString {
        drives.map_to_user_into(kernel_name, &mut self.mapped);
        match previous {
            Some(previous) if self.names.get(previous) == self.mapped => previous,
            _ => self.names.push(&self.mapped),
        }
    }

    pub fn name_of(&self, file_key: u64, file_object: u64) -> String {
        let name = self.key_names.get(&file_key).or_else(|| self.object_names.get(&file_object));
        match name.map(|&name| self.names.get(name)) {
            Some(name) if self.session_files.iter().any(|file| text::eq_ignore_case(file, name)) => {
                format!("{name}  (this trace, written by ETW)")
            }
            Some(name) => name.to_owned(),
            None => "(file name not in trace)".to_owned(),
        }
    }
}

/// Strings kept in large chunks, rather than in an allocation each.  A chunk is never grown (which would copy it), so a
/// string that doesn't fit in the current chunk starts a new one.
#[derive(Default)]
pub struct StringArena {
    full: Vec<String>,
    current: String,
}

/// A string in a StringArena.
#[derive(Clone, Copy)]
pub struct ArenaString {
    chunk: u32,
    start: u32,
    end: u32,
}

const ARENA_CHUNK: usize = 1 << 20;

impl StringArena {
    pub fn push(&mut self, text: &str) -> ArenaString {
        if self.current.capacity().saturating_sub(self.current.len()) < text.len() {
            let full = std::mem::replace(&mut self.current, String::with_capacity(ARENA_CHUNK.max(text.len())));
            self.full.push(full);
        }

        let start = self.current.len();
        self.current.push_str(text);
        let index = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
        ArenaString {
            chunk: index(self.full.len()),
            start: index(start),
            end: index(self.current.len()),
        }
    }

    pub fn get(&self, string: ArenaString) -> &str {
        let chunk = string.chunk as usize;
        let chunk = if chunk == self.full.len() { Some(&self.current) } else { self.full.get(chunk) };
        chunk.and_then(|chunk| chunk.get(string.start as usize..string.end as usize)).unwrap_or_default()
    }
}

/// A map whose iteration order is that of .NET's Dictionary: insertion order, except that a removed entry's slot is
/// reused by the next insertion (most recently freed first).  Where a .NET report iterates a dictionary it removes from,
/// the order decides which spelling a case-insensitive key keeps, so it is reproduced.
pub struct DotNetOrder<K, V> {
    slots: Vec<Option<(K, V)>>,
    free: Vec<usize>,
    index: FxMap<K, usize>,
}

impl<K: Copy + Eq + std::hash::Hash, V> Default for DotNetOrder<K, V> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            index: FxMap::default(),
        }
    }
}

impl<K: Copy + Eq + std::hash::Hash, V> DotNetOrder<K, V> {
    pub fn get_or_insert_with(&mut self, key: K, make: impl FnOnce() -> V) -> Option<&mut V> {
        let slot = match self.index.get(&key) {
            Some(&slot) => slot,
            None => {
                let slot = match self.free.pop() {
                    Some(slot) => {
                        if let Some(entry) = self.slots.get_mut(slot) {
                            *entry = Some((key, make()));
                        }

                        slot
                    }
                    None => {
                        self.slots.push(Some((key, make())));
                        self.slots.len().saturating_sub(1)
                    }
                };
                self.index.insert(key, slot);
                slot
            }
        };
        self.slots.get_mut(slot).and_then(Option::as_mut).map(|(_, value)| value)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let slot = self.index.remove(key)?;
        let (_, value) = self.slots.get_mut(slot)?.take()?;
        self.free.push(slot);
        Some(value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.slots.iter().flatten().map(|(key, value)| (key, value))
    }
}

/// Insertion ordered counts by a key that compares ignoring case (keeping the first spelling).
#[derive(Default)]
pub struct CaseInsensitiveCounts {
    index: FxMap<String, usize>,
    entries: Vec<(String, i64)>,
}

impl CaseInsensitiveCounts {
    /// Adds one to the key; `folded` is a reusable buffer.
    pub fn increment(&mut self, key: &str, folded: &mut String) {
        fold_case_into(key, folded);
        match self.index.get(folded.as_str()).copied().and_then(|slot| self.entries.get_mut(slot)) {
            Some(entry) => entry.1 = entry.1.wrapping_add(1),
            None => {
                self.index.insert(folded.clone(), self.entries.len());
                self.entries.push((key.to_owned(), 1));
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, i64)> {
        self.entries.iter().map(|(key, count)| (key.as_str(), *count))
    }
}

/// Orders f64 like .NET's Comparer<double>.Default: NaN first (smallest), then by value.
pub fn dotnet_cmp(a: f64, b: f64) -> Ordering {
    match (a.is_nan(), b.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
    }
}

#[cfg(test)]
mod tests {
    use super::{ARENA_CHUNK, StringArena};

    #[test]
    fn arena_strings_survive_new_chunks() {
        let mut arena = StringArena::default();
        let filler = "x".repeat(ARENA_CHUNK - 3);
        let oversized = "y".repeat(ARENA_CHUNK + 1);
        let strings = ["", "C:\\a.txt", filler.as_str(), "C:\\b.txt", oversized.as_str(), "C:\\c.txt"];
        let stored: Vec<_> = strings.iter().map(|text| arena.push(text)).collect();
        for (text, string) in strings.iter().zip(stored) {
            assert_eq!(arena.get(string), *text);
        }
    }
}
