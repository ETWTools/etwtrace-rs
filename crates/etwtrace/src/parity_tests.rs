//! Manual parity tests that need a trace file, so they are ignored by default.  Each writes a trace that
//! the report should handle as a reference implementation would:
//!
//! ```text
//! set ETWTRACE_TEST_INPUT=C:\traces\some.etl
//! set ETWTRACE_TEST_OUTPUT=C:\traces\merged.etl
//! cargo test -p etwtrace merge_trace -- --ignored          (the input, merged as 'record' merges; ';' separates several)
//! cargo test -p etwtrace synthesize_trace -- --ignored     (the input, plus synthetic events of the kinds below)
//! ```
//!
//! The synthetic events cover what traces recorded without elevation are unlikely to have: registry operations and key
//! control blocks (including a reused KCB slot whose order decides a key's spelling), handles and object type names,
//! reference set page accesses, per process memory info snapshots, PMC overflow samples and intervals, last branch
//! records, IPv6 TCP and UDP, and stacks for them.  Payload layouts are TraceEvent's, which is what the report
//! decodes them with.  Most are 64-bit copies of a kernel event (whose header has no IDs, so both reports find the
//! process through the thread); some are 32-bit new events with explicit IDs, since the relogger writes new events with
//! kernel GUIDs as 32-bit, which exercises the 32-bit layouts.

#![allow(clippy::arithmetic_side_effects, reason = "Test data.")]

use std::path::Path;

use etw::{EventRecord, Guid, NewEvent, RelogContext, RelogHandler};

use crate::guids::{IMAGE, LAST_BRANCH, OBJECT, PAGE_FAULT, PERF_INFO, REGISTRY, STACK_WALK, TCP_IP, UDP_IP};

fn paths() -> (String, String) {
    let input = std::env::var("ETWTRACE_TEST_INPUT").expect("set ETWTRACE_TEST_INPUT to a trace file");
    let output = std::env::var("ETWTRACE_TEST_OUTPUT").expect("set ETWTRACE_TEST_OUTPUT to the file to write");
    (input, output)
}

#[test]
#[ignore = "needs ETWTRACE_TEST_INPUT and ETWTRACE_TEST_OUTPUT"]
fn merge_trace() {
    let (input, output) = paths();
    let inputs: Vec<&Path> = input.split(';').map(Path::new).collect();
    crate::merge::merge(&inputs, Path::new(&output)).unwrap();
}

#[test]
#[ignore = "needs ETWTRACE_TEST_INPUT and ETWTRACE_TEST_OUTPUT"]
fn synthesize_trace() {
    let (input, output) = paths();
    let frequency = etw::consumer::file_info(Path::new(&input)).unwrap().perf_freq;
    let mut synthesizer = Synthesizer { frequency, ..Synthesizer::default() };
    etw::relogger::relog(&[Path::new(&input)], Path::new(&output), &mut synthesizer).unwrap();
    assert_eq!(synthesizer.batches, 2, "the trace needs a thread and image rundown and to last a second");
}

#[derive(Default)]
struct Synthesizer {
    frequency: i64,
    /// Images by process (base, size), from the image rundown.
    images: std::collections::HashMap<i32, (u64, u64)>,
    first_batch_time: i64,
    batches: usize,
}

impl RelogHandler for Synthesizer {
    fn on_event(&mut self, event: &EventRecord<'_>, relog: &mut RelogContext<'_>) {
        relog.keep();
        if !event.is_64_bit() {
            return;
        }

        let data = event.user_data();
        if self.batches == 0 && event.provider() == IMAGE && event.opcode() == 3 {
            self.images.entry(read_i32(data, 16)).or_insert((read_u64(data, 0), read_u64(data, 8)));
        }

        // The first event logged by a user mode thread of a process whose images are known: the synthetic events are
        // logged as that thread (64-bit copies keep the event's IDs).
        let (pid, tid) = (event.process_id() as i32, event.thread_id() as i32);
        if self.batches == 0
            && pid > 4
            && tid > 0
            && let (Some(&module), Some(&kernel)) = (self.images.get(&pid), self.images.get(&0))
        {
            self.first_batch_time = event.timestamp();
            let mut copies = Writer::new(relog, event, 8, pid as u32, tid as u32);
            first_batch(&mut copies, tid, module, kernel);
            let mut created = Writer::new(relog, event, 4, pid as u32, tid as u32);
            first_batch_32(&mut created, tid);
            self.batches = 1;
        } else if self.batches == 1 && event.timestamp() - self.first_batch_time > self.frequency / 3 {
            second_batch(&mut Writer::new(relog, event, 8, u32::MAX, u32::MAX));
            self.batches = 2;
        }
    }
}

fn first_batch(w: &mut Writer<'_, '_>, tid: i32, (module_base, module_size): (u64, u64), (kernel_base, _): (u64, u64)) {
    // Registry: KCB names, opens relative to a KCB in two spellings, statuses, value operations, absolute paths.
    w.registry(22, 0xA000, 0, r"\REGISTRY\MACHINE\SOFTWARE");
    w.registry(11, 0xA000, 0, r"Microsoft\Windows");
    w.stack_walk();
    w.registry(11, 0xA000, 0xC000_0034_u32 as i32, r"MICROSOFT\WINDOWS");
    w.registry(10, 0xA000, 0, "Contoso");
    w.registry(16, 0xB000, 0x8000_0005_u32 as i32, "Version");
    w.registry(13, 0xC000, 0xC000_0099_u32 as i32, "");
    w.registry(17, 0xD000, 0, "");
    w.registry(11, 0, 0, r"\REGISTRY\USER\S-1-5-18");
    w.registry(27, 0, 0, "");
    // KCBs X, Y, Z, then Y's deletion frees its slot for W, so W's counts come before Z's.  Their keys differ only in
    // case, so the order decides which spelling the report shows.
    w.registry(22, 0xE001, 0, r"\REGISTRY\USER\X");
    w.registry(22, 0xE003, 0, r"\REGISTRY\USER\Q\R");
    w.registry(22, 0xE004, 0, r"\REGISTRY\USER\Q");
    w.registry(16, 0xE001, 0, "a");
    w.registry(16, 0xE002, 0, "b");
    w.registry(13, 0xE003, 0, "");
    w.registry(23, 0xE002, 0, r"\REGISTRY\MACHINE\Y");
    w.registry(11, 0xE004, 0, "r");
    // A KCB whose address is reused after it is deleted.
    w.registry(23, 0xC000, 0, r"\REGISTRY\MACHINE\SYSTEM\Old");
    w.registry(13, 0xC000, 0, "");

    // Handles: creates, closes and a duplicate, of named and unnamed object types.
    for (opcode, object_type) in [(32, 37), (32, 37), (32, 37), (32, 38), (32, 99), (33, 37), (33, 37)] {
        w.handle(opcode, object_type);
        w.stack_walk();
    }

    w.duplicate(4, 38);

    // Reference set page accesses: repeated pages, three page kinds (one TraceEvent has no name for), as PageAccess and
    // PageAccessEx (opcodes 118 and 130, which TraceEvent reads alike).
    for (kind, page, opcode) in [(0u8, 0x1111_u64, 118), (0, 0x1111, 130), (1, 0x2222, 118), (14, 0x3333, 130), (0, 0x4444, 130)] {
        w.page_access(kind, page, opcode);
        w.stack_walk();
    }

    // A process memory snapshot, with the system cache and paged pool pseudo processes.
    w.process_mem_info(&[(1234, 5000, 300, 4000), (-1, 90_000, 0, 0), (-2, 20_000, 0, 0)]);

    // PMC overflow samples of two sources, in the module, the kernel and nowhere known, and the sources' intervals.
    w.interval(6, 100_000);
    w.interval(11, 20_000);
    for (source, address) in [(6, module_base + module_size / 2), (6, module_base), (6, kernel_base + 0x10), (11, 0x1234), (6, 0x1234)] {
        w.pmc_sample(address, tid, source);
        w.stack_walk();
    }

    for branches in [3, 5] {
        w.lbr(branches);
    }

    // IPv6 TCP and UDP, an IPv4 mapped address, and failures.
    let local = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let documentation = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
    w.ip_v6(TCP_IP, 26, 1500, documentation, local, 443, 50000);
    w.ip_v6(TCP_IP, 27, 64_000, documentation, local, 443, 50000);
    w.ip_v6(TCP_IP, 26, 100, mapped, local, 80, 50001);
    w.ip_v6(UDP_IP, 27, 512, local, documentation, 50002, 53);
    w.event(TCP_IP, 17, &[6, 0, 1, 0]);
    w.event(UDP_IP, 17, &[17, 0, 2, 0]);
}

/// 32-bit events with explicit IDs: a named key, handles, a page, a snapshot entry, a sample and branch records.
fn first_batch_32(w: &mut Writer<'_, '_>, tid: i32) {
    w.registry(22, 0xF000, 0, r"\REGISTRY\MACHINE\HARDWARE");
    w.registry(11, 0xF000, 0, r"Description\System");
    w.registry(16, 0xF000, 0xC000_0034_u32 as i32, "Identifier");
    w.handle(32, 37);
    w.handle(33, 38);
    w.duplicate(w.process_id as i32, 37);
    w.page_access(1, 0x5555, 130);
    w.process_mem_info(&[(4321, 70, 7, 60)]);
    w.pmc_sample(0x1234, tid, 11);
    w.lbr(4);
}

fn second_batch(w: &mut Writer<'_, '_>) {
    // The names logged at the end: object types and the KCB rundown.
    w.object_type(37, "File");
    w.object_type(38, "Key");
    w.registry(25, 0xB000, 0, r"\REGISTRY\MACHINE\SOFTWARE\Contoso");
    w.registry(25, 0xC000, 0, r"\REGISTRY\MACHINE\SYSTEM\New");
    // A second process memory snapshot, a third of a second after the first.
    w.process_mem_info(&[(4, 100, 10, 50), (-3, 7, 0, 0)]);
}

/// Writes synthetic events at the current event's time and processor: 64-bit copies of it (which keep its header IDs),
/// or 32-bit new events with the given IDs.
struct Writer<'r, 'c> {
    relog: &'r mut RelogContext<'c>,
    pointer: usize,
    timestamp: i64,
    processor: u16,
    process_id: u32,
    thread_id: u32,
}

impl<'r, 'c> Writer<'r, 'c> {
    fn new(relog: &'r mut RelogContext<'c>, event: &EventRecord<'_>, pointer: usize, process_id: u32, thread_id: u32) -> Self {
        Self {
            relog,
            pointer,
            timestamp: event.timestamp(),
            processor: event.processor_index(),
            process_id,
            thread_id,
        }
    }

    fn event(&mut self, provider: Guid, opcode: u8, payload: &[u8]) {
        let event = NewEvent {
            provider,
            id: 0,
            version: 2,
            level: 4,
            opcode,
            flags: 0x0100 | 0x0020, // Classic, 32-bit (copies keep the copied event's flags).
            timestamp: self.timestamp,
            processor_index: self.processor,
            process_id: self.process_id,
            thread_id: self.thread_id,
            payload,
        };
        if self.pointer == 8 { self.relog.inject_copy(&event) } else { self.relog.inject(&event) }
    }

    fn pointer(&self, payload: &mut Vec<u8>, value: u64) {
        payload.extend_from_slice(&value.to_le_bytes()[..self.pointer]);
    }

    fn registry(&mut self, opcode: u8, kcb: u64, status: i32, name: &str) {
        let mut payload = 0_i64.to_le_bytes().to_vec();
        payload.extend_from_slice(&status.to_le_bytes());
        payload.extend_from_slice(&0_i32.to_le_bytes());
        self.pointer(&mut payload, kcb);
        push_utf16z(&mut payload, name);
        self.event(REGISTRY, opcode, &payload);
    }

    fn handle(&mut self, opcode: u8, object_type: i16) {
        let mut payload = Vec::new();
        self.pointer(&mut payload, 0xFFFF_9000_0000_2000);
        payload.extend_from_slice(&0x400_i32.to_le_bytes());
        payload.extend_from_slice(&object_type.to_le_bytes());
        payload.extend_from_slice(&[0, 0]);
        self.event(OBJECT, opcode, &payload);
    }

    fn duplicate(&mut self, target_process_id: i32, object_type: i16) {
        let mut payload = Vec::new();
        self.pointer(&mut payload, 0xFFFF_9000_0000_1000);
        payload.extend_from_slice(&0x100_i32.to_le_bytes());
        payload.extend_from_slice(&0x200_i32.to_le_bytes());
        payload.extend_from_slice(&target_process_id.to_le_bytes());
        payload.extend_from_slice(&object_type.to_le_bytes());
        payload.extend_from_slice(&(self.process_id as i32).to_le_bytes());
        self.event(OBJECT, 34, &payload);
    }

    fn object_type(&mut self, object_type: i16, name: &str) {
        let mut payload = object_type.to_le_bytes().to_vec();
        payload.extend_from_slice(&[0, 0]);
        push_utf16z(&mut payload, name);
        self.event(OBJECT, 37, &payload);
    }

    fn page_access(&mut self, kind: u8, page: u64, opcode: u8) {
        let mut payload = vec![kind | (2 << 4), 0, 0, 0, 0, 0, 0, 0];
        self.pointer(&mut payload, page);
        self.pointer(&mut payload, 0x7FF0_0000);
        self.event(PAGE_FAULT, opcode, &payload);
    }

    fn process_mem_info(&mut self, processes: &[(i32, u64, u64, u64)]) {
        let mut payload = i32::try_from(processes.len()).unwrap().to_le_bytes().to_vec();
        for &(pid, working_set, private_working_set, commit) in processes {
            payload.extend_from_slice(&pid.to_le_bytes());
            for value in [working_set, commit, working_set * 2, private_working_set, 0, 0, 0, 0] {
                self.pointer(&mut payload, value);
            }
        }

        self.event(PAGE_FAULT, 125, &payload);
    }

    fn interval(&mut self, source: i32, interval: i32) {
        let payload: Vec<u8> = [source, interval, interval].iter().flat_map(|value| value.to_le_bytes()).collect();
        self.event(PERF_INFO, 73, &payload);
    }

    fn pmc_sample(&mut self, address: u64, thread_id: i32, source: i16) {
        let mut payload = Vec::new();
        self.pointer(&mut payload, address);
        payload.extend_from_slice(&thread_id.to_le_bytes());
        payload.extend_from_slice(&source.to_le_bytes());
        payload.extend_from_slice(&0_i16.to_le_bytes());
        let ids = (self.process_id, self.thread_id);
        (self.process_id, self.thread_id) = (u32::MAX, u32::MAX); // As the kernel logs them.
        self.event(PERF_INFO, 47, &payload);
        (self.process_id, self.thread_id) = ids;
    }

    fn lbr(&mut self, branches: usize) {
        let mut payload = self.timestamp.to_le_bytes().to_vec();
        payload.extend_from_slice(&self.process_id.to_le_bytes());
        payload.extend_from_slice(&self.thread_id.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        if self.pointer == 8 {
            payload.extend_from_slice(&[0; 4]);
        }

        payload.extend(std::iter::repeat_n(0x11_u8, branches * 3 * self.pointer));
        self.event(LAST_BRANCH, 32, &payload);
    }

    #[expect(clippy::too_many_arguments, reason = "One test helper for four event layouts.")]
    fn ip_v6(&mut self, guid: Guid, opcode: u8, size: i32, daddr: [u8; 16], saddr: [u8; 16], dport: u16, sport: u16) {
        let mut payload = 1234_i32.to_le_bytes().to_vec();
        payload.extend_from_slice(&size.to_le_bytes());
        payload.extend_from_slice(&daddr);
        payload.extend_from_slice(&saddr);
        payload.extend_from_slice(&dport.to_be_bytes());
        payload.extend_from_slice(&sport.to_be_bytes());
        payload.extend_from_slice(&[0; 20]);
        self.event(guid, opcode, &payload);
    }

    /// A kernel stack for the event just written (same processor and time).
    fn stack_walk(&mut self) {
        let mut payload = self.timestamp.to_le_bytes().to_vec();
        payload.extend_from_slice(&self.process_id.to_le_bytes());
        payload.extend_from_slice(&self.thread_id.to_le_bytes());
        self.pointer(&mut payload, 0xFFFF_F800_0000_1000);
        self.event(STACK_WALK, 32, &payload);
    }
}

fn push_utf16z(payload: &mut Vec<u8>, text: &str) {
    payload.extend(text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
}

fn read_i32(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
