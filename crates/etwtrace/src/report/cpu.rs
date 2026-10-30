//! SampledProfile, CSwitch, ReadyThread and PmcInterrupt (counted in the stack coverage table), LBR, the profile source
//! intervals at trace start, each counter's PMC overflow samples by process and by module, and the counter values ETW
//! attaches to context switches.

use std::collections::BTreeMap;

use super::Shared;
use super::common::{Out, ProcessTally, StackKind, Tally, outln};
use super::event::{EXT_PMC_COUNTERS, Event, Kind};
use crate::hash::FxMap;
use crate::profile_sources;
use crate::text::{self, pad_left, pad_right};

/// A CSwitch event's stack is the new thread's, so switches to the idle thread (every processor's thread 0) never have
/// one; they are counted separately so the coverage of the others shows.
pub struct CpuSummary {
    source_names: FxMap<i32, String>,
    intervals: BTreeMap<i32, i32>,
    samples: BTreeMap<i32, PmcSamples>,
    lbr_events: i64,
    lbr_branches: i64,
}

#[derive(Default)]
struct PmcSamples {
    by_process: ProcessTally,
    by_module: FxMap<Option<u32>, i64>,
}

impl CpuSummary {
    pub fn new() -> Self {
        Self {
            source_names: profile_sources::names(),
            intervals: BTreeMap::new(),
            samples: BTreeMap::new(),
            lbr_events: 0,
            lbr_branches: 0,
        }
    }

    pub fn on_event(&mut self, event: &Event<'_>, shared: &mut Shared) {
        let p = event.payload;
        match event.kind {
            Kind::SampledProfile => shared.expect_stack_walk(event, StackKind::SampledProfile),
            Kind::CSwitch => {
                let kind = if event.thread_id == 0 { StackKind::CSwitchToIdle } else { StackKind::CSwitch };
                shared.expect_stack_walk(event, kind);
            }
            Kind::ReadyThread => shared.expect_stack_walk(event, StackKind::ReadyThread),
            Kind::PmcSample => {
                shared.expect_stack_walk(event, StackKind::PmcInterrupt);
                let source = i32::from(p.i16(p.host(8, 1)));
                let samples = self.samples.entry(source).or_default();
                samples.by_process.add(event.process_id, event.thread_id, 1);
                let module = shared.modules.find(event.process_id, p.pointer(0));
                let count = samples.by_module.entry(module).or_insert(0);
                *count = count.wrapping_add(1);
            }
            Kind::ProfileInterval => {
                self.intervals.insert(p.i32(0), p.i32(4));
            }
            Kind::LastBranches => {
                // A timestamp, process, thread and filters, then (from, to, reserved) pointer triples.
                let (header, entry) = if p.pointer_size() == 8 { (24, 24) } else { (20, 12) };
                let length = i64::try_from(p.len()).unwrap_or(0);
                self.lbr_events = self.lbr_events.wrapping_add(1);
                self.lbr_branches = self.lbr_branches.wrapping_add(length.wrapping_sub(header).checked_div(entry).unwrap_or(0));
            }
            _ => {}
        }
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        // The LBR line belongs to the stack coverage table, which prints just before.
        if self.lbr_events > 0 {
            let average = text::fixed(self.lbr_branches as f64 / self.lbr_events as f64, 1);
            outln!(out, "  {} {}  ({average} branches each)", pad_right("LBR", 15), pad_left(&text::count(self.lbr_events), 14));
        }

        outln!(out);
        let intervals: Vec<String> = self
            .intervals
            .iter()
            .map(|(&id, &interval)| format!("{} every {}", profile_sources::name(&self.source_names, id), profile_sources::describe_interval(id, interval)))
            .collect();
        outln!(out, "Profile sources at trace start: {}", intervals.join(", "));

        if self.samples.is_empty() {
            outln!(out, "No PmcInterrupt events (record with -pmc to sample hardware counters).");
            return;
        }

        for (&source, samples) in &self.samples {
            let by_process = samples.by_process.by_process(&shared.processes);
            let estimate = match self.intervals.get(&source) {
                Some(&interval) if source != profile_sources::TIMER_ID => {
                    format!(" (~{} events)", text::count(by_process.total().wrapping_mul(i64::from(interval))))
                }
                _ => String::new(),
            };
            outln!(out);
            outln!(out, "{} (ID {source}): {} PmcInterrupt samples{estimate}", profile_sources::name(&self.source_names, source), text::count(by_process.total()));
            by_process.print(out, "samples", "process", text::count, 8);
            let mut by_module = Tally::new();
            for (&module, &count) in &samples.by_module {
                by_module.add(shared.modules.name(module), count);
            }

            by_module.print(out, "samples", "module (instruction pointer)", text::count, 8);
        }
    }
}

/// The counter values ETW attaches to CSwitch events (-counters), turned into totals per process: what a processor
/// counted between two context switches belongs to the thread that was switched out.  The trace names the counters in
/// a PerfInfo event (opcode 48: a count, then that many null terminated UTF-16 names).
#[derive(Default)]
pub struct ContextSwitchCounterSummary {
    totals: Vec<ProcessTally>,
    previous: Vec<Option<([u64; MAX_COUNTERS], usize)>>,
    names: Option<Vec<String>>,
    switches: i64,
}

const MAX_COUNTERS: usize = 16;

impl ContextSwitchCounterSummary {
    pub fn on_event(&mut self, event: &Event<'_>, shared: &Shared) {
        match event.kind {
            Kind::PmcCounterNames if self.names.is_none() => self.names = Some(parse_counter_names(event.payload.bytes())),
            Kind::CSwitch => self.on_context_switch(event, shared),
            _ => {}
        }
    }

    fn on_context_switch(&mut self, event: &Event<'_>, shared: &Shared) {
        let Some(data) = event.extended(EXT_PMC_COUNTERS) else {
            return;
        };

        let mut values = [0u64; MAX_COUNTERS];
        let mut count = 0usize;
        for (value, &bytes) in values.iter_mut().zip(data.as_chunks::<8>().0) {
            *value = u64::from_le_bytes(bytes);
            count = count.saturating_add(1);
        }

        if count == 0 {
            return;
        }

        self.switches = self.switches.wrapping_add(1);
        if self.totals.len() < count {
            self.totals.resize_with(count, ProcessTally::default);
        }

        if self.previous.len() <= event.processor {
            self.previous.resize(event.processor.saturating_add(1), None);
        }

        let old_thread = event.payload.i32(4);
        let old_process = shared.threads.process_of(old_thread, event.timestamp);
        let Some(previous) = self.previous.get_mut(event.processor) else {
            return;
        };

        if let Some((before, before_count)) = previous
            && *before_count == count
        {
            for ((total, &now), &then) in self.totals.iter_mut().zip(&values).zip(before.iter()).take(count) {
                if now >= then {
                    total.add(old_process, old_thread, now.wrapping_sub(then) as i64);
                }
            }
        }

        *previous = Some((values, count));
    }

    pub fn print(&self, shared: &Shared, out: &mut Out) {
        if self.switches == 0 {
            return;
        }

        let names: Vec<String> = (0..self.totals.len())
            .map(|i| match self.names.as_ref().and_then(|names| names.get(i)) {
                Some(name) => name.clone(),
                None => format!("Counter{i}"),
            })
            .collect();
        let find = |part: &str| names.iter().position(|name| text::find_ignore_case(name, part).is_some());
        let instructions = find("Instruction");
        let cycles = find("Cycles");
        let by_process: Vec<Tally> = self.totals.iter().map(|total| total.by_process(&shared.processes)).collect();
        let width = names.iter().map(|name| text::utf16_len(name)).max().unwrap_or(0).max(16);

        outln!(out);
        outln!(out, "Counted on context switches: {} ({} CSwitch events had values).", names.join(", "), text::count(self.switches));
        outln!(out, "Totals over each processor's consecutive context switches, given to the thread switched out:");
        let mut header = String::new();
        for name in &names {
            header.push(' ');
            header.push_str(&pad_left(name, width));
        }

        let ipc = instructions.zip(cycles);
        outln!(out, "{header}{}  process", if ipc.is_some() { "     IPC" } else { "" });
        let totals: Vec<i64> = by_process.iter().map(Tally::total).collect();
        write_row(out, "(all)", &totals, width, ipc);
        let sort_by = by_process.get(cycles.filter(|_| ipc.is_some()).unwrap_or(0));
        for (label, _) in sort_by.map(|tally| tally.largest(10)).unwrap_or_default() {
            let values: Vec<i64> = by_process.iter().map(|tally| tally.get(label)).collect();
            write_row(out, label, &values, width, ipc);
        }
    }
}

fn write_row(out: &mut Out, label: &str, values: &[i64], width: usize, ipc: Option<(usize, usize)>) {
    let mut row = String::new();
    for &value in values {
        row.push(' ');
        row.push_str(&pad_left(&text::count(value), width));
    }

    if let Some((instructions, cycles)) = ipc {
        let instructions = values.get(instructions).copied().unwrap_or(0);
        let cycles = values.get(cycles).copied().unwrap_or(0);
        let ipc = if cycles == 0 { "-".to_owned() } else { text::fixed(instructions as f64 / cycles as f64, 2) };
        row.push_str(&pad_left(&ipc, 8));
    }

    outln!(out, "{row}  {label}");
}

fn parse_counter_names(payload: &[u8]) -> Vec<String> {
    let count = match payload {
        [a, b, c, d, ..] => usize::try_from(i32::from_le_bytes([*a, *b, *c, *d]).clamp(0, 16)).unwrap_or(0),
        _ => 0,
    };
    let mut names = Vec::with_capacity(count);
    let mut offset = 4usize;
    while names.len() < count && offset.saturating_add(1) < payload.len() {
        let units: Vec<u16> = payload
            .get(offset..)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .take_while(|&unit| unit != 0)
            .collect();
        offset = offset.saturating_add(units.len().saturating_mul(2)).saturating_add(2);
        names.push(String::from_utf16_lossy(&units));
    }

    names
}
