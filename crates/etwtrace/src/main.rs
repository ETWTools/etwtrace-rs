//! EtwTrace: a WPR-style recorder.
//!
//! 'record' always collects what a WPR profile with these elements collects:
//!
//! ```text
//!     <Keywords> ProcessThread Loader SampledProfile CSwitch ReadyThread </Keywords>
//!     <Stacks> SampledProfile CSwitch ReadyThread </Stacks>
//! ```
//!
//! and options add (KernelConfig has the kernel details):
//!
//! ```text
//!     -pmc       HardwareCounter/SampledCounters: PMC overflow sampling (the PMC profile group, stacks on PmcInterrupt)
//!     -lbr       HardwareCounter/LastBranch: the last branch records on every PmcInterrupt
//!     -counters  HardwareCounter/Counters with Events/CSwitch: counter values on every context switch
//!     -process, -thread, -image   stacks on process creation, thread creation and image loads
//!     -fileio    WPR's FileIO profile: FileIO, FileIOInit, DiskIO and HardFaults, with stacks on the file operations
//!     -diskio    DiskIO and DiskIOInit, with stacks on the init (issue) events
//!     -registry  Registry, with stacks
//!     -tcpip, -udp   the kernel's TCP/IP and UDP events (one kernel switch turns on both)
//!     -dns       Microsoft-Windows-DNS-Client, with stacks, in a second (user mode) session that is merged in
//!     -virtualalloc  VirtualAllocation, with stacks on VirtualAlloc and VirtualFree
//!     -pagefaults    all page faults and hard faults, with stacks
//!     -meminfo   MemoryInfo and MemoryInfoWS (group mask bits that have no classic enable flag)
//!     -handle    Handle, with stacks on create, duplicate and close
//!     -refset    WPR's ReferenceSet profile: ReferenceSet, FootPrint, MemoryInfo, MemoryInfoWS, Session,
//!                VirtualAllocation, VAMap and HardFaults, with stacks on page accesses and VirtualAlloc
//! ```
//!
//! The kernel session gets its group masks and its stack list (as hook IDs) in the enable flag extension when it starts,
//! so the events logged during the start rundown get stacks too.
//!
//! ETW identifies hardware counters by 'profile source' IDs ('EtwTrace list' prints them) and can use them in two ways,
//! which draw on the same small set of counter slots (TraceMaxPmcCounterQuery):
//!
//!   * Overflow sampling (-pmc).  The counter interrupts every Interval events and the kernel logs a PerfInfo/PMCSample
//!     ("PmcInterrupt") event with the instruction pointer.  Like other kernel events it can carry a stack, and with
//!     -lbr also the CPU's last branch records.  The sampled sources and their intervals are system-wide settings
//!     (TraceProfileSourceConfigInfo, TraceSampledProfileIntervalInfo) that take effect in a kernel session with the PMC
//!     profile group enabled.
//!   * Counting (-counters).  A session can have the raw values of some counters attached to every CSwitch event
//!     (TracePmcCounterListInfo + TracePmcEventListInfo) as EVENT_HEADER_EXT_TYPE_PMC_COUNTERS extended data.
//!
//! Not every combination fits: a source needs a free slot that can count its event (general purpose and fixed function
//! counters are separate slots), and the SampledProfile timer can take a slot too.  Sampled sources that do not fit are
//! skipped without an error, so 'record' checks the slot owners (TracePmcCounterOwners) and warns.
//!
//! All Win32 calls are in the etw crate; this crate has no unsafe code.  'report' decodes the events itself (see
//! report/), following TraceEvent's view of a trace so its numbers match TraceEvent's.

mod console;
mod guids;
mod hash;
mod kernel_config;
mod list;
mod merge;
mod options;
#[cfg(test)]
mod parity_tests;
mod pe;
mod pmc;
mod probe;
mod profile_sources;
mod record;
mod report;
mod sessions;
mod synthetic_load;
mod text;

use std::fmt;
use std::process::ExitCode;

use options::Options;

const USAGE: &str = r#"EtwTrace: a WPR-style recorder.  It records SampledProfile, CSwitch and ReadyThread with stacks
(plus the process, thread and image load events), and optionally hardware counters (PMC overflow
sampling, LBR, counts on context switches) and many more kernel events.  probe and record need
an elevated prompt.

  EtwTrace list
      Hardware counters this machine exposes, their interval limits, how many can be
      programmed at once, and which counter slots are in use.

  EtwTrace probe [-interval N]
      Turns each counter on for overflow sampling for a moment, under a synthetic load, and
      reports which ones deliver PmcInterrupt events.  Default interval 65536 events.

  EtwTrace record [-o File.etl] [-sec N] [-cpums N] [options]
      -o             Output file (default EtwTrace.etl).
      -sec           Stop after N seconds (default: when Enter or Ctrl+C is pressed).
      -cpums         SampledProfile (timer) interval in milliseconds (default 1).
    Hardware counters:
      -pmc Name[:Interval],...  Overflow sampling: a PmcInterrupt event, with a stack, every
                     Interval events of each counter (default: its current interval).  The OS
                     skips counters it has no free slot for; record warns about those.
      -lbr           Also log the CPU's last branch records on every PMC overflow.
      -counters Name,...  Attach these counters' values to every CSwitch event.
    Stacks on events that are always recorded:
      -process       Process creation.
      -thread        Thread creation.
      -image         Image (DLL and EXE) loads.
    More events (all with stacks, except network and memory info):
      -fileio        File I/O, plus disk I/O and hard faults (WPR's FileIO profile).
      -diskio        Disk I/O, with stacks where reads, writes and flushes are issued.
      -registry      Registry operations.
      -tcpip         TCP/IP sends, receives, connects, disconnects and retransmits.
      -udp           UDP sends and receives.  (The kernel logs TCP/IP and UDP together.)
      -dns           DNS client queries and responses (Microsoft-Windows-DNS-Client).
      -virtualalloc  VirtualAlloc and VirtualFree.
      -pagefaults    All page faults (transition, demand zero, copy on write, guard,
                     hard) and access violations, plus hard fault reads.
      -meminfo       System and per process memory every half second (no stacks).
      -handle        Handle creation, duplication and closing.
      -refset        Reference set: page accesses and virtual allocations (WPR's
                     ReferenceSet profile).  Big: every resident page is logged at start and stop.
      Kernel events use the NT Kernel Logger session, like PerfView and xperf.

  EtwTrace report File.etl
      Event counts and stack coverage, then a summary of each kind of event in the trace.

Examples:
  EtwTrace record -pmc BranchMispredictions:100000,LLCMisses:20000 -lbr -sec 10
  EtwTrace record -counters InstructionRetired,UnhaltedCoreCycles -fileio -tcpip -dns -sec 30
  EtwTrace record -process -image -diskio -registry -virtualalloc -handle -meminfo -sec 10"#;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(|command| command.to_uppercase()).unwrap_or_default();
    let rest = args.get(1..).unwrap_or_default();
    let result = match command.as_str() {
        "LIST" => list::run(),
        "PROBE" => Options::parse(rest).and_then(|options| probe::run(&options)),
        "RECORD" => Options::parse(rest).and_then(|options| record::run(&options)),
        "REPORT" if rest.len() == 1 => rest.first().map_or(Ok(()), |file| report::print(file)),
        _ => {
            console::error(USAGE);
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Errors carry messages meant for the user.
            console::error(&format!("Error: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// An error with a message for the user.
#[derive(Debug)]
pub struct AppError(String);

impl AppError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<etw::Error> for AppError {
    fn from(error: etw::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}
