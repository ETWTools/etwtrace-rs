//! What the kernel session is asked for: the event groups (as TraceEvent's kernel keywords, turned into the session's
//! group masks), the events that get stacks, and what to print about them.

use crate::guids::{CSWITCH_OPCODE, IMAGE_LOAD_OPCODE, PMC_INTERRUPT_OPCODE, READY_THREAD_OPCODE, SAMPLED_PROFILE_OPCODE, START_OPCODE, VIRTUAL_ALLOC_OPCODE, VIRTUAL_FREE_OPCODE};
use crate::options::Options;

/// The kernel's event groups (EVENT_TRACE_GROUP_* in ntwmi.h).  A kernel event's hook ID is its group | its event type
/// (opcode), e.g. 0x0524 for CSwitch.  The group is the kernel's, which is not always that of the event's GUID: image
/// loads are hooked in the process group.
mod groups {
    pub const IO: u16 = 0x0100;
    pub const MEMORY: u16 = 0x0200;
    pub const PROCESS: u16 = 0x0300;
    pub const FILE: u16 = 0x0400;
    pub const THREAD: u16 = 0x0500;
    pub const REGISTRY: u16 = 0x0900;
    pub const PERF_INFO: u16 = 0x0F00;
    pub const OBJECT: u16 = 0x1100;
}

/// TraceEvent's KernelTraceEventParser.Keywords: the classic EVENT_TRACE_FLAG_* bits, plus bits TraceEvent made up for
/// groups that have no classic flag (they become group mask bits, see [`KernelConfig::group_masks`]).
pub mod keywords {
    pub const PROCESS: u32 = 0x0000_0001;
    pub const THREAD: u32 = 0x0000_0002;
    pub const IMAGE_LOAD: u32 = 0x0000_0004;
    pub const CONTEXT_SWITCH: u32 = 0x0000_0010;
    pub const DISK_IO: u32 = 0x0000_0100;
    pub const DISK_FILE_IO: u32 = 0x0000_0200;
    pub const DISK_IO_INIT: u32 = 0x0000_0400;
    pub const DISPATCHER: u32 = 0x0000_0800;
    pub const MEMORY: u32 = 0x0000_1000;
    pub const MEMORY_HARD_FAULTS: u32 = 0x0000_2000;
    pub const VIRTUAL_ALLOC: u32 = 0x0000_4000;
    pub const VA_MAP: u32 = 0x0000_8000;
    pub const NETWORK_TCPIP: u32 = 0x0001_0000;
    pub const REGISTRY: u32 = 0x0002_0000;
    pub const HANDLE: u32 = 0x0040_0000;
    pub const PROFILE: u32 = 0x0100_0000;
    pub const FILE_IO: u32 = 0x0200_0000;
    pub const FILE_IO_INIT: u32 = 0x0400_0000;
    pub const IO_QUEUE: u32 = 0x1000_0000;
    pub const THREAD_PRIORITY: u32 = 0x2000_0000;
    pub const REFERENCE_SET: u32 = 0x4000_0000;
    pub const PMC_PROFILE: u32 = 0x8000_0000;
    /// The made-up bits, which are not classic enable flags.
    pub const NON_OS: u32 = 0xf84c_0000;
}

/// PERFINFO_GROUPMASK.Masks[1] bits for memory info (WPR's MemoryInfo and MemoryInfoWS).
const PERF_MEMINFO: u32 = 0x0008_0000;
const PERF_MEMINFO_WS: u32 = 0x0080_0000;

pub struct KernelConfig {
    /// The keywords to enable.
    pub keywords: u32,
    /// The hook IDs of the events that get stacks.
    pub stacks: Vec<u16>,
    /// Bits to add to Masks[1] of the session's group mask.
    pub extra_group_mask1: u32,
    /// What is collected, and what gets stacks, for printing.
    pub events: Vec<String>,
    pub stack_names: Vec<String>,
}

impl KernelConfig {
    pub fn new(options: &Options, sampling: bool) -> Self {
        use keywords::*;

        let mut config = Self {
            keywords: 0,
            stacks: Vec::new(),
            extra_group_mask1: 0,
            events: Vec::new(),
            stack_names: Vec::new(),
        };

        // Always: WPR's ProcessThread, Loader, SampledProfile, CSwitch and ReadyThread, with stacks on the last three.
        let interval = options.cpu_sample_msec.to_string();
        config.add(
            PROCESS | THREAD | IMAGE_LOAD | PROFILE | CONTEXT_SWITCH | DISPATCHER,
            Some(&format!("ProcessThread, Loader, SampledProfile (every {interval} ms), CSwitch, ReadyThread")),
            Some("SampledProfile, CSwitch, ReadyThread"),
        );
        config.add_stacks(groups::PERF_INFO, &[SAMPLED_PROFILE_OPCODE]);
        config.add_stacks(groups::THREAD, &[CSWITCH_OPCODE, READY_THREAD_OPCODE]);

        if sampling {
            config.add(PMC_PROFILE, Some("PmcInterrupt"), Some("PmcInterrupt"));
            config.add_stacks(groups::PERF_INFO, &[PMC_INTERRUPT_OPCODE]);
        }

        config.add_creation_stacks(options);
        config.add_io(options);
        config.add_memory(options);
        if options.handle {
            config.add(HANDLE, Some("Handles"), Some("handle create, duplicate and close"));
            config.add_stacks(groups::OBJECT, &[0x20, 0x21, 0x22]);
        }

        config
    }

    /// The session's PERFINFO_GROUPMASK.
    pub fn group_masks(&self) -> [u32; 8] {
        group_masks(self.keywords, self.extra_group_mask1)
    }

    /// Process, thread and image load events are always on (they say what the other events belong to); these options
    /// add the stacks of whoever created the process or thread or loaded the image.
    fn add_creation_stacks(&mut self, options: &Options) {
        if options.process_stacks {
            self.add(0, None, Some("ProcessStart"));
            self.add_stacks(groups::PROCESS, &[START_OPCODE]);
        }

        if options.thread_stacks {
            self.add(keywords::THREAD, None, Some("ThreadStart"));
            self.add_stacks(groups::THREAD, &[START_OPCODE]);
        }

        if options.image_stacks {
            self.add(keywords::IMAGE_LOAD, None, Some("ImageLoad"));
            self.add_stacks(groups::PROCESS, &[IMAGE_LOAD_OPCODE]); // Image loads are hooked in the process group.
        }
    }

    fn add_io(&mut self, options: &Options) {
        use keywords::*;

        if options.file_io {
            // WPR's FileIO profile: FileIO and FileIOInit (with stacks on the operations), DiskIO and HardFaults.
            // DiskFileIO adds the file name events.
            self.add(FILE_IO | DISK_FILE_IO | DISK_IO | MEMORY_HARD_FAULTS | FILE_IO_INIT, Some("FileIO, DiskIO, HardFaults"), Some("file operations"));
            self.add_stacks(groups::FILE, &[0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4D]);
        }

        if options.disk_io {
            self.add(DISK_IO | DISK_FILE_IO | DISK_IO_INIT, Some("DiskIO"), Some("disk reads, writes and flushes when issued"));
            self.add_stacks(groups::IO, &[0x0C, 0x0D, 0x0F]);
        }

        if options.registry {
            self.add(REGISTRY, Some("Registry"), Some("registry operations"));
            self.add_stacks(groups::REGISTRY, &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x1A, 0x1B]);
        }

        if options.tcp_ip || options.udp {
            // The kernel has one switch for its TCP/IP and UDP events.
            self.add(NETWORK_TCPIP, Some("TcpIp, UdpIp"), None);
        }
    }

    fn add_memory(&mut self, options: &Options) {
        use keywords::*;

        if options.reference_set {
            // The ReferenceSet keyword turns on the reference set, footprint, memory info, session, VirtualAlloc and
            // VAMap groups, like WPR's ReferenceSet profile.
            self.add(MEMORY_HARD_FAULTS | REFERENCE_SET, Some("ReferenceSet"), Some("page accesses, VirtualAlloc"));
            self.add_stacks(groups::MEMORY, &[0x49, 0x4F, 0x76, 0x77, 0x78, 0x79, 0x82, 0x83, VIRTUAL_ALLOC_OPCODE, VIRTUAL_FREE_OPCODE]);
        }

        if options.virtual_alloc {
            self.add(VIRTUAL_ALLOC, Some("VirtualAlloc"), Some("VirtualAlloc, VirtualFree"));
            self.add_stacks(groups::MEMORY, &[VIRTUAL_ALLOC_OPCODE, VIRTUAL_FREE_OPCODE]);
        }

        if options.page_faults {
            // Transition, demand zero, copy on write, guard page and hard page faults and access violations, plus the
            // hard fault events, which say what file was read.
            self.add(MEMORY | MEMORY_HARD_FAULTS, Some("PageFaults, HardFaults"), Some("page faults"));
            self.add_stacks(groups::MEMORY, &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x20]);
        }

        if options.mem_info {
            // WPR's MemoryInfo and MemoryInfoWS: system and per process memory every half second.  No classic flag or
            // TraceEvent keyword turns these groups on (except as part of ReferenceSet), so they are group mask bits.
            self.extra_group_mask1 |= PERF_MEMINFO | PERF_MEMINFO_WS;
            self.events.push("MemInfo, MemInfoWS".to_owned());
        }
    }

    fn add(&mut self, keywords: u32, events: Option<&str>, stacks: Option<&str>) {
        self.keywords |= keywords;
        add_names(&mut self.events, events);
        add_names(&mut self.stack_names, stacks);
    }

    fn add_stacks(&mut self, group: u16, opcodes: &[u8]) {
        for &opcode in opcodes {
            let hook_id = group | u16::from(opcode);
            if !self.stacks.contains(&hook_id) {
                self.stacks.push(hook_id);
            }
        }
    }
}

/// Adds the comma separated names that are not in the list yet (options overlap, e.g. -fileio and -diskio).
fn add_names(list: &mut Vec<String>, names: Option<&str>) {
    for name in names.unwrap_or_default().split(", ").filter(|name| !name.is_empty()) {
        if !list.iter().any(|existing| existing == name) {
            list.push(name.to_owned());
        }
    }
}

/// A kernel session's PERFINFO_GROUPMASK, as TraceEvent computes it from keywords (PutEnableFlagsIntoExtensions), with
/// extra Masks[1] bits.  Mask 0 is the classic enable flags; Process and Thread are always on.
pub fn group_masks(enabled: u32, extra_mask1: u32) -> [u32; 8] {
    use keywords::*;

    let mut flags = enabled | PROCESS | THREAD;
    if flags & REFERENCE_SET != 0 {
        flags |= VA_MAP | VIRTUAL_ALLOC;
    }

    let mut mask1 = extra_mask1;
    if flags & PMC_PROFILE != 0 {
        mask1 |= 0x400;
    }

    if flags & PROFILE != 0 {
        mask1 |= 0x002;
    }

    if flags & REFERENCE_SET != 0 {
        mask1 |= 0x00C8_0029; // PERF_MEMORY, PERF_FOOTPRINT, PERF_MEMINFO, PERF_MEMINFO_WS, PERF_SESSION, PERF_REFSET
    }

    if flags & IO_QUEUE != 0 {
        mask1 |= 0x0100_0000;
    }

    if flags & THREAD_PRIORITY != 0 {
        mask1 |= 0x2000;
    }

    let mask4 = if flags & HANDLE != 0 { 0x40 } else { 0 }; // PERF_OB_HANDLE
    [flags & !NON_OS, mask1, 0, 0, mask4, 0, 0, 0]
}
