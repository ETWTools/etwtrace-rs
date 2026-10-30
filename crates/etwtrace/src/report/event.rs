//! What each event is, and the process and thread it belongs to.
//!
//! The process and thread IDs follow TraceEvent's, so the report's numbers match TraceEvent's: many kernel events
//! carry -1 in the header and have the IDs in the payload (TraceEvent's FixupData), and some only have a thread, whose
//! process TraceEvent looks up from the thread start and rundown events seen so far ([`ThreadProcesses`]).

use etw::EventRecord;

use super::payload::Payload;
use super::state::ThreadProcesses;
use crate::guids::{DISK_IO, DNS_CLIENT, EVENT_TRACE, FILE_IO, IMAGE, LAST_BRANCH, OBJECT, PAGE_FAULT, PERF_INFO, PROCESS, REGISTRY, STACK_WALK, SYS_CONFIG_EX, TCP_IP, THREAD, UDP_IP};

/// File I/O operations (FileIO events 64-77), in the order TraceEvent declares them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOp {
    Create,
    Cleanup,
    Close,
    Read,
    Write,
    SetInfo,
    Delete,
    Rename,
    DirEnum,
    Flush,
    QueryInfo,
    FsControl,
    DirNotify,
}

impl FileOp {
    pub const COUNT: usize = 13;

    pub fn name(self) -> &'static str {
        match self {
            Self::Create => "Create",
            Self::Cleanup => "Cleanup",
            Self::Close => "Close",
            Self::Read => "Read",
            Self::Write => "Write",
            Self::SetInfo => "SetInfo",
            Self::Delete => "Delete",
            Self::Rename => "Rename",
            Self::DirEnum => "DirEnum",
            Self::Flush => "Flush",
            Self::QueryInfo => "QueryInfo",
            Self::FsControl => "FSControl",
            Self::DirNotify => "DirNotify",
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }

    pub const ALL: [Self; Self::COUNT] = [
        Self::Create,
        Self::Cleanup,
        Self::Close,
        Self::Read,
        Self::Write,
        Self::SetInfo,
        Self::Delete,
        Self::Rename,
        Self::DirEnum,
        Self::Flush,
        Self::QueryInfo,
        Self::FsControl,
        Self::DirNotify,
    ];

    fn from_opcode(opcode: u8) -> Option<Self> {
        Some(match opcode {
            64 => Self::Create,
            65 => Self::Cleanup,
            66 => Self::Close,
            67 => Self::Read,
            68 => Self::Write,
            69 => Self::SetInfo,
            70 => Self::Delete,
            71 => Self::Rename,
            72 => Self::DirEnum,
            73 => Self::Flush,
            74 => Self::QueryInfo,
            75 => Self::FsControl,
            77 => Self::DirNotify,
            _ => return None,
        })
    }
}

/// TCP/IP events.  The `Other` kinds only matter for their process ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tcp {
    Send,
    Recv,
    Connect,
    Accept,
    Disconnect,
    Retransmit,
    Fail,
    OtherV4,
    SendV6,
    RecvV6,
    ConnectV6,
    AcceptV6,
    DisconnectV6,
    RetransmitV6,
    OtherV6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Udp {
    Send,
    Recv,
    Fail,
    SendV6,
    RecvV6,
}

/// The events the report reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    TraceHeader,
    ProcessStart,
    ProcessStop,
    ProcessDCStart,
    /// DCStop and Defunct: ProcessTraceData events the report does not read.
    ProcessOther,
    ThreadStart,
    ThreadStop,
    ThreadDCStart,
    ThreadDCStop,
    CSwitch,
    ReadyThread,
    ImageLoad,
    ImageUnload,
    ImageDCStart,
    ImageDCStop,
    SampledProfile,
    PmcSample,
    /// PerfInfo CollectionStart: a profile source's interval when the trace started.
    ProfileInterval,
    /// PerfInfo opcode 48: the names of the counters read on context switches.
    PmcCounterNames,
    StackWalk,
    LastBranches,
    DiskRead,
    DiskWrite,
    /// ReadInit, WriteInit and FlushInit: logged where the I/O is issued.
    DiskInit,
    DiskFlush,
    /// Registry operations (Create through Flush, Virtualize, Close).
    Registry,
    /// KCBCreate, KCBRundownBegin and KCBRundownEnd, which name a key control block.
    KcbName,
    KcbDelete,
    /// FileIO Name, FileCreate, FileDelete and FileRundown, which name a file key.
    FileName,
    FileOp(FileOp),
    Tcp(Tcp),
    Udp(Udp),
    /// Transition, demand zero, copy on write, guard page, hard page faults and access violations (opcodes 10-15).
    PageFault(u8),
    HardFault,
    VirtualAlloc,
    VirtualFree,
    /// PageAccess and PageAccessEx (opcodes 118 and 130).
    PageAccess,
    SystemMemInfo,
    ProcessMemInfo,
    HandleCreate,
    HandleClose,
    HandleDuplicate,
    ObjectTypeName,
    SystemPaths,
    VolumeMapping,
    Dns,
    Other,
}

impl Kind {
    pub fn of(record: &EventRecord<'_>) -> Self {
        let opcode = record.opcode();
        match record.provider() {
            EVENT_TRACE if opcode == 0 => Self::TraceHeader,
            PROCESS => match opcode {
                1 => Self::ProcessStart,
                2 => Self::ProcessStop,
                3 => Self::ProcessDCStart,
                4 | 39 => Self::ProcessOther,
                _ => Self::Other,
            },
            THREAD => match opcode {
                1 => Self::ThreadStart,
                2 => Self::ThreadStop,
                3 => Self::ThreadDCStart,
                4 => Self::ThreadDCStop,
                36 => Self::CSwitch,
                50 => Self::ReadyThread,
                _ => Self::Other,
            },
            IMAGE => match opcode {
                10 => Self::ImageLoad,
                2 => Self::ImageUnload,
                3 => Self::ImageDCStart,
                4 => Self::ImageDCStop,
                _ => Self::Other,
            },
            PERF_INFO => match opcode {
                46 => Self::SampledProfile,
                47 => Self::PmcSample,
                48 => Self::PmcCounterNames,
                73 => Self::ProfileInterval,
                _ => Self::Other,
            },
            STACK_WALK if opcode == 32 => Self::StackWalk,
            LAST_BRANCH if opcode == 32 => Self::LastBranches,
            DISK_IO => match opcode {
                10 => Self::DiskRead,
                11 => Self::DiskWrite,
                12 | 13 | 15 => Self::DiskInit,
                14 => Self::DiskFlush,
                _ => Self::Other,
            },
            REGISTRY => match opcode {
                10..=21 | 26 | 27 => Self::Registry,
                22 | 24 | 25 => Self::KcbName,
                23 => Self::KcbDelete,
                _ => Self::Other,
            },
            FILE_IO => match opcode {
                0 | 32 | 35 | 36 => Self::FileName,
                _ => FileOp::from_opcode(opcode).map_or(Self::Other, Self::FileOp),
            },
            TCP_IP => match opcode {
                10 => Self::Tcp(Tcp::Send),
                11 => Self::Tcp(Tcp::Recv),
                12 => Self::Tcp(Tcp::Connect),
                13 => Self::Tcp(Tcp::Disconnect),
                14 => Self::Tcp(Tcp::Retransmit),
                15 => Self::Tcp(Tcp::Accept),
                17 => Self::Tcp(Tcp::Fail),
                16 | 18..=22 => Self::Tcp(Tcp::OtherV4),
                26 => Self::Tcp(Tcp::SendV6),
                27 => Self::Tcp(Tcp::RecvV6),
                28 => Self::Tcp(Tcp::ConnectV6),
                29 => Self::Tcp(Tcp::DisconnectV6),
                30 => Self::Tcp(Tcp::RetransmitV6),
                31 => Self::Tcp(Tcp::AcceptV6),
                32 | 34 => Self::Tcp(Tcp::OtherV6),
                _ => Self::Other,
            },
            UDP_IP => match opcode {
                10 => Self::Udp(Udp::Send),
                11 => Self::Udp(Udp::Recv),
                17 => Self::Udp(Udp::Fail),
                26 => Self::Udp(Udp::SendV6),
                27 => Self::Udp(Udp::RecvV6),
                _ => Self::Other,
            },
            PAGE_FAULT => match opcode {
                10..=15 => Self::PageFault(opcode),
                32 => Self::HardFault,
                98 => Self::VirtualAlloc,
                99 => Self::VirtualFree,
                112 => Self::SystemMemInfo,
                118 | 130 => Self::PageAccess, // PageAccess and PageAccessEx, which TraceEvent reads alike.
                125 => Self::ProcessMemInfo,
                _ => Self::Other,
            },
            OBJECT => match opcode {
                32 => Self::HandleCreate,
                33 => Self::HandleClose,
                34 => Self::HandleDuplicate,
                37 => Self::ObjectTypeName,
                _ => Self::Other,
            },
            SYS_CONFIG_EX => match opcode {
                33 => Self::SystemPaths,
                35 => Self::VolumeMapping,
                _ => Self::Other,
            },
            DNS_CLIENT => Self::Dns,
            _ => Self::Other,
        }
    }
}

/// One event, identified and with TraceEvent's process and thread IDs.
pub struct Event<'a> {
    pub kind: Kind,
    pub record: EventRecord<'a>,
    pub payload: Payload<'a>,
    pub version: u8,
    pub opcode: u8,
    /// The raw QueryPerformanceCounter timestamp.
    pub timestamp: i64,
    pub processor: usize,
    /// -1 when TraceEvent would not know it.
    pub process_id: i32,
    pub thread_id: i32,
}

impl<'a> Event<'a> {
    pub fn new(kind: Kind, record: EventRecord<'a>, threads: &ThreadProcesses) -> Self {
        let pointer_size = if record.is_64_bit() { 8 } else { 4 };
        let mut event = Self {
            kind,
            record,
            payload: Payload::new(record.user_data(), pointer_size),
            version: record.version(),
            opcode: record.opcode(),
            timestamp: record.timestamp(),
            processor: usize::from(record.processor_index()),
            process_id: record.process_id() as i32,
            thread_id: record.thread_id() as i32,
        };
        event.fix_ids(threads);
        event
    }

    /// TraceEvent's FixupData for the event classes that have one.
    fn fix_ids(&mut self, threads: &ThreadProcesses) {
        let p = self.payload;
        let v = self.version;
        match self.kind {
            Kind::ProcessStart | Kind::ProcessStop | Kind::ProcessDCStart | Kind::ProcessOther => {
                self.process_id = p.i32(p.host(4, 1));
                self.thread_id = -1;
            }
            Kind::ThreadStart | Kind::ThreadDCStart | Kind::ThreadDCStop if v >= 2 => {
                // TraceEvent makes thread events look logged by the thread they are about (stops already are).
                self.thread_id = p.i32(4);
                self.process_id = p.i32(0);
            }
            Kind::CSwitch => {
                self.thread_from(p.i32(0));
                self.process_from(threads);
            }
            Kind::DiskRead | Kind::DiskWrite => {
                if self.thread_id == -1 && p.host(44, 2) <= p.len() {
                    self.thread_id = p.i32(p.host(40, 2));
                }

                self.process_from(threads);
            }
            Kind::DiskInit | Kind::DiskFlush => {
                if v >= 3 {
                    self.thread_from(p.i32(p.host(4, 1)));
                }

                self.process_from(threads);
            }
            Kind::FileOp(op) => {
                let thread_offset = match op {
                    FileOp::Create => {
                        if v <= 2 {
                            p.host(4, 1)
                        } else {
                            p.host(8, 2)
                        }
                    }
                    FileOp::Cleanup | FileOp::Close | FileOp::Flush => {
                        if v <= 2 {
                            p.host(4, 1)
                        } else {
                            p.host(12, 3)
                        }
                    }
                    FileOp::Read | FileOp::Write => {
                        if v <= 2 {
                            p.host(12, 1)
                        } else {
                            p.host(20, 3)
                        }
                    }
                    FileOp::SetInfo | FileOp::Delete | FileOp::Rename | FileOp::QueryInfo | FileOp::FsControl => {
                        if v <= 2 {
                            p.host(4, 1)
                        } else {
                            p.host(16, 4)
                        }
                    }
                    FileOp::DirEnum | FileOp::DirNotify => {
                        if v <= 2 {
                            p.host(4, 1)
                        } else {
                            p.host(12, 3)
                        }
                    }
                };
                self.thread_from(p.i32(thread_offset));
                self.process_from(threads);
            }
            Kind::HardFault => {
                self.thread_from(p.i32(p.host(0x18, 2)));
                self.process_from(threads);
            }
            Kind::SampledProfile | Kind::PmcSample => {
                self.thread_from(p.i32(p.host(4, 1)));
                self.process_from(threads);
            }
            Kind::StackWalk => {
                self.thread_from(p.i32(0xC));
                if self.process_id == -1 {
                    self.process_id = p.i32(8);
                }
            }
            Kind::Tcp(Tcp::Recv | Tcp::Disconnect | Tcp::Retransmit | Tcp::OtherV4) => {
                self.process_id = if v >= 1 { p.i32(0) } else { p.i32(16) };
            }
            Kind::Tcp(Tcp::Send | Tcp::Connect | Tcp::Accept | Tcp::SendV6 | Tcp::RecvV6 | Tcp::ConnectV6 | Tcp::AcceptV6 | Tcp::DisconnectV6 | Tcp::RetransmitV6 | Tcp::OtherV6) | Kind::Udp(Udp::SendV6 | Udp::RecvV6) => {
                self.process_id = p.i32(0)
            }
            Kind::Udp(Udp::Send | Udp::Recv) if v >= 1 => self.process_id = p.i32(0),
            Kind::ImageUnload | Kind::ImageDCStart | Kind::ImageDCStop => {
                self.thread_id = -1;
                if v >= 1 {
                    self.process_id = p.i32(p.host(8, 2));
                }
            }
            Kind::LastBranches => {
                self.process_id = p.i32(8);
                self.thread_id = p.i32(12);
            }
            _ => {}
        }
    }

    fn thread_from(&mut self, thread_id: i32) {
        if self.thread_id == -1 {
            self.thread_id = thread_id;
        }
    }

    fn process_from(&mut self, threads: &ThreadProcesses) {
        if self.process_id == -1 {
            self.process_id = threads.process_of(self.thread_id, self.timestamp);
        }
    }

    /// The extended data item of the given type, if the event has one.
    pub fn extended(&self, ext_type: u16) -> Option<&'a [u8]> {
        self.record.extended_data().find(|&(t, _)| t == ext_type).map(|(_, data)| data)
    }

    /// True if a stack is attached to the event itself (user mode providers' stacks).
    pub fn has_attached_stack(&self) -> bool {
        self.record.extended_data().any(|(t, _)| t == EXT_STACK_TRACE32 || t == EXT_STACK_TRACE64)
    }
}

pub const EXT_STACK_TRACE32: u16 = 5;
pub const EXT_STACK_TRACE64: u16 = 6;
pub const EXT_PMC_COUNTERS: u16 = 8;
