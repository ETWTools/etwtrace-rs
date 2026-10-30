//! The hardware counter and kernel session settings of TraceQueryInformation and TraceSetInformation, with their
//! buffers built and parsed here (the formats are documented next to TRACE_QUERY_INFO_CLASS in evntrace.h).

use etw::Guid;
use etw::session::{query_information, set_information};

use crate::AppError;
use crate::guids::{CSWITCH_OPCODE, THREAD};

// TRACE_QUERY_INFO_CLASS values.
const TRACE_SAMPLED_PROFILE_INTERVAL_INFO: i32 = 5; // Query and set: TRACE_PROFILE_INTERVAL (system-wide).
const TRACE_PROFILE_SOURCE_CONFIG_INFO: i32 = 6; // Set: ULONG[] sources to sample (system-wide).
const TRACE_PROFILE_SOURCE_LIST_INFO: i32 = 7; // Query: PROFILE_SOURCE_INFO chain.
const TRACE_PMC_EVENT_LIST_INFO: i32 = 8; // Set: CLASSIC_EVENT_ID[] that get counter values (once per session).
const TRACE_PMC_COUNTER_LIST_INFO: i32 = 9; // Set: ULONG[] sources read on those events (once per session).
const TRACE_LBR_CONFIGURATION_INFO: i32 = 20; // Set: ULONG LBR filter flags.
const TRACE_LBR_EVENT_LIST_INFO: i32 = 21; // Set: ULONG[] hook IDs that get the last branch records.
const TRACE_MAX_PMC_COUNTER_QUERY: i32 = 22; // Query: ULONG, counters that can be programmed at once (Win10 1903+).
const TRACE_PMC_COUNTER_OWNERS: i32 = 25; // Query: ETW_PMC_COUNTER_OWNERSHIP_STATUS of one processor (Win10 21H2+).
const TRACE_PMC_SESSION_INFORMATION: i32 = 27; // Query: ETW_PMC_SESSION_INFO chain (Win10 22H2+).

/// The hook ID LBR is collected on: PerfInfo PmcInterrupt (EVENT_TRACE_GROUP_PERFINFO | 0x2F).
pub const LBR_ON_PMC_INTERRUPT: u32 = 0x0F2F;

/// One entry of the PROFILE_SOURCE_INFO chain.
pub struct ProfileSourceEntry {
    pub id: i32,
    pub name: String,
    pub min_interval: i32,
    pub max_interval: i32,
}

/// Who holds a counter slot (ETW_PMC_COUNTER_OWNER_TYPE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerType {
    Free,
    Untagged,
    Tagged,
    TaggedWithSource,
    Other(i32),
}

/// One counter slot of one processor (ETW_PMC_COUNTER_OWNER).
#[derive(Clone, Copy, Debug)]
pub struct CounterOwner {
    pub owner_type: OwnerType,
    pub profile_source: i32,
    pub owner_tag: u32,
}

impl CounterOwner {
    /// The owner tag as text: a four character, pool tag style value ('Etwp' for counters ETW reads on events, 'KPrf'
    /// for the kernel profiler's overflow sampling).
    pub fn tag(&self) -> String {
        self.owner_tag.to_le_bytes().iter().map(|&b| if (0x20..0x7F).contains(&b) { char::from(b) } else { '.' }).collect()
    }
}

/// One session's counting configuration (ETW_PMC_SESSION_INFO).
pub struct PmcSession {
    pub logger_id: u16,
    pub profile_sources: Vec<i32>,
    pub hook_ids: Vec<u16>,
}

pub fn query_profile_source_list() -> Result<Vec<ProfileSourceEntry>, AppError> {
    let (buffer, _) = query_information(0, TRACE_PROFILE_SOURCE_LIST_INFO, &[], 16 * 1024)?;
    let mut sources = Vec::new();
    let mut offset = 0usize;
    loop {
        let next = read_i32(&buffer, offset);
        let name: Vec<u16> = buffer
            .get(offset.saturating_add(24)..)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .take_while(|&unit| unit != 0)
            .collect();
        sources.push(ProfileSourceEntry {
            id: read_i32(&buffer, offset.saturating_add(4)),
            name: String::from_utf16_lossy(&name),
            min_interval: read_i32(&buffer, offset.saturating_add(8)),
            max_interval: read_i32(&buffer, offset.saturating_add(12)),
        });
        match usize::try_from(next) {
            Ok(step) if step > 0 && offset.saturating_add(step) < buffer.len() => offset = offset.saturating_add(step),
            _ => break,
        }
    }

    Ok(sources)
}

/// A profile source's current (system-wide) interval.
pub fn query_profile_interval(source: i32) -> Result<i32, AppError> {
    let input = interval_bytes(source, 0);
    let (buffer, _) = query_information(0, TRACE_SAMPLED_PROFILE_INTERVAL_INFO, &input, input.len())?;
    Ok(read_i32(&buffer, 4))
}

/// Sets the system-wide interval of one profile source without changing which sources are sampled.  Needs
/// SeSystemProfilePrivilege.
pub fn set_profile_interval(source: i32, interval: i32) -> Result<(), AppError> {
    Ok(set_information(0, TRACE_SAMPLED_PROFILE_INTERVAL_INFO, &interval_bytes(source, interval))?)
}

/// Sets which profile sources are sampled (system-wide), for kernel sessions with the PMC profile group.
pub fn set_profile_sources(ids: &[i32]) -> Result<(), AppError> {
    Ok(set_information(0, TRACE_PROFILE_SOURCE_CONFIG_INFO, &int_bytes(ids))?)
}

/// How many counters ETW can program at once, or 0 if the OS does not say.
pub fn query_max_pmc_counters() -> i32 {
    query_information(0, TRACE_MAX_PMC_COUNTER_QUERY, &[], 4).map_or(0, |(buffer, _)| read_i32(&buffer, 0))
}

/// The owner of each counter slot of one processor.  Needs SeSystemProfilePrivilege.
pub fn query_counter_owners(processor: usize, max_counters: i32) -> Result<Vec<CounterOwner>, AppError> {
    // ETW_PMC_COUNTER_OWNERSHIP_STATUS: ULONG ProcessorNumber; ULONG NumberOfCounters; ETW_PMC_COUNTER_OWNER[].
    let max = usize::try_from(max_counters).unwrap_or(0);
    let mut input = vec![0u8; max.saturating_mul(12).saturating_add(8)];
    if let Some(number) = input.get_mut(..4) {
        number.copy_from_slice(&u32::try_from(processor).unwrap_or(u32::MAX).to_le_bytes());
    }

    let (buffer, _) = query_information(0, TRACE_PMC_COUNTER_OWNERS, &input, input.len())?;
    let count = usize::try_from(read_i32(&buffer, 4)).unwrap_or(0).min(max);
    Ok((0..count)
        .map(|slot| {
            let at = slot.saturating_mul(12).saturating_add(8);
            CounterOwner {
                owner_type: match read_i32(&buffer, at) {
                    0 => OwnerType::Free,
                    1 => OwnerType::Untagged,
                    2 => OwnerType::Tagged,
                    3 => OwnerType::TaggedWithSource,
                    other => OwnerType::Other(other),
                },
                profile_source: read_i32(&buffer, at.saturating_add(4)),
                owner_tag: read_i32(&buffer, at.saturating_add(8)) as u32,
            }
        })
        .collect())
}

/// The sessions that read counters on events, and what they read.
pub fn query_pmc_sessions() -> Result<Vec<PmcSession>, AppError> {
    // A chain of ETW_PMC_SESSION_INFO: ULONG NextEntryOffset; USHORT LoggerId; USHORT Reserved; ULONG
    // ProfileSourceCount; ULONG HookIdCount; ULONG ProfileSources[]; USHORT HookIds[].
    let (buffer, returned) = query_information(0, TRACE_PMC_SESSION_INFORMATION, &[], 4096)?;
    let mut sessions = Vec::new();
    let mut offset = 0usize;
    while returned > 0 && offset < buffer.len() {
        let source_count = usize::try_from(read_i32(&buffer, offset.saturating_add(8))).unwrap_or(0);
        let hook_count = usize::try_from(read_i32(&buffer, offset.saturating_add(12))).unwrap_or(0);
        let sources = offset.saturating_add(16);
        let hooks = sources.saturating_add(source_count.saturating_mul(4));
        sessions.push(PmcSession {
            logger_id: read_u16(&buffer, offset.saturating_add(4)),
            profile_sources: (0..source_count).map(|i| read_i32(&buffer, sources.saturating_add(i.saturating_mul(4)))).collect(),
            hook_ids: (0..hook_count).map(|i| read_u16(&buffer, hooks.saturating_add(i.saturating_mul(2)))).collect(),
        });
        match usize::try_from(read_i32(&buffer, offset)) {
            Ok(next) if next > 0 && offset.saturating_add(next) < buffer.len() => offset = offset.saturating_add(next),
            _ => break,
        }
    }

    Ok(sessions)
}

/// Attaches the values of the given counters to every CSwitch event of the session (WPR's HardwareCounter Counters and
/// Events).  ETW allows this only once per session.
pub fn count_on_context_switch(session: u64, sources: &[i32]) -> Result<(), etw::Error> {
    set_information(session, TRACE_PMC_COUNTER_LIST_INFO, &int_bytes(sources))?;
    set_information(session, TRACE_PMC_EVENT_LIST_INFO, &classic_event_ids(&[(THREAD, CSWITCH_OPCODE)]))
}

/// Turns on last branch recording for the session, on the given hook IDs.
pub fn configure_lbr(session: u64, filters: u32, hook_ids: &[u32]) -> Result<(), etw::Error> {
    set_information(session, TRACE_LBR_CONFIGURATION_INFO, &filters.to_le_bytes())?;
    let ids: Vec<u8> = hook_ids.iter().flat_map(|id| id.to_le_bytes()).collect();
    set_information(session, TRACE_LBR_EVENT_LIST_INFO, &ids)
}

/// CLASSIC_EVENT_ID[]: a GUID, then the event type and 7 reserved bytes.
fn classic_event_ids(events: &[(Guid, u8)]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(events.len().saturating_mul(24));
    for &(guid, opcode) in events {
        bytes.extend_from_slice(&guid.to_bytes());
        bytes.push(opcode);
        bytes.extend_from_slice(&[0; 7]);
    }

    bytes
}

/// TRACE_PROFILE_INTERVAL.
fn interval_bytes(source: i32, interval: i32) -> Vec<u8> {
    int_bytes(&[source, interval])
}

fn int_bytes(values: &[i32]) -> Vec<u8> {
    values.iter().flat_map(|value| value.to_le_bytes()).collect()
}

fn read_i32(buffer: &[u8], offset: usize) -> i32 {
    offset.checked_add(4).and_then(|end| buffer.get(offset..end)).and_then(|bytes| bytes.try_into().ok()).map_or(0, i32::from_le_bytes)
}

fn read_u16(buffer: &[u8], offset: usize) -> u16 {
    offset.checked_add(2).and_then(|end| buffer.get(offset..end)).and_then(|bytes| bytes.try_into().ok()).map_or(0, u16::from_le_bytes)
}
