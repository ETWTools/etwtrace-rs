//! 'list': the hardware counters (profile sources) this machine exposes, how many can be programmed at once, which
//! counter slots are in use, and which sessions count PMCs on events.

use crate::hash::FxMap;
use crate::pmc::{self, CounterOwner, OwnerType};
use crate::profile_sources::{self, TIMER_ID};
use crate::text::{pad_left, pad_right};
use crate::{AppError, say};

pub fn run() -> Result<(), AppError> {
    let sources = profile_sources::all()?;
    let names: FxMap<i32, String> = sources.iter().map(|source| (source.id, source.name.clone())).collect();

    say!("Hardware counters (ETW profile sources).  Interval = counter events per overflow sample, except");
    say!("for Timer (the SampledProfile clock, see -cpums), whose interval is in 100ns units.");
    say!();
    say!("   ID  Name                            Interval        Min         Max  Unit");
    for source in &sources {
        say!(
            "  {}  {} {} {} {}  {}",
            pad_left(&source.id.to_string(), 3),
            pad_right(&source.name, 28),
            pad_left(&source.interval.to_string(), 11),
            pad_left(&source.min_interval.to_string(), 10),
            pad_left(&source.max_interval.to_string(), 11),
            if source.id == TIMER_ID { "100ns" } else { "events" }
        );
    }

    say!();
    let max_counters = pmc::query_max_pmc_counters();
    if max_counters > 0 {
        say!("At most {max_counters} counters can be programmed at once; -pmc and -counters share them.");
    } else {
        say!("This OS does not report how many counters can be programmed at once (Windows 10 1903+ does).");
    }

    // Slot owners and session information need SeSystemProfilePrivilege, which only elevated processes have.
    if max_counters == 0 || !etw::system::enable_privilege("SeSystemProfilePrivilege") {
        say!("Run elevated (on Windows 10 21H2+) to see which counter slots are in use.");
    } else {
        print_counter_owners(max_counters, &names)?;
        print_pmc_sessions(&names)?;
    }

    say!();
    say!("Run 'EtwTrace probe' to check which counters deliver overflow samples on this machine.");
    Ok(())
}

/// Who owns each counter slot, collapsing runs of processors whose slots are in the same state.
fn print_counter_owners(max_counters: i32, names: &FxMap<i32, String>) -> Result<(), AppError> {
    say!("Counter slots in use (TracePmcCounterOwners):");
    let processors = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let mut first = 0usize;
    let mut previous: Option<String> = None;
    for cpu in 0..=processors {
        let state = if cpu < processors { Some(describe_owners(&pmc::query_counter_owners(cpu, max_counters)?, names)) } else { None };
        if state != previous {
            if let Some(previous) = &previous {
                let last = cpu.saturating_sub(1);
                let cpus = if first == last { first.to_string() } else { format!("{first}-{last}") };
                say!("  CPU {cpus}: {previous}");
            }

            first = cpu;
            previous = state;
        }
    }

    Ok(())
}

fn describe_owners(owners: &[CounterOwner], names: &FxMap<i32, String>) -> String {
    let mut used = Vec::new();
    for (slot, owner) in owners.iter().enumerate() {
        let prefix = format!("slot {slot}");
        match owner.owner_type {
            OwnerType::Free => {}
            OwnerType::Untagged => used.push(format!("{prefix} in use (untagged owner)")),
            OwnerType::Tagged => used.push(format!("{prefix} in use by '{}'", owner.tag())),
            OwnerType::TaggedWithSource | OwnerType::Other(_) => {
                used.push(format!("{prefix} {} by '{}'", profile_sources::name(names, owner.profile_source), owner.tag()));
            }
        }
    }

    let free = owners.len().saturating_sub(used.len());
    if used.is_empty() { format!("all {free} free") } else { format!("{}; {free} free", used.join(", ")) }
}

fn print_pmc_sessions(names: &FxMap<i32, String>) -> Result<(), AppError> {
    let sessions = pmc::query_pmc_sessions()?;
    say!("Sessions counting PMCs on events (TracePmcSessionInformation): {}", if sessions.is_empty() { "none" } else { "" });
    for session in &sessions {
        let sources: Vec<String> = session.profile_sources.iter().map(|&id| profile_sources::name(names, id)).collect();
        let hooks: Vec<String> = session.hook_ids.iter().map(|&hook| hook_name(hook)).collect();
        say!("  {} (logger {}): {} on {}", session_name(session.logger_id), session.logger_id, sources.join(", "), hooks.join(", "));
    }

    Ok(())
}

/// Names the kernel event hook IDs (EVENT_TRACE_GROUP_* | opcode) that matter here.
fn hook_name(hook: u16) -> String {
    match hook {
        0x0524 => "CSwitch".to_owned(),
        0x0532 => "ReadyThread".to_owned(),
        0x0F2E => "SampledProfile".to_owned(),
        0x0F2F => "PmcInterrupt".to_owned(),
        other => format!("hook 0x{other:04x}"),
    }
}

fn session_name(logger_id: u16) -> String {
    if logger_id == 0 {
        return etw::session::KERNEL_LOGGER_NAME.to_owned(); // Logger 0 is always the NT Kernel Logger.
    }

    etw::session::active_session_names()
        .unwrap_or_default()
        .into_iter()
        .find(|name| etw::session::query_session(name).is_ok_and(|handle| handle & 0xFFFF == u64::from(logger_id)))
        .unwrap_or_else(|| "?".to_owned())
}
