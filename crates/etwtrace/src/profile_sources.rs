//! The machine's profile sources: what ETW calls the hardware counters (plus the SampledProfile timer).  Each has an ID
//! and a system-wide interval, the number of events between overflow samples.  The interval settings outlive sessions,
//! so 'record' and 'probe' put them back afterwards.

use crate::AppError;
use crate::hash::FxMap;
use crate::pmc;
use crate::text;

/// The ID of the SampledProfile clock (ProfileTime), the only source whose interval is in 100ns units.  (TimerFixed
/// reports the same interval limits, but on an Intel CPU 'probe' shows it counting reference cycles.)
pub const TIMER_ID: i32 = 0;

#[derive(Clone, Debug)]
pub struct ProfileSource {
    pub id: i32,
    pub name: String,
    pub interval: i32,
    pub min_interval: i32,
    pub max_interval: i32,
}

/// The profile sources (TraceProfileSourceListInfo) with their current intervals, by ID.
pub fn all() -> Result<Vec<ProfileSource>, AppError> {
    let mut sources = Vec::new();
    for entry in pmc::query_profile_source_list()? {
        let interval = pmc::query_profile_interval(entry.id)?;
        sources.push(ProfileSource {
            id: entry.id,
            name: entry.name,
            interval,
            min_interval: entry.min_interval,
            max_interval: entry.max_interval,
        });
    }

    sources.sort_by_key(|source| source.id);
    Ok(sources)
}

/// The sources' names by ID, or none if they cannot be queried.  The names only label output, and they come from this
/// machine, so they can be wrong for a trace recorded on another kind of CPU.
pub fn names() -> FxMap<i32, String> {
    all().map(|sources| sources.into_iter().map(|source| (source.id, source.name)).collect()).unwrap_or_default()
}

pub fn name(names: &FxMap<i32, String>, id: i32) -> String {
    names.get(&id).cloned().unwrap_or_else(|| format!("Source{id}"))
}

pub fn describe_interval(id: i32, interval: i32) -> String {
    if id == TIMER_ID {
        format!("{} ms", text::ten_thousandths(interval))
    } else {
        format!("{} events", text::count(i64::from(interval)))
    }
}

/// A source by name (ignoring case) or ID.
pub fn find<'a>(sources: &'a [ProfileSource], name_or_id: &str) -> Result<&'a ProfileSource, AppError> {
    let by_name = sources.iter().find(|source| text::eq_ignore_case(&source.name, name_or_id));
    let by_id = || {
        let id: i32 = name_or_id.trim().parse().ok()?;
        sources.iter().find(|source| source.id == id)
    };
    by_name
        .or_else(by_id)
        .ok_or_else(|| AppError::new(format!("Unknown hardware counter '{name_or_id}'.  Run 'EtwTrace list' for the counters on this machine.")))
}

/// Sets the sampled sources and their intervals (what TraceEventProfileSources.Set does): each interval
/// (TraceSampledProfileIntervalInfo), then the list (TraceProfileSourceConfigInfo).
pub fn configure(sampled: &[(i32, i32)]) -> Result<(), AppError> {
    let _ = etw::system::enable_privilege("SeSystemProfilePrivilege");
    for &(id, interval) in sampled {
        pmc::set_profile_interval(id, interval)?;
    }

    let ids: Vec<i32> = sampled.iter().map(|&(id, _)| id).collect();
    pmc::set_profile_sources(&ids)?;
    Ok(())
}

/// Puts back the intervals that changed since `before` was read.
pub fn restore_intervals(before: &[ProfileSource]) {
    let restore = || -> Result<(), AppError> {
        let now: FxMap<i32, i32> = all()?.into_iter().map(|source| (source.id, source.interval)).collect();
        for source in before {
            if now.get(&source.id).is_some_and(|&interval| interval != source.interval) {
                pmc::set_profile_interval(source.id, source.interval)?;
            }
        }

        Ok(())
    };
    if let Err(e) = restore() {
        crate::say!("WARNING: could not restore the profile source intervals: {e}");
    }
}
