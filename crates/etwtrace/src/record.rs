//! 'record': records the trace described at the top of main.rs, merges the session files into one ETL file (adding
//! image identity, volume mapping and event metadata so symbols resolve and events decode on other machines), and
//! prints its report.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use etw::system::CtrlC;

use crate::guids::DNS_CLIENT;
use crate::kernel_config::KernelConfig;
use crate::options::{self, Options};
use crate::pmc::{self, OwnerType};
use crate::profile_sources::{self, ProfileSource, TIMER_ID};
use crate::sessions::{self, Session};
use crate::{AppError, merge, report, say};

/// The user mode session that collects the DNS client events (a kernel session cannot have user mode providers).
const USER_SESSION_NAME: &str = "EtwTrace";

/// What 'record' was asked to collect, and where the session files go before they are merged.
struct RecordingPlan<'a> {
    options: &'a Options,
    sampled: Vec<(&'a ProfileSource, i32)>,
    counted: Vec<&'a ProfileSource>,
    max_counters: i32,
    output_file: PathBuf,
    kernel_file: PathBuf,
    user_file: PathBuf,
}

pub fn run(options: &Options) -> Result<(), AppError> {
    sessions::require_elevated_and_kernel_logger_free()?;
    let sources = profile_sources::all()?;
    let sampled = parse_sampled_counters(&options.sampled_counters, &sources)?;
    let counted = options.counted_counters.iter().map(|name| profile_sources::find(&sources, name)).collect::<Result<Vec<_>, _>>()?;
    let max_counters = pmc::query_max_pmc_counters();
    validate(options, sampled.len(), counted.len(), max_counters)?;

    let output_file = std::path::absolute(&options.output_file)?;
    let plan = RecordingPlan {
        options,
        sampled,
        counted,
        max_counters,
        kernel_file: output_file.with_extension("kernel.etl"),
        user_file: output_file.with_extension("user.etl"),
        output_file,
    };

    // Overflow sampling is configured system-wide and applies to kernel sessions with the PMC profile group.
    let mut result = if plan.sampled.is_empty() {
        Ok(())
    } else {
        let sampled: Vec<(i32, i32)> = plan.sampled.iter().map(|(source, interval)| (source.id, *interval)).collect();
        profile_sources::configure(&sampled)
    };
    if result.is_ok() {
        result = run_sessions(&plan);
    }

    profile_sources::restore_intervals(&sources);
    if let Err(e) = result {
        // Do not leave partial traces behind.
        let _ = std::fs::remove_file(&plan.kernel_file);
        let _ = std::fs::remove_file(&plan.user_file);
        return Err(e);
    }

    say!("Merging the session files and image identity (so symbols resolve on any machine)...");
    let mut inputs: Vec<&Path> = vec![&plan.kernel_file];
    if options.dns {
        inputs.push(&plan.user_file);
    }

    let _ = std::fs::remove_file(&plan.output_file);
    merge::merge(&inputs, &plan.output_file)?;
    for input in inputs {
        let _ = std::fs::remove_file(input);
    }

    say!();
    report::print(&plan.output_file.to_string_lossy())
}

fn parse_sampled_counters<'a>(specs: &[String], sources: &'a [ProfileSource]) -> Result<Vec<(&'a ProfileSource, i32)>, AppError> {
    let mut sampled = Vec::new();
    for spec in specs {
        let mut parts = spec.split(':');
        let source = profile_sources::find(sources, parts.next().unwrap_or_default())?;
        if source.id == TIMER_ID {
            return Err(AppError::new("Timer is the SampledProfile clock, which is always on; set its interval with -cpums."));
        }

        let interval = match parts.next() {
            Some(text) => i32::try_from(options::parse_count(text, "-pmc interval")?).unwrap_or(i32::MAX),
            None => source.interval,
        };
        if interval < source.min_interval || source.max_interval < interval {
            return Err(AppError::new(format!("The interval for {} must be between {} and {}.", source.name, source.min_interval, source.max_interval)));
        }

        sampled.push((source, interval));
    }

    Ok(sampled)
}

fn validate(options: &Options, sampled: usize, counted: usize, max_counters: i32) -> Result<(), AppError> {
    let requested = i32::try_from(sampled.saturating_add(counted)).unwrap_or(i32::MAX);
    if 0 < max_counters && max_counters < requested {
        return Err(AppError::new(format!("At most {max_counters} counters can be used at once (-pmc and -counters together).")));
    }

    if options.last_branch_records && sampled == 0 {
        return Err(AppError::new("-lbr captures branches on PMC overflow, so it needs -pmc."));
    }

    if options.seconds == 0 && !std::io::stdin().is_terminal() {
        return Err(AppError::new("Input is redirected, so use -sec to say how long to record."));
    }

    Ok(())
}

fn run_sessions(plan: &RecordingPlan<'_>) -> Result<(), AppError> {
    let options = plan.options;
    let config = KernelConfig::new(options, !plan.sampled.is_empty());
    let user_session = if options.dns { Some(start_dns_session(&plan.user_file)?) } else { None };

    // Reference set tracing logs every resident page when it starts, and page faults can come by the million each
    // second, faster than 256 MB of buffers drain to disk.
    let buffer_mb = if options.reference_set || options.page_faults { 1024 } else { 256 };
    let kernel_session = sessions::start_kernel(Some(&plan.kernel_file), buffer_mb, config.group_masks(), &config.stacks, options.cpu_sample_msec)?;
    if options.last_branch_records {
        pmc::configure_lbr(kernel_session.handle, 0, &[pmc::LBR_ON_PMC_INTERRUPT])?;
    }

    if !plan.counted.is_empty() {
        count_on_context_switch(&kernel_session, &plan.counted)?;
    }

    print_configuration(plan, &config);
    warn_about_counters_without_slots(plan);
    wait_for_stop(options.seconds);
    // The merged trace spans the kernel session (the relogger takes its time span from its first input), so the DNS
    // session stops first, leaving no DNS events after the kernel session's end.
    drop(user_session);
    drop(kernel_session);
    Ok(())
}

fn start_dns_session(user_file: &Path) -> Result<Session, AppError> {
    let session = sessions::start_user(USER_SESSION_NAME, user_file)?;
    etw::session::enable_provider(session.handle, DNS_CLIENT, 5, u64::MAX, 0, true)?;
    Ok(session)
}

fn count_on_context_switch(session: &Session, counted: &[&ProfileSource]) -> Result<(), AppError> {
    let ids: Vec<i32> = counted.iter().map(|source| source.id).collect();
    pmc::count_on_context_switch(session.handle, &ids).map_err(|e| {
        let names: Vec<&str> = counted.iter().map(|source| source.name.as_str()).collect();
        AppError::new(format!("Could not count {} on CSwitch: {e}  Free counter slots may have run out; see 'EtwTrace list'.", names.join(", ")))
    })
}

fn print_configuration(plan: &RecordingPlan<'_>, config: &KernelConfig) {
    let options = plan.options;
    let mut events = config.events.clone();
    let mut stacks = config.stack_names.clone();
    if options.dns {
        events.push(format!("DNS client (user mode session '{USER_SESSION_NAME}')"));
        stacks.push("DNS client".to_owned());
    }

    say!("Recording to {}", plan.output_file.display());
    say!("  Events: {}", events.join(", "));
    say!("  Stacks: {}", stacks.join(", "));
    for (source, interval) in &plan.sampled {
        say!(
            "  Overflow sampling: {} every {}{}",
            source.name,
            profile_sources::describe_interval(source.id, *interval),
            if options.last_branch_records { ", with LBR" } else { "" }
        );
    }

    if !plan.counted.is_empty() {
        let names: Vec<&str> = plan.counted.iter().map(|source| source.name.as_str()).collect();
        say!("  Counted on every CSwitch: {}", names.join(", "));
    }

    if options.reference_set {
        say!("  (Reference set tracing logs every resident page when it starts and stops, so the trace will be big.)");
    }
}

/// The OS quietly skips sampled sources it cannot place on a free counter (for example once the general purpose
/// counters run out; the SampledProfile timer can use one too), so look at the counter slots of processor 0 and warn
/// about requested sources that did not get one.
fn warn_about_counters_without_slots(plan: &RecordingPlan<'_>) {
    if plan.max_counters == 0 || !etw::system::enable_privilege("SeSystemProfilePrivilege") {
        return;
    }

    // Slot owners can only be queried on Windows 10 21H2 and later.
    let Ok(owners) = pmc::query_counter_owners(0, plan.max_counters) else {
        return;
    };

    let programmed: Vec<i32> = owners.iter().filter(|owner| owner.owner_type == OwnerType::TaggedWithSource).map(|owner| owner.profile_source).collect();
    let requested = plan.sampled.iter().map(|(source, _)| *source).chain(plan.counted.iter().copied());
    for source in requested {
        if !programmed.contains(&source.id) {
            say!("  WARNING: {} did not get a counter slot, so it is not being collected.  See 'EtwTrace list'.", source.name);
        }
    }
}

fn wait_for_stop(seconds: u32) {
    let ctrl_c = CtrlC::catch();
    let pressed = || ctrl_c.as_ref().is_some_and(CtrlC::pressed);
    if seconds > 0 {
        say!("Recording for {seconds} s (Ctrl+C stops early)...");
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(u64::from(seconds)) && !pressed() {
            std::thread::sleep(Duration::from_millis(50));
        }
    } else {
        say!("Recording... press Enter or Ctrl+C to stop.");
        let entered = Arc::new(AtomicBool::new(false));
        let reader_entered = Arc::clone(&entered);
        std::thread::spawn(move || {
            let _ = std::io::stdin().read_line(&mut String::new());
            reader_entered.store(true, Ordering::SeqCst);
        });
        while !entered.load(Ordering::SeqCst) && !pressed() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
