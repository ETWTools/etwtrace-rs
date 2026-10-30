//! 'probe': for each profile source, a short real-time kernel session with only that source configured for overflow
//! sampling while this thread runs a synthetic load, counting the PmcInterrupt events that arrive.  Sources that deliver
//! none are tried again with LBR on, because some (e.g. LbrInserts) only count while LBR is active.

use std::time::Duration;

use etw::system::CtrlC;

use crate::guids::{PERF_INFO, PMC_INTERRUPT_OPCODE};
use crate::kernel_config::{group_masks, keywords};
use crate::options::Options;
use crate::profile_sources::{self, ProfileSource, TIMER_ID};
use crate::synthetic_load::SyntheticLoad;
use crate::text::{self, pad_left, pad_right};
use crate::{AppError, pmc, say, sessions};

/// How long each counter stays on.
const PROBE_MSEC: u64 = 250;

pub fn run(options: &Options) -> Result<(), AppError> {
    sessions::require_elevated_and_kernel_logger_free()?;
    let sources = profile_sources::all()?;
    let mut load = SyntheticLoad::new();

    say!("Overflow sampling probe: each counter alone for {PROBE_MSEC} ms of synthetic load (random pointer chasing");
    say!("over 64 MB with an unpredictable branch), one sample per {} events (1 ms for Timer).", text::count(i64::from(options.probe_interval)));
    say!();
    say!("   ID  Name                          PmcInterrupts");

    let ctrl_c = CtrlC::catch();
    for source in &sources {
        if ctrl_c.as_ref().is_some_and(CtrlC::pressed) {
            break;
        }

        probe_source(source, options.probe_interval, &mut load);
    }

    drop(ctrl_c);
    profile_sources::restore_intervals(&sources);
    Ok(())
}

fn probe_source(source: &ProfileSource, probe_interval: u32, load: &mut SyntheticLoad) {
    let interval = if source.id == TIMER_ID {
        10_000
    } else {
        i32::try_from(probe_interval).unwrap_or(i32::MAX).max(source.min_interval).min(source.max_interval)
    };

    let mut samples = 0;
    let result = (|| -> Result<&'static str, AppError> {
        samples = count_overflow_samples(source, interval, load, false)?;
        if samples > 0 {
            return Ok("overflow sampling works");
        }

        samples = count_overflow_samples(source, interval, load, true)?;
        Ok(if samples > 0 { "overflow sampling works only with -lbr" } else { "no overflow samples" })
    })();
    let result = result.map_or_else(|e| format!("failed: {e}"), str::to_owned);
    say!("  {}  {} {}  {result}", pad_left(&source.id.to_string(), 3), pad_right(&source.name, 28), pad_left(&text::count(samples), 13));
}

fn count_overflow_samples(source: &ProfileSource, interval: i32, load: &mut SyntheticLoad, lbr: bool) -> Result<i64, AppError> {
    profile_sources::configure(&[(source.id, interval)])?;
    let processors = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let buffer_mb = u32::try_from(processors.saturating_mul(2)).unwrap_or(u32::MAX).max(64);
    let session = sessions::start_kernel(None, buffer_mb, group_masks(keywords::PMC_PROFILE, 0), &[], 1.0)?;
    if lbr {
        pmc::configure_lbr(session.handle, 0, &[pmc::LBR_ON_PMC_INTERRUPT])?;
    }

    let id = source.id;
    let reader = std::thread::spawn(move || {
        let mut samples = 0i64;
        etw::consumer::process_session(etw::session::KERNEL_LOGGER_NAME, |record| {
            if record.provider() == PERF_INFO && record.opcode() == PMC_INTERRUPT_OPCODE {
                let offset: usize = if record.is_64_bit() { 12 } else { 8 };
                let source = record.user_data().get(offset..offset.saturating_add(2)).and_then(|bytes| bytes.try_into().ok()).map_or(0, i16::from_le_bytes);
                if i32::from(source) == id {
                    samples = samples.saturating_add(1);
                }
            }
        })
        .map(|()| samples)
    });

    load.run(Duration::from_millis(PROBE_MSEC));
    drop(session);
    match reader.join() {
        Ok(result) => Ok(result?),
        Err(_) => Err(AppError::new("the event reader thread failed")),
    }
}
