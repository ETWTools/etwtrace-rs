//! What TraceEvent's parsing state knows while it reads a trace, which the report's numbers depend on: the trace's
//! clock, each thread's process, and how kernel paths map to drive letters.

use crate::hash::FxMap;
use crate::text::{find_ignore_case, strip_prefix_ignore_case};

/// Relative times as TraceEvent computes them (TimeStampRelativeMSec): QPC ticks since the trace's header event.
pub struct Clock {
    start: i64,
    synced: bool,
    frequency: i64,
}

impl Clock {
    pub fn new(frequency: i64) -> Self {
        Self {
            start: 0,
            synced: false,
            frequency: frequency.max(1),
        }
    }

    /// The first header event's timestamp is the session start (in merged traces only the first counts).
    pub fn on_header(&mut self, timestamp: i64) {
        if !self.synced {
            self.start = self.start.wrapping_add(timestamp);
            self.synced = true;
        }
    }

    /// The timestamp, moved up to the session start if it is earlier.  Equal clamped timestamps are what make
    /// TraceEvent's relative times equal, which is how stacks are matched to their events.
    pub fn clamp(&self, timestamp: i64) -> i64 {
        timestamp.max(self.start)
    }

    pub fn relative_msec(&self, timestamp: i64) -> f64 {
        self.clamp(timestamp).wrapping_sub(self.start) as f64 * 1000.0 / self.frequency as f64
    }

    /// A duration in QPC ticks, in milliseconds.
    pub fn msec(&self, ticks: i64) -> f64 {
        ticks as f64 * 1000.0 / self.frequency as f64
    }
}

/// TraceEvent's thread to process map: thread starts (and the start rundown) say a thread's process from then on (the
/// last one wins), and for threads with no start, their end (or end rundown) says it for the time before.
#[derive(Default)]
pub struct ThreadProcesses {
    started: FxMap<i32, i32>,
    /// Per thread: (end time, process), sorted by end time, latest first.
    ended: FxMap<i32, Vec<(i64, i32)>>,
}

impl ThreadProcesses {
    pub fn on_start(&mut self, thread_id: i32, process_id: i32) {
        self.started.insert(thread_id, process_id);
    }

    pub fn on_end(&mut self, thread_id: i32, process_id: i32, timestamp: i64) {
        if self.started.contains_key(&thread_id) {
            return;
        }

        let ends = self.ended.entry(thread_id).or_default();
        match ends.iter().position(|&(time, _)| time <= timestamp) {
            Some(index) => match ends.get_mut(index) {
                Some(entry) if entry.0 == timestamp => entry.1 = process_id,
                _ => ends.insert(index, (timestamp, process_id)),
            },
            None => ends.push((timestamp, process_id)),
        }
    }

    /// The process of a thread at a time, or -1.
    pub fn process_of(&self, thread_id: i32, timestamp: i64) -> i32 {
        if timestamp >= 0
            && let Some(&process_id) = self.started.get(&thread_id)
        {
            return process_id;
        }

        // The first end at or after the time.
        self.ended.get(&thread_id).and_then(|ends| ends.iter().rev().find(|&&(end, _)| end >= timestamp)).map_or(-1, |&(_, process_id)| process_id)
    }
}

/// TraceEvent's KernelToUserDriveMapping: kernel paths (\Device\HarddiskVolume3\...) to user paths (C:\...).  The
/// mapping comes from the trace's volume mapping events if they come before the first path is mapped; otherwise it is
/// this machine's drives, and those events are consulted after them.
#[derive(Default)]
pub struct DriveMapping {
    prefixes: Vec<(String, String)>,
    system_drive: String,
}

impl DriveMapping {
    /// A SysConfig VolumeMapping event.
    pub fn add(&mut self, kernel_prefix: String, user_prefix: String) {
        self.prefixes.push((kernel_prefix, user_prefix));
    }

    /// A SysConfig SystemPaths event's Windows directory.
    pub fn add_system_drive(&mut self, windows: &str) {
        self.add("\\Windows\\".to_owned(), windows.to_owned());
        self.system_drive = windows.chars().take(2).collect();
    }

    /// The user path for a kernel path, into a reused buffer.
    pub fn map_to_user_into(&mut self, kernel_name: &str, user_name: &mut String) {
        if self.prefixes.is_empty() {
            self.add_local_drives();
        }

        user_name.clear();
        // Container paths come from the host, as \...\OS\Windows\... or \...\Files\Windows\...
        let container = find_ignore_case(kernel_name, "\\OS\\Windows\\")
            .map(|index| index.saturating_add(3))
            .or_else(|| find_ignore_case(kernel_name, "\\Files\\Windows\\").map(|index| index.saturating_add(6)));
        if let Some(windows) = container {
            user_name.push_str(&self.system_drive);
            user_name.push_str(kernel_name.get(windows..).unwrap_or(""));
            return;
        }

        for (kernel_prefix, user_prefix) in &self.prefixes {
            if let Some(rest) = strip_prefix_ignore_case(kernel_name, kernel_prefix) {
                user_name.push_str(user_prefix);
                user_name.push_str(rest);
                return;
            }
        }

        user_name.push_str(kernel_name);
    }

    /// PopulateFromLocalMachine.
    fn add_local_drives(&mut self) {
        self.add("\\??\\".to_owned(), String::new());
        self.add("\\SystemRoot\\".to_owned(), std::env::var("SystemRoot").unwrap_or_default() + "\\");
        let drives = etw::system::logical_drives();
        for (bit, letter) in ('A'..='Z').enumerate() {
            if drives.checked_shr(u32::try_from(bit).unwrap_or(u32::MAX)).unwrap_or(0) & 1 == 0 {
                continue;
            }

            let drive = format!("{letter}:");
            if let Some(device) = etw::system::query_dos_device(&drive) {
                self.add(device + "\\", drive + "\\");
            }
        }

        self.add("\\Device\\LanmanRedirector\\".to_owned(), "\\\\".to_owned());
        self.add("\\Device\\Mup\\".to_owned(), "\\\\".to_owned());
        let windows = std::env::var("windir").unwrap_or_default() + "\\";
        self.system_drive = windows.chars().take(2).collect();
        self.add("\\Windows\\".to_owned(), windows);
        self.add("\\\\".to_owned(), "\\\\".to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::ThreadProcesses;

    #[test]
    fn thread_processes_follow_trace_event() {
        let mut threads = ThreadProcesses::default();
        assert_eq!(threads.process_of(7, 100), -1);
        threads.on_end(7, 70, 500);
        threads.on_end(7, 71, 900);
        assert_eq!(threads.process_of(7, 100), 70);
        assert_eq!(threads.process_of(7, 600), 71);
        assert_eq!(threads.process_of(7, 901), -1);
        threads.on_start(7, 72);
        threads.on_end(7, 73, 1000);
        assert_eq!(threads.process_of(7, 100), 72);
    }
}
