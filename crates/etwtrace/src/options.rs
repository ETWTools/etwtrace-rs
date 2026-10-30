//! Command line options for 'probe' and 'record'.

use crate::AppError;

pub struct Options {
    pub output_file: String,
    pub sampled_counters: Vec<String>,
    pub counted_counters: Vec<String>,
    pub cpu_sample_msec: f32,
    pub seconds: u32,
    pub probe_interval: u32,

    // Switches.
    pub last_branch_records: bool,
    pub process_stacks: bool,
    pub thread_stacks: bool,
    pub image_stacks: bool,
    pub file_io: bool,
    pub disk_io: bool,
    pub registry: bool,
    pub tcp_ip: bool,
    pub udp: bool,
    pub dns: bool,
    pub reference_set: bool,
    pub virtual_alloc: bool,
    pub page_faults: bool,
    pub mem_info: bool,
    pub handle: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            output_file: "EtwTrace.etl".to_owned(),
            sampled_counters: Vec::new(),
            counted_counters: Vec::new(),
            cpu_sample_msec: 1.0,
            seconds: 0,
            probe_interval: 65536,
            last_branch_records: false,
            process_stacks: false,
            thread_stacks: false,
            image_stacks: false,
            file_io: false,
            disk_io: false,
            registry: false,
            tcp_ip: false,
            udp: false,
            dns: false,
            reference_set: false,
            virtual_alloc: false,
            page_faults: false,
            mem_info: false,
            handle: false,
        }
    }
}

impl Options {
    /// Parses the arguments after the command name.
    pub fn parse(args: &[String]) -> Result<Self, AppError> {
        let mut options = Self::default();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if options.set_switch(arg) {
                continue;
            }

            let mut value = || args.next().ok_or_else(|| AppError::new(format!("{arg} needs a value.")));
            match arg.to_uppercase().as_str() {
                "-O" => options.output_file.clone_from(value()?),
                "-PMC" => options.sampled_counters.extend(split_list(value()?)),
                "-COUNTERS" => options.counted_counters.extend(split_list(value()?)),
                "-CPUMS" => {
                    let text = value()?;
                    options.cpu_sample_msec = text.trim().parse().map_err(|_| AppError::new(format!("-cpums expects a number of milliseconds, not '{text}'.")))?;
                }
                "-SEC" => options.seconds = parse_count(value()?, "-sec")?,
                "-INTERVAL" => options.probe_interval = parse_count(value()?, "-interval")?,
                _ => {
                    return Err(AppError::new(format!("Unknown option '{arg}'.  Run EtwTrace with no arguments for help.")));
                }
            }
        }

        Ok(options)
    }

    fn set_switch(&mut self, arg: &str) -> bool {
        let switch = match arg.to_ascii_lowercase().as_str() {
            "-lbr" => &mut self.last_branch_records,
            "-process" => &mut self.process_stacks,
            "-thread" => &mut self.thread_stacks,
            "-image" => &mut self.image_stacks,
            "-fileio" => &mut self.file_io,
            "-diskio" => &mut self.disk_io,
            "-registry" => &mut self.registry,
            "-tcpip" => &mut self.tcp_ip,
            "-udp" => &mut self.udp,
            "-dns" => &mut self.dns,
            "-refset" => &mut self.reference_set,
            "-virtualalloc" => &mut self.virtual_alloc,
            "-pagefaults" => &mut self.page_faults,
            "-meminfo" => &mut self.mem_info,
            "-handle" => &mut self.handle,
            _ => return false,
        };
        *switch = true;
        true
    }
}

/// A non-negative integer option value.
pub fn parse_count(text: &str, what: &str) -> Result<u32, AppError> {
    text.trim()
        .parse::<i32>()
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| AppError::new(format!("{what} expects a non-negative integer, not '{text}'.")))
}

fn split_list(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(',').filter(|part| !part.is_empty()).map(str::to_owned)
}
