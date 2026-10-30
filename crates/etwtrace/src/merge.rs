//! Merging the session files into one trace with the OS relogger, adding what KernelTraceControl's merge adds so the
//! trace can be read on another machine (a port of BPerf's KernelTraceControlSupportCode and relogger callback):
//!
//! * Before the first event, the volume mapping: SysConfig SystemPaths and VolumeMapping events that map kernel paths
//!   (\Device\HarddiskVolume3\...) to drive letters, as on this machine.
//! * Before the first event of each kind, its schema (an EventMetadata event with its TRACE_EVENT_INFO), so events of
//!   providers whose manifest is not installed elsewhere still decode.
//! * Before each image event, the image's identity (ImageID: size, timestamp and original file name) and its PDB's
//!   (DbgID_RSDS: GUID, age and PDB name), read from the image file, so symbol servers can find the PDBs.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use etw::{EventRecord, Guid, NewEvent, RelogContext, RelogHandler};

use crate::AppError;
use crate::guids::{EVENT_METADATA, IMAGE, KERNEL_TRACE_CONTROL, SYS_CONFIG_EX};
use crate::hash::{FxMap, FxSet};
use crate::pe::{self, PeIdentity};
use crate::text::{file_name, strip_prefix_ignore_case};

pub fn merge(inputs: &[&Path], output: &Path) -> Result<(), AppError> {
    let mut merger = Merger::new();
    etw::relogger::relog(inputs, output, &mut merger)?;
    Ok(())
}

const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 = 0x0020;
const EVENT_HEADER_FLAG_64_BIT_HEADER: u16 = 0x0040;
const EVENT_HEADER_FLAG_CLASSIC_HEADER: u16 = 0x0100;

const SYSTEM_PATHS_OPCODE: u8 = 33;
const VOLUME_MAPPING_OPCODE: u8 = 35;
const IMAGE_ID_OPCODE: u8 = 0;
const DBG_ID_RSDS_OPCODE: u8 = 36;
const EVENT_METADATA_OPCODE: u8 = 32;

/// Image identity for one image file: its PE identity and the original file names to log it under.
struct ImageInfo {
    identity: PeIdentity,
    names: Vec<String>,
}

struct Merger {
    windows_directory: String,
    system_directory: String,
    /// Kernel path prefixes and what they map to, for the volume mapping events.
    volumes: Vec<(String, String)>,
    volumes_written: bool,
    metadata_written: FxSet<(Guid, u16, u8)>,
    images: FxMap<PathBuf, Option<Rc<ImageInfo>>>,
    payload: Vec<u8>,
}

impl Merger {
    fn new() -> Self {
        let windows_directory = etw::system::windows_directory().unwrap_or_default();
        let mut volumes = vec![("\\SystemRoot\\".to_owned(), format!("{windows_directory}\\"))];
        volumes.extend(etw::system::volume_devices());
        Self {
            system_directory: etw::system::system_directory().unwrap_or_default(),
            windows_directory,
            volumes,
            volumes_written: false,
            metadata_written: FxSet::default(),
            images: FxMap::default(),
            payload: Vec::new(),
        }
    }

    /// The SysConfig events TraceEvent and WPA map kernel paths with.
    fn write_volume_mapping(&mut self, event: &EventRecord<'_>, relog: &mut RelogContext<'_>) {
        let flags = classic_flags(event);
        let mut write = |opcode: u8, first: &str, second: &str, payload: &mut Vec<u8>| {
            payload.clear();
            push_utf16z(payload, first);
            push_utf16z(payload, second);
            relog.inject(&NewEvent {
                provider: SYS_CONFIG_EX,
                id: 0xFFFF,
                version: 0,
                level: 1,
                opcode,
                flags,
                timestamp: event.timestamp(),
                processor_index: 0,
                process_id: 0,
                thread_id: 0,
                payload,
            });
        };

        let mut payload = std::mem::take(&mut self.payload);
        write(SYSTEM_PATHS_OPCODE, &self.system_directory, &format!("{}\\", self.windows_directory), &mut payload);
        write(VOLUME_MAPPING_OPCODE, "\\??\\", "", &mut payload);
        for (device, path) in self.volumes.iter().filter(|(_, path)| !path.is_empty()) {
            write(VOLUME_MAPPING_OPCODE, device, path, &mut payload);
        }

        for (device, path) in [("\\Device\\LanmanRedirector\\", "\\\\"), ("\\Device\\Mup\\", "\\\\"), ("\\Device\\vmsmb\\", "\\\\?\\VMSMB\\"), ("\\\\", "\\\\")] {
            write(VOLUME_MAPPING_OPCODE, device, path, &mut payload);
        }

        self.payload = payload;
    }

    /// The event's schema, the first time its kind is seen.
    fn write_metadata(&mut self, event: &EventRecord<'_>, relog: &mut RelogContext<'_>) {
        let id = if event.is_classic() { u16::from(event.opcode()) } else { event.id() };
        if !self.metadata_written.insert((event.provider(), id, event.version())) {
            return;
        }

        if let Some(info) = event.metadata() {
            relog.inject(&NewEvent {
                provider: EVENT_METADATA,
                id: 0xFFFF,
                version: 0,
                level: 0,
                opcode: EVENT_METADATA_OPCODE,
                flags: classic_flags(event),
                timestamp: event.timestamp(),
                processor_index: event.processor_index(),
                process_id: event.process_id(),
                thread_id: event.thread_id(),
                payload: &info,
            });
        }
    }

    /// ImageID and DbgID_RSDS events for an image event.
    fn write_image_identity(&mut self, event: &EventRecord<'_>, relog: &mut RelogContext<'_>) {
        // Image_Load: ImageBase, ImageSize (pointers), ProcessId, CheckSum, TimeDateStamp, Reserved0, DefaultBase
        // (pointer), Reserved1-4, FileName.
        let data = event.user_data();
        let pointer: usize = if event.is_64_bit() { 8 } else { 4 };
        let process_id = read_u32(data, pointer.saturating_mul(2));
        let kernel_name = read_utf16z(data, pointer.saturating_mul(3).saturating_add(32));
        let path = match strip_prefix_ignore_case(&kernel_name, "\\SystemRoot") {
            Some(rest) => PathBuf::from(format!("{}{rest}", self.windows_directory)),
            None => PathBuf::from(format!("\\\\?\\GLOBALROOT{kernel_name}")),
        };

        let image = self.images.entry(path).or_insert_with_key(|path| read_image_info(path).map(Rc::new)).clone();
        let Some(image) = image else {
            return;
        };

        let image_base = data.get(..pointer).unwrap_or_default();
        let flags = classic_flags(event);
        for name in &image.names {
            // ImageID: ImageBase, ImageSize (pointer sized), ProcessId, TimeDateStamp, OriginalFileName.
            let mut payload = std::mem::take(&mut self.payload);
            payload.clear();
            payload.extend_from_slice(image_base);
            let size = u64::from(image.identity.size_of_image).to_le_bytes();
            payload.extend_from_slice(size.get(..pointer).unwrap_or_default());
            payload.extend_from_slice(&process_id.to_le_bytes());
            payload.extend_from_slice(&image.identity.time_date_stamp.to_le_bytes());
            push_utf16z(&mut payload, name);
            relog.inject(&self.image_event(event, IMAGE_ID_OPCODE, flags, process_id, &payload));

            if let Some(rsds) = &image.identity.rsds {
                // DbgID_RSDS: ImageBase, ProcessId, GUID, Age, PDB file name (ANSI).
                payload.clear();
                payload.extend_from_slice(image_base);
                payload.extend_from_slice(&process_id.to_le_bytes());
                payload.extend_from_slice(&rsds.guid);
                payload.extend_from_slice(&rsds.age.to_le_bytes());
                payload.extend_from_slice(&rsds.pdb_file_name);
                payload.push(0);
                relog.inject(&self.image_event(event, DBG_ID_RSDS_OPCODE, flags, process_id, &payload));
            }

            self.payload = payload;
        }
    }

    fn image_event<'p>(&self, event: &EventRecord<'_>, opcode: u8, flags: u16, process_id: u32, payload: &'p [u8]) -> NewEvent<'p> {
        NewEvent {
            provider: KERNEL_TRACE_CONTROL,
            id: 0xFFFF,
            version: 2,
            level: 1,
            opcode,
            flags,
            timestamp: event.timestamp(),
            processor_index: event.processor_index(),
            process_id,
            thread_id: event.thread_id(),
            payload,
        }
    }
}

impl RelogHandler for Merger {
    fn on_event(&mut self, event: &EventRecord<'_>, relog: &mut RelogContext<'_>) {
        if !self.volumes_written {
            self.write_volume_mapping(event, relog);
            self.volumes_written = true;
        }

        self.write_metadata(event, relog);
        if event.provider() == IMAGE && matches!(event.opcode(), 2 | 3 | 4 | 10) {
            self.write_image_identity(event, relog);
        }

        relog.keep();
    }
}

/// An image's identity and the names to log it under: the original file name (or internal name) of each language of
/// its version resource, else its file name.  Names without an extension get ".dll", and ".mui" is dropped.
fn read_image_info(path: &Path) -> Option<ImageInfo> {
    let identity = pe::read_identity(path)?;
    let path_text = path.to_string_lossy();
    let names: Vec<String> = match etw::system::file_version_names(path) {
        etw::system::VersionNames::Unreadable => return None,
        etw::system::VersionNames::Names(names) if !names.is_empty() => names.iter().map(|name| original_name(name.as_deref().unwrap_or(&path_text))).collect(),
        _ => vec![file_name(&path_text).to_owned()],
    };

    Some(ImageInfo { identity, names })
}

fn original_name(name: &str) -> String {
    let name = match name.rfind('.') {
        None => format!("{name}.dll"),
        Some(dot) if name.get(dot..).is_some_and(|extension| extension.eq_ignore_ascii_case(".mui")) => name.get(..dot).unwrap_or(name).to_owned(),
        Some(_) => name.to_owned(),
    };
    file_name(&name).to_owned()
}

/// Classic header flags with the event's pointer size.
fn classic_flags(event: &EventRecord<'_>) -> u16 {
    EVENT_HEADER_FLAG_CLASSIC_HEADER | if event.is_64_bit() { EVENT_HEADER_FLAG_64_BIT_HEADER } else { EVENT_HEADER_FLAG_32_BIT_HEADER }
}

fn push_utf16z(payload: &mut Vec<u8>, text: &str) {
    payload.extend(text.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes));
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    offset.checked_add(4).and_then(|end| data.get(offset..end)).and_then(|bytes| bytes.try_into().ok()).map_or(0, u32::from_le_bytes)
}

fn read_utf16z(data: &[u8], offset: usize) -> String {
    let units: Vec<u16> = data.get(offset..).unwrap_or_default().as_chunks::<2>().0.iter().map(|&pair| u16::from_le_bytes(pair)).take_while(|&unit| unit != 0).collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::original_name;

    #[test]
    fn original_names() {
        assert_eq!(original_name("ntdll.dll"), "ntdll.dll");
        assert_eq!(original_name("NTDLL"), "NTDLL.dll");
        assert_eq!(original_name("shell32.dll.mui"), "shell32.dll");
        assert_eq!(original_name(r"\\?\GLOBALROOT\Device\HarddiskVolume3\x\y.exe"), "y.exe");
    }
}
