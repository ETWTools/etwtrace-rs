//! Reading what identifies a PE image for symbol servers: its size and timestamp (the image's own key) and its
//! CodeView RSDS record (the PDB's GUID, age and file name).  Only the headers and the debug directory are read.

use std::fs::File;
use std::os::windows::fs::FileExt;
use std::path::Path;

/// What symbol servers know an image and its PDB by.
pub struct PeIdentity {
    pub size_of_image: u32,
    pub time_date_stamp: u32,
    pub rsds: Option<Rsds>,
}

/// A CodeView RSDS record: the PDB's signature GUID (as stored), age and file name (without the null).
pub struct Rsds {
    pub guid: [u8; 16],
    pub age: u32,
    pub pdb_file_name: Vec<u8>,
}

const MZ: u16 = 0x5A4D;
const PE: u32 = 0x0000_4550;
const PE32_MAGIC: u16 = 0x10B;
const PE32_PLUS_MAGIC: u16 = 0x20B;
const RSDS: u32 = 0x5344_5352;
const DEBUG_TYPE_CODEVIEW: u32 = 2;
const DEBUG_DIRECTORY_INDEX: usize = 6;
const HEADER_BYTES: usize = 4096;
const MAX_PDB_NAME: usize = 1024;

/// Reads the identity of the PE file, or None if it cannot be read or is not a PE image.
pub fn read_identity(path: &Path) -> Option<PeIdentity> {
    let file = File::open(path).ok()?;
    let mut headers = vec![0u8; HEADER_BYTES];
    let read = file.seek_read(&mut headers, 0).ok()?;
    headers.truncate(read);

    if u16_at(&headers, 0)? != MZ {
        return None;
    }

    let nt = usize::try_from(u32_at(&headers, 0x3C)?).ok()?;
    if u32_at(&headers, nt)? != PE {
        return None;
    }

    let file_header = nt.checked_add(4)?;
    let section_count = usize::from(u16_at(&headers, file_header.checked_add(2)?)?);
    let time_date_stamp = u32_at(&headers, file_header.checked_add(4)?)?;
    let optional_header_size = usize::from(u16_at(&headers, file_header.checked_add(16)?)?);
    let optional = file_header.checked_add(20)?;
    let size_of_image = u32_at(&headers, optional.checked_add(56)?)?;
    let directories = match u16_at(&headers, optional)? {
        PE32_MAGIC => optional.checked_add(96)?,
        PE32_PLUS_MAGIC => optional.checked_add(112)?,
        _ => return None,
    };

    let debug = directories.checked_add(DEBUG_DIRECTORY_INDEX.checked_mul(8)?)?;
    let debug_rva = u32_at(&headers, debug).unwrap_or(0);
    let debug_size = u32_at(&headers, debug.checked_add(4)?).unwrap_or(0);
    let sections = optional.checked_add(optional_header_size)?;
    let rsds = if debug_rva == 0 {
        None
    } else {
        file_offset(&file, &headers, sections, section_count, debug_rva).and_then(|offset| read_rsds(&file, offset, debug_size))
    };

    Some(PeIdentity { size_of_image, time_date_stamp, rsds })
}

/// The file offset of a relative virtual address, from the section table.
fn file_offset(file: &File, headers: &[u8], sections: usize, count: usize, rva: u32) -> Option<u64> {
    let table = read_bytes(file, headers, sections, count.checked_mul(40)?)?;
    table.as_chunks::<40>().0.iter().find_map(|section| {
        let virtual_size = u32_at(section, 8)?;
        let virtual_address = u32_at(section, 12)?;
        let raw_data = u32_at(section, 20)?;
        let within = rva.checked_sub(virtual_address).filter(|&delta| delta < virtual_size)?;
        u64::from(raw_data).checked_add(u64::from(within))
    })
}

/// The first CodeView debug directory entry's RSDS record, if it is one.
fn read_rsds(file: &File, directory: u64, size: u32) -> Option<Rsds> {
    let count = usize::try_from(size / 28).ok()?.min(64);
    let mut entries = vec![0u8; count.checked_mul(28)?];
    let read = file.seek_read(&mut entries, directory).ok()?;
    entries.truncate(read);
    let entry = entries.as_chunks::<28>().0.iter().find(|entry| u32_at(entry.as_slice(), 12) == Some(DEBUG_TYPE_CODEVIEW))?;
    let data = u64::from(u32_at(entry.as_slice(), 24)?);
    let mut record = vec![0u8; 24 + MAX_PDB_NAME];
    let read = file.seek_read(&mut record, data).ok()?;
    record.truncate(read);
    if u32_at(&record, 0)? != RSDS {
        return None;
    }

    let guid: [u8; 16] = record.get(4..20)?.try_into().ok()?;
    let age = u32_at(&record, 20)?;
    let name = record.get(24..)?;
    let end = name.iter().position(|&b| b == 0)?;
    Some(Rsds {
        guid,
        age,
        pdb_file_name: name.get(..end)?.to_vec(),
    })
}

/// Bytes at a file offset, from the headers already read if they are there.
fn read_bytes(file: &File, headers: &[u8], offset: usize, length: usize) -> Option<Vec<u8>> {
    if let Some(bytes) = offset.checked_add(length).and_then(|end| headers.get(offset..end)) {
        return Some(bytes.to_vec());
    }

    let mut bytes = vec![0u8; length];
    let read = file.seek_read(&mut bytes, u64::try_from(offset).ok()?).ok()?;
    (read == length).then_some(bytes)
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_own_identity() {
        let exe = std::env::current_exe().unwrap();
        let identity = super::read_identity(&exe).unwrap();
        assert!(identity.size_of_image > 0);
        let rsds = identity.rsds.unwrap();
        assert!(String::from_utf8_lossy(&rsds.pdb_file_name).ends_with(".pdb"));
    }
}
