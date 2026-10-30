//! Zeroed, 8-byte aligned buffers for Win32 structures that are followed by variable length data.

/// A zeroed buffer of `len` bytes, aligned for any Win32 structure (it is a `Vec<u64>` underneath).
pub(crate) struct AlignedBuffer {
    words: Vec<u64>,
    len: usize,
}

impl AlignedBuffer {
    pub(crate) fn new(len: usize) -> Self {
        Self { words: vec![0; len.div_ceil(8)], len }
    }

    /// A buffer holding a copy of `data`.
    pub(crate) fn from_bytes(data: &[u8]) -> Self {
        let mut buffer = Self::new(data.len());
        buffer.bytes_mut().copy_from_slice(data);
        buffer
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: the vector owns len.div_ceil(8) initialized u64s, which is at least `len` bytes, and u8 has no alignment
        // requirement.
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len) }
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        // SAFETY: as in bytes(), and the mutable borrow of self makes this the only reference to the bytes.
        unsafe { std::slice::from_raw_parts_mut(self.as_mut_ptr(), len) }
    }

    /// Copies `data` in at `offset`; returns false (and copies nothing) if it does not fit.
    pub(crate) fn write(&mut self, offset: usize, data: &[u8]) -> bool {
        let end = offset.checked_add(data.len());
        match end.and_then(|end| self.bytes_mut().get_mut(offset..end)) {
            Some(target) => {
                target.copy_from_slice(data);
                true
            }
            None => false,
        }
    }

    /// Copies a null terminated UTF-16 string in at `offset`; returns false if it does not fit.
    pub(crate) fn write_wide(&mut self, offset: usize, text: &[u16]) -> bool {
        let bytes: Vec<u8> = text.iter().flat_map(|c| c.to_le_bytes()).collect();
        self.write(offset, &bytes)
    }

    /// Reads the null terminated UTF-16 string at `offset` (at most `max_chars` units).
    pub(crate) fn wide_at(&self, offset: usize, max_chars: usize) -> String {
        let units: Vec<u16> = self
            .bytes()
            .get(offset..)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .take(max_chars)
            .map(|&pair| u16::from_le_bytes(pair))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }
}
