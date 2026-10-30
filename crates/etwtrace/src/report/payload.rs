//! Reading fields of an event's payload.  Offsets follow TraceEvent's, written as the 32-bit offset plus the number of
//! pointer-sized fields before the field (`host`).  Reads past the end return 0 (or an empty string) rather than
//! garbage, which is what TraceEvent reads there.

#[derive(Clone, Copy)]
pub struct Payload<'a> {
    data: &'a [u8],
    pointer_size: usize,
}

impl<'a> Payload<'a> {
    pub fn new(data: &'a [u8], pointer_size: usize) -> Self {
        Self { data, pointer_size }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    /// TraceEvent's HostOffset: the 32-bit layout's offset, moved by 4 bytes per pointer-sized field before it on 64-bit.
    pub fn host(&self, offset: usize, pointers: usize) -> usize {
        offset.saturating_add(self.pointer_size.saturating_sub(4).saturating_mul(pointers))
    }

    pub fn array<const N: usize>(&self, offset: usize) -> [u8; N] {
        offset.checked_add(N).and_then(|end| self.data.get(offset..end)).and_then(|bytes| bytes.try_into().ok()).unwrap_or([0; N])
    }

    pub fn u8(&self, offset: usize) -> u8 {
        self.data.get(offset).copied().unwrap_or(0)
    }

    pub fn i16(&self, offset: usize) -> i16 {
        i16::from_le_bytes(self.array(offset))
    }

    pub fn i32(&self, offset: usize) -> i32 {
        i32::from_le_bytes(self.array(offset))
    }

    pub fn u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.array(offset))
    }

    pub fn i64(&self, offset: usize) -> i64 {
        i64::from_le_bytes(self.array(offset))
    }

    pub fn u64(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.array(offset))
    }

    /// GetAddressAt: a pointer-sized field, zero extended.
    pub fn pointer(&self, offset: usize) -> u64 {
        if self.pointer_size == 8 { self.u64(offset) } else { u64::from(self.u32(offset)) }
    }

    /// The UTF-16 code units from `offset` up to a null (or the end).
    pub fn utf16_units(&self, offset: usize) -> impl Iterator<Item = u16> + 'a {
        self.data.get(offset..).unwrap_or_default().as_chunks::<2>().0.iter().map(|&pair| u16::from_le_bytes(pair)).take_while(|&unit| unit != 0)
    }

    /// A null terminated UTF-16 string (unpaired surrogates become U+FFFD).
    pub fn utf16(&self, offset: usize) -> String {
        let mut text = String::with_capacity(self.utf16_units(offset).count());
        self.utf16_into(offset, &mut text);
        text
    }

    /// A null terminated UTF-16 string, into a reused buffer.
    pub fn utf16_into(&self, offset: usize, text: &mut String) {
        text.clear();
        text.extend(char::decode_utf16(self.utf16_units(offset)).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)));
    }

    /// GetUTF8StringAt: a null terminated UTF-8 (in practice ANSI) string; TraceEvent's marker if it starts past the end.
    pub fn utf8(&self, offset: usize) -> String {
        if offset >= self.data.len() {
            return "<<ERROR EOB>>".to_owned();
        }

        let bytes = self.data.get(offset..).unwrap_or_default();
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned()
    }

    /// SkipUTF8String: the offset just past a null terminated byte string.
    pub fn skip_utf8(&self, offset: usize) -> usize {
        let length = self.data.get(offset..).unwrap_or_default().iter().take_while(|&&b| b != 0).count();
        offset.saturating_add(length).saturating_add(1)
    }

    /// SkipUnicodeString: the offset just past a null terminated UTF-16 string.
    pub fn skip_utf16(&self, offset: usize) -> usize {
        let units = self.utf16_units(offset).count();
        offset.saturating_add(units.saturating_mul(2)).saturating_add(2)
    }

    /// SkipSID: the offset just past a security identifier (4 zero bytes, or a TOKEN_USER and the SID).
    pub fn skip_sid(&self, offset: usize) -> usize {
        if self.i32(offset) == 0 {
            return offset.saturating_add(4);
        }

        let token_size = self.host(8, 2);
        let authorities = usize::from(self.u8(offset.saturating_add(token_size).saturating_add(1)));
        offset.saturating_add(token_size).saturating_add(8).saturating_add(authorities.saturating_mul(4))
    }
}
