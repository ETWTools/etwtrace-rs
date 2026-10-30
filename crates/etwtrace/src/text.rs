//! Text formatting that matches .NET formatting exactly: .NET's invariant "n0", "F", "N" and "0.###" number
//! formats, padding counted in UTF-16 code units (as .NET counts string length), ordinal (UTF-16) and
//! OrdinalIgnoreCase string comparison, Path.GetFileName and friends, and IPAddress.ToString.

use std::cmp::Ordering;
use std::fmt::Write;

/// "n0": the integer with ',' between groups of three digits.
pub fn count(value: i64) -> String {
    let digits = value.unsigned_abs().to_string();
    let mut text = String::with_capacity(digits.len().saturating_mul(2));
    if value < 0 {
        text.push('-');
    }

    push_grouped(&mut text, &digits);
    text
}

/// "F<decimals>": the number rounded to that many decimals.  .NET (Core 3.0+) and Rust both round the exact binary
/// value, with ties to even.
pub fn fixed(value: f64, decimals: usize) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }

    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }

    format!("{value:.decimals$}")
}

/// "N<decimals>": like [`fixed`], with ',' between groups of three digits in the integer part.
pub fn grouped(value: f64, decimals: usize) -> String {
    let plain = fixed(value, decimals);
    if !value.is_finite() {
        return plain;
    }

    let (sign, unsigned) = plain.strip_prefix('-').map_or(("", plain.as_str()), |rest| ("-", rest));
    let (integer, fraction) = unsigned.split_once('.').map_or((unsigned, None), |(i, f)| (i, Some(f)));
    let mut text = String::with_capacity(plain.len().saturating_mul(2));
    text.push_str(sign);
    push_grouped(&mut text, integer);
    if let Some(fraction) = fraction {
        text.push('.');
        text.push_str(fraction);
    }

    text
}

fn push_grouped(text: &mut String, digits: &str) {
    let len = digits.len();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && len.wrapping_sub(i).is_multiple_of(3) {
            text.push(',');
        }

        text.push(digit);
    }
}

/// Units.Bytes: bytes, or KB, MB or GB (powers of 1024), whichever keeps the number readable.
pub fn bytes(value: i64) -> String {
    const KB: f64 = 1024.0;
    let magnitude = (value as f64).abs();
    if magnitude < KB {
        return format!("{value} B");
    }

    let (divisor, unit) = if magnitude >= KB * KB * KB {
        (KB * KB * KB, " GB")
    } else if magnitude >= KB * KB {
        (KB * KB, " MB")
    } else {
        (KB, " KB")
    };
    grouped(value as f64 / divisor, 1) + unit
}

/// Units.Percent: "12.3%", or "-" when the whole is 0.
pub fn percent(part: i64, whole: i64) -> String {
    if whole == 0 {
        return "-".to_owned();
    }

    fixed(100.0 * part as f64 / whole as f64, 1) + "%"
}

/// Formats `interval / 10000.0` with .NET's "0.###": rounded half away from zero to three decimals (custom formats round
/// a 15 digit decimal, which for these values is exact), trailing zeros dropped.
pub fn ten_thousandths(interval: i32) -> String {
    let magnitude = interval.unsigned_abs();
    let thousandths = magnitude.saturating_add(5) / 10;
    let (whole, fraction) = (thousandths / 1000, thousandths % 1000);
    let mut text = String::new();
    if interval < 0 && thousandths != 0 {
        text.push('-');
    }

    let _ = write!(text, "{whole}");
    if fraction != 0 {
        let digits = format!("{fraction:03}");
        text.push('.');
        text.push_str(digits.trim_end_matches('0'));
    }

    text
}

/// The number of UTF-16 code units, which is what .NET pads and truncates by.
pub fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// `{text,width}`: right aligned in at least `width` UTF-16 units.
pub fn pad_left(text: &str, width: usize) -> String {
    let padding = width.saturating_sub(utf16_len(text));
    let mut padded = String::with_capacity(text.len().saturating_add(padding));
    padded.extend(std::iter::repeat_n(' ', padding));
    padded.push_str(text);
    padded
}

/// `{text,-width}`: left aligned in at least `width` UTF-16 units.
pub fn pad_right(text: &str, width: usize) -> String {
    let padding = width.saturating_sub(utf16_len(text));
    let mut padded = String::with_capacity(text.len().saturating_add(padding));
    padded.push_str(text);
    padded.extend(std::iter::repeat_n(' ', padding));
    padded
}

/// The first `max` UTF-16 units of the text (a split surrogate pair becomes U+FFFD, as .NET's '?' would).
pub fn truncate_utf16(text: &str, max: usize) -> String {
    let units: Vec<u16> = text.encode_utf16().take(max).collect();
    String::from_utf16_lossy(&units)
}

/// StringComparer.Ordinal: compares UTF-16 code units.
pub fn ordinal_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The character OrdinalIgnoreCase compares a character as: its simple (one character) upper case mapping.
pub fn fold_char(c: char) -> char {
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) => single,
        _ => c,
    }
}

/// A key that is equal for strings OrdinalIgnoreCase considers equal.
pub fn fold_case(text: &str) -> String {
    if text.is_ascii() {
        return text.to_ascii_uppercase();
    }

    text.chars().map(fold_char).collect()
}

/// `fold_case`, into a reused buffer.
pub fn fold_case_into(text: &str, folded: &mut String) {
    folded.clear();
    folded.extend(text.chars().map(fold_char));
}

/// `text.StartsWith(prefix, OrdinalIgnoreCase)`; returns the rest of `text` on a match.
pub fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let mut rest = text.char_indices();
    for expected in prefix.chars() {
        let (_, actual) = rest.next()?;
        if fold_char(actual) != fold_char(expected) {
            return None;
        }
    }

    Some(rest.next().map_or("", |(index, _)| text.get(index..).unwrap_or("")))
}

/// `text.IndexOf(pattern, OrdinalIgnoreCase)`, as a byte index.
pub fn find_ignore_case(text: &str, pattern: &str) -> Option<usize> {
    text.char_indices()
        .map(|(index, _)| index)
        .find(|&index| text.get(index..).is_some_and(|rest| strip_prefix_ignore_case(rest, pattern).is_some()))
}

/// `a.Equals(b, OrdinalIgnoreCase)`.
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.chars().map(fold_char).eq(b.chars().map(fold_char))
}

/// Path.GetFileName: the part after the last '\' or '/' (or after a drive's "C:" root).
pub fn file_name(path: &str) -> &str {
    if let Some(index) = path.rfind(['\\', '/']) {
        return path.get(index.saturating_add(1)..).unwrap_or("");
    }

    let bytes = path.as_bytes();
    if let [drive, b':', ..] = bytes
        && drive.is_ascii_alphabetic()
    {
        return path.get(2..).unwrap_or("");
    }

    path
}

/// Path.GetFileNameWithoutExtension.
pub fn file_name_without_extension(path: &str) -> &str {
    let name = file_name(path);
    name.rfind('.').map_or(name, |dot| name.get(..dot).unwrap_or(name))
}

/// IPAddress.ToString of an IPv4 address whose bytes are in network order.
pub fn ipv4(address: [u8; 4]) -> String {
    let [a, b, c, d] = address;
    format!("{a}.{b}.{c}.{d}")
}

/// IPAddress.ToString of an IPv6 address: RFC 5952 compression of the longest run of two or more zero groups (the
/// first, on a tie), lower case hex, and the last 32 bits as IPv4 for the forms .NET embeds it in.
pub fn ipv6(address: [u8; 16]) -> String {
    let mut groups = [0u16; 8];
    for (group, &pair) in groups.iter_mut().zip(address.as_chunks::<2>().0) {
        *group = u16::from_be_bytes(pair);
    }

    let mut text = String::with_capacity(48);
    if embeds_ipv4(&groups) {
        let [g0, g1, g2, g3, g4, g5, _, _] = groups;
        push_ipv6_groups(&mut text, &[g0, g1, g2, g3, g4, g5]);
        if !text.ends_with(':') {
            text.push(':');
        }

        let [.., a, b, c, d] = address;
        text.push_str(&ipv4([a, b, c, d]));
    } else {
        push_ipv6_groups(&mut text, &groups);
    }

    text
}

/// IPv6AddressHelper.ShouldHaveIpv4Embedded.
fn embeds_ipv4(groups: &[u16; 8]) -> bool {
    let [g0, g1, g2, g3, g4, g5, g6, _] = *groups;
    if g0 == 0 && g1 == 0 && g2 == 0 && g3 == 0 && g6 != 0 {
        if g4 == 0 && (g5 == 0 || g5 == 0xFFFF) {
            return true;
        }

        if g4 == 0xFFFF && g5 == 0 {
            return true;
        }
    }

    g4 == 0 && g5 == 0x5EFE
}

fn push_ipv6_groups(text: &mut String, groups: &[u16]) {
    // The longest run of zero groups (at least two; the first wins a tie) becomes "::".
    let (mut best_start, mut best_len, mut run_len) = (0usize, 0usize, 0usize);
    for (i, &group) in groups.iter().enumerate() {
        if group == 0 {
            run_len = run_len.saturating_add(1);
            if run_len > best_len {
                best_len = run_len;
                best_start = i.saturating_add(1).saturating_sub(run_len);
            }
        } else {
            run_len = 0;
        }
    }

    let compress = best_len > 1;
    let mut needs_colon = false;
    for (i, &group) in groups.iter().enumerate() {
        if compress && i >= best_start && i < best_start.saturating_add(best_len) {
            if i == best_start {
                text.push_str("::");
                needs_colon = false;
            }

            continue;
        }

        if needs_colon {
            text.push(':');
        }

        let _ = write!(text, "{group:x}");
        needs_colon = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values are .NET 10's output (InvariantCulture) for the same inputs.
    #[test]
    fn fixed_matches_dotnet() {
        let cases: &[(f64, &str, &str, &str, &str)] = &[
            (0.25, "0.2", "0.25", "0.250", "0"),
            (1.25, "1.2", "1.25", "1.250", "1"),
            (0.125, "0.1", "0.12", "0.125", "0"),
            (2.5, "2.5", "2.50", "2.500", "2"),
            (3.5, "3.5", "3.50", "3.500", "4"),
            (0.15, "0.1", "0.15", "0.150", "0"),
            (0.35, "0.3", "0.35", "0.350", "0"),
            (1.05, "1.1", "1.05", "1.050", "1"),
            (2.675, "2.7", "2.67", "2.675", "3"),
            (1.005, "1.0", "1.00", "1.005", "1"),
            (0.05, "0.1", "0.05", "0.050", "0"),
            (0.45, "0.5", "0.45", "0.450", "0"),
            (99.95, "100.0", "99.95", "99.950", "100"),
            (99.85, "99.8", "99.85", "99.850", "100"),
            (0.0005, "0.0", "0.00", "0.001", "0"),
            (0.0015, "0.0", "0.00", "0.002", "0"),
            (12.345, "12.3", "12.35", "12.345", "12"),
            (0.375, "0.4", "0.38", "0.375", "0"),
            (7.125, "7.1", "7.12", "7.125", "7"),
            (-0.25, "-0.2", "-0.25", "-0.250", "-0"),
            (0.95, "0.9", "0.95", "0.950", "1"),
            (9.995, "10.0", "9.99", "9.995", "10"),
        ];
        for &(value, f1, f2, f3, f0) in cases {
            assert_eq!(fixed(value, 1), f1, "F1 of {value}");
            assert_eq!(fixed(value, 2), f2, "F2 of {value}");
            assert_eq!(fixed(value, 3), f3, "F3 of {value}");
            assert_eq!(fixed(value, 0), f0, "F0 of {value}");
        }

        assert_eq!(grouped(1_234_567.25, 1), "1,234,567.2");
        assert_eq!(grouped(1e16, 1), "10,000,000,000,000,000.0");
        assert_eq!(grouped(123_456_789_012.5, 1), "123,456,789,012.5");
        assert_eq!(grouped(-1234.56, 1), "-1,234.6");
    }

    #[test]
    fn counts_match_dotnet() {
        for (value, expected) in [
            (0, "0"),
            (-5, "-5"),
            (999, "999"),
            (1000, "1,000"),
            (-1000, "-1,000"),
            (1_234_567, "1,234,567"),
            (i64::MAX, "9,223,372,036,854,775,807"),
            (i64::MIN, "-9,223,372,036,854,775,808"),
        ] {
            assert_eq!(count(value), expected);
        }
    }

    #[test]
    fn intervals_match_dotnet() {
        for (interval, expected) in [
            (12345, "1.235"),
            (1225, "0.123"),
            (125, "0.013"),
            (1221, "0.122"),
            (2500, "0.25"),
            (10000, "1"),
            (625, "0.063"),
            (3125, "0.313"),
            (1, "0"),
            (5, "0.001"),
            (15, "0.002"),
            (25, "0.003"),
        ] {
            assert_eq!(ten_thousandths(interval), expected);
        }
    }

    #[test]
    fn units() {
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KB");
        assert_eq!(bytes(32 * 1024 * 1024), "32.0 MB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024 + 512 * 1024 * 1024), "3.5 GB");
        assert_eq!(bytes(-2048), "-2.0 KB");
        assert_eq!(percent(1, 3), "33.3%");
        assert_eq!(percent(1, 0), "-");
    }

    #[test]
    fn ipv6_matches_dotnet() {
        let cases: &[([u8; 16], &str)] = &[
            ([0; 16], "::"),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], "::1"),
            ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 0, 0xab, 0xcd], "fe80::1234:0:0:abcd"),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 10], "::ffff:192.168.0.10"),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 0, 10], "::192.168.0.10"),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 192, 168, 0, 10], "::ffff:0:192.168.0.10"),
            ([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1], "2001:db8::1:0:0:1"),
            ([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1], "2001:db8:0:1::1"),
            ([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "2001:db8::"),
            ([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "1::"),
            ([0x26, 0x07, 0xf8, 0xb0, 0x40, 0x05, 0x08, 0x0c, 0, 0, 0, 0, 0, 0, 0x20, 0x0e], "2607:f8b0:4005:80c::200e"),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x5e, 0xfe, 10, 1, 2, 3], "::5efe:10.1.2.3"),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34], "::1234"),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0], "::0.1.0.0"),
            ([0x20, 0x01, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], "2001:0:0:1::"),
            ([0x20, 0x01, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], "2001:1::1:0:0"),
        ];
        for &(address, expected) in cases {
            assert_eq!(ipv6(address), expected);
        }

        assert_eq!(ipv4([192, 168, 0, 10]), "192.168.0.10");
    }

    #[test]
    fn paths_and_case() {
        assert_eq!(file_name(r"C:\Windows\System32\ntdll.dll"), "ntdll.dll");
        assert_eq!(file_name_without_extension(r"C:\x\Microsoft.Photos.exe"), "Microsoft.Photos");
        assert_eq!(file_name_without_extension("System"), "System");
        assert_eq!(file_name("C:foo.dll"), "foo.dll");
        assert_eq!(strip_prefix_ignore_case(r"\device\HarddiskVolume3\x", r"\Device\harddiskvolume3\"), Some("x"));
        assert_eq!(find_ignore_case(r"\\?\GLOBALROOT\os\windows\x", r"\OS\Windows\"), Some(14));
        assert!(eq_ignore_case("Software\\Foo", "SOFTWARE\\foo"));
        assert_eq!(pad_left("ab", 4), "  ab");
        assert_eq!(pad_right("ab", 4), "ab  ");
        assert_eq!(ordinal_cmp("B", "a"), Ordering::Less);
    }
}
