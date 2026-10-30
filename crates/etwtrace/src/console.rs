//! Console output that does not panic when stdout or stderr goes away (e.g. a closed pipe).

use std::io::Write;

/// Writes text to stdout as is.
pub fn write(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

/// Writes a line to stdout.
pub fn line(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// Writes a line to stderr.
pub fn error(text: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(text.as_bytes());
    let _ = err.write_all(b"\n");
}

/// `say!()` prints an empty line, `say!("...", args)` a formatted one.
#[macro_export]
macro_rules! say {
    () => {
        $crate::console::line("")
    };
    ($($arg:tt)*) => {
        $crate::console::line(&format!($($arg)*))
    };
}
