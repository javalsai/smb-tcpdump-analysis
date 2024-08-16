use std::{fmt::Write, ops::Deref};

pub fn byte_iter_as_str(
    iter: impl Iterator<Item = impl Deref<Target = u8>>,
    wrap: usize,
) -> Result<String, std::fmt::Error> {
    let mut f = String::new();
    byte_iter(&mut f, iter, wrap)?;
    Ok(f)
}

pub fn byte_iter(
    f: &mut impl Write,
    iter: impl Iterator<Item = impl Deref<Target = u8>>,
    wrap: usize,
) -> std::fmt::Result {
    for (i, c) in iter.enumerate() {
        let c = *c;
        if i % wrap == 0 {
            write!(f, "\n  ")?;
        }

        if c.is_ascii_graphic() {
            write!(f, "{}", c as char)?;
        } else if c == 0 {
            #[cfg(not(feature = "color"))]
            write!(f, "\\0")?;
            #[cfg(feature = "color")]
            write!(f, "\x1b[1;35m\\0\x1b[0m")?;
        } else {
            #[cfg(not(feature = "color"))]
            write!(f, "\\x{c:02X}")?;
            #[cfg(feature = "color")]
            write!(f, "\x1b[1;31m\\x{c:02X}\x1b[0m")?;
        }
    }
    Ok(())
}
