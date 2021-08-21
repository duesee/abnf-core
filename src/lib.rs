//!
//! Parsing of ABNF Core Rules
//!
//! See https://tools.ietf.org/html/rfc5234#appendix-B.1
//!

pub mod complete;
pub mod streaming;

use nom::AsChar;

/// A-Z / a-z
///
/// ALPHA = %x41-5A / %x61-7A
pub fn is_alpha(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x41'..='\x5A' | '\x61'..='\x7A')
}

/// BIT = "0" / "1"
/// BIT = %x30 / %x31
pub fn is_bit(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x30'..='\x31')
}

/// Any 7-bit US-ASCII character, excluding NUL
///
/// CHAR = %x01-7F
pub fn is_char(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x01'..='\x7F')
}

/// Carriage return
///
/// CR = %x0D
pub fn is_cr(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x0D')
}

// CRLF
// Not implemented as predicate.

/// Controls
///
/// CTL = %x00-1F / %x7F
pub fn is_ctl(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x00'..='\x1F' | '\x7F')
}

/// 0-9
///
/// DIGIT = %x30-39
pub fn is_digit(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x30'..='\x39')
}

/// " (Double Quote)
///
/// DQUOTE = %x22
pub fn is_dquote(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x22')
}

/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
pub fn is_hexdig(c: impl AsChar) -> bool {
    matches!(c.as_char(), '0'..='9' | 'a'..='f' | 'A'..='F')
}

/// Horizontal tab
///
/// HTAB = %x09
pub fn is_htab(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x09')
}

/// Linefeed
///
/// LF = %x0A
pub fn is_lf(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x0A')
}

// LWSP
// Not implemented as predicate.

/// 8 bits of data
///
/// OCTET = %x00-FF
pub fn is_octet(_: u8) -> bool {
    true
}

/// Space
///
/// SP = %x20
pub fn is_sp(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x20')
}

/// Visible (printing) characters
///
/// VCHAR = %x21-7E
pub fn is_vchar(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x21'..='\x7E')
}

/// White space
///
/// WSP = SP / HTAB
pub fn is_wsp(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x20' | '\x09')
}
