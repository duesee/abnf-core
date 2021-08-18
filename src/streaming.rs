//! ABNF Core Rules (RFC5234 B.1.)

use nom::{
    branch::alt,
    bytes::streaming::tag,
    character::{
        is_alphabetic, is_digit as nom_is_digit, is_hex_digit as nom_is_hex_digit,
        streaming::line_ending,
    },
    IResult,
};

/// A-Z / a-z
///
/// ALPHA = %x41-5A / %x61-7A
pub fn is_alpha(byte: u8) -> bool {
    is_alphabetic(byte)
}

/// BIT = "0" / "1"
pub fn is_bit(byte: u8) -> bool {
    byte == b'0' || byte == b'1'
}

/// Any 7-bit US-ASCII character, excluding NUL
///
/// CHAR = %x01-7F
pub fn is_char(byte: u8) -> bool {
    matches!(byte, 0x01..=0x7f)
}

/// Carriage return
///
/// CR = %x0D
pub fn cr(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag("\r")(input)
}

/// Internet standard newline
///
/// CRLF = CR LF
pub fn crlf(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag("\r\n")(input)
}

/// Newline, with and without "\r".
pub fn crlf_relaxed(input: &[u8]) -> IResult<&[u8], &[u8]> {
    line_ending(input)
}

/// Controls
///
/// CTL = %x00-1F / %x7F
pub fn is_ctl(byte: u8) -> bool {
    matches!(byte, 0x00..=0x1f | 0x7f)
}

/// 0-9
///
/// DIGIT = %x30-39
pub fn is_digit(byte: u8) -> bool {
    nom_is_digit(byte)
}

/// Double Quote
///
/// DQUOTE = %x22
pub fn dquote(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag("\"")(input)
}

/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
pub fn is_hexdig(byte: u8) -> bool {
    nom_is_hex_digit(byte)
}

/// Horizontal tab
///
/// HTAB = %x09
pub fn htab(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag("\x09")(input)
}

/// Linefeed
///
/// LF = %x0A
pub fn lf(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag("\n")(input)
}

/// Use of this linear-white-space rule permits lines containing only white
/// space that are no longer legal in mail headers and have caused
/// interoperability problems in other contexts.
///
/// Do not use when defining mail headers and use with caution in other contexts.
///
/// LWSP = *(WSP / CRLF WSP)

/// 8 bits of data
///
/// OCTET = %x00-FF

/// SP = %x20
pub fn sp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(" ")(input)
}

/// Visible (printing) characters
///
/// VCHAR = %x21-7E
pub fn is_vchar(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7E)
}

/// White space
///
/// WSP = SP / HTAB
pub fn wsp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((sp, htab))(input)
}
