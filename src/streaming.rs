//! ABNF Core Rules (RFC5234 B.1.)

use nom::{bytes::streaming::tag, character::streaming::line_ending, IResult};

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

/// Double Quote
///
/// DQUOTE = %x22
pub fn dquote(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag("\"")(input)
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
