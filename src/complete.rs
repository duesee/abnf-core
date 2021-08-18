use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{self as character, anychar, line_ending},
    combinator::{opt, recognize, verify},
    error::ParseError,
    multi::many0_count,
    sequence::terminated,
    IResult,
};

use crate::*;

/// ALPHA = %x41-5A / %x61-7A ; A-Z / a-z
pub fn alpha<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    verify(anychar, |&c| is_alpha(c))(input)
}

/// BIT = "0" / "1"
pub fn bit<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    verify(anychar, |&c| is_bit(c))(input)
}

/// CHAR = %x01-7F ; any 7-bit US-ASCII character, excluding NUL
pub fn char<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    verify(anychar, |&c| is_char(c))(input)
}

/// CR = %x0D ; carriage return
pub fn cr<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    character::char('\r')(input)
}

pub fn crlf_strict<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    tag("\r\n")(input)
}

pub fn crlf_relaxed<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    line_ending(input)
}

/// CRLF = CR LF ; Internet standard newline
///
/// Note: this variant will strictly expect "\r\n".
/// Use [crlf_relaxed](fn.crlf_relaxed.html) to accept "\r\n" as well as only "\n".
pub fn crlf<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    crlf_strict(input)
}

/// CTL = %x00-1F / %x7F ; controls
pub fn ctl<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    verify(anychar, |&c| is_ctl(c))(input)
}

/// DIGIT = %x30-39 ; 0-9
pub fn digit<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    verify(anychar, |&c| is_digit(c))(input)
}

/// DQUOTE = %x22 ; " (Double Quote)
pub fn dquote<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    character::char('"')(input)
}

/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
pub fn hexdig<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    verify(anychar, |&c| is_hexdig(c))(input)
}

/// HTAB = %x09 ; horizontal tab
pub fn htab<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    character::char('\t')(input)
}

/// LF = %x0A ; linefeed
pub fn lf<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    character::char('\n')(input)
}

/// LWSP = *(WSP / CRLF WSP)
///         ; Use of this linear-white-space rule
///         ;  permits lines containing only white
///         ;  space that are no longer legal in
///         ;  mail headers and have caused
///         ;  interoperability problems in other
///         ;  contexts.
///         ; Do not use when defining mail
///         ;  headers and use with caution in
///         ;  other contexts.
// code as equivalent avoid branching LWSP = *([CRLF] WSP)
pub fn lwsp<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    recognize(many0_count(terminated(opt(crlf), wsp)))(input)
}

/// OCTET = %x00-FF ; 8 bits of data
pub fn octet(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take(1usize)(input)
}

/// SP = %x20
pub fn sp<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    character::char(' ')(input)
}

/// VCHAR = %x21-7E ; visible (printing) characters
pub fn vchar<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    verify(anychar, |&c| is_vchar(c))(input)
}

/// WSP = SP / HTAB ; white space
pub fn wsp<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    alt((sp, htab))(input)
}

#[cfg(test)]
mod tests {
    use nom::error::VerboseError;

    use super::*;

    #[test]
    fn test_alpha() {
        assert!(alpha::<VerboseError<&str>>("").is_err());

        assert!(alpha::<VerboseError<&str>>("`").is_err());
        assert_eq!(alpha::<VerboseError<&str>>("a"), Ok(("", 'a')));
        assert_eq!(alpha::<VerboseError<&str>>("z"), Ok(("", 'z')));
        assert!(alpha::<VerboseError<&str>>("{").is_err());

        assert!(alpha::<VerboseError<&str>>("@").is_err());
        assert_eq!(alpha::<VerboseError<&str>>("A"), Ok(("", 'A')));
        assert_eq!(alpha::<VerboseError<&str>>("Z"), Ok(("", 'Z')));
        assert!(alpha::<VerboseError<&str>>("[").is_err());
    }

    #[test]
    fn test_bit() {
        assert!(bit::<VerboseError<&str>>("").is_err());

        assert!(bit::<VerboseError<&str>>("/").is_err());
        assert_eq!(bit::<VerboseError<&str>>("0"), Ok(("", '0')));
        assert_eq!(bit::<VerboseError<&str>>("1"), Ok(("", '1')));
        assert!(bit::<VerboseError<&str>>("2").is_err());
    }

    #[test]
    fn test_char() {
        assert!(char::<VerboseError<&str>>("").is_err());

        assert!(char::<VerboseError<&str>>("\x00").is_err());
        assert_eq!(char::<VerboseError<&str>>("\x01"), Ok(("", '\x01')));
        assert_eq!(char::<VerboseError<&str>>("\x7f"), Ok(("", '\x7f')));
        assert!(char::<VerboseError<&str>>("\u{80}").is_err());
    }

    #[test]
    fn test_cr() {
        assert!(cr::<VerboseError<&str>>("").is_err());

        assert!(cr::<VerboseError<&str>>("\x0c").is_err());
        assert_eq!(cr::<VerboseError<&str>>("\r"), Ok(("", '\r')));
        assert!(cr::<VerboseError<&str>>("\x0e").is_err());
    }

    #[test]
    fn test_crlf_strict() {
        assert!(crlf_strict::<VerboseError<&str>>("").is_err());

        assert!(crlf_strict::<VerboseError<&str>>("\x0c").is_err());
        assert!(crlf_strict::<VerboseError<&str>>("\r").is_err());
        assert!(crlf_strict::<VerboseError<&str>>("\x0e").is_err());

        assert!(crlf_strict::<VerboseError<&str>>("\x09").is_err());
        assert!(crlf_strict::<VerboseError<&str>>("\n").is_err());
        assert!(crlf_strict::<VerboseError<&str>>("\x0b").is_err());

        assert_eq!(crlf_strict::<VerboseError<&str>>("\r\n"), Ok(("", "\r\n")));
    }

    #[test]
    fn test_crlf_relaxed() {
        assert!(crlf_relaxed::<VerboseError<&str>>("").is_err());

        assert!(crlf_relaxed::<VerboseError<&str>>("\x0c").is_err());
        assert!(crlf_relaxed::<VerboseError<&str>>("\r").is_err());
        assert!(crlf_relaxed::<VerboseError<&str>>("\x0e").is_err());

        assert!(crlf_relaxed::<VerboseError<&str>>("\x09").is_err());
        assert_eq!(crlf_relaxed::<VerboseError<&str>>("\n"), Ok(("", "\n")));
        assert!(crlf_relaxed::<VerboseError<&str>>("\x0b").is_err());

        assert_eq!(crlf_relaxed::<VerboseError<&str>>("\r\n"), Ok(("", "\r\n")));
    }

    #[test]
    fn test_ctl() {
        assert!(ctl::<VerboseError<&str>>("").is_err());

        assert!(ctl::<VerboseError<&str>>("\x00").is_ok());
        assert!(ctl::<VerboseError<&str>>("\x1f").is_ok());
        assert!(ctl::<VerboseError<&str>>("\x20").is_err());
        assert!(ctl::<VerboseError<&str>>("\x7f").is_ok());
        assert!(ctl::<VerboseError<&str>>("\u{80}").is_err());
    }

    #[test]
    fn test_digit() {
        assert!(digit::<VerboseError<&str>>("").is_err());

        assert!(digit::<VerboseError<&str>>("/").is_err());
        assert_eq!(digit::<VerboseError<&str>>("0"), Ok(("", '0')));
        assert_eq!(digit::<VerboseError<&str>>("9"), Ok(("", '9')));
        assert!(digit::<VerboseError<&str>>(":").is_err());
    }

    // DQUOTE

    #[test]
    fn test_hexdig() {
        assert!(hexdig::<VerboseError<&str>>("").is_err());

        assert!(hexdig::<VerboseError<&str>>("/").is_err());
        assert_eq!(hexdig::<VerboseError<&str>>("0"), Ok(("", '0')));
        assert_eq!(hexdig::<VerboseError<&str>>("9"), Ok(("", '9')));
        assert!(hexdig::<VerboseError<&str>>(":").is_err());

        assert!(hexdig::<VerboseError<&str>>("`").is_err());
        assert_eq!(hexdig::<VerboseError<&str>>("a"), Ok(("", 'a')));
        assert_eq!(hexdig::<VerboseError<&str>>("f"), Ok(("", 'f')));
        assert!(hexdig::<VerboseError<&str>>("g").is_err());

        assert!(hexdig::<VerboseError<&str>>("@").is_err());
        assert_eq!(hexdig::<VerboseError<&str>>("A"), Ok(("", 'A')));
        assert_eq!(hexdig::<VerboseError<&str>>("F"), Ok(("", 'F')));
        assert!(hexdig::<VerboseError<&str>>("G").is_err());
    }

    // HTAB

    // LF

    // LWSP

    // OCTET

    // SP

    // VCHAR

    // WSP
}
