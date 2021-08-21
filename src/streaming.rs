//! ABNF Core Rules (RFC5234 B.1.)

use std::ops::RangeFrom;

use nom::{
    character::streaming::satisfy, combinator::opt, error::ParseError, sequence::pair, AsChar,
    IResult, InputIter, InputLength, Slice,
};

use crate::{is_char, is_cr, is_dquote, is_htab, is_lf, is_sp, is_wsp};

/// Carriage return
///
/// CR = %x0D
pub fn cr<I, E>(input: I) -> IResult<I, char, E>
where
    I: InputLength + InputIter + Slice<RangeFrom<usize>> + Clone,
    <I as InputIter>::Item: AsChar,
    E: ParseError<I>,
{
    satisfy(is_cr)(input)
}

/// Internet standard newline
///
/// CRLF = CR LF
pub fn crlf<I, E>(input: I) -> IResult<I, (char, char), E>
where
    I: InputLength + InputIter + Slice<RangeFrom<usize>> + Clone,
    <I as InputIter>::Item: AsChar,
    E: ParseError<I>,
{
    pair(satisfy(is_cr), satisfy(is_lf))(input)
}

/// Newline, with and without "\r".
pub fn crlf_relaxed<I, E>(input: I) -> IResult<I, (Option<char>, char), E>
where
    I: InputLength + InputIter + Slice<RangeFrom<usize>> + Clone,
    <I as InputIter>::Item: AsChar,
    E: ParseError<I>,
{
    pair(opt(satisfy(is_cr)), satisfy(is_lf))(input)
}

/// Double Quote
///
/// DQUOTE = %x22
pub fn dquote<I, E>(input: I) -> IResult<I, char, E>
where
    I: InputLength + InputIter + Slice<RangeFrom<usize>> + Clone,
    <I as InputIter>::Item: AsChar,
    E: ParseError<I>,
{
    satisfy(is_dquote)(input)
}

/// Horizontal tab
///
/// HTAB = %x09
pub fn htab<I, E>(input: I) -> IResult<I, char, E>
where
    I: InputLength + InputIter + Slice<RangeFrom<usize>> + Clone,
    <I as InputIter>::Item: AsChar,
    E: ParseError<I>,
{
    satisfy(is_htab)(input)
}

/// Linefeed
///
/// LF = %x0A
pub fn lf<I, E>(input: I) -> IResult<I, char, E>
where
    I: InputLength + InputIter + Slice<RangeFrom<usize>> + Clone,
    <I as InputIter>::Item: AsChar,
    E: ParseError<I>,
{
    satisfy(is_lf)(input)
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
pub fn sp<I, E>(input: I) -> IResult<I, char, E>
where
    I: InputLength + InputIter + Slice<RangeFrom<usize>> + Clone,
    <I as InputIter>::Item: AsChar,
    E: ParseError<I>,
{
    satisfy(is_sp)(input)
}

/// VCHAR = %x21-7E ; visible (printing) characters
pub fn vchar<I, E>(input: I) -> IResult<I, char, E>
where
    I: InputLength + InputIter + Slice<RangeFrom<usize>> + Clone,
    <I as InputIter>::Item: AsChar,
    E: ParseError<I>,
{
    satisfy(is_char)(input)
}

/// White space
///
/// WSP = SP / HTAB
pub fn wsp<I, E>(input: I) -> IResult<I, char, E>
where
    I: InputLength + InputIter + Slice<RangeFrom<usize>> + Clone,
    <I as InputIter>::Item: AsChar,
    E: ParseError<I>,
{
    satisfy(is_wsp)(input)
}
