#![allow(non_snake_case)]

//!
//! Parsing of ABNF Core Rules
//!
//! See https://tools.ietf.org/html/rfc5234#appendix-B.1
//!

pub mod complete;
pub mod streaming;

use nom::AsChar;

pub fn is_alpha(c: impl AsChar) -> bool {
    c.is_alpha()
}

pub fn is_bit(c: impl AsChar) -> bool {
    matches!(c.as_char(), '0' | '1')
}

pub fn is_char(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x01'..='\x7F')
}

pub fn is_cr(c: impl AsChar) -> bool {
    c.as_char() == '\r'
}

// CRLF

pub fn is_ctl(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x00'..='\x1F' | '\x7F')
}

pub fn is_digit(c: impl AsChar) -> bool {
    c.is_dec_digit()
}

pub fn is_dquote(c: impl AsChar) -> bool {
    c.as_char() == '"'
}

pub fn is_hexdig(c: impl AsChar) -> bool {
    c.is_hex_digit()
}

// HTAB

// LF

// LWSP

// OCTET

// SP

// VCHAR

// WSP

pub fn is_vchar(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x21'..='\x7E')
}

pub fn is_wsp(c: impl AsChar) -> bool {
    matches!(c.as_char(), '\x20' | '\x09')
}
