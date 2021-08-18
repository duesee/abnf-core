#![allow(non_snake_case)]

//!
//! Parsing of ABNF Core Rules
//!
//! See https://tools.ietf.org/html/rfc5234#appendix-B.1
//!

pub mod complete;
pub mod streaming;

pub fn is_alpha(c: char) -> bool {
    c.is_ascii_alphabetic()
}

pub fn is_bit(c: char) -> bool {
    c == '0' || c == '1'
}

pub fn is_char(c: char) -> bool {
    matches!(c, '\x01'..='\x7F')
}

pub fn is_cr(c: char) -> bool {
    c == '\r'
}

// CRLF

pub fn is_ctl(c: char) -> bool {
    matches!(c, '\x00'..='\x1F' | '\x7F')
}

pub fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
}

pub fn is_dquote(c: char) -> bool {
    c == '"'
}

pub fn is_hexdig(c: char) -> bool {
    c.is_ascii_hexdigit()
}

// HTAB

// LF

// LWSP

// OCTET

// SP

// VCHAR

// WSP

pub fn is_vchar(c: char) -> bool {
    matches!(c, '\x21'..='\x7E')
}

pub fn is_wsp(c: char) -> bool {
    matches!(c, '\x20' | '\x09')
}
