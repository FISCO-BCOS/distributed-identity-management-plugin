pub mod config;
pub mod gs_tbk_scheme;
pub mod node;
pub mod communication;

use std::fmt;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
    InvalidValue,
    InvalidZkp
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match *self {
            InvalidKey => write!(f, "InvalidKey"),
            InvalidSS => write!(f, "InvalidSS"),
            InvalidCom => write!(f, "InvalidCom"),
            InvalidSig => write!(f, "InvalidSig"),
            InvalidValue => write!(f, "InvalidValue"),
            InvalidZkp => write!(f, "InvalidZkp")
        }
    }
}