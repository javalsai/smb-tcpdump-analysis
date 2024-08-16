#![allow(dead_code)]
pub mod data;
pub mod header;

use data::Data;
use header::Header;
use std::io::{self, BufRead};

/// Same as `?` (in fact copied from its' old macro) but wraps the error branch in `Some`, made for
/// the case shown in the iter below
macro_rules! try_some {
    ($expr:expr $(,)?) => {
        match $expr {
            core::result::Result::Ok(val) => val,
            core::result::Result::Err(err) => {
                return core::option::Option::Some(core::result::Result::Err(
                    core::convert::From::from(err),
                ));
            }
        }
    };
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HeaderError {
    SyntaxError,
    InvalidProtocol,
    InvalidSocketAddr,
    InvalidTimeFmt,
    MissingToken,
    UnexpectedToken(&'static str),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DataError {
    ExpectedByte,
    SyntaxError,
    InvalidByteRepr,
    UnexpectedToken(&'static str),
    UnsupportedIPVersion,
}

#[derive(Debug)]
pub enum Error {
    ReadLine(io::Error),
    HeaderError(HeaderError),
    DataError(DataError),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TcpdumpMsg {
    pub header: Header,
    pub data: Data,
}

pub struct TcpdumpIter<T: BufRead> {
    stream: T,
    header: Option<Header>,
}

impl<T: BufRead> TcpdumpIter<T> {
    fn new(val: T) -> Self {
        Self {
            stream: val,
            header: None,
        }
    }
}

impl Default for TcpdumpIter<io::BufReader<io::StdinLock<'_>>> {
    fn default() -> Self {
        Self {
            stream: io::BufReader::new(io::stdin().lock()),
            header: None,
        }
    }
}

impl<T: BufRead> Iterator for TcpdumpIter<T> {
    type Item = Result<TcpdumpMsg, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = vec![];
        loop {
            let mut line = String::new();
            let read_bytes = try_some!(self
                .stream
                .read_line(&mut line)
                .map_err(Error::ReadLine));
            line.pop();

            if self.header.is_none() {
                if read_bytes == 0 {
                    return None;
                }
                self.header = Some(try_some!(Header::parse(&line).map_err(Error::HeaderError)))
            } else if line.starts_with('\t') {
                buf.append(&mut try_some!(
                    data::parse_data_line(&line).map_err(Error::DataError)
                ));
            } else {
                let header = self.header.take()?;
                if read_bytes != 0 {
                    self.header = Some(try_some!(Header::parse(&line).map_err(Error::HeaderError)));
                }

                let data = try_some!(Data::parse_data_parts(buf).map_err(Error::DataError));
                return Some(Ok(TcpdumpMsg { header, data }));
            }
        }
    }
}
