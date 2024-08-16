use chrono::NaiveTime;
use std::net;

use super::HeaderError as Error;
use crate::tcp;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Header {
    pub time: NaiveTime,
    pub src: net::SocketAddr,
    pub dst: net::SocketAddr,
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    pub win: u16,
    pub options: Option<String>,
    pub length: u128,
    pub flags: tcp::flags::FlagCollection,
}

impl Header {
    pub fn parse(raw: &'_ str) -> Result<Self, Error> {
        let Some((head, tail)) = raw.split_once(": ") else {
            return Err(Error::SyntaxError);
        };

        let head_parts = extract_header_parts(head.split_whitespace()).ok_or(Error::SyntaxError)?;
        let (time, src, dst) = parse_header_parts(head_parts?)?;

        let (flags, seq, ack, win, options, length) = parse_tail(tail)?;

        Ok(Self {
            time,
            src,
            dst,
            seq,
            ack,
            win,
            options,
            length,
            flags,
        })
    }
}

fn extract_header_parts<'a>(
    mut head_iter: impl Iterator<Item = &'a str>,
) -> Option<Result<(&'a str, &'a str, &'a str), Error>> {
    let ts = head_iter.next()?;
    let typ = head_iter.next()?;
    if typ != "IP" {
        return Some(Err(Error::InvalidProtocol));
    }
    let src = head_iter.next()?;
    let dir = head_iter.next()?;
    if dir != ">" {
        return Some(Err(Error::UnexpectedToken("expected '>' instead")));
    }
    let dst = head_iter.next()?;

    Some(Ok((ts, src, dst)))
}

fn parse_header_parts(
    (ts, src, dst): (&str, &str, &str),
) -> Result<(NaiveTime, net::SocketAddr, net::SocketAddr), Error> {
    let Ok(ts) = chrono::NaiveTime::parse_from_str(ts, "%H:%M:%S%.f") else {
        return Err(Error::InvalidTimeFmt);
    };

    let src = parse_tcpdump_sockaddr(src.to_owned().as_mut_str())?;
    let dst = parse_tcpdump_sockaddr(dst.to_owned().as_mut_str())?;

    Ok((ts, src, dst))
}

fn parse_tcpdump_sockaddr(str_addr: &mut str) -> Result<net::SocketAddr, Error> {
    let pos = str_addr.rfind('.').ok_or(Error::InvalidSocketAddr)?;

    let bytes = unsafe { str_addr.as_bytes_mut() };
    bytes[pos] = b':';

    str_addr.parse().map_err(|_| Error::InvalidSocketAddr)
}

fn parse_tail(
    tail: &str,
) -> Result<
    (
        tcp::flags::FlagCollection,
        Option<u32>,
        Option<u32>,
        u16,
        Option<String>,
        u128,
    ),
    Error,
> {
    let mut flags = None;
    let mut seq = None;
    let mut ack = None;
    let mut win = None;
    let mut options = None;
    let mut len = None;

    for entry in tail.split(", ").map(|e| e.split_once(' ')) {
        let (k, v) = entry.ok_or(Error::SyntaxError)?;
        match k {
            "Flags" => {
                flags =
                    Some(tcp::flags::FlagCollection::try_parse(v).map_err(|_| Error::SyntaxError)?)
            }
            "seq" => {
                seq = Some(
                    v.split_once(':')
                        .map(|(s, _)| s)
                        .unwrap_or(v)
                        .parse::<u32>()
                        .map_err(|_| Error::SyntaxError)?,
                )
            }
            "ack" => ack = Some(v.parse::<u32>().map_err(|_| Error::SyntaxError)?),
            "win" => win = Some(v.parse::<u16>().map_err(|_| Error::SyntaxError)?),
            "options" => options = Some(v.to_owned()),
            "length" => len = Some(v.parse::<u128>().map_err(|_| Error::SyntaxError)?),
            _ => return Err(Error::UnexpectedToken("unexpected head key value")),
        };
    }

    if let (Some(flags), seq, ack, Some(win), options, Some(len)) =
        (flags, seq, ack, win, options, len)
    {
        Ok((flags, seq, ack, win, options, len))
    } else {
        Err(Error::MissingToken)
    }
}
