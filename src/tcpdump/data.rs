use std::fmt::Debug;

use super::DataError as Error;

#[derive(Clone, Eq, PartialEq)]
pub struct Data {
    pub ip_header: Vec<u8>,
    pub tcp_header: Vec<u8>,
    pub data: Vec<u8>,
}

impl Data {
    pub fn parse_data_parts(data: Vec<u8>) -> Result<Self, Error> {
        let ipv_and_ihl = data.get(0).ok_or(Error::ExpectedByte)?;
        let ipv = ipv_and_ihl >> 4;
        if ipv != 0x4 {
            return Err(Error::UnsupportedIPVersion);
        }
        let ihl = ipv_and_ihl & 0b1111;

        let (ip_header, data) = data
            .split_at_checked((ihl * 4).into())
            .ok_or(Error::ExpectedByte)?;

        let tcp_offset = data.get(12).ok_or(Error::ExpectedByte)? >> 4;
        let tcp_header_len = tcp_offset * 4;

        let (tcp_header, data) = data
            .split_at_checked(tcp_header_len.into())
            .ok_or(Error::ExpectedByte)?;

        Ok(Self {
            ip_header: ip_header.to_vec(),
            tcp_header: tcp_header.to_vec(),
            data: data.to_vec(),
        })
    }
}

impl Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Data {{ ip_header: {:02X?}, tcp_header: {:02X?}, data: {:02X?} }}",
            self.ip_header, self.tcp_header, self.data
        )
    }
}

pub fn parse_data_line(line: &str) -> Result<Vec<u8>, Error> {
    let data = line
        .split("  ")
        .nth(1)
        .ok_or(Error::UnexpectedToken("expected '  ' at least once"))?;

    data.split(' ')
        .map(|dbyte| dbyte.split_at(2))
        .flat_map(|(a, b)| if b.is_empty() { vec![a] } else { vec![a, b] })
        .map(|byte| u8::from_str_radix(byte, 16))
        .try_collect()
        .map_err(|_| Error::InvalidByteRepr)
}
