pub mod flags;
pub mod opcodes;

use crate::prettify;
use std::{cmp::Ordering, fmt::Debug};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    ExpectedByte,
    InvalidFlags,
    InvalidMagic,
    InvalidMessageLength,
    InvalidOpcode,
    NonZeroFirstByte,
    UnsupportedVersion,
    ZeroHeaderMsg,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RawSMBMsg(Vec<u8>);

// https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SMB2/%5bMS-SMB2%5d-240708.pdf
// 2.2.1.1 SMB2 Packet Header - ASYNC
// 2.2.1.2 SMB2 Packet Header - SYNC
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SMBHeader {
    pub magic: [u8; 4],
    pub hlen: u16,

    ///  CreditCharge (2 bytes): In the SMB 2.0.2 dialect, this field MUST NOT be used and MUST be
    /// reserved. The sender MUST set this to 0, and the receiver MUST ignore it. In all other dialects, this
    /// field indicates the number of credits that this request consumes.
    ///
    /// (is never 0 anyways, always a fucking random val)
    pub cred_charge: u16,

    ///  (ChannelSequence,Reserved)/Status (4 bytes): In a request, this field is interpreted in different
    /// ways depending on the SMB2 dialect.
    ///  In the SMB 3.x dialect family, this field is interpreted as the ChannelSequence field followed by
    /// the Reserved field in a request.
    ///
    ///  ChannelSequence (2 bytes): This field is an indication to the server about the client's Channel
    /// change.
    ///  Reserved (2 bytes): This field SHOULD be set to zero and the server MUST ignore it on receipt.
    ///  In the SMB 2.0.2 and SMB 2.1 dialects, this field is interpreted as the Status field in a request.
    ///  Status (4 bytes): The client MUST set this field to 0 and the server MUST ignore it on receipt.
    ///  In all SMB dialects for a response this field is interpreted as the Status field. This field can be set
    /// to any value. For a list of valid status codes, see [MS-ERREF] section 2.3.
    pub nt_status: u32,

    ///  Command (2 bytes): The command code of this packet. This field MUST contain one of the following
    /// valid commands [./opcodes.rs]
    pub opcode: opcodes::Opcodes,

    ///  CreditRequest/CreditResponse (2 bytes): On a request, this field indicates the number of [credits]
    /// the client is requesting. On a response, it indicates the number of credits granted to the client.
    ///
    ///  [credit]: A value that is granted to an SMB 2 Protocol client by an SMB 2 Protocol server that limits
    /// the number of outstanding requests that a client can send to a server
    pub cred_req_res: u16,

    ///  Flags (4 bytes): A flags field, which indicates how to process the operation. This field MUST be
    /// constructed using the following values
    pub flags: flags::Flags,

    ///  NextCommand (4 bytes): For a compounded request and response, this field MUST be set to the
    /// offset, in bytes, from the beginning of this SMB2 header to the start of the subsequent 8-byte
    /// aligned SMB2 header. If this is not a compounded request or response, or this is the last header in
    /// a compounded request or response, this value MUST be 0.
    pub chain_offset: u32, // a.k.a. NextCommand
    //
    ///  MessageId (8 bytes): A value that identifies a message request and response uniquely across all
    /// messages that are sent on the same SMB 2 Protocol transport
    pub cmd_seq: u64, // a.k.a. MessageId

    ///  Reserved (4 bytes): The client SHOULD<3> set this field to 0. The server MAY<4> ignore this field
    /// on receipt.
    pub pid: u32, // or reserved

    ///  TreeId (4 bytes): Uniquely identifies the [tree connect] for the command. This MUST be 0 for the
    /// SMB2 TREE_CONNECT Request. The TreeId can be any unsigned 32-bit integer that is received
    /// from a previous SMB2 TREE_CONNECT Response. TreeId SHOULD be set to 0 for the following
    /// commands: SMB2 NEGOTIATE Request, SMB2 NEGOTIATE Response, SMB2 SESSION_SETUP Request, SMB2
    ///   SESSION_SETUP Response, SMB2 LOGOFF Request, SMB2 LOGOFF Response, SMB2 ECHO Request, SMB2 ECHO
    ///   Response, SMB2 CANCEL Request
    ///
    ///  [tree connect]: A connection by a specific session on an SMB 2 Protocol client to a specific share on
    /// an SMB 2 Protocol server over an SMB 2 Protocol connection. There could be multiple tree
    /// connects over a single SMB 2 Protocol connection. The TreeId field in the SMB2 packet header
    /// distinguishes the various tree connects.
    pub tid: u32,

    ///  SessionId (8 bytes): Uniquely identifies the established [session] for the command. This field MUST
    /// be set to 0 for an SMB2 NEGOTIATE Request (section 2.2.3) and for an SMB2 NEGOTIATE
    /// Response (section 2.2.4).
    ///
    ///  [session]: An [authenticated context] that is established between an SMB 2 Protocol client and an
    /// SMB 2 Protocol server over an SMB 2 Protocol connection for a specific security principal. There
    /// could be multiple active sessions over a single SMB 2 Protocol connection. The SessionId field in
    /// the SMB2 packet header distinguishes the various sessions.
    ///
    ///  [authenticated context]: The runtime state that is associated with the successful authentication of
    /// a security principal between the client and the server, such as the security principal itself, the
    /// cryptographic key that was generated during authentication, and the rights and privileges of this
    /// security principal.
    pub uid: u64, // or SessionId

    ///  Signature (16 bytes): The 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the
    /// Flags field of the SMB2 header and the message is not encrypted. If the message is not signed,
    /// this field MUST be 0.
    pub signature: u128,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SMBMsg {
    pub header: SMBHeader,
    pub payload: Vec<u8>,
}

macro_rules! __ {
    ($exp:expr) => {
        match $exp {
            Some(val) => val,
            None => return Err(Error::ExpectedByte),
        }
    };
}

impl SMBMsg {
    pub fn parse_from_raw(mut raw: Vec<u8>) -> Result<Self, Error> {
        drain_packet_head(&mut raw)?;

        let mut drainer = raw.drain(..);

        Ok(Self {
            header: SMBHeader::parse_from_raw(&mut drainer)?,
            payload: drainer.collect(),
        })
    }
}
impl SMBHeader {
    pub fn parse_from_raw(it: &mut impl ExactSizeIterator<Item = u8>) -> Result<Self, Error> {
        let orig_len = it.len();

        let magic: [u8; 4] = __!(take_slice(it));

        return if magic.cmp(&[0xFE, b'S', b'M', b'B']) == Ordering::Equal {
            Self::parse_fe_smb(magic, it, orig_len)
        } else if magic.cmp(&[0xFF, b'S', b'M', b'B']) == Ordering::Equal {
            Self::parse_ff_smb(magic, it, orig_len)
        } else {
            Err(Error::InvalidMagic)
        };
    }

    fn parse_fe_smb(
        magic: [u8; 4],
        it: &mut impl ExactSizeIterator<Item = u8>,
        orig_size: usize,
    ) -> Result<Self, Error> {
        let hlen = u16::from_le_bytes(__!(take_slice(it)));
        if orig_size < hlen as usize {
            return Err(Error::InvalidMessageLength);
        }
        let it = &mut it.take(hlen as usize - 6);

        let cred_charge = u16::from_le_bytes(__!(take_slice(it)));
        let nt_status = u32::from_le_bytes(__!(take_slice(it)));
        let opcode = u16::from_le_bytes(__!(take_slice(it)));
        let cred_req_res = u16::from_le_bytes(__!(take_slice(it)));
        let flags = u32::from_le_bytes(__!(take_slice(it)));
        let chain_offset = u32::from_le_bytes(__!(take_slice(it)));
        let cmd_seq = u64::from_le_bytes(__!(take_slice(it)));
        let pid = u32::from_le_bytes(__!(take_slice(it)));
        let tid = u32::from_le_bytes(__!(take_slice(it)));
        let uid = u64::from_le_bytes(__!(take_slice(it)));
        let signature = u128::from_le_bytes(__!(take_slice(it)));

        Ok(Self {
            magic,
            hlen,
            cred_charge,
            nt_status,
            opcode: opcode.try_into().map_err(|_| Error::InvalidOpcode)?,
            cred_req_res,
            flags: flags::Flags::from_bits(flags).ok_or(Error::InvalidFlags)?,
            chain_offset,
            cmd_seq,
            pid,
            tid,
            uid,
            signature,
        })
    }

    fn parse_ff_smb(
        _magic: [u8; 4],
        _it: &mut impl ExactSizeIterator<Item = u8>,
        _orig_size: usize,
    ) -> Result<Self, Error> {
        Err(Error::UnsupportedVersion)
    }
}

impl RawSMBMsg {
    pub fn new(from: Vec<u8>) -> Self {
        Self(from)
    }

    pub fn parse_from_raw(mut raw: Vec<u8>) -> Result<Self, Error> {
        let zero_byte = raw.get(1).ok_or(Error::ExpectedByte)?;
        if *zero_byte != 0 {
            return Err(Error::NonZeroFirstByte);
        }

        let len_bytes: Vec<u8> = raw.drain(0..=3).collect();
        if len_bytes.len() != 4 {
            return Err(Error::ExpectedByte);
        }
        let len_bytes: [u8; 4] = len_bytes.try_into().map_err(|_| Error::ExpectedByte)?;
        let expected_len = u32::from_be_bytes(len_bytes);
        if raw.len() != expected_len as usize {
            return Err(Error::InvalidMessageLength);
        }

        Ok(Self(raw))
    }
}

impl Debug for RawSMBMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        prettify::byte::byte_iter(f, self.0.iter(), 4)
    }
}

pub fn drain_packet_head(raw: &mut Vec<u8>) -> Result<(), Error> {
    let head: [u8; 4] = __!(take_slice(&mut raw.drain(..=3)));
    if head[0] != 0 {
        return Err(Error::NonZeroFirstByte);
    }

    let len = u32::from_be_bytes(head);
    if len == 0 {
        Err(Error::ZeroHeaderMsg)
    } else if raw.len() != len as usize {
        Err(Error::InvalidMessageLength)
    } else {
        Ok(())
    }
}

pub fn take_slice<T, const L: usize>(iter: &mut impl Iterator<Item = T>) -> Option<[T; L]> {
    let array: Vec<T> = iter.take(L).collect();
    if array.len() != L {
        return None;
    }
    array.try_into().ok()
}
