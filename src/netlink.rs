pub mod generic;

use netlink_sys::{protocols, Socket, SocketAddr};
use std::convert::{From, Into, TryFrom, TryInto};
use std::error;
use std::io;
use std::{fmt, mem, slice};

use crate::common;

use generic::{GenericError, GenericNetlinkMessage, GenericNetlinkMessageType};

// * Netlink message format in kernel:
// *    <--- nlmsg_total_size(payload)  --->
// *    <-- nlmsg_msg_size(payload) ->
// *   +----------+- - -+-------------+- - -+-------- - -
// *   | nlmsghdr | Pad |   Payload   | Pad | nlmsghdr
// *   +----------+- - -+-------------+- - -+-------- - -
// *   nlmsg_data(nlh)---^                   ^
// *   nlmsg_next(nlh)-----------------------+
// *
// *
// * Payload Format:
// *    <---------------------- nlmsg_len(nlh) --------------------->
// *    <------ hdrlen ------>       <- nlmsg_attrlen(nlh, hdrlen) ->
// *   +----------------------+- - -+--------------------------------+
// *   |     Family Header    | Pad |           Attributes           |
// *   +----------------------+- - -+--------------------------------+
// *   nlmsg_attrdata(nlh, hdrlen)---^
// *
// *
// * Attribute Format:
// *    <------- nla_total_size(payload) ------->
// *    <---- nla_attr_size(payload) ----->
// *   +----------+- - -+- - - - - - - - - +- - -+-------- - -
// *   |  Header  | Pad |     Payload      | Pad |  Header
// *   +----------+- - -+- - - - - - - - - +- - -+-------- - -
// *                     <- nla_len(nla) ->      ^
// *   nla_data(nla)----^                        |
// *   nla_next(nla)-----------------------------'
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct NetlinkMessageHeader {
    msg_len: u32,         // included header length
    msg_type: u16,           // depend on protocol
    msg_flags: u16,          // used by kernel
    msg_seq_num: u32, // kernel don't care about this
    msg_pid: u32,            // kernel don't care about this
}

impl NetlinkMessageHeader {
    const LENGTH: usize = mem::size_of::<NetlinkMessageHeader>();

    pub fn new(
        payload_len: usize,
        msg_type: u16,
        msg_flags: u16,
        msg_seq_num: u32,
        msg_pid: u32,
    ) -> Self {
        Self {
            msg_len: (Self::LENGTH + payload_len) as u32,
            msg_type,
            msg_flags,
            msg_seq_num,
            msg_pid,
        }
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, NetlinkError> {
        // check size
        if buf.len() < Self::LENGTH {
            return Err(NetlinkError::MsgHeaderErr);
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NetlinkProtocol {
    Route = 0,
    Unused = 1,
    Usersock = 2,
    Firewall = 3,
    SockDiag = 4,
    NetfilterUlog = 5,
    Xfrm = 6,
    SeLinux = 7,
    ISCSI = 8,
    Audit = 9,
    FIBLookup = 10,
    Connector = 11,
    Netfilter = 12,
    Ip6Firewall = 13,
    DecnetRoutingMsg = 14,
    KobjectUEvent = 15,
    Generic = 16,
    SCSITransport = 18,
    EcryptFs = 19,
    RDMA = 20,
    Crypto = 21,
    SMC = 22,
}

impl fmt::Display for NetlinkProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct NetlinkMessageType(u16);

impl NetlinkMessageType {
    pub fn new(value: u16) -> Self {
        Self(value)
    }
}

impl Into<u16> for NetlinkMessageType {
    fn into(self) -> u16 {
        self.0
    }
}

// each protocol can specifies more message types
// those are standard types
#[derive(Clone, Copy, Debug)]
pub enum StandardNetlinkMessageType {
    NOOP = 1,    // this message will be ignored
    ERROR = 2, // this message is an error, should be appended with original message unless user requested to cap the error message
    DONE = 3,  // this is the last part of multi-part message
    OVERRUN = 4, // dunno what is this
}

impl TryFrom<u16> for StandardNetlinkMessageType {
    type Error = ();

    fn try_from(value: u16) -> Result<StandardNetlinkMessageType, Self::Error> {
        match value {
            x if x == Self::NOOP as u16 => Ok(Self::NOOP),
            x if x == Self::ERROR as u16 => Ok(Self::ERROR),
            x if x == Self::DONE as u16 => Ok(Self::DONE),
            x if x == Self::OVERRUN as u16 => Ok(Self::OVERRUN),
            _ => Err(()),
        }
    }
}

impl Into<NetlinkMessageType> for StandardNetlinkMessageType {
    fn into(self) -> NetlinkMessageType {
        NetlinkMessageType::new(self as u16)
    }
}

#[derive(Clone, Debug)]
pub enum NetlinkMessagePayload {
    GENERIC(GenericNetlinkMessage),
    UNIMPLEMENTED,
}

impl NetlinkMessagePayload {
    const ALIGN: usize = 4;

    pub fn to_byte_array(&self) -> Vec<u8> {
        match self {
            Self::GENERIC(generic_payload) => generic_payload.to_byte_array(),
            Self::UNIMPLEMENTED => panic!("Unimplemented netlink message payload"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[allow(unused)]
pub enum NetlinkMessagePayloadType {
    Generic,
    Unimplemented,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
pub enum NetlinkMessageFlag {
    // normal flags
    Request,           // It is request message
    Multipart,         // Multipart message, terminated by NLMSG_DONE
    Ack,               // Reply with ack, with zero or error code
    Echo,              // Echo this request
    DumpInconsistent, // Dump was inconsistent due to sequence change
    DumpFiltered,     // Dump was filtered as requested

    // Modifiers to GET request
    Root,   // specify tree	root
    Match,  // return all matching
    Atomic, // atomic GET
    Dump,

    // Modifiers to NEW request
    Replace, // Override existing
    Excl,    // Do not touch, if it exists
    Create,  // Create, if it does not exist
    Append,  // Add to end of list

    // Modifiers to DELETE request
    NoRecursive, // Do not delete recursively

    // Flags for ACK message
    Capped,   // request was capped
    AckTlvs, // extended ACK TVLs were included
}

impl NetlinkMessageFlag {
    const REQUEST_VALUE: u16 = 0x01;
    const MULTIPART_VALUE: u16 = 0x02;
    const ACK_VALUE: u16 = 0x04;
    const ECHO_VALUE: u16 = 0x08;
    const DUMP_INCONSISTENT_VALUE: u16 = 0x10;
    const DUMP_FILTERED_VALUE: u16 = 0x20;

    const ROOT_VALUE: u16 = 0x100;
    const MATCH_VALUE: u16 = 0x200;
    const ATOMIC_VALUE: u16 = 0x400;
    const DUMP_VALUE: u16 = (Self::ROOT_VALUE | Self::MATCH_VALUE);

    const REPLACE_VALUE: u16 = 0x100;
    const EXCL_VALUE: u16 = 0x200;
    const CREATE_VALUE: u16 = 0x400;
    const APPEND_VALUE: u16 = 0x800;

    const NO_RECURSIVE_VALUE: u16 = 0x100;

    const CAPPED_VALUE: u16 = 0x100;
    const ACK_TLVS_VALUE: u16 = 0x200;

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Request => Self::REQUEST_VALUE,
            Self::Multipart => Self::MULTIPART_VALUE,
            Self::Ack => Self::ACK_VALUE,
            Self::Echo => Self::ECHO_VALUE,
            Self::DumpInconsistent => Self::DUMP_INCONSISTENT_VALUE,
            Self::DumpFiltered => Self::DUMP_FILTERED_VALUE,
            Self::Root => Self::ROOT_VALUE,
            Self::Match => Self::MATCH_VALUE,
            Self::Atomic => Self::ATOMIC_VALUE,
            Self::Dump => Self::DUMP_VALUE,
            Self::Replace => Self::REPLACE_VALUE,
            Self::Excl => Self::EXCL_VALUE,
            Self::Create => Self::CREATE_VALUE,
            Self::Append => Self::APPEND_VALUE,
            Self::NoRecursive => Self::NO_RECURSIVE_VALUE,
            Self::Capped => Self::CAPPED_VALUE,
            Self::AckTlvs => Self::ACK_TLVS_VALUE,
        }
    }

    pub fn from_u16(value: u16) -> Result<Vec<Self>, NetlinkError> {
        let mut result = Vec::new();
        let mut tmp = 0;

        if value & Self::REQUEST_VALUE != 0 {
            result.push(Self::Request);
            tmp |= Self::REQUEST_VALUE;
        }

        if value & Self::MULTIPART_VALUE != 0 {
            result.push(Self::Multipart);
            tmp |= Self::MULTIPART_VALUE;
        }

        if value & Self::ACK_VALUE != 0 {
            result.push(Self::Ack);
            tmp |= Self::ACK_VALUE;
        }

        if value & Self::ECHO_VALUE != 0 {
            result.push(Self::Echo);
            tmp |= Self::ECHO_VALUE;
        }

        if value & Self::DUMP_INCONSISTENT_VALUE != 0 {
            result.push(Self::DumpInconsistent);
            tmp |= Self::DUMP_INCONSISTENT_VALUE;
        }

        if value & Self::DUMP_FILTERED_VALUE != 0 {
            result.push(Self::DumpFiltered);
            tmp |= Self::DUMP_FILTERED_VALUE;
        }

        if value & Self::ROOT_VALUE != 0 {
            result.push(Self::Root);
            tmp |= Self::ROOT_VALUE;
        }

        if value & Self::MATCH_VALUE != 0 {
            result.push(Self::Match);
            tmp |= Self::MATCH_VALUE;
        }

        if value & Self::ATOMIC_VALUE != 0 {
            result.push(Self::Atomic);
            tmp |= Self::ATOMIC_VALUE;
        }

        if value & Self::DUMP_VALUE != 0 {
            result.push(Self::Dump);
            tmp |= Self::DUMP_VALUE;
        }

        if value & Self::REPLACE_VALUE != 0 {
            result.push(Self::Replace);
            tmp |= Self::REPLACE_VALUE;
        }

        if value & Self::EXCL_VALUE != 0 {
            result.push(Self::Excl);
            tmp |= Self::EXCL_VALUE;
        }

        if value & Self::CREATE_VALUE != 0 {
            result.push(Self::Create);
            tmp |= Self::CREATE_VALUE;
        }

        if value & Self::APPEND_VALUE != 0 {
            result.push(Self::Append);
            tmp |= Self::APPEND_VALUE;
        }

        if value & Self::NO_RECURSIVE_VALUE != 0 {
            result.push(Self::NoRecursive);
            tmp |= Self::NO_RECURSIVE_VALUE;
        }

        if value & Self::CAPPED_VALUE != 0 {
            result.push(Self::Capped);
            tmp |= Self::CAPPED_VALUE;
        }

        if value & Self::ACK_TLVS_VALUE != 0 {
            result.push(Self::AckTlvs);
            tmp |= Self::ACK_TLVS_VALUE;
        }

        if tmp != value {
            return Err(NetlinkError::UnknownMsgFlags(tmp ^ value));
        }

        Ok(result)
    }
}

#[derive(Clone, Debug)]
pub struct NetlinkMessage {
    msg_type: NetlinkMessageType,
    flags: Vec<NetlinkMessageFlag>,
    payload: NetlinkMessagePayload,
}

#[allow(unused)]
impl NetlinkMessage {
    pub const ALIGN: usize = 4;

    pub fn new(
        msg_type: NetlinkMessageType,
        flags: &[NetlinkMessageFlag],
        payload: NetlinkMessagePayload,
    ) -> Self {
        Self {
            msg_type,
            flags: flags.to_vec(),
            payload,
        }
    }

    pub fn get_type(&self) -> NetlinkMessagePayloadType {
        match self.payload {
            NetlinkMessagePayload::GENERIC(_) => NetlinkMessagePayloadType::Generic,
            NetlinkMessagePayload::UNIMPLEMENTED => NetlinkMessagePayloadType::Unimplemented,
        }
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        let mut payload = self.payload.to_byte_array();

        let mut flags = 0;
        for flag in &self.flags {
            flags |= flag.to_u16();
        }

        let header = NetlinkMessageHeader::new(payload.len(), self.msg_type.into(), flags, 0, 0);

        result.append(&mut header.to_byte_array());
        common::align_buffer(&mut result, NetlinkMessagePayload::ALIGN);
        result.append(&mut payload);
        result
    }

    pub fn from_byte_array(
        buf: &[u8],
        payload_type: NetlinkMessagePayloadType,
    ) -> Result<Self, NetlinkError> {
        let netlink_msg_header = NetlinkMessageHeader::from_byte_array(&buf)?;
        let payload_start_idx =
            common::next_align_num(NetlinkMessageHeader::LENGTH, NetlinkMessagePayload::ALIGN);

        let payload_size = netlink_msg_header.msg_len as usize - payload_start_idx;
        let flags = NetlinkMessageFlag::from_u16(netlink_msg_header.msg_flags)?;

        // check for error message
        if let Ok(StandardNetlinkMessageType::ERROR) = netlink_msg_header.msg_type.try_into() {
            let err_code = i32::from_ne_bytes(
                buf[payload_start_idx..payload_start_idx + 4]
                    .try_into()
                    .unwrap(),
            );
            return Err(NetlinkError::KernelErr(err_code));
        }

        match payload_type {
            NetlinkMessagePayloadType::Generic => {
                let msg_type = GenericNetlinkMessageType::new(netlink_msg_header.msg_type);
                let payload = GenericNetlinkMessage::from_byte_array(
                    &buf[payload_start_idx..payload_start_idx + payload_size],
                    msg_type,
                )?;
                Ok(NetlinkMessage::new(
                    msg_type.into(),
                    &flags,
                    NetlinkMessagePayload::GENERIC(payload),
                ))
            }
            NetlinkMessagePayloadType::Unimplemented => {
                panic!("Unimplemented netlink message payload type")
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct NetlinkAttributeHeader {
    length: u16,
    attr_type: u16,
}

#[allow(unused)]
impl NetlinkAttributeHeader {
    const LENGTH: usize = mem::size_of::<NetlinkAttributeHeader>();

    pub fn new(payload_len: usize, attr_type: NetlinkMessageAttributeType) -> Self {
        Self {
            length: (payload_len + Self::LENGTH) as u16,
            attr_type: attr_type.into(),
        }
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, NetlinkError> {
        // check size
        if buf.len() < Self::LENGTH {
            return Err(NetlinkError::AttrHeaderErr);
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetlinkMessageAttributeType(u16);

impl NetlinkMessageAttributeType {
    pub fn new(value: u16) -> Self {
        Self(value)
    }
}

impl Into<u16> for NetlinkMessageAttributeType {
    fn into(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug)]
#[allow(unused)]
pub struct NetlinkMessageAttribute {
    attr_type: NetlinkMessageAttributeType,
    payload: Vec<u8>,
}

#[allow(unused)]
impl NetlinkMessageAttribute {
    const PAYLOAD_ALIGN: usize = 4;

    pub fn to_byte_array(&self) -> Vec<u8> {
        unimplemented!();
    }
}

#[derive(Debug)]
#[allow(unused)]
pub struct NetlinkConnection {
    socket: Socket,
    self_addr: SocketAddr,
    protocol: NetlinkProtocol,
}

impl NetlinkConnection {
    const BUFFER_SIZE: usize = 1024;

    pub fn new(protocol: NetlinkProtocol) -> Result<Self, NetlinkError> {
        let mut socket = Socket::new(protocols::NETLINK_GENERIC)?;
        let self_addr = socket.bind_auto()?;

        Ok(Self {
            socket,
            self_addr,
            protocol,
        })
    }

    pub fn send(&self, message: NetlinkMessage) -> Result<(), NetlinkError> {
        self.socket.send(&message.to_byte_array(), 0)?;
        Ok(())
    }

    pub fn recv(&self) -> Result<NetlinkMessage, NetlinkError> {
        let mut buf = vec![0; Self::BUFFER_SIZE];
        self.socket.recv(&mut buf, 0)?;

        let payload_type = match self.protocol {
            NetlinkProtocol::Generic => NetlinkMessagePayloadType::Generic,
            _ => return Err(NetlinkError::UnsupportedProtocol(self.protocol)),
        };

        NetlinkMessage::from_byte_array(&buf, payload_type)
    }
}

#[derive(Debug)]
pub enum NetlinkError {
    IOErr(io::Error),
    GenericErr(Box<GenericError>),
    MsgHeaderErr,
    AttrHeaderErr,
    UnknownMsgFlags(u16),
    UnsupportedProtocol(NetlinkProtocol),
    KernelErr(i32),
}

impl error::Error for NetlinkError {}

impl fmt::Display for NetlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::IOErr(error) => String::from(format!("IO error: {}", error)),
            Self::GenericErr(error) => String::from(format!("Generic netlink error: {}", error)),
            Self::MsgHeaderErr => String::from(format!("Message header error")),
            Self::AttrHeaderErr => String::from(format!("Attribute header error")),
            Self::UnknownMsgFlags(flags) => {
                String::from(format!("Unknown netlink message flags: {}", flags))
            }
            Self::UnsupportedProtocol(protocol) => {
                String::from(format!("Unsupported protocol: {:?}", protocol))
            }
            Self::KernelErr(err_code) => {
                String::from(format!("Kernel error code: {}", err_code))
            }
        };

        write!(f, "{}", result)
    }
}

impl From<io::Error> for NetlinkError {
    fn from(error: io::Error) -> Self {
        Self::IOErr(error)
    }
}

impl From<GenericError> for NetlinkError {
    fn from(error: GenericError) -> Self {
        Self::GenericErr(Box::new(error))
    }
}
