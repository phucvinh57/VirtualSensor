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
    messageLength: u32,         // included header length
    messageType: u16,           // depend on protocol
    messageFlags: u16,          // used by kernel
    messageSequenceNumber: u32, // kernel don't care about this
    messagePid: u32,            // kernel don't care about this
}

impl NetlinkMessageHeader {
    const LENGTH: usize = mem::size_of::<NetlinkMessageHeader>();

    pub fn New(
        payloadLength: usize,
        messageType: u16,
        messageFlags: u16,
        messageSequenceNumber: u32,
        messagePid: u32,
    ) -> Self {
        Self {
            messageLength: (Self::LENGTH + payloadLength) as u32,
            messageType,
            messageFlags,
            messageSequenceNumber,
            messagePid,
        }
    }

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, NetlinkError> {
        // check size
        if buf.len() < Self::LENGTH {
            return Err(NetlinkError::MESSAGE_HEADER_ERROR);
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NetlinkProtocol {
    ROUTE = 0,
    UNUSED = 1,
    USERSOCK = 2,
    FIREWALL = 3,
    SOCK_DIAG = 4,
    NETFILTER_ULOG = 5,
    XFRM = 6,
    SELINUX = 7,
    ISCSI = 8,
    AUDIT = 9,
    FIB_LOOKUP = 10,
    CONNECTOR = 11,
    NETFILTER = 12,
    IP6_FIREWALL = 13,
    DECNET_ROUTING_MESSAGE = 14,
    KOBJECT_UEVENT = 15,
    GENERIC = 16,
    SCSI_TRANSPORT = 18,
    ECRYPTFS = 19,
    RDMA = 20,
    CRYPTO = 21,
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
    pub fn New(value: u16) -> Self {
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
        NetlinkMessageType::New(self as u16)
    }
}

#[derive(Clone, Debug)]
pub enum NetlinkMessagePayload {
    GENERIC(GenericNetlinkMessage),
    UNIMPLEMENTED,
}

impl NetlinkMessagePayload {
    const ALIGN: usize = 4;

    pub fn ToByteArray(&self) -> Vec<u8> {
        match self {
            Self::GENERIC(genericPayload) => genericPayload.ToByteArray(),
            Self::UNIMPLEMENTED => panic!("Unimplemented netlink message payload"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NetlinkMessagePayloadType {
    GENERIC,
    UNIMPLEMENTED,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
pub enum NetlinkMessageFlag {
    // normal flags
    REQUEST,           // It is request message
    MULTIPART,         // Multipart message, terminated by NLMSG_DONE
    ACK,               // Reply with ack, with zero or error code
    ECHO,              // Echo this request
    DUMP_INCONSISTENT, // Dump was inconsistent due to sequence change
    DUMP_FILTERED,     // Dump was filtered as requested

    // Modifiers to GET request
    ROOT,   // specify tree	root
    MATCH,  // return all matching
    ATOMIC, // atomic GET
    DUMP,

    // Modifiers to NEW request
    REPLACE, // Override existing
    EXCL,    // Do not touch, if it exists
    CREATE,  // Create, if it does not exist
    APPEND,  // Add to end of list

    // Modifiers to DELETE request
    NO_RECURSIVE, // Do not delete recursively

    // Flags for ACK message
    CAPPED,   // request was capped
    ACK_TLVS, // extended ACK TVLs were included
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

    pub fn ToU16(&self) -> u16 {
        match self {
            Self::REQUEST => Self::REQUEST_VALUE,
            Self::MULTIPART => Self::MULTIPART_VALUE,
            Self::ACK => Self::ACK_VALUE,
            Self::ECHO => Self::ECHO_VALUE,
            Self::DUMP_INCONSISTENT => Self::DUMP_INCONSISTENT_VALUE,
            Self::DUMP_FILTERED => Self::DUMP_FILTERED_VALUE,
            Self::ROOT => Self::ROOT_VALUE,
            Self::MATCH => Self::MATCH_VALUE,
            Self::ATOMIC => Self::ATOMIC_VALUE,
            Self::DUMP => Self::DUMP_VALUE,
            Self::REPLACE => Self::REPLACE_VALUE,
            Self::EXCL => Self::EXCL_VALUE,
            Self::CREATE => Self::CREATE_VALUE,
            Self::APPEND => Self::APPEND_VALUE,
            Self::NO_RECURSIVE => Self::NO_RECURSIVE_VALUE,
            Self::CAPPED => Self::CAPPED_VALUE,
            Self::ACK_TLVS => Self::ACK_TLVS_VALUE,
        }
    }

    pub fn FromU16(value: u16) -> Result<Vec<Self>, NetlinkError> {
        let mut result = Vec::new();
        let mut tmp = 0;

        if value & Self::REQUEST_VALUE != 0 {
            result.push(Self::REQUEST);
            tmp |= Self::REQUEST_VALUE;
        }

        if value & Self::MULTIPART_VALUE != 0 {
            result.push(Self::MULTIPART);
            tmp |= Self::MULTIPART_VALUE;
        }

        if value & Self::ACK_VALUE != 0 {
            result.push(Self::ACK);
            tmp |= Self::ACK_VALUE;
        }

        if value & Self::ECHO_VALUE != 0 {
            result.push(Self::ECHO);
            tmp |= Self::ECHO_VALUE;
        }

        if value & Self::DUMP_INCONSISTENT_VALUE != 0 {
            result.push(Self::DUMP_INCONSISTENT);
            tmp |= Self::DUMP_INCONSISTENT_VALUE;
        }

        if value & Self::DUMP_FILTERED_VALUE != 0 {
            result.push(Self::DUMP_FILTERED);
            tmp |= Self::DUMP_FILTERED_VALUE;
        }

        if value & Self::ROOT_VALUE != 0 {
            result.push(Self::ROOT);
            tmp |= Self::ROOT_VALUE;
        }

        if value & Self::MATCH_VALUE != 0 {
            result.push(Self::MATCH);
            tmp |= Self::MATCH_VALUE;
        }

        if value & Self::ATOMIC_VALUE != 0 {
            result.push(Self::ATOMIC);
            tmp |= Self::ATOMIC_VALUE;
        }

        if value & Self::DUMP_VALUE != 0 {
            result.push(Self::DUMP);
            tmp |= Self::DUMP_VALUE;
        }

        if value & Self::REPLACE_VALUE != 0 {
            result.push(Self::REPLACE);
            tmp |= Self::REPLACE_VALUE;
        }

        if value & Self::EXCL_VALUE != 0 {
            result.push(Self::EXCL);
            tmp |= Self::EXCL_VALUE;
        }

        if value & Self::CREATE_VALUE != 0 {
            result.push(Self::CREATE);
            tmp |= Self::CREATE_VALUE;
        }

        if value & Self::APPEND_VALUE != 0 {
            result.push(Self::APPEND);
            tmp |= Self::APPEND_VALUE;
        }

        if value & Self::NO_RECURSIVE_VALUE != 0 {
            result.push(Self::NO_RECURSIVE);
            tmp |= Self::NO_RECURSIVE_VALUE;
        }

        if value & Self::CAPPED_VALUE != 0 {
            result.push(Self::CAPPED);
            tmp |= Self::CAPPED_VALUE;
        }

        if value & Self::ACK_TLVS_VALUE != 0 {
            result.push(Self::ACK_TLVS);
            tmp |= Self::ACK_TLVS_VALUE;
        }

        if tmp != value {
            return Err(NetlinkError::UNKNOWN_MESSAGE_FLAGS(tmp ^ value));
        }

        Ok(result)
    }
}

#[derive(Clone, Debug)]
pub struct NetlinkMessage {
    messageType: NetlinkMessageType,
    flags: Vec<NetlinkMessageFlag>,
    payload: NetlinkMessagePayload,
}

impl NetlinkMessage {
    pub const ALIGN: usize = 4;

    pub fn New(
        messageType: NetlinkMessageType,
        flags: &[NetlinkMessageFlag],
        payload: NetlinkMessagePayload,
    ) -> Self {
        Self {
            messageType,
            flags: flags.to_vec(),
            payload,
        }
    }

    pub fn Type(&self) -> NetlinkMessagePayloadType {
        match self.payload {
            NetlinkMessagePayload::GENERIC(_) => NetlinkMessagePayloadType::GENERIC,
            NetlinkMessagePayload::UNIMPLEMENTED => NetlinkMessagePayloadType::UNIMPLEMENTED,
        }
    }

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        let mut payload = self.payload.ToByteArray();

        let mut flags = 0;
        for flag in &self.flags {
            flags |= flag.ToU16();
        }

        let header = NetlinkMessageHeader::New(payload.len(), self.messageType.into(), flags, 0, 0);

        result.append(&mut header.ToByteArray());
        common::AlignBuffer(&mut result, NetlinkMessagePayload::ALIGN);
        result.append(&mut payload);
        result
    }

    pub fn FromByteArray(
        buf: &[u8],
        payloadType: NetlinkMessagePayloadType,
    ) -> Result<Self, NetlinkError> {
        let netlinkMessageHeader = NetlinkMessageHeader::FromByteArray(&buf)?;
        let payloadStartIndex =
            common::NextAlignNumber(NetlinkMessageHeader::LENGTH, NetlinkMessagePayload::ALIGN);

        println!("{:?}", netlinkMessageHeader.messageLength as u32); // 0
        println!("{:?}", payloadStartIndex as u32);

        let payloadSize = netlinkMessageHeader.messageLength as usize - payloadStartIndex;
        let flags = NetlinkMessageFlag::FromU16(netlinkMessageHeader.messageFlags)?;

        // check for error message
        if let Ok(StandardNetlinkMessageType::ERROR) = netlinkMessageHeader.messageType.try_into() {
            let errorCode = i32::from_ne_bytes(
                buf[payloadStartIndex..payloadStartIndex + 4]
                    .try_into()
                    .unwrap(),
            );
            return Err(NetlinkError::KERNEL_ERROR(errorCode));
        }

        match payloadType {
            NetlinkMessagePayloadType::GENERIC => {
                let messageType = GenericNetlinkMessageType::New(netlinkMessageHeader.messageType);
                let payload = GenericNetlinkMessage::FromByteArray(
                    &buf[payloadStartIndex..payloadStartIndex + payloadSize],
                    messageType,
                )?;
                Ok(NetlinkMessage::New(
                    messageType.into(),
                    &flags,
                    NetlinkMessagePayload::GENERIC(payload),
                ))
            }
            NetlinkMessagePayloadType::UNIMPLEMENTED => {
                panic!("Unimplemented netlink message payload type")
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct NetlinkAttributeHeader {
    length: u16,
    attributeType: u16,
}

impl NetlinkAttributeHeader {
    const LENGTH: usize = mem::size_of::<NetlinkAttributeHeader>();

    pub fn New(payloadLength: usize, attributeType: NetlinkMessageAttributeType) -> Self {
        Self {
            length: (payloadLength + Self::LENGTH) as u16,
            attributeType: attributeType.into(),
        }
    }

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, NetlinkError> {
        // check size
        if buf.len() < Self::LENGTH {
            return Err(NetlinkError::ATTRIBUTE_HEADER_ERROR);
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetlinkMessageAttributeType(u16);

impl NetlinkMessageAttributeType {
    pub fn New(value: u16) -> Self {
        Self(value)
    }
}

impl Into<u16> for NetlinkMessageAttributeType {
    fn into(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct NetlinkMessageAttribute {
    attributeType: NetlinkMessageAttributeType,
    payload: Vec<u8>,
}

impl NetlinkMessageAttribute {
    const PAYLOAD_ALIGN: usize = 4;

    pub fn ToByteArray(&self) -> Vec<u8> {
        unimplemented!();
    }
}

#[derive(Debug)]
pub struct NetlinkConnection {
    socket: Socket,
    selfAddress: SocketAddr,
    protocol: NetlinkProtocol,
}

impl NetlinkConnection {
    const BUFFER_SIZE: usize = 1024;

    pub fn New(protocol: NetlinkProtocol) -> Result<Self, NetlinkError> {
        let mut socket = Socket::new(protocols::NETLINK_GENERIC)?;
        let selfAddress = socket.bind_auto()?;

        Ok(Self {
            socket,
            selfAddress,
            protocol,
        })
    }

    pub fn Send(&self, message: NetlinkMessage) -> Result<(), NetlinkError> {
        self.socket.send(&message.ToByteArray(), 0)?;
        Ok(())
    }

    pub fn Recv(&self) -> Result<NetlinkMessage, NetlinkError> {
        let mut buf = [0u8; Self::BUFFER_SIZE];
        self.socket.recv(&mut buf, 0)?;

        let payloadType = match self.protocol {
            NetlinkProtocol::GENERIC => NetlinkMessagePayloadType::GENERIC,
            _ => return Err(NetlinkError::UNSUPPORTED_PROTOCOL(self.protocol)),
        };

        NetlinkMessage::FromByteArray(&buf, payloadType)
    }
}

#[derive(Debug)]
pub enum NetlinkError {
    IO_ERROR(io::Error),
    GENERIC_ERROR(Box<GenericError>),
    MESSAGE_HEADER_ERROR,
    ATTRIBUTE_HEADER_ERROR,
    UNKNOWN_MESSAGE_FLAGS(u16),
    UNSUPPORTED_PROTOCOL(NetlinkProtocol),
    KERNEL_ERROR(i32),
}

impl error::Error for NetlinkError {}

impl fmt::Display for NetlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::IO_ERROR(error) => String::from(format!("IO error: {}", error)),
            Self::GENERIC_ERROR(error) => String::from(format!("Generic netlink error: {}", error)),
            Self::MESSAGE_HEADER_ERROR => String::from(format!("Message header error")),
            Self::ATTRIBUTE_HEADER_ERROR => String::from(format!("Attribute header error")),
            Self::UNKNOWN_MESSAGE_FLAGS(flags) => {
                String::from(format!("Unknown netlink message flags: {}", flags))
            }
            Self::UNSUPPORTED_PROTOCOL(protocol) => {
                String::from(format!("Unsupported protocol: {:?}", protocol))
            }
            Self::KERNEL_ERROR(errorCode) => {
                String::from(format!("Kernel error code: {}", errorCode))
            }
        };

        write!(f, "{}", result)
    }
}

impl From<io::Error> for NetlinkError {
    fn from(error: io::Error) -> Self {
        Self::IO_ERROR(error)
    }
}

impl From<GenericError> for NetlinkError {
    fn from(error: GenericError) -> Self {
        Self::GENERIC_ERROR(Box::new(error))
    }
}
