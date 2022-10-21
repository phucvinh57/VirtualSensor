use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::str::Utf8Error;
use std::{fmt, mem, slice, str};

use crate::common;
use crate::netlink::{
    NetlinkAttributeHeader, NetlinkMessageAttribute, NetlinkMessageAttributeType,
	NetlinkConnection, NetlinkError, NetlinkProtocol,
	NetlinkMessage, NetlinkMessageType,
	NetlinkMessageFlag, NetlinkMessagePayload
};

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct GenericNetlinkMessageHeader {
    command: u8,
    version: u8,
    reserved: u16,
}

impl GenericNetlinkMessageHeader {
    const LENGTH: usize = mem::size_of::<GenericNetlinkMessageHeader>();

    pub fn new(command: u8, version: u8) -> Self {
        Self {
            command,
            version,
            reserved: 0,
        }
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, GenericError> {
        // check size
        if buf.len() < Self::LENGTH {
            return Err(GenericError::HeaderErr(buf.to_vec()));
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericNetlinkMessageCommand(u8);

impl GenericNetlinkMessageCommand {
    pub fn new(value: u8) -> Self {
        Self(value)
    }
}

impl Into<u8> for GenericNetlinkMessageCommand {
    fn into(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericNetlinkMessageType(u16);

impl GenericNetlinkMessageType {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }
}

impl Into<NetlinkMessageType> for GenericNetlinkMessageType {
    fn into(self) -> NetlinkMessageType {
        NetlinkMessageType::new(self.0)
    }
}

impl Into<u16> for GenericNetlinkMessageType {
    fn into(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct GenericNetlinkMessageAttribute {
    attribute_type: GenericNetlinkMessageAttributeType,
    pub payload: Vec<u8>,
}

impl GenericNetlinkMessageAttribute {
    const ALIGN: usize = 4;
    const PAYLOAD_ALIGN: usize = 4;

    pub fn new(attribute_type: GenericNetlinkMessageAttributeType, payload: Vec<u8>) -> Self {
        Self {
            attribute_type,
            payload,
        }
    }

    pub fn get_type(&self) -> GenericNetlinkMessageAttributeType {
        self.attribute_type
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let header = NetlinkAttributeHeader::new(self.payload.len(), self.attribute_type.into());
        result.append(&mut header.ToByteArray());
        common::align_buffer(&mut result, Self::PAYLOAD_ALIGN);
        result.extend_from_slice(&self.payload[..]);
        result
    }

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, GenericError> {
        let attribute_type = GenericNetlinkMessageAttributeType::new(u16::from_ne_bytes(
            buf[2..4].try_into().unwrap(),
        ));

        Ok(Self {
            attribute_type,
            payload: buf[4..].to_vec(),
        })
    }
}

impl Into<NetlinkMessageAttribute> for GenericNetlinkMessageAttribute {
    fn into(self) -> NetlinkMessageAttribute {
        unimplemented!();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericNetlinkMessageAttributeType(u16);

impl GenericNetlinkMessageAttributeType {
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl Into<NetlinkMessageAttributeType> for GenericNetlinkMessageAttributeType {
    fn into(self) -> NetlinkMessageAttributeType {
        NetlinkMessageAttributeType::New(self.0)
    }
}

impl Into<u16> for GenericNetlinkMessageAttributeType {
    fn into(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct GenericNetlinkMessage {
    message_type: GenericNetlinkMessageType,
    command: GenericNetlinkMessageCommand,
    version: usize,
    pub attributes: Vec<GenericNetlinkMessageAttribute>,
}

impl GenericNetlinkMessage {
    const VERSION: usize = 2;
    const ATTRIBUTE_ALIGN: usize = 4;

    pub fn new(
        message_type: GenericNetlinkMessageType,
        command: GenericNetlinkMessageCommand,
    ) -> Self {
        Self {
            message_type,
            command,
            version: Self::VERSION,
            attributes: Vec::new(),
        }
    }

    pub fn get_message_type(&self) -> GenericNetlinkMessageType {
        self.message_type
    }
    pub fn get_command(&self) -> GenericNetlinkMessageCommand {
        self.command
    }

    pub fn add_attr(&mut self, attribute: GenericNetlinkMessageAttribute) {
        self.attributes.push(attribute)
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // make header
        let header = GenericNetlinkMessageHeader::new(self.command.into(), self.version as u8);

        // append header
        result.append(&mut header.to_byte_array());

        // append all attributes
        for attr in &self.attributes {
            common::align_buffer(&mut result, GenericNetlinkMessageAttribute::ALIGN);
            result.append(&mut attr.to_byte_array());
        }

        result
    }

    pub fn from_byte_array(
        buf: &[u8],
        message_type: GenericNetlinkMessageType,
    ) -> Result<Self, GenericError> {
        let generic_msg_header = GenericNetlinkMessageHeader::from_byte_array(&buf)?;

        let mut generic_netlink_msg = GenericNetlinkMessage::new(
            message_type,
            GenericNetlinkMessageCommand::new(generic_msg_header.command),
        );

        // attribute start index
        let mut attr_curr_idx = common::next_align_num(
            GenericNetlinkMessageHeader::LENGTH,
            GenericNetlinkMessage::ATTRIBUTE_ALIGN,
        );

        while attr_curr_idx < buf.len() {
            let curr_attr_size = u16::from_ne_bytes(
                buf[attr_curr_idx..attr_curr_idx + 2]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let curr_attr = GenericNetlinkMessageAttribute::from_byte_array(
                &buf[attr_curr_idx..attr_curr_idx + curr_attr_size],
            )?;
            attr_curr_idx = common::next_align_num(
                attr_curr_idx + curr_attr_size,
                GenericNetlinkMessage::ATTRIBUTE_ALIGN,
            );

            generic_netlink_msg.add_attr(curr_attr.into());
        }

        Ok(generic_netlink_msg)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericNetlinkControlMessageCommand {
    Unspecified = 0,
    NewFamily = 1,
    DeleteFamily = 2,
    GetFamilyId = 3,
    NewOperation = 4,
    DeleteOperation = 5,
    GetOperation = 6,
    NewMulticastGroup = 7,
    DeleteMulticastGroup = 8,
    GetMulticastGroup = 9,
    GetPolicy = 10,
}

impl Into<GenericNetlinkMessageCommand> for GenericNetlinkControlMessageCommand {
    fn into(self) -> GenericNetlinkMessageCommand {
        GenericNetlinkMessageCommand::new(self as u8)
    }
}

impl TryFrom<GenericNetlinkMessageCommand> for GenericNetlinkControlMessageCommand {
    type Error = GenericError;

    fn try_from(
        generic_netlink_msg_cmd: GenericNetlinkMessageCommand,
    ) -> Result<Self, Self::Error> {
        match generic_netlink_msg_cmd {
            x if x == Self::Unspecified.into() => Ok(Self::Unspecified),
            x if x == Self::NewFamily.into() => Ok(Self::NewFamily),
            x if x == Self::DeleteFamily.into() => Ok(Self::DeleteFamily),
            x if x == Self::GetFamilyId.into() => Ok(Self::GetFamilyId),
            x if x == Self::NewOperation.into() => Ok(Self::NewOperation),
            x if x == Self::DeleteOperation.into() => Ok(Self::DeleteOperation),
            x if x == Self::GetOperation.into() => Ok(Self::GetOperation),
            x if x == Self::NewMulticastGroup.into() => Ok(Self::NewMulticastGroup),
            x if x == Self::DeleteMulticastGroup.into() => Ok(Self::DeleteMulticastGroup),
            x if x == Self::GetMulticastGroup.into() => Ok(Self::GetMulticastGroup),
            x if x == Self::GetPolicy.into() => Ok(Self::GetPolicy),
            _ => Err(GenericError::UnknownControlCommand(
                generic_netlink_msg_cmd,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenericNetlinkControlMessageOpAttributeComponent {
    UNSPECIFIED,
    ID(u32),
    FLAGS(u32),
}

impl GenericNetlinkControlMessageOpAttributeComponent {
    const SIZE: usize = 8;

    const UNSPECIFIED_VALUE: u16 = 0;
    const ID_VALUE: u16 = 1;
    const FLAGS_VALUE: u16 = 2;

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, GenericError> {
        // check size
        // u16::from_ne_bytes (buf[2..4].try_into ().unwrap ())
        let size = u16::from_ne_bytes(buf[0..2].try_into().unwrap()) as usize;
        let component_type = u16::from_ne_bytes(buf[2..4].try_into().unwrap());

        if size != Self::SIZE {
            return Err(GenericError::OpAttrComponentErr(buf.to_vec()));
        }

        match component_type {
            Self::UNSPECIFIED_VALUE => Ok(Self::UNSPECIFIED),
            Self::ID_VALUE => Ok(Self::ID(u32::from_ne_bytes(buf[4..8].try_into().unwrap()))),
            Self::FLAGS_VALUE => Ok(Self::FLAGS(u32::from_ne_bytes(
                buf[4..8].try_into().unwrap(),
            ))),
            _ => Err(GenericError::OpAttrComponentErr(buf.to_vec())),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum GenericNetlinkControlMessageOpAttributeFlag {
    VALUE(u32),
}

impl GenericNetlinkControlMessageOpAttributeFlag {
    pub fn from_u32(value: u32) -> Result<Vec<Self>, GenericError> {
        Ok([Self::VALUE(value)].to_vec())
    }
}

#[derive(Clone, Debug)]
#[allow(unused)]
pub struct GenericNetlinkControlMessageOpAttribute {
    id: u32,
    flags: Vec<GenericNetlinkControlMessageOpAttributeFlag>,
}

impl GenericNetlinkControlMessageOpAttribute {
    const SIZE: usize = 16;

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, GenericError> {
        // check size
        if buf.len() < Self::SIZE {
            return Err(GenericError::OpAttrErr(buf.to_vec()));
        }

        let first_com =
            GenericNetlinkControlMessageOpAttributeComponent::from_byte_array(&buf[0..8])?;
        let second_com =
            GenericNetlinkControlMessageOpAttributeComponent::from_byte_array(&buf[8..16])?;

        match (first_com, second_com) {
            (
                GenericNetlinkControlMessageOpAttributeComponent::ID(id),
                GenericNetlinkControlMessageOpAttributeComponent::FLAGS(flags),
            ) => Ok(Self {
                id,
                flags: GenericNetlinkControlMessageOpAttributeFlag::from_u32(flags)?,
            }),
            (
                GenericNetlinkControlMessageOpAttributeComponent::FLAGS(flags),
                GenericNetlinkControlMessageOpAttributeComponent::ID(id),
            ) => Ok(Self {
                id,
                flags: GenericNetlinkControlMessageOpAttributeFlag::from_u32(flags)?,
            }),
            _ => return Err(GenericError::OpAttrErr(buf.to_vec())),
        }
    }
}

#[derive(Clone, Debug)]
#[allow(unused)]
pub enum GenericNetlinkControlMessageAttribute {
    Unspecified,
    FamilyName(String),
    FamilyId(u16),
    Version(u32),
    HeaderSize(u32),
    MaxAttr(u32),
    Ops(Vec<GenericNetlinkControlMessageOpAttribute>),
}

impl GenericNetlinkControlMessageAttribute {
    pub fn get_type(&self) -> GenericNetlinkControlMessageAttributeType {
        match self {
            Self::Unspecified => GenericNetlinkControlMessageAttributeType::Unspecified,
            Self::FamilyName(_) => GenericNetlinkControlMessageAttributeType::FamilyName,
            Self::FamilyId(_) => GenericNetlinkControlMessageAttributeType::FamilyId,
            Self::Version(_) => GenericNetlinkControlMessageAttributeType::Version,
            Self::HeaderSize(_) => GenericNetlinkControlMessageAttributeType::HeaderSize,
            Self::MaxAttr(_) => GenericNetlinkControlMessageAttributeType::MaxAttr,
            Self::Ops(_) => GenericNetlinkControlMessageAttributeType::OPS,
        }
    }
}

impl Into<GenericNetlinkMessageAttribute> for GenericNetlinkControlMessageAttribute {
    fn into(self) -> GenericNetlinkMessageAttribute {
        match self {
            Self::Unspecified => {
                GenericNetlinkMessageAttribute::new(self.get_type().into(), [].to_vec())
            }
            Self::FamilyName(ref name) => {
                let mut payload = name.as_bytes().to_vec();
                payload.push(0);
                GenericNetlinkMessageAttribute::new(self.get_type().into(), payload)
            }
            Self::FamilyId(id) => {
                GenericNetlinkMessageAttribute::new(self.get_type().into(), id.to_le_bytes().to_vec())
            }
            Self::Version(version) => GenericNetlinkMessageAttribute::new(
                self.get_type().into(),
                version.to_le_bytes().to_vec(),
            ),
            Self::HeaderSize(header_size) => GenericNetlinkMessageAttribute::new(
                self.get_type().into(),
                header_size.to_le_bytes().to_vec(),
            ),
            Self::MaxAttr(max_attr) => GenericNetlinkMessageAttribute::new(
                self.get_type().into(),
                max_attr.to_le_bytes().to_vec(),
            ),
            Self::Ops(_) => {
                unimplemented!()
            }
        }
    }
}

impl TryFrom<GenericNetlinkMessageAttribute> for GenericNetlinkControlMessageAttribute {
    type Error = GenericError;

    fn try_from(
        generic_netlink_msg_attr: GenericNetlinkMessageAttribute,
    ) -> Result<Self, Self::Error> {
        let attr_type: GenericNetlinkControlMessageAttributeType =
            generic_netlink_msg_attr.get_type().try_into()?;
        let payload = generic_netlink_msg_attr.payload;

        match attr_type {
            GenericNetlinkControlMessageAttributeType::FamilyName => {
                let name = str::from_utf8(&payload[..payload.len() - 1])?;
                Ok(Self::FamilyName(name.to_string()))
            }
            GenericNetlinkControlMessageAttributeType::FamilyId => Ok(Self::FamilyId(
                u16::from_ne_bytes(payload[0..2].try_into().unwrap()),
            )),
            GenericNetlinkControlMessageAttributeType::Version => Ok(Self::Version(
                u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
            )),
            GenericNetlinkControlMessageAttributeType::HeaderSize => Ok(Self::HeaderSize(
                u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
            )),
            GenericNetlinkControlMessageAttributeType::MaxAttr => Ok(Self::MaxAttr(
                u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
            )),
            GenericNetlinkControlMessageAttributeType::OPS => {
                let ops_buf = payload;
                let mut ops = Vec::new();
                let mut curr_op_attr_idx = 0;

                // make a list of op
                while curr_op_attr_idx < ops_buf.len() {
                    let op_size = u16::from_ne_bytes(
                        ops_buf[curr_op_attr_idx..curr_op_attr_idx + 2]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    let curr_op_attr =
                        GenericNetlinkControlMessageOpAttribute::from_byte_array(
                            &ops_buf[curr_op_attr_idx + 4..curr_op_attr_idx + op_size],
                        )?;
                    ops.push(curr_op_attr);
                    curr_op_attr_idx =
                        common::next_align_num(curr_op_attr_idx + op_size, 4);
                }

                Ok(Self::Ops(ops))
            }
            _ => {
                return Err(GenericError::UnsupportedControlAttrType(
                    attr_type,
                ))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericNetlinkControlMessageAttributeType {
    Unspecified = 0,
    FamilyId = 1,
    FamilyName = 2,
    Version = 3,
    HeaderSize = 4,
    MaxAttr = 5,
    OPS = 6, // this attribute is an array, with nested attributes follow, each type is array index, counting from 1
    MulticastGroups = 7,
    Policy = 8,
    OpPolicy = 9,
    Op = 10,
}

impl Into<GenericNetlinkMessageAttributeType> for GenericNetlinkControlMessageAttributeType {
    fn into(self) -> GenericNetlinkMessageAttributeType {
        GenericNetlinkMessageAttributeType::new(self as u16)
    }
}

impl TryFrom<GenericNetlinkMessageAttributeType> for GenericNetlinkControlMessageAttributeType {
    type Error = GenericError;

    fn try_from(
        generic_netlink_msg_attr_type: GenericNetlinkMessageAttributeType,
    ) -> Result<Self, Self::Error> {
        match generic_netlink_msg_attr_type {
            x if x == Self::Unspecified.into() => Ok(Self::Unspecified),
            x if x == Self::FamilyId.into() => Ok(Self::FamilyId),
            x if x == Self::FamilyName.into() => Ok(Self::FamilyName),
            x if x == Self::Version.into() => Ok(Self::Version),
            x if x == Self::HeaderSize.into() => Ok(Self::HeaderSize),
            x if x == Self::MaxAttr.into() => Ok(Self::MaxAttr),
            x if x == Self::OPS.into() => Ok(Self::OPS),
            x if x == Self::MulticastGroups.into() => Ok(Self::MulticastGroups),
            x if x == Self::Policy.into() => Ok(Self::Policy),
            x if x == Self::OpPolicy.into() => Ok(Self::OpPolicy),
            x if x == Self::Op.into() => Ok(Self::Op),
            _ => Err(GenericError::UnknownAttrType(
                generic_netlink_msg_attr_type,
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GenericNetlinkControlMessage {
    command: GenericNetlinkControlMessageCommand,
    attributes: Vec<GenericNetlinkControlMessageAttribute>,
}

impl GenericNetlinkControlMessage {
    const TYPE: GenericNetlinkMessageType = GenericNetlinkMessageType::new(16);

    pub fn new(command: GenericNetlinkControlMessageCommand) -> Self {
        Self {
            command,
            attributes: Vec::new(),
        }
    }

    pub fn add_ctrl_attr(&mut self, ctrl_attr: GenericNetlinkControlMessageAttribute) {
        self.attributes.push(ctrl_attr);
    }

    pub fn get_ctrl_attr(
        &self,
        attr_type: GenericNetlinkControlMessageAttributeType,
    ) -> Option<GenericNetlinkControlMessageAttribute> {
        for attribute in &self.attributes {
            if attribute.get_type() == attr_type {
                return Some(attribute.clone());
            }
        }

        None
    }
}

impl Into<GenericNetlinkMessage> for GenericNetlinkControlMessage {
    fn into(self) -> GenericNetlinkMessage {
        let mut generic_netlink_msg = GenericNetlinkMessage::new(Self::TYPE, self.command.into());

        for attribute in self.attributes {
            generic_netlink_msg.add_attr(attribute.into());
        }

        generic_netlink_msg
    }
}

impl TryFrom<GenericNetlinkMessage> for GenericNetlinkControlMessage {
    type Error = GenericError;

    fn try_from(generic_netlink_msg: GenericNetlinkMessage) -> Result<Self, Self::Error> {
        // check type
        if generic_netlink_msg.message_type != Self::TYPE {
            return Err(GenericError::ControlMsgErr(generic_netlink_msg));
        }

        let mut result = Self {
            command: generic_netlink_msg.command.try_into()?,
            attributes: Vec::new(),
        };

        for attribute in generic_netlink_msg.attributes {
            result.attributes.push(attribute.try_into()?);
        }

        Ok(result)
    }
}

#[derive(Debug)]
pub struct GenericNetlinkConnection {
    netlink_conn: NetlinkConnection,
}

impl GenericNetlinkConnection {
    pub fn new() -> Result<Self, GenericError> {
        Ok(Self {
            netlink_conn: NetlinkConnection::new(NetlinkProtocol::GENERIC)?,
        })
    }

    pub fn send(&self, message: GenericNetlinkMessage) -> Result<(), GenericError> {
        let netlink_msg = NetlinkMessage::New(
            message.message_type.into(),
            &[NetlinkMessageFlag::REQUEST],
            NetlinkMessagePayload::GENERIC(message),
        );

        self.netlink_conn.Send(netlink_msg)?;
        Ok(())
    }

    pub fn recv(&self) -> Result<GenericNetlinkMessage, GenericError> {
        let netlink_msg = self.netlink_conn.Recv()?;

        match netlink_msg.payload {
            NetlinkMessagePayload::GENERIC(tmp) => Ok(tmp),
            payload => Err(GenericError::UnimplementedNetlinkMsgPayload(payload)),
        }
    }
}

#[derive(Debug)]
pub enum GenericError {
    NetlinkErr(NetlinkError),
    HeaderErr(Vec<u8>),
    ControlMsgErr(GenericNetlinkMessage),
    UnknownControlCommand(GenericNetlinkMessageCommand),
    UnsupportedControlAttrType(GenericNetlinkControlMessageAttributeType),
    UnknownAttrType(GenericNetlinkMessageAttributeType),
    OpAttrErr(Vec<u8>),
    OpAttrComponentErr(Vec<u8>),
    UnimplementedNetlinkMsgPayload(NetlinkMessagePayload),
    Utf8Err(Utf8Error),
}

impl Error for GenericError {}

impl fmt::Display for GenericError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::NetlinkErr(error) => String::from(format!("Netlink error: {}", error)),
            Self::HeaderErr(buf) => String::from(format!("Header error: {:?}", buf)),
            Self::ControlMsgErr(generic_netlink_msg) => String::from(format!(
                "Control message error: {:?}",
                generic_netlink_msg
            )),
            Self::UnknownControlCommand(generic_netlink_msg_cmd) => String::from(format!(
                "Unknown control command: {:?}",
                generic_netlink_msg_cmd
            )),
            Self::UnsupportedControlAttrType(attr_type) => String::from(format!(
                "Unsupported control attribute type: {:?}",
                attr_type
            )),
            Self::UnknownAttrType(attr_type) => {
                String::from(format!("Unknown attribute type: {:?}", attr_type))
            }
            Self::OpAttrErr(op_attr) => {
                String::from(format!("Op attribute error: {:?}", op_attr))
            }
            Self::OpAttrComponentErr(op_attr_component) => String::from(format!(
                "Op attribute component error: {:?}",
                op_attr_component
            )),
            Self::UnimplementedNetlinkMsgPayload(payload) => String::from(format!(
                "Unimplemented netlink message payload: {:?}",
                payload
            )),
            Self::Utf8Err(utf8_err) => String::from(format!("UTF-8 error: {}", utf8_err)),
        };

        write!(f, "{}", result)
    }
}

impl From<NetlinkError> for GenericError {
    fn from(error: NetlinkError) -> Self {
        Self::NetlinkErr(error)
    }
}

impl From<Utf8Error> for GenericError {
    fn from(error: Utf8Error) -> Self {
        Self::Utf8Err(error)
    }
}
