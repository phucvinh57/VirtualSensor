use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::str::Utf8Error;
use std::{fmt, mem, slice, str};

use crate::common;
use crate::netlink::{
    NetlinkAttributeHeader, NetlinkMessageAttribute, NetlinkMessageAttributeType,
};
use crate::netlink::{NetlinkConnection, NetlinkError, NetlinkProtocol};
use crate::netlink::{NetlinkMessage, NetlinkMessageType};
use crate::netlink::{NetlinkMessageFlag, NetlinkMessagePayload};

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct GenericNetlinkMessageHeader {
    command: u8,
    version: u8,
    reserved: u16,
}

impl GenericNetlinkMessageHeader {
    const LENGTH: usize = mem::size_of::<GenericNetlinkMessageHeader>();

    pub fn New(command: u8, version: u8) -> Self {
        Self {
            command,
            version,
            reserved: 0,
        }
    }

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, GenericError> {
        // check size
        if buf.len() < Self::LENGTH {
            return Err(GenericError::HEADER_ERROR(buf.to_vec()));
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericNetlinkMessageCommand(u8);

impl GenericNetlinkMessageCommand {
    pub fn New(value: u8) -> Self {
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
    pub const fn New(value: u16) -> Self {
        Self(value)
    }
}

impl Into<NetlinkMessageType> for GenericNetlinkMessageType {
    fn into(self) -> NetlinkMessageType {
        NetlinkMessageType::New(self.0)
    }
}

impl Into<u16> for GenericNetlinkMessageType {
    fn into(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct GenericNetlinkMessageAttribute {
    attributeType: GenericNetlinkMessageAttributeType,
    pub payload: Vec<u8>,
}

impl GenericNetlinkMessageAttribute {
    const ALIGN: usize = 4;
    const PAYLOAD_ALIGN: usize = 4;

    pub fn New(attributeType: GenericNetlinkMessageAttributeType, payload: Vec<u8>) -> Self {
        Self {
            attributeType,
            payload,
        }
    }

    pub fn Type(&self) -> GenericNetlinkMessageAttributeType {
        self.attributeType
    }

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let header = NetlinkAttributeHeader::New(self.payload.len(), self.attributeType.into());
        result.append(&mut header.ToByteArray());
        common::AlignBuffer(&mut result, Self::PAYLOAD_ALIGN);
        result.extend_from_slice(&self.payload[..]);
        result
    }

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, GenericError> {
        let attributeType = GenericNetlinkMessageAttributeType::New(u16::from_ne_bytes(
            buf[2..4].try_into().unwrap(),
        ));

        Ok(Self {
            attributeType,
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
    pub fn New(value: u16) -> Self {
        Self(value)
    }

    pub fn ToByteArray(&self) -> Vec<u8> {
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
    messageType: GenericNetlinkMessageType,
    command: GenericNetlinkMessageCommand,
    version: usize,
    pub attributes: Vec<GenericNetlinkMessageAttribute>,
}

impl GenericNetlinkMessage {
    const VERSION: usize = 2;
    const ATTRIBUTE_ALIGN: usize = 4;

    pub fn New(
        messageType: GenericNetlinkMessageType,
        command: GenericNetlinkMessageCommand,
    ) -> Self {
        Self {
            messageType,
            command,
            version: Self::VERSION,
            attributes: Vec::new(),
        }
    }

    pub fn MessageType(&self) -> GenericNetlinkMessageType {
        self.messageType
    }
    pub fn Command(&self) -> GenericNetlinkMessageCommand {
        self.command
    }

    pub fn AddAttribute(&mut self, attribute: GenericNetlinkMessageAttribute) {
        self.attributes.push(attribute)
    }

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // make header
        let header = GenericNetlinkMessageHeader::New(self.command.into(), self.version as u8);

        // append header
        result.append(&mut header.ToByteArray());

        // append all attributes
        for attr in &self.attributes {
            common::AlignBuffer(&mut result, GenericNetlinkMessageAttribute::ALIGN);
            result.append(&mut attr.ToByteArray());
        }

        result
    }

    pub fn FromByteArray(
        buf: &[u8],
        messageType: GenericNetlinkMessageType,
    ) -> Result<Self, GenericError> {
        let genericMessageHeader = GenericNetlinkMessageHeader::FromByteArray(&buf)?;

        let mut genericNetlinkMessage = GenericNetlinkMessage::New(
            messageType,
            GenericNetlinkMessageCommand::New(genericMessageHeader.command),
        );

        // attribute start index
        let mut attributeCurrentIndex = common::NextAlignNumber(
            GenericNetlinkMessageHeader::LENGTH,
            GenericNetlinkMessage::ATTRIBUTE_ALIGN,
        );

        while attributeCurrentIndex < buf.len() {
            let currentAttributeSize = u16::from_ne_bytes(
                buf[attributeCurrentIndex..attributeCurrentIndex + 2]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let currentAttribute = GenericNetlinkMessageAttribute::FromByteArray(
                &buf[attributeCurrentIndex..attributeCurrentIndex + currentAttributeSize],
            )?;
            attributeCurrentIndex = common::NextAlignNumber(
                attributeCurrentIndex + currentAttributeSize,
                GenericNetlinkMessage::ATTRIBUTE_ALIGN,
            );

            genericNetlinkMessage.AddAttribute(currentAttribute.into());
        }

        Ok(genericNetlinkMessage)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericNetlinkControlMessageCommand {
    UNSPECIFIED = 0,
    NEW_FAMILY = 1,
    DELETE_FAMILY = 2,
    GET_FAMILY_ID = 3,
    NEW_OPERATION = 4,
    DELETE_OPERATION = 5,
    GET_OPERATION = 6,
    NEW_MULTICAST_GROUP = 7,
    DELETE_MULTICAST_GROUP = 8,
    GET_MULTICAST_GROUP = 9,
    GET_POLICY = 10,
}

impl Into<GenericNetlinkMessageCommand> for GenericNetlinkControlMessageCommand {
    fn into(self) -> GenericNetlinkMessageCommand {
        GenericNetlinkMessageCommand::New(self as u8)
    }
}

impl TryFrom<GenericNetlinkMessageCommand> for GenericNetlinkControlMessageCommand {
    type Error = GenericError;

    fn try_from(
        genericNetlinkMessageCommand: GenericNetlinkMessageCommand,
    ) -> Result<Self, Self::Error> {
        match genericNetlinkMessageCommand {
            x if x == Self::UNSPECIFIED.into() => Ok(Self::UNSPECIFIED),
            x if x == Self::NEW_FAMILY.into() => Ok(Self::NEW_FAMILY),
            x if x == Self::DELETE_FAMILY.into() => Ok(Self::DELETE_FAMILY),
            x if x == Self::GET_FAMILY_ID.into() => Ok(Self::GET_FAMILY_ID),
            x if x == Self::NEW_OPERATION.into() => Ok(Self::NEW_OPERATION),
            x if x == Self::DELETE_OPERATION.into() => Ok(Self::DELETE_OPERATION),
            x if x == Self::GET_OPERATION.into() => Ok(Self::GET_OPERATION),
            x if x == Self::NEW_MULTICAST_GROUP.into() => Ok(Self::NEW_MULTICAST_GROUP),
            x if x == Self::DELETE_MULTICAST_GROUP.into() => Ok(Self::DELETE_MULTICAST_GROUP),
            x if x == Self::GET_MULTICAST_GROUP.into() => Ok(Self::GET_MULTICAST_GROUP),
            x if x == Self::GET_POLICY.into() => Ok(Self::GET_POLICY),
            _ => Err(GenericError::UNKNOWN_CONTROL_COMMAND(
                genericNetlinkMessageCommand,
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

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, GenericError> {
        // check size
        // u16::from_ne_bytes (buf[2..4].try_into ().unwrap ())
        let size = u16::from_ne_bytes(buf[0..2].try_into().unwrap()) as usize;
        let componentType = u16::from_ne_bytes(buf[2..4].try_into().unwrap());

        if size != Self::SIZE {
            return Err(GenericError::OP_ATTRIBUTE_COMPONENT_ERROR(buf.to_vec()));
        }

        match componentType {
            Self::UNSPECIFIED_VALUE => Ok(Self::UNSPECIFIED),
            Self::ID_VALUE => Ok(Self::ID(u32::from_ne_bytes(buf[4..8].try_into().unwrap()))),
            Self::FLAGS_VALUE => Ok(Self::FLAGS(u32::from_ne_bytes(
                buf[4..8].try_into().unwrap(),
            ))),
            _ => Err(GenericError::OP_ATTRIBUTE_COMPONENT_ERROR(buf.to_vec())),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum GenericNetlinkControlMessageOpAttributeFlag {
    VALUE(u32),
}

impl GenericNetlinkControlMessageOpAttributeFlag {
    pub fn FromU32(value: u32) -> Result<Vec<Self>, GenericError> {
        Ok([Self::VALUE(value)].to_vec())
    }
}

#[derive(Clone, Debug)]
pub struct GenericNetlinkControlMessageOpAttribute {
    id: u32,
    flags: Vec<GenericNetlinkControlMessageOpAttributeFlag>,
}

impl GenericNetlinkControlMessageOpAttribute {
    const SIZE: usize = 16;

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, GenericError> {
        // check size
        if buf.len() < Self::SIZE {
            return Err(GenericError::OP_ATTRIBUTE_ERROR(buf.to_vec()));
        }

        let firstComponent =
            GenericNetlinkControlMessageOpAttributeComponent::FromByteArray(&buf[0..8])?;
        let secondComponent =
            GenericNetlinkControlMessageOpAttributeComponent::FromByteArray(&buf[8..16])?;

        match (firstComponent, secondComponent) {
            (
                GenericNetlinkControlMessageOpAttributeComponent::ID(id),
                GenericNetlinkControlMessageOpAttributeComponent::FLAGS(flags),
            ) => Ok(Self {
                id,
                flags: GenericNetlinkControlMessageOpAttributeFlag::FromU32(flags)?,
            }),
            (
                GenericNetlinkControlMessageOpAttributeComponent::FLAGS(flags),
                GenericNetlinkControlMessageOpAttributeComponent::ID(id),
            ) => Ok(Self {
                id,
                flags: GenericNetlinkControlMessageOpAttributeFlag::FromU32(flags)?,
            }),
            _ => return Err(GenericError::OP_ATTRIBUTE_ERROR(buf.to_vec())),
        }
    }
}

#[derive(Clone, Debug)]
pub enum GenericNetlinkControlMessageAttribute {
    UNSPECIFIED,
    FAMILY_NAME(String),
    FAMILY_ID(u16),
    VERSION(u32),
    HEADER_SIZE(u32),
    MAX_ATTRIBUTE(u32),
    OPS(Vec<GenericNetlinkControlMessageOpAttribute>),
}

impl GenericNetlinkControlMessageAttribute {
    pub fn Type(&self) -> GenericNetlinkControlMessageAttributeType {
        match self {
            Self::UNSPECIFIED => GenericNetlinkControlMessageAttributeType::UNSPECIFIED,
            Self::FAMILY_NAME(_) => GenericNetlinkControlMessageAttributeType::FAMILY_NAME,
            Self::FAMILY_ID(_) => GenericNetlinkControlMessageAttributeType::FAMILY_ID,
            Self::VERSION(_) => GenericNetlinkControlMessageAttributeType::VERSION,
            Self::HEADER_SIZE(_) => GenericNetlinkControlMessageAttributeType::HEADER_SIZE,
            Self::MAX_ATTRIBUTE(_) => GenericNetlinkControlMessageAttributeType::MAX_ATTRIBUTE,
            Self::OPS(_) => GenericNetlinkControlMessageAttributeType::OPS,
        }
    }
}

impl Into<GenericNetlinkMessageAttribute> for GenericNetlinkControlMessageAttribute {
    fn into(self) -> GenericNetlinkMessageAttribute {
        match self {
            Self::UNSPECIFIED => {
                GenericNetlinkMessageAttribute::New(self.Type().into(), [].to_vec())
            }
            Self::FAMILY_NAME(ref name) => {
                let mut payload = name.as_bytes().to_vec();
                payload.push(0);
                GenericNetlinkMessageAttribute::New(self.Type().into(), payload)
            }
            Self::FAMILY_ID(id) => {
                GenericNetlinkMessageAttribute::New(self.Type().into(), id.to_le_bytes().to_vec())
            }
            Self::VERSION(version) => GenericNetlinkMessageAttribute::New(
                self.Type().into(),
                version.to_le_bytes().to_vec(),
            ),
            Self::HEADER_SIZE(headerSize) => GenericNetlinkMessageAttribute::New(
                self.Type().into(),
                headerSize.to_le_bytes().to_vec(),
            ),
            Self::MAX_ATTRIBUTE(maxAttribute) => GenericNetlinkMessageAttribute::New(
                self.Type().into(),
                maxAttribute.to_le_bytes().to_vec(),
            ),
            Self::OPS(_) => {
                unimplemented!()
            }
        }
    }
}

impl TryFrom<GenericNetlinkMessageAttribute> for GenericNetlinkControlMessageAttribute {
    type Error = GenericError;

    fn try_from(
        genericNetlinkMessageAttribute: GenericNetlinkMessageAttribute,
    ) -> Result<Self, Self::Error> {
        let attributeType: GenericNetlinkControlMessageAttributeType =
            genericNetlinkMessageAttribute.Type().try_into()?;
        let payload = genericNetlinkMessageAttribute.payload;

        match attributeType {
            GenericNetlinkControlMessageAttributeType::FAMILY_NAME => {
                let name = str::from_utf8(&payload[..payload.len() - 1])?;
                Ok(Self::FAMILY_NAME(name.to_string()))
            }
            GenericNetlinkControlMessageAttributeType::FAMILY_ID => Ok(Self::FAMILY_ID(
                u16::from_ne_bytes(payload[0..2].try_into().unwrap()),
            )),
            GenericNetlinkControlMessageAttributeType::VERSION => Ok(Self::VERSION(
                u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
            )),
            GenericNetlinkControlMessageAttributeType::HEADER_SIZE => Ok(Self::HEADER_SIZE(
                u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
            )),
            GenericNetlinkControlMessageAttributeType::MAX_ATTRIBUTE => Ok(Self::MAX_ATTRIBUTE(
                u32::from_ne_bytes(payload[0..4].try_into().unwrap()),
            )),
            GenericNetlinkControlMessageAttributeType::OPS => {
                let opsBuf = payload;
                let mut ops = Vec::new();
                let mut currentOpAttributeIndex = 0;

                // make a list of op
                while currentOpAttributeIndex < opsBuf.len() {
                    let opSize = u16::from_ne_bytes(
                        opsBuf[currentOpAttributeIndex..currentOpAttributeIndex + 2]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    let currentOpAttribute =
                        GenericNetlinkControlMessageOpAttribute::FromByteArray(
                            &opsBuf[currentOpAttributeIndex + 4..currentOpAttributeIndex + opSize],
                        )?;
                    ops.push(currentOpAttribute);
                    currentOpAttributeIndex =
                        common::NextAlignNumber(currentOpAttributeIndex + opSize, 4);
                }

                Ok(Self::OPS(ops))
            }
            _ => {
                return Err(GenericError::UNSUPPORTED_CONTROL_ATTRIBUTE_TYPE(
                    attributeType,
                ))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericNetlinkControlMessageAttributeType {
    UNSPECIFIED = 0,
    FAMILY_ID = 1,
    FAMILY_NAME = 2,
    VERSION = 3,
    HEADER_SIZE = 4,
    MAX_ATTRIBUTE = 5,
    OPS = 6, // this attribute is an array, with nested attributes follow, each type is array index, counting from 1
    MULTICAST_GROUPS = 7,
    POLICY = 8,
    OP_POLICY = 9,
    OP = 10,
}

impl Into<GenericNetlinkMessageAttributeType> for GenericNetlinkControlMessageAttributeType {
    fn into(self) -> GenericNetlinkMessageAttributeType {
        GenericNetlinkMessageAttributeType::New(self as u16)
    }
}

impl TryFrom<GenericNetlinkMessageAttributeType> for GenericNetlinkControlMessageAttributeType {
    type Error = GenericError;

    fn try_from(
        genericNetlinkMessageAttributeType: GenericNetlinkMessageAttributeType,
    ) -> Result<Self, Self::Error> {
        match genericNetlinkMessageAttributeType {
            x if x == Self::UNSPECIFIED.into() => Ok(Self::UNSPECIFIED),
            x if x == Self::FAMILY_ID.into() => Ok(Self::FAMILY_ID),
            x if x == Self::FAMILY_NAME.into() => Ok(Self::FAMILY_NAME),
            x if x == Self::VERSION.into() => Ok(Self::VERSION),
            x if x == Self::HEADER_SIZE.into() => Ok(Self::HEADER_SIZE),
            x if x == Self::MAX_ATTRIBUTE.into() => Ok(Self::MAX_ATTRIBUTE),
            x if x == Self::OPS.into() => Ok(Self::OPS),
            x if x == Self::MULTICAST_GROUPS.into() => Ok(Self::MULTICAST_GROUPS),
            x if x == Self::POLICY.into() => Ok(Self::POLICY),
            x if x == Self::OP_POLICY.into() => Ok(Self::OP_POLICY),
            x if x == Self::OP.into() => Ok(Self::OP),
            _ => Err(GenericError::UNKNOWN_ATTRIBUTE_TYPE(
                genericNetlinkMessageAttributeType,
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
    const TYPE: GenericNetlinkMessageType = GenericNetlinkMessageType::New(16);

    pub fn New(command: GenericNetlinkControlMessageCommand) -> Self {
        Self {
            command,
            attributes: Vec::new(),
        }
    }

    pub fn AddControlAttribute(&mut self, controlAttribute: GenericNetlinkControlMessageAttribute) {
        self.attributes.push(controlAttribute);
    }

    pub fn GetControlAttribute(
        &self,
        attributeType: GenericNetlinkControlMessageAttributeType,
    ) -> Option<GenericNetlinkControlMessageAttribute> {
        for attribute in &self.attributes {
            if attribute.Type() == attributeType {
                return Some(attribute.clone());
            }
        }

        None
    }
}

impl Into<GenericNetlinkMessage> for GenericNetlinkControlMessage {
    fn into(self) -> GenericNetlinkMessage {
        let mut genericNetlinkMessage = GenericNetlinkMessage::New(Self::TYPE, self.command.into());

        for attribute in self.attributes {
            genericNetlinkMessage.AddAttribute(attribute.into());
        }

        genericNetlinkMessage
    }
}

impl TryFrom<GenericNetlinkMessage> for GenericNetlinkControlMessage {
    type Error = GenericError;

    fn try_from(genericNetlinkMessage: GenericNetlinkMessage) -> Result<Self, Self::Error> {
        // check type
        if genericNetlinkMessage.messageType != Self::TYPE {
            return Err(GenericError::CONTROL_MESSAGE_ERROR(genericNetlinkMessage));
        }

        let mut result = Self {
            command: genericNetlinkMessage.command.try_into()?,
            attributes: Vec::new(),
        };

        for attribute in genericNetlinkMessage.attributes {
            result.attributes.push(attribute.try_into()?);
        }

        Ok(result)
    }
}

#[derive(Debug)]
pub struct GenericNetlinkConnection {
    netlinkConnection: NetlinkConnection,
}

impl GenericNetlinkConnection {
    pub fn New() -> Result<Self, GenericError> {
        Ok(Self {
            netlinkConnection: NetlinkConnection::New(NetlinkProtocol::GENERIC)?,
        })
    }

    pub fn Send(&self, message: GenericNetlinkMessage) -> Result<(), GenericError> {
        let netlinkMessage = NetlinkMessage::New(
            message.messageType.into(),
            &[NetlinkMessageFlag::REQUEST],
            NetlinkMessagePayload::GENERIC(message),
        );

        self.netlinkConnection.Send(netlinkMessage)?;
        Ok(())
    }

    pub fn Recv(&self) -> Result<GenericNetlinkMessage, GenericError> {
        let netlinkMessage = self.netlinkConnection.Recv()?;

        match netlinkMessage.payload {
            NetlinkMessagePayload::GENERIC(tmp) => Ok(tmp),
            payload => Err(GenericError::UNIMPLEMENTED_NETLINK_MESSAGE_PAYLOAD(payload)),
        }
    }
}

#[derive(Debug)]
pub enum GenericError {
    NETLINK_ERROR(NetlinkError),
    HEADER_ERROR(Vec<u8>),
    CONTROL_MESSAGE_ERROR(GenericNetlinkMessage),
    UNKNOWN_CONTROL_COMMAND(GenericNetlinkMessageCommand),
    UNSUPPORTED_CONTROL_ATTRIBUTE_TYPE(GenericNetlinkControlMessageAttributeType),
    UNKNOWN_ATTRIBUTE_TYPE(GenericNetlinkMessageAttributeType),
    OP_ATTRIBUTE_ERROR(Vec<u8>),
    OP_ATTRIBUTE_COMPONENT_ERROR(Vec<u8>),
    UNIMPLEMENTED_NETLINK_MESSAGE_PAYLOAD(NetlinkMessagePayload),
    UTF8_ERROR(Utf8Error),
}

impl Error for GenericError {}

impl fmt::Display for GenericError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::NETLINK_ERROR(error) => String::from(format!("Netlink error: {}", error)),
            Self::HEADER_ERROR(buf) => String::from(format!("Header error: {:?}", buf)),
            Self::CONTROL_MESSAGE_ERROR(genericNetlinkMessage) => String::from(format!(
                "Control message error: {:?}",
                genericNetlinkMessage
            )),
            Self::UNKNOWN_CONTROL_COMMAND(genericNetlinkMessageCommand) => String::from(format!(
                "Unknown control command: {:?}",
                genericNetlinkMessageCommand
            )),
            Self::UNSUPPORTED_CONTROL_ATTRIBUTE_TYPE(attributeType) => String::from(format!(
                "Unsupported control attribute type: {:?}",
                attributeType
            )),
            Self::UNKNOWN_ATTRIBUTE_TYPE(attributeType) => {
                String::from(format!("Unknown attribute type: {:?}", attributeType))
            }
            Self::OP_ATTRIBUTE_ERROR(opAttribute) => {
                String::from(format!("Op attribute error: {:?}", opAttribute))
            }
            Self::OP_ATTRIBUTE_COMPONENT_ERROR(opAttributeComponent) => String::from(format!(
                "Op attribute component error: {:?}",
                opAttributeComponent
            )),
            Self::UNIMPLEMENTED_NETLINK_MESSAGE_PAYLOAD(payload) => String::from(format!(
                "Unimplemented netlink message payload: {:?}",
                payload
            )),
            Self::UTF8_ERROR(utf8Error) => String::from(format!("UTF-8 error: {}", utf8Error)),
        };

        write!(f, "{}", result)
    }
}

impl From<NetlinkError> for GenericError {
    fn from(error: NetlinkError) -> Self {
        Self::NETLINK_ERROR(error)
    }
}

impl From<Utf8Error> for GenericError {
    fn from(error: Utf8Error) -> Self {
        Self::UTF8_ERROR(error)
    }
}
