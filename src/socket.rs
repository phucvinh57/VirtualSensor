use std::fmt;
use std::error::Error;
use std::os::unix::prelude::RawFd;


#[derive (Clone, Copy, Debug)]
pub enum SocketFamily
{
	UNSPECIFIED = 0,
	UNIX = 1,	// Unix domain sockets
	INET = 2,	// Internet IP Protocol
	AX25 = 3,	// Amateur Radio AX.25
	IPX = 4,	// Novell IPX
	APPLETALK = 5,	// AppleTalk DDP
	NETROM = 6,	// Amateur Radio NET/ROM
	BRIDGE = 7,	// Multiprotocol bridge
	ATMPVC = 8,	// ATM PVCs
	X25 = 9,	// Reserved for X.25 project
	INET6 = 10,	// IP version 6
	ROSE = 11,	// Amateur Radio X.25 PLP
	DEC_NET = 12,	// Reserved for DECnet project
	NETBEUI = 13,	// Reserved for 802.2LLC project
	SECURITY = 14,	// Security callback pseudo AF
	KEY = 15,	// PF_KEY key management API
	NETLINK = 16,
	PACKET = 17,	// Packet family
	ASH = 18,	// Ash
	ECONET = 19,	// Acorn Econet
	ATMSVC = 20,	// ATM SVCs
	RDS = 21,	// RDS sockets
	SNA = 22,	// Linux SNA Project (nutters!)
	IRDA = 23,	// IRDA sockets
	PPPOX = 24,	// PPPoX sockets
	WANPIPE = 25,	// Wanpipe API Sockets
	LLC = 26,	// Linux LLC
	IB = 27,	// Native InfiniBand address
	MPLS = 28,	// MPLS
	CAN = 29,	// Controller Area Network
	TIPC = 30,	// TIPC sockets
	BLUETOOTH = 31,	// Bluetooth sockets
	IUCV = 32,	// IUCV sockets
	RXRPC = 33,	// RxRPC sockets
	ISDN = 34,	// mISDN sockets
	PHONET = 35,	// Phonet sockets
	IEEE802154 = 36,	// IEEE802154 sockets
	CAIF = 37,	// CAIF sockets
	ALG = 38,	// Algorithm sockets
	NFC = 39,	// NFC sockets
	VSOCK = 40,	// vSockets
	KCM = 41,	// Kernel Connection Multiplexor
	QIPCRTR = 42,	// Qualcomm IPC Router
	SMC = 43,	// smc sockets: reserve number for PF_SMC protocol family that reuses AF_INET address family
	XDP = 44,	// XDP sockets
	MCTP = 45,	// Management component transport protocol
}


#[derive (Clone, Copy, Debug)]
pub enum SocketType
{
	STREAM = 1,
	DATAGRAM = 2,
	RAW = 3,
	RDM = 4,
	SEQUENCE_PACKET = 5,
	DCCP = 6,
	PACKET = 10,
}


pub trait SocketProtocol: fmt::Display
{
	fn ToUsize (&self) -> usize;
}

impl fmt::Debug for dyn SocketProtocol
{
	fn fmt (&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
	{
		write! (f, "Socket Protocol {}({})", self, self.ToUsize ())
	}
}


#[derive (Clone, Copy, Debug)]
pub struct SocketAddress
{

}


#[derive (Debug)]
pub struct Socket
{
	protocol: Box<dyn SocketProtocol>,
	rawFd: RawFd,
}

impl Socket
{
	pub fn New (socketFamily: SocketFamily, socketType: SocketType, socketProtocol: Box<dyn SocketProtocol>) -> Result<Self, SocketError>
	{
		let rawFd = unsafe { libc::socket (socketFamily as i32, socketType as i32, socketProtocol.ToUsize () as i32) };

		if rawFd < 0
		{
			return Err(SocketError::CANT_CREATE_SOCKET(rawFd));
		}

		Ok(Self
		{
			protocol: socketProtocol,
			rawFd,
		})
	}

	// this one is for connection oriented socket
	pub fn Send (&self, data: &[u8]) -> Result<(), SocketError>
	{
		let mut bytesSent = 0;
		let mut remainingBytes = data.len ();

		while remainingBytes > 0
		{
			let res = unsafe { libc::send (self.rawFd, &data[bytesSent..] as *const _ as *const libc::c_void, data[bytesSent..].len (), 0) };

			if res < 0
			{
				return Err(SocketError::WRITE_ERROR(res, bytesSent, data.len ()));
			}
			else
			{
				bytesSent += res as usize;
				remainingBytes -= res as usize;
			}
		}

		Ok(())
	}

	// this one is for connectless socket
	pub fn SendTo (&self, socketAddress: SocketAddress, data: &[u8]) -> Result<(), SocketError>
	{
		let mut bytesSent = 0;
		let mut remainingBytes = data.len ();

		while remainingBytes > 0
		{
			let res = unsafe { libc::sendto (self.rawFd, &data[bytesSent..] as *const _ as *const libc::c_void, data[bytesSent..].len (), 0, addr_ptr, addr_len) };

			if res < 0
			{
				return Err(SocketError::WRITE_ERROR(res, bytesSent, data.len ()));
			}
			else
			{
				bytesSent += res as usize;
				remainingBytes -= res as usize;
			}
		}

		Ok(())
	}

	pub fn Recv (&self, buffer: &[u8]) -> Result<(), SocketError>
	{
		unimplemented! ();
	}
}

impl Drop for Socket
{
	fn drop (&mut self) { unsafe { libc::close (self.rawFd); } }
}


#[derive (Clone, Copy, Debug)]
pub enum SocketError
{
	CANT_CREATE_SOCKET(i32),
	READ_ERROR(isize),
	WRITE_ERROR(isize, usize, usize),
}

impl Error for SocketError {}

impl fmt::Display for SocketError
{
	fn fmt (&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
	{
		let result = match self
		{
			Self::CANT_CREATE_SOCKET(errorCode) => String::from (format! ("Error while creating socket: {}", errorCode)),
			Self::READ_ERROR(errorCode) => String::from (format! ("Error while reading from socket: {}", errorCode)),
			Self::WRITE_ERROR(errorCode, bytesSent, totalBytesToSend) => String::from (format! ("Error while writing to socket: {}, sent {}/{} bytes", errorCode, bytesSent, totalBytesToSend)),
		};

		write! (f, "{}", result)
	}
}
