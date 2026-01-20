//! Network packet types and parsing

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Network protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            other => Protocol::Other(other),
        }
    }
}

/// Packet direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

/// TCP flags
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: byte & 0x01 != 0,
            syn: byte & 0x02 != 0,
            rst: byte & 0x04 != 0,
            psh: byte & 0x08 != 0,
            ack: byte & 0x10 != 0,
            urg: byte & 0x20 != 0,
            ece: byte & 0x40 != 0,
            cwr: byte & 0x80 != 0,
        }
    }

    pub fn is_handshake(&self) -> bool {
        self.syn && !self.ack
    }

    pub fn is_handshake_ack(&self) -> bool {
        self.syn && self.ack
    }

    pub fn is_data(&self) -> bool {
        self.psh && self.ack
    }
}

/// Packet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    /// Unique packet identifier
    pub id: Uuid,
    /// Capture timestamp
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    pub source_ip: IpAddr,
    /// Source port
    pub source_port: u16,
    /// Destination IP address
    pub dest_ip: IpAddr,
    /// Destination port
    pub dest_port: u16,
    /// Protocol
    pub protocol: Protocol,
    /// Packet direction
    pub direction: Direction,
    /// TCP flags (if TCP)
    pub tcp_flags: Option<TcpFlags>,
    /// TCP sequence number (if TCP)
    pub tcp_seq: Option<u32>,
    /// TCP acknowledgment number (if TCP)
    pub tcp_ack: Option<u32>,
    /// Payload length
    pub payload_len: usize,
    /// Total packet length
    pub total_len: usize,
}

/// Complete packet with payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    /// Packet metadata
    pub info: PacketInfo,
    /// Raw packet data (including headers)
    pub raw: Vec<u8>,
    /// Payload data (application layer)
    pub payload: Vec<u8>,
    /// Decoded content (if applicable)
    pub decoded: Option<DecodedContent>,
}

/// Decoded packet content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedContent {
    /// Content type
    pub content_type: ContentType,
    /// Decoded data as string (if text-based)
    pub text: Option<String>,
    /// Decoded data as structured format
    pub structured: Option<serde_json::Value>,
    /// Decoding notes/warnings
    pub notes: Vec<String>,
}

/// Content type of decoded data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    Unknown,
    Binary,
    Text,
    Json,
    Protobuf,
    MessagePack,
    Custom,
}

impl Packet {
    /// Create a new packet from raw bytes
    pub fn from_raw(raw: &[u8], timestamp: DateTime<Utc>) -> Option<Self> {
        // Parse Ethernet frame
        if raw.len() < 14 {
            return None;
        }

        let ethertype = u16::from_be_bytes([raw[12], raw[13]]);

        // Only handle IPv4 for now
        if ethertype != 0x0800 {
            return None;
        }

        let ip_header = &raw[14..];
        Self::parse_ipv4(ip_header, raw.to_vec(), timestamp)
    }

    fn parse_ipv4(data: &[u8], raw: Vec<u8>, timestamp: DateTime<Utc>) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let version = (data[0] >> 4) & 0x0f;
        if version != 4 {
            return None;
        }

        let ihl = (data[0] & 0x0f) as usize * 4;
        let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let protocol = Protocol::from(data[9]);

        let source_ip = IpAddr::V4(std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dest_ip = IpAddr::V4(std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]));

        if data.len() < ihl {
            return None;
        }

        let transport_data = &data[ihl..];

        let (source_port, dest_port, tcp_flags, tcp_seq, tcp_ack, payload_offset) = match protocol {
            Protocol::TCP => {
                if transport_data.len() < 20 {
                    return None;
                }
                let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
                let seq = u32::from_be_bytes([
                    transport_data[4],
                    transport_data[5],
                    transport_data[6],
                    transport_data[7],
                ]);
                let ack = u32::from_be_bytes([
                    transport_data[8],
                    transport_data[9],
                    transport_data[10],
                    transport_data[11],
                ]);
                let data_offset = ((transport_data[12] >> 4) & 0x0f) as usize * 4;
                let flags = TcpFlags::from_byte(transport_data[13]);

                (src_port, dst_port, Some(flags), Some(seq), Some(ack), data_offset)
            }
            Protocol::UDP => {
                if transport_data.len() < 8 {
                    return None;
                }
                let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
                (src_port, dst_port, None, None, None, 8)
            }
            _ => (0, 0, None, None, None, 0),
        };

        let payload = if transport_data.len() > payload_offset {
            transport_data[payload_offset..].to_vec()
        } else {
            Vec::new()
        };

        let info = PacketInfo {
            id: Uuid::new_v4(),
            timestamp,
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            protocol,
            direction: Direction::Unknown,
            tcp_flags,
            tcp_seq,
            tcp_ack,
            payload_len: payload.len(),
            total_len: total_length,
        };

        Some(Self {
            info,
            raw,
            payload,
            decoded: None,
        })
    }

    /// Get a summary string for display
    pub fn summary(&self) -> String {
        let proto = match self.info.protocol {
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
            Protocol::ICMP => "ICMP",
            Protocol::Other(n) => return format!("Protocol {}", n),
        };

        let flags = if let Some(ref f) = self.info.tcp_flags {
            let mut s = String::new();
            if f.syn { s.push_str("SYN "); }
            if f.ack { s.push_str("ACK "); }
            if f.fin { s.push_str("FIN "); }
            if f.rst { s.push_str("RST "); }
            if f.psh { s.push_str("PSH "); }
            s.trim().to_string()
        } else {
            String::new()
        };

        format!(
            "{} {}:{} -> {}:{} {} [{} bytes]",
            proto,
            self.info.source_ip,
            self.info.source_port,
            self.info.dest_ip,
            self.info.dest_port,
            flags,
            self.info.payload_len
        )
    }

    /// Check if this is a connection establishment packet
    pub fn is_connection_start(&self) -> bool {
        self.info.tcp_flags.as_ref().map(|f| f.is_handshake()).unwrap_or(false)
    }

    /// Check if this packet contains data
    pub fn has_data(&self) -> bool {
        !self.payload.is_empty()
    }
}

/// Stream of related packets (TCP connection or UDP flow)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketStream {
    pub id: Uuid,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub protocol: Protocol,
    pub packets: Vec<Uuid>,
    pub started: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl PacketStream {
    /// Create a new stream from the first packet
    pub fn new(packet: &Packet) -> Self {
        Self {
            id: Uuid::new_v4(),
            source_ip: packet.info.source_ip,
            source_port: packet.info.source_port,
            dest_ip: packet.info.dest_ip,
            dest_port: packet.info.dest_port,
            protocol: packet.info.protocol,
            packets: vec![packet.info.id],
            started: packet.info.timestamp,
            last_activity: packet.info.timestamp,
            bytes_sent: packet.info.payload_len as u64,
            bytes_received: 0,
        }
    }

    /// Check if a packet belongs to this stream
    pub fn matches(&self, packet: &Packet) -> bool {
        if packet.info.protocol != self.protocol {
            return false;
        }

        // Forward direction
        if packet.info.source_ip == self.source_ip
            && packet.info.source_port == self.source_port
            && packet.info.dest_ip == self.dest_ip
            && packet.info.dest_port == self.dest_port
        {
            return true;
        }

        // Reverse direction
        if packet.info.source_ip == self.dest_ip
            && packet.info.source_port == self.dest_port
            && packet.info.dest_ip == self.source_ip
            && packet.info.dest_port == self.source_port
        {
            return true;
        }

        false
    }

    /// Add a packet to the stream
    pub fn add_packet(&mut self, packet: &Packet) {
        self.packets.push(packet.info.id);
        self.last_activity = packet.info.timestamp;

        // Track bytes in each direction
        if packet.info.source_ip == self.source_ip {
            self.bytes_sent += packet.info.payload_len as u64;
        } else {
            self.bytes_received += packet.info.payload_len as u64;
        }
    }
}
