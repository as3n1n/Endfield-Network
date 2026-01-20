//! Packet filtering

use crate::packet::{Direction, Packet, Protocol};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Packet filter
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketFilter {
    /// Filter by source IP
    pub source_ip: Option<IpAddr>,
    /// Filter by destination IP
    pub dest_ip: Option<IpAddr>,
    /// Filter by either source or destination IP
    pub any_ip: Option<IpAddr>,
    /// Filter by source port
    pub source_port: Option<u16>,
    /// Filter by destination port
    pub dest_port: Option<u16>,
    /// Filter by either port
    pub any_port: Option<u16>,
    /// Filter by port range
    pub port_range: Option<(u16, u16)>,
    /// Filter by protocol
    pub protocol: Option<Protocol>,
    /// Filter by direction
    pub direction: Option<Direction>,
    /// Filter by minimum payload size
    pub min_payload_size: Option<usize>,
    /// Filter by maximum payload size
    pub max_payload_size: Option<usize>,
    /// Filter by payload containing bytes
    pub payload_contains: Option<Vec<u8>>,
    /// Filter by payload containing string
    pub payload_contains_str: Option<String>,
    /// Exclude packets matching filter (negate)
    pub exclude: bool,
}

impl PacketFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by source IP
    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Filter by destination IP
    pub fn dest_ip(mut self, ip: IpAddr) -> Self {
        self.dest_ip = Some(ip);
        self
    }

    /// Filter by either IP
    pub fn any_ip(mut self, ip: IpAddr) -> Self {
        self.any_ip = Some(ip);
        self
    }

    /// Filter by source port
    pub fn source_port(mut self, port: u16) -> Self {
        self.source_port = Some(port);
        self
    }

    /// Filter by destination port
    pub fn dest_port(mut self, port: u16) -> Self {
        self.dest_port = Some(port);
        self
    }

    /// Filter by either port
    pub fn any_port(mut self, port: u16) -> Self {
        self.any_port = Some(port);
        self
    }

    /// Filter by port range
    pub fn port_range(mut self, start: u16, end: u16) -> Self {
        self.port_range = Some((start, end));
        self
    }

    /// Filter by protocol
    pub fn protocol(mut self, proto: Protocol) -> Self {
        self.protocol = Some(proto);
        self
    }

    /// Filter by direction
    pub fn direction(mut self, dir: Direction) -> Self {
        self.direction = Some(dir);
        self
    }

    /// Filter by minimum payload size
    pub fn min_payload(mut self, size: usize) -> Self {
        self.min_payload_size = Some(size);
        self
    }

    /// Filter by maximum payload size
    pub fn max_payload(mut self, size: usize) -> Self {
        self.max_payload_size = Some(size);
        self
    }

    /// Filter by payload containing bytes
    pub fn payload_contains(mut self, pattern: Vec<u8>) -> Self {
        self.payload_contains = Some(pattern);
        self
    }

    /// Filter by payload containing string
    pub fn payload_contains_str(mut self, pattern: impl Into<String>) -> Self {
        self.payload_contains_str = Some(pattern.into());
        self
    }

    /// Negate the filter (exclude matching packets)
    pub fn exclude(mut self) -> Self {
        self.exclude = true;
        self
    }

    /// Check if a packet matches this filter
    pub fn matches(&self, packet: &Packet) -> bool {
        let result = self.matches_internal(packet);
        if self.exclude {
            !result
        } else {
            result
        }
    }

    fn matches_internal(&self, packet: &Packet) -> bool {
        // Source IP
        if let Some(ref ip) = self.source_ip {
            if packet.info.source_ip != *ip {
                return false;
            }
        }

        // Destination IP
        if let Some(ref ip) = self.dest_ip {
            if packet.info.dest_ip != *ip {
                return false;
            }
        }

        // Any IP
        if let Some(ref ip) = self.any_ip {
            if packet.info.source_ip != *ip && packet.info.dest_ip != *ip {
                return false;
            }
        }

        // Source port
        if let Some(port) = self.source_port {
            if packet.info.source_port != port {
                return false;
            }
        }

        // Destination port
        if let Some(port) = self.dest_port {
            if packet.info.dest_port != port {
                return false;
            }
        }

        // Any port
        if let Some(port) = self.any_port {
            if packet.info.source_port != port && packet.info.dest_port != port {
                return false;
            }
        }

        // Port range
        if let Some((start, end)) = self.port_range {
            let in_range = |p: u16| p >= start && p <= end;
            if !in_range(packet.info.source_port) && !in_range(packet.info.dest_port) {
                return false;
            }
        }

        // Protocol
        if let Some(proto) = self.protocol {
            if packet.info.protocol != proto {
                return false;
            }
        }

        // Direction
        if let Some(dir) = self.direction {
            if packet.info.direction != dir {
                return false;
            }
        }

        // Minimum payload size
        if let Some(min) = self.min_payload_size {
            if packet.payload.len() < min {
                return false;
            }
        }

        // Maximum payload size
        if let Some(max) = self.max_payload_size {
            if packet.payload.len() > max {
                return false;
            }
        }

        // Payload contains bytes
        if let Some(ref pattern) = self.payload_contains {
            if !packet
                .payload
                .windows(pattern.len())
                .any(|window| window == pattern.as_slice())
            {
                return false;
            }
        }

        // Payload contains string
        if let Some(ref pattern) = self.payload_contains_str {
            let pattern_bytes = pattern.as_bytes();
            if !packet
                .payload
                .windows(pattern_bytes.len())
                .any(|window| window == pattern_bytes)
            {
                return false;
            }
        }

        true
    }
}

/// Composite filter that can combine multiple filters
#[derive(Debug, Clone, Default)]
pub struct CompositeFilter {
    /// Filters that must all match (AND)
    pub all: Vec<PacketFilter>,
    /// Filters where at least one must match (OR)
    pub any: Vec<PacketFilter>,
}

impl CompositeFilter {
    /// Create a new composite filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a filter that must match
    pub fn and(mut self, filter: PacketFilter) -> Self {
        self.all.push(filter);
        self
    }

    /// Add a filter where at least one must match
    pub fn or(mut self, filter: PacketFilter) -> Self {
        self.any.push(filter);
        self
    }

    /// Check if a packet matches
    pub fn matches(&self, packet: &Packet) -> bool {
        // All "and" filters must match
        let all_match = self.all.is_empty() || self.all.iter().all(|f| f.matches(packet));

        // At least one "or" filter must match (if any exist)
        let any_match = self.any.is_empty() || self.any.iter().any(|f| f.matches(packet));

        all_match && any_match
    }
}

/// Filter packets in an iterator
pub fn filter_packets<'a>(
    packets: impl Iterator<Item = &'a Packet> + 'a,
    filter: &'a PacketFilter,
) -> impl Iterator<Item = &'a Packet> + 'a {
    packets.filter(|p| filter.matches(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_test_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Packet {
        Packet {
            info: crate::packet::PacketInfo {
                id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                source_port: src_port,
                dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                dest_port: dst_port,
                protocol: Protocol::TCP,
                direction: Direction::Outbound,
                tcp_flags: None,
                tcp_seq: None,
                tcp_ack: None,
                payload_len: payload.len(),
                total_len: payload.len() + 40,
            },
            raw: Vec::new(),
            payload: payload.to_vec(),
            decoded: None,
        }
    }

    #[test]
    fn test_port_filter() {
        let packet = make_test_packet(12345, 443, b"test");
        let filter = PacketFilter::new().any_port(443);
        assert!(filter.matches(&packet));

        let filter = PacketFilter::new().any_port(80);
        assert!(!filter.matches(&packet));
    }

    #[test]
    fn test_payload_filter() {
        let packet = make_test_packet(12345, 443, b"GET /test HTTP/1.1");
        let filter = PacketFilter::new().payload_contains_str("GET");
        assert!(filter.matches(&packet));

        let filter = PacketFilter::new().payload_contains_str("POST");
        assert!(!filter.matches(&packet));
    }

    #[test]
    fn test_exclude_filter() {
        let packet = make_test_packet(12345, 443, b"test");
        let filter = PacketFilter::new().any_port(443).exclude();
        assert!(!filter.matches(&packet));
    }
}
