//! Packet capture functionality

use crate::packet::{Direction, Packet, PacketStream};
use chrono::Utc;
use crossbeam_channel::{bounded, Receiver, Sender};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Capture errors
#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Capture error: {0}")]
    CaptureError(String),
    #[error("Not capturing")]
    NotCapturing,
    #[error("Already capturing")]
    AlreadyCapturing,
}

pub type CaptureResult<T> = std::result::Result<T, CaptureError>;

/// Capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Network interface to capture on (None for default)
    pub interface: Option<String>,
    /// BPF filter expression
    pub filter: Option<String>,
    /// Promiscuous mode
    pub promiscuous: bool,
    /// Snapshot length
    pub snaplen: u32,
    /// Read timeout in milliseconds
    pub timeout_ms: i32,
    /// Local IPs to determine direction
    pub local_ips: Vec<IpAddr>,
    /// Game server IPs to track
    pub game_server_ips: Vec<IpAddr>,
    /// Game ports to track
    pub game_ports: Vec<u16>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            filter: None,
            promiscuous: false,
            snaplen: 65535,
            timeout_ms: 1000,
            local_ips: Vec::new(),
            game_server_ips: Vec::new(),
            game_ports: vec![443, 8080, 9000, 9001],
        }
    }
}

/// Capture statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureStats {
    pub packets_captured: u64,
    pub packets_dropped: u64,
    pub bytes_captured: u64,
    pub streams_tracked: u64,
}

/// Packet capture handle
pub struct PacketCapture {
    config: CaptureConfig,
    running: Arc<AtomicBool>,
    stats: Arc<CaptureStatsInner>,
    packet_sender: Option<Sender<Packet>>,
    packet_receiver: Option<Receiver<Packet>>,
    capture_thread: Option<thread::JoinHandle<()>>,
    streams: Arc<DashMap<String, PacketStream>>,
}

struct CaptureStatsInner {
    packets_captured: AtomicU64,
    packets_dropped: AtomicU64,
    bytes_captured: AtomicU64,
}

impl Default for CaptureStatsInner {
    fn default() -> Self {
        Self {
            packets_captured: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            bytes_captured: AtomicU64::new(0),
        }
    }
}

impl PacketCapture {
    /// Create a new packet capture with the given configuration
    pub fn new(config: CaptureConfig) -> Self {
        let (sender, receiver) = bounded(10000);

        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(CaptureStatsInner::default()),
            packet_sender: Some(sender),
            packet_receiver: Some(receiver),
            capture_thread: None,
            streams: Arc::new(DashMap::new()),
        }
    }

    /// List available network interfaces
    pub fn list_interfaces() -> CaptureResult<Vec<NetworkInterface>> {
        // In a real implementation, this would use pcap or pnet
        // For now, return a placeholder
        Ok(vec![
            NetworkInterface {
                name: "eth0".to_string(),
                description: "Ethernet adapter".to_string(),
                addresses: vec![],
                is_up: true,
                is_loopback: false,
            },
            NetworkInterface {
                name: "lo".to_string(),
                description: "Loopback".to_string(),
                addresses: vec![],
                is_up: true,
                is_loopback: true,
            },
        ])
    }

    /// Start capturing packets
    pub fn start(&mut self) -> CaptureResult<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(CaptureError::AlreadyCapturing);
        }

        info!("Starting packet capture");
        self.running.store(true, Ordering::SeqCst);

        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);
        let sender = self.packet_sender.take().ok_or(CaptureError::CaptureError(
            "No sender available".to_string(),
        ))?;
        let config = self.config.clone();
        let streams = Arc::clone(&self.streams);

        let handle = thread::spawn(move || {
            Self::capture_loop(running, stats, sender, config, streams);
        });

        self.capture_thread = Some(handle);

        Ok(())
    }

    /// Stop capturing packets
    pub fn stop(&mut self) -> CaptureResult<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(CaptureError::NotCapturing);
        }

        info!("Stopping packet capture");
        self.running.store(false, Ordering::SeqCst);

        if let Some(handle) = self.capture_thread.take() {
            let _ = handle.join();
        }

        Ok(())
    }

    /// Check if capturing
    pub fn is_capturing(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get capture statistics
    pub fn stats(&self) -> CaptureStats {
        CaptureStats {
            packets_captured: self.stats.packets_captured.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
            bytes_captured: self.stats.bytes_captured.load(Ordering::Relaxed),
            streams_tracked: self.streams.len() as u64,
        }
    }

    /// Get the packet receiver
    pub fn receiver(&self) -> Option<&Receiver<Packet>> {
        self.packet_receiver.as_ref()
    }

    /// Get all tracked streams
    pub fn streams(&self) -> Vec<PacketStream> {
        self.streams.iter().map(|r| r.value().clone()).collect()
    }

    fn capture_loop(
        running: Arc<AtomicBool>,
        stats: Arc<CaptureStatsInner>,
        sender: Sender<Packet>,
        config: CaptureConfig,
        streams: Arc<DashMap<String, PacketStream>>,
    ) {
        info!("Capture thread started");

        // In a real implementation, this would use pcap
        // For now, simulate with a placeholder loop
        while running.load(Ordering::SeqCst) {
            // Simulated capture delay
            thread::sleep(std::time::Duration::from_millis(100));

            // In real implementation:
            // 1. Read packet from pcap
            // 2. Parse into our Packet structure
            // 3. Determine direction
            // 4. Track in stream
            // 5. Send to channel
        }

        info!("Capture thread stopped");
    }

    fn determine_direction(packet: &Packet, config: &CaptureConfig) -> Direction {
        // Check if source is local
        let source_is_local = config.local_ips.contains(&packet.info.source_ip);
        let dest_is_local = config.local_ips.contains(&packet.info.dest_ip);

        if source_is_local && !dest_is_local {
            Direction::Outbound
        } else if !source_is_local && dest_is_local {
            Direction::Inbound
        } else {
            Direction::Unknown
        }
    }

    fn get_stream_key(packet: &Packet) -> String {
        let (ip1, port1, ip2, port2) = if packet.info.source_ip < packet.info.dest_ip {
            (
                packet.info.source_ip,
                packet.info.source_port,
                packet.info.dest_ip,
                packet.info.dest_port,
            )
        } else {
            (
                packet.info.dest_ip,
                packet.info.dest_port,
                packet.info.source_ip,
                packet.info.source_port,
            )
        };

        format!("{}:{}-{}:{}", ip1, port1, ip2, port2)
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            let _ = self.stop();
        }
    }
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub addresses: Vec<IpAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// BPF filter builder
pub struct FilterBuilder {
    conditions: Vec<String>,
}

impl FilterBuilder {
    /// Create a new filter builder
    pub fn new() -> Self {
        Self {
            conditions: Vec::new(),
        }
    }

    /// Add a host filter
    pub fn host(mut self, ip: &str) -> Self {
        self.conditions.push(format!("host {}", ip));
        self
    }

    /// Add a port filter
    pub fn port(mut self, port: u16) -> Self {
        self.conditions.push(format!("port {}", port));
        self
    }

    /// Add multiple ports
    pub fn ports(mut self, ports: &[u16]) -> Self {
        if !ports.is_empty() {
            let port_list = ports
                .iter()
                .map(|p| format!("port {}", p))
                .collect::<Vec<_>>()
                .join(" or ");
            self.conditions.push(format!("({})", port_list));
        }
        self
    }

    /// Add TCP filter
    pub fn tcp(mut self) -> Self {
        self.conditions.push("tcp".to_string());
        self
    }

    /// Add UDP filter
    pub fn udp(mut self) -> Self {
        self.conditions.push("udp".to_string());
        self
    }

    /// Build the filter string
    pub fn build(self) -> String {
        self.conditions.join(" and ")
    }
}

impl Default for FilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_builder() {
        let filter = FilterBuilder::new()
            .tcp()
            .ports(&[443, 8080])
            .build();

        assert!(filter.contains("tcp"));
        assert!(filter.contains("port 443"));
        assert!(filter.contains("port 8080"));
    }
}
