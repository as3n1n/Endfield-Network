//! Packet analysis and pattern detection

use crate::packet::{ContentType, DecodedContent, Packet, PacketStream, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// Packet analyzer
pub struct PacketAnalyzer {
    patterns: Vec<AnalysisPattern>,
    protocol_hints: HashMap<u16, String>,
}

/// Analysis pattern for detecting specific packet types
#[derive(Debug, Clone)]
pub struct AnalysisPattern {
    pub name: String,
    pub description: String,
    pub matcher: PatternMatcher,
}

/// Pattern matching criteria
#[derive(Debug, Clone)]
pub enum PatternMatcher {
    /// Match by port
    Port(u16),
    /// Match by port range
    PortRange(u16, u16),
    /// Match by payload prefix
    PayloadPrefix(Vec<u8>),
    /// Match by payload pattern at offset
    PayloadPattern { offset: usize, pattern: Vec<u8> },
    /// Match by payload containing bytes
    PayloadContains(Vec<u8>),
    /// Custom matcher function name
    Custom(String),
}

impl PatternMatcher {
    /// Check if packet matches
    pub fn matches(&self, packet: &Packet) -> bool {
        match self {
            PatternMatcher::Port(port) => {
                packet.info.source_port == *port || packet.info.dest_port == *port
            }
            PatternMatcher::PortRange(start, end) => {
                (packet.info.source_port >= *start && packet.info.source_port <= *end)
                    || (packet.info.dest_port >= *start && packet.info.dest_port <= *end)
            }
            PatternMatcher::PayloadPrefix(prefix) => packet.payload.starts_with(prefix),
            PatternMatcher::PayloadPattern { offset, pattern } => {
                if packet.payload.len() >= offset + pattern.len() {
                    &packet.payload[*offset..*offset + pattern.len()] == pattern.as_slice()
                } else {
                    false
                }
            }
            PatternMatcher::PayloadContains(pattern) => {
                packet
                    .payload
                    .windows(pattern.len())
                    .any(|window| window == pattern.as_slice())
            }
            PatternMatcher::Custom(_) => false, // Custom matchers need special handling
        }
    }
}

impl PacketAnalyzer {
    /// Create a new analyzer with default patterns
    pub fn new() -> Self {
        let mut analyzer = Self {
            patterns: Vec::new(),
            protocol_hints: HashMap::new(),
        };

        // Add default patterns
        analyzer.add_default_patterns();
        analyzer.add_default_hints();

        analyzer
    }

    fn add_default_patterns(&mut self) {
        // HTTP patterns
        self.patterns.push(AnalysisPattern {
            name: "HTTP Request".to_string(),
            description: "HTTP request detected".to_string(),
            matcher: PatternMatcher::PayloadPrefix(b"GET ".to_vec()),
        });
        self.patterns.push(AnalysisPattern {
            name: "HTTP Request".to_string(),
            description: "HTTP request detected".to_string(),
            matcher: PatternMatcher::PayloadPrefix(b"POST ".to_vec()),
        });
        self.patterns.push(AnalysisPattern {
            name: "HTTP Response".to_string(),
            description: "HTTP response detected".to_string(),
            matcher: PatternMatcher::PayloadPrefix(b"HTTP/".to_vec()),
        });

        // TLS/SSL
        self.patterns.push(AnalysisPattern {
            name: "TLS Handshake".to_string(),
            description: "TLS handshake detected".to_string(),
            matcher: PatternMatcher::PayloadPattern {
                offset: 0,
                pattern: vec![0x16, 0x03], // TLS handshake, version 3.x
            },
        });

        // WebSocket
        self.patterns.push(AnalysisPattern {
            name: "WebSocket Upgrade".to_string(),
            description: "WebSocket upgrade request".to_string(),
            matcher: PatternMatcher::PayloadContains(b"Upgrade: websocket".to_vec()),
        });

        // Protobuf (common in game protocols)
        self.patterns.push(AnalysisPattern {
            name: "Protobuf Message".to_string(),
            description: "Possible protobuf message".to_string(),
            matcher: PatternMatcher::PayloadPattern {
                offset: 0,
                pattern: vec![0x08], // Common protobuf field tag
            },
        });
    }

    fn add_default_hints(&mut self) {
        self.protocol_hints.insert(80, "HTTP".to_string());
        self.protocol_hints.insert(443, "HTTPS/TLS".to_string());
        self.protocol_hints.insert(8080, "HTTP Alt".to_string());
        self.protocol_hints.insert(8443, "HTTPS Alt".to_string());
        self.protocol_hints.insert(9000, "Game Server".to_string());
        self.protocol_hints.insert(9001, "Game Server".to_string());
    }

    /// Add a custom pattern
    pub fn add_pattern(&mut self, pattern: AnalysisPattern) {
        self.patterns.push(pattern);
    }

    /// Add a protocol hint for a port
    pub fn add_protocol_hint(&mut self, port: u16, protocol: impl Into<String>) {
        self.protocol_hints.insert(port, protocol.into());
    }

    /// Analyze a packet
    pub fn analyze(&self, packet: &Packet) -> AnalysisResult {
        let mut result = AnalysisResult {
            matched_patterns: Vec::new(),
            protocol_hint: None,
            content_type: ContentType::Unknown,
            is_encrypted: false,
            notes: Vec::new(),
        };

        // Check port hints
        if let Some(hint) = self.protocol_hints.get(&packet.info.dest_port) {
            result.protocol_hint = Some(hint.clone());
        } else if let Some(hint) = self.protocol_hints.get(&packet.info.source_port) {
            result.protocol_hint = Some(hint.clone());
        }

        // Check patterns
        for pattern in &self.patterns {
            if pattern.matcher.matches(packet) {
                result.matched_patterns.push(pattern.name.clone());
            }
        }

        // Detect content type
        result.content_type = self.detect_content_type(packet);

        // Check for encryption
        result.is_encrypted = self.detect_encryption(packet);

        result
    }

    /// Analyze a stream of packets
    pub fn analyze_stream(&self, stream: &PacketStream, packets: &[Packet]) -> StreamAnalysis {
        let mut analysis = StreamAnalysis {
            stream_id: stream.id,
            protocol_guess: None,
            message_count: 0,
            request_count: 0,
            response_count: 0,
            patterns_seen: Vec::new(),
            timeline: Vec::new(),
        };

        for packet in packets {
            if !stream.packets.contains(&packet.info.id) {
                continue;
            }

            let result = self.analyze(packet);

            // Track patterns
            for pattern in &result.matched_patterns {
                if !analysis.patterns_seen.contains(pattern) {
                    analysis.patterns_seen.push(pattern.clone());
                }
            }

            // Update protocol guess
            if analysis.protocol_guess.is_none() {
                analysis.protocol_guess = result.protocol_hint.clone();
            }

            // Count messages
            if packet.has_data() {
                analysis.message_count += 1;

                // Try to determine if request or response
                if packet.info.source_ip == stream.source_ip {
                    analysis.request_count += 1;
                } else {
                    analysis.response_count += 1;
                }
            }

            // Add to timeline
            analysis.timeline.push(StreamEvent {
                timestamp: packet.info.timestamp,
                packet_id: packet.info.id,
                direction: if packet.info.source_ip == stream.source_ip {
                    "outbound".to_string()
                } else {
                    "inbound".to_string()
                },
                size: packet.info.payload_len,
                patterns: result.matched_patterns,
            });
        }

        analysis
    }

    fn detect_content_type(&self, packet: &Packet) -> ContentType {
        if packet.payload.is_empty() {
            return ContentType::Unknown;
        }

        // Check for text content
        if packet.payload.iter().all(|&b| {
            b.is_ascii_graphic() || b.is_ascii_whitespace()
        }) {
            // Try to detect JSON
            if packet.payload.starts_with(b"{") || packet.payload.starts_with(b"[") {
                return ContentType::Json;
            }
            return ContentType::Text;
        }

        // Check for MessagePack
        if packet.payload.len() >= 1 {
            let first = packet.payload[0];
            // MessagePack map or array markers
            if (0x80..=0x8f).contains(&first) || (0x90..=0x9f).contains(&first) {
                return ContentType::MessagePack;
            }
        }

        ContentType::Binary
    }

    fn detect_encryption(&self, packet: &Packet) -> bool {
        if packet.payload.len() < 5 {
            return false;
        }

        // TLS record
        if packet.payload[0] >= 0x14 && packet.payload[0] <= 0x18 {
            if packet.payload[1] == 0x03 && packet.payload[2] <= 0x03 {
                return true;
            }
        }

        // High entropy (simple check)
        let mut byte_counts = [0u32; 256];
        for &b in &packet.payload {
            byte_counts[b as usize] += 1;
        }
        let non_zero = byte_counts.iter().filter(|&&c| c > 0).count();

        // Encrypted data tends to have high entropy (many different byte values)
        non_zero > 200 && packet.payload.len() > 100
    }
}

impl Default for PacketAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Analysis result for a single packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub matched_patterns: Vec<String>,
    pub protocol_hint: Option<String>,
    pub content_type: ContentType,
    pub is_encrypted: bool,
    pub notes: Vec<String>,
}

/// Analysis of a packet stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamAnalysis {
    pub stream_id: uuid::Uuid,
    pub protocol_guess: Option<String>,
    pub message_count: usize,
    pub request_count: usize,
    pub response_count: usize,
    pub patterns_seen: Vec<String>,
    pub timeline: Vec<StreamEvent>,
}

/// Event in a stream timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub packet_id: uuid::Uuid,
    pub direction: String,
    pub size: usize,
    pub patterns: Vec<String>,
}
