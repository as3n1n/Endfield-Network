//! Packet payload decoding

use crate::packet::{ContentType, DecodedContent, Packet};
use serde_json::Value as JsonValue;
use thiserror::Error;

/// Decoding errors
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Unsupported content type")]
    UnsupportedContentType,
    #[error("Decode failed: {0}")]
    DecodeFailed(String),
}

pub type DecodeResult<T> = std::result::Result<T, DecodeError>;

/// Packet decoder
pub struct PacketDecoder {
    decoders: Vec<Box<dyn PayloadDecoder>>,
}

/// Trait for payload decoders
pub trait PayloadDecoder: Send + Sync {
    /// Name of the decoder
    fn name(&self) -> &str;

    /// Check if this decoder can handle the payload
    fn can_decode(&self, packet: &Packet) -> bool;

    /// Decode the payload
    fn decode(&self, packet: &Packet) -> DecodeResult<DecodedContent>;
}

impl PacketDecoder {
    /// Create a new decoder with default decoders
    pub fn new() -> Self {
        let mut decoder = Self {
            decoders: Vec::new(),
        };

        // Add default decoders
        decoder.add_decoder(Box::new(JsonDecoder));
        decoder.add_decoder(Box::new(TextDecoder));
        decoder.add_decoder(Box::new(HttpDecoder));
        decoder.add_decoder(Box::new(HexDecoder));

        decoder
    }

    /// Add a custom decoder
    pub fn add_decoder(&mut self, decoder: Box<dyn PayloadDecoder>) {
        self.decoders.push(decoder);
    }

    /// Decode a packet
    pub fn decode(&self, packet: &Packet) -> Option<DecodedContent> {
        for decoder in &self.decoders {
            if decoder.can_decode(packet) {
                if let Ok(content) = decoder.decode(packet) {
                    return Some(content);
                }
            }
        }
        None
    }

    /// Try all decoders and return the best result
    pub fn decode_best(&self, packet: &Packet) -> DecodedContent {
        for decoder in &self.decoders {
            if decoder.can_decode(packet) {
                if let Ok(content) = decoder.decode(packet) {
                    return content;
                }
            }
        }

        // Fallback to hex dump
        DecodedContent {
            content_type: ContentType::Binary,
            text: Some(hex_dump(&packet.payload, 16)),
            structured: None,
            notes: vec!["No decoder matched, showing hex dump".to_string()],
        }
    }
}

impl Default for PacketDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// JSON payload decoder
struct JsonDecoder;

impl PayloadDecoder for JsonDecoder {
    fn name(&self) -> &str {
        "JSON"
    }

    fn can_decode(&self, packet: &Packet) -> bool {
        if packet.payload.is_empty() {
            return false;
        }

        let first = packet.payload[0];
        first == b'{' || first == b'['
    }

    fn decode(&self, packet: &Packet) -> DecodeResult<DecodedContent> {
        let text = std::str::from_utf8(&packet.payload)
            .map_err(|e| DecodeError::InvalidFormat(e.to_string()))?;

        let json: JsonValue = serde_json::from_str(text)
            .map_err(|e| DecodeError::DecodeFailed(e.to_string()))?;

        let pretty = serde_json::to_string_pretty(&json)
            .map_err(|e| DecodeError::DecodeFailed(e.to_string()))?;

        Ok(DecodedContent {
            content_type: ContentType::Json,
            text: Some(pretty),
            structured: Some(json),
            notes: Vec::new(),
        })
    }
}

/// Plain text decoder
struct TextDecoder;

impl PayloadDecoder for TextDecoder {
    fn name(&self) -> &str {
        "Text"
    }

    fn can_decode(&self, packet: &Packet) -> bool {
        if packet.payload.is_empty() {
            return false;
        }

        // Check if mostly printable ASCII
        let printable_count = packet
            .payload
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();

        printable_count as f64 / packet.payload.len() as f64 > 0.9
    }

    fn decode(&self, packet: &Packet) -> DecodeResult<DecodedContent> {
        let text = String::from_utf8_lossy(&packet.payload).to_string();

        Ok(DecodedContent {
            content_type: ContentType::Text,
            text: Some(text),
            structured: None,
            notes: Vec::new(),
        })
    }
}

/// HTTP decoder
struct HttpDecoder;

impl PayloadDecoder for HttpDecoder {
    fn name(&self) -> &str {
        "HTTP"
    }

    fn can_decode(&self, packet: &Packet) -> bool {
        if packet.payload.len() < 4 {
            return false;
        }

        // Check for HTTP request methods or response
        packet.payload.starts_with(b"GET ")
            || packet.payload.starts_with(b"POST ")
            || packet.payload.starts_with(b"PUT ")
            || packet.payload.starts_with(b"DELETE ")
            || packet.payload.starts_with(b"HEAD ")
            || packet.payload.starts_with(b"OPTIONS ")
            || packet.payload.starts_with(b"PATCH ")
            || packet.payload.starts_with(b"HTTP/")
    }

    fn decode(&self, packet: &Packet) -> DecodeResult<DecodedContent> {
        let text = String::from_utf8_lossy(&packet.payload).to_string();

        // Parse HTTP
        let mut lines = text.lines();
        let first_line = lines.next().unwrap_or("");

        let mut headers = Vec::new();
        let mut body_start = 0;

        for line in lines {
            if line.is_empty() {
                break;
            }
            headers.push(line.to_string());
            body_start += line.len() + 1;
        }

        // Build structured representation
        let structured = serde_json::json!({
            "request_line": first_line,
            "headers": headers,
            "body_preview": if body_start < text.len() {
                Some(&text[body_start..body_start.min(text.len()).min(body_start + 1000)])
            } else {
                None
            }
        });

        let mut notes = Vec::new();
        if first_line.starts_with("HTTP/") {
            notes.push(format!("Response: {}", first_line));
        } else {
            notes.push(format!("Request: {}", first_line));
        }

        Ok(DecodedContent {
            content_type: ContentType::Text,
            text: Some(text),
            structured: Some(structured),
            notes,
        })
    }
}

/// Hex dump decoder (fallback)
struct HexDecoder;

impl PayloadDecoder for HexDecoder {
    fn name(&self) -> &str {
        "Hex"
    }

    fn can_decode(&self, packet: &Packet) -> bool {
        !packet.payload.is_empty()
    }

    fn decode(&self, packet: &Packet) -> DecodeResult<DecodedContent> {
        Ok(DecodedContent {
            content_type: ContentType::Binary,
            text: Some(hex_dump(&packet.payload, 16)),
            structured: None,
            notes: vec![format!("{} bytes", packet.payload.len())],
        })
    }
}

/// Create a hex dump of data
pub fn hex_dump(data: &[u8], bytes_per_line: usize) -> String {
    let mut output = String::new();

    for (i, chunk) in data.chunks(bytes_per_line).enumerate() {
        let offset = i * bytes_per_line;

        // Offset
        output.push_str(&format!("{:08x}  ", offset));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }

        // Padding for incomplete lines
        if chunk.len() < bytes_per_line {
            for j in chunk.len()..bytes_per_line {
                output.push_str("   ");
                if j == 7 {
                    output.push(' ');
                }
            }
        }

        output.push(' ');

        // ASCII representation
        output.push('|');
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push('|');
        output.push('\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_dump() {
        let data = b"Hello, World!";
        let dump = hex_dump(data, 16);
        assert!(dump.contains("48 65 6c 6c 6f"));
        assert!(dump.contains("|Hello, World!|"));
    }

    #[test]
    fn test_json_decoder() {
        let decoder = JsonDecoder;
        let packet = crate::packet::Packet {
            info: crate::packet::PacketInfo {
                id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                source_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                source_port: 1234,
                dest_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                dest_port: 80,
                protocol: crate::packet::Protocol::TCP,
                direction: crate::packet::Direction::Outbound,
                tcp_flags: None,
                tcp_seq: None,
                tcp_ack: None,
                payload_len: 0,
                total_len: 0,
            },
            raw: Vec::new(),
            payload: br#"{"test": "value"}"#.to_vec(),
            decoded: None,
        };

        assert!(decoder.can_decode(&packet));
        let result = decoder.decode(&packet).unwrap();
        assert_eq!(result.content_type, ContentType::Json);
    }
}
