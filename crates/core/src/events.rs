//! Event types for inter-component communication

use crate::types::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Application events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppEvent {
    // Project events
    ProjectCreated(Uuid),
    ProjectLoaded(Uuid),
    ProjectSaved(Uuid),
    ProjectClosed,

    // IL2CPP events
    DumpStarted,
    DumpProgress { current: usize, total: usize, message: String },
    DumpCompleted(DumpResults),
    DumpFailed(String),

    // Network events
    CaptureStarted(Uuid),
    CaptureStoppped(Uuid),
    PacketCaptured(CapturedPacket),
    PacketDecoded { packet_id: Uuid, decoded: String },

    // UI events
    TabChanged(TabId),
    FilterChanged(String),
    SearchRequested(String),

    // Error events
    Error(String),
    Warning(String),
    Info(String),
}

/// Tab identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TabId {
    Dashboard,
    Il2CppDumper,
    NetworkCapture,
    TypeBrowser,
    MethodBrowser,
    StringBrowser,
    PacketAnalyzer,
    Settings,
}

impl std::fmt::Display for TabId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TabId::Dashboard => write!(f, "Dashboard"),
            TabId::Il2CppDumper => write!(f, "IL2CPP Dumper"),
            TabId::NetworkCapture => write!(f, "Network Capture"),
            TabId::TypeBrowser => write!(f, "Types"),
            TabId::MethodBrowser => write!(f, "Methods"),
            TabId::StringBrowser => write!(f, "Strings"),
            TabId::PacketAnalyzer => write!(f, "Packet Analyzer"),
            TabId::Settings => write!(f, "Settings"),
        }
    }
}

/// Event bus for broadcasting events
pub struct EventBus {
    subscribers: Vec<Box<dyn Fn(&AppEvent) + Send + Sync>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn subscribe<F>(&mut self, callback: F)
    where
        F: Fn(&AppEvent) + Send + Sync + 'static,
    {
        self.subscribers.push(Box::new(callback));
    }

    pub fn emit(&self, event: AppEvent) {
        for subscriber in &self.subscribers {
            subscriber(&event);
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
