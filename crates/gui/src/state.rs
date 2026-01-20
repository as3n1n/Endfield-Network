//! Application state management

use endfield_core::{Config, DumpResults, ProjectState};
use endfield_network::capture::{CaptureStats, PacketCapture};
use endfield_network::packet::Packet;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Main application state
pub struct AppState {
    /// Current project
    pub project: Option<ProjectState>,
    /// Application configuration
    pub config: Config,
    /// IL2CPP dump results
    pub dump_results: Option<DumpResults>,
    /// Current tab
    pub current_tab: Tab,
    /// Packet capture state
    pub capture: CaptureState,
    /// Search state
    pub search: SearchState,
    /// Notification queue
    pub notifications: VecDeque<Notification>,
    /// Loading state
    pub loading: Option<LoadingState>,
    /// Sidebar collapsed
    pub sidebar_collapsed: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            project: None,
            config: Config::default(),
            dump_results: None,
            current_tab: Tab::Dashboard,
            capture: CaptureState::default(),
            search: SearchState::default(),
            notifications: VecDeque::new(),
            loading: None,
            sidebar_collapsed: false,
        }
    }
}

impl AppState {
    /// Add a notification
    pub fn notify(&mut self, notification: Notification) {
        self.notifications.push_back(notification);
        // Keep only last 10 notifications
        while self.notifications.len() > 10 {
            self.notifications.pop_front();
        }
    }

    /// Success notification
    pub fn notify_success(&mut self, message: impl Into<String>) {
        self.notify(Notification::success(message));
    }

    /// Error notification
    pub fn notify_error(&mut self, message: impl Into<String>) {
        self.notify(Notification::error(message));
    }

    /// Info notification
    pub fn notify_info(&mut self, message: impl Into<String>) {
        self.notify(Notification::info(message));
    }

    /// Start loading
    pub fn start_loading(&mut self, message: impl Into<String>) {
        self.loading = Some(LoadingState {
            message: message.into(),
            progress: None,
        });
    }

    /// Update loading progress
    pub fn update_loading(&mut self, progress: f32, message: impl Into<String>) {
        self.loading = Some(LoadingState {
            message: message.into(),
            progress: Some(progress),
        });
    }

    /// Stop loading
    pub fn stop_loading(&mut self) {
        self.loading = None;
    }
}

/// Application tabs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tab {
    Dashboard,
    Il2CppDumper,
    TypeBrowser,
    MethodBrowser,
    StringBrowser,
    NetworkCapture,
    PacketAnalyzer,
    Settings,
}

impl Tab {
    pub fn label(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Il2CppDumper => "IL2CPP Dumper",
            Tab::TypeBrowser => "Types",
            Tab::MethodBrowser => "Methods",
            Tab::StringBrowser => "Strings",
            Tab::NetworkCapture => "Network",
            Tab::PacketAnalyzer => "Packets",
            Tab::Settings => "Settings",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Tab::Dashboard => "\u{1F3E0}",      // House
            Tab::Il2CppDumper => "\u{1F4BE}",   // Floppy
            Tab::TypeBrowser => "\u{1F4C4}",   // Document
            Tab::MethodBrowser => "\u{2699}",  // Gear
            Tab::StringBrowser => "\u{1F4DD}", // Memo
            Tab::NetworkCapture => "\u{1F310}", // Globe
            Tab::PacketAnalyzer => "\u{1F4E6}", // Package
            Tab::Settings => "\u{2699}",       // Gear
        }
    }

    pub fn all() -> &'static [Tab] {
        &[
            Tab::Dashboard,
            Tab::Il2CppDumper,
            Tab::TypeBrowser,
            Tab::MethodBrowser,
            Tab::StringBrowser,
            Tab::NetworkCapture,
            Tab::PacketAnalyzer,
            Tab::Settings,
        ]
    }
}

/// Packet capture state
#[derive(Default)]
pub struct CaptureState {
    /// Is capture running
    pub is_capturing: bool,
    /// Capture statistics
    pub stats: CaptureStats,
    /// Captured packets (limited buffer)
    pub packets: VecDeque<Packet>,
    /// Selected packet index
    pub selected_packet: Option<usize>,
    /// Filter text
    pub filter_text: String,
    /// Max packets to keep in memory
    pub max_packets: usize,
}

impl CaptureState {
    pub fn new() -> Self {
        Self {
            max_packets: 10000,
            ..Default::default()
        }
    }

    pub fn add_packet(&mut self, packet: Packet) {
        self.packets.push_back(packet);
        while self.packets.len() > self.max_packets {
            self.packets.pop_front();
        }
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.selected_packet = None;
    }
}

/// Search state
#[derive(Default)]
pub struct SearchState {
    /// Search query
    pub query: String,
    /// Search in types
    pub search_types: bool,
    /// Search in methods
    pub search_methods: bool,
    /// Search in strings
    pub search_strings: bool,
    /// Case sensitive
    pub case_sensitive: bool,
    /// Use regex
    pub use_regex: bool,
    /// Search results
    pub results: Vec<SearchResult>,
}

impl SearchState {
    pub fn new() -> Self {
        Self {
            search_types: true,
            search_methods: true,
            search_strings: true,
            ..Default::default()
        }
    }
}

/// Search result
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub result_type: SearchResultType,
    pub name: String,
    pub full_name: String,
    pub context: String,
    pub index: usize,
}

/// Search result type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchResultType {
    Type,
    Method,
    Field,
    String,
}

/// Notification message
#[derive(Debug, Clone)]
pub struct Notification {
    pub id: u64,
    pub message: String,
    pub level: NotificationLevel,
    pub timestamp: std::time::Instant,
    pub dismissed: bool,
}

impl Notification {
    pub fn new(message: impl Into<String>, level: NotificationLevel) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self {
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            message: message.into(),
            level,
            timestamp: std::time::Instant::now(),
            dismissed: false,
        }
    }

    pub fn success(message: impl Into<String>) -> Self {
        Self::new(message, NotificationLevel::Success)
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::new(message, NotificationLevel::Error)
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(message, NotificationLevel::Warning)
    }

    pub fn info(message: impl Into<String>) -> Self {
        Self::new(message, NotificationLevel::Info)
    }

    pub fn age_seconds(&self) -> f32 {
        self.timestamp.elapsed().as_secs_f32()
    }
}

/// Notification level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationLevel {
    Success,
    Error,
    Warning,
    Info,
}

/// Loading state
#[derive(Debug, Clone)]
pub struct LoadingState {
    pub message: String,
    pub progress: Option<f32>,
}

/// Type browser state
#[derive(Default)]
pub struct TypeBrowserState {
    pub filter: String,
    pub selected_type: Option<usize>,
    pub expanded_types: std::collections::HashSet<usize>,
    pub show_fields: bool,
    pub show_methods: bool,
    pub show_properties: bool,
    pub namespace_filter: Option<String>,
}

/// Method browser state
#[derive(Default)]
pub struct MethodBrowserState {
    pub filter: String,
    pub selected_method: Option<usize>,
    pub show_static_only: bool,
    pub show_virtual_only: bool,
    pub class_filter: Option<String>,
}

/// String browser state
#[derive(Default)]
pub struct StringBrowserState {
    pub filter: String,
    pub selected_string: Option<usize>,
    pub min_length: usize,
    pub max_length: Option<usize>,
}
