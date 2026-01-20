//! Modern GUI for Endfield Tracker using egui
//!
//! Provides a beautiful, responsive interface for:
//! - IL2CPP metadata browsing and analysis
//! - Network packet capture and analysis
//! - Project management

pub mod app;
pub mod theme;
pub mod views;
pub mod widgets;
pub mod state;

pub use app::EndfieldApp;
pub use theme::Theme;
