//! Core types and traits for Endfield Tracker
//!
//! This crate provides the foundational types used throughout the application.

pub mod error;
pub mod types;
pub mod config;
pub mod events;

pub use error::{Error, Result};
pub use types::*;
pub use config::Config;
