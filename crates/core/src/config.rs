//! Application configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Application theme
    pub theme: Theme,
    /// Default export directory
    pub export_dir: Option<PathBuf>,
    /// Network capture settings
    pub network: NetworkConfig,
    /// Security settings
    pub security: SecurityConfig,
    /// Recent projects
    pub recent_projects: Vec<PathBuf>,
    /// Max recent projects to remember
    pub max_recent_projects: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            export_dir: None,
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            recent_projects: Vec::new(),
            max_recent_projects: 10,
        }
    }
}

/// UI Theme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    Dark,
    Light,
    Custom,
}

/// Network capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network interface to capture on
    pub interface: Option<String>,
    /// Capture filter (BPF syntax)
    pub filter: Option<String>,
    /// Auto-start capture
    pub auto_start: bool,
    /// Known game server IPs
    pub game_servers: Vec<String>,
    /// Known game ports
    pub game_ports: Vec<u16>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interface: None,
            filter: None,
            auto_start: false,
            game_servers: Vec::new(),
            game_ports: vec![443, 8080, 9000],
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Encrypt saved projects
    pub encrypt_projects: bool,
    /// Verify binary integrity before loading
    pub verify_integrity: bool,
    /// Use secure memory for sensitive data
    pub secure_memory: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            encrypt_projects: true,
            verify_integrity: true,
            secure_memory: true,
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content).map_err(|e| crate::Error::parse(e.to_string()))
    }

    /// Save configuration to file
    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| crate::Error::parse(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Add a recent project
    pub fn add_recent_project(&mut self, path: PathBuf) {
        self.recent_projects.retain(|p| p != &path);
        self.recent_projects.insert(0, path);
        self.recent_projects.truncate(self.max_recent_projects);
    }
}
