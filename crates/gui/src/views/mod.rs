//! Application views

mod dashboard;
mod dumper;
mod type_browser;
mod method_browser;
mod string_browser;
mod network;
mod settings;

pub use dashboard::DashboardView;
pub use dumper::DumperView;
pub use type_browser::TypeBrowserView;
pub use method_browser::MethodBrowserView;
pub use string_browser::StringBrowserView;
pub use network::NetworkView;
pub use settings::SettingsView;
