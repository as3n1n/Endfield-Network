//! Dashboard view

use crate::state::AppState;
use crate::theme::Theme;
use crate::widgets::StatCard;
use egui::{RichText, Ui};

/// Dashboard view
pub struct DashboardView;

impl DashboardView {
    pub fn show(ui: &mut Ui, state: &mut AppState, theme: Theme) {
        ui.heading("Dashboard");
        ui.add_space(16.0);

        // Welcome section
        if state.project.is_none() {
            Self::show_welcome(ui, theme);
        } else {
            Self::show_project_overview(ui, state, theme);
        }
    }

    fn show_welcome(ui: &mut Ui, theme: Theme) {
        egui::Frame::none()
            .fill(theme.card_bg())
            .rounding(egui::Rounding::same(12.0))
            .inner_margin(egui::Margin::same(24.0))
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);

                    ui.label(
                        RichText::new("Welcome to Endfield Tracker")
                            .size(28.0)
                            .strong(),
                    );

                    ui.add_space(12.0);

                    ui.label(
                        RichText::new("IL2CPP Reverse Engineering & Network Analysis Tool")
                            .size(14.0)
                            .color(ui.visuals().weak_text_color()),
                    );

                    ui.add_space(32.0);

                    ui.horizontal(|ui| {
                        ui.add_space(ui.available_width() / 2.0 - 200.0);

                        if ui.button(RichText::new("Open Binary").size(14.0)).clicked() {
                            // TODO: Open file dialog
                        }

                        ui.add_space(16.0);

                        if ui.button(RichText::new("New Project").size(14.0)).clicked() {
                            // TODO: Create new project
                        }
                    });

                    ui.add_space(20.0);
                });
            });

        ui.add_space(24.0);

        // Quick actions
        ui.label(RichText::new("Quick Actions").size(16.0).strong());
        ui.add_space(12.0);

        ui.horizontal_wrapped(|ui| {
            Self::action_card(ui, "\u{1F4BE}", "Load IL2CPP Binary", "Analyze GameAssembly.dll or libil2cpp.so", theme);
            Self::action_card(ui, "\u{1F4C4}", "Load Metadata", "Parse global-metadata.dat", theme);
            Self::action_card(ui, "\u{1F310}", "Start Capture", "Begin network packet capture", theme);
            Self::action_card(ui, "\u{1F4C1}", "Open Recent", "Open a recent project", theme);
        });
    }

    fn action_card(ui: &mut Ui, icon: &str, title: &str, description: &str, theme: Theme) {
        let response = egui::Frame::none()
            .fill(theme.card_bg())
            .rounding(egui::Rounding::same(8.0))
            .inner_margin(egui::Margin::same(16.0))
            .show(ui, |ui| {
                ui.set_min_width(200.0);
                ui.set_min_height(100.0);

                ui.vertical(|ui| {
                    ui.label(RichText::new(icon).size(24.0));
                    ui.add_space(8.0);
                    ui.label(RichText::new(title).size(14.0).strong());
                    ui.label(
                        RichText::new(description)
                            .size(11.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                });
            });

        if response.response.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        }
    }

    fn show_project_overview(ui: &mut Ui, state: &mut AppState, theme: Theme) {
        // Statistics cards
        ui.horizontal_wrapped(|ui| {
            if let Some(ref results) = state.dump_results {
                ui.add(
                    StatCard::new("Types", results.statistics.total_types)
                        .icon("\u{1F4C4}")
                        .subtitle("Classes & Structs")
                        .color(theme.accent_color()),
                );

                ui.add(
                    StatCard::new("Methods", results.statistics.total_methods)
                        .icon("\u{2699}")
                        .subtitle("Functions")
                        .color(theme.success_color()),
                );

                ui.add(
                    StatCard::new("Fields", results.statistics.total_fields)
                        .icon("\u{1F4DD}")
                        .subtitle("Variables")
                        .color(theme.warning_color()),
                );

                ui.add(
                    StatCard::new("Strings", results.statistics.total_strings)
                        .icon("\u{1F4AC}")
                        .subtitle("Literals")
                        .color(theme.secondary_color()),
                );
            }
        });

        ui.add_space(24.0);

        // Network stats if capturing
        if state.capture.is_capturing {
            ui.label(RichText::new("Network Capture").size(16.0).strong());
            ui.add_space(12.0);

            ui.horizontal_wrapped(|ui| {
                ui.add(
                    StatCard::new("Packets", state.capture.stats.packets_captured)
                        .icon("\u{1F4E6}")
                        .color(theme.accent_color()),
                );

                ui.add(
                    StatCard::new("Bytes", format_bytes(state.capture.stats.bytes_captured))
                        .icon("\u{1F4CA}")
                        .color(theme.success_color()),
                );

                ui.add(
                    StatCard::new("Streams", state.capture.stats.streams_tracked)
                        .icon("\u{1F310}")
                        .color(theme.warning_color()),
                );
            });
        }

        ui.add_space(24.0);

        // Recent activity
        ui.label(RichText::new("Recent Activity").size(16.0).strong());
        ui.add_space(12.0);

        egui::Frame::none()
            .fill(theme.card_bg())
            .rounding(egui::Rounding::same(8.0))
            .inner_margin(egui::Margin::same(16.0))
            .show(ui, |ui| {
                ui.label(
                    RichText::new("No recent activity")
                        .color(ui.visuals().weak_text_color()),
                );
            });
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
