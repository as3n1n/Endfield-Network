//! Application theming

use egui::{Color32, FontFamily, FontId, Rounding, Stroke, Style, TextStyle, Visuals};

/// Application theme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Dark,
    Light,
    Cyberpunk,
}

impl Theme {
    /// Apply theme to egui context
    pub fn apply(&self, ctx: &egui::Context) {
        let visuals = match self {
            Theme::Dark => dark_visuals(),
            Theme::Light => light_visuals(),
            Theme::Cyberpunk => cyberpunk_visuals(),
        };

        ctx.set_visuals(visuals);
        ctx.set_style(custom_style());
    }

    /// Get the primary accent color
    pub fn accent_color(&self) -> Color32 {
        match self {
            Theme::Dark => Color32::from_rgb(100, 149, 237), // Cornflower blue
            Theme::Light => Color32::from_rgb(59, 130, 246), // Blue
            Theme::Cyberpunk => Color32::from_rgb(0, 255, 136), // Neon green
        }
    }

    /// Get secondary accent color
    pub fn secondary_color(&self) -> Color32 {
        match self {
            Theme::Dark => Color32::from_rgb(156, 163, 175),
            Theme::Light => Color32::from_rgb(107, 114, 128),
            Theme::Cyberpunk => Color32::from_rgb(255, 0, 128), // Neon pink
        }
    }

    /// Get success color
    pub fn success_color(&self) -> Color32 {
        match self {
            Theme::Cyberpunk => Color32::from_rgb(0, 255, 136),
            _ => Color32::from_rgb(34, 197, 94),
        }
    }

    /// Get warning color
    pub fn warning_color(&self) -> Color32 {
        match self {
            Theme::Cyberpunk => Color32::from_rgb(255, 200, 0),
            _ => Color32::from_rgb(234, 179, 8),
        }
    }

    /// Get error color
    pub fn error_color(&self) -> Color32 {
        match self {
            Theme::Cyberpunk => Color32::from_rgb(255, 0, 64),
            _ => Color32::from_rgb(239, 68, 68),
        }
    }

    /// Get background color for panels
    pub fn panel_bg(&self) -> Color32 {
        match self {
            Theme::Dark => Color32::from_rgb(30, 32, 40),
            Theme::Light => Color32::from_rgb(249, 250, 251),
            Theme::Cyberpunk => Color32::from_rgb(10, 10, 20),
        }
    }

    /// Get background color for cards
    pub fn card_bg(&self) -> Color32 {
        match self {
            Theme::Dark => Color32::from_rgb(40, 42, 54),
            Theme::Light => Color32::WHITE,
            Theme::Cyberpunk => Color32::from_rgb(20, 20, 35),
        }
    }
}

fn dark_visuals() -> Visuals {
    let mut visuals = Visuals::dark();

    // Background colors
    visuals.window_fill = Color32::from_rgb(24, 26, 32);
    visuals.panel_fill = Color32::from_rgb(30, 32, 40);
    visuals.faint_bg_color = Color32::from_rgb(35, 38, 48);
    visuals.extreme_bg_color = Color32::from_rgb(20, 22, 28);

    // Widget colors
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(40, 42, 54);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(200, 200, 220));
    visuals.widgets.noninteractive.rounding = Rounding::same(8.0);

    visuals.widgets.inactive.bg_fill = Color32::from_rgb(50, 52, 64);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(180, 180, 200));
    visuals.widgets.inactive.rounding = Rounding::same(8.0);

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(60, 65, 80);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::from_rgb(220, 220, 240));
    visuals.widgets.hovered.rounding = Rounding::same(8.0);

    visuals.widgets.active.bg_fill = Color32::from_rgb(100, 149, 237);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.rounding = Rounding::same(8.0);

    // Selection
    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(100, 149, 237, 100);
    visuals.selection.stroke = Stroke::new(1.0, Color32::from_rgb(100, 149, 237));

    // Window
    visuals.window_rounding = Rounding::same(12.0);
    visuals.window_shadow.extrusion = 16.0;
    visuals.window_stroke = Stroke::new(1.0, Color32::from_rgb(50, 52, 64));

    // Misc
    visuals.resize_corner_size = 12.0;
    visuals.hyperlink_color = Color32::from_rgb(100, 149, 237);
    visuals.warn_fg_color = Color32::from_rgb(234, 179, 8);
    visuals.error_fg_color = Color32::from_rgb(239, 68, 68);

    visuals
}

fn light_visuals() -> Visuals {
    let mut visuals = Visuals::light();

    visuals.window_fill = Color32::WHITE;
    visuals.panel_fill = Color32::from_rgb(249, 250, 251);
    visuals.faint_bg_color = Color32::from_rgb(243, 244, 246);

    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(243, 244, 246);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(55, 65, 81));
    visuals.widgets.noninteractive.rounding = Rounding::same(8.0);

    visuals.widgets.inactive.bg_fill = Color32::from_rgb(229, 231, 235);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(75, 85, 99));
    visuals.widgets.inactive.rounding = Rounding::same(8.0);

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(209, 213, 219);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::from_rgb(31, 41, 55));
    visuals.widgets.hovered.rounding = Rounding::same(8.0);

    visuals.widgets.active.bg_fill = Color32::from_rgb(59, 130, 246);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.rounding = Rounding::same(8.0);

    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(59, 130, 246, 60);
    visuals.selection.stroke = Stroke::new(1.0, Color32::from_rgb(59, 130, 246));

    visuals.window_rounding = Rounding::same(12.0);
    visuals.window_shadow.extrusion = 8.0;
    visuals.window_stroke = Stroke::new(1.0, Color32::from_rgb(229, 231, 235));

    visuals
}

fn cyberpunk_visuals() -> Visuals {
    let mut visuals = Visuals::dark();

    // Deep dark background with blue tint
    visuals.window_fill = Color32::from_rgb(5, 5, 15);
    visuals.panel_fill = Color32::from_rgb(10, 10, 25);
    visuals.faint_bg_color = Color32::from_rgb(15, 15, 35);
    visuals.extreme_bg_color = Color32::from_rgb(2, 2, 8);

    // Neon accents
    let neon_green = Color32::from_rgb(0, 255, 136);
    let neon_pink = Color32::from_rgb(255, 0, 128);
    let neon_blue = Color32::from_rgb(0, 200, 255);

    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(15, 15, 30);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, neon_green);
    visuals.widgets.noninteractive.rounding = Rounding::same(4.0);

    visuals.widgets.inactive.bg_fill = Color32::from_rgb(20, 20, 40);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(100, 255, 180));
    visuals.widgets.inactive.rounding = Rounding::same(4.0);

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(30, 30, 60);
    visuals.widgets.hovered.fg_stroke = Stroke::new(2.0, neon_green);
    visuals.widgets.hovered.rounding = Rounding::same(4.0);

    visuals.widgets.active.bg_fill = neon_pink;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.rounding = Rounding::same(4.0);

    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(0, 255, 136, 50);
    visuals.selection.stroke = Stroke::new(2.0, neon_green);

    visuals.window_rounding = Rounding::same(4.0);
    visuals.window_shadow.extrusion = 20.0;
    visuals.window_shadow.color = Color32::from_rgba_unmultiplied(0, 255, 136, 30);
    visuals.window_stroke = Stroke::new(1.0, neon_green);

    visuals.hyperlink_color = neon_blue;
    visuals.warn_fg_color = Color32::from_rgb(255, 200, 0);
    visuals.error_fg_color = Color32::from_rgb(255, 0, 64);

    visuals
}

fn custom_style() -> Style {
    let mut style = Style::default();

    // Text styles
    style.text_styles = [
        (TextStyle::Small, FontId::new(12.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Heading, FontId::new(20.0, FontFamily::Proportional)),
    ]
    .into();

    // Spacing
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.window_margin = egui::Margin::same(16.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.indent = 20.0;
    style.spacing.scroll_bar_width = 10.0;

    // Animation
    style.animation_time = 0.15;

    style
}

/// Color utilities
pub mod colors {
    use super::*;

    pub fn with_alpha(color: Color32, alpha: u8) -> Color32 {
        Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha)
    }

    pub fn lerp(a: Color32, b: Color32, t: f32) -> Color32 {
        let t = t.clamp(0.0, 1.0);
        Color32::from_rgba_unmultiplied(
            (a.r() as f32 * (1.0 - t) + b.r() as f32 * t) as u8,
            (a.g() as f32 * (1.0 - t) + b.g() as f32 * t) as u8,
            (a.b() as f32 * (1.0 - t) + b.b() as f32 * t) as u8,
            (a.a() as f32 * (1.0 - t) + b.a() as f32 * t) as u8,
        )
    }

    pub fn highlight(base: Color32, amount: f32) -> Color32 {
        lerp(base, Color32::WHITE, amount.clamp(0.0, 1.0))
    }

    pub fn darken(base: Color32, amount: f32) -> Color32 {
        lerp(base, Color32::BLACK, amount.clamp(0.0, 1.0))
    }
}
