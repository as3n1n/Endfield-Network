//! Notification toast widget

use crate::state::{Notification, NotificationLevel};
use crate::theme::Theme;
use egui::{Color32, Response, RichText, Ui, Widget};

/// Notification toast widget
pub struct NotificationToast<'a> {
    notification: &'a Notification,
    theme: Theme,
}

impl<'a> NotificationToast<'a> {
    pub fn new(notification: &'a Notification, theme: Theme) -> Self {
        Self { notification, theme }
    }

    fn icon(&self) -> &'static str {
        match self.notification.level {
            NotificationLevel::Success => "\u{2713}", // Check mark
            NotificationLevel::Error => "\u{2717}",   // X mark
            NotificationLevel::Warning => "\u{26A0}", // Warning
            NotificationLevel::Info => "\u{2139}",    // Info
        }
    }

    fn color(&self) -> Color32 {
        match self.notification.level {
            NotificationLevel::Success => self.theme.success_color(),
            NotificationLevel::Error => self.theme.error_color(),
            NotificationLevel::Warning => self.theme.warning_color(),
            NotificationLevel::Info => self.theme.accent_color(),
        }
    }
}

impl<'a> Widget for NotificationToast<'a> {
    fn ui(self, ui: &mut Ui) -> Response {
        let age = self.notification.age_seconds();
        let alpha = if age < 0.2 {
            // Fade in
            (age / 0.2).min(1.0)
        } else if age > 4.0 {
            // Fade out
            (1.0 - ((age - 4.0) / 1.0)).max(0.0)
        } else {
            1.0
        };

        let alpha_u8 = (alpha * 255.0) as u8;

        let frame = egui::Frame::none()
            .fill(Color32::from_rgba_unmultiplied(
                self.theme.card_bg().r(),
                self.theme.card_bg().g(),
                self.theme.card_bg().b(),
                alpha_u8,
            ))
            .rounding(egui::Rounding::same(8.0))
            .inner_margin(egui::Margin::symmetric(16.0, 12.0))
            .stroke(egui::Stroke::new(
                1.0,
                Color32::from_rgba_unmultiplied(
                    self.color().r(),
                    self.color().g(),
                    self.color().b(),
                    alpha_u8,
                ),
            ));

        frame
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Icon
                    ui.label(
                        RichText::new(self.icon())
                            .size(16.0)
                            .color(Color32::from_rgba_unmultiplied(
                                self.color().r(),
                                self.color().g(),
                                self.color().b(),
                                alpha_u8,
                            )),
                    );

                    ui.add_space(8.0);

                    // Message
                    ui.label(
                        RichText::new(&self.notification.message)
                            .color(Color32::from_rgba_unmultiplied(
                                255,
                                255,
                                255,
                                alpha_u8,
                            )),
                    );
                });
            })
            .response
    }
}

/// Render notifications overlay
pub fn render_notifications(ui: &mut Ui, notifications: &[Notification], theme: Theme) {
    let screen_rect = ui.ctx().screen_rect();
    let margin = 16.0;

    // Position in top-right corner
    let mut y = margin;

    for notification in notifications.iter().filter(|n| !n.dismissed && n.age_seconds() < 5.0) {
        let area = egui::Area::new(egui::Id::new(notification.id))
            .fixed_pos(egui::pos2(screen_rect.max.x - 350.0, y))
            .order(egui::Order::Foreground);

        area.show(ui.ctx(), |ui| {
            ui.add(NotificationToast::new(notification, theme));
        });

        y += 60.0;
    }
}
