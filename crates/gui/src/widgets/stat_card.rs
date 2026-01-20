//! Statistics card widget

use crate::theme::Theme;
use egui::{Color32, Response, RichText, Ui, Widget};

/// Statistics card for displaying metrics
pub struct StatCard<'a> {
    title: &'a str,
    value: String,
    subtitle: Option<&'a str>,
    icon: Option<&'a str>,
    color: Option<Color32>,
}

impl<'a> StatCard<'a> {
    pub fn new(title: &'a str, value: impl ToString) -> Self {
        Self {
            title,
            value: value.to_string(),
            subtitle: None,
            icon: None,
            color: None,
        }
    }

    pub fn subtitle(mut self, subtitle: &'a str) -> Self {
        self.subtitle = Some(subtitle);
        self
    }

    pub fn icon(mut self, icon: &'a str) -> Self {
        self.icon = Some(icon);
        self
    }

    pub fn color(mut self, color: Color32) -> Self {
        self.color = Some(color);
        self
    }
}

impl<'a> Widget for StatCard<'a> {
    fn ui(self, ui: &mut Ui) -> Response {
        let frame = egui::Frame::none()
            .fill(ui.visuals().widgets.noninteractive.bg_fill)
            .rounding(ui.visuals().widgets.noninteractive.rounding)
            .inner_margin(egui::Margin::same(16.0));

        frame
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    // Header with icon and title
                    ui.horizontal(|ui| {
                        if let Some(icon) = self.icon {
                            ui.label(RichText::new(icon).size(16.0));
                        }
                        ui.label(
                            RichText::new(self.title)
                                .size(12.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                    });

                    ui.add_space(8.0);

                    // Value
                    let color = self.color.unwrap_or(ui.visuals().text_color());
                    ui.label(RichText::new(&self.value).size(28.0).color(color).strong());

                    // Subtitle
                    if let Some(subtitle) = self.subtitle {
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(subtitle)
                                .size(11.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                    }
                });
            })
            .response
    }
}
