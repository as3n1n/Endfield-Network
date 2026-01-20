//! Search bar widget

use egui::{Response, TextEdit, Ui, Widget};

/// Configurable search bar widget
pub struct SearchBar<'a> {
    text: &'a mut String,
    hint: &'a str,
    width: Option<f32>,
}

impl<'a> SearchBar<'a> {
    pub fn new(text: &'a mut String) -> Self {
        Self {
            text,
            hint: "Search...",
            width: None,
        }
    }

    pub fn hint(mut self, hint: &'a str) -> Self {
        self.hint = hint;
        self
    }

    pub fn width(mut self, width: f32) -> Self {
        self.width = Some(width);
        self
    }
}

impl<'a> Widget for SearchBar<'a> {
    fn ui(self, ui: &mut Ui) -> Response {
        let desired_width = self.width.unwrap_or(ui.available_width());

        ui.horizontal(|ui| {
            ui.set_min_width(desired_width);

            // Search icon
            ui.label("\u{1F50D}");

            // Text input
            let response = ui.add(
                TextEdit::singleline(self.text)
                    .hint_text(self.hint)
                    .desired_width(desired_width - 50.0),
            );

            // Clear button
            if !self.text.is_empty() {
                if ui.small_button("\u{2715}").clicked() {
                    self.text.clear();
                }
            }

            response
        })
        .response
    }
}
