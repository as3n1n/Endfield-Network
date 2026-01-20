//! Hex viewer widget for binary data

use egui::{Color32, Response, RichText, Ui, Widget};

/// Hex viewer widget
pub struct HexView<'a> {
    data: &'a [u8],
    bytes_per_row: usize,
    show_ascii: bool,
    show_offset: bool,
    highlight_ranges: Vec<(usize, usize, Color32)>,
    base_offset: u64,
}

impl<'a> HexView<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bytes_per_row: 16,
            show_ascii: true,
            show_offset: true,
            highlight_ranges: Vec::new(),
            base_offset: 0,
        }
    }

    pub fn bytes_per_row(mut self, count: usize) -> Self {
        self.bytes_per_row = count;
        self
    }

    pub fn show_ascii(mut self, show: bool) -> Self {
        self.show_ascii = show;
        self
    }

    pub fn show_offset(mut self, show: bool) -> Self {
        self.show_offset = show;
        self
    }

    pub fn base_offset(mut self, offset: u64) -> Self {
        self.base_offset = offset;
        self
    }

    pub fn highlight(mut self, start: usize, end: usize, color: Color32) -> Self {
        self.highlight_ranges.push((start, end, color));
        self
    }

    fn is_highlighted(&self, offset: usize) -> Option<Color32> {
        for &(start, end, color) in &self.highlight_ranges {
            if offset >= start && offset < end {
                return Some(color);
            }
        }
        None
    }
}

impl<'a> Widget for HexView<'a> {
    fn ui(self, ui: &mut Ui) -> Response {
        let text_color = ui.visuals().text_color();
        let weak_color = ui.visuals().weak_text_color();

        egui::Frame::none()
            .fill(ui.visuals().extreme_bg_color)
            .rounding(ui.visuals().widgets.noninteractive.rounding)
            .inner_margin(egui::Margin::same(8.0))
            .show(ui, |ui| {
                ui.style_mut().override_font_id = Some(egui::FontId::monospace(12.0));

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (row_idx, chunk) in self.data.chunks(self.bytes_per_row).enumerate() {
                            ui.horizontal(|ui| {
                                // Offset column
                                if self.show_offset {
                                    let offset = self.base_offset + (row_idx * self.bytes_per_row) as u64;
                                    ui.label(
                                        RichText::new(format!("{:08X}", offset))
                                            .color(weak_color)
                                            .monospace(),
                                    );
                                    ui.add_space(8.0);
                                }

                                // Hex bytes
                                for (byte_idx, &byte) in chunk.iter().enumerate() {
                                    let abs_offset = row_idx * self.bytes_per_row + byte_idx;
                                    let color = self
                                        .is_highlighted(abs_offset)
                                        .unwrap_or(text_color);

                                    ui.label(
                                        RichText::new(format!("{:02X}", byte))
                                            .color(color)
                                            .monospace(),
                                    );

                                    // Extra space after 8 bytes
                                    if byte_idx == 7 {
                                        ui.add_space(4.0);
                                    }
                                }

                                // Padding for incomplete rows
                                if chunk.len() < self.bytes_per_row {
                                    for i in chunk.len()..self.bytes_per_row {
                                        ui.label(RichText::new("  ").monospace());
                                        if i == 7 {
                                            ui.add_space(4.0);
                                        }
                                    }
                                }

                                // ASCII column
                                if self.show_ascii {
                                    ui.add_space(8.0);
                                    ui.label(RichText::new("|").color(weak_color).monospace());

                                    for (byte_idx, &byte) in chunk.iter().enumerate() {
                                        let abs_offset = row_idx * self.bytes_per_row + byte_idx;
                                        let color = self
                                            .is_highlighted(abs_offset)
                                            .unwrap_or(text_color);

                                        let ch = if byte.is_ascii_graphic() || byte == b' ' {
                                            byte as char
                                        } else {
                                            '.'
                                        };

                                        ui.label(
                                            RichText::new(ch.to_string())
                                                .color(color)
                                                .monospace(),
                                        );
                                    }

                                    // Padding for incomplete rows
                                    for _ in chunk.len()..self.bytes_per_row {
                                        ui.label(RichText::new(" ").monospace());
                                    }

                                    ui.label(RichText::new("|").color(weak_color).monospace());
                                }
                            });
                        }
                    });
            })
            .response
    }
}
