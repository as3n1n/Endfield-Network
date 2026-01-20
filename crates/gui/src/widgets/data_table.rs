//! Data table widget for displaying tabular data

use egui::{Response, RichText, Ui, Widget};

/// Column definition
pub struct Column {
    pub header: String,
    pub width: Option<f32>,
    pub resizable: bool,
}

impl Column {
    pub fn new(header: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            width: None,
            resizable: true,
        }
    }

    pub fn width(mut self, width: f32) -> Self {
        self.width = Some(width);
        self
    }

    pub fn fixed(mut self) -> Self {
        self.resizable = false;
        self
    }
}

/// Data table widget
pub struct DataTable<'a, T> {
    columns: Vec<Column>,
    data: &'a [T],
    row_height: f32,
    selected: Option<usize>,
    on_select: Option<Box<dyn FnMut(usize) + 'a>>,
    cell_renderer: Box<dyn Fn(&T, usize) -> String + 'a>,
}

impl<'a, T> DataTable<'a, T> {
    pub fn new<F>(columns: Vec<Column>, data: &'a [T], cell_renderer: F) -> Self
    where
        F: Fn(&T, usize) -> String + 'a,
    {
        Self {
            columns,
            data,
            row_height: 24.0,
            selected: None,
            on_select: None,
            cell_renderer: Box::new(cell_renderer),
        }
    }

    pub fn row_height(mut self, height: f32) -> Self {
        self.row_height = height;
        self
    }

    pub fn selected(mut self, index: Option<usize>) -> Self {
        self.selected = index;
        self
    }

    pub fn on_select<F>(mut self, callback: F) -> Self
    where
        F: FnMut(usize) + 'a,
    {
        self.on_select = Some(Box::new(callback));
        self
    }
}

impl<'a, T> Widget for DataTable<'a, T> {
    fn ui(mut self, ui: &mut Ui) -> Response {
        let available_width = ui.available_width();
        let num_columns = self.columns.len();

        // Calculate column widths
        let total_fixed_width: f32 = self
            .columns
            .iter()
            .filter_map(|c| c.width)
            .sum();
        let flexible_columns = self.columns.iter().filter(|c| c.width.is_none()).count();
        let flexible_width = if flexible_columns > 0 {
            (available_width - total_fixed_width) / flexible_columns as f32
        } else {
            0.0
        };

        let column_widths: Vec<f32> = self
            .columns
            .iter()
            .map(|c| c.width.unwrap_or(flexible_width))
            .collect();

        egui::Frame::none()
            .fill(ui.visuals().extreme_bg_color)
            .rounding(ui.visuals().widgets.noninteractive.rounding)
            .show(ui, |ui| {
                // Header row
                ui.horizontal(|ui| {
                    for (i, col) in self.columns.iter().enumerate() {
                        ui.allocate_ui_with_layout(
                            egui::vec2(column_widths[i], self.row_height),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.label(
                                    RichText::new(&col.header)
                                        .strong()
                                        .size(12.0),
                                );
                            },
                        );
                    }
                });

                ui.separator();

                // Data rows with scrolling
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (row_idx, item) in self.data.iter().enumerate() {
                            let is_selected = self.selected == Some(row_idx);

                            let response = ui.horizontal(|ui| {
                                let row_rect = ui.available_rect_before_wrap();
                                let row_rect = egui::Rect::from_min_size(
                                    row_rect.min,
                                    egui::vec2(available_width, self.row_height),
                                );

                                // Background for selected row
                                if is_selected {
                                    ui.painter().rect_filled(
                                        row_rect,
                                        0.0,
                                        ui.visuals().selection.bg_fill,
                                    );
                                }

                                // Hover effect
                                let response = ui.allocate_rect(row_rect, egui::Sense::click());
                                if response.hovered() && !is_selected {
                                    ui.painter().rect_filled(
                                        row_rect,
                                        0.0,
                                        ui.visuals().widgets.hovered.bg_fill,
                                    );
                                }

                                // Render cells
                                for col_idx in 0..num_columns {
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(column_widths[col_idx], self.row_height),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            let text = (self.cell_renderer)(item, col_idx);
                                            ui.label(
                                                RichText::new(text)
                                                    .size(12.0)
                                                    .monospace(),
                                            );
                                        },
                                    );
                                }

                                response
                            });

                            if response.inner.clicked() {
                                if let Some(ref mut on_select) = self.on_select {
                                    on_select(row_idx);
                                }
                            }
                        }
                    });
            })
            .response
    }
}
