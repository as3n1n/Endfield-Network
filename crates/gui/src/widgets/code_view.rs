//! Code viewer widget with syntax highlighting

use egui::{Color32, Response, RichText, Ui, Widget};

/// Simple syntax highlighting for C#-like code
pub struct CodeView<'a> {
    code: &'a str,
    language: Language,
    show_line_numbers: bool,
    highlight_line: Option<usize>,
}

/// Supported languages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    CSharp,
    Cpp,
    Json,
    Plain,
}

impl<'a> CodeView<'a> {
    pub fn new(code: &'a str) -> Self {
        Self {
            code,
            language: Language::CSharp,
            show_line_numbers: true,
            highlight_line: None,
        }
    }

    pub fn language(mut self, lang: Language) -> Self {
        self.language = lang;
        self
    }

    pub fn show_line_numbers(mut self, show: bool) -> Self {
        self.show_line_numbers = show;
        self
    }

    pub fn highlight_line(mut self, line: usize) -> Self {
        self.highlight_line = Some(line);
        self
    }
}

impl<'a> Widget for CodeView<'a> {
    fn ui(self, ui: &mut Ui) -> Response {
        let weak_color = ui.visuals().weak_text_color();

        egui::Frame::none()
            .fill(ui.visuals().extreme_bg_color)
            .rounding(ui.visuals().widgets.noninteractive.rounding)
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.style_mut().override_font_id = Some(egui::FontId::monospace(12.0));

                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (line_num, line) in self.code.lines().enumerate() {
                            let is_highlighted = self.highlight_line == Some(line_num + 1);

                            ui.horizontal(|ui| {
                                // Line number
                                if self.show_line_numbers {
                                    let line_color = if is_highlighted {
                                        ui.visuals().selection.stroke.color
                                    } else {
                                        weak_color
                                    };

                                    ui.label(
                                        RichText::new(format!("{:4}", line_num + 1))
                                            .color(line_color)
                                            .monospace(),
                                    );
                                    ui.add_space(16.0);
                                }

                                // Highlight background for selected line
                                if is_highlighted {
                                    let rect = ui.available_rect_before_wrap();
                                    ui.painter().rect_filled(
                                        rect,
                                        0.0,
                                        ui.visuals().selection.bg_fill,
                                    );
                                }

                                // Syntax highlighted code
                                self.render_line(ui, line);
                            });
                        }
                    });
            })
            .response
    }
}

impl<'a> CodeView<'a> {
    fn render_line(&self, ui: &mut Ui, line: &str) {
        match self.language {
            Language::CSharp | Language::Cpp => self.render_csharp_line(ui, line),
            Language::Json => self.render_json_line(ui, line),
            Language::Plain => {
                ui.label(RichText::new(line).monospace());
            }
        }
    }

    fn render_csharp_line(&self, ui: &mut Ui, line: &str) {
        let keywords = [
            "public", "private", "protected", "internal", "static", "virtual",
            "abstract", "sealed", "override", "class", "struct", "interface",
            "enum", "namespace", "using", "new", "void", "int", "string",
            "bool", "float", "double", "long", "short", "byte", "var", "const",
            "readonly", "if", "else", "for", "foreach", "while", "return",
            "true", "false", "null", "this", "base", "get", "set",
        ];

        let keyword_color = Color32::from_rgb(198, 120, 221); // Purple
        let string_color = Color32::from_rgb(152, 195, 121);  // Green
        let comment_color = Color32::from_rgb(92, 99, 112);   // Gray
        let number_color = Color32::from_rgb(209, 154, 102);  // Orange
        let type_color = Color32::from_rgb(97, 175, 239);     // Blue
        let text_color = ui.visuals().text_color();

        // Simple tokenization
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];

        // Render indent
        if !indent.is_empty() {
            ui.label(RichText::new(indent).monospace());
        }

        // Check for comments
        if trimmed.starts_with("//") {
            ui.label(RichText::new(trimmed).color(comment_color).monospace());
            return;
        }

        // Simple word-by-word rendering
        let mut chars = trimmed.chars().peekable();
        let mut current_word = String::new();
        let mut in_string = false;

        while let Some(ch) = chars.next() {
            if in_string {
                current_word.push(ch);
                if ch == '"' && !current_word.ends_with("\\\"") {
                    ui.label(RichText::new(&current_word).color(string_color).monospace());
                    current_word.clear();
                    in_string = false;
                }
            } else if ch == '"' {
                // Flush current word
                if !current_word.is_empty() {
                    self.render_word(ui, &current_word, &keywords, keyword_color, type_color, number_color, text_color);
                    current_word.clear();
                }
                current_word.push(ch);
                in_string = true;
            } else if ch.is_alphanumeric() || ch == '_' {
                current_word.push(ch);
            } else {
                // Flush current word
                if !current_word.is_empty() {
                    self.render_word(ui, &current_word, &keywords, keyword_color, type_color, number_color, text_color);
                    current_word.clear();
                }
                // Render punctuation
                ui.label(RichText::new(ch.to_string()).color(text_color).monospace());
            }
        }

        // Flush remaining
        if !current_word.is_empty() {
            let color = if in_string { string_color } else { text_color };
            self.render_word(ui, &current_word, &keywords, keyword_color, type_color, number_color, color);
        }
    }

    fn render_word(
        &self,
        ui: &mut Ui,
        word: &str,
        keywords: &[&str],
        keyword_color: Color32,
        type_color: Color32,
        number_color: Color32,
        default_color: Color32,
    ) {
        let color = if keywords.contains(&word) {
            keyword_color
        } else if word.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            type_color
        } else if word.chars().all(|c| c.is_numeric() || c == '.') {
            number_color
        } else {
            default_color
        };

        ui.label(RichText::new(word).color(color).monospace());
    }

    fn render_json_line(&self, ui: &mut Ui, line: &str) {
        let key_color = Color32::from_rgb(97, 175, 239);      // Blue
        let string_color = Color32::from_rgb(152, 195, 121);  // Green
        let number_color = Color32::from_rgb(209, 154, 102);  // Orange
        let bool_color = Color32::from_rgb(198, 120, 221);    // Purple
        let text_color = ui.visuals().text_color();

        // Simple JSON rendering
        let mut chars = line.chars().peekable();
        let mut current = String::new();
        let mut in_string = false;
        let mut is_key = true;

        while let Some(ch) = chars.next() {
            if in_string {
                current.push(ch);
                if ch == '"' {
                    let color = if is_key { key_color } else { string_color };
                    ui.label(RichText::new(&current).color(color).monospace());
                    current.clear();
                    in_string = false;
                }
            } else if ch == '"' {
                current.push(ch);
                in_string = true;
            } else if ch == ':' {
                is_key = false;
                ui.label(RichText::new(":").color(text_color).monospace());
            } else if ch == ',' {
                is_key = true;
                ui.label(RichText::new(",").color(text_color).monospace());
            } else if ch.is_alphanumeric() || ch == '.' || ch == '-' {
                current.push(ch);
            } else {
                if !current.is_empty() {
                    let color = if current == "true" || current == "false" || current == "null" {
                        bool_color
                    } else if current.chars().all(|c| c.is_numeric() || c == '.' || c == '-') {
                        number_color
                    } else {
                        text_color
                    };
                    ui.label(RichText::new(&current).color(color).monospace());
                    current.clear();
                }
                ui.label(RichText::new(ch.to_string()).color(text_color).monospace());
            }
        }

        if !current.is_empty() {
            ui.label(RichText::new(&current).color(text_color).monospace());
        }
    }
}
