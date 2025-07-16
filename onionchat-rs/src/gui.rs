use eframe::{egui, App, CreationContext};
use egui::{Align, TextEdit};
use std::sync::mpsc::{Receiver, Sender};
use chrono::Local;
use std::fs::File;
use std::io::Write;

pub struct ChatApp {
    pub tx: Sender<String>,
    pub rx: Receiver<String>,
    input: String,
    messages: Vec<String>,
    status: String,
    scroll_to_end: bool,
}

impl ChatApp {
    pub fn new(_cc: &CreationContext<'_>, tx: Sender<String>, rx: Receiver<String>, status: String) -> Self {
        Self {
            tx,
            rx,
            input: String::new(),
            messages: Vec::new(),
            status,
            scroll_to_end: false,
        }
    }
}

impl App for ChatApp {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        while let Ok(msg) = self.rx.try_recv() {
            let ts = Local::now().format("%H:%M:%S");
            self.messages.push(format!("[{ts}] < {msg}", ts=ts, msg=msg));
            self.scroll_to_end = true;
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.image(egui::include_image!("../../Logo/onionchat_logo.png"));
                ui.label(egui::RichText::new("OnionChat").heading());
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.label(&self.status);
                });
            });
            ui.menu_button("File", |ui| {
                if ui.button("Save log").clicked() {
                    if let Ok(mut f) = File::create("chat.log") {
                        for m in &self.messages {
                            let _ = writeln!(f, "{}", m);
                        }
                    }
                    ui.close();
                }
                if ui.button("Clear chat").clicked() {
                    self.messages.clear();
                    ui.close();
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for msg in &self.messages {
                        ui.label(msg);
                    }
                    if self.scroll_to_end {
                        ui.scroll_to_cursor(Some(Align::BOTTOM));
                        self.scroll_to_end = false;
                    }
                });
        });

        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            let send = ui.horizontal(|ui| {
                let text = ui.add_sized(
                    [ui.available_width() - 60.0, 20.0],
                    TextEdit::singleline(&mut self.input).hint_text("Type a message"),
                );
                let enter_pressed = text.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let clicked = ui.button("Send").clicked();
                enter_pressed || clicked
            }).inner;
            if send {
                let msg = self.input.trim().to_owned();
                if !msg.is_empty() {
                    let _ = self.tx.send(msg.clone());
                    self.messages.push(format!("> {}", msg));
                    self.input.clear();
                    self.scroll_to_end = true;
                }
            }
        });
    }
}

