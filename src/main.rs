#![windows_subsystem = "windows"]

mod app;
mod bam;
mod model;
mod scanner;
mod winutil;
mod yara_rules;

use app::App;
use eframe::egui;
use winutil::{EnsureOutcome, LogSink, ensure_elevated, load_app_icon, show_message};

fn main() {
    let log = LogSink::new();
    match ensure_elevated(&log) {
        Ok(EnsureOutcome::Spawned) => return,
        Ok(EnsureOutcome::Already) => {}
        Err(err) => {
            log.log_error(&format!("elevation error: {err}"));
            show_message("RSS-BamView", &format!("Admin rights required. {err}"));
            return;
        }
    }

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1320.0, 760.0])
        .with_min_inner_size([760.0, 460.0]);
    if let Some(icon) = load_app_icon(&log) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        centered: true,
        ..Default::default()
    };

    let result = eframe::run_native(
        "RSS-BamView",
        options,
        Box::new(|_cc| Ok(Box::new(App::new(log.clone())))),
    );

    if let Err(err) = result {
        let msg = format!("fatal error: {err}");
        log.log_error(&msg);
        show_message("RSS-BamView", &msg);
    }
}
