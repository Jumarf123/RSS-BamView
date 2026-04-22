use crate::bam::collect_bam_info;
use crate::model::{
    BamInfo, ExportRow, InfoState, Progress, ScanEntry, SignedStatus, SortBy, StatusKey,
    StatusMessage, WorkerEvent,
};
use crate::scanner::run_pipeline;
use crate::winutil::{LogSink, apply_theme, system_language_is_russian};
use anyhow::{Context, Result};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::cmp::Ordering;
use std::fs::File;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use time::OffsetDateTime;

const MIN_ZOOM: f32 = 0.75;
const MAX_ZOOM: f32 = 1.75;
const ZOOM_STEP: f32 = 1.1;
const GREEN: egui::Color32 = egui::Color32::from_rgb(72, 220, 125);
const RED: egui::Color32 = egui::Color32::from_rgb(255, 90, 90);
const PANEL: egui::Color32 = egui::Color32::from_rgb(13, 13, 16);
const PANEL_HIGHLIGHT: egui::Color32 = egui::Color32::from_rgb(22, 18, 22);
const PANEL_STROKE: egui::Color32 = egui::Color32::from_rgb(64, 48, 56);

enum Mode {
    Loading,
    Ready,
    Error,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Language {
    En,
    Ru,
}

#[derive(Clone, Copy)]
struct UiText {
    search: &'static str,
    search_hint: &'static str,
    not_signed_only: &'static str,
    yara_only: &'static str,
    deleted_only: &'static str,
    clear: &'static str,
    reload: &'static str,
    export_json: &'static str,
    export_csv: &'static str,
    rows: &'static str,
    total: &'static str,
    scanning: &'static str,
    errors: &'static str,
    processing_failed: &'static str,
    retry: &'static str,
    name: &'static str,
    path: &'static str,
    date: &'static str,
    deleted: &'static str,
    signed: &'static str,
    yara: &'static str,
    yes: &'static str,
    no: &'static str,
    empty: &'static str,
    info_title: &'static str,
    load_info: &'static str,
    collecting_info: &'static str,
    collected: &'static str,
    services: &'static str,
    service: &'static str,
    exists: &'static str,
    start: &'static str,
    enabled: &'static str,
    service_type: &'static str,
    image_path: &'static str,
    last_write: &'static str,
    roots: &'static str,
    sid_keys: &'static str,
    values: &'static str,
    evidence: &'static str,
    no_events: &'static str,
    collection_errors: &'static str,
    display_name: &'static str,
    key_path: &'static str,
    error_control: &'static str,
}

pub struct App {
    mode: Mode,
    entries: Vec<ScanEntry>,
    view: Vec<usize>,
    status: StatusMessage,
    progress: Option<Progress>,
    search: String,
    filter_not_signed: bool,
    filter_yara: bool,
    filter_deleted: bool,
    sort_by: SortBy,
    sort_asc: bool,
    rx: Option<mpsc::Receiver<WorkerEvent>>,
    log: LogSink,
    errors: Vec<String>,
    fatal_error: Option<String>,
    theme_applied: bool,
    language: Language,
    show_info: bool,
    info_state: InfoState,
    info_rx: Option<mpsc::Receiver<Result<BamInfo, String>>>,
}

impl App {
    pub fn new(log: LogSink) -> Self {
        let mut app = Self {
            mode: Mode::Loading,
            entries: Vec::new(),
            view: Vec::new(),
            status: StatusMessage::Key(StatusKey::Processing),
            progress: None,
            search: String::new(),
            filter_not_signed: false,
            filter_yara: false,
            filter_deleted: false,
            sort_by: SortBy::Name,
            sort_asc: true,
            rx: None,
            log,
            errors: Vec::new(),
            fatal_error: None,
            theme_applied: false,
            language: if system_language_is_russian() {
                Language::Ru
            } else {
                Language::En
            },
            show_info: false,
            info_state: InfoState::Empty,
            info_rx: None,
        };
        app.start_worker();
        app
    }

    fn start_worker(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.mode = Mode::Loading;
        self.status = StatusMessage::Key(StatusKey::Processing);
        self.progress = None;
        self.entries.clear();
        self.view.clear();
        self.errors.clear();
        self.fatal_error = None;

        let log = self.log.clone();
        thread::spawn(move || {
            if let Err(err) = run_pipeline(&tx, log.clone()) {
                log.log_error(&format!("worker failed: {err}"));
                let _ = tx.send(WorkerEvent::Failed(err.to_string()));
            }
        });
    }

    fn start_info_worker(&mut self) {
        if matches!(self.info_state, InfoState::Loading) {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.info_rx = Some(rx);
        self.info_state = InfoState::Loading;
        thread::spawn(move || {
            let info = collect_bam_info();
            let _ = tx.send(Ok(info));
        });
    }

    fn push_error(&mut self, message: String) {
        self.log.log_error(&message);
        self.errors.push(message);
    }

    fn handle_worker_events(&mut self) {
        let events = match self.rx.as_ref() {
            Some(rx) => rx.try_iter().collect::<Vec<_>>(),
            None => return,
        };
        let mut done = false;
        for event in events {
            match event {
                WorkerEvent::Status(key) => self.status = StatusMessage::Key(key),
                WorkerEvent::Progress { scanned, total } => {
                    self.progress = Some(Progress { scanned, total });
                }
                WorkerEvent::Finished { entries, errors } => {
                    self.entries = entries;
                    self.errors = errors;
                    self.refresh_view();
                    self.status = StatusMessage::Key(StatusKey::Ready);
                    self.progress = None;
                    self.mode = Mode::Ready;
                    done = true;
                }
                WorkerEvent::Failed(message) => {
                    self.fatal_error = Some(message.clone());
                    self.status = StatusMessage::Custom(message);
                    self.progress = None;
                    self.mode = Mode::Error;
                    done = true;
                }
            }
        }
        if done {
            self.rx = None;
        }
    }

    fn handle_info_events(&mut self) {
        let Some(rx) = self.info_rx.as_ref() else {
            return;
        };
        let Ok(result) = rx.try_recv() else {
            return;
        };
        self.info_state = match result {
            Ok(info) => InfoState::Ready(info),
            Err(err) => InfoState::Failed(err),
        };
        self.info_rx = None;
    }

    fn refresh_view(&mut self) {
        let search = self.search.to_lowercase();
        self.view.clear();
        for (idx, entry) in self.entries.iter().enumerate() {
            let deleted_search = deleted_label(entry.deleted, self.language).to_lowercase();
            let signed_search = signed_label(entry.signed, self.language).to_lowercase();
            if self.filter_not_signed && !entry.signed.is_not_signed() {
                continue;
            }
            if self.filter_yara && !entry.yara.has_match() {
                continue;
            }
            if self.filter_deleted && !entry.deleted {
                continue;
            }
            if !search.is_empty()
                && !entry.name_lower.contains(&search)
                && !entry.path_lower.contains(&search)
                && !entry.registry_path_lower.contains(&search)
                && !entry.date_lower.contains(&search)
                && !entry.yara_lower.contains(&search)
                && !entry.signed_lower.contains(&search)
                && !signed_search.contains(&search)
                && !entry.deleted_label().contains(&search)
                && !deleted_search.contains(&search)
                && !entry.sid.to_lowercase().contains(&search)
            {
                continue;
            }
            self.view.push(idx);
        }

        let sort_by = self.sort_by;
        let sort_asc = self.sort_asc;
        self.view.sort_by(|a, b| {
            let left = &self.entries[*a];
            let right = &self.entries[*b];
            let mut cmp = match sort_by {
                SortBy::Name => left.name_lower.cmp(&right.name_lower),
                SortBy::Path => left.path_lower.cmp(&right.path_lower),
                SortBy::Date => compare_datetime(left.last_run_dt, right.last_run_dt).reverse(),
                SortBy::Deleted => left.deleted.cmp(&right.deleted),
                SortBy::Signed => left.signed_lower.cmp(&right.signed_lower),
                SortBy::Yara => left.yara_lower.cmp(&right.yara_lower),
            };
            if !sort_asc {
                cmp = cmp.reverse();
            }
            if cmp == Ordering::Equal {
                compare_datetime(left.last_run_dt, right.last_run_dt)
                    .reverse()
                    .then(left.index.cmp(&right.index))
            } else {
                cmp
            }
        });
    }

    fn export_csv(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .set_file_name("RSS-BamView.csv")
            .save_file()
        else {
            return;
        };
        match export_csv(&path, self.export_rows()) {
            Ok(()) => self.status = StatusMessage::ExportedCsv(path),
            Err(err) => self.push_error(format!("CSV export failed: {err}")),
        }
    }

    fn export_json(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name("RSS-BamView.json")
            .save_file()
        else {
            return;
        };
        match export_json(&path, self.export_rows()) {
            Ok(()) => self.status = StatusMessage::ExportedJson(path),
            Err(err) => self.push_error(format!("JSON export failed: {err}")),
        }
    }

    fn export_rows(&self) -> Vec<ExportRow> {
        let mut rows = Vec::with_capacity(self.view.len());
        for &idx in &self.view {
            let entry = &self.entries[idx];
            rows.push(ExportRow {
                name: entry.name.clone(),
                path: entry.path.clone(),
                registry_path: entry.registry_path.clone(),
                resolved_path: entry.resolved_path.clone(),
                deleted: entry.deleted_label().to_string(),
                signed: entry.signed.display().to_string(),
                yara: entry.yara_display.clone(),
                date: entry.date.clone(),
                last_run: entry.last_run.clone(),
                sid: entry.sid.clone(),
                source: entry.source.clone(),
            });
        }
        rows
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            apply_theme(ctx);
            self.theme_applied = true;
        }
        handle_zoom(ctx);
        self.handle_worker_events();
        self.handle_info_events();

        match self.mode {
            Mode::Loading => self.loading_ui(ctx),
            Mode::Error => self.error_ui(ctx),
            Mode::Ready => self.ready_ui(ctx),
        }

        if self.show_info {
            let strings = ui_text(self.language);
            let mut open = true;
            egui::Window::new(strings.info_title)
                .open(&mut open)
                .resizable(true)
                .default_size([1080.0, 720.0])
                .min_size([760.0, 500.0])
                .show(ctx, |ui| self.info_ui(ui));
            self.show_info = open;
        }
    }
}

impl App {
    fn loading_ui(&mut self, ctx: &egui::Context) {
        let status = status_text_lang(&self.status, self.language);
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(44.0);
                ui.heading("RSS-BamView");
                ui.add_space(6.0);
                if !status.is_empty() {
                    ui.label(&status);
                }
                ui.add_space(14.0);
                if let Some(progress) = &self.progress {
                    let fraction = if progress.total == 0 {
                        0.0
                    } else {
                        progress.scanned as f32 / progress.total as f32
                    };
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .show_percentage()
                            .desired_width(ui.available_width().min(520.0)),
                    );
                    ui.label(format!("{}/{}", progress.scanned, progress.total));
                } else {
                    ui.spinner();
                }
            });
        });
        ctx.request_repaint_after(Duration::from_millis(200));
    }

    fn error_ui(&mut self, ctx: &egui::Context) {
        let strings = ui_text(self.language);
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(44.0);
                ui.heading(strings.processing_failed);
                if let Some(message) = &self.fatal_error {
                    ui.label(message);
                }
                ui.add_space(12.0);
                if ui.button(strings.retry).clicked() {
                    self.start_worker();
                }
            });
        });
    }

    fn ready_ui(&mut self, ctx: &egui::Context) {
        let strings = ui_text(self.language);
        let status = status_text_lang(&self.status, self.language);
        let mut changed = false;
        egui::TopBottomPanel::top("topbar").show(ctx, |ui| {
            egui::Frame::NONE
                .fill(PANEL)
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(36, 36, 42)))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("RSS-BamView");
                        ui.add_space(10.0);
                        if !status.is_empty() {
                            ui.label(&status);
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button(strings.reload).clicked() {
                                self.start_worker();
                            }
                            if ui.button(strings.export_json).clicked() {
                                self.export_json();
                            }
                            if ui.button(strings.export_csv).clicked() {
                                self.export_csv();
                            }
                            if ui.button("INFO").clicked() {
                                self.show_info = true;
                                if matches!(
                                    self.info_state,
                                    InfoState::Empty | InfoState::Failed(_)
                                ) {
                                    self.start_info_worker();
                                }
                            }
                            language_switch(ui, &mut self.language);
                        });
                    });
                });
        });

        egui::TopBottomPanel::top("filters").show(ctx, |ui| {
            egui::Frame::NONE
                .fill(egui::Color32::from_rgb(7, 7, 8))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        egui::Frame::NONE
                            .fill(PANEL_HIGHLIGHT)
                            .stroke(egui::Stroke::new(1.0, PANEL_STROKE))
                            .corner_radius(egui::CornerRadius::same(5))
                            .inner_margin(egui::Margin::symmetric(10, 7))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.strong(strings.search);
                                    let search = egui::TextEdit::singleline(&mut self.search)
                                        .hint_text(strings.search_hint)
                                        .desired_width(
                                            (ui.available_width() * 0.45).clamp(220.0, 520.0),
                                        );
                                    if ui.add(search).changed() {
                                        changed = true;
                                    }
                                });
                            });
                        egui::Frame::NONE
                            .fill(egui::Color32::from_rgb(16, 18, 22))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(44, 50, 58)))
                            .corner_radius(egui::CornerRadius::same(5))
                            .inner_margin(egui::Margin::symmetric(10, 7))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    changed |= filter_button(
                                        ui,
                                        &mut self.filter_not_signed,
                                        strings.not_signed_only,
                                    );
                                    changed |=
                                        filter_button(ui, &mut self.filter_yara, strings.yara_only);
                                    changed |= filter_button(
                                        ui,
                                        &mut self.filter_deleted,
                                        strings.deleted_only,
                                    );
                                    if ui.button(strings.clear).clicked() {
                                        self.search.clear();
                                        self.filter_not_signed = false;
                                        self.filter_yara = false;
                                        self.filter_deleted = false;
                                        changed = true;
                                    }
                                });
                            });
                    });
                });
            if changed {
                self.refresh_view();
            }
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if !status.is_empty() {
                    ui.label(&status);
                    ui.separator();
                }
                ui.label(format!("{}: {}", strings.rows, self.view.len()));
                ui.label(format!("{}: {}", strings.total, self.entries.len()));
                if let Some(progress) = &self.progress {
                    ui.separator();
                    ui.label(format!(
                        "{}: {}/{}",
                        strings.scanning, progress.scanned, progress.total
                    ));
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| self.table_ui(ui));
    }

    fn table_ui(&mut self, ui: &mut egui::Ui) {
        let strings = ui_text(self.language);
        if !self.errors.is_empty() {
            ui.collapsing(
                format!("{} ({})", strings.errors, self.errors.len()),
                |ui| {
                    for err in &self.errors {
                        ui.label(err);
                    }
                },
            );
            ui.add_space(6.0);
        }

        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = text_height + 7.0;
        let mut sort_changed = false;
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .vscroll(true)
            .min_scrolled_height(280.0)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(
                Column::initial(210.0)
                    .resizable(true)
                    .at_least(120.0)
                    .clip(true),
            )
            .column(
                Column::remainder()
                    .resizable(true)
                    .at_least(260.0)
                    .clip(true),
            )
            .column(
                Column::initial(104.0)
                    .resizable(true)
                    .at_least(86.0)
                    .clip(true),
            )
            .column(
                Column::initial(88.0)
                    .resizable(true)
                    .at_least(72.0)
                    .clip(true),
            )
            .column(
                Column::initial(88.0)
                    .resizable(true)
                    .at_least(72.0)
                    .clip(true),
            )
            .column(
                Column::initial(220.0)
                    .resizable(true)
                    .at_least(120.0)
                    .clip(true),
            )
            .header(row_height, |mut header| {
                header.col(|ui| {
                    sort_changed |= header_sort_label(
                        ui,
                        strings.name,
                        SortBy::Name,
                        &mut self.sort_by,
                        &mut self.sort_asc,
                    );
                });
                header.col(|ui| {
                    sort_changed |= header_sort_label(
                        ui,
                        strings.path,
                        SortBy::Path,
                        &mut self.sort_by,
                        &mut self.sort_asc,
                    );
                });
                header.col(|ui| {
                    sort_changed |= header_sort_label(
                        ui,
                        strings.date,
                        SortBy::Date,
                        &mut self.sort_by,
                        &mut self.sort_asc,
                    );
                });
                header.col(|ui| {
                    sort_changed |= header_sort_label(
                        ui,
                        strings.deleted,
                        SortBy::Deleted,
                        &mut self.sort_by,
                        &mut self.sort_asc,
                    );
                });
                header.col(|ui| {
                    sort_changed |= header_sort_label(
                        ui,
                        strings.signed,
                        SortBy::Signed,
                        &mut self.sort_by,
                        &mut self.sort_asc,
                    );
                });
                header.col(|ui| {
                    sort_changed |= header_sort_label(
                        ui,
                        strings.yara,
                        SortBy::Yara,
                        &mut self.sort_by,
                        &mut self.sort_asc,
                    );
                });
            })
            .body(|body| {
                body.rows(row_height, self.view.len(), |mut row| {
                    let idx = self.view[row.index()];
                    let entry = &self.entries[idx];
                    row.col(|ui| {
                        add_trunc_label(ui, &entry.name, entry_hover(entry, self.language))
                    });
                    row.col(|ui| {
                        add_trunc_label(ui, &entry.path, entry_hover(entry, self.language))
                    });
                    row.col(|ui| {
                        add_trunc_label(ui, &entry.date, entry_hover(entry, self.language))
                    });
                    row.col(|ui| {
                        yes_no_label(
                            ui,
                            deleted_label(entry.deleted, self.language),
                            entry.deleted,
                        )
                        .on_hover_text(entry_hover(entry, self.language));
                    });
                    row.col(|ui| {
                        signed_status_label(ui, entry.signed, self.language)
                            .on_hover_text(entry_hover(entry, self.language));
                    });
                    row.col(|ui| {
                        if entry.yara.has_match() {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&entry.yara_display).color(RED).strong(),
                                )
                                .truncate(),
                            )
                            .on_hover_text(entry_hover(entry, self.language));
                        } else {
                            add_trunc_label(
                                ui,
                                &entry.yara_display,
                                entry_hover(entry, self.language),
                            );
                        }
                    });
                });
            });

        if sort_changed {
            self.refresh_view();
        }
    }

    fn info_ui(&mut self, ui: &mut egui::Ui) {
        let strings = ui_text(self.language);
        match &self.info_state {
            InfoState::Empty => {
                if ui.button(strings.load_info).clicked() {
                    self.start_info_worker();
                }
            }
            InfoState::Loading => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(strings.collecting_info);
                });
            }
            InfoState::Failed(err) => {
                ui.label(err);
                if ui.button(strings.retry).clicked() {
                    self.start_info_worker();
                }
            }
            InfoState::Ready(info) => {
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_min_width(1040.0);
                        egui::Frame::NONE
                            .fill(egui::Color32::from_rgb(18, 18, 22))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 52, 62)))
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(12, 10))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.heading(strings.info_title);
                                    ui.separator();
                                    ui.label(format!(
                                        "{}: {}",
                                        strings.collected, info.collected_at
                                    ));
                                });
                            });

                        ui.add_space(10.0);
                        section_header(ui, strings.services);
                        service_info_table(ui, info, strings, self.language);

                        ui.add_space(14.0);
                        section_header(ui, strings.roots);
                        root_info_table(ui, info, strings, self.language);

                        ui.add_space(14.0);
                        section_header(ui, strings.evidence);
                        if info.events.is_empty() {
                            info_note_frame(
                                ui,
                                strings.no_events,
                                egui::Color32::from_rgb(42, 34, 18),
                            );
                        } else {
                            for event in &info.events {
                                egui::Frame::NONE
                                    .fill(egui::Color32::from_rgb(14, 15, 18))
                                    .stroke(egui::Stroke::new(
                                        1.0,
                                        egui::Color32::from_rgb(52, 58, 68),
                                    ))
                                    .corner_radius(egui::CornerRadius::same(6))
                                    .inner_margin(egui::Margin::symmetric(10, 8))
                                    .show(ui, |ui| {
                                        ui.horizontal_wrapped(|ui| {
                                            ui.strong(
                                                egui::RichText::new(format!(
                                                    "{} / {}",
                                                    event.log, event.id
                                                ))
                                                .color(egui::Color32::from_rgb(120, 180, 255)),
                                            );
                                            ui.label(&event.time);
                                            ui.label(&event.provider);
                                            if !event.category.is_empty() {
                                                ui.label(
                                                    egui::RichText::new(event_category_text(
                                                        &event.category,
                                                        self.language,
                                                    ))
                                                    .color(egui::Color32::from_rgb(235, 196, 92))
                                                    .strong(),
                                                );
                                            }
                                        });
                                        if !event.signal.is_empty() {
                                            ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(event_signal_text(
                                                        &event.signal,
                                                        self.language,
                                                    ))
                                                    .color(egui::Color32::from_rgb(180, 220, 255))
                                                    .strong(),
                                                )
                                                .wrap(),
                                            );
                                        }
                                        ui.add_space(6.0);
                                        let (preview, is_truncated) =
                                            event_message_preview(&event.message);
                                        egui::Frame::NONE
                                            .fill(egui::Color32::from_rgb(9, 10, 12))
                                            .stroke(egui::Stroke::new(
                                                1.0,
                                                egui::Color32::from_rgb(36, 40, 48),
                                            ))
                                            .corner_radius(egui::CornerRadius::same(4))
                                            .inner_margin(egui::Margin::symmetric(8, 7))
                                            .show(ui, |ui| {
                                                ui.add_sized(
                                                    [ui.available_width(), 0.0],
                                                    egui::Label::new(
                                                        egui::RichText::new(preview).monospace(),
                                                    )
                                                    .wrap(),
                                                );
                                            });
                                        if is_truncated {
                                            egui::CollapsingHeader::new(event_details_text(
                                                self.language,
                                            ))
                                            .default_open(false)
                                            .show(
                                                ui,
                                                |ui| {
                                                    egui::ScrollArea::vertical()
                                                        .max_height(220.0)
                                                        .auto_shrink([false, false])
                                                        .show(ui, |ui| {
                                                            ui.add_sized(
                                                                [ui.available_width(), 0.0],
                                                                egui::Label::new(
                                                                    egui::RichText::new(
                                                                        event_full_message(
                                                                            &event.message,
                                                                        ),
                                                                    )
                                                                    .monospace(),
                                                                )
                                                                .wrap(),
                                                            );
                                                        });
                                                },
                                            );
                                        }
                                    });
                                ui.add_space(6.0);
                            }
                        }

                        if !info.errors.is_empty() {
                            ui.add_space(14.0);
                            section_header(ui, strings.collection_errors);
                            for err in &info.errors {
                                info_note_frame(ui, err, egui::Color32::from_rgb(38, 18, 20));
                            }
                        }
                    });
            }
        }
    }
}

fn section_header(ui: &mut egui::Ui, title: &str) {
    egui::Frame::NONE
        .fill(egui::Color32::from_rgb(20, 21, 25))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(44, 50, 60)))
        .corner_radius(egui::CornerRadius::same(5))
        .inner_margin(egui::Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.heading(title);
        });
    ui.add_space(6.0);
}

fn service_info_table(ui: &mut egui::Ui, info: &BamInfo, strings: UiText, language: Language) {
    let row_height = ui.text_style_height(&egui::TextStyle::Body) + 9.0;
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(90.0).resizable(true).at_least(70.0))
        .column(Column::initial(84.0).resizable(true).at_least(70.0))
        .column(Column::initial(155.0).resizable(true).at_least(120.0))
        .column(Column::initial(100.0).resizable(true).at_least(80.0))
        .column(Column::initial(180.0).resizable(true).at_least(120.0))
        .column(Column::remainder().resizable(true).at_least(300.0))
        .header(row_height, |mut header| {
            header.col(|ui| {
                ui.strong(strings.service);
            });
            header.col(|ui| {
                ui.strong(strings.exists);
            });
            header.col(|ui| {
                ui.strong(strings.start);
            });
            header.col(|ui| {
                ui.strong(strings.enabled);
            });
            header.col(|ui| {
                ui.strong(strings.service_type);
            });
            header.col(|ui| {
                ui.strong(strings.image_path);
            });
        })
        .body(|body| {
            body.rows(row_height, info.services.len(), |mut row| {
                let svc = &info.services[row.index()];
                let hover = format!(
                    "{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}",
                    strings.display_name,
                    svc.display_name,
                    strings.key_path,
                    svc.key_path,
                    strings.image_path,
                    svc.image_path,
                    strings.error_control,
                    localize_known(&svc.error_control, language),
                    strings.last_write,
                    svc.key_last_write
                );
                row.col(|ui| {
                    ui.add(egui::Label::new(&svc.name).truncate())
                        .on_hover_text(&hover);
                });
                row.col(|ui| {
                    yes_no_label(
                        ui,
                        if svc.exists { strings.yes } else { strings.no },
                        svc.exists,
                    )
                    .on_hover_text(&hover);
                });
                row.col(|ui| {
                    let mut start = localize_known(&svc.start_label, language);
                    if let Some(raw) = svc.start_raw {
                        start.push_str(&format!(" ({raw})"));
                    }
                    ui.add(egui::Label::new(start).truncate())
                        .on_hover_text(&hover);
                });
                row.col(|ui| match svc.enabled {
                    Some(value) => {
                        yes_no_label(ui, if value { strings.yes } else { strings.no }, value)
                            .on_hover_text(&hover);
                    }
                    None => {
                        ui.label("").on_hover_text(&hover);
                    }
                });
                row.col(|ui| {
                    ui.add(
                        egui::Label::new(localize_known(&svc.service_type, language)).truncate(),
                    )
                    .on_hover_text(&hover);
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(&svc.image_path).truncate())
                        .on_hover_text(hover);
                });
            });
        });
}

fn root_info_table(ui: &mut egui::Ui, info: &BamInfo, strings: UiText, _language: Language) {
    let row_height = ui.text_style_height(&egui::TextStyle::Body) + 9.0;
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::remainder().resizable(true).at_least(420.0))
        .column(Column::initial(90.0).resizable(true).at_least(70.0))
        .column(Column::initial(110.0).resizable(true).at_least(85.0))
        .column(Column::initial(110.0).resizable(true).at_least(85.0))
        .header(row_height, |mut header| {
            header.col(|ui| {
                ui.strong(strings.path);
            });
            header.col(|ui| {
                ui.strong(strings.exists);
            });
            header.col(|ui| {
                ui.strong(strings.sid_keys);
            });
            header.col(|ui| {
                ui.strong(strings.values);
            });
        })
        .body(|body| {
            body.rows(row_height, info.roots.len(), |mut row| {
                let root = &info.roots[row.index()];
                row.col(|ui| {
                    ui.add(egui::Label::new(&root.path).truncate())
                        .on_hover_text(&root.path);
                });
                row.col(|ui| {
                    yes_no_label(
                        ui,
                        if root.exists { strings.yes } else { strings.no },
                        root.exists,
                    )
                    .on_hover_text(&root.path);
                });
                row.col(|ui| {
                    ui.label(root.sid_count.to_string());
                });
                row.col(|ui| {
                    ui.label(root.value_count.to_string());
                });
            });
        });
}

fn info_note_frame(ui: &mut egui::Ui, text: &str, fill: egui::Color32) {
    egui::Frame::NONE
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 54, 62)))
        .corner_radius(egui::CornerRadius::same(5))
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.add_sized([ui.available_width(), 0.0], egui::Label::new(text).wrap());
        });
    ui.add_space(5.0);
}

fn language_switch(ui: &mut egui::Ui, language: &mut Language) {
    ui.horizontal(|ui| {
        if ui
            .selectable_label(*language == Language::Ru, "RU")
            .clicked()
        {
            *language = Language::Ru;
        }
        if ui
            .selectable_label(*language == Language::En, "EN")
            .clicked()
        {
            *language = Language::En;
        }
    });
}

fn yes_no_label(ui: &mut egui::Ui, text: &str, yes: bool) -> egui::Response {
    ui.add(
        egui::Label::new(
            egui::RichText::new(text)
                .color(if yes { GREEN } else { RED })
                .strong(),
        )
        .truncate(),
    )
}

fn signed_status_label(
    ui: &mut egui::Ui,
    status: SignedStatus,
    language: Language,
) -> egui::Response {
    match status {
        SignedStatus::Signed => yes_no_label(ui, signed_label(status, language), true),
        SignedStatus::NotSigned => yes_no_label(ui, signed_label(status, language), false),
        SignedStatus::Skipped => ui.add(egui::Label::new("").truncate()),
    }
}

fn localize_known(value: &str, language: Language) -> String {
    if language == Language::En {
        return value.to_string();
    }
    match value {
        "Boot" => "Boot".to_string(),
        "System" => "System".to_string(),
        "Automatic" => "Автоматически".to_string(),
        "Manual" => "Вручную".to_string(),
        "Disabled" => "Отключена".to_string(),
        "Kernel driver" => "Драйвер ядра".to_string(),
        "File system driver" => "Драйвер файловой системы".to_string(),
        "Own process" => "Собственный процесс".to_string(),
        "Shared process" => "Общий процесс".to_string(),
        "Ignore" => "Игнорировать".to_string(),
        "Normal" => "Обычный".to_string(),
        "Severe" => "Серьёзный".to_string(),
        "Critical" => "Критический".to_string(),
        "Unknown" => "Неизвестно".to_string(),
        "missing" => "нет данных".to_string(),
        _ => value.to_string(),
    }
}

fn event_category_text(value: &str, language: Language) -> String {
    match (value, language) {
        ("service_control", Language::En) => "Service Control Manager".to_string(),
        ("service_control", Language::Ru) => "Service Control Manager".to_string(),
        ("registry_audit", Language::En) => "Security registry audit".to_string(),
        ("registry_audit", Language::Ru) => "Аудит реестра Security".to_string(),
        ("process_command", Language::En) => "Process command".to_string(),
        ("process_command", Language::Ru) => "Команда процесса".to_string(),
        ("sysmon_registry", Language::En) => "Sysmon registry/process".to_string(),
        ("sysmon_registry", Language::Ru) => "Sysmon реестр/процесс".to_string(),
        ("powershell_script", Language::En) => "PowerShell script".to_string(),
        ("powershell_script", Language::Ru) => "PowerShell script".to_string(),
        ("log_integrity", Language::En) => "Log integrity".to_string(),
        ("log_integrity", Language::Ru) => "Целостность журналов".to_string(),
        _ => value.to_string(),
    }
}

fn event_signal_text(value: &str, language: Language) -> String {
    match (value, language) {
        ("strong_service_start_type_changed", Language::En) => {
            "Strong: BAM/DAM service start type was changed".to_string()
        }
        ("strong_service_start_type_changed", Language::Ru) => {
            "Сильный след: изменён тип запуска службы BAM/DAM".to_string()
        }
        ("medium_service_control_state", Language::En) => {
            "Medium: service control/state event for BAM/DAM".to_string()
        }
        ("medium_service_control_state", Language::Ru) => {
            "Средний след: команда или состояние службы BAM/DAM".to_string()
        }
        ("medium_service_start_failure", Language::En) => {
            "Medium: BAM/DAM driver/service startup failure".to_string()
        }
        ("medium_service_start_failure", Language::Ru) => {
            "Средний след: ошибка запуска драйвера/службы BAM/DAM".to_string()
        }
        ("strong_security_registry_start", Language::En) => {
            "Strong: Security audit shows Services\\bam/dam Start value change".to_string()
        }
        ("strong_security_registry_start", Language::Ru) => {
            "Сильный след: Security audit показывает изменение Services\\bam/dam Start".to_string()
        }
        ("medium_security_registry_services", Language::En) => {
            "Medium: Security audit shows BAM/DAM service registry access/change".to_string()
        }
        ("medium_security_registry_services", Language::Ru) => {
            "Средний след: Security audit показывает доступ/изменение ключей BAM/DAM".to_string()
        }
        ("medium_process_command", Language::En) => {
            "Medium: process command references BAM/DAM service or registry control".to_string()
        }
        ("medium_process_command", Language::Ru) => {
            "Средний след: команда процесса связана с управлением BAM/DAM".to_string()
        }
        ("strong_sysmon_registry_start", Language::En) => {
            "Strong: Sysmon shows Services\\bam/dam Start value set".to_string()
        }
        ("strong_sysmon_registry_start", Language::Ru) => {
            "Сильный след: Sysmon показывает запись Services\\bam/dam Start".to_string()
        }
        ("medium_sysmon_registry_services", Language::En) => {
            "Medium: Sysmon shows BAM/DAM registry create/set/rename activity".to_string()
        }
        ("medium_sysmon_registry_services", Language::Ru) => {
            "Средний след: Sysmon показывает создание/изменение/rename ключей BAM/DAM".to_string()
        }
        ("medium_powershell_command", Language::En) => {
            "Medium: PowerShell logging references BAM/DAM control".to_string()
        }
        ("medium_powershell_command", Language::Ru) => {
            "Средний след: PowerShell logging содержит управление BAM/DAM".to_string()
        }
        ("context_log_cleared", Language::En) => {
            "Context: event log was cleared; absence of older BAM/DAM events is weaker".to_string()
        }
        ("context_log_cleared", Language::Ru) => {
            "Контекст: журнал очищался; отсутствие старых BAM/DAM событий менее доказательно"
                .to_string()
        }
        ("context_eventlog_service", Language::En) => {
            "Context: Windows Event Log service interruption".to_string()
        }
        ("context_eventlog_service", Language::Ru) => {
            "Контекст: остановка/сбой службы Windows Event Log".to_string()
        }
        ("context_service_installed", Language::En) => {
            "Context: service installation/change event mentions BAM/DAM".to_string()
        }
        ("context_service_installed", Language::Ru) => {
            "Контекст: событие установки/изменения службы связано с BAM/DAM".to_string()
        }
        ("context_other", Language::En) => "Context evidence".to_string(),
        ("context_other", Language::Ru) => "Контекстный след".to_string(),
        _ => value.to_string(),
    }
}

fn event_details_text(language: Language) -> &'static str {
    match language {
        Language::En => "Full event details",
        Language::Ru => "Полные детали события",
    }
}

fn event_message_preview(message: &str) -> (String, bool) {
    const MAX_CHARS: usize = 520;
    let normalized = event_full_message(message);
    if normalized.chars().count() <= MAX_CHARS {
        return (normalized, false);
    }

    let mut preview = normalized.chars().take(MAX_CHARS).collect::<String>();
    preview.push_str("\n...");
    (preview, true)
}

fn event_full_message(message: &str) -> String {
    message.replace(" | ", "\n")
}

fn filter_button(ui: &mut egui::Ui, value: &mut bool, text: &str) -> bool {
    let response = ui.selectable_label(*value, text);
    if response.clicked() {
        *value = !*value;
        true
    } else {
        false
    }
}

fn ui_text(language: Language) -> UiText {
    match language {
        Language::En => UiText {
            search: "Search",
            search_hint: "file name, path, YARA, SID",
            not_signed_only: "Not Signed only",
            yara_only: "YARA only",
            deleted_only: "Deleted only",
            clear: "Clear",
            reload: "Reload",
            export_json: "Export JSON",
            export_csv: "Export CSV",
            rows: "Rows",
            total: "Total",
            scanning: "Scanning",
            errors: "Errors",
            processing_failed: "Processing failed",
            retry: "Retry",
            name: "Name",
            path: "Path",
            date: "Date",
            deleted: "Deleted",
            signed: "Signed",
            yara: "YARA",
            yes: "Yes",
            no: "No",
            empty: "",
            info_title: "BAM info",
            load_info: "Load BAM info",
            collecting_info: "Collecting BAM service and event-log evidence...",
            collected: "Collected",
            services: "Services",
            service: "Service",
            exists: "Exists",
            start: "Start",
            enabled: "Enabled",
            service_type: "Type",
            image_path: "ImagePath",
            last_write: "Key last write",
            roots: "BAM/DAM registry roots",
            sid_keys: "SID keys",
            values: "Values",
            evidence: "Disable/enable evidence",
            no_events: "No matching BAM/DAM service or registry-change events were found in available logs.",
            collection_errors: "Collection errors",
            display_name: "Display name",
            key_path: "Registry key",
            error_control: "ErrorControl",
        },
        Language::Ru => UiText {
            search: "Поиск",
            search_hint: "имя файла, путь, YARA, SID",
            not_signed_only: "Только без подписи",
            yara_only: "Только YARA",
            deleted_only: "Только удалённые",
            clear: "Сброс",
            reload: "Обновить",
            export_json: "Экспорт JSON",
            export_csv: "Экспорт CSV",
            rows: "Строки",
            total: "Всего",
            scanning: "Сканирование",
            errors: "Ошибки",
            processing_failed: "Ошибка обработки",
            retry: "Повторить",
            name: "Имя",
            path: "Путь",
            date: "Дата",
            deleted: "Удалён",
            signed: "Подпись",
            yara: "YARA",
            yes: "Да",
            no: "Нет",
            empty: "",
            info_title: "BAM info",
            load_info: "Загрузить BAM info",
            collecting_info: "Сбор состояния служб BAM/DAM и событий журналов...",
            collected: "Собрано",
            services: "Службы",
            service: "Служба",
            exists: "Есть",
            start: "Запуск",
            enabled: "Включена",
            service_type: "Тип",
            image_path: "ImagePath",
            last_write: "Последняя запись ключа",
            roots: "Корни реестра BAM/DAM",
            sid_keys: "SID-ключи",
            values: "Значения",
            evidence: "Следы выключения/включения",
            no_events: "В доступных журналах не найдены события BAM/DAM или изменения связанных ключей реестра.",
            collection_errors: "Ошибки сбора",
            display_name: "Отображаемое имя",
            key_path: "Ключ реестра",
            error_control: "ErrorControl",
        },
    }
}

fn status_text_lang(status: &StatusMessage, language: Language) -> String {
    match status {
        StatusMessage::Key(key) => match (key, language) {
            (StatusKey::Processing, Language::En) => "Processing".to_string(),
            (StatusKey::Processing, Language::Ru) => "Обработка".to_string(),
            (StatusKey::LoadingRegistry, Language::En) => "Loading BAM registry".to_string(),
            (StatusKey::LoadingRegistry, Language::Ru) => "Загрузка BAM из реестра".to_string(),
            (StatusKey::CompilingYara, Language::En) => "Compiling YARA rules".to_string(),
            (StatusKey::CompilingYara, Language::Ru) => "Компиляция YARA-правил".to_string(),
            (StatusKey::Scanning, Language::En) => "Scanning files".to_string(),
            (StatusKey::Scanning, Language::Ru) => "Сканирование файлов".to_string(),
            (StatusKey::Ready, _) => String::new(),
        },
        StatusMessage::ExportedCsv(path) => match language {
            Language::En => format!("Exported CSV: {}", path.display()),
            Language::Ru => format!("CSV экспортирован: {}", path.display()),
        },
        StatusMessage::ExportedJson(path) => match language {
            Language::En => format!("Exported JSON: {}", path.display()),
            Language::Ru => format!("JSON экспортирован: {}", path.display()),
        },
        StatusMessage::Custom(value) => value.clone(),
    }
}

fn deleted_label(deleted: bool, language: Language) -> &'static str {
    let strings = ui_text(language);
    if deleted { strings.yes } else { strings.no }
}

fn signed_label(status: SignedStatus, language: Language) -> &'static str {
    let strings = ui_text(language);
    match status {
        SignedStatus::Signed => strings.yes,
        SignedStatus::NotSigned => strings.no,
        SignedStatus::Skipped => strings.empty,
    }
}

fn add_trunc_label(ui: &mut egui::Ui, text: &str, hover: String) {
    ui.add(egui::Label::new(text).truncate())
        .on_hover_text(hover);
}

fn entry_hover(entry: &ScanEntry, language: Language) -> String {
    match language {
        Language::En => format!(
            "Name: {}\nPath: {}\nDate: {}\nRegistry path: {}\nResolved: {}\nDeleted: {}\nSigned: {}\nYARA: {}\nLast run: {}\nSID: {}\nSource: {}",
            entry.name,
            entry.path,
            entry.date,
            entry.registry_path,
            entry.resolved_path,
            deleted_label(entry.deleted, language),
            signed_label(entry.signed, language),
            entry.yara_display,
            entry.last_run,
            entry.sid,
            entry.source
        ),
        Language::Ru => format!(
            "Имя: {}\nПуть: {}\nДата: {}\nПуть в BAM: {}\nResolved: {}\nУдалён: {}\nПодпись: {}\nYARA: {}\nПоследний запуск: {}\nSID: {}\nИсточник: {}",
            entry.name,
            entry.path,
            entry.date,
            entry.registry_path,
            entry.resolved_path,
            deleted_label(entry.deleted, language),
            signed_label(entry.signed, language),
            entry.yara_display,
            entry.last_run,
            entry.sid,
            entry.source
        ),
    }
}

fn header_sort_label(
    ui: &mut egui::Ui,
    title: &str,
    sort: SortBy,
    current: &mut SortBy,
    asc: &mut bool,
) -> bool {
    let arrow = if *current == sort {
        if *asc { " ^" } else { " v" }
    } else {
        ""
    };
    let mut text = egui::RichText::new(format!("{title}{arrow}"));
    if *current == sort {
        text = text.strong().color(egui::Color32::from_rgb(255, 90, 90));
    }
    if ui
        .add(
            egui::Label::new(text)
                .sense(egui::Sense::click())
                .truncate(),
        )
        .clicked()
    {
        if *current == sort {
            *asc = !*asc;
        } else {
            *current = sort;
            *asc = true;
        }
        true
    } else {
        false
    }
}

fn handle_zoom(ctx: &egui::Context) {
    let mut factor = ctx.zoom_factor();
    let mut changed = false;
    ctx.input(|i| {
        if i.modifiers.command {
            let scroll_delta = i.raw_scroll_delta.y;
            if scroll_delta > 0.0 {
                factor *= ZOOM_STEP;
                changed = true;
            } else if scroll_delta < 0.0 {
                factor /= ZOOM_STEP;
                changed = true;
            }
            if i.key_pressed(egui::Key::Plus) || i.key_pressed(egui::Key::Equals) {
                factor *= ZOOM_STEP;
                changed = true;
            }
            if i.key_pressed(egui::Key::Minus) {
                factor /= ZOOM_STEP;
                changed = true;
            }
            if i.key_pressed(egui::Key::Num0) {
                factor = 1.0;
                changed = true;
            }
        }
    });
    if changed {
        ctx.set_zoom_factor(factor.clamp(MIN_ZOOM, MAX_ZOOM));
    }
}

fn compare_datetime(left: Option<OffsetDateTime>, right: Option<OffsetDateTime>) -> Ordering {
    match (left, right) {
        (Some(l), Some(r)) => l.cmp(&r),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn export_csv(path: &Path, rows: Vec<ExportRow>) -> Result<()> {
    let file = File::create(path).with_context(|| format!("create csv {}", path.display()))?;
    let mut writer = csv::WriterBuilder::new()
        .has_headers(true)
        .from_writer(file);
    for row in rows {
        writer.serialize(row).context("write csv row")?;
    }
    writer.flush().context("flush csv writer")?;
    Ok(())
}

fn export_json(path: &Path, rows: Vec<ExportRow>) -> Result<()> {
    let file = File::create(path).with_context(|| format!("create json {}", path.display()))?;
    serde_json::to_writer_pretty(file, &rows).context("write json")?;
    Ok(())
}
