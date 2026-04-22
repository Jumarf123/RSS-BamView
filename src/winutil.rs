use crate::model::SignedStatus;
use anyhow::{Context, Result};
use eframe::egui;
use image::GenericImageView;
use std::ffi::{OsStr, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::mem::size_of;
use std::os::windows::prelude::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Globalization::GetUserDefaultLocaleName;
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_IGNORE,
    WTD_UI_NONE, WinVerifyTrust,
};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW, SW_SHOW};
use windows::core::{GUID, PCWSTR};

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Clone)]
pub struct LogSink {
    file: Arc<Mutex<Option<File>>>,
}

impl LogSink {
    pub fn new() -> Self {
        let path = default_log_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        Self {
            file: Arc::new(Mutex::new(file)),
        }
    }

    pub fn log_error(&self, message: &str) {
        self.log("ERROR", message);
    }

    fn log(&self, level: &str, message: &str) {
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string());
        if let Ok(mut guard) = self.file.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = writeln!(file, "[{timestamp}] {level}: {message}");
            }
        }
    }
}

fn default_log_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        PathBuf::from(dir)
            .join("RSS-BamView")
            .join("rss-bamview.log")
    } else {
        std::env::temp_dir()
            .join("RSS-BamView")
            .join("rss-bamview.log")
    }
}

pub fn load_app_icon(log: &LogSink) -> Option<egui::IconData> {
    let bytes = include_bytes!("../logo/rss.ico");
    let image = match image::load_from_memory(bytes) {
        Ok(value) => value,
        Err(err) => {
            log.log_error(&format!("icon decode failed: {err}"));
            return None;
        }
    };
    let rgba = image.to_rgba8();
    let (width, height) = image.dimensions();
    Some(egui::IconData {
        rgba: rgba.into_raw(),
        width,
        height,
    })
}

pub fn show_message(title: &str, message: &str) {
    let title_wide = to_wide(title);
    let message_wide = to_wide(message);
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(message_wide.as_ptr()),
            PCWSTR(title_wide.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

pub fn to_wide(value: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = OsStr::new(value).encode_wide().collect();
    wide.push(0);
    wide
}

fn to_wide_path(path: &Path) -> Vec<u16> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    wide
}

pub enum EnsureOutcome {
    Already,
    Spawned,
}

pub fn ensure_elevated(log: &LogSink) -> Result<EnsureOutcome> {
    if is_elevated()? {
        return Ok(EnsureOutcome::Already);
    }
    let exe = std::env::current_exe().context("locate executable")?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_line = join_args(&args);

    let verb = to_wide("runas");
    let exe_wide = to_wide(&exe.to_string_lossy());
    let args_wide = if args_line.is_empty() {
        None
    } else {
        Some(to_wide(&args_line))
    };

    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe_wide.as_ptr()),
            args_wide
                .as_ref()
                .map_or(PCWSTR::null(), |v| PCWSTR(v.as_ptr())),
            PCWSTR::null(),
            SW_SHOW,
        )
    };

    if result.0 as isize <= 32 {
        log.log_error(&format!("ShellExecuteW failed: {}", result.0 as isize));
        return Err(anyhow::anyhow!("UAC was canceled or failed."));
    }

    Ok(EnsureOutcome::Spawned)
}

fn join_args(args: &[String]) -> String {
    let mut out = String::new();
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        if arg.contains(' ') || arg.contains('"') {
            out.push('"');
            out.push_str(&arg.replace('"', "\\\""));
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }
    out
}

fn is_elevated() -> Result<bool> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )?;
        let _ = CloseHandle(token);
        Ok(elevation.TokenIsElevated != 0)
    }
}

pub fn verify_signature(path: &Path) -> SignedStatus {
    let wide = to_wide_path(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA::default();
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file_info;
    data.dwStateAction = WTD_STATEACTION_IGNORE;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let result = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        )
    };

    if result == 0 {
        SignedStatus::Signed
    } else {
        SignedStatus::NotSigned
    }
}

pub fn run_powershell(script: &str) -> Result<String> {
    let script = format!(
        "$enc = New-Object System.Text.UTF8Encoding $false; \
         [Console]::OutputEncoding = $enc; \
         $OutputEncoding = $enc; \
         {script}"
    );
    let output = Command::new("powershell.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .context("run powershell")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if output.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!("powershell failed: {}", stderr.trim()))
    }
}

pub fn system_language_is_russian() -> bool {
    let mut buffer = [0u16; 85];
    let len = unsafe { GetUserDefaultLocaleName(&mut buffer) };
    if len <= 1 {
        return false;
    }
    let locale = String::from_utf16_lossy(&buffer[..(len as usize - 1)]).to_lowercase();
    locale.starts_with("ru")
}

pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    let bg = egui::Color32::from_rgb(6, 7, 9);
    let panel = egui::Color32::from_rgb(11, 12, 15);
    let panel_alt = egui::Color32::from_rgb(18, 17, 19);
    let red = egui::Color32::from_rgb(204, 20, 32);
    let red_dim = egui::Color32::from_rgb(112, 16, 22);
    let text = egui::Color32::from_rgb(232, 232, 235);
    let text_dim = egui::Color32::from_rgb(168, 170, 176);

    visuals.window_fill = bg;
    visuals.panel_fill = bg;
    visuals.extreme_bg_color = egui::Color32::from_rgb(3, 4, 5);
    visuals.faint_bg_color = panel_alt;
    visuals.code_bg_color = panel;
    visuals.selection.bg_fill = red_dim;
    visuals.selection.stroke = egui::Stroke::new(1.0, red);
    visuals.hyperlink_color = red;
    visuals.override_text_color = Some(text);
    visuals.window_corner_radius = egui::CornerRadius::same(6);
    visuals.menu_corner_radius = egui::CornerRadius::same(4);

    visuals.widgets.noninteractive.bg_fill = panel;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, text_dim);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(16, 17, 20);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, text);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(44, 20, 24);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, text);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(78, 20, 28);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, text);
    visuals.widgets.open.bg_fill = egui::Color32::from_rgb(34, 19, 22);
    visuals.widgets.open.fg_stroke = egui::Stroke::new(1.0, text);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.window_margin = egui::Margin::same(8);
    style.visuals = visuals;
    ctx.set_style(style);
}
