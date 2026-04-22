use serde::Serialize;
use std::path::PathBuf;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub enum YaraStatus {
    Matches(Vec<String>),
    NoMatch,
    Skipped,
    Error,
    Disabled,
}

impl YaraStatus {
    pub fn has_match(&self) -> bool {
        matches!(self, YaraStatus::Matches(v) if !v.is_empty())
    }

    pub fn display(&self) -> String {
        match self {
            YaraStatus::Matches(rules) => rules.join(" / "),
            YaraStatus::NoMatch | YaraStatus::Skipped => String::new(),
            YaraStatus::Error => "error".to_string(),
            YaraStatus::Disabled => "rules missing".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedStatus {
    Signed,
    NotSigned,
    Skipped,
}

impl SignedStatus {
    pub fn display(self) -> &'static str {
        match self {
            SignedStatus::Signed => "yes",
            SignedStatus::NotSigned => "no",
            SignedStatus::Skipped => "",
        }
    }

    pub fn is_not_signed(self) -> bool {
        matches!(self, SignedStatus::NotSigned)
    }
}

#[derive(Debug, Clone)]
pub struct ScanEntry {
    pub index: usize,
    pub name: String,
    pub name_lower: String,
    pub path: String,
    pub path_lower: String,
    pub registry_path: String,
    pub registry_path_lower: String,
    pub resolved_path: String,
    pub deleted: bool,
    pub signed: SignedStatus,
    pub signed_lower: String,
    pub yara: YaraStatus,
    pub yara_display: String,
    pub yara_lower: String,
    pub date: String,
    pub date_lower: String,
    pub last_run: String,
    pub last_run_dt: Option<OffsetDateTime>,
    pub sid: String,
    pub source: String,
}

impl ScanEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: usize,
        path: String,
        resolved_path: String,
        registry_path: String,
        deleted: bool,
        signed: SignedStatus,
        yara: YaraStatus,
        date: String,
        last_run: String,
        last_run_dt: Option<OffsetDateTime>,
        sid: String,
        source: String,
    ) -> Self {
        let name = file_name_from_any_path(&path);
        let name_lower = name.to_lowercase();
        let path_lower = path.to_lowercase();
        let registry_path_lower = registry_path.to_lowercase();
        let yara_display = yara.display();
        let yara_lower = yara_display.to_lowercase();
        let date_lower = date.to_lowercase();
        let signed_lower = signed.display().to_string();
        Self {
            index,
            name,
            name_lower,
            path,
            path_lower,
            registry_path,
            registry_path_lower,
            resolved_path,
            deleted,
            signed,
            signed_lower,
            yara,
            yara_display,
            yara_lower,
            date,
            date_lower,
            last_run,
            last_run_dt,
            sid,
            source,
        }
    }

    pub fn deleted_label(&self) -> &'static str {
        if self.deleted { "yes" } else { "no" }
    }
}

pub fn file_name_from_any_path(path: &str) -> String {
    path.trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Name,
    Path,
    Date,
    Deleted,
    Signed,
    Yara,
}

#[derive(Debug)]
pub struct Progress {
    pub scanned: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum StatusKey {
    Processing,
    LoadingRegistry,
    CompilingYara,
    Scanning,
    Ready,
}

#[derive(Debug, Clone)]
pub enum StatusMessage {
    Key(StatusKey),
    ExportedCsv(PathBuf),
    ExportedJson(PathBuf),
    Custom(String),
}

#[derive(Debug)]
pub enum WorkerEvent {
    Status(StatusKey),
    Progress {
        scanned: usize,
        total: usize,
    },
    Finished {
        entries: Vec<ScanEntry>,
        errors: Vec<String>,
    },
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum InfoState {
    Empty,
    Loading,
    Ready(BamInfo),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct BamInfo {
    pub collected_at: String,
    pub services: Vec<ServiceInfo>,
    pub roots: Vec<BamRootInfo>,
    pub events: Vec<BamEvent>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub key_path: String,
    pub exists: bool,
    pub start_raw: Option<u32>,
    pub start_label: String,
    pub enabled: Option<bool>,
    pub service_type: String,
    pub image_path: String,
    pub error_control: String,
    pub key_last_write: String,
}

#[derive(Debug, Clone)]
pub struct BamRootInfo {
    pub path: String,
    pub exists: bool,
    pub sid_count: usize,
    pub value_count: usize,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct BamEvent {
    #[serde(rename = "Log")]
    pub log: String,
    #[serde(rename = "Id")]
    pub id: u32,
    #[serde(rename = "Time")]
    pub time: String,
    #[serde(rename = "Provider")]
    pub provider: String,
    #[serde(rename = "Category", default)]
    pub category: String,
    #[serde(rename = "Signal", default)]
    pub signal: String,
    #[serde(rename = "Message")]
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ExportRow {
    pub name: String,
    pub path: String,
    pub registry_path: String,
    pub resolved_path: String,
    pub deleted: String,
    pub signed: String,
    pub yara: String,
    pub date: String,
    pub last_run: String,
    pub sid: String,
    pub source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_file_name_from_nt_path() {
        assert_eq!(
            file_name_from_any_path(r"\Device\HarddiskVolume3\Windows\System32\cmd.exe"),
            "cmd.exe"
        );
    }
}
