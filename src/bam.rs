use crate::model::{BamEvent, BamInfo, BamRootInfo, ServiceInfo};
use crate::winutil::{run_powershell, to_wide};
use anyhow::Result;
use std::path::PathBuf;
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::core::PCWSTR;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

pub const BAM_ROOTS: &[&str] = &[
    r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
    r"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings",
    r"SYSTEM\CurrentControlSet\Services\dam\UserSettings",
];

const SERVICE_KEYS: &[(&str, &str)] = &[
    ("bam", "Background Activity Moderator Driver"),
    ("dam", "Desktop Activity Moderator Driver"),
];

#[derive(Debug)]
pub struct BamRecord {
    pub index: usize,
    pub sid: String,
    pub source: String,
    pub path: String,
    pub resolved_path: String,
    pub last_run_dt: Option<OffsetDateTime>,
}

#[derive(Debug)]
pub struct CandidateAgg {
    pub index: usize,
    pub sid: String,
    pub source: String,
    pub path: String,
    pub resolved_path: String,
    pub last_run_dt: Option<OffsetDateTime>,
}

pub fn load_bam_records(errors: &mut Vec<String>) -> Result<Vec<BamRecord>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let device_map = DeviceMap::load();
    let mut out = Vec::new();
    let mut index = 0usize;
    let mut opened_any = false;

    for root_path in BAM_ROOTS {
        let root = match hklm.open_subkey_with_flags(root_path, KEY_READ) {
            Ok(root) => {
                opened_any = true;
                root
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                errors.push(format!("open registry {} failed: {}", root_path, err));
                continue;
            }
        };

        for sid_result in root.enum_keys() {
            let sid = match sid_result {
                Ok(sid) => sid,
                Err(err) => {
                    errors.push(format!("enumerate SID under {} failed: {}", root_path, err));
                    continue;
                }
            };
            let sid_key = match root.open_subkey_with_flags(&sid, KEY_READ) {
                Ok(key) => key,
                Err(err) => {
                    errors.push(format!(
                        "open SID {} under {} failed: {}",
                        sid, root_path, err
                    ));
                    continue;
                }
            };

            for value_result in sid_key.enum_values() {
                let (raw_name, value) = match value_result {
                    Ok(value) => value,
                    Err(err) => {
                        errors.push(format!("enumerate values for {} failed: {}", sid, err));
                        continue;
                    }
                };
                if !looks_like_bam_path(&raw_name) {
                    continue;
                }
                let path = normalize_registry_path(&raw_name);
                let resolved_path = device_map.resolve(&path);
                let last_run_dt = filetime_from_bytes(&value.bytes);
                out.push(BamRecord {
                    index,
                    sid: sid.clone(),
                    source: (*root_path).to_string(),
                    path,
                    resolved_path,
                    last_run_dt,
                });
                index += 1;
            }
        }
    }

    if !opened_any {
        errors.push("No BAM/DAM registry UserSettings keys were found.".to_string());
    }
    Ok(out)
}

pub fn collect_bam_info() -> BamInfo {
    let mut errors = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let services = collect_service_info(&hklm, &mut errors);
    let roots = collect_root_info(&hklm, &mut errors);
    let events = match collect_bam_events() {
        Ok(events) => events,
        Err(err) => {
            errors.push(format!("event log query failed: {err}"));
            Vec::new()
        }
    };

    BamInfo {
        collected_at: format_date(OffsetDateTime::now_utc()),
        services,
        roots,
        events,
        errors,
    }
}

fn collect_service_info(hklm: &RegKey, errors: &mut Vec<String>) -> Vec<ServiceInfo> {
    SERVICE_KEYS
        .iter()
        .map(|(name, default_display)| {
            let key_path = format!(r"SYSTEM\CurrentControlSet\Services\{}", name);
            let key = hklm.open_subkey_with_flags(&key_path, KEY_READ);
            match key {
                Ok(key) => {
                    let start_raw: Option<u32> = key.get_value("Start").ok();
                    let type_raw: Option<u32> = key.get_value("Type").ok();
                    let error_raw: Option<u32> = key.get_value("ErrorControl").ok();
                    let image_path: String =
                        key.get_value("ImagePath").unwrap_or_else(|_| String::new());
                    let display_name: String = key
                        .get_value("DisplayName")
                        .unwrap_or_else(|_| (*default_display).to_string());
                    let key_last_write = key
                        .query_info()
                        .map(|info| {
                            let st = info.get_last_write_time_system();
                            format!(
                                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
                            )
                        })
                        .unwrap_or_default();

                    ServiceInfo {
                        name: (*name).to_string(),
                        display_name,
                        key_path,
                        exists: true,
                        start_raw,
                        start_label: start_raw.map(start_label).unwrap_or("missing").to_string(),
                        enabled: start_raw.map(|value| value != 4),
                        service_type: type_raw.map(type_label).unwrap_or("missing").to_string(),
                        image_path,
                        error_control: error_raw
                            .map(error_control_label)
                            .unwrap_or("missing")
                            .to_string(),
                        key_last_write,
                    }
                }
                Err(err) => {
                    if err.kind() != std::io::ErrorKind::NotFound {
                        errors.push(format!("open service key {} failed: {}", key_path, err));
                    }
                    ServiceInfo {
                        name: (*name).to_string(),
                        display_name: (*default_display).to_string(),
                        key_path,
                        exists: false,
                        start_raw: None,
                        start_label: "missing".to_string(),
                        enabled: None,
                        service_type: "missing".to_string(),
                        image_path: String::new(),
                        error_control: "missing".to_string(),
                        key_last_write: String::new(),
                    }
                }
            }
        })
        .collect()
}

fn collect_root_info(hklm: &RegKey, errors: &mut Vec<String>) -> Vec<BamRootInfo> {
    BAM_ROOTS
        .iter()
        .map(|path| match hklm.open_subkey_with_flags(path, KEY_READ) {
            Ok(root) => {
                let mut sid_count = 0usize;
                let mut value_count = 0usize;
                for sid in root.enum_keys().flatten() {
                    sid_count += 1;
                    if let Ok(sid_key) = root.open_subkey_with_flags(&sid, KEY_READ) {
                        value_count += sid_key.enum_values().flatten().count();
                    }
                }
                BamRootInfo {
                    path: (*path).to_string(),
                    exists: true,
                    sid_count,
                    value_count,
                }
            }
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    errors.push(format!("open root {} failed: {}", path, err));
                }
                BamRootInfo {
                    path: (*path).to_string(),
                    exists: false,
                    sid_count: 0,
                    value_count: 0,
                }
            }
        })
        .collect()
}

fn collect_bam_events() -> Result<Vec<BamEvent>> {
    let script = r#"
$serviceNeedle = '(?i)(\bbam\b|Background Activity Moderator|\\Services\\bam|bam\.sys|\bdam\b|Desktop Activity Moderator|\\Services\\dam|dam\.sys)'
$registryNeedle = '(?i)(\\Services\\(bam|dam)|\\REGISTRY\\MACHINE\\SYSTEM\\.*\\Services\\(bam|dam)|HKLM\\.*\\Services\\(bam|dam)|HKLM:\\.*\\Services\\(bam|dam)|TargetObject=.*\\Services\\(bam|dam)|ObjectName=.*\\Services\\(bam|dam))'
$directCommandNeedle = '(?i)(^|[\s"`'';&|])((sc|sc\.exe)\s+((start|stop|delete|create)\s+(bam|dam)\b|(bam|dam)\s+(start|stop|delete|create)\b|config\s+(bam|dam)\b.*\bstart\s*=|(bam|dam)\s+config\b.*\bstart\s*=)|(net|net\.exe)\s+(start|stop)\s+(bam|dam)\b|((Start|Stop|Restart)-Service)\s+.*\b(bam|dam)\b|Set-Service\s+.*\b(bam|dam)\b.*\b(StartupType|Disabled|Automatic|Manual)\b|Set-ItemProperty\s+.*\\Services\\(bam|dam)\b.*\bStart\b|New-ItemProperty\s+.*\\Services\\(bam|dam)\b.*\bStart\b|reg(\.exe)?\s+(add|delete)\s+.*\\Services\\(bam|dam)\b.*\b(/v\s+Start|Start\b))'
$collectorNeedle = '(?i)(Get-WinEvent|Resolve-Signal|New-OutputEvent|directCommandNeedle|serviceNeedle|registryNeedle|RSS-BamView|rss-bamview)'
$startNeedle = '(?i)(\\Services\\(bam|dam).*\\Start|ObjectValueName=Start|TargetObject=.*\\Start|Details=.*DWORD \(0x00000004\)|NewValue=.*\b4\b|disabled)'

function Get-EventDataMap($event) {
  $map = @{}
  try {
    [xml]$xml = $event.ToXml()
    $idx = 1
    foreach ($node in @($xml.Event.EventData.Data)) {
      $name = [string]$node.Name
      if ([string]::IsNullOrWhiteSpace($name)) {
        $name = "param$idx"
      }
      $value = [string]$node.'#text'
      $map[$name] = $value
      $idx++
    }
  } catch {}
  return $map
}

function Get-EventTextData($event) {
  try {
    [xml]$xml = $event.ToXml()
    $parts = New-Object System.Collections.Generic.List[string]
    $data = Get-EventDataMap $event
    foreach ($name in $data.Keys) {
      $value = [string]$data[$name]
      if (![string]::IsNullOrWhiteSpace($value)) {
        $parts.Add("$name=$value")
      }
    }
    foreach ($parent in @($xml.Event.UserData.ChildNodes)) {
      foreach ($node in @($parent.ChildNodes)) {
        $name = [string]$node.Name
        $value = [string]$node.InnerText
        if (![string]::IsNullOrWhiteSpace($value)) {
          $parts.Add("$name=$value")
        }
      }
    }
    return ($parts -join ' | ')
  } catch {
    return ''
  }
}

function Get-FullText($event) {
  $message = (([string]$event.Message) -replace "`r?`n", " ").Trim()
  $dataText = Get-EventTextData $event
  return "$message $dataText"
}

function Get-CommandText($event) {
  $data = Get-EventDataMap $event
  switch ([int]$event.Id) {
    4688 { return "$($data['NewProcessName']) $($data['CommandLine']) $($data['ParentProcessName'])" }
    1 { return "$($data['Image']) $($data['CommandLine']) $($data['ParentImage'])" }
    default { return (Get-FullText $event) }
  }
}

function Resolve-Signal($event, $text) {
  switch ([int]$event.Id) {
    7040 { return 'strong_service_start_type_changed' }
    7035 { return 'medium_service_control_state' }
    7036 { return 'medium_service_control_state' }
    7045 { return 'context_service_installed' }
    4657 { if ($text -match $startNeedle) { return 'strong_security_registry_start' } return 'medium_security_registry_services' }
    4660 { return 'medium_security_registry_services' }
    4663 { return 'medium_security_registry_services' }
    4670 { return 'medium_security_registry_services' }
    4688 { return 'medium_process_command' }
    4697 { return 'context_service_installed' }
    1 { return 'medium_process_command' }
    12 { return 'medium_sysmon_registry_services' }
    13 { if ($text -match $startNeedle) { return 'strong_sysmon_registry_start' } return 'medium_sysmon_registry_services' }
    14 { return 'medium_sysmon_registry_services' }
    4103 { return 'medium_powershell_command' }
    4104 { return 'medium_powershell_command' }
    104 { return 'context_log_cleared' }
    1100 { return 'context_eventlog_service' }
    1101 { return 'context_eventlog_service' }
    1102 { return 'context_log_cleared' }
    default { return 'context_other' }
  }
}

function Get-CompactMessage($event) {
  $data = Get-EventDataMap $event
  switch ([int]$event.Id) {
    4688 {
      return "Process=$($data['NewProcessName']) | CommandLine=$($data['CommandLine']) | Parent=$($data['ParentProcessName']) | User=$($data['SubjectDomainName'])\$($data['SubjectUserName'])"
    }
    1 {
      return "Image=$($data['Image']) | CommandLine=$($data['CommandLine']) | Parent=$($data['ParentImage']) | User=$($data['User'])"
    }
    4657 {
      return "Object=$($data['ObjectName']) | Value=$($data['ObjectValueName']) | Old=$($data['OldValue']) | New=$($data['NewValue']) | Process=$($data['ProcessName'])"
    }
    13 {
      return "Target=$($data['TargetObject']) | Details=$($data['Details']) | Image=$($data['Image']) | User=$($data['User'])"
    }
    12 {
      return "Target=$($data['TargetObject']) | EventType=$($data['EventType']) | Image=$($data['Image']) | User=$($data['User'])"
    }
    14 {
      return "Target=$($data['TargetObject']) | NewName=$($data['NewName']) | Image=$($data['Image']) | User=$($data['User'])"
    }
    default {
      $message = (([string]$event.Message) -replace "`r?`n", " ").Trim()
      $dataText = Get-EventTextData $event
      if (![string]::IsNullOrWhiteSpace($dataText)) {
        return "$message | EventData: $dataText"
      }
      return $message
    }
  }
}

function New-OutputEvent($event, $category, $text) {
  $resolvedCategory = [string]$category
  if ([int]$event.Id -eq 4688 -or [int]$event.Id -eq 1) { $resolvedCategory = 'process_command' }
  [pscustomobject]@{
    Log = [string]$event.LogName
    Id = [int]$event.Id
    Time = $event.TimeCreated.ToString('dd.MM.yyyy')
    Provider = [string]$event.ProviderName
    Category = [string]$resolvedCategory
    Signal = [string](Resolve-Signal $event $text)
    Message = [string](Get-CompactMessage $event)
  }
}

$out = New-Object System.Collections.Generic.List[object]

$eventSpecs = @(
  @{ Log = 'System'; Ids = @(7035,7036,7040,7045); Category = 'service_control'; Max = 5000; Needle = $serviceNeedle; Direct = $false },
  @{ Log = 'Security'; Ids = @(4657,4660,4663,4670,4697); Category = 'registry_audit'; Max = 5000; Needle = $registryNeedle; Direct = $false },
  @{ Log = 'Security'; Ids = @(4688); Category = 'process_command'; Max = 5000; Needle = $directCommandNeedle; Direct = $true },
  @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(12,13,14); Category = 'sysmon_registry'; Max = 5000; Needle = $registryNeedle; Direct = $false },
  @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1); Category = 'process_command'; Max = 5000; Needle = $directCommandNeedle; Direct = $true },
  @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4103,4104); Category = 'powershell_script'; Max = 2500; Needle = $directCommandNeedle; Direct = $true }
)

foreach ($spec in $eventSpecs) {
  try {
    Get-WinEvent -FilterHashtable @{LogName=$spec.Log; Id=$spec.Ids} -MaxEvents $spec.Max -ErrorAction Stop |
      ForEach-Object {
        $skip = $false
        if ($spec.Direct) {
          $text = Get-CommandText $_
          if ($text -match $collectorNeedle) { $skip = $true }
        } else {
          $text = Get-FullText $_
        }
        if ((-not $skip) -and ($text -match $spec.Needle)) {
          $out.Add((New-OutputEvent $_ $spec.Category $text))
        }
      }
  } catch {}
}

$integritySpecs = @(
  @{ Log = 'Security'; Ids = @(1102); Category = 'log_integrity'; Max = 60 },
  @{ Log = 'System'; Ids = @(104,1100,1101); Category = 'log_integrity'; Max = 120 }
)
foreach ($spec in $integritySpecs) {
  try {
    Get-WinEvent -FilterHashtable @{LogName=$spec.Log; Id=$spec.Ids} -MaxEvents $spec.Max -ErrorAction Stop |
      Select-Object -First 40 |
      ForEach-Object {
        $text = Get-FullText $_
        $out.Add((New-OutputEvent $_ $spec.Category $text))
      }
  } catch {}
}

@($out | Sort-Object Time -Descending | Select-Object -First 240) | ConvertTo-Json -Compress -Depth 5
"#;
    let stdout = run_powershell(script)?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        Ok(serde_json::from_str::<Vec<BamEvent>>(trimmed).unwrap_or_default())
    } else {
        let one = serde_json::from_str::<BamEvent>(trimmed).ok();
        Ok(one.into_iter().collect())
    }
}

fn looks_like_bam_path(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if value.eq_ignore_ascii_case("SequenceNumber") || value.eq_ignore_ascii_case("Version") {
        return false;
    }
    value.contains('\\') || value.contains(':')
}

fn normalize_registry_path(value: &str) -> String {
    let mut path = value.trim_matches('\0').to_string();
    if let Some(stripped) = path.strip_prefix(r"\??\") {
        path = stripped.to_string();
    }
    if let Some(stripped) = path.strip_prefix(r"\\?\") {
        path = stripped.to_string();
    }
    if let Some(stripped) = path.strip_prefix(r"GLOBALROOT\") {
        path = format!(r"\{stripped}");
    }
    path
}

#[derive(Debug)]
struct DeviceMap {
    devices: Vec<(String, String)>,
}

impl DeviceMap {
    fn load() -> Self {
        let mut devices = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let drive_wide = to_wide(&drive);
            let mut buffer = vec![0u16; 8192];
            let len = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut buffer)) };
            if len == 0 {
                continue;
            }
            let mut start = 0usize;
            let limit = len as usize;
            while start < limit {
                let Some(relative_end) = buffer[start..limit].iter().position(|&ch| ch == 0) else {
                    break;
                };
                let end = start + relative_end;
                if end == start {
                    break;
                }
                let device = String::from_utf16_lossy(&buffer[start..end]);
                devices.push((device, drive.clone()));
                start = end + 1;
            }
        }
        devices.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Self { devices }
    }

    fn resolve(&self, path: &str) -> String {
        if is_drive_path(path) || path.starts_with(r"\\") {
            return path.to_string();
        }
        for (device, drive) in &self.devices {
            if path.eq_ignore_ascii_case(device) {
                return drive.clone();
            }
            let prefix = format!("{device}\\");
            if path.len() > prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(&prefix) {
                return format!("{}\\{}", drive, &path[prefix.len()..]);
            }
        }
        if let Some(stripped) = path.strip_prefix(r"\SystemRoot\") {
            if let Some(system_root) = std::env::var_os("SystemRoot") {
                return PathBuf::from(system_root)
                    .join(stripped)
                    .to_string_lossy()
                    .into_owned();
            }
        }
        path.to_string()
    }
}

fn is_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')
}

pub fn filetime_from_bytes(bytes: &[u8]) -> Option<OffsetDateTime> {
    let raw = bytes.get(..8)?;
    let value = u64::from_le_bytes(raw.try_into().ok()?);
    filetime_to_datetime(value)
}

fn filetime_to_datetime(value: u64) -> Option<OffsetDateTime> {
    if value == 0 {
        return None;
    }
    let unix_100ns = value.checked_sub(116_444_736_000_000_000)?;
    let secs = (unix_100ns / 10_000_000) as i64;
    let nanos = ((unix_100ns % 10_000_000) * 100) as i64;
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .map(|dt| dt + time::Duration::nanoseconds(nanos))
}

const SHORT_DATE_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
const DATE_ONLY_FORMAT: &[FormatItem<'static>] = format_description!("[day].[month].[year]");

pub fn format_datetime(dt: OffsetDateTime) -> String {
    dt.format(SHORT_DATE_FORMAT).unwrap_or_default()
}

pub fn format_date(dt: OffsetDateTime) -> String {
    dt.format(DATE_ONLY_FORMAT).unwrap_or_default()
}

pub fn max_opt_dt(
    left: Option<OffsetDateTime>,
    right: Option<OffsetDateTime>,
) -> Option<OffsetDateTime> {
    match (left, right) {
        (Some(l), Some(r)) => Some(l.max(r)),
        (Some(l), None) => Some(l),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    }
}

fn start_label(value: u32) -> &'static str {
    match value {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

fn type_label(value: u32) -> &'static str {
    match value {
        1 => "Kernel driver",
        2 => "File system driver",
        16 => "Own process",
        32 => "Shared process",
        _ => "Unknown",
    }
}

fn error_control_label(value: u32) -> &'static str {
    match value {
        0 => "Ignore",
        1 => "Normal",
        2 => "Severe",
        3 => "Critical",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_windows_epoch_filetime() {
        let dt = filetime_to_datetime(116_444_736_000_000_000).unwrap();
        assert_eq!(dt.unix_timestamp(), 0);
    }
}
