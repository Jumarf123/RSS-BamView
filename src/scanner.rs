use crate::bam::{CandidateAgg, format_date, format_datetime, load_bam_records, max_opt_dt};
use crate::model::{ScanEntry, SignedStatus, StatusKey, WorkerEvent, YaraStatus};
use crate::winutil::{LogSink, verify_signature};
use crate::yara_rules::{load_embedded_yara_rules, scan_file_with_yara};
use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, mpsc};

pub fn run_pipeline(tx: &mpsc::Sender<WorkerEvent>, log: LogSink) -> Result<()> {
    let mut errors = Vec::new();
    let _ = tx.send(WorkerEvent::Status(StatusKey::LoadingRegistry));
    let records = load_bam_records(&mut errors)?;

    let mut map: HashMap<String, CandidateAgg> = HashMap::new();
    for record in records {
        let key = record.resolved_path.to_lowercase();
        let entry = map.entry(key).or_insert_with(|| CandidateAgg {
            index: record.index,
            sid: record.sid.clone(),
            source: record.source.clone(),
            path: record.path.clone(),
            resolved_path: record.resolved_path.clone(),
            last_run_dt: record.last_run_dt,
        });
        if record.index < entry.index {
            entry.index = record.index;
        }
        entry.last_run_dt = max_opt_dt(entry.last_run_dt, record.last_run_dt);
    }
    let mut candidates: Vec<CandidateAgg> = map.into_values().collect();
    candidates.sort_by_key(|c| c.index);

    let _ = tx.send(WorkerEvent::Status(StatusKey::CompilingYara));
    let yara_rules = load_embedded_yara_rules(&log, &mut errors);
    let rules_available = yara_rules.is_some();
    let rules_for_threads = yara_rules.map(Arc::new);

    let _ = tx.send(WorkerEvent::Status(StatusKey::Scanning));
    let total = candidates.len();
    let progress = Arc::new(AtomicUsize::new(0));
    let errors_shared: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let rows: Vec<ScanEntry> = candidates
        .into_par_iter()
        .map({
            let tx = tx.clone();
            let progress = progress.clone();
            let errors_shared = errors_shared.clone();
            let rules_for_threads = rules_for_threads.clone();
            let log = log.clone();
            move |candidate| {
                let deleted = match fs::metadata(&candidate.resolved_path) {
                    Ok(metadata) => !metadata.is_file(),
                    Err(_) => true,
                };

                let signed = if deleted {
                    SignedStatus::Skipped
                } else {
                    verify_signature(Path::new(&candidate.resolved_path))
                };

                let yara = if !rules_available {
                    YaraStatus::Disabled
                } else if deleted {
                    YaraStatus::Skipped
                } else if let Some(bundle) = rules_for_threads.as_ref() {
                    scan_file_with_yara(
                        bundle,
                        &candidate.resolved_path,
                        &candidate.path,
                        &log,
                        &errors_shared,
                    )
                } else {
                    YaraStatus::Disabled
                };

                let scanned = progress.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                if scanned % 20 == 0 || scanned == total {
                    let _ = tx.send(WorkerEvent::Progress { scanned, total });
                }

                ScanEntry::new(
                    candidate.index,
                    display_path(&candidate.path, &candidate.resolved_path),
                    candidate.resolved_path,
                    candidate.path,
                    deleted,
                    signed,
                    yara,
                    candidate.last_run_dt.map(format_date).unwrap_or_default(),
                    candidate
                        .last_run_dt
                        .map(format_datetime)
                        .unwrap_or_default(),
                    candidate.last_run_dt,
                    candidate.sid,
                    candidate.source,
                )
            }
        })
        .collect();

    if let Ok(mut guard) = errors_shared.lock() {
        errors.append(&mut guard);
    }

    let mut rows = rows;
    rows.sort_by_key(|r| r.index);
    let _ = tx.send(WorkerEvent::Finished {
        entries: rows,
        errors,
    });
    Ok(())
}

fn display_path(raw_path: &str, resolved_path: &str) -> String {
    if resolved_path.is_empty() {
        raw_path.to_string()
    } else {
        resolved_path.to_string()
    }
}
