use crate::model::YaraStatus;
use crate::winutil::LogSink;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use yara_x::{Compiler, Scanner};

mod embedded_yara {
    include!(concat!(env!("OUT_DIR"), "/embedded_yara.rs"));
}

#[derive(Clone)]
pub struct YaraBundle {
    rules: Arc<yara_x::Rules>,
    namespace_map: Arc<HashMap<String, String>>,
}

pub fn load_embedded_yara_rules(log: &LogSink, errors: &mut Vec<String>) -> Option<YaraBundle> {
    let mut compiler = Compiler::new();
    if let Err(err) = compiler.define_global("filepath", "") {
        let message = format!("yara global filepath define failed: {err}");
        log.log_error(&message);
        errors.push(message);
        return None;
    }

    let mut any = false;
    let mut namespace_map: HashMap<String, String> = HashMap::new();
    for rule in embedded_yara::EMBEDDED_RULES {
        let display = rule
            .name
            .trim_end_matches(".yara")
            .trim_end_matches(".yar")
            .to_string();
        let namespace = sanitize_namespace(&display);
        namespace_map
            .entry(namespace.clone())
            .or_insert_with(|| display.clone());
        compiler.new_namespace(&namespace);
        match compiler.add_source(rule.source) {
            Ok(_) => any = true,
            Err(err) => {
                let message = format!("yara compile error in embedded {}: {err}", rule.name);
                log.log_error(&message);
                errors.push(message);
            }
        }
    }

    if !any {
        errors.push("No embedded YARA rules compiled.".to_string());
        return None;
    }

    Some(YaraBundle {
        rules: compiler.build().into(),
        namespace_map: Arc::new(namespace_map),
    })
}

pub fn scan_file_with_yara(
    bundle: &YaraBundle,
    resolved_path: &str,
    display_path: &str,
    log: &LogSink,
    errors: &Arc<Mutex<Vec<String>>>,
) -> YaraStatus {
    let mut scanner = Scanner::new(&bundle.rules);
    let filepath = display_path.replace('\\', "/");
    let scan_result = match scanner.set_global("filepath", filepath.as_str()) {
        Ok(_) => scanner
            .scan_file(resolved_path)
            .map_err(|err| anyhow::anyhow!(err)),
        Err(err) => Err(anyhow::anyhow!(err)),
    };

    match scan_result {
        Ok(results) => {
            let mut matched = HashSet::new();
            for rule in results.matching_rules() {
                let namespace = rule.namespace();
                let display = bundle
                    .namespace_map
                    .get(namespace)
                    .map(|value| value.as_str())
                    .unwrap_or(namespace);
                matched.insert(display.to_string());
            }
            if matched.is_empty() {
                YaraStatus::NoMatch
            } else {
                let mut matched: Vec<String> = matched.into_iter().collect();
                matched.sort();
                YaraStatus::Matches(matched)
            }
        }
        Err(err) => {
            let message = format!("YARA scan failed for {}: {err}", display_path);
            log.log_error(&message);
            if let Ok(mut guard) = errors.lock() {
                guard.push(message);
            }
            YaraStatus::Error
        }
    }
}

fn sanitize_namespace(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("rule");
    }
    if out.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}
