use std::path::{Path, PathBuf};

fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("logo/rss.ico");
    res.set_manifest_file("app.manifest");
    if let Err(err) = res.compile() {
        eprintln!("winres error: {err}");
    }

    if let Err(err) = generate_embedded_yara() {
        eprintln!("yara embed error: {err}");
    }
}

fn generate_embedded_yara() -> std::io::Result<()> {
    use std::env;
    use std::fs;
    use std::io::Write;

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    let yara_dir = manifest_dir.join("yara");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| ".".into()));
    let out_file = out_dir.join("embedded_yara.rs");

    println!("cargo:rerun-if-changed={}", yara_dir.display());

    let mut entries = Vec::new();
    collect_yara_files(&yara_dir, &mut entries)?;
    entries.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

    let mut out = String::new();
    out.push_str("pub struct EmbeddedRule { pub name: &'static str, pub source: &'static str }\n");
    out.push_str("pub const EMBEDDED_RULES: &[EmbeddedRule] = &[\n");
    for path in entries {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("rule");
        let rel = path.strip_prefix(&manifest_dir).unwrap_or(&path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        out.push_str("    EmbeddedRule { name: \"");
        out.push_str(&escape_rust_string(name));
        out.push_str("\", source: include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/");
        out.push_str(&escape_rust_string(&rel_str));
        out.push_str("\")) },\n");
    }
    out.push_str("];\n");

    let mut file = fs::File::create(out_file)?;
    file.write_all(out.as_bytes())?;
    Ok(())
}

fn collect_yara_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            collect_yara_files(&path, out)?;
        } else if is_yara_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_yara_file(path: &Path) -> bool {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara")
}

fn escape_rust_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
