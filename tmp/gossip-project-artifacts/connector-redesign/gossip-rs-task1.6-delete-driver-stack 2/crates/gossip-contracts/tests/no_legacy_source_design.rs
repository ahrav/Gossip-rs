use std::{fs, path::{Path, PathBuf}};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn needles() -> Vec<String> {
    vec![
        ["Scan", "Driver"].concat(),
        ["Connector", "Kind"].concat(),
        ["Assignment", "Source"].concat(),
        ["gossip", "-", "scan", "-", "driver"].concat(),
        ["gossip", "_", "scan", "_", "driver"].concat(),
    ]
}

fn scan_files(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![root.join("Cargo.toml")];
    collect_rs_and_toml(&root.join("crates"), &mut files);
    files
}

fn collect_rs_and_toml(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            collect_rs_and_toml(&path, out);
            continue;
        }
        if matches!(path.extension().and_then(|e| e.to_str()), Some("rs" | "toml")) {
            out.push(path);
        }
    }
}

#[test]
fn removed_source_design_identifiers_do_not_reappear() {
    let root = repo_root();
    let needles = needles();
    let mut violations = Vec::new();

    for path in scan_files(&root) {
        let text = fs::read_to_string(&path).unwrap_or_default();
        for needle in &needles {
            if text.contains(needle) {
                let rel = path.strip_prefix(&root).unwrap_or(&path).display().to_string();
                violations.push(format!("{rel}: {needle}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "legacy source-design identifiers must not reappear:\n{}",
        violations.join("\n")
    );
}
