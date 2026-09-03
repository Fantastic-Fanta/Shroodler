use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use tauri::{AppHandle, Emitter, State};

pub struct AppState {
    scan_pid: Mutex<Option<u32>>,
    proxy: Mutex<Option<Child>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            scan_pid: Mutex::new(None),
            proxy: Mutex::new(None),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ScanMeta {
    pub id: String,
    pub target: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub finding_count: usize,
}

pub fn parse_progress(line: &str) -> Option<(u32, String)> {
    let line = line.trim();
    let rest = line.strip_prefix("PROGRESS pages=")?;
    let (n, url) = rest.split_once(" current=")?;
    Some((n.parse().ok()?, url.to_string()))
}

fn scans_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Shroodler")
        .join("scans")
}

fn find_bin(kind: &str) -> PathBuf {
    let env_key = match kind {
        "go" => "SHROODLER_GO_BIN",
        "py" => "SHROODLER_PY_BIN",
        _ => "SHROODLER_PROXY_BIN",
    };
    if let Ok(p) = std::env::var(env_key) {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    if kind == "go" {
        p.push("crawler-go");
        p.push("shroodler-go");
    } else if kind == "py" {
        p.pop();
        p.push(".venv");
        p.push("bin");
        p.push("python");
    } else {
        p.push("proxy-go");
        p.push("shroodler-proxy");
    }
    p
}

fn is_python_bin(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|n| n.starts_with("python"))
        .unwrap_or(false)
}

/// Program + argv prefix before `crawl ...`.
/// Headless prefers repo Python (Playwright Chromium from `make bootstrap`);
/// otherwise Go chromedp against system Chrome. Neither CPython nor Chrome is bundled.
fn crawl_sidecar(mode: &str) -> Result<(PathBuf, Vec<String>), String> {
    if mode == "headless" {
        let py = find_bin("py");
        if py.exists() {
            let prefix = if is_python_bin(&py) {
                vec!["-m".into(), "shroodler".into()]
            } else {
                vec![]
            };
            return Ok((py, prefix));
        }
    }
    let go = find_bin("go");
    if !go.exists() {
        if mode == "headless" {
            return Err(format!(
                "headless sidecar missing (no {} and no {})",
                find_bin("py").display(),
                go.display()
            ));
        }
        return Err(format!("sidecar missing: {}", go.display()));
    }
    Ok((go, vec![]))
}

fn crawl_args(
    prefix: &[String],
    target: &str,
    mode: &str,
    depth: u32,
    output: &str,
    cookie_jar: Option<&str>,
    login_recipe: Option<&str>,
    via_proxy: bool,
    cookie: Option<&str>,
    seeds: &[String],
) -> Vec<String> {
    let mut args = prefix.to_vec();
    args.push("crawl".into());
    args.push(target.into());
    args.push("--mode".into());
    args.push(mode.into());
    args.push("--depth".into());
    args.push(depth.to_string());
    args.push("--output".into());
    args.push(output.into());
    if let Some(j) = cookie_jar.filter(|s| !s.is_empty()) {
        args.push("--cookie-jar".into());
        args.push(j.into());
    }
    if let Some(r) = login_recipe.filter(|s| !s.is_empty()) {
        args.push("--login-recipe".into());
        args.push(r.into());
    }
    if via_proxy {
        args.push("--proxy".into());
        args.push("http://127.0.0.1:8888".into());
    }
    if let Some(c) = cookie.filter(|s| !s.is_empty()) {
        for part in c.split(';') {
            let part = part.trim();
            if !part.is_empty() {
                args.push("--cookie".into());
                args.push(part.into());
            }
        }
    }
    for s in seeds {
        if !s.is_empty() {
            args.push("--seed".into());
            args.push(s.clone());
        }
    }
    args
}

fn slug(target: &str) -> String {
    target
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .chars()
        .take(48)
        .collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tauri::command]
fn start_scan(
    app: AppHandle,
    state: State<AppState>,
    target: String,
    mode: String,
    depth: u32,
    cookie_jar: Option<String>,
    login_recipe: Option<String>,
    via_proxy: Option<bool>,
    cookie: Option<String>,
    seeds: Option<Vec<String>>,
) -> Result<String, String> {
    if mode != "static" && mode != "headless" {
        return Err("mode must be static or headless".into());
    }
    let sidecar = crawl_sidecar(&mode);
    if let Err(msg) = &sidecar {
        let id = format!("{}-{}", now_secs(), slug(&target));
        let _ = app.emit(
            "scan:error",
            serde_json::json!({"scan_id": id, "message": msg}),
        );
        return Err(msg.clone());
    }
    let (bin, prefix) = sidecar.unwrap();
    let dir = scans_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let id = format!("{}-{}", now_secs(), slug(&target));
    let out = dir.join(format!("{id}.json"));
    let args = crawl_args(
        &prefix,
        &target,
        &mode,
        depth,
        out.to_str().unwrap(),
        cookie_jar.as_deref(),
        login_recipe.as_deref(),
        via_proxy.unwrap_or(false),
        cookie.as_deref(),
        seeds.as_deref().unwrap_or(&[]),
    );
    let mut child = Command::new(&bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start sidecar {}: {e}", bin.display()))?;
    *state.scan_pid.lock().unwrap() = Some(child.id());
    let scan_id = id.clone();
    let out_path = out.display().to_string();
    let app_thread = app.clone();
    thread::spawn(move || {
        if let Some(stdout) = child.stdout.take() {
            for line in BufReader::new(stdout).lines().flatten() {
                if let Some((pages, url)) = parse_progress(&line) {
                    let _ = app_thread.emit(
                        "scan:progress",
                        serde_json::json!({
                            "scan_id": scan_id,
                            "pages_crawled": pages,
                            "current_url": url
                        }),
                    );
                }
            }
        }
        let status = child.wait();
        match status {
            Ok(st) if st.success() => {
                let _ = app_thread.emit(
                    "scan:complete",
                    serde_json::json!({"scan_id": scan_id, "output_path": out_path}),
                );
            }
            Ok(st) => {
                let _ = app_thread.emit(
                    "scan:error",
                    serde_json::json!({
                        "scan_id": scan_id,
                        "message": format!("sidecar exited {}", st)
                    }),
                );
            }
            Err(e) => {
                let _ = app_thread.emit(
                    "scan:error",
                    serde_json::json!({"scan_id": scan_id, "message": e.to_string()}),
                );
            }
        }
    });
    let _ = app.emit(
        "scan:progress",
        serde_json::json!({"scan_id": id, "pages_crawled": 0, "current_url": target}),
    );
    Ok(id)
}

#[tauri::command]
fn stop_scan(state: State<AppState>, _scan_id: String) -> Result<(), String> {
    if let Some(pid) = *state.scan_pid.lock().unwrap() {
        let _ = Command::new("kill").arg(pid.to_string()).status();
        *state.scan_pid.lock().unwrap() = None;
    }
    Ok(())
}

#[tauri::command]
fn list_scans() -> Result<Vec<ScanMeta>, String> {
    let dir = scans_dir();
    let mut out = vec![];
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.path().extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if let Ok(txt) = fs::read_to_string(e.path()) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                    out.push(ScanMeta {
                        id: e.path().file_stem().unwrap().to_string_lossy().into(),
                        target: v["target"].as_str().unwrap_or("").into(),
                        started_at: v["scan_started_at"].as_str().unwrap_or("").into(),
                        finished_at: v["scan_finished_at"].as_str().map(|s| s.to_string()),
                        finding_count: v["findings"].as_array().map(|a| a.len()).unwrap_or(0),
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    Ok(out)
}

#[tauri::command]
fn load_scan(scan_id: String) -> Result<serde_json::Value, String> {
    let p = scans_dir().join(format!("{scan_id}.json"));
    let txt = fs::read_to_string(p).map_err(|e| e.to_string())?;
    serde_json::from_str(&txt).map_err(|e| e.to_string())
}

#[tauri::command]
fn diff_scans(base_id: String, compare_id: String) -> Result<serde_json::Value, String> {
    let base = load_scan(base_id)?;
    let compare = load_scan(compare_id)?;
    let bf = base["findings"].as_array().cloned().unwrap_or_default();
    let cf = compare["findings"].as_array().cloned().unwrap_or_default();
    let key = |f: &serde_json::Value| {
        format!(
            "{}|{}",
            f["id"].as_str().unwrap_or(""),
            f["url"].as_str().unwrap_or("")
        )
    };
    let bset: std::collections::HashSet<_> = bf.iter().map(key).collect();
    let cset: std::collections::HashSet<_> = cf.iter().map(key).collect();
    let added: Vec<_> = cf
        .iter()
        .filter(|f| !bset.contains(&key(f)))
        .cloned()
        .collect();
    let resolved: Vec<_> = bf
        .iter()
        .filter(|f| !cset.contains(&key(f)))
        .cloned()
        .collect();
    Ok(serde_json::json!({"added": added, "resolved": resolved}))
}

#[tauri::command]
fn ingest_sessions(
    app: AppHandle,
    sessions: Vec<serde_json::Value>,
    target: String,
) -> Result<String, String> {
    if sessions.is_empty() {
        return Err("no sessions to ingest".into());
    }
    let dir = scans_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let id = format!("{}-{}", now_secs(), slug(&target));
    let jsonl = dir.join(format!("{id}.sessions.jsonl"));
    let out = dir.join(format!("{id}.json"));
    let mut body = String::new();
    for s in &sessions {
        body.push_str(&serde_json::to_string(s).map_err(|e| e.to_string())?);
        body.push('\n');
    }
    fs::write(&jsonl, body).map_err(|e| e.to_string())?;
    let bin = find_bin("go");
    if !bin.exists() {
        return Err(format!("sidecar missing: {}", bin.display()));
    }
    let output = Command::new(&bin)
        .args([
            "ingest-sessions",
            jsonl.to_str().unwrap(),
            "--target",
            &target,
            "--output",
            out.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        let msg = String::from_utf8_lossy(&output.stderr).to_string();
        let _ = app.emit(
            "scan:error",
            serde_json::json!({"scan_id": id, "message": msg}),
        );
        return Err(msg);
    }
    let _ = app.emit(
        "scan:complete",
        serde_json::json!({"scan_id": id, "output_path": out.display().to_string()}),
    );
    Ok(id)
}

#[tauri::command]
fn start_proxy(state: State<AppState>) -> Result<serde_json::Value, String> {
    let mut slot = state.proxy.lock().unwrap();
    if let Some(child) = slot.as_mut() {
        if child.try_wait().ok().flatten().is_none() {
            return Ok(serde_json::json!({"proxy": "127.0.0.1:8888", "control": "ws://127.0.0.1:8890/control", "already": true}));
        }
    }
    let bin = find_bin("proxy");
    if !bin.exists() {
        return Err(format!("sidecar missing: {}", bin.display()));
    }
    let child = Command::new(&bin)
        .args(["start", "--port", "8888", "--control-port", "8890"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start proxy sidecar: {e}"))?;
    *slot = Some(child);
    Ok(serde_json::json!({"proxy": "127.0.0.1:8888", "control": "ws://127.0.0.1:8890/control"}))
}

#[tauri::command]
fn stop_proxy(state: State<AppState>) -> Result<(), String> {
    let mut slot = state.proxy.lock().unwrap();
    if let Some(mut child) = slot.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

#[tauri::command]
fn install_ca(confirmed: bool) -> Result<String, String> {
    if !confirmed {
        return Err("CA install requires explicit confirmation".into());
    }
    let bin = find_bin("proxy");
    let gen = Command::new(&bin)
        .args(["ca", "generate"])
        .output()
        .map_err(|e| e.to_string())?;
    if !gen.status.success() && !String::from_utf8_lossy(&gen.stderr).contains("exists") {
        // generate is idempotent-ish; continue to export
    }
    let export_path = scans_dir()
        .parent()
        .unwrap_or(Path::new("/tmp"))
        .join("ca.pem");
    if let Some(parent) = export_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let out = Command::new(&bin)
        .args(["ca", "export", "--output", export_path.to_str().unwrap()])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into());
    }
    let _ = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            &format!(
                "{}/Library/Keychains/login.keychain-db",
                std::env::var("HOME").unwrap_or_default()
            ),
            export_path.to_str().unwrap(),
        ])
        .status();
    Ok(export_path.display().to_string())
}

#[tauri::command]
fn uninstall_ca(confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("CA uninstall requires explicit confirmation".into());
    }
    let bin = find_bin("proxy");
    let out = Command::new(&bin)
        .args(["ca", "uninstall", "--yes"])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into());
    }
    Ok(())
}

#[tauri::command]
fn export_ca(path: String) -> Result<String, String> {
    let bin = find_bin("proxy");
    let out = Command::new(&bin)
        .args(["ca", "export", "--output", &path])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into());
    }
    Ok(path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            start_scan,
            stop_scan,
            list_scans,
            load_scan,
            diff_scans,
            ingest_sessions,
            start_proxy,
            stop_proxy,
            install_ca,
            uninstall_ca,
            export_ca
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::{crawl_args, crawl_sidecar, is_python_bin, parse_progress};
    use std::path::Path;

    #[test]
    fn progress_line() {
        let (n, u) = parse_progress("PROGRESS pages=3 current=http://127.0.0.1/login").unwrap();
        assert_eq!(n, 3);
        assert_eq!(u, "http://127.0.0.1/login");
    }

    #[test]
    fn progress_rejects_noise() {
        assert!(parse_progress("{").is_none());
    }

    #[test]
    fn python_bin_name() {
        assert!(is_python_bin(Path::new("/opt/venv/bin/python3")));
        assert!(!is_python_bin(Path::new("/opt/shroodler")));
    }

    #[test]
    fn crawl_args_include_auth_files() {
        let args = crawl_args(
            &["-m".into(), "shroodler".into()],
            "http://127.0.0.1:8081",
            "headless",
            3,
            "/tmp/out.json",
            Some("/tmp/jar.json"),
            Some("/tmp/login.json"),
            true,
            Some("sid=abc"),
            &["http://127.0.0.1:8081/hidden".into()],
        );
        assert_eq!(args[0], "-m");
        assert!(args.contains(&"--mode".into()) && args.contains(&"headless".into()));
        assert!(args.contains(&"--cookie-jar".into()));
        assert!(args.contains(&"--login-recipe".into()));
        assert!(args.contains(&"--proxy".into()));
        assert!(args.contains(&"--cookie".into()));
        assert!(args.contains(&"--seed".into()));
    }

    #[test]
    fn headless_sidecar_is_python_or_go() {
        let (bin, prefix) = crawl_sidecar("headless").expect("a headless sidecar");
        let name = bin.file_name().unwrap().to_string_lossy();
        if name.starts_with("python") {
            assert_eq!(prefix, vec!["-m".to_string(), "shroodler".to_string()]);
        } else {
            assert!(prefix.is_empty());
            assert!(name.contains("shroodler"));
        }
    }
}
