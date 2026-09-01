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
    } else {
        p.push("proxy-go");
        p.push("shroodler-proxy");
    }
    p
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
) -> Result<String, String> {
    if mode == "headless" {
        let id = format!("{}-{}", now_secs(), slug(&target));
        let _ = app.emit(
            "scan:error",
            serde_json::json!({
                "scan_id": id,
                "message": "headless mode is Python-only; the desktop sidecar is shroodler-go (static)"
            }),
        );
        return Err("headless mode is Python-only".into());
    }
    let dir = scans_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let id = format!("{}-{}", now_secs(), slug(&target));
    let out = dir.join(format!("{id}.json"));
    let bin = find_bin("go");
    if !bin.exists() {
        let msg = format!("sidecar missing: {}", bin.display());
        let _ = app.emit(
            "scan:error",
            serde_json::json!({"scan_id": id, "message": msg}),
        );
        return Err(msg);
    }
    let mut child = Command::new(&bin)
        .args([
            "crawl",
            &target,
            "--mode",
            "static",
            "--depth",
            &depth.to_string(),
            "--output",
            out.to_str().unwrap(),
        ])
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
    use super::parse_progress;

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
}
