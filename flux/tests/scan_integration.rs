//! `--daemon` `scan` jobs: per-`moof` sample-encryption census without decrypting

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

struct Daemon {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::io::Lines<BufReader<std::process::ChildStdout>>,
}

impl Daemon {
    fn spawn() -> Self {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_flux"))
            .arg("--daemon")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn flux daemon");
        let stdin = child.stdin.take().expect("daemon stdin");
        let stdout = child.stdout.take().expect("daemon stdout");
        Daemon {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
        }
    }

    fn scan(&mut self, input: &Path) -> serde_json::Value {
        let job = serde_json::json!({"scan": input.to_string_lossy()}).to_string();
        writeln!(self.stdin, "{job}").expect("daemon stdin write");
        let line = self.lines.next().expect("daemon stdout EOF").expect("daemon stdout read");
        serde_json::from_str(&line).expect("daemon scan response must be valid JSON")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "--quit");
        let _ = self.child.wait();
    }
}

#[test]
fn scan_reports_senc_fragments_without_moov_or_keys() {
    let mut daemon = Daemon::spawn();
    let report = daemon.scan(&fixture("cenc_audio.mp4"));
    assert_eq!(report["ok"], true, "scan must succeed: {report}");
    let tracks = report["tracks"].as_array().expect("tracks array");
    assert_eq!(tracks.len(), 1);
    let enc = tracks[0]["encrypted_fragments"].as_u64().expect("u64");
    let clear = tracks[0]["clear_fragments"].as_u64().expect("u64");
    assert!(enc > 0, "every fragment carries senc: {report}");
    assert_eq!(clear, 0);
    assert!(report["scan_cut"].as_u64().is_some(), "cut must exist: {report}");
}

#[test]
fn scan_reports_saiz_saio_and_piff_uuid_styles() {
    let mut daemon = Daemon::spawn();
    let report = daemon.scan(&fixture("piff_uuid_senc.mp4"));
    assert_eq!(report["ok"], true, "scan must succeed: {report}");
    let tracks = report["tracks"].as_array().expect("tracks array");
    assert!(!tracks.is_empty(), "at least one track: {report}");
    let enc: u64 = tracks.iter().map(|t| t["encrypted_fragments"].as_u64().unwrap_or(0)).sum();
    assert!(enc > 0, "piff uuid fragments must report encrypted: {report}");

    let report = daemon.scan(&fixture("enc_saiz_saio.mp4"));
    assert_eq!(report["ok"], true, "scan must succeed: {report}");
    assert!(
        report["tracks"].as_array().expect("tracks array").is_empty(),
        "progressive input has no moof: {report}"
    );
}

#[test]
fn scan_reports_empty_tracks_for_inputs_without_moof() {
    let mut daemon = Daemon::spawn();
    let report = daemon.scan(&fixture("video_edit_list.mp4"));
    assert_eq!(report["ok"], true, "scan must succeed: {report}");
    let tracks = report["tracks"].as_array().expect("tracks array");
    assert!(tracks.is_empty(), "no moof => no tracks: {report}");
    assert!(report["scan_cut"].as_u64().is_none());
}

#[test]
fn scan_fails_cleanly_on_missing_file() {
    let mut daemon = Daemon::spawn();
    let report = daemon.scan(Path::new("definitely-not-here-12345.mp4"));
    assert_eq!(report["ok"], false);
    assert!(report["error"].as_str().is_some());
}

#[test]
fn decrypt_jobs_still_work_after_scan_jobs() {
    let mut daemon = Daemon::spawn();
    let scan_report = daemon.scan(&fixture("cenc_audio.mp4"));
    assert_eq!(scan_report["ok"], true);
    let out = std::env::temp_dir().join(format!(
        "flux-test-scan-then-decrypt-{}.mp4",
        std::process::id()
    ));
    let job = serde_json::json!({
        "input": fixture("cenc_audio.mp4").to_string_lossy(),
        "output": out.to_string_lossy(),
        "keys": ["f8c80c25690f47368132430e5c6994ce:7bc99cb1dd0623cd0b5065056a57a1dd"],
    })
    .to_string();
    writeln!(daemon.stdin, "{job}").expect("daemon stdin write");
    let line = daemon.lines.next().expect("daemon stdout EOF").expect("daemon stdout read");
    let decrypt_report: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
    std::fs::remove_file(&out).ok();
    assert_eq!(decrypt_report["ok"], true, "decrypt after scan must succeed: {decrypt_report}");
}
