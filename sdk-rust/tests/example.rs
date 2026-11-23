//! An example plugin using every helper, run against rpt built from this repository. Outside
//! it (the crate on its own, or without Go) these tests skip.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use rpt_sdk::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// rpt built for these tests, once; `None` when it can't be.
fn rpt() -> Option<&'static Path> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        if !repo().join("cmd/rpt").exists() {
            return None;
        }
        let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rpt");
        let built = Process::new("go")
            .args(["build", "-o"])
            .arg(&out)
            .arg("./cmd/rpt")
            .current_dir(repo())
            .env("GOWORK", "")
            .status();
        match built {
            Ok(s) if s.success() => Some(out),
            Ok(s) => panic!("go build rpt: {s}"),
            Err(_) => None, // no Go
        }
    })
    .as_deref()
}

/// The environment is the process's: one test at a time sets it.
static ENV: Mutex<()> = Mutex::new(());

/// A copy of the fixture report, with `RPT_BIN` and `RPT_REPORT_DIR` set as rpt would; `None`
/// when there is no rpt to test against.
fn report(name: &str) -> Option<(PathBuf, std::sync::MutexGuard<'static, ()>)> {
    let Some(bin) = rpt() else {
        eprintln!("skipped: needs the rpt repository and Go");
        return None;
    };
    let guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&repo().join("testdata/fixture"), &dir);
    // SAFETY: tests that touch the environment hold ENV, so nothing reads it meanwhile.
    unsafe {
        std::env::set_var("RPT_BIN", bin);
        std::env::set_var("RPT_REPORT_DIR", &dir);
    }
    Some((dir, guard))
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TagSettings {
    label: String,
}

/// Tags each finding record on stdin with `x-tag-label`, from its settings (default
/// `triaged`), and ends with a warning counting the report's scope rows.
fn tag_plugin() -> Plugin {
    let mut schemas = Schemas::default();
    schemas.finding.insert("x-tag-label".into(), json!({"type": "string"}));
    Plugin::new(
        Description {
            summary: "Tag findings with a label".into(),
            usage: "rpt tag < findings.jsonl".into(),
            input: "records".into(),
            output: "records".into(),
            roles: vec![role::FILTER.into()],
            requires: Some(Requires {
                schema_version: Some(Range { min: 2, ..Default::default() }),
                ..Default::default()
            }),
            schemas: Some(schemas),
            ..Default::default()
        },
        |_args, stdin, stdout, stderr| {
            let settings = match settings("tag", TagSettings { label: "triaged".into() }) {
                Ok(s) => s,
                Err(e) => {
                    let _ = writeln!(stderr, "rpt-tag: {e}");
                    return 1;
                }
            };
            for item in records(stdin).stop_at_error() {
                let rec = match item {
                    Ok(rec) => rec,
                    Err(ReadError::Stopped(rec)) => {
                        let _ = writeln!(stdout, "{}", rec.raw); // pass it on; write nothing of our own
                        return 1;
                    }
                    Err(e) => {
                        let _ = writeln!(stderr, "rpt-tag: {e}");
                        return 1;
                    }
                };
                let mut line = rec.raw;
                if rec.kind == kind::FINDING {
                    line = set_member(&line, "x-tag-label", &settings.label).unwrap();
                }
                let _ = writeln!(stdout, "{line}");
            }
            let out = match Call::new(["scope", "get"]).timeout(Duration::from_secs(30)).run() {
                Ok(out) if out.code == 0 => out,
                Ok(out) => {
                    let _ = writeln!(stderr, "rpt-tag: {}", out.stderr);
                    return 1;
                }
                Err(e) => {
                    let _ = writeln!(stderr, "rpt-tag: {e}");
                    return 1;
                }
            };
            let problem = Problem {
                path: ".".into(),
                rule: "tag".into(),
                level: level::WARNING.into(),
                message: format!("{} scope rows", out.records.len()),
                ..Default::default()
            };
            emit(stdout, &problem).map_or(1, |_| 0)
        },
    )
}

fn run_tag(stdin: &str) -> (i32, String, String) {
    let (mut out, mut err) = (vec![], vec![]);
    let code = run(&tag_plugin(), &[] as &[OsString], &mut stdin.as_bytes(), &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

#[test]
fn example_plugin() {
    let Some((dir, _env)) = report("example") else { return };
    let set = Process::new(rpt().unwrap())
        .args(["--report"])
        .arg(&dir)
        .args(["config", "set", "x-tag.label", "verified"])
        .output()
        .unwrap();
    assert!(set.status.success(), "{set:?}");
    let (code, out, err) = run_tag("{\"kind\":\"finding\",\"id\":\"F-001\"}\n{\"kind\":\"note\"}\n");
    let want = "{\"kind\":\"finding\",\"id\":\"F-001\",\"x-tag-label\":\"verified\"}\n{\"kind\":\"note\"}\n\
                {\"kind\":\"problem\",\"path\":\".\",\"rule\":\"tag\",\"level\":\"warning\",\"message\":\"3 scope rows\"}\n";
    assert_eq!((code, out.as_str()), (0, want), "stderr {err}");
}

#[test]
fn example_plugin_stops_at_an_error() {
    let Some(_report) = report("stops") else { return };
    let first = "{\"kind\":\"problem\",\"path\":\"x\",\"rule\":\"r\",\"level\":\"error\",\"message\":\"m\"}\n";
    let (code, out, _) = run_tag(&format!("{first}{{\"kind\":\"finding\",\"id\":\"F-001\"}}\n"));
    assert_eq!((code, out.as_str()), (1, first));
}

#[test]
fn null_settings_keep_the_defaults() {
    let Some((dir, _env)) = report("null-settings") else { return };
    let set = Process::new(rpt().unwrap()).arg("--report").arg(&dir).args(["config", "set", "x-tag", "null"]).output();
    assert!(set.unwrap().status.success());
    let (_, out, err) = run_tag("{\"kind\":\"finding\",\"id\":\"F-001\"}\n");
    assert!(out.contains("\"x-tag-label\":\"triaged\""), "stdout {out}, stderr {err}");
}

#[test]
fn call_stale() {
    let Some(_report) = report("stale") else { return };
    let out = Call::new(["finding", "set", "--if-rev", "0000", "F-001", "title", "New"]).run().unwrap();
    assert_eq!((out.code, out.stale(), out.problems().len()), (1, true, 1), "{out:?}");
}

#[test]
fn call_feeds_stdin() {
    let Some(_report) = report("call") else { return };
    let out = Call::new(["validate", "-"]).stdin("{\"kind\":\"note\"}\n").run().unwrap();
    assert_eq!((out.code, out.records.len()), (0, 1), "{out:?}");
}

#[test]
fn call_times_out() {
    let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let hang = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rpt-hang");
    std::fs::write(&hang, "#!/bin/sh\nexec sleep 30\n").unwrap();
    std::fs::set_permissions(&hang, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    // SAFETY: tests that touch the environment hold ENV.
    unsafe { std::env::set_var("RPT_BIN", &hang) };
    let started = std::time::Instant::now();
    let got = Call::new(["scope", "get"]).timeout(Duration::from_millis(200)).run();
    assert!(matches!(got, Err(Error::TimedOut { .. })), "{got:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn range_display() {
    let r = |min, max| Range { min, max, ..Default::default() };
    let got: Vec<String> = [r(0, 0), r(2, 0), r(0, 1), r(2, 2), r(2, 3)].iter().map(ToString::to_string).collect();
    assert_eq!(got, ["any", "2 or later", "up to 1", "2", "2 to 3"]);
    assert!(Requires::default().fits(3, 2));
    let req = Requires { format: Some(r(1, 1)), ..Default::default() };
    assert!(!req.fits(3, 2));
}

/// A shell script standing in for rpt, at a path of its own.
fn stand_in(name: &str, body: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("rpt");
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    p
}

/// The pid the stand-in wrote to `file`.
fn pid_in(file: &Path) -> String {
    for _ in 0..200 {
        let pid = std::fs::read_to_string(file).unwrap_or_default();
        if !pid.trim().is_empty() {
            return pid.trim().to_string();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the stand-in never wrote its child's pid");
}

fn alive(pid: &str) -> bool {
    Process::new("kill").args(["-0", pid]).status().is_ok_and(|s| s.success())
}

#[test]
fn call_runs_the_rpt_it_is_given() {
    let bin =
        stand_in("env", r#"printf '{"kind":"x-env","dir":"%s","x":"%s","home":"%s"}\n' "$(pwd)" "$X" "${HOME-unset}""#);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("env-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let out =
        Call::new(Vec::<String>::new()).bin(&bin).current_dir(&dir).env("X", "1").env_remove("HOME").run().unwrap();
    let want = format!(r#"{{"kind":"x-env","dir":"{}","x":"1","home":"unset"}}"#, dir.display());
    assert_eq!(out.records.iter().map(|r| r.raw.as_str()).collect::<Vec<_>>(), [want.as_str()]);
}

#[test]
fn process_group_kills_what_rpt_started() {
    let pids = Path::new(env!("CARGO_TARGET_TMPDIR")).join("group.pid");
    let _ = std::fs::remove_file(&pids);
    let bin = stand_in("group", &format!("sleep 30 &\necho $! > {}\nwait", pids.display()));
    let started = std::time::Instant::now();
    let got = Call::new(["scope", "get"]).bin(&bin).process_group().timeout(Duration::from_millis(300)).run();
    assert!(matches!(got, Err(Error::TimedOut { .. })), "{got:?}");
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    let pid = pid_in(&pids);
    let gone = (0..200).any(|_| {
        std::thread::sleep(Duration::from_millis(10));
        !alive(&pid)
    });
    assert!(gone, "the plugin's child outlived the call");
}

#[test]
fn call_returns_when_something_rpt_started_holds_the_pipes() {
    let pids = Path::new(env!("CARGO_TARGET_TMPDIR")).join("pipes.pid");
    let _ = std::fs::remove_file(&pids);
    let bin = stand_in("pipes", &format!("sleep 30 &\necho $! > {}\necho '{{\"kind\":\"x\"}}'", pids.display()));
    let started = std::time::Instant::now();
    let out = Call::new(Vec::<String>::new()).bin(&bin).run().unwrap();
    let _ = Process::new("kill").args(["-9", &pid_in(&pids)]).status();
    assert_eq!((out.code, out.records.len()), (0, 1), "{out:?}");
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}
