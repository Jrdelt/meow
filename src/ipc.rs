//! Client side of the coordinator API, used by helper subcommands.
//!
//! A helper first tries the live session (`runtime.json` + bearer token over
//! loopback HTTP). When there is none it gets `None` back and falls back to
//! working on the workspace files directly.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::StatusCode;
use serde_json::Value;

use crate::coordinator::{Command, RuntimeInfo};
use crate::evidence::sanitize;
use crate::lock::{LockError, SessionLock};
use crate::workspace::{Workspace, LOCK_FILE, RUNTIME_FILE};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// A session that does not answer a ping within this time is not listed as
/// running.
const PING_TIMEOUT: Duration = Duration::from_secs(2);

const ERROR_REPLY_MAX_BYTES: usize = 64 * 1024;
const REPLY_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Connection details of the live session in `dir`, if `session.lock` is
/// currently held and `runtime.json` is readable and was written by the
/// process that holds the lock.
///
/// Checking `SessionLock::check_free` before trusting `runtime.json` ensures a
/// stale file left behind by `SIGKILL` never causes helpers or the HUD to
/// transmit the bearer token to an unrelated process on a reused port. The
/// process id is compared as well: a session that is still starting holds
/// the lock before it has replaced the file of the session before it.
pub fn runtime_info_in(dir: &Path) -> Option<RuntimeInfo> {
    let info = RuntimeInfo::read(&dir.join(RUNTIME_FILE))?;
    match SessionLock::check_free(&dir.join(LOCK_FILE)) {
        Err(LockError::Held { pid: Some(holder) }) => (holder == info.pid).then_some(info),
        _ => None,
    }
}

/// Connection details of the session that owns `workspace`, if its
/// `session.lock` is held and `runtime.json` is readable.
pub fn runtime_info(workspace: &Workspace) -> Option<RuntimeInfo> {
    runtime_info_in(&workspace.dir)
}

fn client() -> Result<&'static reqwest::Client> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    if let Some(http) = CLIENT.get() {
        return Ok(http);
    }
    let built = reqwest::Client::builder()
        .no_proxy() // loopback only; never through a system proxy
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("cannot create the HTTP client")?;
    let _ = CLIENT.set(built);
    CLIENT.get().context("cannot create the HTTP client")
}

async fn read_json_bounded(mut response: reqwest::Response, max_bytes: usize) -> Result<Value> {
    if response
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        anyhow::bail!("the session coordinator sent an oversized reply");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("the session coordinator reply was cut off")?
    {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            anyhow::bail!("the session coordinator sent an oversized reply");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("the session coordinator sent an invalid reply")
}

fn error_message(body: &Value) -> String {
    body.get("error")
        .and_then(Value::as_str)
        .map(|err| sanitize(err, 500))
        .filter(|err| !err.is_empty())
        .unwrap_or_else(|| "the session coordinator refused the request".to_owned())
}

/// Sends `command` to a live coordinator described by `info`.
/// `Ok(None)` means nothing (or an unrelated service on a reused port) is
/// listening there.
pub async fn send_to(info: &RuntimeInfo, command: &Command) -> Result<Option<Value>> {
    let response = client()?
        .post(format!("{}/api/command", info.base_url()))
        .bearer_auth(&info.token)
        .json(command)
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) if error.is_connect() => return Ok(None),
        Err(error) => return Err(error).context("cannot reach the session coordinator"),
    };
    let status = response.status();
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        return Err(anyhow!(
            "the request is too large for the session coordinator"
        ));
    }
    if status != StatusCode::OK && status != StatusCode::BAD_REQUEST {
        // Another process reuses the port of a session that is gone.
        return Ok(None);
    }
    if status == StatusCode::BAD_REQUEST {
        let Ok(body) = read_json_bounded(response, ERROR_REPLY_MAX_BYTES).await else {
            return Ok(None);
        };
        if body.get("ok").and_then(Value::as_bool) != Some(false) {
            return Ok(None);
        }
        return Err(anyhow!("{}", error_message(&body)));
    }
    let body = read_json_bounded(response, REPLY_MAX_BYTES).await?;
    if body.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(Some(body.get("result").cloned().unwrap_or(Value::Null)));
    }
    Err(anyhow!("{}", error_message(&body)))
}

/// Sends `command` to the session that owns `workspace`, if one is live.
pub fn send(workspace: &Workspace, command: &Command) -> Result<Option<Value>> {
    let Some(info) = runtime_info(workspace) else {
        return Ok(None);
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?
        .block_on(send_to(&info, command))
}

/// True when a session is open on the workspace in `dir` and answers. Only
/// reads: a `runtime.json` left behind by a crashed session counts as closed.
pub fn is_live(dir: &Path) -> bool {
    let Some(info) = runtime_info_in(dir) else {
        return false;
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    runtime.block_on(async {
        let ping = send_to(&info, &Command::Ping);
        matches!(
            tokio::time::timeout(PING_TIMEOUT, ping).await,
            Ok(Ok(Some(_)))
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::Mode;
    use crate::workspace::MeowHome;
    use axum::extract::State as AxumState;
    use axum::http::HeaderMap;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn stale_runtime_file_never_contacts_listener_or_leaks_bearer_token() {
        let hits = Arc::new(AtomicUsize::new(0));
        let leaked = Arc::new(Mutex::new(Vec::<String>::new()));
        let hits_srv = Arc::clone(&hits);
        let leaked_srv = Arc::clone(&leaked);
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let app = Router::new().route(
                    "/api/command",
                    post(move |headers: HeaderMap| {
                        let hits_srv = Arc::clone(&hits_srv);
                        let leaked_srv = Arc::clone(&leaked_srv);
                        async move {
                            hits_srv.fetch_add(1, Ordering::SeqCst);
                            if let Some(auth) = headers.get("authorization") {
                                leaked_srv
                                    .lock()
                                    .unwrap()
                                    .push(auth.to_str().unwrap_or_default().to_owned());
                            }
                            (StatusCode::NOT_FOUND, "not meow")
                        }
                    }),
                );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap().port()).unwrap();
                let _ = axum::serve(listener, app).await;
            });
        });
        let port = rx.recv().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        // Leftover files from a SIGKILLed session: PID in session.lock, but no
        // live kernel lock held on it.
        std::fs::write(workspace.lock_path(), "99999\n").unwrap();
        let secret_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(
            workspace.runtime_path(),
            serde_json::to_vec(&RuntimeInfo {
                pid: 99999,
                port,
                token: secret_token.to_owned(),
            })
            .unwrap(),
        )
        .unwrap();

        assert_eq!(runtime_info(&workspace), None);
        assert_eq!(send(&workspace, &Command::Ping).unwrap(), None);
        assert!(!is_live(&workspace.dir));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "foreign listener must never be contacted when session.lock is not held"
        );
        assert!(leaked.lock().unwrap().is_empty());
    }

    /// A listener that counts requests to `/api/command` and answers like
    /// some other program.
    #[cfg(unix)]
    fn counting_listener() -> (u16, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let app = Router::new().route(
                    "/api/command",
                    post(move || {
                        let hits_srv = Arc::clone(&hits_srv);
                        async move {
                            hits_srv.fetch_add(1, Ordering::SeqCst);
                            (StatusCode::NOT_FOUND, "not meow")
                        }
                    }),
                );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap().port()).unwrap();
                let _ = axum::serve(listener, app).await;
            });
        });
        (rx.recv().unwrap(), hits)
    }

    #[cfg(unix)]
    #[test]
    fn a_starting_session_does_not_vouch_for_the_runtime_file_of_the_one_before() {
        let (port, hits) = counting_listener();
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        // The session before was killed: its runtime.json is still there.
        // A new session holds the lock and has not written its own yet.
        std::fs::write(
            workspace.runtime_path(),
            serde_json::to_vec(&RuntimeInfo {
                pid: std::process::id() + 1,
                port,
                token: "0123456789abcdef".repeat(4),
            })
            .unwrap(),
        )
        .unwrap();
        let _held = SessionLock::acquire(&workspace.lock_path()).unwrap();

        assert_eq!(runtime_info(&workspace), None);
        assert_eq!(send(&workspace, &Command::Ping).unwrap(), None);
        assert!(!is_live(&workspace.dir));
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // Its own file is trusted.
        let own = RuntimeInfo {
            pid: std::process::id(),
            port,
            token: "0123456789abcdef".repeat(4),
        };
        std::fs::write(workspace.runtime_path(), serde_json::to_vec(&own).unwrap()).unwrap();
        assert_eq!(runtime_info(&workspace), Some(own));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_pipe_or_huge_file_as_runtime_file_or_lock_is_no_session() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let runtime = dir.join(RUNTIME_FILE);

        // A link to a file that never ends.
        std::os::unix::fs::symlink("/dev/zero", &runtime).unwrap();
        assert_eq!(RuntimeInfo::read(&runtime), None);
        assert!(!is_live(dir));
        std::fs::remove_file(&runtime).unwrap();

        // A link to a real runtime file elsewhere.
        let elsewhere = dir.join("elsewhere.json");
        let info = RuntimeInfo {
            pid: std::process::id(),
            port: 9,
            token: "0123456789abcdef".repeat(4),
        };
        std::fs::write(&elsewhere, serde_json::to_vec(&info).unwrap()).unwrap();
        assert_eq!(RuntimeInfo::read(&elsewhere), Some(info.clone()));
        std::os::unix::fs::symlink(&elsewhere, &runtime).unwrap();
        assert_eq!(RuntimeInfo::read(&runtime), None);
        std::fs::remove_file(&runtime).unwrap();

        // A regular file far larger than meow writes.
        let mut big = serde_json::to_vec(&info).unwrap();
        big.resize(1024 * 1024, b' ');
        std::fs::write(&runtime, &big).unwrap();
        assert_eq!(RuntimeInfo::read(&runtime), None);
        std::fs::remove_file(&runtime).unwrap();

        // A pipe nobody writes to, as the runtime file and as the lock:
        // neither read waits.
        let pipe = std::ffi::CString::new(runtime.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
        assert_eq!(RuntimeInfo::read(&runtime), None);
        std::fs::remove_file(&runtime).unwrap();
        std::fs::write(&runtime, serde_json::to_vec(&info).unwrap()).unwrap();
        let lock = dir.join(LOCK_FILE);
        let pipe = std::ffi::CString::new(lock.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
        assert!(!SessionLock::is_held(&lock));
        assert_eq!(runtime_info_in(dir), None);
    }

    #[test]
    fn reused_port_non_json_responses_fall_back_to_none() {
        let mode = Arc::new(AtomicUsize::new(0));
        let mode_srv = Arc::clone(&mode);
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let app = Router::new()
                    .route(
                        "/api/command",
                        post(|AxumState(step): AxumState<Arc<AtomicUsize>>| async move {
                            match step.load(Ordering::SeqCst) {
                                0 => (StatusCode::UNAUTHORIZED, "401 Unauthorized").into_response(),
                                1 => (StatusCode::NOT_FOUND, "<html>404</html>").into_response(),
                                2 => (StatusCode::METHOD_NOT_ALLOWED, "405").into_response(),
                                3 => (
                                    StatusCode::FOUND,
                                    [("Location", "http://192.0.2.1/steal")],
                                    "",
                                )
                                    .into_response(),
                                4 => (StatusCode::BAD_REQUEST, "plain 400").into_response(),
                                _ => (
                                    StatusCode::BAD_REQUEST,
                                    Json(json!({
                                        "ok": false,
                                        "error": "recon is disabled\u{001b}[31m in light mode"
                                    })),
                                )
                                    .into_response(),
                            }
                        }),
                    )
                    .with_state(mode_srv);
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap().port()).unwrap();
                let _ = axum::serve(listener, app).await;
            });
        });
        let port = rx.recv().unwrap();
        let info = RuntimeInfo {
            pid: 1,
            port,
            token: "tok".to_owned(),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for step in 0..=4 {
            mode.store(step, Ordering::SeqCst);
            let reply = rt.block_on(send_to(&info, &Command::Ping)).unwrap();
            assert_eq!(reply, None, "step {step} should fall back cleanly to None");
        }

        mode.store(5, Ordering::SeqCst);
        let err = rt
            .block_on(send_to(&info, &Command::Ping))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "recon is disabled[31m in light mode");
    }

    #[test]
    fn oversized_ipc_replies_are_refused_without_unbounded_reads() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            for step in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                if step == 0 {
                    let body = "x".repeat(ERROR_REPLY_MAX_BYTES + 1024);
                    let head = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body.as_bytes());
                } else {
                    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000000\r\nConnection: close\r\n\r\n{}";
                    let _ = stream.write_all(head.as_bytes());
                }
                let _ = stream.flush();
            }
        });
        let info = RuntimeInfo {
            pid: 1,
            port,
            token: "tok".to_owned(),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // Oversized 400 body from a foreign listener falls back to None cleanly.
        assert_eq!(rt.block_on(send_to(&info, &Command::Ping)).unwrap(), None);

        // Oversized Content-Length on 200 OK is rejected immediately without reading 100 MB.
        let err = rt.block_on(send_to(&info, &Command::Ping)).unwrap_err();
        assert!(format!("{err:#}").contains("oversized reply"), "{err:#}");
        handle.join().unwrap();
    }
}
