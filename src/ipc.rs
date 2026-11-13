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
use crate::lock::SessionLock;
use crate::workspace::{Workspace, LOCK_FILE, RUNTIME_FILE};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// A session that does not answer a ping within this time is not listed as
/// running.
const PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Connection details of the live session in `dir`, if `session.lock` is
/// currently held and `runtime.json` is readable.
///
/// Checking `SessionLock::is_held` before trusting `runtime.json` ensures a
/// stale file left behind by `SIGKILL` never causes helpers or the HUD to
/// transmit the bearer token to an unrelated process on a reused port.
pub fn runtime_info_in(dir: &Path) -> Option<RuntimeInfo> {
    let info = RuntimeInfo::read(&dir.join(RUNTIME_FILE))?;
    SessionLock::is_held(&dir.join(LOCK_FILE)).then_some(info)
}

/// Connection details of the session that owns `workspace`, if its
/// `session.lock` is held and `runtime.json` is readable.
pub fn runtime_info(workspace: &Workspace) -> Option<RuntimeInfo> {
    runtime_info_in(&workspace.dir)
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy() // loopback only; never through a system proxy
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("cannot create the HTTP client")
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
        let Ok(body) = response.json::<Value>().await else {
            return Ok(None);
        };
        if body.get("ok").and_then(Value::as_bool) != Some(false) {
            return Ok(None);
        }
        return Err(anyhow!("{}", error_message(&body)));
    }
    let body: Value = response
        .json()
        .await
        .context("the session coordinator sent an invalid reply")?;
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
}
