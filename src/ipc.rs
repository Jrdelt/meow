//! Client side of the coordinator API, used by helper subcommands.
//!
//! A helper first tries the live session (`runtime.json` + bearer token over
//! loopback HTTP). When there is none it gets `None` back and falls back to
//! working on the workspace files directly.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

use crate::coordinator::{Command, RuntimeInfo};
use crate::workspace::Workspace;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Connection details of the session that owns `workspace`, if its
/// `runtime.json` exists. The session may still be gone (stale file).
pub fn runtime_info(workspace: &Workspace) -> Option<RuntimeInfo> {
    RuntimeInfo::read(&workspace.runtime_path())
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy() // loopback only; never through a system proxy
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("cannot create the HTTP client")
}

/// Sends `command` to a live coordinator described by `info`.
/// `Ok(None)` means nothing is listening there.
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
    let body: Value = response
        .json()
        .await
        .context("the session coordinator sent an invalid reply")?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        // Another process reuses the port of a session that is gone.
        return Ok(None);
    }
    if body.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(Some(body.get("result").cloned().unwrap_or(Value::Null)));
    }
    Err(anyhow!(
        "{}",
        body.get("error")
            .and_then(Value::as_str)
            .unwrap_or("the session coordinator refused the request")
    ))
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
