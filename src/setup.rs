//! `meow setup`: each user's own AI for meow.
//!
//! meow is a shared tool, so nothing about a particular user's AI is built
//! in: no key, no model server. This command lets everyone point it at their
//! own local model server, or add their own cloud API key, and keeps that in
//! `~/.meow/ai.toml`, which only they can read and which is never part of a
//! repository. A running session uses the new setup for its next request.
//!
//! With flags it is scriptable; without any, on a terminal, it asks.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::ai::{AiOverrides, AiSettings, CloudProvider};
use crate::anthropic;
use crate::workspace::{Config, MeowHome};

/// Where model servers usually listen on the machine they run on.
pub(crate) const LOCAL_SERVERS: &[(&str, &str)] = &[
    ("http://localhost:1234/v1", "LM Studio"),
    ("http://localhost:11434/v1", "Ollama"),
    ("http://localhost:8080/v1", "llama.cpp"),
];
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_INPUT_BYTES: u64 = 4096;
const MAX_SECRET_CHARS: usize = 4096;
/// More models than any server offers; the rest of a list is not read.
const MAX_MODELS: usize = 500;

/// Said when Ctrl+V is pressed at a key prompt: terminals paste with other
/// keys, and Ctrl+V itself would only add a "v".
pub const PASTE_HINT: &str = if cfg!(target_os = "macos") {
    "Ctrl+V does not paste here: use Cmd+V"
} else {
    "Ctrl+V does not paste here: use Ctrl+Shift+V or right-click"
};

/// What a cloud AI service without a key means, where its key would stand.
pub(crate) const KEY_MISSING: &str = "missing · local AI answers instead";

/// What `meow setup` was asked to do without asking questions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupArgs {
    pub show: bool,
    pub check: bool,
    /// Use the plain line-mode prompt instead of the full-screen Cat TUI.
    pub plain: bool,
    pub local_url: Option<String>,
    pub local_model: Option<String>,
    pub cloud_url: Option<String>,
    pub cloud_model: Option<String>,
    pub research_model: Option<String>,
    /// `claude` (the Claude API with a Claude key) or `openrouter`.
    pub provider: Option<String>,
    /// Claude API only: the models asked next when one declines, comma
    /// separated and in order. Empty leaves the choice to the API.
    pub fallback_models: Option<String>,
    /// Read the API key from standard input. It is never taken from the
    /// command line, where it would end up in the shell history.
    pub api_key_stdin: bool,
    pub forget_key: bool,
    /// Cloud AI off: local AI only, also with a key in the environment.
    /// The stored key is removed.
    pub cloud_off: bool,
}

impl SetupArgs {
    fn changes_something(&self) -> bool {
        self.api_key_stdin
            || self.forget_key
            || self.cloud_off
            || [
                &self.local_url,
                &self.local_model,
                &self.cloud_url,
                &self.cloud_model,
                &self.research_model,
                &self.provider,
                &self.fallback_models,
            ]
            .iter()
            .any(|value| value.is_some())
    }
}

/// A loopback `http://` or `https://` address of a local OpenAI-compatible
/// API, without a trailing slash.
pub(crate) fn checked_url(raw: &str) -> Result<String> {
    crate::ai::validate_local_url(raw)
}

/// A key is shown by its last four characters only.
pub(crate) fn masked(key: &str) -> String {
    let tail: String = key
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let safe_tail = crate::evidence::sanitize(&tail, 16);
    match key.chars().count() {
        0..=8 => "set".to_owned(),
        _ => format!("set, ends in {safe_tail}"),
    }
}

/// Where a key comes from, in a word or two: `in ai.toml`, `in config.toml`
/// or `from $VARIABLE` (as [`AiSettings::key_source`] names them, shorter).
pub(crate) fn key_origin(source: &str) -> String {
    let variable = source
        .strip_prefix("the ")
        .and_then(|rest| rest.strip_suffix(" environment variable"));
    match (source, variable) {
        ("your setup file", _) => "in ai.toml".to_owned(),
        (_, Some(variable)) => format!("from ${variable}"),
        _ => format!("in {source}"),
    }
}

/// The host a URL names, in lower case; empty if it names none.
pub(crate) fn url_host(url: &str) -> String {
    url::Url::parse(url.trim())
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default()
}

/// The service a key was made for, by its prefix: `sk-ant-` keys are the
/// Claude API's, `sk-or-` keys OpenRouter's. Other keys do not say.
pub(crate) fn key_service(key: &str) -> Option<(CloudProvider, &'static str)> {
    let key = key.trim();
    if key.starts_with("sk-ant-") {
        Some((CloudProvider::Anthropic, "api.anthropic.com"))
    } else if key.starts_with("sk-or-") {
        Some((CloudProvider::OpenAi, "openrouter.ai"))
    } else {
        None
    }
}

/// The hosts of the services [`key_service`] knows keys of.
const KEY_HOSTS: [&str; 2] = ["api.anthropic.com", "openrouter.ai"];

/// Whether `key` may be sent to `url`: a key made for one of the services
/// [`key_service`] knows never goes to the other. Any other address was
/// named by the user, such as a gateway or a server on this machine.
pub(crate) fn key_fits(key: &str, url: &str) -> bool {
    let host = url_host(url);
    // `openrouter.ai.` is `openrouter.ai`.
    let host = host.trim_end_matches('.');
    key_service(key).is_none_or(|(_, home)| host == home || !KEY_HOSTS.contains(&host))
}

/// Whether `key` is for the service at `url` that speaks `provider`: its
/// own service, or a server on this machine. A key that is not picks its
/// own service where the user named none.
pub(crate) fn key_belongs(key: &str, provider: CloudProvider, url: &str) -> bool {
    key_service(key).is_none_or(|(made_for, home)| {
        made_for == provider && (url_host(url) == home || crate::ai::is_loopback_url(url))
    })
}

/// Whether the user's file asks for a cloud AI: not switched off, and a
/// service was chosen or there is a key to use (`has_key`, from any source).
/// A fresh install has neither, and its cloud AI is off, not short of a key.
pub(crate) fn cloud_in_use(own: &AiOverrides, has_key: bool) -> bool {
    let own_key = own.api_key.as_deref().is_some_and(|k| !k.trim().is_empty());
    let chosen = own.cloud_provider.is_some() || own.cloud_url.is_some();
    !own.disable_cloud && (own_key || has_key || chosen)
}

/// [`cloud_in_use`] for the setup `settings` reads: its own file decides. A
/// file that cannot be read counts as a choice, so nothing is hidden.
fn cloud_wanted(settings: &AiSettings) -> bool {
    let effective = settings.effective();
    if effective.disable_cloud {
        return false;
    }
    let own = match &settings.user_file {
        Some(file) => AiOverrides::load(file).ok(),
        None => None,
    };
    match own {
        Some(own) => cloud_in_use(&own, effective.api_key().is_some()),
        None => true,
    }
}

/// The current setup as `Label  value` lines. Never prints a key. What is
/// not in use is not listed: a cloud AI that is off has no models to show.
pub fn describe(settings: &AiSettings, file: &Path) -> String {
    // Names and addresses come from files and, once, from a server's
    // answer: none of it reaches the terminal as anything but text.
    let clean = |text: &str| crate::evidence::sanitize(text, 200);
    let mut effective = settings.effective();
    for field in [
        &mut effective.local_url,
        &mut effective.local_model,
        &mut effective.cloud_url,
        &mut effective.cloud_model,
        &mut effective.research_model,
    ] {
        *field = clean(field);
    }
    if let Some(chain) = &mut effective.cloud_fallbacks {
        chain.iter_mut().for_each(|model| *model = clean(model));
    }
    let mut rows: Vec<(&str, String)> = Vec::new();
    let mut local = effective.local_url.clone();
    if !effective.local_model.is_empty() {
        local = format!("{local} · {}", effective.local_model);
    }
    rows.push(("Local AI", local));
    // The local AI gets real text only on this machine.
    if !crate::ai::is_loopback_url(&effective.local_url) {
        rows.push(("", "not this machine: it gets masked text only".to_owned()));
    }
    let claude = effective.provider() == CloudProvider::Anthropic;
    let service = match claude {
        true => "Claude API".to_owned(),
        false => effective.cloud_url.clone(),
    };
    let key = match (effective.api_key(), settings.key_source()) {
        (Some(key), Some(source)) => Some(format!("{} ({})", masked(&key), key_origin(&source))),
        _ => None,
    };
    match key {
        _ if !cloud_wanted(settings) => rows.push(("Cloud AI", "off".to_owned())),
        // The one thing to act on; the models of a service without a key
        // are not in use.
        None => {
            rows.push(("Cloud AI", service));
            rows.push(("Key", format!("{KEY_MISSING}, no CVE research")));
        }
        Some(key) => {
            rows.push(("Cloud AI", service));
            rows.push(("Triage model", effective.cloud_model.clone()));
            rows.push(("Research model", effective.research_model.clone()));
            // Asked next when a model declines a request: the Claude API only.
            if claude {
                rows.push((
                    "Fallback models",
                    match effective.fallbacks().as_slice() {
                        [] => "chosen by the Claude API".to_owned(),
                        chain => chain.join(", "),
                    },
                ));
            }
            rows.push(("Key", key));
        }
    }
    let mut text = format!("AI setup · {}\n", file.display());
    for (label, value) in rows {
        text.push_str(&format!("  {label:<15}  {value}\n"));
    }
    text
}

/// Points the cloud tiers at the Claude API. Model names of another service
/// mean nothing there, so they are replaced by the Claude defaults.
fn use_claude(own: &mut AiOverrides, current: &AiSettings) {
    own.disable_cloud = false;
    own.cloud_provider = Some(CloudProvider::Anthropic);
    own.cloud_url = Some(anthropic::API_URL.to_owned());
    if !current.cloud_model.starts_with("claude-") {
        own.cloud_model = Some(anthropic::DEFAULT_MODEL.to_owned());
    }
    if !current.research_model.starts_with("claude-") {
        own.research_model = Some(anthropic::DEFAULT_MODEL.to_owned());
    }
    if own.cloud_fallbacks.is_none() {
        let chain = anthropic::DEFAULT_FALLBACKS.iter();
        own.cloud_fallbacks = Some(chain.map(|model| (*model).to_owned()).collect());
    }
}

/// Points the cloud tiers at an OpenAI-style service (OpenRouter by
/// default). Bare Claude model names belong to the Claude API, so they go
/// back to this service's defaults.
fn use_openai_style(own: &mut AiOverrides, current: &AiSettings, url: Option<String>) {
    let defaults = AiSettings::default();
    own.disable_cloud = false;
    own.cloud_provider = Some(CloudProvider::OpenAi);
    let was_claude = anthropic::is_claude_api(&current.cloud_url);
    own.cloud_url = Some(url.unwrap_or(match was_claude {
        true => defaults.cloud_url,
        false => current.cloud_url.clone(),
    }));
    if current.cloud_model.starts_with("claude-") {
        own.cloud_model = Some(defaults.cloud_model);
    }
    if current.research_model.starts_with("claude-") {
        own.research_model = Some(defaults.research_model);
    }
    own.cloud_fallbacks = None;
}

/// `a, b` as a fallback chain; `none` or nothing is an empty one.
pub(crate) fn parse_chain(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|model| !model.is_empty() && !model.eq_ignore_ascii_case("none"))
        .filter_map(model_name)
        .collect()
}

/// A client for the service at `url`: one on this machine is reached
/// directly, never through a proxy (see [`crate::ai::http_client`]).
fn http(url: &str) -> Result<reqwest::Client> {
    crate::ai::http_client(url, PROBE_TIMEOUT * 3)
}

/// A model name as a server gave it, safe to print and to store: whatever
/// answers on the local model port chooses these words.
fn model_name(id: &str) -> Option<String> {
    let name = crate::evidence::sanitize(id, 120);
    (!name.is_empty()).then_some(name)
}

fn validate_bearer_key(key: &str) -> Result<()> {
    if key.trim().is_empty() || key.len() > 512 || key.chars().any(char::is_control) {
        bail!("the key is empty, too long or has control characters");
    }
    Ok(())
}

/// The models an OpenAI-compatible server offers (`GET <url>/models`).
/// `Err` says why it could not be asked.
pub async fn list_models(url: &str, key: Option<&str>) -> Result<Vec<String>> {
    use crate::ai::Carries;
    let carries = if key.is_some() {
        Carries::Key
    } else {
        Carries::Nothing
    };
    crate::ai::check_server(url, carries)?;
    let mut request = http(url)?.get(format!("{}/models", url.trim_end_matches('/')));
    if let Some(key) = key {
        validate_bearer_key(key)?;
        request = request.bearer_auth(key);
    }
    let mut response = match request.send().await {
        Ok(response) => response,
        Err(error) if error.is_connect() => bail!("no answer at {url}"),
        Err(error) if error.is_timeout() => bail!("{url} did not answer in time"),
        Err(error) => return Err(error).with_context(|| format!("cannot reach {url}")),
    };
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        bail!("{url} refused the key (HTTP {})", status.as_u16());
    }
    if !status.is_success() {
        bail!("{url} answered HTTP {}", status.as_u16());
    }
    let body = crate::ai::read_bounded(&mut response, crate::ai::MAX_ANSWER_BYTES).await?;
    let body: Value = serde_json::from_slice(&body)
        .with_context(|| format!("{url} did not answer like an OpenAI-compatible API"))?;
    let models = body
        .get("data")
        .and_then(Value::as_array)
        .with_context(|| format!("{url} did not answer like an OpenAI-compatible API"))?;
    Ok(models
        .iter()
        .filter_map(|model| model.get("id").and_then(Value::as_str))
        .filter_map(model_name)
        .take(MAX_MODELS)
        .collect())
}

/// Asks the cloud service whether it accepts the key. OpenRouter has an
/// endpoint for exactly that (`/key`); other services are asked for their
/// model list, which needs a valid key.
pub async fn check_key(url: &str, key: &str) -> Result<()> {
    validate_bearer_key(key)?;
    let base = crate::ai::validate_cloud_url(url)?;
    crate::ai::check_server(&base, crate::ai::Carries::Key)?;
    let response = http(&base)?
        .get(format!("{base}/key"))
        .bearer_auth(key)
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) if matches!(response.status().as_u16(), 401 | 403) => {
            bail!(
                "{url} refused the key (HTTP {})",
                response.status().as_u16()
            )
        }
        // No such endpoint, or no answer at all: the model list decides.
        _ => list_models(url, Some(key)).await.map(|_| ()),
    }
}

fn block_on<T>(future: impl std::future::Future<Output = T>) -> Result<T> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?
        .block_on(future))
}

/// Tries the local server and, if there is a key, the cloud service, and
/// says what happened, a line each: `[+]` it works, `[!]` it does not or
/// was skipped. Returns whether everything set up works.
pub(crate) fn check(settings: &AiSettings, out: &mut dyn Write) -> Result<bool> {
    let clean = |text: &str| crate::evidence::sanitize(text, 200);
    let effective = settings.effective();
    let safe_local_url = clean(&effective.local_url);
    let safe_cloud_url = clean(&effective.cloud_url);
    let mut works = true;
    match block_on(list_models(&effective.local_url, None))? {
        Ok(models) => {
            let count = match models.len() {
                1 => "1 model".to_owned(),
                n => format!("{n} models"),
            };
            // Another machine's server, or another user's, is sent masked
            // text: said here, where the server was just seen to answer.
            let masked = match crate::ai::not_own_server_short(&effective.local_url) {
                Some(whose) => format!(" · {}: masked text only", clean(&whose)),
                None => String::new(),
            };
            writeln!(out, "[+] Local AI  {safe_local_url} · {count}{masked}")?;
        }
        Err(error) => {
            works = false;
            writeln!(out, "[!] Local AI  {}", clean(&format!("{error:#}")))?;
        }
    }
    if !cloud_wanted(settings) {
        writeln!(out, "[+] Cloud AI  off")?;
        return Ok(works);
    }
    let claude = effective.provider() == CloudProvider::Anthropic;
    match effective.api_key() {
        None => writeln!(out, "[!] Cloud AI  skipped: no key")?,
        Some(key) if claude => {
            // The key first, then every model the setup names: a key is not
            // necessarily offered all of them.
            let url = &effective.cloud_url;
            let client = http(url)?;
            match block_on(anthropic::list_models(&client, url, &key))? {
                Ok(_) => writeln!(out, "[+] Cloud AI  Claude API · key accepted")?,
                Err(error) if anthropic::key_refused(&error) => {
                    writeln!(out, "[!] Cloud AI  Claude API refused the key")?;
                    return Ok(false);
                }
                Err(error) => {
                    writeln!(out, "[!] Cloud AI  {}", clean(&format!("{error:#}")))?;
                    return Ok(false);
                }
            }
            let mut models = vec![effective.cloud_model.clone()];
            models.push(effective.research_model.clone());
            models.extend(effective.fallbacks());
            let mut asked: Vec<String> = Vec::new();
            // The models this key is offered on one line; one line for each
            // that it is not.
            let mut offered: Vec<String> = Vec::new();
            let mut refused: Vec<String> = Vec::new();
            for model in models {
                if asked.contains(&model) {
                    continue;
                }
                let safe_model = clean(&model);
                match block_on(anthropic::has_model(&client, url, &key, &model))? {
                    Ok(()) => offered.push(safe_model),
                    Err(error) => {
                        works = false;
                        refused.push(match anthropic::model_unknown(&error) {
                            true => format!("[!] Cloud AI  {safe_model} not offered to this key"),
                            false => format!(
                                "[!] Cloud AI  {safe_model}: {}",
                                clean(&format!("{error:#}"))
                            ),
                        });
                    }
                }
                asked.push(model);
            }
            if !offered.is_empty() {
                writeln!(out, "[+] Cloud AI  {} available", offered.join(", "))?;
            }
            for line in refused {
                writeln!(out, "{line}")?;
            }
        }
        Some(key) => match block_on(check_key(&effective.cloud_url, &key))? {
            Ok(()) => writeln!(out, "[+] Cloud AI  {safe_cloud_url} · key accepted")?,
            Err(error) => {
                works = false;
                writeln!(out, "[!] Cloud AI  {}", clean(&format!("{error:#}")))?;
            }
        },
    }
    Ok(works)
}

/// Applies the flags to the user's file. Returns what the setup printed
/// afterwards cannot say: a key that was removed, and what to do next, as
/// whole lines (`[+]` done, `[!]` to do).
fn apply(
    args: &SetupArgs,
    current: &AiSettings,
    own: &mut AiOverrides,
    key_from_stdin: Option<String>,
) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    if args.cloud_off
        && (args.provider.is_some() || args.cloud_url.is_some() || key_from_stdin.is_some())
    {
        bail!("--cloud-off cannot be used with --provider, --cloud-url or --api-key-stdin");
    }
    match args.provider.as_deref().map(str::to_lowercase).as_deref() {
        Some("claude" | "anthropic") => use_claude(own, current),
        Some("openrouter" | "openai") => use_openai_style(own, current, None),
        Some(other) => bail!(
            "unknown provider '{}': use claude or openrouter",
            crate::evidence::sanitize(other, 80)
        ),
        None => {}
    }
    if let Some(chain) = &args.fallback_models {
        own.cloud_fallbacks = Some(parse_chain(chain));
    }
    if let Some(url) = &args.local_url {
        own.local_url = Some(checked_url(url)?);
    }
    if let Some(model) = &args.local_model {
        own.local_model = Some(crate::evidence::sanitize(model, 120));
    }
    if let Some(url) = &args.cloud_url {
        let url = crate::ai::validate_cloud_url(url)?;
        own.disable_cloud = false;
        // The address decides the protocol unless a provider was named.
        if args.provider.is_none() {
            if anthropic::is_claude_api(&url) {
                use_claude(own, current);
            } else {
                use_openai_style(own, current, Some(url.clone()));
            }
        }
        own.cloud_url = Some(url);
    }
    for (value, slot) in [
        (&args.cloud_model, &mut own.cloud_model),
        (&args.research_model, &mut own.research_model),
    ] {
        if let Some(model) = value.as_deref().and_then(model_name) {
            *slot = Some(model);
        }
    }
    // A key stays with the service it was entered for. Naming another
    // service without giving its key does not send the old one there.
    let (before, after) = (
        url_host(&current.cloud_url),
        url_host(own.cloud_url.as_deref().unwrap_or(&current.cloud_url)),
    );
    if before != after && key_from_stdin.is_none() && own.api_key.take().is_some() {
        notes.push(format!("[+] Key removed: it was for {before}"));
        notes.push(format!("[!] Add the key for {after} with --api-key-stdin"));
    }
    if args.forget_key {
        match own.api_key.take() {
            Some(_) => notes.push("[+] Key removed".to_owned()),
            // Unless the line above just said where it went.
            None if notes.is_empty() => notes.push(NO_KEY_STORED.to_owned()),
            None => {}
        }
    }
    if let Some(key) = key_from_stdin {
        let key = key.trim().to_owned();
        if key.is_empty() {
            bail!("no key on standard input");
        }
        if key.len() > 512 || key.chars().any(char::is_control) {
            bail!("key refused: over 512 bytes or control characters");
        }
        // A Claude key goes to the Claude API, an OpenRouter key to
        // OpenRouter: with no service named, the key picks its own. A
        // service named here is kept (a gateway, say), but neither key is
        // sent to the other one's service.
        let url = own.cloud_url.clone().unwrap_or(current.cloud_url.clone());
        let provider = AiSettings {
            cloud_url: url.clone(),
            cloud_provider: own.cloud_provider.or(current.cloud_provider),
            ..AiSettings::default()
        }
        .provider();
        let named = args.provider.is_some() || args.cloud_url.is_some();
        match key_service(&key) {
            Some((_, made_for)) if named && !key_fits(&key, &url) => {
                bail!("key refused: it is for {made_for}, not {}", url_host(&url));
            }
            Some((made_for, _)) if !named && !key_belongs(&key, provider, &url) => {
                match made_for {
                    CloudProvider::Anthropic => use_claude(own, current),
                    CloudProvider::OpenAi => {
                        use_openai_style(own, current, Some(AiSettings::default().cloud_url));
                    }
                }
                // The models named in this call stay.
                if let Some(model) = args.cloud_model.as_deref().and_then(model_name) {
                    own.cloud_model = Some(model);
                }
                if let Some(model) = args.research_model.as_deref().and_then(model_name) {
                    own.research_model = Some(model);
                }
            }
            _ => {}
        }
        own.disable_cloud = false;
        own.api_key = Some(key);
        let service = own.cloud_url.as_deref().unwrap_or(&current.cloud_url);
        notes.push(format!("[+] Key saved for {}", url_host(service)));
    }
    if args.cloud_off {
        notes.extend(turn_cloud_off(own));
    }
    Ok(notes)
}

/// Turns the cloud AI off: local AI only, also with a key in the
/// environment. The stored key is removed; returns the line that says so.
fn turn_cloud_off(own: &mut AiOverrides) -> Option<String> {
    own.disable_cloud = true;
    own.api_key.take().map(|_| "[+] Key removed".to_owned())
}

/// Said when a key is to be removed and none is stored.
const NO_KEY_STORED: &str = "[+] No key stored";
/// Said once after the setup was saved: a mode is fixed when a session starts.
const RUNNING_SESSIONS: &str = "[+] Running sessions use the AI setup from their next request";

/// One line typed by the user, without the line end. `None` at end of input.
fn ask(prompt: &str) -> Result<Option<String>> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let stdin = std::io::stdin();
    let read = stdin
        .lock()
        .take(MAX_INPUT_BYTES)
        .read_line(&mut line)
        .context("cannot read the answer")?;
    Ok((read > 0).then(|| line.trim().to_owned()))
}

struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = ratatui::crossterm::execute!(
            std::io::stdout(),
            ratatui::crossterm::event::DisableBracketedPaste
        );
        let _ = ratatui::crossterm::terminal::disable_raw_mode();
        crate::pty::ensure_cooked_terminal();
    }
}

/// Reads a secret from the terminal without showing it. `None` if the user
/// cancelled (Esc, Ctrl-C) or typed nothing.
fn ask_hidden(prompt: &str) -> Result<Option<String>> {
    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::crossterm::terminal;

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("cannot switch the terminal to hidden input (is this a TTY?)");
    }
    // Echo goes off before the prompt shows: a key pasted the moment the
    // prompt appears must not be echoed by the terminal.
    crate::pty::ensure_cooked_terminal();
    terminal::enable_raw_mode().context("cannot switch the terminal to hidden input")?;
    let raw_guard = RawModeGuard;
    let mut out = std::io::stdout();
    // A paste then arrives whole, as one event. Not on Windows: crossterm
    // reads the console key by key there, and the marks a terminal asked
    // for it puts around a paste would be read as keys, Esc (cancel) first.
    #[cfg(not(windows))]
    let _ = ratatui::crossterm::execute!(out, event::EnableBracketedPaste);
    print!("{prompt}");
    out.flush().ok();
    let mut secret = String::new();
    // One `*` per character, so a paste that worked can be seen to have
    // worked; the key itself never shows.
    let add = |secret: &mut String, text: &str| {
        let before = secret.chars().count();
        let remaining = MAX_SECRET_CHARS.saturating_sub(before);
        secret.extend(text.chars().filter(|c| !c.is_control()).take(remaining));
        print!("{}", "*".repeat(secret.chars().count() - before));
        std::io::stdout().flush().ok();
    };
    let outcome = loop {
        match event::read() {
            Ok(Event::Key(key)) if key.kind != KeyEventKind::Release => {
                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    KeyCode::Enter => break Ok(Some(secret)),
                    KeyCode::Esc => break Ok(None),
                    KeyCode::Char('c') if ctrl => break Ok(None),
                    KeyCode::Char('v') if ctrl => {
                        print!(
                            "\r\n{PASTE_HINT}\r\n{prompt}{}",
                            "*".repeat(secret.chars().count())
                        );
                        out.flush().ok();
                    }
                    KeyCode::Char(_) if ctrl || key.modifiers.contains(KeyModifiers::ALT) => {}
                    KeyCode::Backspace => {
                        if secret.pop().is_some() {
                            print!("\x08 \x08");
                            out.flush().ok();
                        }
                    }
                    KeyCode::Char(ch) => add(&mut secret, &ch.to_string()),
                    _ => {}
                }
            }
            Ok(Event::Paste(text)) => add(&mut secret, &text),
            Ok(_) => {}
            Err(error) => break Err(error),
        }
    };
    drop(raw_guard);
    println!();
    let secret = outcome.context("cannot read from the terminal")?;
    Ok(secret
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty()))
}

/// Picks from a numbered list: a number, or free text, or Enter for
/// `default`. `None` means "go back".
fn choose(prompt: &str, options: &[String], default: Option<&str>) -> Result<Option<String>> {
    let Some(answer) = ask(prompt)? else {
        return Ok(None);
    };
    if answer.is_empty() {
        return Ok(default.map(str::to_owned));
    }
    match answer.parse::<usize>() {
        Ok(n) if (1..=options.len()).contains(&n) => Ok(Some(options[n - 1].clone())),
        _ => Ok(Some(answer)),
    }
}

/// Probes `current_url` plus the well-known local server ports (`:1234`,
/// `:11434`, `:8080`) and returns `(url, label, models)` for each server
/// that answered.
pub(crate) fn probe_local_servers(current_url: &str) -> Result<Vec<(String, String, Vec<String>)>> {
    let mut candidates: Vec<(String, &str)> = vec![(current_url.to_owned(), "current setting")];
    for (url, name) in LOCAL_SERVERS {
        if !candidates.iter().any(|(known, _)| known == url) {
            candidates.push(((*url).to_owned(), name));
        }
    }
    let mut found = Vec::new();
    for (url, name) in candidates {
        if let Ok(models) = block_on(list_models(&url, None))? {
            found.push((url, name.to_owned(), models));
        }
    }
    Ok(found)
}

fn setup_local(settings: &AiSettings, own: &mut AiOverrides) -> Result<bool> {
    println!("Looking for local AI servers ...");
    let current = settings.effective().local_url;
    let probed = probe_local_servers(&current)?;
    let mut found: Vec<(String, Vec<String>)> = Vec::new();
    for (url, name, models) in probed {
        let count = match models.len() {
            1 => "1 model".to_owned(),
            n => format!("{n} models"),
        };
        println!("  {}  {url}  {name} · {count}", found.len() + 1);
        found.push((url, models));
    }
    let urls: Vec<String> = found.iter().map(|(url, _)| url.clone()).collect();
    let prompt = if found.is_empty() {
        println!(
            "0 found. Start one first, or type its URL:\n\
             \x20 Ollama     ollama serve\n\
             \x20 LM Studio  Developer > Start Server"
        );
        "URL (Enter goes back): ".to_owned()
    } else {
        "Server, number or URL (Enter: 1): ".to_owned()
    };
    let Some(url) = choose(&prompt, &urls, urls.first().map(String::as_str))? else {
        return Ok(false);
    };
    let url = checked_url(&url)?;
    let models = match found.iter().find(|(known, _)| *known == url) {
        Some((_, models)) => models.clone(),
        None => match block_on(list_models(&url, None))? {
            Ok(models) => models,
            Err(error) => {
                println!(
                    "[!] {}. Saved anyway: start the server before use",
                    crate::evidence::sanitize(&format!("{error:#}"), 300)
                );
                Vec::new()
            }
        },
    };
    for (index, model) in models.iter().enumerate().take(30) {
        println!("  {}  {model}", index + 1);
    }
    let model = choose(
        "Model, number or name (Enter: server's choice): ",
        &models,
        Some(""),
    )?
    .unwrap_or_default();
    own.local_url = Some(url);
    own.local_model = Some(crate::evidence::sanitize(&model, 120));
    Ok(true)
}

fn setup_claude(settings: &AiSettings, own: &mut AiOverrides) -> Result<bool> {
    println!(
        "Get a key: Claude Console > API keys\n\
         Kept in ai.toml, which only you can read; sent only to the Claude API"
    );
    let Some(key) = ask_hidden("Claude key, hidden (Esc cancels): ")? else {
        println!("[+] Nothing changed");
        return Ok(false);
    };
    if !may_keep_for(&key, anthropic::API_URL) {
        return Ok(false);
    }
    let mut next = own.clone();
    use_claude(&mut next, &settings.effective());
    let default = |own: &Option<String>, current: &str| own.clone().unwrap_or(current.to_owned());
    let effective = settings.effective();
    let triage_now =
        crate::evidence::sanitize(&default(&next.cloud_model, &effective.cloud_model), 120);
    let research_now = crate::evidence::sanitize(
        &default(&next.research_model, &effective.research_model),
        120,
    );
    let chain_now = next.cloud_fallbacks.clone().unwrap_or_default();
    let triage = ask(&format!("Triage model (Enter keeps {triage_now}): "))?.unwrap_or_default();
    let research =
        ask(&format!("Research model (Enter keeps {research_now}): "))?.unwrap_or_default();
    let chain = ask(&format!(
        "Fallback models, asked in order when one declines\n\
         (Enter keeps {}; none: the Claude API chooses): ",
        match chain_now.as_slice() {
            [] => "none".to_owned(),
            chain => crate::evidence::sanitize(&chain.join(", "), 200),
        }
    ))?
    .unwrap_or_default();
    next.api_key = Some(key);
    if let Some(clean) = model_name(&triage) {
        next.cloud_model = Some(clean);
    }
    if let Some(clean) = model_name(&research) {
        next.research_model = Some(clean);
    }
    if !chain.is_empty() {
        next.cloud_fallbacks = Some(parse_chain(&chain));
    }
    *own = next;
    Ok(true)
}

fn setup_cloud(settings: &AiSettings, own: &mut AiOverrides) -> Result<bool> {
    let effective = settings.effective();
    println!(
        "Get a key: openrouter.ai > Keys\n\
         Another OpenAI-style service works too, without research: type its URL\n\
         Kept in ai.toml, which only you can read; sent only to that service"
    );
    // Coming from a Claude key, the address to propose is OpenRouter's.
    let proposed = match anthropic::is_claude_api(&effective.cloud_url) {
        true => AiSettings::default().cloud_url,
        false => crate::evidence::sanitize(&effective.cloud_url, 200),
    };
    let url = ask(&format!("URL (Enter keeps {proposed}): "))?.unwrap_or_default();
    let url = match url.as_str() {
        "" => crate::ai::validate_cloud_url(&proposed)?,
        typed => crate::ai::validate_cloud_url(typed)?,
    };
    let Some(key) = ask_hidden("Key, hidden (Esc cancels): ")? else {
        println!("[+] Nothing changed");
        return Ok(false);
    };
    if !may_keep_for(&key, &url) {
        return Ok(false);
    }
    // What would be kept if every question is answered with Enter: model
    // names of the Claude API are replaced by this service's own.
    let mut next = own.clone();
    use_openai_style(&mut next, &effective, Some(url));
    let kept = |own: &Option<String>, current: &str| own.clone().unwrap_or(current.to_owned());
    let triage_now =
        crate::evidence::sanitize(&kept(&next.cloud_model, &effective.cloud_model), 120);
    let research_now =
        crate::evidence::sanitize(&kept(&next.research_model, &effective.research_model), 120);
    let triage = ask(&format!("Triage model (Enter keeps {triage_now}): "))?.unwrap_or_default();
    let research =
        ask(&format!("Research model (Enter keeps {research_now}): "))?.unwrap_or_default();
    *own = next;
    own.api_key = Some(key);
    if let Some(clean) = model_name(&triage) {
        own.cloud_model = Some(clean);
    }
    if let Some(clean) = model_name(&research) {
        own.research_model = Some(clean);
    }
    Ok(true)
}

/// Whether `key` may be kept for the service at `url`; if not, says so.
fn may_keep_for(key: &str, url: &str) -> bool {
    match key_service(key) {
        Some((_, made_for)) if !key_fits(key, url) => {
            println!("[!] Not saved: that key is for {made_for}");
            false
        }
        _ => true,
    }
}

/// The line-mode menu shown by `meow setup --plain` (or `TERM=dumb`). The
/// setup is printed at the start and after each change, not with every menu.
fn interactive(settings: &AiSettings, file: &Path, own: &mut AiOverrides) -> Result<()> {
    println!("{}\n", crate::wizard::CAT_CLI_BANNER);
    print!("{}", describe(settings, file));
    let mut saved_any = false;
    // What running sessions do with it is said once, on the way out.
    let done = |saved_any: bool| {
        if saved_any {
            println!("{RUNNING_SESSIONS}");
        }
    };
    loop {
        println!(
            "\n  1  Local AI server\n\
             \x20 2  Claude key\n\
             \x20 3  OpenRouter or other key\n\
             \x20 4  Remove key\n\
             \x20 5  Test\n\
             \x20 6  Cloud AI off (local AI only)\n\
             \x20 q  Done"
        );
        let Some(answer) = ask("> ")? else {
            done(saved_any);
            return Ok(());
        };
        let saved = match answer.as_str() {
            "1" => setup_local(settings, own),
            "2" => setup_claude(settings, own),
            "3" => setup_cloud(settings, own),
            "4" => {
                let stored = own.api_key.take().is_some();
                if !stored {
                    println!("{NO_KEY_STORED}");
                }
                Ok(stored)
            }
            "5" => check(settings, &mut std::io::stdout()).map(|_| false),
            "6" => {
                if let Some(said) = turn_cloud_off(own) {
                    println!("{said}");
                }
                Ok(true)
            }
            "q" | "Q" | "" => {
                done(saved_any);
                return Ok(());
            }
            _ => {
                println!("Type 1-6 or q");
                Ok(false)
            }
        };
        match saved {
            Ok(true) => {
                own.save(file)?;
                saved_any = true;
                println!("[+] Saved");
                print!("{}", describe(settings, file));
            }
            Ok(false) => {}
            // A mistyped address must not end the whole setup.
            Err(error) => println!(
                "[!] {}",
                crate::evidence::sanitize(&format!("{error:#}"), 300)
            ),
        }
    }
}

/// Runs `meow setup`.
pub fn run(home: &MeowHome, args: &SetupArgs) -> Result<ExitCode> {
    if !args.changes_something()
        && !args.show
        && !args.check
        && !args.plain
        && crate::wizard::can_run_tui()
    {
        match crate::wizard::run_setup(home)? {
            crate::wizard::WizardOutcome::Saved { launch_workspace } => {
                let config = Config::load_or_create(home)?;
                let file = home.ai_path();
                // Both files are in the folder the setup's first line names;
                // the mode is the one thing saved that the lines below do
                // not show.
                println!(
                    "[+] Saved config.toml and ai.toml · default mode {}",
                    config.default_mode
                );
                println!("{RUNNING_SESSIONS}");
                print!("{}", describe(&config.ai, &file));
                if let Some(name) = launch_workspace {
                    let valid = crate::workspace::validate_name(&name)
                        .map_err(|reason| anyhow::anyhow!("session name refused: {reason}"))?;
                    let exe = std::env::current_exe().context("cannot locate the meow binary")?;
                    let cwd = std::env::current_dir()
                        .context("cannot determine the current directory")?;
                    let status = std::process::Command::new(exe)
                        .arg(&valid)
                        .current_dir(cwd)
                        .status()
                        .with_context(|| format!("cannot launch session '{valid}'"))?;
                    let code = status
                        .code()
                        .and_then(|c| u8::try_from(c).ok())
                        .unwrap_or(1);
                    return Ok(ExitCode::from(code));
                }
            }
            crate::wizard::WizardOutcome::Cancelled => {
                println!("[+] Nothing changed");
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    let settings = Config::load_or_create(home)?.ai;
    let file = home.ai_path();
    let mut own = AiOverrides::load(&file)?;

    if args.changes_something() {
        let key = if args.api_key_stdin {
            let mut line = String::new();
            let stdin = std::io::stdin();
            stdin
                .lock()
                .take(MAX_INPUT_BYTES)
                .read_line(&mut line)
                .context("cannot read the key from standard input")?;
            Some(line)
        } else {
            None
        };
        let notes = apply(args, &settings.effective(), &mut own, key)?;
        own.save(&file)?;
        for line in &notes {
            println!("{line}");
        }
        println!("[+] Saved");
    } else if !args.show && !args.check {
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            interactive(&settings, &file, &mut own)?;
            return Ok(ExitCode::SUCCESS);
        }
        // Nothing to ask on: show the state and how to change it.
        print!("{}", describe(&settings, &file));
        println!("\nRun `meow setup` in a terminal to change it, or see `meow setup --help`");
        return Ok(ExitCode::SUCCESS);
    }

    if args.show || args.changes_something() {
        print!("{}", describe(&settings, &file));
    }
    if args.check && !check(&settings, &mut std::io::stdout())? {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;

    const GOOD_KEY: &str = "sk-test-their-own-key-9f3a";

    fn accepted(headers: &HeaderMap) -> bool {
        headers
            .get("authorization")
            .is_some_and(|value| value.to_str().unwrap() == format!("Bearer {GOOD_KEY}"))
    }

    /// The Claude API's model list: for the right `x-api-key` only.
    async fn claude_models(headers: HeaderMap) -> (StatusCode, Json<Value>) {
        match headers
            .get("x-api-key")
            .is_some_and(|key| key == CLAUDE_KEY)
        {
            true => (StatusCode::OK, Json(json!({ "data": [] }))),
            false => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": {
                    "type": "authentication_error", "message": "invalid x-api-key" } })),
            ),
        }
    }

    /// One model of the Claude API: every one but `claude-opus-4-6`.
    async fn claude_model(
        axum::extract::Path(id): axum::extract::Path<String>,
    ) -> (StatusCode, Json<Value>) {
        match id.as_str() {
            "claude-opus-4-6" => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": {
                    "type": "not_found_error", "message": format!("model: {id}") } })),
            ),
            _ => (StatusCode::OK, Json(json!({ "id": id }))),
        }
    }

    const CLAUDE_KEY: &str = "sk-ant-test-their-claude-key-5b2c";

    /// Four services: a local model server, an OpenRouter-like one with a
    /// `/key` endpoint, a plain OpenAI-compatible one without it, and a
    /// stand-in for the Claude API.
    async fn services() -> String {
        let models = || Json(json!({ "data": [ { "id": "llama3.2" }, { "id": "qwen2.5" } ] }));
        let guarded = move |headers: HeaderMap| async move {
            match accepted(&headers) {
                true => (StatusCode::OK, Json(json!({ "data": [ { "id": "gpt" } ] }))),
                false => (StatusCode::UNAUTHORIZED, Json(json!({ "error": "no" }))),
            }
        };
        let app = Router::new()
            .route("/local/v1/models", get(move || async move { models() }))
            .route("/openrouter/v1/key", get(guarded))
            .route("/plain/v1/models", get(guarded))
            .route("/odd/v1/models", get(|| async { "not json" }))
            .route("/claude/v1/models", get(claude_models))
            .route("/claude/v1/models/{id}", get(claude_model));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    #[tokio::test]
    async fn servers_and_keys_are_checked_with_plain_answers() {
        let base = services().await;
        let local = format!("{base}/local/v1");
        assert_eq!(
            list_models(&local, None).await.unwrap(),
            ["llama3.2", "qwen2.5"]
        );
        // A trailing slash is the same address.
        assert_eq!(
            list_models(&format!("{local}/"), None).await.unwrap().len(),
            2
        );

        let error = |result: Result<Vec<String>>| format!("{:#}", result.unwrap_err());
        let dead = "http://127.0.0.1:9/v1";
        assert_eq!(
            error(list_models(dead, None).await),
            format!("no answer at {dead}")
        );
        let odd = format!("{base}/odd/v1");
        assert!(error(list_models(&odd, None).await)
            .contains("did not answer like an OpenAI-compatible API"));
        assert!(error(list_models(&format!("{base}/nowhere"), None).await).contains("HTTP 404"));

        // OpenRouter-style: the key endpoint answers.
        let openrouter = format!("{base}/openrouter/v1");
        check_key(&openrouter, GOOD_KEY).await.unwrap();
        let refused = format!("{:#}", check_key(&openrouter, "wrong").await.unwrap_err());
        assert_eq!(refused, format!("{openrouter} refused the key (HTTP 401)"));
        // Any other service: no key endpoint, so its model list decides.
        let plain = format!("{base}/plain/v1");
        check_key(&plain, GOOD_KEY).await.unwrap();
        let refused = format!("{:#}", check_key(&plain, "wrong").await.unwrap_err());
        assert_eq!(refused, format!("{plain} refused the key (HTTP 401)"));
        // The error never repeats the key.
        assert!(!refused.contains("wrong"));
    }

    #[tokio::test]
    async fn model_names_from_a_server_reach_the_terminal_as_text_only() {
        // Whatever answers on the local model port: here with a title
        // change, a clipboard write and a forged status line in one name.
        const HOSTILE: &str =
            "llama3\u{1b}]0;owned\u{7}\u{1b}]52;c;aGk=\u{7}\r\u{1b}[2K[+] cloud AI  key accepted";
        let app = Router::new().route(
            "/v1/models",
            get(|| async {
                Json(json!({ "data": [ { "id": HOSTILE }, { "id": "\u{1b}\u{7}" }, { "id": "plain" } ] }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let models = list_models(&url, None).await.unwrap();
        assert_eq!(
            models.len(),
            2,
            "a name of nothing but control codes is dropped"
        );
        assert_eq!(models[1], "plain");
        assert!(models[0].starts_with("llama3]0;owned"), "{:?}", models[0]);
        for model in &models {
            assert!(!model.chars().any(char::is_control), "{model:?}");
        }
        // And a name already saved in the setup file, by an earlier version
        // or by hand, is printed clean too.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.toml");
        AiOverrides {
            local_model: Some(HOSTILE.into()),
            cloud_model: Some(format!("m{HOSTILE}")),
            cloud_fallbacks: Some(vec![HOSTILE.into()]),
            cloud_provider: Some(CloudProvider::Anthropic),
            // With a key the models and the fallback models are listed.
            api_key: Some(GOOD_KEY.into()),
            ..AiOverrides::default()
        }
        .save(&file)
        .unwrap();
        let settings = AiSettings {
            user_file: Some(file.clone()),
            ..AiSettings::default()
        };
        let shown = describe(&settings, &file);
        assert!(
            !shown.chars().any(|c| c.is_control() && c != '\n'),
            "{shown:?}"
        );
        assert!(shown.contains("llama3]0;owned"));
        assert_eq!(
            shown.matches("llama3]0;owned").count(),
            3,
            "the local, the triage and the fallback model are listed: {shown}"
        );
    }

    #[test]
    fn a_key_stays_with_the_service_it_was_entered_for() {
        let claude = AiSettings {
            cloud_url: anthropic::API_URL.into(),
            ..AiSettings::default()
        };
        let stored = || AiOverrides {
            cloud_url: Some(anthropic::API_URL.into()),
            cloud_provider: Some(CloudProvider::Anthropic),
            api_key: Some("sk-ant-their-claude-key-ZZ99".into()),
            ..AiOverrides::default()
        };
        // Another service by address, or by name: the Claude key is not
        // taken along, and the answer says so without printing it.
        for args in [
            SetupArgs {
                cloud_url: Some("https://llm.other-service.example/v1".into()),
                ..SetupArgs::default()
            },
            SetupArgs {
                provider: Some("openrouter".into()),
                ..SetupArgs::default()
            },
        ] {
            let mut own = stored();
            let notes = apply(&args, &claude, &mut own, None).unwrap();
            assert_eq!(own.api_key, None, "{notes:?}");
            assert_eq!(notes[0], "[+] Key removed: it was for api.anthropic.com");
            // What is left to do is not marked as done.
            assert!(notes[1].starts_with("[!] Add the key for "), "{notes:?}");
            assert!(notes[1].ends_with(" with --api-key-stdin"), "{notes:?}");
            let said = notes.join("\n");
            assert!(!said.contains("ZZ99") && !said.contains("sk-ant"), "{said}");
        }
        // With the new service's key in the same call, that key is stored.
        let mut own = stored();
        let args = SetupArgs {
            cloud_url: Some("https://llm.other-service.example/v1".into()),
            api_key_stdin: true,
            ..SetupArgs::default()
        };
        apply(&args, &claude, &mut own, Some(GOOD_KEY.into())).unwrap();
        assert_eq!(own.api_key.as_deref(), Some(GOOD_KEY));
        // A change that keeps the service keeps the key.
        let mut own = stored();
        let args = SetupArgs {
            cloud_model: Some("claude-opus-5-5".into()),
            cloud_url: Some(format!("{}/", anthropic::API_URL)),
            ..SetupArgs::default()
        };
        apply(&args, &claude, &mut own, None).unwrap();
        assert!(own.api_key.is_some());
    }

    #[test]
    fn flags_change_only_what_they_name() {
        let mut own = AiOverrides {
            cloud_model: Some("kept/model".into()),
            api_key: Some("old-key-0000".into()),
            ..AiOverrides::default()
        };
        let args = SetupArgs {
            local_url: Some(" http://localhost:11434/v1/ ".into()),
            local_model: Some("llama3.2".into()),
            research_model: Some("my/research".into()),
            api_key_stdin: true,
            ..SetupArgs::default()
        };
        assert!(args.changes_something());
        let notes = apply(
            &args,
            &AiSettings::default(),
            &mut own,
            Some(format!("{GOOD_KEY}\n")),
        )
        .unwrap();
        // The setup printed afterwards shows each of these: nothing is
        // said twice, and the key's ending once. Where the key goes is
        // said, and never the key.
        assert_eq!(notes, ["[+] Key saved for openrouter.ai"]);
        assert_eq!(
            own,
            AiOverrides {
                local_url: Some("http://localhost:11434/v1".into()),
                local_model: Some("llama3.2".into()),
                cloud_url: None,
                cloud_model: Some("kept/model".into()),
                research_model: Some("my/research".into()),
                cloud_provider: None,
                cloud_fallbacks: None,
                api_key: Some(GOOD_KEY.into()),
                disable_cloud: false,
            }
        );

        // Forgetting the key, and letting the server choose its model.
        let args = SetupArgs {
            forget_key: true,
            local_model: Some(String::new()),
            ..SetupArgs::default()
        };
        let notes = apply(&args, &AiSettings::default(), &mut own, None).unwrap();
        assert_eq!(notes, ["[+] Key removed"]);
        assert_eq!(
            (own.api_key.as_deref(), own.local_model.as_deref()),
            (None, Some(""))
        );
        // Removing a key that is not there changes nothing, and says so.
        let notes = apply(&args, &AiSettings::default(), &mut own, None).unwrap();
        assert_eq!(notes, ["[+] No key stored"]);

        // Refused before anything is saved.
        let bad = |args: SetupArgs, key: Option<String>| {
            format!(
                "{:#}",
                apply(
                    &args,
                    &AiSettings::default(),
                    &mut AiOverrides::default(),
                    key
                )
                .unwrap_err()
            )
        };
        let url = |url: &str| SetupArgs {
            local_url: Some(url.into()),
            ..SetupArgs::default()
        };
        assert_eq!(
            bad(url("ftp://models.example"), None),
            "'ftp://models.example': needs http:// or https://"
        );
        assert!(bad(url("localhost:1234"), None).ends_with(": needs http:// or https://"));
        assert_eq!(bad(url("not a url"), None), "'not a url': not a URL");
        let cloud_http = SetupArgs {
            cloud_url: Some("http://203.0.113.10/v1".into()),
            ..SetupArgs::default()
        };
        assert!(bad(cloud_http, None).ends_with(": needs https:// (http:// only for this machine)"));
        let cloud_loopback = SetupArgs {
            cloud_url: Some("http://127.0.0.1:8080/v1".into()),
            ..SetupArgs::default()
        };
        assert!(apply(
            &cloud_loopback,
            &AiSettings::default(),
            &mut AiOverrides::default(),
            None
        )
        .is_ok());
        let empty_key = SetupArgs {
            api_key_stdin: true,
            ..SetupArgs::default()
        };
        assert!(bad(empty_key, Some("  \n".into())).contains("no key on standard input"));
        assert!(!SetupArgs::default().changes_something());
        assert!(!SetupArgs {
            show: true,
            check: true,
            ..SetupArgs::default()
        }
        .changes_something());
    }

    /// Choosing a Claude key switches the cloud tiers to the Claude API,
    /// with Claude model names and the fallback chain, and back again.
    #[test]
    fn a_claude_key_brings_the_claude_api_its_models_and_the_fallback_chain() {
        if std::env::var(anthropic::KEY_ENV).is_ok()
            || std::env::var(crate::ai::API_KEY_ENV).is_ok()
        {
            return; // a key in the environment would be named as the source
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.toml");
        let settings = AiSettings {
            user_file: Some(file.clone()),
            ..AiSettings::default()
        };
        let claude_key = "sk-ant-test-their-own-key-7c1d";
        let mut own = AiOverrides::default();
        let args = SetupArgs {
            provider: Some("claude".into()),
            api_key_stdin: true,
            ..SetupArgs::default()
        };
        let notes = apply(
            &args,
            &settings.effective(),
            &mut own,
            Some(claude_key.into()),
        )
        .unwrap();
        assert_eq!(notes, ["[+] Key saved for api.anthropic.com"]);
        assert_eq!(
            own,
            AiOverrides {
                cloud_provider: Some(CloudProvider::Anthropic),
                cloud_url: Some("https://api.anthropic.com/v1".into()),
                // OpenRouter's model names mean nothing to the Claude API.
                cloud_model: Some("claude-opus-5-5".into()),
                research_model: Some("claude-opus-5-5".into()),
                cloud_fallbacks: Some(vec!["claude-opus-4-6".into(), "claude-opus-4-8".into()]),
                api_key: Some(claude_key.into()),
                ..AiOverrides::default()
            }
        );
        own.save(&file).unwrap();
        let effective = settings.effective();
        assert_eq!(effective.provider(), CloudProvider::Anthropic);
        assert_eq!(
            effective.fallbacks(),
            ["claude-opus-4-6", "claude-opus-4-8"]
        );
        assert_eq!(effective.key_variable(), "ANTHROPIC_API_KEY");
        let text = describe(&settings, &file);
        for expected in [
            "  Cloud AI         Claude API\n",
            "  Triage model     claude-opus-5-5\n",
            "  Research model   claude-opus-5-5\n",
            "  Fallback models  claude-opus-4-6, claude-opus-4-8\n",
            "  Key              set, ends in 7c1d (in ai.toml)\n",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(!text.contains(claude_key));
        // The file says it in plain TOML, for anyone who prefers an editor.
        let saved = std::fs::read_to_string(&file).unwrap();
        assert!(saved.contains("cloud_provider = \"anthropic\""), "{saved}");
        assert!(
            saved.contains("cloud_fallbacks = [\"claude-opus-4-6\", \"claude-opus-4-8\"]"),
            "{saved}"
        );

        // Their own chain, their own models; a model already chosen stays.
        let args = SetupArgs {
            cloud_model: Some("claude-sonnet-5-5".into()),
            fallback_models: Some("claude-opus-4-8, claude-opus-5".into()),
            ..SetupArgs::default()
        };
        apply(&args, &settings.effective(), &mut own, None).unwrap();
        own.save(&file).unwrap();
        let again = SetupArgs {
            provider: Some("anthropic".into()),
            ..SetupArgs::default()
        };
        apply(&again, &settings.effective(), &mut own, None).unwrap();
        assert_eq!(own.cloud_model.as_deref(), Some("claude-sonnet-5-5"));
        assert_eq!(
            own.cloud_fallbacks,
            Some(vec!["claude-opus-4-8".into(), "claude-opus-5".into()])
        );
        // An empty chain hands the choice to the Claude API.
        let none = SetupArgs {
            fallback_models: Some("none".into()),
            ..SetupArgs::default()
        };
        apply(&none, &settings.effective(), &mut own, None).unwrap();
        own.save(&file).unwrap();
        assert!(settings.effective().fallbacks().is_empty());
        assert!(describe(&settings, &file).contains("Fallback models  chosen by the Claude API"));

        // Back to OpenRouter: its address and its model names return.
        let back = SetupArgs {
            provider: Some("openrouter".into()),
            ..SetupArgs::default()
        };
        let notes = apply(&back, &settings.effective(), &mut own, None).unwrap();
        // The Claude key does not go along to the other service.
        assert_eq!(
            notes,
            [
                "[+] Key removed: it was for api.anthropic.com",
                "[!] Add the key for openrouter.ai with --api-key-stdin"
            ]
        );
        assert_eq!(own.api_key, None);
        own.save(&file).unwrap();
        let effective = settings.effective();
        assert_eq!(effective.provider(), CloudProvider::OpenAi);
        assert_eq!(effective.cloud_model, "anthropic/claude-sonnet-5.5");
        assert_eq!(effective.research_model, "anthropic/claude-opus-5.5");
        assert!(effective.fallbacks().is_empty());
        assert_eq!(effective.key_variable(), "OPENROUTER_API_KEY");
        // Without a key, and for another service: no fallback models, and
        // no models of a cloud AI that is not in use.
        let text = describe(&settings, &file);
        assert!(!text.contains("Fallback models"), "{text}");
        assert!(
            text.ends_with(
                "  Cloud AI         https://openrouter.ai/api/v1\n\
                 \x20 Key              missing · local AI answers instead, no CVE research\n"
            ),
            "{text}"
        );

        // The address alone is enough to know which protocol to speak.
        let by_address = AiSettings {
            cloud_url: "https://api.anthropic.com/v1".into(),
            ..AiSettings::default()
        };
        assert_eq!(by_address.provider(), CloudProvider::Anthropic);
        assert_eq!(
            by_address.fallbacks(),
            ["claude-opus-4-6", "claude-opus-4-8"]
        );
        assert_eq!(parse_chain(" a , ,b,none"), ["a", "b"]);
        let unknown = SetupArgs {
            provider: Some("other".into()),
            ..SetupArgs::default()
        };
        assert!(apply(&unknown, &settings, &mut own, None).is_err());
    }

    #[test]
    fn the_setup_is_described_without_ever_printing_a_key() {
        if std::env::var(crate::ai::API_KEY_ENV).is_ok() {
            return; // the environment would be named as the key's source
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.toml");
        let settings = AiSettings {
            user_file: Some(file.clone()),
            ..AiSettings::default()
        };
        let text = describe(&settings, &file);
        // No service chosen and no key: the cloud AI is off, as the setup
        // screen shows it, not short of a key nobody asked for.
        assert_eq!(
            text,
            format!(
                "AI setup · {}\n\
                 \x20 Local AI         http://localhost:1234/v1\n\
                 \x20 Cloud AI         off\n",
                file.display()
            ),
            "nothing empty is listed"
        );
        // A service chosen, its key not entered yet: that is to act on.
        AiOverrides {
            cloud_provider: Some(CloudProvider::OpenAi),
            ..AiOverrides::default()
        }
        .save(&file)
        .unwrap();
        assert!(
            describe(&settings, &file).ends_with(
                "  Cloud AI         https://openrouter.ai/api/v1\n\
                 \x20 Key              missing · local AI answers instead, no CVE research\n"
            ),
            "{}",
            describe(&settings, &file)
        );

        AiOverrides {
            local_model: Some("llama3.2".into()),
            api_key: Some(GOOD_KEY.into()),
            ..AiOverrides::default()
        }
        .save(&file)
        .unwrap();
        let text = describe(&settings, &file);
        assert!(
            text.contains("  Local AI         http://localhost:1234/v1 · llama3.2\n"),
            "{text}"
        );
        assert!(
            text.contains("  Key              set, ends in 9f3a (in ai.toml)\n"),
            "{text}"
        );
        assert!(
            !text.contains(GOOD_KEY) && !text.contains("sk-test"),
            "{text}"
        );
        // A short key is not even hinted at.
        assert_eq!(masked("abc123"), "set");

        // Cloud AI switched off: one word, and nothing of the unused service.
        AiOverrides {
            disable_cloud: true,
            ..AiOverrides::default()
        }
        .save(&file)
        .unwrap();
        let text = describe(&settings, &file);
        let rows: Vec<&str> = text.lines().skip(1).collect();
        assert_eq!(
            rows,
            [
                "  Local AI         http://localhost:1234/v1",
                "  Cloud AI         off"
            ]
        );
        // A local AI on another machine: where the text goes is said.
        AiOverrides {
            local_url: Some("http://203.0.113.10:1234/v1".into()),
            ..AiOverrides::default()
        }
        .save(&file)
        .unwrap();
        let text = describe(&settings, &file);
        assert!(
            text.contains(
                "  Local AI         http://203.0.113.10:1234/v1\n\
                 \x20                  not this machine: it gets masked text only\n"
            ),
            "{text}"
        );
        // Where a key comes from, in a word or two.
        assert_eq!(key_origin("your setup file"), "in ai.toml");
        assert_eq!(key_origin("config.toml"), "in config.toml");
        assert_eq!(
            key_origin("the OPENROUTER_API_KEY environment variable"),
            "from $OPENROUTER_API_KEY"
        );
    }

    /// `--check` and the setup screen's test: one short line per service,
    /// and a local AI that is not this user's own is said to get masked text.
    #[test]
    fn the_check_says_one_short_line_per_service() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                tx.send(services().await).unwrap();
                std::future::pending::<()>().await
            });
        });
        let base = rx.recv().unwrap();
        let settings = AiSettings {
            local_url: format!("{base}/local/v1"),
            cloud_url: format!("{base}/openrouter/v1"),
            openrouter_api_key: Some(GOOD_KEY.into()),
            user_file: None,
            ..AiSettings::default()
        };
        let said = |settings: &AiSettings| {
            let mut out = Vec::new();
            let works = check(settings, &mut out).unwrap();
            (works, String::from_utf8(out).unwrap())
        };
        {
            let _owner = crate::ai::FakePortOwner::set(None);
            assert_eq!(
                said(&settings),
                (
                    true,
                    format!(
                        "[+] Local AI  {base}/local/v1 · 2 models\n\
                         [+] Cloud AI  {base}/openrouter/v1 · key accepted\n"
                    )
                )
            );
            // No key: skipped, and said so; cloud AI off: one word.
            let no_key = AiSettings {
                openrouter_api_key: None,
                ..settings.clone()
            };
            let (_, text) = said(&no_key);
            assert!(text.ends_with("[!] Cloud AI  skipped: no key\n"), "{text}");
            let off = AiSettings {
                disable_cloud: true,
                ..settings.clone()
            };
            let (works, text) = said(&off);
            assert!(works && text.ends_with("[+] Cloud AI  off\n"), "{text}");
        }
        // Another user's server on this machine: the local AI gets masked
        // text, and the key is not sent at all.
        let _owner = crate::ai::FakePortOwner::set(Some(4242));
        let (works, text) = said(&settings);
        assert!(!works, "{text}");
        let whose = match cfg!(windows) {
            true => "another user's server",
            false => "another user's server (uid 4242)",
        };
        assert_eq!(
            text,
            format!(
                "[+] Local AI  {base}/local/v1 · 2 models · {whose}: masked text only\n\
                 [!] Cloud AI  key not sent to {base}/openrouter/v1: {whose}\n"
            )
        );
        assert!(
            !text.contains(GOOD_KEY) && !text.contains("sk-test"),
            "{text}"
        );
    }

    /// The Claude API: the key, then every model the setup names. A refusal
    /// is said in a few words, without the API's own sentence or the model
    /// twice.
    #[test]
    fn the_check_names_the_claude_models_a_key_is_not_offered() {
        if std::env::var(anthropic::KEY_ENV).is_ok() {
            return; // a key in the environment would be the one checked
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                tx.send(services().await).unwrap();
                std::future::pending::<()>().await
            });
        });
        let base = rx.recv().unwrap();
        let _owner = crate::ai::FakePortOwner::set(None);
        let settings = AiSettings {
            local_url: format!("{base}/local/v1"),
            cloud_url: format!("{base}/claude/v1"),
            cloud_provider: Some(CloudProvider::Anthropic),
            cloud_model: "claude-opus-5-5".into(),
            research_model: "claude-opus-5-5".into(),
            cloud_fallbacks: Some(vec!["claude-opus-4-6".into(), "claude-opus-4-8".into()]),
            openrouter_api_key: Some(CLAUDE_KEY.into()),
            user_file: None,
            ..AiSettings::default()
        };
        let said = |settings: &AiSettings| {
            let mut out = Vec::new();
            let works = check(settings, &mut out).unwrap();
            (works, String::from_utf8(out).unwrap())
        };
        assert_eq!(
            said(&settings),
            (
                false,
                format!(
                    "[+] Local AI  {base}/local/v1 · 2 models\n\
                     [+] Cloud AI  Claude API · key accepted\n\
                     [+] Cloud AI  claude-opus-5-5, claude-opus-4-8 available\n\
                     [!] Cloud AI  claude-opus-4-6 not offered to this key\n"
                )
            )
        );
        let wrong = AiSettings {
            openrouter_api_key: Some("sk-ant-test-wrong-key-0000".into()),
            ..settings
        };
        let (works, text) = said(&wrong);
        assert!(!works);
        assert!(
            text.ends_with("[!] Cloud AI  Claude API refused the key\n"),
            "{text}"
        );
        assert!(!text.contains("sk-ant"), "{text}");
    }

    /// A fresh install: no service chosen and no key. `--check` calls the
    /// cloud AI off, as `--show` and the setup screen do.
    #[test]
    fn a_fresh_install_has_its_cloud_ai_off_not_a_key_missing() {
        if std::env::var(anthropic::KEY_ENV).is_ok()
            || std::env::var(crate::ai::API_KEY_ENV).is_ok()
        {
            return; // a key in the environment is a cloud AI in use
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.toml");
        let settings = AiSettings {
            // Nothing listens there.
            local_url: "http://127.0.0.1:9/v1".into(),
            user_file: Some(file.clone()),
            ..AiSettings::default()
        };
        let said = |settings: &AiSettings| {
            let mut out = Vec::new();
            check(settings, &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        assert_eq!(
            said(&settings),
            "[!] Local AI  no answer at http://127.0.0.1:9/v1\n[+] Cloud AI  off\n"
        );
        assert!(!cloud_in_use(&AiOverrides::default(), false));
        assert!(cloud_in_use(&AiOverrides::default(), true));
        // A service chosen, by name or by URL: its key is what is missing.
        for own in [
            AiOverrides {
                cloud_provider: Some(CloudProvider::OpenAi),
                ..AiOverrides::default()
            },
            AiOverrides {
                cloud_url: Some("https://llm.other-service.example/v1".into()),
                ..AiOverrides::default()
            },
        ] {
            assert!(cloud_in_use(&own, false));
            own.save(&file).unwrap();
            assert!(
                said(&settings).ends_with("[!] Cloud AI  skipped: no key\n"),
                "{}",
                said(&settings)
            );
        }
        // Switched off wins over a key.
        let off = AiOverrides {
            disable_cloud: true,
            api_key: Some(GOOD_KEY.into()),
            ..AiOverrides::default()
        };
        assert!(!cloud_in_use(&off, true));
    }

    #[test]
    fn stdin_keys_and_cli_models_reject_control_chars_and_sanitize_check_output() {
        let base = AiSettings::default();
        for bad_key in ["sk-bad\0key", "sk-bad\rkey", &"k".repeat(513)] {
            let mut own = AiOverrides::default();
            let args = SetupArgs {
                api_key_stdin: true,
                ..SetupArgs::default()
            };
            assert!(
                apply(&args, &base, &mut own, Some(bad_key.to_owned())).is_err(),
                "must reject malformed stdin key len={}",
                bad_key.len()
            );
            assert_eq!(own.api_key, None);
        }

        let mut own = AiOverrides::default();
        let args = SetupArgs {
            local_model: Some("qwen\x1b]2;pwn\x07".into()),
            cloud_model: Some("claude-sonnet\x1b[2J".into()),
            research_model: Some("claude-opus\u{202e}evil".into()),
            provider: Some("claude".into()),
            fallback_models: Some("claude-haiku\x1b[31m, \x1b\x07".into()),
            ..SetupArgs::default()
        };
        let summary = apply(&args, &base, &mut own, None).unwrap().join("\n");
        assert!(!summary.chars().any(|c| c.is_control() && c != '\n'));
        assert_eq!(own.local_model.as_deref(), Some("qwen]2;pwn"));
        assert_eq!(own.cloud_model.as_deref(), Some("claude-sonnet[2J"));
        assert_eq!(own.research_model.as_deref(), Some("claude-opusevil"));
        assert_eq!(
            own.cloud_fallbacks.as_deref(),
            Some(&["claude-haiku[31m".to_owned()][..])
        );

        // `check()` never writes raw escape sequences from tampered settings to the terminal.
        let hostile_settings = AiSettings {
            local_url: "http://127.0.0.1:1/v1\x1b]0;owned\x07".into(),
            local_model: "m\x1b[2J".into(),
            disable_cloud: true,
            user_file: None,
            ..AiSettings::default()
        };
        let mut out = Vec::new();
        let _ = check(&hostile_settings, &mut out).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            !rendered.chars().any(|c| c.is_control() && c != '\n'),
            "{rendered:?}"
        );
    }

    /// A Claude key goes to the Claude API and an OpenRouter key to
    /// OpenRouter, whichever service was set before; one named service's
    /// key is never stored for another.
    #[test]
    fn a_key_with_its_service_in_its_name_goes_to_that_service_only() {
        const CLAUDE: &str = "sk-ant-api03-piped-without-provider-bbbb";
        const OPENROUTER: &str = "sk-or-v1-piped-without-provider-cccc";
        let openrouter = AiSettings::default();
        let claude = AiSettings {
            cloud_url: anthropic::API_URL.into(),
            cloud_provider: Some(CloudProvider::Anthropic),
            ..AiSettings::default()
        };
        let other = AiSettings {
            cloud_url: "https://llm.example.com/v1".into(),
            cloud_provider: Some(CloudProvider::OpenAi),
            ..AiSettings::default()
        };
        let piped = SetupArgs {
            api_key_stdin: true,
            ..SetupArgs::default()
        };
        let chosen = |current: &AiSettings| AiOverrides {
            cloud_url: Some(current.cloud_url.clone()),
            cloud_provider: current.cloud_provider,
            ..AiOverrides::default()
        };
        // Set up for OpenRouter, a Claude key: the Claude API.
        let mut own = chosen(&openrouter);
        let notes = apply(&piped, &openrouter, &mut own, Some(format!("{CLAUDE}\n"))).unwrap();
        assert_eq!(own.cloud_provider, Some(CloudProvider::Anthropic));
        assert_eq!(own.cloud_url.as_deref(), Some(anthropic::API_URL));
        assert_eq!(own.cloud_model.as_deref(), Some(anthropic::DEFAULT_MODEL));
        assert_eq!(own.api_key.as_deref(), Some(CLAUDE));
        assert_eq!(notes, ["[+] Key saved for api.anthropic.com"]);
        // Set up for the Claude API, or another service, an OpenRouter
        // key: OpenRouter, with its own model names.
        for current in [&claude, &other] {
            let mut own = chosen(current);
            let notes = apply(&piped, current, &mut own, Some(OPENROUTER.into())).unwrap();
            assert_eq!(own.cloud_provider, Some(CloudProvider::OpenAi));
            assert_eq!(own.cloud_url, Some(openrouter.cloud_url.clone()));
            assert_eq!(own.api_key.as_deref(), Some(OPENROUTER));
            assert_eq!(notes, ["[+] Key saved for openrouter.ai"]);
            let said = notes.join("\n");
            assert!(!said.contains("cccc"), "{said}");
        }
        // Models named in the same call stay.
        let mut own = chosen(&openrouter);
        let with_models = SetupArgs {
            cloud_model: Some("claude-sonnet-5-5".into()),
            ..piped.clone()
        };
        apply(&with_models, &openrouter, &mut own, Some(CLAUDE.into())).unwrap();
        assert_eq!(own.cloud_model.as_deref(), Some("claude-sonnet-5-5"));
        // A key that does not say whose it is stays with the service set.
        let mut own = chosen(&other);
        let notes = apply(&piped, &other, &mut own, Some(GOOD_KEY.into())).unwrap();
        assert_eq!(own.cloud_url.as_deref(), Some("https://llm.example.com/v1"));
        assert_eq!(notes, ["[+] Key saved for llm.example.com"]);
        // A server on this machine is the user's own: a Claude stand-in
        // there keeps a Claude key.
        let stand_in = AiSettings {
            cloud_url: "http://127.0.0.1:9/v1".into(),
            cloud_provider: Some(CloudProvider::Anthropic),
            ..AiSettings::default()
        };
        let mut own = chosen(&stand_in);
        apply(&piped, &stand_in, &mut own, Some(CLAUDE.into())).unwrap();
        assert_eq!(own.cloud_url.as_deref(), Some("http://127.0.0.1:9/v1"));

        // The other service named in the same call: the key is refused, and
        // nothing is changed.
        for (args, key, said) in [
            (
                SetupArgs {
                    provider: Some("openrouter".into()),
                    ..piped.clone()
                },
                CLAUDE,
                "key refused: it is for api.anthropic.com, not openrouter.ai",
            ),
            (
                SetupArgs {
                    provider: Some("claude".into()),
                    ..piped.clone()
                },
                OPENROUTER,
                "key refused: it is for openrouter.ai, not api.anthropic.com",
            ),
            (
                SetupArgs {
                    cloud_url: Some("https://openrouter.ai/api/v1".into()),
                    ..piped.clone()
                },
                CLAUDE,
                "key refused: it is for api.anthropic.com, not openrouter.ai",
            ),
            (
                SetupArgs {
                    cloud_url: Some("https://API.Anthropic.com/v1".into()),
                    ..piped.clone()
                },
                OPENROUTER,
                "key refused: it is for openrouter.ai, not api.anthropic.com",
            ),
        ] {
            let mut own = chosen(&openrouter);
            let before = own.clone();
            let error = apply(&args, &openrouter, &mut own, Some(key.into())).unwrap_err();
            assert_eq!(format!("{error:#}"), said);
            assert_eq!(own.api_key, before.api_key);
        }
        // Named, on this machine: the user's own server, as they asked.
        let mut own = AiOverrides::default();
        let local = SetupArgs {
            cloud_url: Some("http://127.0.0.1:9/v1".into()),
            ..piped.clone()
        };
        apply(&local, &openrouter, &mut own, Some(CLAUDE.into())).unwrap();
        assert_eq!(own.api_key.as_deref(), Some(CLAUDE));
        // Named, a gateway that passes the service's own key on: kept there,
        // with the protocol named.
        for (provider, url, key, speaks) in [
            (
                Some("claude"),
                "https://gateway.example.com/v1/anthropic",
                CLAUDE,
                CloudProvider::Anthropic,
            ),
            (
                None,
                "https://gateway.example.com/v1/openrouter",
                OPENROUTER,
                CloudProvider::OpenAi,
            ),
        ] {
            let mut own = chosen(&openrouter);
            let gateway = SetupArgs {
                provider: provider.map(Into::into),
                cloud_url: Some(url.into()),
                ..piped.clone()
            };
            let notes = apply(&gateway, &openrouter, &mut own, Some(key.into())).unwrap();
            assert_eq!(own.cloud_url.as_deref(), Some(url));
            assert_eq!(own.cloud_provider, Some(speaks));
            assert_eq!(own.api_key.as_deref(), Some(key));
            assert_eq!(notes, ["[+] Key saved for gateway.example.com"]);
            // Unnamed again, the key picks its own service.
            let current = AiSettings {
                cloud_url: url.into(),
                cloud_provider: Some(speaks),
                ..AiSettings::default()
            };
            let mut again = own.clone();
            apply(&piped, &current, &mut again, Some(key.into())).unwrap();
            assert_ne!(again.cloud_url.as_deref(), Some(url));
        }

        assert!(key_fits(CLAUDE, "https://api.anthropic.com/v1"));
        assert!(!key_fits(CLAUDE, "https://openrouter.ai/api/v1"));
        assert!(key_fits(OPENROUTER, "http://localhost:8080/v1"));
        assert!(!key_fits(OPENROUTER, "https://api.anthropic.com/v1"));
        assert!(!key_fits(OPENROUTER, "https://API.anthropic.com./v1"));
        assert!(key_fits(OPENROUTER, "https://gateway.example.com/v1"));
        assert!(key_fits(CLAUDE, "https://gateway.example.com/v1"));
        assert!(key_fits(GOOD_KEY, "https://llm.example.com/v1"));
        assert!(key_fits(GOOD_KEY, "https://openrouter.ai/api/v1"));
        // The unnamed switch: a key's own service or this machine only.
        assert!(key_belongs(
            CLAUDE,
            CloudProvider::Anthropic,
            anthropic::API_URL
        ));
        assert!(key_belongs(
            CLAUDE,
            CloudProvider::Anthropic,
            "http://[::1]:9/v1"
        ));
        assert!(!key_belongs(
            CLAUDE,
            CloudProvider::Anthropic,
            "https://gateway.example.com/v1"
        ));
        assert!(!key_belongs(
            CLAUDE,
            CloudProvider::OpenAi,
            anthropic::API_URL
        ));
        assert!(key_belongs(
            GOOD_KEY,
            CloudProvider::OpenAi,
            "https://llm.example.com/v1"
        ));
    }

    /// `--cloud-off`: local AI only, also with a key in the environment,
    /// and the stored key goes.
    #[test]
    fn cloud_off_keeps_the_ai_local_and_removes_the_stored_key() {
        let args = SetupArgs {
            cloud_off: true,
            ..SetupArgs::default()
        };
        assert!(args.changes_something());
        let mut own = AiOverrides {
            cloud_url: Some(AiSettings::default().cloud_url),
            cloud_provider: Some(CloudProvider::OpenAi),
            api_key: Some("sk-or-v1-stored-before-off-dddd".into()),
            ..AiOverrides::default()
        };
        let notes = apply(&args, &AiSettings::default(), &mut own, None).unwrap();
        assert_eq!(notes, ["[+] Key removed"]);
        assert!(own.disable_cloud);
        assert_eq!(own.api_key, None);
        // Read back, the cloud AI is off and has no key.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.toml");
        own.save(&file).unwrap();
        let settings = AiSettings {
            user_file: Some(file.clone()),
            ..AiSettings::default()
        };
        let effective = settings.effective();
        assert!(effective.disable_cloud);
        assert_eq!(effective.api_key(), None);
        assert!(describe(&settings, &file).contains("  Cloud AI         off\n"));
        // Again: nothing more to remove, nothing said.
        let notes = apply(&args, &AiSettings::default(), &mut own, None).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        // A key piped in later turns it on again.
        let piped = SetupArgs {
            api_key_stdin: true,
            ..SetupArgs::default()
        };
        apply(
            &piped,
            &AiSettings::default(),
            &mut own,
            Some(GOOD_KEY.into()),
        )
        .unwrap();
        assert!(!own.disable_cloud);

        // With a service or a key in the same call it means nothing.
        for (args, key) in [
            (
                SetupArgs {
                    provider: Some("claude".into()),
                    ..args.clone()
                },
                None,
            ),
            (
                SetupArgs {
                    cloud_url: Some("https://llm.example.com/v1".into()),
                    ..args.clone()
                },
                None,
            ),
            (
                SetupArgs {
                    api_key_stdin: true,
                    ..args.clone()
                },
                Some(GOOD_KEY.to_owned()),
            ),
        ] {
            let mut own = AiOverrides::default();
            let error = apply(&args, &AiSettings::default(), &mut own, key).unwrap_err();
            assert!(format!("{error:#}").starts_with("--cloud-off cannot be used with"));
            assert_eq!(own, AiOverrides::default());
        }
    }
}
