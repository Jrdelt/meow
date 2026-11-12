//! `meow setup`: each user's own AI for meow.
//!
//! meow is a shared tool, so nothing about a particular user's AI is built
//! in: no key, no model server. This command lets everyone point it at their
//! own local model server, or add their own cloud API key, and keeps that in
//! `~/.meow/ai.toml`, which only they can read and which is never part of a
//! repository. A running session uses the new setup for its next request.
//!
//! With flags it is scriptable; without any, on a terminal, it asks.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::ai::{AiOverrides, AiSettings};
use crate::workspace::{Config, MeowHome};

/// Where model servers usually listen on the machine they run on.
const LOCAL_SERVERS: &[(&str, &str)] = &[
    ("http://localhost:1234/v1", "LM Studio"),
    ("http://localhost:11434/v1", "Ollama"),
    ("http://localhost:8080/v1", "llama.cpp"),
];
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// What `meow setup` was asked to do without asking questions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupArgs {
    pub show: bool,
    pub check: bool,
    pub local_url: Option<String>,
    pub local_model: Option<String>,
    pub cloud_url: Option<String>,
    pub cloud_model: Option<String>,
    pub research_model: Option<String>,
    /// Read the API key from standard input. It is never taken from the
    /// command line, where it would end up in the shell history.
    pub api_key_stdin: bool,
    pub forget_key: bool,
}

impl SetupArgs {
    fn changes_something(&self) -> bool {
        self.api_key_stdin
            || self.forget_key
            || [
                &self.local_url,
                &self.local_model,
                &self.cloud_url,
                &self.cloud_model,
                &self.research_model,
            ]
            .iter()
            .any(|value| value.is_some())
    }
}

/// An `http://` or `https://` address of an OpenAI-compatible API, without a
/// trailing slash.
fn checked_url(raw: &str) -> Result<String> {
    let url = raw.trim().trim_end_matches('/');
    let parsed = url::Url::parse(url).with_context(|| format!("'{raw}' is not a URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        bail!("'{raw}' must start with http:// or https://");
    }
    Ok(url.to_owned())
}

/// A key is shown by its last four characters only.
fn masked(key: &str) -> String {
    let tail: String = key
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    match key.chars().count() {
        0..=8 => "set".to_owned(),
        _ => format!("set, ends in {tail}"),
    }
}

/// The current setup in a few lines. Never prints a key.
pub fn describe(settings: &AiSettings, file: &Path) -> String {
    let effective = settings.effective();
    let model = match effective.local_model.as_str() {
        "" => "chosen by the server".to_owned(),
        model => model.to_owned(),
    };
    let key = match (effective.api_key(), settings.key_source()) {
        (Some(key), Some(source)) => format!("{} (from {source})", masked(&key)),
        _ => "not set: [C] answers with the local model, [R] is unavailable".to_owned(),
    };
    format!(
        "Your AI setup ({}):\n\
         \x20 [L] local model    {}, model: {model}\n\
         \x20 [C] cloud triage   {}, model: {}\n\
         \x20 [R] research       model: {}\n\
         \x20 API key            {key}\n",
        file.display(),
        effective.local_url,
        effective.cloud_url,
        effective.cloud_model,
        effective.research_model,
    )
}

fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT * 3)
        .user_agent("security-audit-client")
        .build()
        .context("cannot create the HTTP client")
}

/// The models an OpenAI-compatible server offers (`GET <url>/models`).
/// `Err` says why it could not be asked.
pub async fn list_models(url: &str, key: Option<&str>) -> Result<Vec<String>> {
    let mut request = http()?.get(format!("{}/models", url.trim_end_matches('/')));
    if let Some(key) = key {
        request = request.bearer_auth(key);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) if error.is_connect() => bail!("nothing is listening at {url}"),
        Err(error) if error.is_timeout() => bail!("{url} did not answer in time"),
        Err(error) => return Err(error).with_context(|| format!("cannot reach {url}")),
    };
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        bail!("{url} refused the API key (HTTP {})", status.as_u16());
    }
    if !status.is_success() {
        bail!("{url} answered HTTP {}", status.as_u16());
    }
    let body: Value = response
        .json()
        .await
        .with_context(|| format!("{url} did not answer like an OpenAI-compatible API"))?;
    let models = body
        .get("data")
        .and_then(Value::as_array)
        .with_context(|| format!("{url} did not answer like an OpenAI-compatible API"))?;
    Ok(models
        .iter()
        .filter_map(|model| model.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}

/// Asks the cloud service whether it accepts the key. OpenRouter has an
/// endpoint for exactly that (`/key`); other services are asked for their
/// model list, which needs a valid key.
pub async fn check_key(url: &str, key: &str) -> Result<()> {
    let base = url.trim_end_matches('/');
    let response = http()?
        .get(format!("{base}/key"))
        .bearer_auth(key)
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) if matches!(response.status().as_u16(), 401 | 403) => {
            bail!(
                "{url} refused the API key (HTTP {})",
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
/// says in plain words what happened. Returns whether everything set up
/// works.
fn check(settings: &AiSettings, out: &mut dyn Write) -> Result<bool> {
    let effective = settings.effective();
    let mut works = true;
    match block_on(list_models(&effective.local_url, None))? {
        Ok(models) => writeln!(
            out,
            "[+] [L] {} answers with {} model(s){}",
            effective.local_url,
            models.len(),
            match models.first() {
                Some(first) => format!(", for example {first}"),
                None => String::new(),
            }
        )?,
        Err(error) => {
            works = false;
            writeln!(out, "[!] [L] {error:#}")?;
        }
    }
    match effective.api_key() {
        None => writeln!(out, "[!] [C] no API key set, so it was not tried")?,
        Some(key) => match block_on(check_key(&effective.cloud_url, &key))? {
            Ok(()) => writeln!(out, "[+] [C] {} accepts your API key", effective.cloud_url)?,
            Err(error) => {
                works = false;
                writeln!(out, "[!] [C] {error:#}")?;
            }
        },
    }
    Ok(works)
}

/// Applies the flags to the user's file. Returns what changed, in words.
fn apply(
    args: &SetupArgs,
    own: &mut AiOverrides,
    key_from_stdin: Option<String>,
) -> Result<Vec<String>> {
    let mut changed = Vec::new();
    if let Some(url) = &args.local_url {
        let url = checked_url(url)?;
        changed.push(format!("local model server: {url}"));
        own.local_url = Some(url);
    }
    if let Some(model) = &args.local_model {
        changed.push(match model.trim() {
            "" => "local model: chosen by the server".to_owned(),
            model => format!("local model: {model}"),
        });
        own.local_model = Some(model.trim().to_owned());
    }
    if let Some(url) = &args.cloud_url {
        let url = checked_url(url)?;
        changed.push(format!("cloud service: {url}"));
        own.cloud_url = Some(url);
    }
    for (value, slot, what) in [
        (&args.cloud_model, &mut own.cloud_model, "triage model"),
        (
            &args.research_model,
            &mut own.research_model,
            "research model",
        ),
    ] {
        if let Some(model) = value.as_deref().map(str::trim).filter(|m| !m.is_empty()) {
            changed.push(format!("{what}: {model}"));
            *slot = Some(model.to_owned());
        }
    }
    if args.forget_key {
        own.api_key = None;
        changed.push("API key removed from your setup file".to_owned());
    }
    if let Some(key) = key_from_stdin {
        let key = key.trim().to_owned();
        if key.is_empty() {
            bail!("no API key arrived on standard input");
        }
        changed.push(format!("API key {}", masked(&key)));
        own.api_key = Some(key);
    }
    Ok(changed)
}

/// One line typed by the user, without the line end. `None` at end of input.
fn ask(prompt: &str) -> Result<Option<String>> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let read = std::io::stdin()
        .read_line(&mut line)
        .context("cannot read the answer")?;
    Ok((read > 0).then(|| line.trim().to_owned()))
}

/// Reads a secret from the terminal without showing it. `None` if the user
/// cancelled (Esc, Ctrl-C) or typed nothing.
fn ask_hidden(prompt: &str) -> Result<Option<String>> {
    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::crossterm::terminal;

    print!("{prompt}");
    std::io::stdout().flush().ok();
    terminal::enable_raw_mode().context("cannot switch the terminal to hidden input")?;
    let mut secret = String::new();
    let outcome = loop {
        match event::read() {
            Ok(Event::Key(key)) if key.kind != KeyEventKind::Release => match key.code {
                KeyCode::Enter => break Ok(Some(secret)),
                KeyCode::Esc => break Ok(None),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Ok(None)
                }
                KeyCode::Backspace => {
                    secret.pop();
                }
                KeyCode::Char(ch) => secret.push(ch),
                _ => {}
            },
            Ok(Event::Paste(text)) => secret.push_str(&text),
            Ok(_) => {}
            Err(error) => break Err(error),
        }
    };
    terminal::disable_raw_mode().ok();
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

fn setup_local(settings: &AiSettings, own: &mut AiOverrides) -> Result<bool> {
    println!("Looking for model servers on this machine ...");
    let current = settings.effective().local_url;
    let mut candidates: Vec<(String, &str)> = vec![(current.clone(), "current setting")];
    for (url, name) in LOCAL_SERVERS {
        if !candidates.iter().any(|(known, _)| known == url) {
            candidates.push(((*url).to_owned(), name));
        }
    }
    let mut found: Vec<(String, Vec<String>)> = Vec::new();
    for (url, name) in &candidates {
        if let Ok(models) = block_on(list_models(url, None))? {
            println!(
                "  {}  {url}  ({name}, {} model(s))",
                found.len() + 1,
                models.len()
            );
            found.push((url.clone(), models));
        }
    }
    let urls: Vec<String> = found.iter().map(|(url, _)| url.clone()).collect();
    let prompt = if found.is_empty() {
        println!(
            "  None answered. Start one first (LM Studio: Developer > Start Server; \
             Ollama: `ollama serve`), or type the address of yours."
        );
        "Server address (Enter to go back): ".to_owned()
    } else {
        "Server [1], or type another address: ".to_owned()
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
                println!("[!] {error:#}. Saved all the same; start the server before using [L].");
                Vec::new()
            }
        },
    };
    for (index, model) in models.iter().enumerate().take(30) {
        println!("  {}  {model}", index + 1);
    }
    let model = choose(
        "Model (number or name; Enter lets the server choose): ",
        &models,
        Some(""),
    )?
    .unwrap_or_default();
    own.local_url = Some(url);
    own.local_model = Some(model);
    Ok(true)
}

fn setup_cloud(settings: &AiSettings, own: &mut AiOverrides) -> Result<bool> {
    let effective = settings.effective();
    println!(
        "Any OpenAI-compatible service works for [C]. [R] (research with web search) \
         needs OpenRouter."
    );
    let url = ask(&format!("Service address [{}]: ", effective.cloud_url))?.unwrap_or_default();
    let url = match url.as_str() {
        "" => effective.cloud_url.clone(),
        typed => checked_url(typed)?,
    };
    let Some(key) =
        ask_hidden("Your API key (hidden as you type; Enter to finish, Esc to cancel): ")?
    else {
        println!("Nothing changed.");
        return Ok(false);
    };
    let triage = ask(&format!("Triage model [{}]: ", effective.cloud_model))?.unwrap_or_default();
    let research =
        ask(&format!("Research model [{}]: ", effective.research_model))?.unwrap_or_default();
    own.cloud_url = Some(url);
    own.api_key = Some(key);
    if !triage.is_empty() {
        own.cloud_model = Some(triage);
    }
    if !research.is_empty() {
        own.research_model = Some(research);
    }
    Ok(true)
}

/// The menu shown by a bare `meow setup` on a terminal.
fn interactive(settings: &AiSettings, file: &Path, own: &mut AiOverrides) -> Result<()> {
    println!("meow setup: your own AI for meow. Nothing here is shared with anyone else.\n");
    loop {
        print!("{}", describe(settings, file));
        println!(
            "\n  1  Use a model on this machine (LM Studio, Ollama, llama.cpp, ...)\n\
             \x20 2  Use my own cloud API key (OpenRouter or another service)\n\
             \x20 3  Remove my API key\n\
             \x20 4  Check that it works\n\
             \x20 q  Done"
        );
        let Some(answer) = ask("> ")? else {
            return Ok(());
        };
        let saved = match answer.as_str() {
            "1" => setup_local(settings, own),
            "2" => setup_cloud(settings, own),
            "3" => {
                own.api_key = None;
                Ok(true)
            }
            "4" => check(settings, &mut std::io::stdout()).map(|_| false),
            "q" | "Q" | "" => return Ok(()),
            _ => {
                println!("Type 1, 2, 3, 4 or q.");
                Ok(false)
            }
        };
        match saved {
            Ok(true) => {
                own.save(file)?;
                println!("[+] Saved. A running session uses it for its next request.");
            }
            Ok(false) => {}
            // A mistyped address must not end the whole setup.
            Err(error) => println!("[!] {error:#}"),
        }
        println!();
    }
}

/// Runs `meow setup`.
pub fn run(home: &MeowHome, args: &SetupArgs) -> Result<ExitCode> {
    let settings = Config::load_or_create(home)?.ai;
    let file = home.ai_path();
    let mut own = AiOverrides::load(&file)?;

    if args.changes_something() {
        let key = if args.api_key_stdin {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context("cannot read the API key from standard input")?;
            Some(line)
        } else {
            None
        };
        let changed = apply(args, &mut own, key)?;
        own.save(&file)?;
        for line in &changed {
            println!("[+] {line}");
        }
        println!("[+] Saved to {}", file.display());
    } else if !args.show && !args.check {
        if std::io::stdin().is_terminal() {
            interactive(&settings, &file, &mut own)?;
            return Ok(ExitCode::SUCCESS);
        }
        // Nothing to ask on: show the state and how to change it.
        print!("{}", describe(&settings, &file));
        println!(
            "\nRun `meow setup` in a terminal to change it, or use the flags listed by \
             `meow setup --help`."
        );
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

    /// Three services: a local model server, an OpenRouter-like one with a
    /// `/key` endpoint, and a plain OpenAI-compatible one without it.
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
            .route("/odd/v1/models", get(|| async { "not json" }));
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
            format!("nothing is listening at {dead}")
        );
        let odd = format!("{base}/odd/v1");
        assert!(error(list_models(&odd, None).await)
            .contains("did not answer like an OpenAI-compatible API"));
        assert!(error(list_models(&format!("{base}/nowhere"), None).await).contains("HTTP 404"));

        // OpenRouter-style: the key endpoint answers.
        let openrouter = format!("{base}/openrouter/v1");
        check_key(&openrouter, GOOD_KEY).await.unwrap();
        let refused = format!("{:#}", check_key(&openrouter, "wrong").await.unwrap_err());
        assert_eq!(
            refused,
            format!("{openrouter} refused the API key (HTTP 401)")
        );
        // Any other service: no key endpoint, so its model list decides.
        let plain = format!("{base}/plain/v1");
        check_key(&plain, GOOD_KEY).await.unwrap();
        let refused = format!("{:#}", check_key(&plain, "wrong").await.unwrap_err());
        assert_eq!(refused, format!("{plain} refused the API key (HTTP 401)"));
        // The error never repeats the key.
        assert!(!refused.contains("wrong"));
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
        let changed = apply(&args, &mut own, Some(format!("{GOOD_KEY}\n"))).unwrap();
        assert_eq!(
            changed,
            [
                "local model server: http://localhost:11434/v1",
                "local model: llama3.2",
                "research model: my/research",
                "API key set, ends in 9f3a",
            ],
            "what changed is said in words, and the key only by its ending"
        );
        assert_eq!(
            own,
            AiOverrides {
                local_url: Some("http://localhost:11434/v1".into()),
                local_model: Some("llama3.2".into()),
                cloud_url: None,
                cloud_model: Some("kept/model".into()),
                research_model: Some("my/research".into()),
                api_key: Some(GOOD_KEY.into()),
            }
        );

        // Forgetting the key, and letting the server choose its model.
        let args = SetupArgs {
            forget_key: true,
            local_model: Some(String::new()),
            ..SetupArgs::default()
        };
        apply(&args, &mut own, None).unwrap();
        assert_eq!(
            (own.api_key.as_deref(), own.local_model.as_deref()),
            (None, Some(""))
        );

        // Refused before anything is saved.
        let bad = |args: SetupArgs, key: Option<String>| {
            format!(
                "{:#}",
                apply(&args, &mut AiOverrides::default(), key).unwrap_err()
            )
        };
        let url = |url: &str| SetupArgs {
            local_url: Some(url.into()),
            ..SetupArgs::default()
        };
        assert!(bad(url("ftp://models.example"), None).contains("must start with http://"));
        assert!(bad(url("localhost:1234"), None).contains("must start with http://"));
        assert!(bad(url("not a url"), None).contains("is not a URL"));
        let empty_key = SetupArgs {
            api_key_stdin: true,
            ..SetupArgs::default()
        };
        assert!(bad(empty_key, Some("  \n".into())).contains("no API key arrived"));
        assert!(!SetupArgs::default().changes_something());
        assert!(!SetupArgs {
            show: true,
            check: true,
            ..SetupArgs::default()
        }
        .changes_something());
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
        assert!(text
            .contains("[L] local model    http://localhost:1234/v1, model: chosen by the server"));
        assert!(text.contains("API key            not set: [C] answers with the local model"));

        AiOverrides {
            local_model: Some("llama3.2".into()),
            api_key: Some(GOOD_KEY.into()),
            ..AiOverrides::default()
        }
        .save(&file)
        .unwrap();
        let text = describe(&settings, &file);
        assert!(text.contains("model: llama3.2"), "{text}");
        assert!(
            text.contains("API key            set, ends in 9f3a (from your setup file)"),
            "{text}"
        );
        assert!(
            !text.contains(GOOD_KEY) && !text.contains("sk-test"),
            "{text}"
        );
        // A short key is not even hinted at.
        assert_eq!(masked("abc123"), "set");
    }
}
