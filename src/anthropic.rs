//! Claude through the Anthropic API, for users who bring their own Claude
//! API key (`meow setup`).
//!
//! The API is spoken natively (`POST /v1/messages`) over plain HTTP: there is
//! no official Anthropic SDK for Rust. It is a different protocol from the
//! OpenAI-style one the other cloud services use, so it has its own module.
//!
//! * `[C]` triage streams its reply.
//! * `[R]` research uses Claude's own web search tool, which runs on
//!   Anthropic's side; a turn the server pauses is resumed here.
//! * The API reports tokens, not money, so the cost for the daily budget is
//!   worked out from the list prices below.
//! * A request a safety classifier declines is asked again on the next model
//!   of the user's own fallback chain (by default Opus 5.5, then Opus 4.6,
//!   then Opus 4.8), in exactly that order. With an empty chain the API's own
//!   fallback is used instead (`fallbacks: "default"`). If every model
//!   declines, the refusal is reported as what it is.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::ai::{Allowance, Usage};
use crate::evidence::sanitize;

/// Where the Claude API lives; `/messages` and `/models` hang off it.
pub const API_URL: &str = "https://api.anthropic.com/v1";
pub const API_VERSION: &str = "2026-10-21";
/// The environment variable the Claude API key is conventionally kept in.
pub const KEY_ENV: &str = "ANTHROPIC_API_KEY";
/// What `meow setup` proposes for both cloud tiers with a Claude key.
pub const DEFAULT_MODEL: &str = "claude-opus-5-5";
/// The models asked next, in this order, when the one before declines.
pub const DEFAULT_FALLBACKS: &[&str] = &["claude-opus-4-6", "claude-opus-4-8"];

/// Lets a declined request be re-run server-side on another model.
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
/// Room for the reply and the model's thinking. Deliberately well below the
/// model's limit: this is also the ceiling of what one request can cost.
const MAX_TOKENS: u32 = 16_000;
/// Searches per research request, as the specification sets it.
const MAX_SEARCHES: u32 = 2;
/// A paused research turn is resumed at most this many times.
const MAX_RESUMES: usize = 3;
/// Research is not streamed and may take a few minutes with searches.
const RESEARCH_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_REPLY: usize = 200_000;
/// List price of one web search: $10 per 1,000.
const WEB_SEARCH_USD: f64 = 0.01;

/// List prices in US dollars per million tokens (input, output), as
/// published on 2026-11-03. The first entry whose name the model id starts
/// with applies, so the more specific names come first.
const PRICES: &[(&str, f64, f64)] = &[
    ("claude-fable-5-2", 8.0, 40.0),
    ("claude-mythos-5-2", 8.0, 40.0),
    ("claude-fable-5", 10.0, 50.0),
    ("claude-mythos-5", 10.0, 50.0),
    ("claude-opus-5-5", 4.0, 20.0),
    ("claude-opus-5", 5.0, 25.0),
    ("claude-opus-4", 5.0, 25.0),
    ("claude-sonnet-5", 2.0, 10.0),
    ("claude-sonnet-4", 3.0, 15.0),
    ("claude-haiku-5-5", 0.10, 0.50),
    ("claude-haiku-4", 1.0, 5.0),
];
/// A model this table does not know is priced as the most expensive one, so
/// the daily budget errs on the careful side.
const UNKNOWN_PRICE: (f64, f64) = (10.0, 50.0);

/// Models of the current generations. They take an effort level, the newer
/// web search tool, and (the first group) the server-side fallback.
const WITH_FALLBACK: &[&str] = &[
    "claude-fable-5",
    "claude-mythos-5",
    "claude-opus-5",
    "claude-sonnet-5-5",
];
const CURRENT: &[&str] = &[
    "claude-fable-5",
    "claude-mythos-5",
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-haiku-5-5",
];

fn is_one_of(model: &str, families: &[&str]) -> bool {
    families.iter().any(|family| model.starts_with(family))
}

/// True when `url` is the Claude API itself, whatever the settings say.
pub fn is_claude_api(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|host| host == "api.anthropic.com")
}

/// What `tokens` cost on `model` at list prices.
pub fn cost_usd(model: &str, input_tokens: u64, output_tokens: u64, searches: u32) -> f64 {
    let (input, output) = PRICES
        .iter()
        .find(|(name, _, _)| model.starts_with(name))
        .map_or(UNKNOWN_PRICE, |(_, input, output)| (*input, *output));
    (input_tokens as f64 * input + output_tokens as f64 * output) / 1_000_000.0
        + f64::from(searches) * WEB_SEARCH_USD
}

/// The most one request of `bytes` is likely to cost on `model`: input at
/// three bytes a token (prose runs about four), what every search allowed
/// adds to it, and the whole reply allowance used.
fn most_usd(model: &str, bytes: usize, research: bool) -> f64 {
    /// What the results of one web search add to the input, about.
    const SEARCH_INPUT_TOKENS: u64 = 25_000;
    let searches = if research { MAX_SEARCHES } else { 0 };
    let input = (bytes as u64).div_ceil(3) + u64::from(searches) * SEARCH_INPUT_TOKENS;
    cost_usd(model, input, u64::from(MAX_TOKENS), searches)
}

/// What sending a request of `bytes` costs on `model` before any reply:
/// its input, counted as [`most_usd`] counts it.
fn input_usd(model: &str, bytes: usize) -> f64 {
    cost_usd(model, (bytes as u64).div_ceil(3), 0, 0)
}

/// The request body for one question. Thinking is adaptive (asked for by
/// name, because the 4.x models run without it otherwise); how hard the
/// model works is set with the effort level. `own_chain` is true when meow
/// walks the user's fallback chain itself, so the API's fallback stays off.
fn body(model: &str, research: bool, own_chain: bool, system: &str, messages: &Value) -> Value {
    let mut body = json!({
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": system,
        "messages": messages,
    });
    if is_one_of(model, CURRENT) {
        body["thinking"] = json!({ "type": "adaptive" });
        // Triage is a short, structured answer; research has to weigh
        // sources against each other.
        body["output_config"] = json!({ "effort": if research { "high" } else { "medium" } });
    }
    if !own_chain && is_one_of(model, WITH_FALLBACK) {
        body["fallbacks"] = json!("default");
    }
    if research {
        let tool = if is_one_of(model, CURRENT) {
            "web_search_20260209"
        } else {
            "web_search_20250305"
        };
        body["tools"] = json!([{ "type": tool, "name": "web_search", "max_uses": MAX_SEARCHES }]);
    } else {
        body["stream"] = json!(true);
    }
    body
}

fn validate_api_key(key: &str) -> Result<()> {
    let trimmed = key.trim();
    if trimmed.is_empty() || key.len() > 512 || key.chars().any(char::is_control) {
        bail!("the configured Claude API key is empty or contains control characters");
    }
    Ok(())
}

fn request(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    body: &Value,
) -> Result<reqwest::RequestBuilder> {
    validate_api_key(key)?;
    let mut request = http
        .post(format!("{}/messages", base.trim_end_matches('/')))
        .header("x-api-key", key)
        .header("anthropic-version", API_VERSION)
        .json(body);
    if body.get("fallbacks").is_some() {
        request = request.header("anthropic-beta", FALLBACK_BETA);
    }
    Ok(request)
}

/// How two refusals of the Claude API begin. `meow setup --check` says
/// them in its own few words ([`key_refused`], [`model_unknown`]).
const KEY_REFUSED: &str = "the Claude API did not accept the API key";
const MODEL_UNKNOWN: &str = "the Claude API does not know this model or does not offer it to you";

/// Whether `error` is the Claude API not accepting the key.
pub(crate) fn key_refused(error: &anyhow::Error) -> bool {
    format!("{error:#}").starts_with(KEY_REFUSED)
}

/// Whether `error` is the Claude API not offering a model to the key.
pub(crate) fn model_unknown(error: &anyhow::Error) -> bool {
    format!("{error:#}").starts_with(MODEL_UNKNOWN)
}

/// Sends the request and turns anything but a success into a message a
/// person can act on.
async fn send(request: reqwest::RequestBuilder, base: &str) -> Result<reqwest::Response> {
    crate::ai::check_server(base, crate::ai::Carries::Key)?;
    let mut response = match request.send().await {
        Ok(response) => response,
        Err(error) if error.is_connect() => bail!("cannot connect to the Claude API at {base}"),
        Err(error) if error.is_timeout() => bail!("the Claude API did not answer in time"),
        Err(error) => return Err(error).context("cannot reach the Claude API"),
    };
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let detail = crate::ai::read_error(&mut response).await;
    let error = serde_json::from_str::<Value>(&detail).unwrap_or_default();
    let kind = error.pointer("/error/type").and_then(Value::as_str);
    let message = error
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or(&detail);
    let message = sanitize(message, 300);
    match kind.unwrap_or_default() {
        "authentication_error" => bail!("{KEY_REFUSED} (run `meow setup`): {message}"),
        "billing_error" => bail!("the Claude API reports a billing problem: {message}"),
        "permission_error" => bail!("this API key may not do that: {message}"),
        "not_found_error" => bail!("{MODEL_UNKNOWN}: {message}"),
        "rate_limit_error" => bail!("the Claude API is rate limiting this key; try again shortly"),
        "overloaded_error" => bail!("the Claude API is overloaded right now; try again shortly"),
        _ => bail!(
            "the Claude API answered HTTP {}: {message}",
            status.as_u16()
        ),
    }
}

/// Every model that was asked declined. That is an answer, not a failure
/// of the connection.
fn refusal(asked: &[&str], category: Option<&str>) -> anyhow::Error {
    let who = match asked {
        [only] => format!("{only} declined this request"),
        all => format!("{} all declined this request", all.join(", ")),
    };
    match category {
        Some("cyber") => anyhow::anyhow!(
            "{who} (category: cyber). For defensive security work, Anthropic's Cyber \
             Verification Program can lift this for your organization"
        ),
        Some(category) => anyhow::anyhow!("{who} (category: {category})"),
        None => anyhow::anyhow!("{who}"),
    }
}

/// What one model made of the question.
struct Attempt {
    text: String,
    /// `Some` when a safety classifier declined; inside, its category.
    declined: Option<Option<String>>,
}

fn category(details: Option<&Value>) -> Option<String> {
    details
        .and_then(|d| d.get("category"))
        .and_then(Value::as_str)
        .map(|c| sanitize(c, 80))
        .filter(|c| !c.is_empty())
}

/// Token counts as the API reports them, kept up to date over a stream.
#[derive(Default)]
struct Counts {
    input: u64,
    output: u64,
    searches: u32,
    /// The model that answered, which is not the requested one after a
    /// fallback.
    model: Option<String>,
}

impl Counts {
    fn set_model(&mut self, value: Option<&str>) {
        if let Some(clean) = value.map(|m| sanitize(m, 120)).filter(|m| !m.is_empty()) {
            self.model = Some(clean);
        }
    }

    fn read(&mut self, usage: &Value) {
        let number = |key: &str| usage.get(key).and_then(Value::as_u64);
        // Cached input is input all the same; meow does not cache prompts,
        // so pricing it in full never understates the cost.
        let cached = number("cache_creation_input_tokens")
            .unwrap_or(0)
            .saturating_add(number("cache_read_input_tokens").unwrap_or(0));
        if let Some(input) = number("input_tokens") {
            self.input = self.input.max(input.saturating_add(cached));
        }
        if let Some(output) = number("output_tokens") {
            self.output = self.output.max(output);
        }
        let searches = usage
            .pointer("/server_tool_use/web_search_requests")
            .and_then(Value::as_u64);
        if let Some(searches) = searches {
            let capped = searches.min(u64::from(u32::MAX)) as u32;
            self.searches = self.searches.max(capped);
        }
    }

    fn usage(&self, requested: &str) -> Usage {
        let model = self.model.as_deref().unwrap_or(requested);
        Usage {
            cost_usd: cost_usd(model, self.input, self.output, self.searches),
            web_search_requests: self.searches,
            prompt_tokens: self.input,
            completion_tokens: self.output,
        }
    }

    /// The model that answered: the requested one unless the API's own
    /// fallback stepped in.
    fn answered_by(&self, requested: &str) -> String {
        self.model.as_deref().unwrap_or(requested).to_owned()
    }
}

fn append_bounded_utf8<'a>(target: &mut String, piece: &'a str, max: usize) -> &'a str {
    let remaining = max.saturating_sub(target.len());
    if remaining == 0 {
        return "";
    }
    if piece.len() <= remaining {
        target.push_str(piece);
        return piece;
    }
    let mut end = remaining;
    while !piece.is_char_boundary(end) {
        end -= 1;
    }
    let prefix = &piece[..end];
    target.push_str(prefix);
    prefix
}

fn sanitize_source_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 500
        || trimmed.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || crate::evidence::is_hidden(c)
                || matches!(c, '<' | '>' | '`')
        })
    {
        return None;
    }
    let parsed = url::Url::parse(trimmed).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    Some(trimmed.to_owned())
}

/// `[C]`: one streamed reply. `on_text` receives each piece as it arrives.
#[allow(clippy::too_many_arguments)]
async fn triage(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    model: &str,
    own_chain: bool,
    system: &str,
    user: &str,
    on_text: &mut (dyn FnMut(&str) + Send),
    counts: &mut Counts,
    allowance: &mut Allowance,
    spent: f64,
) -> Result<Attempt> {
    let messages = json!([{ "role": "user", "content": user }]);
    let body = body(model, false, own_chain, system, &messages);
    let request = request(http, base, key, &body)?;
    let bytes = body.to_string().len();
    allowance.take_call(
        spent,
        most_usd(model, bytes, false),
        input_usd(model, bytes),
    )?;
    let mut response = send(request, base).await?;
    if let Some(len) = response.content_length() {
        if len > crate::ai::MAX_ANSWER_BYTES as u64 {
            bail!(
                "the reply is larger than the {} MB meow reads",
                crate::ai::MAX_ANSWER_BYTES / (1024 * 1024)
            );
        }
    }

    let mut text = String::new();
    let mut truncated = false;
    let mut stop = String::new();
    let mut stop_details = None;
    let mut lines = crate::ai::StreamLines::default();
    while let Some(chunk) = response.chunk().await.context("the reply was cut off")? {
        lines.push(&chunk)?;
        while let Some(line) = lines.next_line()? {
            let Some(data) = line.strip_prefix("data:") else {
                continue; // `event:` lines and keep-alives
            };
            let Ok(event) = serde_json::from_str::<Value>(data.trim()) else {
                continue;
            };
            match event
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
            {
                "message_start" => {
                    if let Some(message) = event.get("message") {
                        counts.set_model(message.get("model").and_then(Value::as_str));
                        counts.read(message.get("usage").unwrap_or(&Value::Null));
                    }
                }
                "content_block_delta" => {
                    // Only the answer is shown; thinking stays with the model.
                    let piece = event
                        .pointer("/delta/text")
                        .and_then(Value::as_str)
                        .filter(|_| event.pointer("/delta/type") == Some(&json!("text_delta")));
                    if let Some(piece) = piece {
                        if !truncated {
                            let clean_piece = crate::ai::sanitize_model_chunk(piece);
                            let added = append_bounded_utf8(&mut text, &clean_piece, MAX_REPLY);
                            if !added.is_empty() {
                                on_text(added);
                            }
                            if added.len() < clean_piece.len() {
                                truncated = true;
                            }
                        }
                    }
                }
                "message_delta" => {
                    counts.read(event.get("usage").unwrap_or(&Value::Null));
                    if let Some(reason) =
                        event.pointer("/delta/stop_reason").and_then(Value::as_str)
                    {
                        stop = reason.to_owned();
                    }
                    let details = event
                        .pointer("/delta/stop_details")
                        .or_else(|| event.get("stop_details"));
                    if let Some(details) = details.filter(|d| !d.is_null()) {
                        stop_details = Some(details.clone());
                    }
                }
                "error" => {
                    let message = event
                        .pointer("/error/message")
                        .and_then(Value::as_str)
                        .unwrap_or("no reason given");
                    bail!("the Claude API reported: {}", sanitize(message, 300));
                }
                _ => {}
            }
        }
    }
    let declined = (stop == "refusal").then(|| category(stop_details.as_ref()));
    if stop == "max_tokens" && !truncated {
        let note = "\n\n[The reply was cut off at the length limit.]";
        let added = append_bounded_utf8(&mut text, note, MAX_REPLY);
        if !added.is_empty() {
            on_text(added);
        }
    }
    Ok(Attempt { text, declined })
}

/// `[R]`: one researched reply, with Claude searching the web on
/// Anthropic's side. Not streamed: a paused turn has to be sent back whole.
#[allow(clippy::too_many_arguments)]
async fn research(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    model: &str,
    own_chain: bool,
    system: &str,
    user: &str,
    counts: &mut Counts,
    allowance: &mut Allowance,
    spent: f64,
) -> Result<Attempt> {
    const MAX_RESUME_MESSAGES_BYTES: usize = 2 * 1024 * 1024;
    const MAX_SOURCES: usize = 12;
    let mut messages = vec![json!({ "role": "user", "content": user })];
    let mut text = String::new();
    let mut truncated = false;
    let mut sources: Vec<String> = Vec::new();
    for _ in 0..=MAX_RESUMES {
        let body = body(model, true, own_chain, system, &json!(messages));
        let request = request(http, base, key, &body)?.timeout(RESEARCH_TIMEOUT);
        // A resumed turn is a request of its own, billed again.
        let so_far = spent + counts.usage(model).cost_usd;
        let bytes = body.to_string().len();
        allowance.take_call(
            so_far,
            most_usd(model, bytes, true),
            input_usd(model, bytes),
        )?;
        let mut response = send(request, base).await?;
        let body = crate::ai::read_bounded(&mut response, crate::ai::MAX_ANSWER_BYTES).await?;
        let reply: Value =
            serde_json::from_slice(&body).context("the Claude API sent invalid JSON")?;
        counts.set_model(reply.get("model").and_then(Value::as_str));
        // Usage is per request; a resumed turn adds to what came before.
        let mut this = Counts::default();
        this.read(reply.get("usage").unwrap_or(&Value::Null));
        counts.input = counts.input.saturating_add(this.input);
        counts.output = counts.output.saturating_add(this.output);
        counts.searches = counts.searches.saturating_add(this.searches);

        let stop = reply
            .get("stop_reason")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if stop == "refusal" {
            return Ok(Attempt {
                text: String::new(),
                declined: Some(category(reply.get("stop_details"))),
            });
        }
        let blocks = reply
            .get("content")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for block in &blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if !truncated {
                        let piece = block.get("text").and_then(Value::as_str).unwrap_or("");
                        let clean_piece = crate::ai::sanitize_model_chunk(piece);
                        let added = append_bounded_utf8(&mut text, &clean_piece, MAX_REPLY);
                        if added.len() < clean_piece.len() {
                            truncated = true;
                        }
                    }
                }
                // A list is results; an object there is an error, which the
                // model has already been told about.
                Some("web_search_tool_result") => {
                    let results = block.get("content").and_then(Value::as_array);
                    for result in results.into_iter().flatten() {
                        if sources.len() >= MAX_SOURCES {
                            break;
                        }
                        let url = result.get("url").and_then(Value::as_str);
                        let title = result.get("title").and_then(Value::as_str);
                        if let Some(line) = source_line(title, url) {
                            if !sources.contains(&line) {
                                sources.push(line);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if stop != "pause_turn" {
            if stop == "max_tokens" && !truncated {
                let note = "\n\n[The reply was cut off at the length limit.]";
                let _ = append_bounded_utf8(&mut text, note, MAX_REPLY);
            }
            break;
        }
        if truncated {
            break;
        }
        // The server stopped mid-turn: send its own blocks back unchanged
        // and it carries on from there. No extra "continue" message.
        messages.push(json!({ "role": "assistant", "content": blocks }));
        if serde_json::to_vec(&messages).is_ok_and(|raw| raw.len() > MAX_RESUME_MESSAGES_BYTES) {
            break;
        }
    }
    if !sources.is_empty() {
        let footer = format!(
            "\n\nSources consulted:\n{}",
            sources[..sources.len().min(MAX_SOURCES)].join("\n")
        );
        if footer.len() < MAX_REPLY {
            crate::ai::cut(&mut text, MAX_REPLY - footer.len());
            text.push_str(&footer);
        }
    }
    crate::ai::cut(&mut text, MAX_REPLY);
    Ok(Attempt {
        text,
        declined: None,
    })
}

/// One line of the list of pages a search read. The title is whatever the
/// page calls itself, the address whatever the search returned: neither may
/// bring Markdown, a placeholder or anything but a web address into the
/// reply, which meow then unmasks and saves.
fn source_line(title: Option<&str>, url: Option<&str>) -> Option<String> {
    let plain = |text: &str, max: usize| -> String {
        crate::evidence::sanitize(text, max)
            .chars()
            .filter(|c| {
                !matches!(
                    c,
                    '<' | '>' | '[' | ']' | '(' | ')' | '!' | '`' | '|' | '\\'
                )
            })
            .collect::<String>()
            .trim()
            .to_owned()
    };
    let url = sanitize_source_url(url?)?;
    let title = title.map(|t| plain(t, 200)).filter(|t| !t.is_empty());
    Some(format!(
        "- {}: `{url}`",
        title.as_deref().unwrap_or("source")
    ))
}

/// What came back from the Claude API for one question.
pub struct Answer {
    pub text: String,
    /// Everything that was spent on it, declined attempts included.
    pub usage: Usage,
    /// The model that answered.
    pub model: String,
}

/// Asks Claude one question. `model` is asked first; if a safety classifier
/// declines, each model of `fallbacks` is asked in turn. `on_text` receives
/// the reply as it arrives (in one piece for research).
#[allow(clippy::too_many_arguments)]
pub async fn ask(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    model: &str,
    fallbacks: &[String],
    research_tier: bool,
    system: &str,
    user: &str,
    on_text: &mut (dyn FnMut(&str) + Send),
) -> Result<Answer> {
    let mut spent = Usage::default();
    ask_with_spend(
        http,
        base,
        key,
        model,
        fallbacks,
        research_tier,
        system,
        user,
        on_text,
        &mut spent,
    )
    .await
}

/// Like [`ask`], but writes accumulated `Usage` into `spent` after each
/// attempt (including partial multi-turn or mid-stream failures) so billed
/// tokens and web searches are never lost when an attempt declines or errors.
#[allow(clippy::too_many_arguments)]
pub async fn ask_with_spend(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    model: &str,
    fallbacks: &[String],
    research_tier: bool,
    system: &str,
    user: &str,
    on_text: &mut (dyn FnMut(&str) + Send),
    spent: &mut Usage,
) -> Result<Answer> {
    ask_with_spend_and_reset(
        http,
        base,
        key,
        model,
        fallbacks,
        research_tier,
        system,
        user,
        on_text,
        &mut || {},
        &mut Allowance::unlimited(),
        spent,
    )
    .await
}

/// Like [`ask_with_spend`], invoking `on_reset` between declined attempts so
/// stateful stream unmaskers never carry unclosed Markdown/HTML state from a
/// declined model into the next fallback model. Every request it makes (a
/// model after one declined, a resumed research turn) is first checked
/// against `allowance`, the day's budget, and counted there.
#[allow(clippy::too_many_arguments)]
pub async fn ask_with_spend_and_reset(
    http: &reqwest::Client,
    base: &str,
    key: &str,
    model: &str,
    fallbacks: &[String],
    research_tier: bool,
    system: &str,
    user: &str,
    on_text: &mut (dyn FnMut(&str) + Send),
    on_reset: &mut (dyn FnMut() + Send),
    allowance: &mut Allowance,
    spent: &mut Usage,
) -> Result<Answer> {
    let mut chain: Vec<&str> = vec![model];
    for next in fallbacks {
        if !chain.contains(&next.as_str()) && !next.trim().is_empty() {
            chain.push(next);
        }
    }
    let own_chain = chain.len() > 1;
    let mut last_category = None;
    for (index, current) in chain.iter().enumerate() {
        let mut counts = Counts::default();
        let so_far = spent.cost_usd;
        let result = if research_tier {
            research(
                http,
                base,
                key,
                current,
                own_chain,
                system,
                user,
                &mut counts,
                allowance,
                so_far,
            )
            .await
        } else {
            triage(
                http,
                base,
                key,
                current,
                own_chain,
                system,
                user,
                on_text,
                &mut counts,
                allowance,
                so_far,
            )
            .await
        };
        let usage = counts.usage(current);
        spent.cost_usd += usage.cost_usd;
        spent.web_search_requests = spent
            .web_search_requests
            .saturating_add(usage.web_search_requests);
        spent.prompt_tokens = spent.prompt_tokens.saturating_add(usage.prompt_tokens);
        spent.completion_tokens = spent
            .completion_tokens
            .saturating_add(usage.completion_tokens);
        let attempt = result?;
        let Some(category) = attempt.declined else {
            if research_tier {
                on_text(&attempt.text);
            }
            return Ok(Answer {
                text: attempt.text,
                usage: *spent,
                model: counts.answered_by(current),
            });
        };
        last_category = category;
        on_reset();
        // What a model wrote before it stopped is not the answer.
        if let Some(next) = chain.get(index + 1) {
            if !attempt.text.is_empty() {
                on_text(&format!(
                    "\n\n[{current} stopped here and declined; asking {next} instead.]\n\n"
                ));
            }
        }
    }
    Err(refusal(&chain, last_category.as_deref()))
}

fn validate_model_id(model: &str) -> Result<()> {
    if model.is_empty()
        || model.len() > 128
        || matches!(model, "." | "..")
        || !model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
    {
        bail!("refusing invalid model id '{model}'");
    }
    Ok(())
}

/// The models this key may use (`GET /v1/models`); also the way to find out
/// whether the API accepts the key at all.
pub async fn list_models(http: &reqwest::Client, base: &str, key: &str) -> Result<Vec<String>> {
    validate_api_key(key)?;
    let request = http
        .get(format!("{}/models", base.trim_end_matches('/')))
        .header("x-api-key", key)
        .header("anthropic-version", API_VERSION);
    let mut response = send(request, base).await?;
    let body = crate::ai::read_bounded(&mut response, crate::ai::MAX_ANSWER_BYTES).await?;
    let reply: Value = serde_json::from_slice(&body).context("the Claude API sent invalid JSON")?;
    let models = reply.get("data").and_then(Value::as_array);
    Ok(models
        .into_iter()
        .flatten()
        .filter_map(|model| model.get("id").and_then(Value::as_str))
        .map(|id| sanitize(id, 120))
        .filter(|id| !id.is_empty())
        .take(500)
        .collect())
}

/// Whether this key is offered `model` (`GET /v1/models/{id}`).
pub async fn has_model(http: &reqwest::Client, base: &str, key: &str, model: &str) -> Result<()> {
    validate_api_key(key)?;
    validate_model_id(model)?;
    let request = http
        .get(format!("{}/models/{model}", base.trim_end_matches('/')))
        .header("x-api-key", key)
        .header("anthropic-version", API_VERSION);
    send(request, base).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::sync::{Arc, Mutex};

    const KEY: &str = "sk-ant-test-their-own-key";

    /// One request as the stand-in API received it.
    #[derive(Clone)]
    struct Sent {
        key: String,
        version: String,
        beta: Option<String>,
        body: Value,
    }

    /// Everything the stand-in has been sent so far, as a copy: the lock is
    /// released before any test awaits again.
    fn sent(mock: &Mock) -> Vec<Sent> {
        mock.requests.lock().unwrap().clone()
    }

    /// A stand-in for the Claude API that records what it is sent.
    #[derive(Default)]
    struct Mock {
        requests: Mutex<Vec<Sent>>,
        /// Models that decline every request, with the category they give.
        declining: Mutex<Vec<(String, &'static str)>>,
        /// Text a declining model writes before it stops (a mid-stream stop).
        partial: Mutex<Option<&'static str>>,
    }

    fn header(headers: &HeaderMap, name: &str) -> Option<String> {
        headers.get(name).map(|v| v.to_str().unwrap().to_owned())
    }

    fn sse(events: &[Value]) -> Response {
        let mut body = String::new();
        for event in events {
            let name = event["type"].as_str().unwrap();
            body.push_str(&format!("event: {name}\ndata: {event}\n\n"));
        }
        ([("content-type", "text/event-stream")], body).into_response()
    }

    async fn messages(
        State(mock): State<Arc<Mock>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        let key = header(&headers, "x-api-key").unwrap_or_default();
        mock.requests.lock().unwrap().push(Sent {
            key: key.clone(),
            version: header(&headers, "anthropic-version").unwrap_or_default(),
            beta: header(&headers, "anthropic-beta"),
            body: body.clone(),
        });
        if key != KEY {
            let error = json!({ "type": "error", "error": {
                "type": "authentication_error", "message": "invalid x-api-key" } });
            return (StatusCode::UNAUTHORIZED, Json(error)).into_response();
        }
        let model = body["model"].as_str().unwrap().to_owned();
        let declines = mock.declining.lock().unwrap().clone();
        let declined = declines.iter().find(|(name, _)| *name == model);
        let streamed = body["stream"] == true;
        let start = json!({ "type": "message_start", "message": {
            "model": model, "usage": { "input_tokens": 1000, "output_tokens": 1 } } });

        if let Some((_, category)) = declined {
            let details = json!({ "type": "refusal", "category": category });
            if !streamed {
                return Json(
                    json!({ "model": model, "content": [], "stop_reason": "refusal",
                    "stop_details": details,
                    "usage": { "input_tokens": 1000, "output_tokens": 0 } }),
                )
                .into_response();
            }
            let mut events = vec![start];
            if let Some(text) = *mock.partial.lock().unwrap() {
                events.push(json!({ "type": "content_block_delta", "index": 0,
                    "delta": { "type": "text_delta", "text": text } }));
            }
            events.push(json!({ "type": "message_delta",
                "delta": { "stop_reason": "refusal", "stop_details": details },
                "usage": { "output_tokens": 10 } }));
            return sse(&events);
        }

        if streamed {
            return sse(&[
                start,
                json!({ "type": "ping" }),
                // Thinking is the model's own; it must never reach the reader.
                json!({ "type": "content_block_delta", "index": 0,
                    "delta": { "type": "thinking_delta", "thinking": "SECRET REASONING" } }),
                json!({ "type": "content_block_delta", "index": 1,
                    "delta": { "type": "text_delta", "text": "## 1. Risk\nPatch " } }),
                json!({ "type": "content_block_delta", "index": 1,
                    "delta": { "type": "text_delta", "text": "nginx now." } }),
                json!({ "type": "message_delta", "delta": { "stop_reason": "end_turn" },
                    "usage": { "output_tokens": 2000 } }),
                json!({ "type": "message_stop" }),
            ]);
        }

        // Research: the first request is paused mid-turn after one search.
        let search = json!({ "type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search",
            "input": { "query": "nginx 1.18.0 advisory" } });
        let results = json!({ "type": "web_search_tool_result", "tool_use_id": "srvtoolu_1",
            "content": [
                { "type": "web_search_result", "title": "nginx security advisories",
                  "url": "https://nginx.org/en/security_advisories.html" },
                { "type": "web_search_result", "title": "NVD",
                  "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017" } ] });
        if body["messages"].as_array().unwrap().len() == 1 {
            return Json(json!({ "model": model, "stop_reason": "pause_turn",
                "content": [ { "type": "text", "text": "Looking it up. " }, search, results ],
                "usage": { "input_tokens": 3000, "output_tokens": 500,
                           "server_tool_use": { "web_search_requests": 1 } } }))
            .into_response();
        }
        let failed = json!({ "type": "web_search_tool_result", "tool_use_id": "srvtoolu_2",
            "content": { "type": "web_search_tool_result_error", "error_code": "max_uses_exceeded" } });
        Json(json!({ "model": model, "stop_reason": "end_turn",
            "content": [ failed, { "type": "text", "text": "Fixed in 1.20.1." } ],
            "usage": { "input_tokens": 4000, "output_tokens": 1500,
                       "server_tool_use": { "web_search_requests": 1 } } }))
        .into_response()
    }

    async fn model(Path(id): Path<String>, headers: HeaderMap) -> Response {
        if header(&headers, "x-api-key").as_deref() != Some(KEY) {
            let error = json!({ "type": "error", "error": {
                "type": "authentication_error", "message": "invalid x-api-key" } });
            return (StatusCode::UNAUTHORIZED, Json(error)).into_response();
        }
        if id.starts_with("claude-opus") {
            return Json(json!({ "id": id, "type": "model" })).into_response();
        }
        let error = json!({ "type": "error", "error": {
            "type": "not_found_error", "message": format!("model: {id}") } });
        (StatusCode::NOT_FOUND, Json(error)).into_response()
    }

    async fn claude_api() -> (String, Arc<Mock>) {
        let mock = Arc::new(Mock::default());
        let models = |headers: HeaderMap| async move {
            if header(&headers, "x-api-key").as_deref() != Some(KEY) {
                let error = json!({ "type": "error", "error": {
                    "type": "authentication_error", "message": "invalid x-api-key" } });
                return (StatusCode::UNAUTHORIZED, Json(error)).into_response();
            }
            Json(json!({ "data": [ { "id": "claude-opus-5-5" }, { "id": "claude-opus-4-6" } ] }))
                .into_response()
        };
        let app = Router::new()
            .route("/v1/messages", post(messages))
            .route("/v1/models", get(models))
            .route("/v1/models/{id}", get(model))
            .with_state(Arc::clone(&mock));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, mock)
    }

    fn chain(models: &[&str]) -> Vec<String> {
        models.iter().map(|m| (*m).to_owned()).collect()
    }

    /// Runs one question and returns the answer with everything shown.
    async fn run(
        base: &str,
        key: &str,
        fallbacks: &[String],
        research: bool,
    ) -> (Result<Answer>, String) {
        let http = reqwest::Client::new();
        let mut shown = String::new();
        let mut show = |piece: &str| shown.push_str(piece);
        let answer = ask(
            &http,
            base,
            key,
            DEFAULT_MODEL,
            fallbacks,
            research,
            "You are a careful analyst.",
            "{\"untrusted_scan_data\":\"x\"}",
            &mut show,
        )
        .await;
        (answer, shown)
    }

    #[tokio::test]
    async fn triage_speaks_the_claude_api_and_streams_only_the_answer() {
        let (base, mock) = claude_api().await;
        let (answer, shown) = run(&base, KEY, &chain(DEFAULT_FALLBACKS), false).await;
        let answer = answer.unwrap();
        assert_eq!(answer.text, "## 1. Risk\nPatch nginx now.");
        assert_eq!(shown, answer.text, "thinking is never shown");
        assert_eq!(answer.model, "claude-opus-5-5");
        // 1,000 tokens in and 2,000 out on Opus 5.5 at $4 / $20 per million.
        assert!(
            (answer.usage.cost_usd - 0.044).abs() < 1e-9,
            "{}",
            answer.usage.cost_usd
        );
        assert_eq!(
            (answer.usage.prompt_tokens, answer.usage.completion_tokens),
            (1000, 2000)
        );

        let requests = sent(&mock);
        assert_eq!(
            requests.len(),
            1,
            "the first model answered: nobody else is asked"
        );
        let Sent {
            key,
            version,
            beta,
            body,
        } = &requests[0];
        assert_eq!((key.as_str(), version.as_str()), (KEY, "2026-10-21"));
        assert_eq!(
            *body,
            json!({
                "model": "claude-opus-5-5",
                "max_tokens": 16000,
                "system": "You are a careful analyst.",
                "messages": [ { "role": "user", "content": "{\"untrusted_scan_data\":\"x\"}" } ],
                "thinking": { "type": "adaptive" },
                "output_config": { "effort": "medium" },
                "stream": true,
            }),
            "no sampling parameters, no prefill, the system prompt at the top level"
        );
        // meow walks the user's chain itself, so the API's fallback is off.
        assert_eq!(*beta, None);
    }

    #[tokio::test]
    async fn a_declined_request_goes_down_the_users_chain_in_order() {
        let (base, mock) = claude_api().await;
        *mock.declining.lock().unwrap() = vec![
            ("claude-opus-5-5".to_owned(), "cyber"),
            ("claude-opus-4-6".to_owned(), "cyber"),
        ];
        let (answer, shown) = run(&base, KEY, &chain(DEFAULT_FALLBACKS), false).await;
        let answer = answer.unwrap();
        let asked: Vec<String> = sent(&mock)
            .iter()
            .map(|sent| sent.body["model"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            asked,
            ["claude-opus-5-5", "claude-opus-4-6", "claude-opus-4-8"],
            "Opus 5.5 first, then 4.6, then 4.8"
        );
        assert_eq!(answer.model, "claude-opus-4-8");
        assert_eq!(answer.text, "## 1. Risk\nPatch nginx now.");
        assert_eq!(
            shown, answer.text,
            "nothing was written before the declines"
        );
        // Two declined attempts and the answer are all paid for.
        let declined =
            cost_usd("claude-opus-5-5", 1000, 10, 0) + cost_usd("claude-opus-4-6", 1000, 10, 0);
        let answered = cost_usd("claude-opus-4-8", 1000, 2000, 0);
        assert!((answer.usage.cost_usd - declined - answered).abs() < 1e-9);
        // The 4.x models think only when asked to.
        let requests = sent(&mock);
        assert_eq!(requests[1].body["thinking"], json!({ "type": "adaptive" }));
        assert!(requests
            .iter()
            .all(|sent| sent.beta.is_none() && sent.body.get("fallbacks").is_none()));

        // A model that stops mid-answer: what it wrote is marked, not passed
        // off as the answer.
        mock.requests.lock().unwrap().clear();
        *mock.declining.lock().unwrap() = vec![("claude-opus-5-5".to_owned(), "cyber")];
        *mock.partial.lock().unwrap() = Some("The first step is");
        let (answer, shown) = run(&base, KEY, &chain(DEFAULT_FALLBACKS), false).await;
        let answer = answer.unwrap();
        assert_eq!(answer.model, "claude-opus-4-6");
        assert_eq!(answer.text, "## 1. Risk\nPatch nginx now.");
        assert_eq!(
            shown,
            "The first step is\n\n[claude-opus-5-5 stopped here and declined; asking \
             claude-opus-4-6 instead.]\n\n## 1. Risk\nPatch nginx now."
        );

        // Every model declines: said plainly, with all of them named.
        *mock.partial.lock().unwrap() = None;
        *mock.declining.lock().unwrap() = vec![
            ("claude-opus-5-5".to_owned(), "cyber"),
            ("claude-opus-4-6".to_owned(), "cyber"),
            ("claude-opus-4-8".to_owned(), "bio"),
        ];
        let (answer, _) = run(&base, KEY, &chain(DEFAULT_FALLBACKS), false).await;
        let error = format!("{:#}", answer.err().unwrap());
        assert_eq!(
            error,
            "claude-opus-5-5, claude-opus-4-6, claude-opus-4-8 all declined this request \
             (category: bio)"
        );
    }

    #[tokio::test]
    async fn without_a_chain_the_api_picks_the_fallback() {
        let (base, mock) = claude_api().await;
        let (answer, _) = run(&base, KEY, &[], false).await;
        answer.unwrap();
        let requests = sent(&mock);
        let Sent { beta, body, .. } = &requests[0];
        assert_eq!(body["fallbacks"], "default");
        assert_eq!(beta.as_deref(), Some("server-side-fallback-2026-07-01"));

        // And then a refusal is the end of it.
        *mock.declining.lock().unwrap() = vec![("claude-opus-5-5".to_owned(), "cyber")];
        let (answer, _) = run(&base, KEY, &[], false).await;
        let error = format!("{:#}", answer.err().unwrap());
        assert!(
            error.starts_with("claude-opus-5-5 declined this request (category: cyber)."),
            "{error}"
        );
        assert!(error.contains("Cyber Verification Program"), "{error}");
        // The same model named twice is asked once.
        mock.requests.lock().unwrap().clear();
        let (answer, _) = run(&base, KEY, &chain(&["claude-opus-5-5", " "]), false).await;
        assert!(answer.is_err());
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_search_result_brings_no_markdown_placeholder_or_odd_address_into_the_reply() {
        let line = source_line(
            Some("![s](https://collector.example/p.png?a=<<SEC_01>>&h=<<HOST_01>>) `x` | y"),
            Some("https://example.org/advisory"),
        )
        .unwrap();
        assert!(line.ends_with(": `https://example.org/advisory`"), "{line}");
        for mark in ["![", "](", "<<", ">>", "|"] {
            assert!(!line.contains(mark), "{mark} in {line}");
        }
        assert_eq!(line.matches('`').count(), 2, "{line}");
        assert_eq!(
            source_line(None, Some("https://example.org/a")).unwrap(),
            "- source: `https://example.org/a`"
        );
        for bad in [
            "javascript:alert(1)",
            "data:text/html,x",
            "https://collector.example/?a=<<SEC_01>>",
            "https://collector.example/a`b",
            "not a url",
        ] {
            assert_eq!(source_line(Some("t"), Some(bad)), None, "{bad}");
        }
        assert_eq!(source_line(Some("t"), None), None);
    }

    #[tokio::test]
    async fn research_searches_on_claudes_side_and_resumes_a_paused_turn() {
        let (base, mock) = claude_api().await;
        let (answer, shown) = run(&base, KEY, &chain(DEFAULT_FALLBACKS), true).await;
        let answer = answer.unwrap();
        assert_eq!(
            answer.text,
            "Looking it up. Fixed in 1.20.1.\n\nSources consulted:\n\
             - nginx security advisories: `https://nginx.org/en/security_advisories.html`\n\
             - NVD: `https://nvd.nist.gov/vuln/detail/CVE-2021-23017`"
        );
        assert_eq!(shown, answer.text, "shown once, complete");
        assert_eq!(answer.usage.web_search_requests, 2);
        // Both requests of the turn, plus two searches at a cent each.
        let expected = cost_usd("claude-opus-5-5", 7000, 2000, 2);
        assert!((answer.usage.cost_usd - expected).abs() < 1e-9);
        assert!((expected - (0.028 + 0.040 + 0.02)).abs() < 1e-9);

        let requests = sent(&mock);
        assert_eq!(requests.len(), 2);
        let first = &requests[0].body;
        assert_eq!(
            first["tools"],
            json!([{ "type": "web_search_20260209", "name": "web_search", "max_uses": 2 }])
        );
        assert_eq!(first["output_config"], json!({ "effort": "high" }));
        assert!(first.get("stream").is_none());
        // The paused turn goes back exactly as it came, with nothing added.
        let resumed = requests[1].body["messages"].as_array().unwrap();
        assert_eq!(resumed.len(), 2);
        assert_eq!(resumed[1]["role"], "assistant");
        assert_eq!(resumed[1]["content"][1]["type"], "server_tool_use");
        assert_eq!(resumed[1]["content"][2]["type"], "web_search_tool_result");
    }

    #[tokio::test]
    async fn errors_say_what_to_do() {
        let (base, _mock) = claude_api().await;
        let (answer, _) = run(&base, "sk-ant-wrong", &[], false).await;
        let error = format!("{:#}", answer.err().unwrap());
        assert_eq!(
            error,
            "the Claude API did not accept the API key (run `meow setup`): invalid x-api-key"
        );
        assert!(!error.contains("sk-ant-wrong"));

        let http = reqwest::Client::new();
        assert_eq!(
            list_models(&http, &base, KEY).await.unwrap(),
            ["claude-opus-5-5", "claude-opus-4-6"]
        );
        assert!(list_models(&http, &base, "sk-ant-wrong").await.is_err());
        has_model(&http, &base, KEY, "claude-opus-4-8")
            .await
            .unwrap();
        let missing = has_model(&http, &base, KEY, "claude-nope-1")
            .await
            .unwrap_err();
        assert!(
            format!("{missing:#}").starts_with("the Claude API does not know this model"),
            "{missing:#}"
        );
        // Nothing listens there; were it the user's own server, the key
        // would be tried (elsewhere than Linux, no listener means the
        // owner cannot be verified, and the key is not sent at all).
        let _owner = crate::ai::FakePortOwner::set(None);
        let nobody = ask(
            &http,
            "http://127.0.0.1:9/v1",
            KEY,
            DEFAULT_MODEL,
            &[],
            false,
            "s",
            "u",
            &mut |_| {},
        )
        .await;
        assert_eq!(
            format!("{:#}", nobody.err().unwrap()),
            "cannot connect to the Claude API at http://127.0.0.1:9/v1"
        );
    }

    #[test]
    fn requests_fit_the_model_and_costs_follow_the_price_list() {
        let messages = json!([{ "role": "user", "content": "u" }]);
        // An older model: no effort level, no adaptive thinking, the basic
        // search tool, and no server-side fallback.
        let old = body("claude-haiku-4-5", true, false, "s", &messages);
        assert!(old.get("thinking").is_none() && old.get("output_config").is_none());
        assert!(old.get("fallbacks").is_none());
        assert_eq!(old["tools"][0]["type"], "web_search_20250305");
        // Haiku 5.5 is current but has no server-side fallback.
        let haiku = body("claude-haiku-5-5", false, false, "s", &messages);
        assert_eq!(haiku["thinking"], json!({ "type": "adaptive" }));
        assert!(haiku.get("fallbacks").is_none());
        assert_eq!(
            body("claude-sonnet-5-5", false, false, "s", &messages)["fallbacks"],
            "default"
        );
        for body in [&old, &haiku] {
            assert!(body.get("temperature").is_none() && body.get("top_p").is_none());
        }

        let per_million = |model: &str| {
            (
                cost_usd(model, 1_000_000, 0, 0),
                cost_usd(model, 0, 1_000_000, 0),
            )
        };
        assert_eq!(per_million("claude-opus-5-5"), (4.0, 20.0));
        assert_eq!(per_million("claude-opus-5"), (5.0, 25.0));
        assert_eq!(per_million("claude-opus-4-6"), (5.0, 25.0));
        assert_eq!(per_million("claude-opus-4-8"), (5.0, 25.0));
        assert_eq!(per_million("claude-sonnet-5-5"), (2.0, 10.0));
        assert_eq!(per_million("claude-sonnet-4-6"), (3.0, 15.0));
        assert_eq!(per_million("claude-haiku-5-5"), (0.10, 0.50));
        assert_eq!(per_million("claude-fable-5-2"), (8.0, 40.0));
        assert_eq!(per_million("claude-fable-5-1"), (10.0, 50.0));
        // Unknown to the table: priced as the dearest, so the budget holds.
        assert_eq!(per_million("claude-something-new"), (10.0, 50.0));
        assert_eq!(cost_usd("claude-opus-5-5", 0, 0, 3), 0.03);

        assert!(is_claude_api("https://api.anthropic.com/v1"));
        assert!(!is_claude_api("https://openrouter.ai/api/v1"));
        assert!(!is_claude_api("https://api.anthropic.com.evil.example/v1"));
        assert!(!is_claude_api("not a url"));
    }

    #[test]
    fn source_urls_truncation_and_token_counts_are_hardened() {
        assert_eq!(
            sanitize_source_url("https://nginx.org/en/security_advisories.html"),
            Some("https://nginx.org/en/security_advisories.html".into())
        );
        assert_eq!(sanitize_source_url("javascript:alert(1)"), None);
        assert_eq!(sanitize_source_url("https://user:pass@example.com/a"), None);
        assert_eq!(
            sanitize_source_url("https://example.com/path\n## Injected"),
            None
        );
        assert_eq!(
            sanitize_source_url("https://example.com/\u{202e}gnp.exe"),
            None
        );
        assert_eq!(sanitize_source_url("https://example.com/<script>"), None);
        assert_eq!(sanitize_source_url("https://example.com/a`b"), None);

        let mut buf = String::new();
        assert_eq!(append_bounded_utf8(&mut buf, "hello ", 9), "hello ");
        assert_eq!(append_bounded_utf8(&mut buf, "ééé", 9), "é");
        assert_eq!(buf, "hello é");

        let mut counts = Counts::default();
        counts.read(&json!({
            "input_tokens": u64::MAX - 2,
            "cache_creation_input_tokens": 100,
            "cache_read_input_tokens": 100,
            "output_tokens": 50,
            "server_tool_use": { "web_search_requests": u64::from(u32::MAX) + 50 }
        }));
        assert_eq!(counts.input, u64::MAX);
        assert_eq!(counts.searches, u32::MAX);
    }

    #[tokio::test]
    async fn mid_turn_failure_still_charges_spent_and_max_tokens_cutoff_is_cached() {
        let step = Arc::new(Mutex::new(0usize));
        let state = Arc::clone(&step);
        let app = Router::new().route(
            "/v1/messages",
            post(move |Json(body): Json<Value>| {
                let state = Arc::clone(&state);
                async move {
                    if body["stream"] == true {
                        return sse(&[
                            json!({ "type": "message_start", "message": {
                                "model": "claude-opus-5-5\u{1b}[31m",
                                "usage": { "input_tokens": 500, "output_tokens": 1 } } }),
                            json!({ "type": "content_block_delta", "index": 0,
                                "delta": { "type": "text_delta", "text": "Partial answer" } }),
                            json!({ "type": "message_delta",
                                "delta": { "stop_reason": "max_tokens" },
                                "usage": { "output_tokens": 250 } }),
                            json!({ "type": "message_stop" }),
                        ]);
                    }
                    let mut turn = state.lock().unwrap();
                    *turn += 1;
                    if *turn == 1 {
                        Json(json!({
                            "model": "claude-opus-5-5",
                            "stop_reason": "pause_turn",
                            "content": [{ "type": "text", "text": "Searching... " }],
                            "usage": {
                                "input_tokens": 3000,
                                "output_tokens": 500,
                                "server_tool_use": { "web_search_requests": 1 }
                            }
                        }))
                        .into_response()
                    } else {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "type": "error", "error": {
                                "type": "api_error", "message": "upstream broke" } })),
                        )
                            .into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let http = reqwest::Client::new();
        // Control characters in API key are rejected before network I/O.
        let bad_key = ask(
            &http,
            &base,
            "sk-ant-bad\r\nx-injected: 1",
            DEFAULT_MODEL,
            &[],
            false,
            "s",
            "u",
            &mut |_| {},
        )
        .await;
        assert!(bad_key.is_err());

        // Triage max_tokens cutoff notice is present in both streamed output and Answer.text,
        // and untrusted model identifiers are stripped of terminal escape sequences.
        let mut shown = String::new();
        let cutoff = ask(
            &http,
            &base,
            KEY,
            DEFAULT_MODEL,
            &[],
            false,
            "s",
            "u",
            &mut |p| shown.push_str(p),
        )
        .await
        .unwrap();
        assert!(cutoff
            .text
            .ends_with("[The reply was cut off at the length limit.]"));
        assert_eq!(cutoff.text, shown);
        assert!(!cutoff.model.contains('\u{1b}'));

        // Research failure on turn 2 still records turn 1's tokens and search in `spent`.
        let mut spent = Usage::default();
        let err = ask_with_spend(
            &http,
            &base,
            KEY,
            DEFAULT_MODEL,
            &[],
            true,
            "s",
            "u",
            &mut |_| {},
            &mut spent,
        )
        .await;
        assert!(err.is_err());
        assert_eq!(spent.prompt_tokens, 3000);
        assert_eq!(spent.completion_tokens, 500);
        assert_eq!(spent.web_search_requests, 1);
        assert!(spent.cost_usd > 0.0);
    }
}
