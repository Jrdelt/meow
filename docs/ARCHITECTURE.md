# How meow works

meow is one Rust binary with one small C11 file in it. It sits between you and
your shell, reads a copy of everything the shell prints, and turns what it
recognises into a graph of hosts, ports, services and findings. Everything
else (the HUD, the map, the report, the AI tiers) reads that graph.

File references point at the source as of v0.2.7 and may drift.

```mermaid
flowchart LR
    you([you]) -- keys --> pty[PTY host<br/>src/pty.rs]
    pty -- keys --> shell[your shell<br/>zsh, bash, fish, pwsh]
    shell -- output --> pty
    pty -- "raw bytes, first" --> term([your terminal])
    pty -. "a copy, on a worker thread" .-> tap["tap filter<br/>src/c/tap_filter.c (C11)"]
    tap -- "clean text lines" --> text["line parser<br/>src/parsers/text.rs"]
    add["meow add &lt;file&gt;"] --> detect["format detection<br/>src/parsers/mod.rs"]
    recon["meow recon<br/>src/queue/"] --> detect
    detect --> parsers["Nmap XML · JSONL · git diff · log"]
    text --> obs[(Observations)]
    parsers --> obs
    obs --> graph["Graph::apply<br/>src/graph.rs"]
    graph --> cve["CVE grounding<br/>NVD · OSV · CISA KEV"]
    cve --> graph
    graph --> views["HUD · web map · REPORT.md"]
    graph --> vault["vault: mask"] --> ai["cloud AI"] --> unmask["vault: unmask"] --> views
```

## 1. Capturing output

- **Starting the shell.** `shims::prepare` (src/shims.rs) writes per-session
  startup files for zsh, bash, fish or PowerShell. Their hooks append each
  command to the session's `replay.sh`. They do not touch output.
- **The PTY host.** `pty::run_session` (src/pty.rs) runs the shell on a
  pseudo-terminal. It reads 4 KiB at a time and always writes the chunk to
  your terminal first. Only then does it offer a copy to a bounded queue of
  256 chunks. When the queue is full the copy is dropped and counted, so a
  slow parser can never stall your terminal.
- **The tap filter (C11).** A worker thread feeds the copies through
  `TapFilter::feed` (src/tap.rs), which calls the C state machine in
  src/c/tap_filter.c. It turns a raw VT500/ECMA-48 byte stream into plain,
  newline-terminated UTF-8 lines:
  - escape sequences, OSC/DCS/APC strings (capped at 64 KiB) and C1
    controls are removed;
  - carriage return, backspace, erase-in-line, cursor moves and row breaks
    are applied the way a terminal would;
  - full-screen programs (the alternate screen) pause capture;
  - lines with binary bytes, and password or passphrase prompts, are
    dropped;
  - lines are cut at 4096 bytes.
- **The FFI boundary.** Rust declares eight C functions in one `extern "C"`
  block (src/tap.rs). The C state is opaque: Rust asks C for its size and
  alignment and allocates it, so the struct layout is never written twice.
  Rust sizes every output buffer for the worst case, which the fuzz target
  `tap_filter` checks (no line is ever lost for room).
- **Into the session.** Each clean line goes to the coordinator
  (src/coordinator.rs) over a bounded channel. Its `tap_loop` runs the line
  parser and applies what it finds to the graph.

## 2. Parsing

Parsers never change the graph themselves. Each one returns `Observation`s,
and `Graph::apply` (src/graph.rs) is the single place where they are merged.

| Input | Parser | Entry point |
|---|---|---|
| Terminal lines (Nmap normal output, `curl -I` headers, URLs, banners) | src/parsers/text.rs | `TextParser::feed(&mut self, line)`; keeps state from line to line |
| Nmap XML (`-oX`) | src/parsers/nmap.rs | `nmap::parse(xml, trusted_names)` |
| katana and feroxbuster JSONL, generic `{url}` objects | src/parsers/jsonl.rs | `jsonl::parse(text)` |
| `git diff` / unified diff | src/parsers/diff.rs | `diff::parse(text)`: each changed file becomes a note |
| Any file for `meow add` | src/parsers/mod.rs | `detect(text)` picks the format from the content, not the file name; `parse_text` runs it |

Every observation carries an `EvidenceRecord` (src/evidence.rs): where it came
from (`Source`, for example the live terminal or an imported file), a
confidence and a timestamp. The report prints them.

Names are claims. A host name that only appeared in text, a certificate or
reverse DNS never moves a host or takes over one you already worked on
(tests in src/parsers/mod.rs and src/parsers/nmap.rs).

## 3. Recon

`meow recon` queues a staged inventory (src/queue/): 17 stages, one at a time,
from DNS and subdomains to ports, services, TLS, SSH, crawling and paths.

- External tools (nmap, katana, feroxbuster) run in their own process group
  with stdin closed, a timeout and an output cap. Secret-looking environment
  variables are not passed on (src/queue/runner.rs).
- Their output files go through the same parsers as `meow add`.
- The session mode decides what may be sent to a target: light sends
  nothing, mild runs slow scans and aggressive runs fast ones
  (src/mode.rs, src/queue/mod.rs).

## 4. CVE grounding

For every open port with a known version, src/cve.rs asks:

- **NVD**, by CPE (`cpe::to_cpe23` turns Nmap's CPE 2.2 names into the 2.3 form
  NVD expects) and again by keyword, since recent CVEs often have no CPE data
  yet;
- **OSV.dev**, in batches, for packages;
- **CISA KEV**, a catalog cached for 7 days, to flag known exploited CVEs.

A match needs the version to fall in the CVE's range. When NVD gives no
range, the description must name both the product and the version, and the
match is marked low confidence. Answers are cached in `state.db`. Only
software names and versions leave the machine, never a scanned host's name or
address.

## 5. Storage and views

- **`graph.json`** holds the graph. It is written atomically, at most every
  750 ms.
- **`state.db`** (SQLite, WAL mode) holds the CVE cache, the recon queue, the
  vault and the AI ledger. It is opened with defensive settings: no views, no
  triggers, `trusted_schema` off (src/db.rs).
- **The web map** is served by the session on `127.0.0.1` (port 8765 or the
  next free one) behind a 256-bit token. The page, its script and styles are
  compiled into the binary (src/webui.rs, assets/). The browser gets live
  updates over a WebSocket.
- **The HUD** (src/hud.rs, ratatui) uses the same WebSocket.
- **Helper commands** (`meow mode`, `meow recon`, `meow add`) talk to the
  running session over loopback HTTP with the same token (src/ipc.rs).
- **`meow report`** writes `REPORT.md` from the files alone, with no network
  and no AI ([sample](sample-report.md)).

## 6. AI and the vault

There are three tiers: **L**ocal AI, **C**loud AI and **R**esearch (src/ai.rs).
A cloud request goes through these steps in order:

1. The prompt is built. Text scraped from the audited systems only ever
   travels inside one JSON field, `untrusted_scan_data`, never in the
   instructions.
2. `mask_prompt` registers every address, name, user, path and secret the
   graph knows, masks the prompt, and checks it again with `leaks_json`. If
   anything private is left, meow refuses to send.
3. The masked prompt is looked up in the cache, then checked against the daily
   cost and call caps.
4. The request goes out; the reply streams back.
5. `StreamUnmasker` puts real values back as the reply streams, but only the
   triaged host's own values, only in prose, and never secrets.

Placeholders look like `<<HOST_01>>`. The same value always gets the same one,
and the mapping is stored in `state.db` (src/vault.rs). A local AI server gets
unmasked text only when meow counts it as yours ([SECURITY.md](../SECURITY.md#known-limits)
says what that includes); otherwise it gets masked text, like a cloud server.
[THREAT_MODEL.md](THREAT_MODEL.md) covers what is sent where.

## 7. Why Rust, and why one C11 file

- **Rust for nearly everything.** meow spends its time reading text that other
  people's machines produced: banners, headers, certificates, XML, JSON and
  AI replies. Doing that in a memory-safe language takes a whole class of
  bugs off the table. The same code builds one binary for macOS, Linux and
  Windows.
- **C11 for the terminal filter.** The filter is a byte-at-a-time state
  machine of about 670 lines. It needs only `<stddef.h>` and `<stdint.h>`, and
  allocates nothing (Rust owns its state and its buffers). It builds with
  strict warnings (`-std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow`,
  or `/std:c11 /W4` on MSVC; build.rs). Its interface is eight small
  functions, so the unsafe surface stays small and easy to audit.
- **Keeping the C safe.** The C code never sees your terminal's display path,
  only copies, on a worker thread. 28 unit tests cover it (src/tap.rs), and
  the `tap_filter` fuzz target runs it under AddressSanitizer
  ([fuzzing](../fuzz/README.md)).

## 8. Tests

- Over 740 tests run on macOS, Linux and Windows on every push to `main`
  (`.github/workflows/checks.yml`): `cargo fmt`, `clippy -D warnings`, a build
  at the 1.89 minimum Rust version, a Windows cross-clippy, and a RustSec
  dependency audit.
- Parser tests cover hostile input: entity expansion, deep nesting, huge
  attributes, escape-injected fields, and lines packed with addresses.
- Four fuzz targets (`fuzz/`) cover the parsers and the C filter. They run
  weekly and on demand (`.github/workflows/fuzz.yml`).
