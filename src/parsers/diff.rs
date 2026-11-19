//! `git diff` / unified diff parser.
//!
//! A diff says nothing about hosts or ports; it is recorded as workspace
//! notes (one per changed file) whose evidence is the exact `+` / `-` block,
//! so that triage and reports can refer to the change.

use crate::evidence::{Confidence, EvidenceRecord, Source};
use crate::graph::Observation;

#[derive(Default)]
struct FileDiff {
    path: String,
    added: usize,
    removed: usize,
    block: String,
}

impl FileDiff {
    fn finish(self, out: &mut Vec<Observation>) {
        if self.path.is_empty() || self.added + self.removed == 0 {
            return;
        }
        out.push(Observation::Note {
            address: None,
            text: format!(
                "git diff: {} (+{} -{})",
                self.path, self.added, self.removed
            ),
            record: EvidenceRecord::observed_block(Source::GitDiff, Confidence::High, &self.block),
        });
    }
}

fn strip_side(path: &str) -> &str {
    let path = path.split('\t').next().unwrap_or(path).trim();
    path.strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .unwrap_or(path)
}

/// The most of a file's path that is kept. The note that names it is cut
/// to a line anyway; a header line of megabytes is not carried along.
const MAX_DIFF_PATH: usize = 1024;

fn kept_path(path: &str) -> String {
    crate::evidence::head(path, MAX_DIFF_PATH).to_owned()
}

const MAX_DIFF_FILES: usize = 512;

pub fn parse(text: &str) -> Vec<Observation> {
    let mut out = Vec::new();
    let mut current = FileDiff::default();
    let mut in_hunk = false;
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if out.len() >= MAX_DIFF_FILES {
            return out;
        }
        if let Some(rest) = line.strip_prefix("diff --git ") {
            std::mem::take(&mut current).finish(&mut out);
            if out.len() >= MAX_DIFF_FILES {
                return out;
            }
            in_hunk = false;
            // "a/old b/new": the new path is after the last " b/".
            current.path = kept_path(
                rest.rsplit_once(" b/")
                    .map_or_else(|| strip_side(rest), |(_, new)| new),
            );
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            if !in_hunk {
                if rest.trim() != "/dev/null" {
                    current.path = kept_path(strip_side(rest));
                }
                continue;
            }
            current.added += 1;
            push_line(&mut current.block, line);
        } else if let Some(rest) = line.strip_prefix("--- ") {
            let next_is_plus_header = lines.peek().is_some_and(|next| next.starts_with("+++ "));
            if !in_hunk || next_is_plus_header {
                // A plain unified diff has no "diff --git" header between files.
                if !current.block.is_empty() {
                    std::mem::take(&mut current).finish(&mut out);
                    if out.len() >= MAX_DIFF_FILES {
                        return out;
                    }
                }
                in_hunk = false;
                if current.path.is_empty() && rest.trim() != "/dev/null" {
                    current.path = kept_path(strip_side(rest));
                }
                continue;
            }
            current.removed += 1;
            push_line(&mut current.block, line);
        } else if line.starts_with("@@") {
            in_hunk = true;
            push_line(&mut current.block, line);
        } else if in_hunk && line.starts_with('+') {
            current.added += 1;
            push_line(&mut current.block, line);
        } else if in_hunk && line.starts_with('-') {
            current.removed += 1;
            push_line(&mut current.block, line);
        } else if in_hunk && !line.starts_with(' ') && !line.starts_with('\\') && !line.is_empty() {
            in_hunk = false; // next file header ("index ...", "new file mode ...")
        }
    }
    if out.len() < MAX_DIFF_FILES {
        current.finish(&mut out);
    }
    out
}

const MAX_DIFF_BLOCK: usize = 64 * 1024;

fn push_line(block: &mut String, line: &str) {
    if block.len() + line.len() < MAX_DIFF_BLOCK {
        block.push_str(line);
        block.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIFF: &str = "\
diff --git a/nginx/site.conf b/nginx/site.conf
index 1111111..2222222 100644
--- a/nginx/site.conf
+++ b/nginx/site.conf
@@ -10,7 +10,8 @@ server {
     listen 443 ssl;
-    server_tokens on;
+    server_tokens off;
+    add_header X-Frame-Options DENY;
     root /var/www;
diff --git a/old name.txt b/new name.txt
similarity index 90%
rename from old name.txt
rename to new name.txt
--- a/old name.txt
+++ b/new name.txt
@@ -1 +1 @@
--- not a header, a removed line
+plain
diff --git a/empty.bin b/empty.bin
new file mode 100644
";

    fn notes(text: &str) -> Vec<(String, String)> {
        parse(text)
            .into_iter()
            .map(|o| match o {
                Observation::Note {
                    address: None,
                    text,
                    record,
                } => {
                    assert_eq!(record.source, Source::GitDiff);
                    (text, record.evidence)
                }
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    #[test]
    fn each_changed_file_becomes_a_note_with_its_exact_block() {
        let notes = notes(DIFF);
        assert_eq!(notes.len(), 2, "the file without hunks is skipped");
        assert_eq!(notes[0].0, "git diff: nginx/site.conf (+2 -1)");
        assert_eq!(
            notes[0].1,
            "@@ -10,7 +10,8 @@ server {\n-    server_tokens on;\n+    server_tokens off;\n+    add_header X-Frame-Options DENY;"
        );
        assert_eq!(notes[1].0, "git diff: new name.txt (+1 -1)");
        assert!(notes[1].1.contains("--- not a header, a removed line"));
    }

    #[test]
    fn plain_unified_diffs_work_without_a_git_header() {
        let text = "--- config.old\t2026-01-01\n+++ config.new\t2026-01-02\n@@ -1 +1 @@\n-debug = true\n+debug = false\n--- auth.old\t2026-01-01\n+++ auth.new\t2026-01-02\n@@ -1 +1 @@\n-allow_guest = true\n+allow_guest = false\n";
        assert_eq!(
            notes(text),
            [
                (
                    "git diff: config.new (+1 -1)".to_owned(),
                    "@@ -1 +1 @@\n-debug = true\n+debug = false".to_owned()
                ),
                (
                    "git diff: auth.new (+1 -1)".to_owned(),
                    "@@ -1 +1 @@\n-allow_guest = true\n+allow_guest = false".to_owned()
                ),
            ]
        );
        assert!(parse("just some text\n+ not a diff\n").is_empty());
    }

    #[test]
    fn a_path_of_megabytes_is_cut_to_a_line() {
        let long = "A".repeat(4 * 1024 * 1024);
        for text in [
            format!("diff --git a/x b/{long}\n@@ -1 +1 @@\n+b\n"),
            format!("--- a/{long}\n+++ b/{long}\n@@ -1 +1 @@\n+b\n"),
        ] {
            let notes = notes(&text);
            assert_eq!(notes.len(), 1);
            // `git diff: <path> (+1 -0)`, the path cut to a kilobyte.
            assert!(notes[0].0.len() < 1100, "{}", notes[0].0.len());
            assert!(notes[0].0.ends_with("AAA (+1 -0)"));
        }
    }
}
