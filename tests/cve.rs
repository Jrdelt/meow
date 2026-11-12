//! `meow add` followed by CVE grounding against a local stand-in for the
//! NVD, OSV and CISA KEV endpoints. No real network is used.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc;

use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

const SCAN: &str = r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0" method="probed" conf="10"><cpe>cpe:/a:nginx:nginx:1.18.0</cpe></service></port>
</ports></host></nmaprun>"#;

/// Starts the stand-in server on its own thread and returns its base URL.
fn mock_apis() -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let app = Router::new()
                .route(
                    "/nvd",
                    get(|| async {
                        Json(json!({ "vulnerabilities": [ { "cve": {
                            "id": "CVE-2021-23017", "vulnStatus": "Analyzed",
                            "descriptions": [ { "lang": "en", "value": "nginx resolver off-by-one." } ],
                            "metrics": { "cvssMetricV31": [ { "cvssData": { "baseScore": 7.7, "baseSeverity": "HIGH" } } ] },
                            "configurations": [ { "nodes": [ { "cpeMatch": [ {
                                "vulnerable": true, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "1.20.1" } ] } ] } ]
                        } } ] }))
                    }),
                )
                .route(
                    "/kev",
                    get(|| async { Json(json!({ "vulnerabilities": [ { "cveID": "CVE-2021-23017" } ] })) }),
                )
                .route("/osv/v1/querybatch", post(|| async { Json(json!({ "results": [] })) }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(format!("http://{}", listener.local_addr().unwrap())).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    rx.recv().unwrap()
}

struct Sandbox {
    tmp: tempfile::TempDir,
}

impl Sandbox {
    fn new(api_base: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("meow-home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("config.toml"),
            format!(
                "[cve]\nnvd_api_key = \"test\"\nnvd_url = \"{api_base}/nvd\"\n\
                 osv_url = \"{api_base}/osv\"\nkev_url = \"{api_base}/kev\"\n"
            ),
        )
        .unwrap();
        std::fs::write(tmp.path().join("scan.xml"), SCAN).unwrap();
        let sandbox = Self { tmp };
        assert!(sandbox.run(&["acme"]).status.success());
        sandbox
    }

    fn workspace(&self) -> PathBuf {
        self.tmp.path().join("meow-home/workspaces/acme")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_meow"))
            .args(args)
            .current_dir(self.tmp.path())
            .env("MEOW_HOME", self.tmp.path().join("meow-home"))
            .env("SHELL", "/bin/sh")
            .env_remove("MEOW_SESSION")
            .env_remove("MEOW_WORKSPACE")
            .output()
            .unwrap()
    }

    fn graph(&self) -> Value {
        let text = std::fs::read_to_string(self.workspace().join("graph.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }
}

fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn add_grounds_new_software_as_unverified_hypotheses() {
    let sandbox = Sandbox::new(&mock_apis());
    let output = sandbox.run(&["add", "scan.xml", "--session", "acme"]);
    let text = out(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("[+] CVE lookups: 2 to run, at most 1 s"),
        "{text}"
    );
    assert!(
        text.contains("[+] CVE lookups: 1 new advisories (1 in CISA KEV), all stored as UnverifiedHypothesis; 1 in total"),
        "{text}"
    );

    let graph = sandbox.graph();
    let host = &graph["hosts"]["10.0.0.5"];
    let advisory = &host["advisories"][0];
    assert_eq!(advisory["id"], "CVE-2021-23017");
    assert_eq!(advisory["verification_status"], "UnverifiedHypothesis");
    assert_eq!(advisory["source"], "nvd_api");
    assert_eq!(advisory["kev"], true);
    assert_eq!(advisory["port"], "80/tcp");
    assert_eq!(advisory["severity"], "HIGH");
    // The port facts are still plain observations.
    assert_eq!(
        host["ports"]["80/tcp"]["facts"][0]["verification_status"],
        "Observed"
    );
    assert!(host["facts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["source"] == "cisa_kev"));

    // Re-importing finds nothing new, and the answers come from state.db.
    let text = out(&sandbox.run(&["add", "scan.xml", "--session", "acme"]));
    assert!(text.contains("0 new advisories (0 in CISA KEV)"), "{text}");
    assert!(Path::new(&sandbox.workspace().join("state.db")).is_file());

    // --no-cve skips the lookups entirely.
    let text = out(&sandbox.run(&["add", "scan.xml", "--session", "acme", "--no-cve"]));
    assert!(!text.contains("CVE lookups"), "{text}");
}

#[test]
fn offline_grounding_fails_fast_without_failing_the_import() {
    // A port with nothing listening: every connection is refused at once.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);

    let sandbox = Sandbox::new(&dead);
    let started = std::time::Instant::now();
    let output = sandbox.run(&["add", "scan.xml", "--session", "acme"]);
    let text = out(&output);
    assert!(output.status.success(), "{text}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(text.contains("[!] CVE lookup failed: "), "{text}");
    assert!(text.contains("0 new advisories"), "{text}");
    // The imported facts are kept even though grounding failed.
    assert_eq!(
        sandbox.graph()["hosts"]["10.0.0.5"]["ports"]["80/tcp"]["product"],
        "nginx"
    );
}
