//! The background recon queue, driven through a real coordinator with
//! stand-in tools (shell scripts) in place of nmap, katana and feroxbuster.
//! No packets are sent anywhere.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use meow::coordinator::{Command, Coordinator};
use meow::mode::Mode;
use meow::queue::{self, TaskRow};
use meow::workspace::{Config, MeowHome, Workspace};

const PORTS_XML: &str = r#"<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" method="table" conf="3"/></port>
</ports></host></nmaprun>"#;

const SERVICES_XML: &str = r#"<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl" product="nginx" version="1.18.0" method="probed" conf="10"/>
<script id="ssl-cert" output="Subject Alternative Name: DNS:app.lab.local"/></port>
</ports></host></nmaprun>"#;

struct Lab {
    tmp: tempfile::TempDir,
    workspace: Workspace,
    config: Config,
}

impl Lab {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (mut workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
        workspace.set_mode(Mode::Mild).unwrap();

        let log = tmp.path().join("calls.log");
        let hold = tmp.path().join("hold");
        let fail = tmp.path().join("fail");
        let tool = |name: &str, body: &str| -> String {
            let path = tmp.path().join(name);
            let script = format!(
                "#!/bin/sh\necho \"start {name} $*\" >> '{log}'\n\
                 while [ -f '{hold}' ] || [ -f '{hold}-{name}' ]; do sleep 0.05; done\n{body}\necho \"end {name}\" >> '{log}'\n",
                log = log.display(),
                hold = hold.display(),
            );
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.to_string_lossy().into_owned()
        };
        // Each stand-in finds its output file the way the real tool is told.
        let find = |flag: &str, var: &str| {
            format!("{var}=''; prev=''\nfor a in \"$@\"; do [ \"$prev\" = '{flag}' ] && {var}=\"$a\"; prev=\"$a\"; done\n")
        };
        let wordlist = tmp.path().join("words.txt");
        std::fs::write(&wordlist, "admin\n").unwrap();

        let mut config = Config::default();
        config.cve.enabled = false;
        config.recon.wordlist_path = Some(wordlist.to_string_lossy().into_owned());
        config.recon.nmap = tool(
            "nmap",
            &format!(
                "{}[ -f '{fail}' ] && exit 1\ncase \" $* \" in\n*' -sV '*) cat > \"$out\" <<'XML'\n{SERVICES_XML}\nXML\n;;\n\
                 *) cat > \"$out\" <<'XML'\n{PORTS_XML}\nXML\n;;\nesac",
                find("-oX", "out"),
                fail = fail.display(),
            ),
        );
        config.recon.katana = tool(
            "katana",
            &format!(
                // The page also links to another site, as a default web
                // server page does.
                "{}{}printf '{{\"request\":{{\"endpoint\":\"%s/portal/login\"}},\"response\":{{\"status_code\":200}}}}\\n' \"$url\" > \"$out\"\n\
                 printf '{{\"request\":{{\"endpoint\":\"https://www.example.org/download\"}},\"response\":{{\"status_code\":200,\"headers\":{{\"server\":\"Apache\"}}}}}}\\n' >> \"$out\"",
                find("-u", "url"),
                find("-o", "out"),
            ),
        );
        config.recon.feroxbuster = tool(
            "feroxbuster",
            &format!(
                "{}{}printf '{{\"type\":\"response\",\"url\":\"%s/admin\",\"status\":403}}\\n' \"$url\" > \"$out\"",
                find("-u", "url"),
                find("-o", "out"),
            ),
        );
        Self {
            tmp,
            workspace,
            config,
        }
    }

    fn start(&self) -> Coordinator {
        Coordinator::start(self.workspace.clone(), self.config.clone()).unwrap()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.file("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn task(coordinator: &Coordinator, id: i64) -> TaskRow {
    queue::task(&coordinator.state().db_lock(), id)
        .unwrap()
        .unwrap()
}

fn statuses(coordinator: &Coordinator, id: i64) -> Vec<String> {
    task(coordinator, id)
        .stages
        .iter()
        .map(|s| s.status.clone())
        .collect()
}

fn recon(coordinator: &Coordinator, target: &str) -> i64 {
    let result = coordinator
        .state()
        .execute(Command::Recon {
            target: target.to_owned(),
            flags: vec!["-p".into(), "1-1000".into()],
        })
        .unwrap();
    result["task"].as_i64().unwrap()
}

fn wait_finished(coordinator: &Coordinator, id: i64) {
    wait_until("the task to finish", || !task(coordinator, id).unfinished());
}

fn leftovers(tmp_dir: &Path) -> Vec<String> {
    std::fs::read_dir(tmp_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "shell")
        .collect()
}

#[test]
fn four_stages_run_in_order_one_at_a_time_and_fill_the_graph() {
    let lab = Lab::new();
    let coordinator = lab.start();
    let id = recon(&coordinator, "10.0.0.77/24");
    wait_finished(&coordinator, id);
    assert_eq!(statuses(&coordinator, id), ["done"; 4]);

    // Strictly sequential: every start is followed by its own end.
    let calls = lab.calls();
    let kinds: Vec<&str> = calls
        .iter()
        .map(|c| c.split(' ').take(2).last().unwrap())
        .collect();
    assert_eq!(
        calls
            .iter()
            .map(|c| c.split(' ').next().unwrap())
            .collect::<Vec<_>>(),
        ["start", "end"].repeat(6),
        "{calls:#?}"
    );
    assert_eq!(
        kinds.iter().step_by(2).copied().collect::<Vec<_>>(),
        [
            "nmap",
            "nmap",
            "katana",
            "katana",
            "feroxbuster",
            "feroxbuster"
        ]
    );

    // The exact commands, including the operator's extra flags after `--`
    // and the normalised target.
    let tmp_dir = lab.workspace.tmp_dir();
    let scan = if queue::is_privileged() { "-sS" } else { "-sT" };
    assert_eq!(
        calls[0],
        format!(
            "start nmap {scan} -T3 -p 1-1000 -oX {}/nmap_ports_{id}.xml -- 10.0.0.0/24",
            tmp_dir.display()
        )
    );
    assert!(
        calls[2].contains(" -sV ")
            && calls[2].contains(" -p 22,443,80 ")
            && calls[2].ends_with(" -- 10.0.0.5"),
        "{}",
        calls[2]
    );
    assert!(
        calls[4].contains("-u https://10.0.0.5 -jsonl -silent -nc -jc -fs fqdn -ct 5m -d 2 -o "),
        "{}",
        calls[4]
    );
    assert!(calls[6].contains("-u http://10.0.0.5 "), "{}", calls[6]);
    assert!(
        calls[8].contains("--rate-limit 20 --scan-limit 1 --auto-bail --time-limit 10m --json -o "),
        "{}",
        calls[8]
    );
    assert!(
        calls[8].ends_with(&format!("-w {}", lab.file("words.txt").display())),
        "{}",
        calls[8]
    );

    let state = coordinator.state();
    {
        let graph = state.graph();
        let host = &graph.hosts["10.0.0.5"];
        assert_eq!(host.ports["80/tcp"].product.as_deref(), Some("nginx"));
        assert_eq!(host.ports["80/tcp"].version.as_deref(), Some("1.18.0"));
        assert!(host.hostnames.contains("app.lab.local"));
        for port in ["80/tcp", "443/tcp"] {
            let paths: Vec<String> = host.ports[port]
                .paths
                .walk()
                .into_iter()
                .map(|(p, _)| p)
                .collect();
            assert_eq!(paths, ["/admin", "/portal/", "/portal/login"], "{port}");
            assert_eq!(host.ports[port].paths.children["admin"].status, Some(403));
        }
        // A link to another site is not a host, and says nothing about it.
        assert_eq!(
            graph.hosts.keys().collect::<Vec<_>>(),
            ["10.0.0.5"],
            "only the scanned hosts"
        );
    }
    let crawl = &task(&coordinator, id).stages[2].detail;
    assert!(crawl.contains("links to 1 other site left out"), "{crawl}");
    // Structured tool output is deleted once parsed.
    assert_eq!(leftovers(&tmp_dir), Vec::<String>::new());

    let snapshot = state.snapshot();
    assert_eq!(snapshot["tasks"][0]["id"], id);
    assert_eq!(snapshot["tasks"][0]["stages"][0]["status"], "done");
    let notices = snapshot["notices"].to_string();
    assert!(
        notices.contains("recon 10.0.0.0/24: ports done"),
        "{notices}"
    );
    assert!(notices.contains("queued as task"), "{notices}");
}

#[test]
fn light_mode_refuses_recon_and_bad_targets_are_rejected() {
    let lab = Lab::new();
    let coordinator = lab.start();
    let state = coordinator.state();
    let run = |target: &str| {
        state.execute(Command::Recon {
            target: target.to_owned(),
            flags: vec![],
        })
    };

    state
        .execute(Command::SetMode { mode: Mode::Light })
        .unwrap();
    let error = run("10.0.0.5").unwrap_err().to_string();
    assert!(error.contains("light mode sends no packets"), "{error}");

    state
        .execute(Command::SetMode { mode: Mode::Mild })
        .unwrap();
    for bad in [
        "-iL /etc/passwd",
        "10.0.0.1-50",
        "",
        "10.0.0.5 10.0.0.6",
        "http://10.0.0.5/",
    ] {
        let error = run(bad).unwrap_err().to_string();
        assert!(
            error.contains("not a host name, an IP address or a CIDR range"),
            "{bad}: {error}"
        );
    }
    for unsafe_flags in [
        &["--script=/tmp/evil.nse"][..],
        &["--script", "intrusive"],
        &["-oN", "/tmp/out.txt"],
        &["-iL", "/etc/hosts"],
        &["192.0.2.99"],
        &["-p"],
    ] {
        let error = state
            .execute(Command::Recon {
                target: "192.0.2.10".to_owned(),
                flags: unsafe_flags.iter().map(|s| (*s).to_owned()).collect(),
            })
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("not allowed")
                || error.contains("takes script categories")
                || error.contains("unexpected nmap argument")
                || error.contains("requires a port range"),
            "{unsafe_flags:?}: {error}"
        );
    }
    // A range far wider than anyone means to scan.
    for wide in [
        "0.0.0.0/0",
        "10.0.0.0/8",
        "172.16.0.0/15",
        "::/0",
        "fd00::/64",
    ] {
        let error = run(wide).unwrap_err().to_string();
        assert!(error.contains("at most 65,536 at once"), "{wide}: {error}");
    }
    assert!(
        lab.calls().is_empty(),
        "nothing may run for a refused request"
    );
    assert!(queue::tasks(&state.db_lock(), 10).unwrap().is_empty());

    // The widest that is taken, and one planted in the database.
    for fine in ["10.20.0.0/16", "fd00::1:0/112"] {
        run(fine).unwrap();
    }
    let planted = queue::enqueue(&state.db_lock(), "0.0.0.0/0", Mode::Mild, &[]).unwrap();
    state.resume_unfinished().unwrap();
    wait_finished(&coordinator, planted);
    assert_eq!(
        statuses(&coordinator, planted),
        ["failed", "skipped", "skipped", "skipped"]
    );
    assert!(task(&coordinator, planted).stages[0]
        .detail
        .contains("0.0.0.0/0 covers 4,294,967,296 addresses"));
    assert!(
        !lab.calls().iter().any(|call| call.contains("0.0.0.0/0")),
        "{:?}",
        lab.calls()
    );
}

#[test]
fn missing_tools_and_wordlists_skip_their_stage_cleanly() {
    let mut lab = Lab::new();
    lab.config.recon.katana = lab.file("no-such-katana").to_string_lossy().into_owned();
    lab.config.recon.feroxbuster = lab.file("no-such-ferox").to_string_lossy().into_owned();
    let coordinator = lab.start();
    let id = recon(&coordinator, "10.0.0.5");
    wait_finished(&coordinator, id);
    assert_eq!(
        statuses(&coordinator, id),
        ["done", "done", "skipped", "skipped"]
    );
    let row = task(&coordinator, id);
    for stage in &row.stages[2..] {
        assert!(
            stage
                .detail
                .contains("is not installed (run `meow tools` to install it)"),
            "{}",
            stage.detail
        );
    }
    // The facts from the stages that did run are kept.
    assert!(coordinator.state().graph().hosts["10.0.0.5"]
        .ports
        .contains_key("22/tcp"));
}

#[test]
fn a_failed_port_inventory_skips_the_stages_that_depend_on_it() {
    let lab = Lab::new();
    std::fs::write(lab.file("fail"), "").unwrap();
    let coordinator = lab.start();
    let id = recon(&coordinator, "10.0.0.5");
    wait_finished(&coordinator, id);
    assert_eq!(
        statuses(&coordinator, id),
        ["failed", "skipped", "skipped", "skipped"]
    );
    let row = task(&coordinator, id);
    assert!(
        row.stages[0].detail.contains("exited with code 1"),
        "{}",
        row.stages[0].detail
    );
    assert_eq!(
        lab.calls().len(),
        1,
        "only the port inventory was attempted"
    );
    assert_eq!(leftovers(&lab.workspace.tmp_dir()), Vec::<String>::new());
}

#[test]
fn a_stage_cut_off_by_the_session_ending_is_interrupted_and_can_be_resumed() {
    let lab = Lab::new();
    std::fs::write(lab.file("hold"), "").unwrap();
    let coordinator = lab.start();
    let id = recon(&coordinator, "10.0.0.5");
    wait_until("the port stage to start", || {
        statuses(&coordinator, id)[0] == "running"
    });
    wait_until("the tool to start", || lab.calls().len() == 1);

    // The session ends while nmap is still running.
    coordinator.shutdown();
    std::fs::remove_file(lab.file("hold")).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        lab.calls().len(),
        1,
        "the tool was killed, it never reached its end"
    );
    assert_eq!(queue::count_unfinished(&lab.workspace.state_db_path()), 1);

    // Reopening finds it interrupted; nothing restarts by itself.
    let coordinator = lab.start();
    assert_eq!(
        statuses(&coordinator, id),
        ["interrupted", "pending", "pending", "pending"]
    );
    assert_eq!(
        task(&coordinator, id).describe(),
        "recon 10.0.0.5: ports interrupted"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(lab.calls().len(), 1);

    assert_eq!(coordinator.state().resume_unfinished().unwrap(), 1);
    wait_finished(&coordinator, id);
    assert_eq!(statuses(&coordinator, id), ["done"; 4]);
}

#[test]
fn light_mode_pauses_queued_work_and_leaving_it_resumes() {
    let lab = Lab::new();
    std::fs::write(lab.file("hold"), "").unwrap();
    let coordinator = lab.start();
    let state = coordinator.state();
    let first = recon(&coordinator, "10.0.0.5");
    let second = recon(&coordinator, "10.0.0.0/24");
    wait_until("the first tool to start", || lab.calls().len() == 1);
    // One at a time: the second task has not started anything.
    assert_eq!(statuses(&coordinator, second), ["pending"; 4]);

    state
        .execute(Command::SetMode { mode: Mode::Light })
        .unwrap();
    wait_until("both tasks to pause", || {
        statuses(&coordinator, first)[0] == "interrupted"
            && statuses(&coordinator, second)[0] == "interrupted"
    });
    for id in [first, second] {
        assert!(task(&coordinator, id).stages[0]
            .detail
            .contains("light mode"));
    }
    // The tool that was running was stopped, not left to finish.
    std::fs::remove_file(lab.file("hold")).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        lab.calls().len(),
        1,
        "nothing runs in light mode: {:?}",
        lab.calls()
    );
    assert!(leftovers(&lab.workspace.tmp_dir()).is_empty());

    let result = state
        .execute(Command::SetMode { mode: Mode::Mild })
        .unwrap();
    assert_eq!(result["resumed"], 2);
    wait_finished(&coordinator, first);
    wait_finished(&coordinator, second);
    assert_eq!(statuses(&coordinator, first), ["done"; 4]);
    assert_eq!(statuses(&coordinator, second), ["done"; 4]);
}

#[test]
fn work_queued_in_aggressive_runs_as_mild_once_the_session_is_mild() {
    let mut lab = Lab::new();
    lab.workspace.set_mode(Mode::Aggressive).unwrap();
    std::fs::write(lab.file("hold"), "").unwrap();
    let coordinator = lab.start();
    let state = coordinator.state();
    let id = recon(&coordinator, "10.0.0.5");
    assert_eq!(task(&coordinator, id).mode, Mode::Aggressive);
    wait_until("the first tool to start", || lab.calls().len() == 1);
    assert!(lab.calls()[0].contains(" -T4 "), "{:?}", lab.calls());

    // The session is turned down while the aggressive scan runs: that scan
    // is stopped and the stage starts again with the mild settings.
    state
        .execute(Command::SetMode { mode: Mode::Mild })
        .unwrap();
    wait_until("the stage to start again", || lab.calls().len() == 2);
    std::fs::remove_file(lab.file("hold")).unwrap();
    wait_finished(&coordinator, id);
    assert_eq!(statuses(&coordinator, id), ["done"; 4]);
    let calls = lab.calls();
    assert!(calls[1].starts_with("start nmap") && calls[1].contains(" -T3 "));
    for call in &calls[1..] {
        assert!(!call.contains(" -T4"), "{call}");
        assert!(!call.contains("--auto-tune"), "{call}");
    }
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("start feroxbuster") && call.contains("--rate-limit")),
        "{calls:?}"
    );
    assert_eq!(
        calls.iter().filter(|call| *call == "end nmap").count(),
        2,
        "the stopped scan never reached its end: {calls:?}"
    );

    // Turning the session up does not make an earlier mild request aggressive.
    state
        .execute(Command::SetMode { mode: Mode::Mild })
        .unwrap();
    std::fs::write(lab.file("hold"), "").unwrap();
    let before = lab.calls().len();
    let mild = recon(&coordinator, "10.0.0.5");
    wait_until("the mild task to start", || lab.calls().len() == before + 1);
    state
        .execute(Command::SetMode {
            mode: Mode::Aggressive,
        })
        .unwrap();
    std::fs::remove_file(lab.file("hold")).unwrap();
    wait_finished(&coordinator, mild);
    for call in &lab.calls()[before..] {
        assert!(!call.contains(" -T4"), "{call}");
        assert!(!call.contains("--auto-tune"), "{call}");
    }
}

#[test]
fn light_mode_stops_a_stage_between_its_runs() {
    let lab = Lab::new();
    // The crawl covers two sites (ports 80 and 443); the first run waits.
    std::fs::write(lab.file("hold-katana"), "").unwrap();
    let coordinator = lab.start();
    let state = coordinator.state();
    let id = recon(&coordinator, "10.0.0.5");
    let crawls = |lab: &Lab| {
        lab.calls()
            .iter()
            .filter(|call| call.starts_with("start katana"))
            .count()
    };
    wait_until("the first crawl to start", || crawls(&lab) == 1);

    state
        .execute(Command::SetMode { mode: Mode::Light })
        .unwrap();
    wait_until("the crawl to pause", || {
        statuses(&coordinator, id)[2] == "interrupted"
    });
    std::fs::remove_file(lab.file("hold-katana")).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        crawls(&lab),
        1,
        "no second site was crawled: {:?}",
        lab.calls()
    );
    assert!(!lab.calls().iter().any(|call| call == "end katana"));
    assert_eq!(
        statuses(&coordinator, id),
        ["done", "done", "interrupted", "pending"]
    );
    assert!(leftovers(&lab.workspace.tmp_dir()).is_empty());

    // Leaving light mode runs the stage from its start.
    state
        .execute(Command::SetMode { mode: Mode::Mild })
        .unwrap();
    wait_finished(&coordinator, id);
    assert_eq!(statuses(&coordinator, id), ["done"; 4]);
    assert_eq!(crawls(&lab), 3);
}

#[test]
fn a_planted_task_cannot_carry_unchecked_flags_into_a_later_stage() {
    let lab = Lab::new();
    let coordinator = lab.start();
    // A normal run first, so the graph holds open ports to inspect.
    let first = recon(&coordinator, "10.0.0.5");
    wait_finished(&coordinator, first);
    let before = lab.calls().len();

    // A task row as a tampered state.db would hold it: the port stage
    // already done, and flags the queue refuses when a task is added.
    let state = coordinator.state();
    let planted = {
        let db = state.db_lock();
        db.conn()
            .execute(
                "INSERT INTO tasks (target, mode, extra_flags, created_utc) VALUES \
                 ('10.0.0.5', 'mild', '[\"--script\",\"/tmp/evil.nse\"]', '2026-01-01T00:00:00Z')",
                (),
            )
            .unwrap();
        let id = db.conn().last_insert_rowid();
        for (position, (stage, status)) in [
            ("ports", "done"),
            ("services", "pending"),
            ("crawl", "pending"),
            ("dirs", "pending"),
        ]
        .into_iter()
        .enumerate()
        {
            db.conn()
                .execute(
                    "INSERT INTO task_stages (task_id, stage, position, status) VALUES (?1, ?2, ?3, ?4)",
                    (id, stage, position as i64, status),
                )
                .unwrap();
        }
        id
    };

    assert_eq!(state.resume_unfinished().unwrap(), 1);
    wait_finished(&coordinator, planted);
    let row = task(&coordinator, planted);
    assert_eq!(row.stages[1].status, "failed", "{:?}", row.stages[1]);
    assert!(
        row.stages[1].detail.contains("--script"),
        "the refusal names the flag: {}",
        row.stages[1].detail
    );
    // nmap was never started with it.
    let calls = lab.calls();
    assert!(
        calls[before..].iter().all(|call| !call.contains("nmap")),
        "{:?}",
        &calls[before..]
    );
    assert!(
        calls.iter().all(|call| !call.contains("evil.nse")),
        "{calls:?}"
    );
}
