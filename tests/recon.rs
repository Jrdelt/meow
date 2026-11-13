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
                 while [ -f '{hold}' ]; do sleep 0.05; done\n{body}\necho \"end {name}\" >> '{log}'\n",
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
            "start nmap {scan} -T3 --top-ports 1000 -p 1-1000 -oX {}/nmap_ports_{id}.xml 10.0.0.0/24",
            tmp_dir.display()
        )
    );
    assert!(
        calls[2].contains(" -sV ")
            && calls[2].contains(" -p 22,443,80 ")
            && calls[2].ends_with(" 10.0.0.5"),
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
    assert!(
        lab.calls().is_empty(),
        "nothing may run for a refused request"
    );
    assert!(queue::tasks(&state.db_lock(), 10).unwrap().is_empty());
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
            stage.detail.contains("is not installed (to add it: "),
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
    std::fs::remove_file(lab.file("hold")).unwrap();
    wait_until("both tasks to pause", || {
        statuses(&coordinator, first)[1] == "interrupted"
            && statuses(&coordinator, second)[0] == "interrupted"
    });
    assert_eq!(
        statuses(&coordinator, first)[0],
        "done",
        "the running stage was allowed to finish"
    );
    assert!(task(&coordinator, second).stages[0]
        .detail
        .contains("light mode"));
    let calls_while_paused = lab.calls().len();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        lab.calls().len(),
        calls_while_paused,
        "nothing runs in light mode"
    );

    let result = state
        .execute(Command::SetMode { mode: Mode::Mild })
        .unwrap();
    assert_eq!(result["resumed"], 2);
    wait_finished(&coordinator, first);
    wait_finished(&coordinator, second);
    assert_eq!(statuses(&coordinator, first), ["done"; 4]);
    assert_eq!(statuses(&coordinator, second), ["done"; 4]);
}
