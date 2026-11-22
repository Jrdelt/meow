use super::*;

#[test]
fn stages_can_be_turned_off_in_the_config() {
    let settings: ReconSettings =
        toml::from_str("skip = [\"udp\", \" JS \", \"waf_cdn\", \"no-such-stage\"]").unwrap();
    assert!(settings.skips(Stage::Udp));
    assert!(settings.skips(Stage::Js));
    assert!(settings.skips(Stage::WafCdn));
    assert!(!settings.skips(Stage::Ports));
    assert!(!ReconSettings::default().skips(Stage::Udp));
}

#[test]
fn the_udp_scan_names_its_services_and_explains_open_ones() {
    let settings = ReconSettings::default();
    let command = udp_command(
        &settings,
        &["203.0.113.5".to_owned()],
        &[],
        false,
        Path::new("/tmp/out.xml"),
    );
    assert_eq!(command.program, "nmap");
    assert_eq!(&command.args[..2], ["-sU", "-sV"]);
    let ports = command.args.iter().position(|a| a == "-p").unwrap();
    assert_eq!(command.args[ports + 1], UDP_PORTS);
    assert_eq!(
        command.args[command.args.len() - 2..],
        ["--", "203.0.113.5"]
    );
    assert!(!command.args.contains(&"-6".to_owned()));
    assert!(udp_command(
        &settings,
        &["2001:db8::5".to_owned()],
        &[],
        true,
        Path::new("o.xml")
    )
    .args
    .contains(&"-6".to_owned()));
    // Its flags are ones an operator may give, but for the progress
    // reports, which are meow's own.
    let own = command.args.len() - 6;
    assert_eq!(command.args[own..own + 3], ["--stats-every", "5s", "-oX"]);
    validate_nmap_flags(&command.args[..own]).unwrap();
    // Every port scanned has a note, and the notes are about UDP services.
    for port in UDP_PORTS.trim_start_matches("U:").split(',') {
        let port: u16 = port.parse().unwrap();
        assert!(udp_note(port).is_some(), "no note for {port}");
    }
    assert!(udp_note(161).unwrap().contains("SNMP"));
    assert!(udp_note(623).unwrap().contains("IPMI"));
    assert!(udp_note(9999).is_none());

    // nmap's UDP answers: open, open|filtered, and the rest closed.
    let xml = r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" args="nmap -sU">
<host><status state="up"/><address addr="203.0.113.5" addrtype="ipv4"/><ports>
<extraports state="closed" count="20"><extrareasons reason="port-unreach" count="20" proto="udp" ports="53,67,69"/></extraports>
<port protocol="udp" portid="161"><state state="open" reason="udp-response"/><service name="snmp" product="net-snmp" method="probed" conf="10"/></port>
<port protocol="udp" portid="123"><state state="open|filtered" reason="no-response"/><service name="ntp" method="table" conf="3"/></port>
</ports></host><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>"#;
    let observations = parsers::nmap::parse(xml, true).unwrap();
    let state_of = |number: u16| {
        observations.iter().find_map(|o| match o {
            Observation::Port {
                port,
                protocol,
                state,
                ..
            } if *port == number && protocol == "udp" => Some(state.clone()),
            _ => None,
        })
    };
    assert_eq!(state_of(161).as_deref(), Some("open"));
    assert_eq!(state_of(123).as_deref(), Some("open|filtered"));
}

#[tokio::test]
async fn work_in_progress_is_stopped_when_the_mode_changes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let changed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&changed);
    let same = move || !flag.load(Ordering::SeqCst);
    // A handshake that would take a minute (a slow SSH server).
    let slow = tokio::time::sleep(Duration::from_secs(60));
    let started = std::time::Instant::now();
    let switch = Arc::clone(&changed);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        switch.store(true, Ordering::SeqCst);
    });
    assert_eq!(while_same_mode(&same, slow).await, None);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    // Without a change the work finishes and its result comes back.
    changed.store(false, Ordering::SeqCst);
    assert_eq!(while_same_mode(&same, async { 7 }).await, Some(7));
}

fn args(command: &ToolCommand) -> String {
    command.args.join(" ")
}

fn target(text: &str) -> Target {
    Target::parse(text).unwrap()
}

#[test]
fn unprivileged_scans_fall_back_to_connect_and_drop_os_detection() {
    let flags = strings(&[
        "-sS", "-T4", "-p-", "-O", "--script", "ssl-cert", "-sV", "-sSV",
    ]);
    let (root, notices) = adapt_for_privilege(flags.clone(), true);
    assert_eq!(root, flags);
    assert!(notices.is_empty());

    let (user, notices) = adapt_for_privilege(flags, false);
    assert_eq!(
        user,
        strings(&["-sT", "-T4", "-p-", "--script", "ssl-cert", "-sV", "-sTV"])
    );
    assert_eq!(notices.len(), 3);
    assert!(notices[0].contains("connect scan instead of SYN scan"));
    assert!(notices[1].contains("no OS detection"));

    // UDP needs root: left out, with a way to do it by hand.
    let (user, notices) = adapt_for_privilege(strings(&["-sU", "-sSU", "-T3"]), false);
    assert_eq!(user, strings(&["-sT", "-T3"]));
    assert_eq!(notices.len(), 2);
    assert!(notices[0].contains("no UDP scan (-sU)"), "{notices:?}");
    assert!(notices[0].contains("meow add udp.xml"), "{notices:?}");
    let (root, notices) = adapt_for_privilege(strings(&["-sU"]), true);
    assert_eq!((root, notices.len()), (strings(&["-sU"]), 0));
}

#[test]
fn a_silent_target_says_how_to_scan_it_anyway() {
    let down =
        r#"<nmaprun><runstats><finished/><hosts up="0" down="1" total="1"/></runstats></nmaprun>"#;
    let up = r#"<nmaprun><host/><runstats><hosts up="1" down="0" total="1"/></runstats></nmaprun>"#;
    assert_eq!(nmap_hosts_up(down), Some(0));
    assert_eq!(nmap_hosts_up(up), Some(1));
    assert_eq!(nmap_hosts_up("<nmaprun>"), None);
    assert!(discovery_hint(&[]).contains("run again with `-- -Pn`"));
    assert!(discovery_hint(&strings(&["-Pn"])).contains("even scanning without the up check"));
}

#[test]
fn port_stage_command_is_built_from_preset_extra_flags_and_target() {
    let settings = ReconSettings::default();
    let mild = settings.preset(Mode::Mild, &PresetOverride::default());
    let out = Path::new("/w/tmp/nmap_ports_7.xml");

    let (command, notices) =
        ports_command(&settings, &mild, &target("10.0.0.0/24"), &[], true, out);
    assert_eq!(command.program, "nmap");
    assert_eq!(
        args(&command),
        "-sS -T3 --top-ports 1000 --stats-every 5s -oX /w/tmp/nmap_ports_7.xml -- 10.0.0.0/24"
    );
    assert!(notices.is_empty());

    // Ports the operator names replace the preset's --top-ports, which
    // nmap would otherwise apply within them (verified with nmap 7.94:
    // `--top-ports 1000 -p-` scans 1000 ports, `-p-` alone 65535).
    let extra = strings(&["-p", "80,443", "-O"]);
    let (command, notices) =
        ports_command(&settings, &mild, &target("10.0.0.5"), &extra, false, out);
    assert_eq!(
        args(&command),
        "-sT -T3 -p 80,443 --stats-every 5s -oX /w/tmp/nmap_ports_7.xml -- 10.0.0.5"
    );
    assert_eq!(notices.len(), 2);
    for (extra, expected) in [
        (vec!["-p-"], "-sS -T3 -p-"),
        (vec!["-p1-10000"], "-sS -T3 -p1-10000"),
        (vec!["--top-ports", "100"], "-sS -T3 --top-ports 100"),
        (vec!["-F"], "-sS -T3 -F"),
        (vec!["-Pn"], "-sS -T3 --top-ports 1000 -Pn"),
    ] {
        let (command, _) = ports_command(
            &settings,
            &mild,
            &target("10.0.0.5"),
            &strings(&extra),
            true,
            out,
        );
        assert_eq!(
            args(&command),
            format!("{expected} --stats-every 5s -oX /w/tmp/nmap_ports_7.xml -- 10.0.0.5"),
            "{extra:?}"
        );
    }

    let aggressive = settings.preset(Mode::Aggressive, &PresetOverride::default());
    let (command, _) = ports_command(
        &settings,
        &aggressive,
        &target("2001:db8::/64"),
        &[],
        true,
        out,
    );
    assert_eq!(
        args(&command),
        "-sS -T4 -p- -O -6 --stats-every 5s -oX /w/tmp/nmap_ports_7.xml -- 2001:db8::/64"
    );
}

#[test]
fn service_stage_probes_only_the_open_ports() {
    let settings = ReconSettings::default();
    let mild = settings.preset(Mode::Mild, &PresetOverride::default());
    let (command, _) = services_command(
        &settings,
        &mild,
        &ReconFlags::default(),
        "10.0.0.5",
        &[22, 443, 8080],
        false,
        Path::new("/t/svc.xml"),
    );
    assert_eq!(
        args(&command),
        "-sV --version-intensity 5 -T3 --script ssl-cert,http-server-header,http-title \
         -p 22,443,8080 --stats-every 5s -oX /t/svc.xml -- 10.0.0.5"
    );
    let (command, _) = services_command(
        &settings,
        &mild,
        &ReconFlags::default(),
        "2001:db8::a",
        &[80],
        true,
        Path::new("/t/svc.xml"),
    );
    assert!(args(&command).contains("-6 -p 80 --stats-every 5s -oX /t/svc.xml -- 2001:db8::a"));
}

#[test]
fn only_known_categories_and_built_in_scripts_reach_the_script_expression() {
    let chosen = strings(&[
        "vuln",
        "banner",
        "/tmp/evil.nse",
        "http-shellshock",
        "default or exploit",
    ]);
    assert_eq!(
        script_expression(&["ssl-cert"], &chosen),
        format!("ssl-cert or banner or ((vuln) and not ({SCRIPT_NEVER}))")
    );
}

#[test]
fn os_detection_versions_and_scripts_go_to_the_stage_they_belong_to() {
    let flags = split_recon_flags(&strings(&[
        "-A",
        "-p-",
        "-Pn",
        "--script",
        "vuln,default",
        "--version-all",
        "-sSV",
    ]));
    assert_eq!(flags.ports, strings(&["-O", "-p-", "-Pn", "-sS"]));
    assert_eq!(flags.versions, strings(&["--version-all"]));
    assert_eq!(flags.scripts, strings(&["default", "vuln"]));
    assert_eq!(flags.shared, strings(&["-Pn"]));

    let settings = ReconSettings::default();
    let mild = settings.preset(Mode::Mild, &PresetOverride::default());
    let (command, _) = services_command(
        &settings,
        &mild,
        &flags,
        "10.0.0.5",
        &[22, 445],
        true,
        Path::new("/t/svc.xml"),
    );
    // One --script: the built-in scripts, then the chosen categories
    // with the never-run ones excluded (nmap --script-help checked:
    // 0 of the selected scripts are intrusive, external, brute, dos,
    // exploit, fuzzer, malware or broadcast). `-Pn` carries over from
    // Stage 1 so hosts that ignore discovery probes still get inspected.
    assert_eq!(
        command.args,
        strings(&[
            "-sV",
            "--version-intensity",
            "5",
            "-T3",
            "--script",
            "ssl-cert or http-server-header or http-title or ((default or vuln) and not \
             (intrusive or external or brute or dos or exploit or fuzzer or malware or broadcast))",
            "--version-all",
            "-Pn",
            "-p",
            "22,445",
            "--stats-every",
            "5s",
            "-oX",
            "/t/svc.xml",
            "--",
            "10.0.0.5",
        ])
    );
    // -sC alone, and --script= spelled inline.
    assert_eq!(
        split_recon_flags(&strings(&["-sC"])).scripts,
        strings(&["default"])
    );
    assert_eq!(
        split_recon_flags(&strings(&["--script=safe,ssh-hostkey"])).scripts,
        strings(&["safe", "ssh-hostkey"])
    );
    // --ports replaces the preset's --top-ports choice.
    let (port_cmd, _) = ports_command(
        &settings,
        &mild,
        &target("10.0.0.5"),
        &strings(&["--ports", "80,443"]),
        true,
        Path::new("/t/ports.xml"),
    );
    assert!(!args(&port_cmd).contains("--top-ports"));
}

#[test]
fn nmap_flag_allowlist_permits_tuning_and_blocks_scripts_files_and_targets() {
    for allowed in [
        &[][..],
        &["-Pn", "-p", "22,80,443", "-T4", "--open"],
        &["-p-", "-sU", "--top-ports=100", "--max-retries", "2"],
        &["-p80-90", "-PS22,443", "-PA", "-n", "--reason"],
        &["-p", "T:80,U:53", "-p", "http,ssh"],
        &[
            "--min-rate",
            "100",
            "--max-rate=500",
            "--host-timeout",
            "5m",
            "--scan-delay=200ms",
            "--exclude",
            "192.0.2.1,198.51.100.0/24,10.0.0.0/8",
        ],
        &["-T", "3", "--exclude-ports=9100,515"],
        // OS detection, versions and scripts by category.
        &["-A"],
        &["-sC", "-O", "--version-all"],
        &["--script", "default,vuln,safe,discovery,version"],
        &["--script=ssh-hostkey,banner"],
    ] {
        validate_nmap_flags(&strings(allowed))
            .unwrap_or_else(|e| panic!("rejected safe flags {allowed:?}: {e:#}"));
    }

    for mode in [Mode::Mild, Mode::Aggressive] {
        let preset = Preset::builtin(mode);
        validate_preset_nmap_flags(&preset.nmap_ports, &preset.nmap_services).unwrap();
    }

    for blocked in [
        &["--script=/tmp/evil.nse"][..],
        &["--script", "intrusive"],
        &["--script", "default,brute"],
        &["--script", "all"],
        &["--script", "*"],
        &["--script", "vuln and intrusive"],
        &["--script", "smb-vuln-ms17-010"],
        &["--script-args", "foo=bar"],
        &["--script-args-file=/etc/passwd"],
        &["-sSC"],
        &["-sVV"],
        &["-oN", "/tmp/out.txt"],
        &["-oX", "/tmp/out.xml"],
        &["-oG", "-"],
        &["-oA", "/tmp/base"],
        &["--append-output"],
        &["--resume", "/tmp/scan.gnmap"],
        &["--datadir", "/tmp"],
        &["--servicedb", "/tmp/services"],
        &["--stylesheet", "https://example.invalid/x.xsl"],
        &["-iL", "/etc/hosts"],
        &["-iR", "50"],
        &["--excludefile", "/etc/hosts"],
        &["--proxies", "http://192.0.2.9:8080"],
        &["-D", "192.0.2.2"],
        &["-S", "192.0.2.2"],
        &["-e", "en0"],
        &["192.0.2.99"],
        &["--", "192.0.2.99"],
        &["-"],
        &[""],
        &["-p"],
        &["-p", "-oN"],
        &["--top-ports"],
        &["--top-ports=0"],
        &["--top-ports=70000"],
        &["--exclude", "-iL"],
        &["-p", "80\n443"],
        // nmap would read these as --port-ratio, --packet-trace,
        // --privileged and --proxies, taking the next value with them.
        &["-po", "-p", "2130706434"],
        &["-po"],
        &["-pa"],
        &["-packet-trace"],
        &["-pri"],
        &["-privileged"],
        &["-pro", "-p", "http"],
        &["-proxies"],
        &["-pT:80"],
        &["-phttp"],
    ] {
        assert!(
            validate_nmap_flags(&strings(blocked)).is_err(),
            "accepted unsafe flags {blocked:?}"
        );
    }

    let too_many: Vec<String> = vec!["-n".to_owned(); MAX_NMAP_FLAGS + 1];
    assert!(validate_nmap_flags(&too_many).is_err());

    // Service presets may name only the known safe built-in NSE scripts,
    // never arbitrary script names or file paths.
    assert!(validate_preset_nmap_flags(
        &strings(&["-sS"]),
        &strings(&["-sV", "--script", "/tmp/evil.nse"])
    )
    .is_err());
    assert!(
        validate_preset_nmap_flags(&strings(&["-sS"]), &strings(&["-sV", "--script=vuln"]))
            .is_err()
    );
    assert!(
        validate_preset_nmap_flags(&strings(&["--script", "ssl-cert"]), &strings(&["-sV"]))
            .is_err()
    );

    // `enqueue` enforces the same gate at persistence time.
    let db = Db::open_in_memory().unwrap();
    assert!(enqueue(
        &db,
        "192.0.2.10",
        Mode::Mild,
        &strings(&["--script=/tmp/evil.nse"])
    )
    .is_err());
}

#[test]
fn web_stage_commands_match_the_mode_rules() {
    let settings = ReconSettings::default();
    let none = PresetOverride::default();
    let mild = settings.preset(Mode::Mild, &none);
    let aggressive = settings.preset(Mode::Aggressive, &none);
    let out = Path::new("/t/out.jsonl");
    let url = "https://app.lab.local:8443";

    assert_eq!(
        args(&crawl_command(&settings, &mild, url, out)),
        "-u https://app.lab.local:8443 -jsonl -silent -nc -jc -fs fqdn -dr -ct 5m -d 2 -o /t/out.jsonl"
    );
    assert!(args(&crawl_command(&settings, &aggressive, url, out)).contains(" -d 4 "));

    let wordlist = Path::new("/usr/share/wordlists/common.txt");
    assert_eq!(
        args(&dirs_command(&settings, &mild, url, wordlist, out)),
        "-u https://app.lab.local:8443 --quiet --no-state --rate-limit 20 --scan-limit 1 --auto-bail \
         --time-limit 10m --json -o /t/out.jsonl -w /usr/share/wordlists/common.txt"
    );
    let fast = args(&dirs_command(&settings, &aggressive, url, wordlist, out));
    assert_eq!(
        fast,
        "-u https://app.lab.local:8443 --quiet --no-state --auto-tune --time-limit 15m \
         --json -o /t/out.jsonl -w /usr/share/wordlists/common.txt"
    );
    assert!(!fast.contains("--rate-limit") && !fast.contains("--auto-bail"));
}

#[test]
fn presets_layer_builtin_config_and_profile() {
    let mut settings = ReconSettings::default();
    settings.mild.nmap_ports = Some(strings(&["-sT", "--top-ports", "100"]));
    settings.mild.katana_depth = Some(3);
    let profile = PresetOverride {
        katana_depth: Some(1),
        ferox_rate_limit: Some(5),
        ..PresetOverride::default()
    };
    let preset = settings.preset(Mode::Mild, &profile);
    assert_eq!(preset.nmap_ports, strings(&["-sT", "--top-ports", "100"]));
    assert_eq!(preset.katana_depth, 1, "profile.toml wins over config.toml");
    assert_eq!(preset.ferox_rate_limit, Some(5));
    assert_eq!(
        preset.nmap_services,
        Preset::builtin(Mode::Mild).nmap_services
    );
    // The aggressive preset is untouched by the mild overrides.
    assert_eq!(
        settings.preset(Mode::Aggressive, &PresetOverride::default()),
        Preset::builtin(Mode::Aggressive)
    );

    let parsed: ReconSettings = toml::from_str(
        "stage_timeout_secs = 60\nwordlist_path = \"/w.txt\"\nnmap = \"/opt/nmap\"\n\
         [aggressive]\nnmap_ports = [\"-sS\", \"-T5\"]\n",
    )
    .unwrap();
    assert_eq!(parsed.stage_timeout_secs, 60);
    assert_eq!(parsed.output_cap_mb, 50);
    assert_eq!(parsed.nmap, "/opt/nmap");
    assert_eq!(parsed.aggressive.nmap_ports, Some(strings(&["-sS", "-T5"])));
    assert_eq!(
        high_rate_flags(&strings(&["-sS", "-T5", "-A", "-T3"])),
        ["-T5", "-A"]
    );
}

#[test]
fn wordlist_is_only_used_if_it_exists() {
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("words.txt");
    std::fs::write(&list, "admin\n").unwrap();
    assert_eq!(
        find_wordlist(Some(list.to_str().unwrap()), None),
        Some(list)
    );
    let missing = dir.path().join("missing.txt");
    let found = find_wordlist(Some(missing.to_str().unwrap()), None);
    assert!(found.is_none_or(|path| STANDARD_WORDLISTS.contains(&path.to_str().unwrap())));

    // Without a configured or system wordlist, the user's own folder is
    // read: the first .txt file by name, nothing else.
    let own = dir.path().join("own");
    std::fs::create_dir(&own).unwrap();
    std::fs::write(own.join("notes.md"), "x").unwrap();
    std::fs::write(own.join("b.txt"), "x").unwrap();
    std::fs::write(own.join("a.txt"), "x").unwrap();
    let installed = STANDARD_WORDLISTS.iter().any(|p| Path::new(p).is_file());
    if !installed {
        assert_eq!(find_wordlist(None, Some(&own)), Some(own.join("a.txt")));
        assert_eq!(find_wordlist(None, Some(&dir.path().join("none"))), None);
    }
}

fn statuses_of(db: &Db, id: i64) -> Vec<String> {
    task(db, id)
        .unwrap()
        .unwrap()
        .stages
        .iter()
        .map(|s| s.status.clone())
        .collect()
}

fn stage_of(row: &TaskRow, stage: Stage) -> StageRow {
    row.stages
        .iter()
        .find(|s| s.stage == stage)
        .unwrap()
        .clone()
}

fn is_time(text: &Option<String>) -> bool {
    text.as_deref()
        .is_some_and(|t| crate::timeutil::parse_rfc3339(t).is_some())
}

#[test]
fn task_rows_track_stage_status() {
    let db = Db::open_in_memory().unwrap();
    let id = enqueue(&db, "10.0.0.0/24", Mode::Mild, &strings(&["-p", "80"])).unwrap();
    let row = task(&db, id).unwrap().unwrap();
    assert_eq!(row.target, "10.0.0.0/24");
    assert_eq!(row.mode, Mode::Mild);
    assert_eq!(row.extra_flags, ["-p", "80"]);
    assert_eq!(statuses_of(&db, id), ["pending"; STAGES.len()]);
    assert!(row.unfinished());
    assert_eq!(row.stages_over(), 0);
    assert_eq!(newest_id(&db).unwrap(), id);

    // Every stage before `services` is done; `services` is running.
    let running = STAGES.iter().position(|s| *s == Stage::Services).unwrap();
    for s in &STAGES[..running] {
        set_stage(&db, id, *s, "done", "ok").unwrap();
    }
    set_stage(&db, id, Stage::Services, "running", "").unwrap();
    assert_eq!(unfinished(&db).unwrap().len(), 1);
    assert_eq!(task(&db, id).unwrap().unwrap().stages_over(), running);

    // Light mode stops it: it still has work to do in this session.
    set_stage(&db, id, Stage::Services, "interrupted", LIGHT_DETAIL).unwrap();
    let paused = task(&db, id).unwrap().unwrap();
    assert!(paused.unfinished() && paused.stages[running].live());
    assert_eq!(unfinished(&db).unwrap(), std::slice::from_ref(&paused));

    // Every stage over, however it ended: nothing is left to do.
    for s in &STAGES[running..] {
        set_stage(&db, id, *s, "skipped", "turned off").unwrap();
    }
    let over = task(&db, id).unwrap().unwrap();
    assert!(!over.unfinished());
    assert_eq!(over.stages_over(), STAGES.len());
    assert!(unfinished(&db).unwrap().is_empty());
    assert_eq!(task(&db, 999).unwrap(), None);
    assert_eq!(newest_id(&Db::open_in_memory().unwrap()).unwrap(), 0);

    // The same rule as SQL, for the same words.
    assert!(LIVE_STAGE.contains(&format!("detail <> '{CLOSED_DETAIL}'")));
    for (status, word) in [
        ("pending", "waiting"),
        ("running", "running"),
        ("done", "done"),
        ("skipped", "skipped"),
        ("failed", "failed"),
        ("interrupted", "stopped"),
    ] {
        assert_eq!(status_word(status), word);
    }
}

/// A session that closes ends its recons: the running stage is stopped,
/// the stages that had not started are left out, and what was finished
/// stays as it is. Nothing is kept waiting for a later session.
#[test]
fn a_closed_session_stops_its_running_stage_and_drops_the_rest() {
    let db = Db::open_in_memory().unwrap();
    let id = enqueue(&db, "192.0.2.5", Mode::Mild, &[]).unwrap();
    for stage in STAGES.iter().take_while(|stage| **stage != Stage::Ports) {
        set_stage(&db, id, *stage, "done", "").unwrap();
    }
    set_stage(&db, id, Stage::Lan, "done", "3 neighbours").unwrap();
    set_stage(&db, id, Stage::Dns, "skipped", "turned off").unwrap();
    set_stage(&db, id, Stage::Trace, "failed", "no route").unwrap();
    // A stage that ran before and is running again.
    set_stage(&db, id, Stage::Ports, "done", "earlier").unwrap();
    set_stage(&db, id, Stage::Ports, "running", "").unwrap();
    // A second recon, queued behind it: nothing of it has started.
    let queued = enqueue(&db, "192.0.2.6", Mode::Aggressive, &[]).unwrap();
    let before = task(&db, id).unwrap().unwrap();
    // The times of each stage come with the rows.
    assert!(is_time(&stage_of(&before, Stage::Lan).finished_utc));
    assert!(is_time(&stage_of(&before, Stage::Ports).started_utc));
    assert_eq!(
        stage_of(&before, Stage::Ports).finished_utc,
        None,
        "running again"
    );
    assert_eq!(stage_of(&before, Stage::Services).started_utc, None);
    assert_eq!(
        stage_of(&before, Stage::Ports).progress,
        None,
        "never stored"
    );
    let over_before = before.stages_over();

    assert_eq!(end_session(&db, SessionEnd::Closed).unwrap(), 2);
    let after = task(&db, id).unwrap().unwrap();
    for (was, is) in before.stages.iter().zip(&after.stages) {
        match was.status.as_str() {
            "running" => {
                assert_eq!(is.status, "interrupted", "{:?}", is.stage);
                assert_eq!(is.detail, "stopped: the session was closed");
                assert_eq!(is.started_utc, was.started_utc);
                assert!(is_time(&is.finished_utc), "{:?}", is.finished_utc);
                assert!(!is.live() && !is.not_run());
            }
            "pending" => {
                assert_eq!(is.status, "skipped", "{:?}", is.stage);
                assert_eq!(is.detail, "not run: the session was closed");
                assert!(is.started_utc.is_none() && is_time(&is.finished_utc));
                assert!(is.not_run() && !is.live());
            }
            // Finished stages keep status, result and times.
            _ => assert_eq!(was, is),
        }
    }
    assert_eq!(stage_of(&after, Stage::Lan).detail, "3 neighbours");
    assert!(
        !stage_of(&after, Stage::Dns).not_run(),
        "turned off, not cut"
    );
    // Nothing of either recon is left to do, now or later.
    assert!(!after.unfinished());
    assert!(unfinished(&db).unwrap().is_empty());
    assert_eq!(
        after.stages_over(),
        over_before,
        "the cut stages are not over"
    );
    let never = task(&db, queued).unwrap().unwrap();
    assert!(never.stages.iter().all(StageRow::not_run), "{never:?}");
    assert_eq!(never.stages_over(), 0);
    assert_eq!(tasks(&db, 5).unwrap(), [never.clone(), after.clone()]);
    // Said again, it changes nothing.
    assert_eq!(end_session(&db, SessionEnd::Closed).unwrap(), 0);
    assert_eq!(end_session(&db, SessionEnd::Lost).unwrap(), 0);
    assert_eq!(task(&db, id).unwrap().unwrap(), after);

    // The next start is told of both, once.
    let (left, more) = take_left(&db).unwrap();
    assert_eq!(
        (left.as_slice(), more),
        ([after.clone(), never.clone()].as_slice(), 0)
    );
    assert_eq!(
        after.left_line(true),
        "Recon 192.0.2.5 cut short at ports \u{b7} `meow recon 192.0.2.5`"
    );
    // None of its stages ran: "not run" says it all.
    assert_eq!(
        never.left_line(true),
        "Recon 192.0.2.6 not run \u{b7} `meow recon 192.0.2.6`"
    );
    assert_eq!(take_left(&db).unwrap(), (Vec::new(), 0));
}

/// After a meow that was killed, the next start finds its stages as they
/// were: the one left running is marked stopped (nothing says when it
/// ended) and the ones that had not run are left out.
#[test]
fn what_a_killed_meow_left_is_ended_by_the_next_start() {
    let db = Db::open_in_memory().unwrap();
    let id = enqueue(&db, "192.0.2.5", Mode::Mild, &[]).unwrap();
    for stage in STAGES.iter().take_while(|stage| **stage != Stage::Ports) {
        set_stage(&db, id, *stage, "running", "").unwrap();
        set_stage(&db, id, *stage, "done", "3 neighbours").unwrap();
    }
    // A stage that ended once and was running again.
    set_stage(&db, id, Stage::Ports, "running", "").unwrap();
    set_stage(&db, id, Stage::Ports, "interrupted", LIGHT_DETAIL).unwrap();
    set_stage(&db, id, Stage::Ports, "running", "").unwrap();
    // A recon that light mode had stopped at a stage that had run.
    let paused = enqueue(&db, "192.0.2.6", Mode::Mild, &[]).unwrap();
    set_stage(&db, paused, Stage::Lan, "running", "").unwrap();
    set_stage(&db, paused, Stage::Lan, "interrupted", LIGHT_DETAIL).unwrap();
    let before = task(&db, id).unwrap().unwrap();
    let paused_before = task(&db, paused).unwrap().unwrap();

    assert_eq!(end_session(&db, SessionEnd::Lost).unwrap(), 2);
    let after = task(&db, id).unwrap().unwrap();
    for (was, is) in before.stages.iter().zip(&after.stages) {
        match was.status.as_str() {
            "running" => {
                assert_eq!(
                    (is.status.as_str(), is.detail.as_str()),
                    ("interrupted", CLOSED_DETAIL)
                );
                assert_eq!(is.started_utc, was.started_utc);
                assert_eq!(is.finished_utc, None, "no end time is made up");
            }
            "pending" => assert_eq!(
                (is.status.as_str(), is.detail.as_str()),
                ("skipped", "not run: the session ended")
            ),
            _ => assert_eq!(was, is),
        }
    }
    // The stage light mode had stopped is left out too, with the times it
    // ran from and to.
    let after_paused = task(&db, paused).unwrap().unwrap();
    let lan = stage_of(&after_paused, Stage::Lan);
    assert_eq!(
        (lan.status.as_str(), lan.detail.as_str()),
        ("skipped", NOT_RUN_ENDED)
    );
    assert_eq!(
        (&lan.started_utc, &lan.finished_utc),
        (
            &stage_of(&paused_before, Stage::Lan).started_utc,
            &stage_of(&paused_before, Stage::Lan).finished_utc
        )
    );
    assert!(after_paused.stages.iter().all(StageRow::not_run));
    assert!(unfinished(&db).unwrap().is_empty());
    assert_eq!(end_session(&db, SessionEnd::Lost).unwrap(), 0);

    // A later session that ends changes nothing of them: the stopped
    // stage stays stopped.
    let later = enqueue(&db, "192.0.2.7", Mode::Mild, &[]).unwrap();
    assert_eq!(end_session(&db, SessionEnd::Closed).unwrap(), 1);
    assert_eq!(task(&db, id).unwrap().unwrap(), after);
    assert_eq!(task(&db, paused).unwrap().unwrap(), after_paused);
    let (left, more) = take_left(&db).unwrap();
    assert_eq!(
        left.iter().map(|row| row.id).collect::<Vec<_>>(),
        [id, paused, later]
    );
    assert_eq!(more, 0);
}

/// A recon that meow 0.2.3 kept for its resume question: the first start
/// of this version ends it like any other, and the stage that was stopped
/// then is shown as stopped.
#[test]
fn a_recon_an_earlier_version_kept_for_a_resume_is_ended_too() {
    let db = Db::open_in_memory().unwrap();
    let id = enqueue(&db, "192.0.2.5", Mode::Mild, &[]).unwrap();
    set_stage(&db, id, Stage::Lan, "done", "3 neighbours").unwrap();
    set_stage(&db, id, Stage::Dns, "running", "").unwrap();
    set_stage(
        &db,
        id,
        Stage::Dns,
        "interrupted",
        "the session ended while this stage was running",
    )
    .unwrap();
    // One it had paused in light mode, in its words.
    let paused = enqueue(&db, "192.0.2.6", Mode::Mild, &[]).unwrap();
    set_stage(
        &db,
        paused,
        Stage::Lan,
        "interrupted",
        "paused: the session is in light mode",
    )
    .unwrap();
    assert_eq!(unfinished(&db).unwrap().len(), 2);

    assert_eq!(end_session(&db, SessionEnd::Lost).unwrap(), 2);
    let row = task(&db, id).unwrap().unwrap();
    let dns = stage_of(&row, Stage::Dns);
    assert_eq!(
        (dns.status.as_str(), dns.detail.as_str()),
        ("interrupted", CLOSED_DETAIL)
    );
    assert!(row.stages[2..].iter().all(StageRow::not_run));
    assert_eq!(
        row.left_line(true),
        "Recon 192.0.2.5 cut short at dns \u{b7} `meow recon 192.0.2.5`"
    );
    assert!(task(&db, paused)
        .unwrap()
        .unwrap()
        .stages
        .iter()
        .all(StageRow::not_run));
    assert!(unfinished(&db).unwrap().is_empty());
}

/// What is said of a recon that was cut short: short, once, and never a
/// command to run for a target that someone else may have put there.
#[test]
fn the_line_about_a_cut_recon_offers_only_the_users_own_targets() {
    let db = Db::open_in_memory().unwrap();
    let id = enqueue(&db, "192.0.2.10", Mode::Mild, &[]).unwrap();
    for stage in STAGES.iter().take_while(|stage| **stage != Stage::Dirs) {
        set_stage(&db, id, *stage, "done", "").unwrap();
    }
    set_stage(&db, id, Stage::Dirs, "running", "").unwrap();
    end_session(&db, SessionEnd::Closed).unwrap();
    let row = task(&db, id).unwrap().unwrap();
    // Stopped at the last stage: nothing was left out.
    assert_eq!(
        row.left_line(true),
        "Recon 192.0.2.10 cut short at dirs \u{b7} `meow recon 192.0.2.10`"
    );
    // Files that are not the user's own: no command is offered.
    assert_eq!(
        row.left_line(false),
        "Dropped a scan queued in these files: recon 192.0.2.10"
    );
    // A target that is none (only a changed database holds one) is never
    // put into a command, and is shown as plain text.
    let mut planted = row.clone();
    planted.target = "192.0.2.10`; curl x | sh #\u{1b}[2J".to_owned();
    let line = planted.left_line(true);
    assert!(
        !line.contains("rerun") && !line.contains("`meow") && !line.contains('\u{1b}'),
        "{line}"
    );
    assert!(line.starts_with("Dropped a scan queued in these files: recon 192.0.2.10"));

    // More recons than are told one by one: the newest, and how many more.
    take_left(&db).unwrap();
    let ids: Vec<i64> = (0..LEFT_MAX + 3)
        .map(|n| enqueue(&db, &format!("192.0.2.{n}"), Mode::Mild, &[]).unwrap())
        .collect();
    assert_eq!(end_session(&db, SessionEnd::Closed).unwrap(), LEFT_MAX + 3);
    let (left, more) = take_left(&db).unwrap();
    assert_eq!(left.iter().map(|row| row.id).collect::<Vec<_>>(), ids[3..]);
    assert_eq!(more, 3);

    // A list that is not meow's own is not believed.
    for planted in [
        format!("{{\"ids\":[{}],\"more\":0}}", "1,".repeat(4000) + "1"),
        "not a list".to_owned(),
        "{\"ids\":[-5,999999,1,1,1,1,1,1,1,1,1],\"more\":18446744073709551615}".to_owned(),
    ] {
        db.set_meta("recon_left", &planted).unwrap();
        let (left, _) = take_left(&db).unwrap();
        assert!(left.len() <= LEFT_MAX, "{planted}: {}", left.len());
        assert_eq!(db.get_meta("recon_left").unwrap(), None);
    }
}

/// Tasks as a session that is gone leaves them, for a view of it: the
/// same as the next start stores, and nothing is stored by looking.
#[test]
fn a_view_of_a_session_that_is_gone_shows_its_recons_as_ended() {
    let db = Db::open_in_memory().unwrap();
    let id = enqueue(&db, "192.0.2.5", Mode::Mild, &[]).unwrap();
    set_stage(&db, id, Stage::Lan, "done", "3 neighbours").unwrap();
    set_stage(&db, id, Stage::Dns, "running", "").unwrap();
    let paused = enqueue(&db, "192.0.2.6", Mode::Mild, &[]).unwrap();
    set_stage(&db, paused, Stage::Lan, "interrupted", LIGHT_DETAIL).unwrap();

    let mut shown = tasks(&db, 5).unwrap();
    shown[1].stages[1].progress = Some(Progress::items(1, 2));
    show_ended(&mut shown);
    assert_eq!(statuses_of(&db, id)[..3], ["done", "running", "pending"]);
    assert_eq!(statuses_of(&db, paused)[..2], ["interrupted", "pending"]);

    end_session(&db, SessionEnd::Closed).unwrap();
    let ended = tasks(&db, 5).unwrap();
    for (shown, ended) in shown.iter().zip(&ended) {
        for (shown, ended) in shown.stages.iter().zip(&ended.stages) {
            assert_eq!(
                (&shown.status, &shown.detail, &shown.progress),
                (&ended.status, &ended.detail, &None),
                "{:?}",
                shown.stage
            );
        }
    }
    // A stage an earlier session stopped stays as it is.
    let before = shown.clone();
    show_ended(&mut shown);
    assert_eq!(shown, before);

    // A workspace meow 0.2.3 closed, looked at before this version first
    // opens it: the stage it had stopped is shown as stopped, not as one
    // that never ran, and the same as the first start then stores.
    let old = enqueue(&db, "192.0.2.7", Mode::Mild, &[]).unwrap();
    set_stage(&db, old, Stage::Lan, "done", "3 neighbours").unwrap();
    set_stage(&db, old, Stage::Dns, "running", "").unwrap();
    set_stage(&db, old, Stage::Dns, "interrupted", CLOSED_DETAIL_BEFORE).unwrap();
    let mut shown = vec![task(&db, old).unwrap().unwrap()];
    show_ended(&mut shown);
    let dns = stage_of(&shown[0], Stage::Dns);
    assert_eq!(
        (dns.status.as_str(), dns.detail.as_str()),
        ("interrupted", CLOSED_DETAIL)
    );
    assert!(shown[0].stages[2..].iter().all(StageRow::not_run));
    end_session(&db, SessionEnd::Lost).unwrap();
    let stored = task(&db, old).unwrap().unwrap();
    for (shown, stored) in shown[0].stages.iter().zip(&stored.stages) {
        assert_eq!(
            (&shown.status, shown.not_run()),
            (&stored.status, stored.not_run())
        );
    }
    assert_eq!(stage_of(&stored, Stage::Dns).detail, CLOSED_DETAIL);
}

/// What a tool was writing when meow was killed is cleared when the next
/// session starts; nothing else in `tmp/` is touched.
#[test]
fn a_new_session_clears_what_a_killed_tool_left_in_tmp() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path().join("tmp");
    let outside = dir.path().join("outside");
    for folder in [tmp.join("run-Ab12Cd"), tmp.join("shell"), outside.clone()] {
        std::fs::create_dir_all(&folder).unwrap();
    }
    for file in [
        tmp.join("run-Ab12Cd").join("nmap.log"),
        tmp.join("nmap_svc_3_0.xml"),
        tmp.join("katana_12_1.jsonl"),
        // Not a tool's: other names, a stage's name without a task.
        tmp.join("shell").join("bashrc"),
        tmp.join("map-open.html"),
        tmp.join("nmap_svc_notes.xml"),
        tmp.join("run-notes.txt"),
        outside.join("keep.txt"),
    ] {
        std::fs::write(file, "x").unwrap();
    }
    #[cfg(unix)]
    for link in ["run-linked", "ferox_7_0.jsonl"] {
        // A link with a tool's name leads out of tmp: not followed, kept.
        let to = if link.starts_with("run-") {
            outside.clone()
        } else {
            outside.join("keep.txt")
        };
        std::os::unix::fs::symlink(to, tmp.join(link)).unwrap();
    }

    assert_eq!(clear_tool_leftovers(&tmp), 3);
    let mut left: Vec<String> = std::fs::read_dir(&tmp)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| !matches!(name.as_str(), "run-linked" | "ferox_7_0.jsonl"))
        .collect();
    left.sort();
    assert_eq!(
        left,
        [
            "map-open.html",
            "nmap_svc_notes.xml",
            "run-notes.txt",
            "shell"
        ]
    );
    assert!(tmp.join("shell").join("bashrc").exists());
    assert!(outside.join("keep.txt").exists());
    // Nothing left to clear, and no folder at all, are both fine.
    assert_eq!(clear_tool_leftovers(&tmp), 0);
    assert_eq!(clear_tool_leftovers(&dir.path().join("none")), 0);
}

#[test]
fn only_meow_asks_nmap_for_progress_reports() {
    let settings = ReconSettings::default();
    let out = Path::new("/w/tmp/out.xml");
    let asks = |command: &ToolCommand| {
        let at: Vec<usize> = (0..command.args.len())
            .filter(|i| command.args[*i].starts_with("--stats"))
            .collect();
        // Once, with its value, among the options (before `--`).
        let end = command.args.iter().position(|a| a == "--").unwrap();
        at.len() == 1 && command.args[at[0]..at[0] + 2] == NMAP_STATS && at[0] + 1 < end
    };
    for mode in [Mode::Mild, Mode::Aggressive] {
        let preset = settings.preset(mode, &PresetOverride::default());
        for extra in [&[][..], &["-p-", "-T4", "-Pn", "-A", "--script", "vuln"]] {
            let flags = split_recon_flags(&strings(extra));
            let target = target("192.0.2.0/28");
            let (ports, _) = ports_command(&settings, &preset, &target, &flags.ports, false, out);
            assert!(asks(&ports), "{:?}", ports.args);
            let (services, _) =
                services_command(&settings, &preset, &flags, "192.0.2.5", &[80], true, out);
            assert!(asks(&services), "{:?}", services.args);
        }
    }
    assert!(asks(&udp_command(
        &settings,
        &["192.0.2.5".into()],
        &[],
        false,
        out
    )));
    // The web tools have no such flag.
    let mild = settings.preset(Mode::Mild, &PresetOverride::default());
    assert!(!args(&crawl_command(&settings, &mild, "http://192.0.2.5", out)).contains("stats"));

    // Neither an operator nor a preset can give it, in any spelling nmap
    // would take: it is never there twice, and never with another value.
    for refused in [
        &["--stats-every", "1s"][..],
        &["--stats-every=1s"],
        &["--stats-every"],
        &["--stats", "1s"],
        &["--stats-e=0.001s"],
        &["-stats-every", "1s"],
        &["--STATS-EVERY", "1s"],
        &["-T4", "--stats-every", "5s"],
    ] {
        let flags = strings(refused);
        assert!(validate_nmap_flags(&flags).is_err(), "{refused:?}");
        assert!(
            validate_preset_nmap_flags(&flags, &[]).is_err(),
            "{refused:?}"
        );
        assert!(
            validate_preset_nmap_flags(&[], &flags).is_err(),
            "{refused:?}"
        );
    }
}

#[test]
fn a_stage_reads_its_tools_output_as_what_that_tool_writes() {
    // A scanned server puts the marker of another format into a header.
    // Guessed from the content this file was "XML", failed to parse, and
    // the stage reported nothing found.
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("ferox_1_0.jsonl");
    std::fs::write(
        &output,
        "{\"type\":\"response\",\"url\":\"http://10.0.0.5/admin\",\"status\":403,\"headers\":{\"x-a\":\"<nmaprun\"}}\n\
         {\"type\":\"response\",\"url\":\"http://10.0.0.5/login\",\"status\":200}\n",
    )
    .unwrap();
    assert_eq!(
        parsers::detect(&std::fs::read_to_string(&output).unwrap()),
        parsers::Format::NmapXml,
        "what guessing makes of it"
    );
    let observations = read_lines(&output).unwrap();
    assert_eq!(observations.len(), 2, "{observations:?}");
    assert!(!output.exists(), "read once, then deleted");
    // A scanner's output that is not XML is an error with the file's name.
    let output = dir.path().join("nmap_ports_1.xml");
    std::fs::write(&output, "not xml").unwrap();
    let error = format!("{:#}", read_scan(&output).unwrap_err());
    assert!(error.contains("nmap_ports_1.xml"), "{error}");
    assert!(!output.exists());
}

#[test]
fn what_a_scan_found_is_taken_from_its_own_output_only() {
    let observations = parsers::nmap::parse(
        r#"<nmaprun>
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/><service name="smtp"/></port>
<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
</ports></host>
<host><status state="up"/><address addr="10.0.9.9" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
</ports></host>
<host><status state="up"/><address addr="10.0.0.7" addrtype="ipv4"/><ports></ports></host>
</nmaprun>"#,
        true,
    )
    .unwrap();
    let range = target("10.0.0.0/24");
    let found = Found::of(&observations, &range);
    assert_eq!(found.up, 2, "the host outside the range is not counted");
    assert_eq!(
        found.hosts,
        BTreeMap::from([("10.0.0.5".to_owned(), vec![22, 80, 443])])
    );
    assert_eq!(
        found.web,
        [
            ("10.0.0.5".to_owned(), 443, true),
            ("10.0.0.5".to_owned(), 80, false)
        ]
    );
    assert_eq!(found.open_ports(), 3);
    // For a name the scanner resolved, every address it reported.
    let named = Found::of(&observations, &target("app.example.org"));
    assert_eq!(named.hosts.len(), 2);
    // Read back from a database, the same checks apply again.
    let planted: Found = serde_json::from_str(
        r#"{"hosts":{"10.0.0.5":[443,443,22],"192.0.2.1":[80],"x":[1],"10.0.0.6":[]},
            "web":[["10.0.0.5",443,false],["10.0.0.5",443,true],["10.0.0.5",8443,true],["192.0.2.1",80,false]]}"#,
    )
    .unwrap();
    let checked = planted.checked(&range);
    assert_eq!(
        checked.hosts,
        BTreeMap::from([("10.0.0.5".to_owned(), vec![22, 443])])
    );
    assert_eq!(checked.web, [("10.0.0.5".to_owned(), 443, true)]);
    assert_eq!(Found::default().checked(&range), Found::default());
}

#[test]
fn unfinished_tasks_are_counted_without_touching_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    assert_eq!(count_unfinished(&path), 0);
    assert!(!path.exists(), "counting must not create the file");
    {
        let db = Db::open(&path).unwrap();
        let first = enqueue(&db, "10.0.0.5", Mode::Mild, &[]).unwrap();
        for stage in STAGES {
            set_stage(&db, first, stage, "done", "").unwrap();
        }
        enqueue(&db, "10.0.0.6", Mode::Mild, &[]).unwrap();
    }
    assert_eq!(count_unfinished(&path), 1);
    // A session's end leaves nothing unfinished, not even the stage it
    // stopped.
    {
        let db = Db::open(&path).unwrap();
        let cut = enqueue(&db, "10.0.0.7", Mode::Mild, &[]).unwrap();
        set_stage(&db, cut, Stage::Lan, "running", "").unwrap();
        assert_eq!(end_session(&db, SessionEnd::Closed).unwrap(), 2);
    }
    assert_eq!(count_unfinished(&path), 0);
}

#[test]
fn a_database_someone_else_prepared_cannot_run_its_own_statements() {
    let dir = tempfile::tempdir().unwrap();

    // A file in which the table that is counted is a view that never
    // finishes: the count comes back at once, as nothing.
    let endless = dir.path().join("endless.db");
    rusqlite::Connection::open(&endless)
        .unwrap()
        .execute_batch(
            "CREATE VIEW task_stages AS
             WITH RECURSIVE forever(task_id, status) AS (
                 SELECT 1, 'pending' UNION ALL SELECT task_id + 1, 'pending' FROM forever
             ) SELECT task_id, status FROM forever;",
        )
        .unwrap();
    let started = std::time::Instant::now();
    assert_eq!(count_unfinished(&endless), 0);
    assert!(started.elapsed() < Duration::from_secs(5));

    // A real database with a trigger added behind meow's back: queueing
    // a task does not run it, and deleting a task still removes its
    // stages (the schema's own rule).
    let path = dir.path().join("state.db");
    drop(Db::open(&path).unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TABLE planted (note TEXT);
             CREATE TRIGGER on_task AFTER INSERT ON tasks BEGIN
                 INSERT INTO planted VALUES ('ran');
                 UPDATE tasks SET extra_flags = '[\"--script\",\"/tmp/x.nse\"]';
             END;",
        )
        .unwrap();
    let db = Db::open(&path).unwrap();
    let id = enqueue(&db, "10.0.0.5", Mode::Mild, &[]).unwrap();
    let planted: i64 = db
        .conn()
        .query_row("SELECT COUNT(*) FROM planted", [], |row| row.get(0))
        .unwrap();
    assert_eq!(planted, 0, "the trigger did not run");
    assert!(task(&db, id).unwrap().unwrap().extra_flags.is_empty());
    assert_eq!(count_unfinished(&path), 1);
    db.conn()
        .execute("DELETE FROM tasks WHERE id = ?1", [id])
        .unwrap();
    let stages: i64 = db
        .conn()
        .query_row("SELECT COUNT(*) FROM task_stages", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stages, 0, "stages still go with their task");
    // The schema cannot be rewritten through meow's own connection.
    assert!(db
        .conn()
        .execute_batch("PRAGMA writable_schema = ON; DELETE FROM sqlite_schema;")
        .is_err());
}

#[cfg(unix)]
mod tools {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn command(program: String, output: &Path) -> ToolCommand {
        ToolCommand {
            program,
            args: vec![output.to_string_lossy().into_owned()],
            output: output.to_path_buf(),
        }
    }

    const GENEROUS: RunLimits = RunLimits {
        timeout: Duration::from_secs(20),
        cap_bytes: 1024 * 1024,
    };

    #[tokio::test]
    async fn a_tool_runs_in_its_own_empty_folder_without_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::env::set_var("MEOW_TEST_SCANNER_API_KEY", "sk-not-for-scanners");
        std::env::set_var("MEOW_TEST_SCANNER_PLAIN", "kept");
        let tool = script(
            dir.path(),
            "tool",
            "{ pwd; ls -A | wc -l; stat -c %a . 2>/dev/null || stat -f %Lp .; env; } > \"$1\"",
        );
        let outcome = run_tool(&command(tool, &out), GENEROUS).await;
        assert_eq!(outcome, RunOutcome::Exited(Some(0)));
        let text = std::fs::read_to_string(&out).unwrap();
        let mut lines = text.lines();
        let ran_in = PathBuf::from(lines.next().unwrap());
        // Not where the session was started, but a fresh folder beside
        // the output: empty, private, and gone afterwards.
        assert_ne!(ran_in, std::env::current_dir().unwrap());
        assert_eq!(
            ran_in.parent().unwrap().canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
        assert!(ran_in
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("run-"));
        assert_eq!(lines.next().unwrap().trim(), "0", "the folder is empty");
        assert_eq!(lines.next().unwrap().trim(), "700");
        assert!(!ran_in.exists());
        assert!(!text.contains("sk-not-for-scanners"), "{text}");
        assert!(text.contains("MEOW_TEST_SCANNER_PLAIN=kept"));
        for (name, secret) in [
            ("ANTHROPIC_API_KEY", true),
            ("OPENROUTER_API_KEY", true),
            ("GITHUB_TOKEN", true),
            ("aws_secret_access_key", true),
            ("DB_PASSWORD", true),
            ("PATH", false),
            ("HOME", false),
            ("HTTPS_PROXY", false),
            ("SSH_AUTH_SOCK", false),
        ] {
            assert_eq!(is_secret_variable(name), secret, "{name}");
        }

        // A link (or anything but a file) where the output goes is not
        // written through, and the tool is not started.
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "keep me").unwrap();
        let linked = dir.path().join("linked-out");
        std::os::unix::fs::symlink(&outside, &linked).unwrap();
        let marker = dir.path().join("started");
        let tool = script(
            dir.path(),
            "tool2",
            &format!("touch '{}'; echo scan > \"$1\"", marker.display()),
        );
        let outcome = run_tool(&command(tool, &linked), GENEROUS).await;
        assert!(
            matches!(&outcome, RunOutcome::Failed(why) if why.contains("not a regular file")),
            "{outcome:?}"
        );
        assert!(!marker.exists());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep me");
    }

    #[tokio::test]
    async fn a_tool_runs_with_stdin_closed_and_its_exit_code_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        // `read` returns at once on a closed stdin; an interactive prompt
        // would otherwise wait forever.
        let ok = script(
            dir.path(),
            "ok",
            "read answer; echo \"answer=[$answer]\" > \"$1\"; exit 0",
        );
        assert_eq!(
            run_tool(&command(ok, &out), GENEROUS).await,
            RunOutcome::Exited(Some(0))
        );
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "answer=[]\n");

        let bad = script(dir.path(), "bad", "exit 3");
        assert_eq!(
            run_tool(&command(bad, &out), GENEROUS).await,
            RunOutcome::Exited(Some(3))
        );
        let missing = command(dir.path().join("nope").to_string_lossy().into_owned(), &out);
        assert_eq!(run_tool(&missing, GENEROUS).await, RunOutcome::NotInstalled);
    }

    fn alive(pid: &str) -> bool {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            return !status.lines().any(|line| {
                line.strip_prefix("State:")
                    .is_some_and(|s| s.trim_start().starts_with('Z'))
            });
        }
        if Path::new(&format!("/proc/{pid}")).exists() {
            return true;
        }
        std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    async fn wait_gone(pid: &str) {
        for _ in 0..100 {
            if !alive(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("process {pid} is still running");
    }

    #[tokio::test]
    async fn a_runaway_tool_is_stopped_at_the_timeout_with_its_children() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let pids = dir.path().join("pids");
        // The tool starts a child of its own; both must die.
        let body = format!("sleep 300 &\necho \"$$ $!\" > {}\nwait", pids.display());
        let slow = script(dir.path(), "slow", &body);
        let limits = RunLimits {
            timeout: Duration::from_millis(600),
            cap_bytes: 1024 * 1024,
        };
        let started = std::time::Instant::now();
        assert_eq!(
            run_tool(&command(slow, &out), limits).await,
            RunOutcome::TimedOut
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        let recorded = std::fs::read_to_string(&pids).unwrap();
        for pid in recorded.split_whitespace() {
            wait_gone(pid).await;
        }
    }

    #[tokio::test]
    async fn a_tool_that_floods_its_output_is_stopped_at_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let flood = script(
            dir.path(),
            "flood",
            "while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx >> \"$1\"; done",
        );
        let limits = RunLimits {
            timeout: Duration::from_secs(30),
            cap_bytes: 64 * 1024,
        };
        assert_eq!(
            run_tool(&command(flood, &out), limits).await,
            RunOutcome::OutputCapExceeded
        );
        let size = std::fs::metadata(&out).unwrap().len();
        assert!(size > 64 * 1024 && size < 64 * 1024 * 1024, "{size}");
    }

    #[tokio::test]
    async fn dropping_a_running_tool_kills_its_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let pids = dir.path().join("pids");
        let body = format!("sleep 300 &\necho \"$$ $!\" > {}\nwait", pids.display());
        let slow = script(dir.path(), "slow", &body);
        let command = command(slow, &out);
        // Cancel the run (as a closing session does) once it has started.
        let cancelled =
            tokio::time::timeout(Duration::from_millis(600), run_tool(&command, GENEROUS)).await;
        assert!(cancelled.is_err());
        let recorded = std::fs::read_to_string(&pids).unwrap();
        for pid in recorded.split_whitespace() {
            wait_gone(pid).await;
        }
    }

    #[tokio::test]
    async fn parent_traversal_program_and_symlinked_stage_output_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let parent_prog = command("../bin/sh".to_owned(), &out);
        assert_eq!(
            run_tool(&parent_prog, GENEROUS).await,
            RunOutcome::NotInstalled
        );

        let victim = dir.path().join("victim.jsonl");
        std::fs::write(&victim, "{\"url\":\"http://10.0.0.5/secret\"}\n").unwrap();
        let link = dir.path().join("ferox_9_0.jsonl");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(read_lines(&link).is_err());
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(victim.exists());
    }
}

#[test]
fn zoned_ipv6_found_and_inline_preset_scripts_are_handled_cleanly() {
    let observations = parsers::nmap::parse(
        r#"<nmaprun>
<host><status state="up"/><address addr="fe80::1%eth0" addrtype="ipv6"/><ports>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http"/></port>
</ports></host>
<host><status state="up"/><address addr="fe80::1%eth1" addrtype="ipv6"/><ports>
<port protocol="tcp" portid="8443"><state state="open"/><service name="https"/></port>
</ports></host>
</nmaprun>"#,
        true,
    )
    .unwrap();
    let found = Found::of(&observations, &target("fe80::1%eth0"));
    assert_eq!(found.up, 1);
    assert_eq!(
        found.hosts,
        BTreeMap::from([("fe80::1%eth0".to_owned(), vec![8080])])
    );
    assert_eq!(found.web, [("fe80::1%eth0".to_owned(), 8080, false)]);

    let settings = ReconSettings::default();
    let mut preset = settings.preset(Mode::Mild, &PresetOverride::default());
    preset.nmap_services = strings(&["-sV", "--script=ssl-cert,banner"]);
    let extra = split_recon_flags(&strings(&["--script", "safe"]));
    let (cmd, _) = services_command(
        &settings,
        &preset,
        &extra,
        "fe80::1%eth0",
        &[8080],
        true,
        Path::new("/t/svc.xml"),
    );
    assert_eq!(
        cmd.args
            .iter()
            .filter(|arg| *arg == "--script" || arg.starts_with("--script="))
            .count(),
        1,
        "{:?}",
        cmd.args
    );
    assert!(args(&cmd).contains("ssl-cert or banner"));
    assert!(args(&cmd).contains(" -6 "));

    let ext = target("evil.example");
    assert!(!Found::belongs("127.0.0.1", &ext));
    assert!(!Found::belongs("169.254.169.254", &ext));
    assert!(Found::belongs("10.0.0.5", &ext));
    assert!(Found::belongs("127.0.0.1", &target("localhost")));
    assert!(is_secret_variable("LD_PRELOAD"));
    assert!(is_secret_variable("DYLD_INSERT_LIBRARIES"));
    assert!(is_secret_variable("OPENSSL_CONF"));
    assert!(!is_secret_variable("MEOW_TEST_SCANNER_PLAIN"));
}

#[test]
fn a_script_s_endpoints_and_keys_reach_the_vault_before_its_facts() {
    use crate::evidence::{Confidence, EvidenceRecord, Source};
    use crate::vault::Vault;
    let mut vault = Vault::ephemeral();
    // `.zz` is an ending no pattern masks: only the vault can know the name.
    let endpoints = vec![
        "https://orders.acme-ops.zz/v2/items".to_owned(),
        "/api/v1/users".to_owned(),
    ];
    // Built here, so that no key-shaped text stands in the source.
    let key = format!("{}_{}_{}", "sk", "live", "Qm7x".repeat(7));
    let (facts, secrets, _) = stages::script_facts(
        &mut vault,
        "198.51.100.7",
        443,
        "/static/app.js",
        &endpoints,
        vec![("Stripe secret key", key.clone())],
    );
    let claims: Vec<String> = facts
        .iter()
        .filter_map(|fact| match fact {
            Observation::Fact { claim, .. } => Some(claim.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(claims.len(), 2, "{claims:?}");

    // The graph keeps none of the endpoints, as when the port already has
    // the 150 it keeps: the fact that names them is masked all the same.
    let mut graph = Graph::default();
    graph.apply(Observation::Port {
        address: "198.51.100.7".into(),
        port: 443,
        protocol: "tcp".into(),
        state: "open".into(),
        service: Some("https".into()),
        product: None,
        version: None,
        extra_info: None,
        cpes: vec![],
        record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
    });
    graph.apply_all(facts);
    vault.register_graph(&graph);
    let masked = vault.mask_text(&claims[0]);
    assert!(!masked.contains("acme-ops"), "{masked}");
    assert!(masked.contains("/api/v1/users"), "{masked}");

    // The key is in the vault, and the fact names it by its placeholder
    // alone; the hint at it is kept for the map and the report.
    let secret = &secrets[0];
    assert_eq!(vault.unmask(&secret.token), key);
    assert!(claims[1].ends_with(&format!("kept in the vault as {}", secret.token)));
    assert!(!claims[1].contains(&key[..4]), "{}", claims[1]);
    assert!(secret.preview.starts_with(&key[..4]), "{}", secret.preview);
}

#[test]
fn a_key_a_script_names_in_an_endpoint_stays_in_the_vault() {
    use crate::vault::Vault;
    // Built here, so that no key-shaped text stands in the source.
    let google = format!("{}{}", "AIza", "SyD-1234567890abcdefghijklmnopqrstu");
    let hook = format!(
        "https://hooks.slack.com/services/{}/{}/{}",
        "T0123456", "B0123456", "abcdefghijklmnopqrstuvwx"
    );
    let token = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
    let generic = "Zq3vLm8pRt5wXy2nBc7k";
    let path_id = "aB3dE5fG7hJ9kL1mN2pQ4xY6zW8vT0";
    let source = format!(
        r#"const maps = "https://maps.googleapis.com/maps/api/js?key={google}&v=3#frag";
        const hook = "{hook}";
        fetch("/api/v1/orders?access_token={token}");
        var config = {{ apiKey: "{generic}" }};
        fetch("/api/v1/reports/{generic}/latest");
        fetch("/api/v1/hooks/{path_id}");"#
    );
    let found = crate::webfp::extract_endpoints(&source, 60);
    let keys = crate::webfp::find_secrets(&source);
    let mut vault = Vault::ephemeral();
    let (facts, secrets, endpoints) =
        stages::script_facts(&mut vault, "198.51.100.7", 443, "/app.js", &found, keys);
    assert_eq!(secrets.len(), 3, "{secrets:?}");
    let generic_token = &secrets
        .iter()
        .find(|s| s.kind.starts_with("possible secret"))
        .unwrap()
        .token;
    assert!(endpoints.contains(&"https://maps.googleapis.com/maps/api/js?key&v".to_owned()));
    assert!(endpoints.contains(&"/api/v1/orders?access_token".to_owned()));
    assert!(
        endpoints.contains(&format!("/api/v1/reports/{generic_token}/latest")),
        "{endpoints:?}"
    );
    // A Slack webhook URL is a key whole: listed with the keys only.
    assert!(
        !endpoints.iter().any(|e| e.contains("hooks.slack.com")),
        "{endpoints:?}"
    );
    // An id in a path is no key: kept as it is, and not listed to rotate.
    assert!(
        endpoints.contains(&format!("/api/v1/hooks/{path_id}")),
        "{endpoints:?}"
    );
    assert_eq!(vault.exposed_secrets().len(), 3);
    // What the graph, the facts, the map and the report hold: no key.
    let mut graph = Graph::default();
    graph.apply(Observation::Port {
        address: "198.51.100.7".into(),
        port: 443,
        protocol: "tcp".into(),
        state: "open".into(),
        service: Some("https".into()),
        product: None,
        version: None,
        extra_info: None,
        cpes: vec![],
        record: crate::evidence::EvidenceRecord::observed(
            crate::evidence::Source::NmapXml,
            crate::evidence::Confidence::High,
            "x",
        ),
    });
    graph.apply_all(facts.clone());
    graph.apply(Observation::WebMeta {
        address: "198.51.100.7".into(),
        port: 443,
        http: Box::new(crate::graph::HttpInfo {
            scheme: "https".into(),
            js_endpoints: endpoints.clone(),
            js_secrets: secrets,
            ..crate::graph::HttpInfo::default()
        }),
        record: crate::evidence::EvidenceRecord::observed(
            crate::evidence::Source::JsScan,
            crate::evidence::Confidence::Medium,
            "x",
        ),
    });
    let report = crate::report::render(&crate::report::Inputs {
        session: "acme".into(),
        mode: Mode::Mild,
        generated_utc: String::new(),
        graph: graph.clone(),
        tasks: Vec::new(),
        secrets: vault.exposed_secrets(),
        replay: None,
        chats: Vec::new(),
    });
    assert!(
        report.contains("Endpoints named in the scripts"),
        "{report}"
    );
    let kept = serde_json::to_string(&graph).unwrap() + &format!("{facts:?}") + &report;
    for secret in [google.as_str(), hook.as_str(), token, generic] {
        assert!(!kept.contains(secret), "{secret} in {kept}");
    }
    assert!(kept.contains("https://maps.googleapis.com/maps/api/js?key&v"));
}

#[test]
fn ids_in_script_endpoints_are_kept_and_never_listed_to_rotate() {
    let endpoints: Vec<String> = [
        "/api/v2/projects/5f8d0d55b54764421b7156c5/members",
        "/api/v1/session/Zx81Kd02Lm77Qa19Wv44/refresh",
        "/api/v1/orders/550e8400-e29b-41d4-a716-446655440000",
        "https://api.example.com/v1/users/5f8d0d55b54764421b7156c5/avatar",
        "/api/v1/search?q",
    ]
    .map(str::to_owned)
    .to_vec();
    let mut vault = crate::vault::Vault::ephemeral();
    let (facts, secrets, kept) = stages::script_facts(
        &mut vault,
        "198.51.100.7",
        443,
        "/app.js",
        &endpoints,
        Vec::new(),
    );
    assert_eq!(kept, endpoints);
    assert!(secrets.is_empty());
    assert!(vault.exposed_secrets().is_empty());
    let facts = format!("{facts:?}");
    for endpoint in &endpoints {
        assert!(facts.contains(endpoint.as_str()), "{endpoint} in {facts}");
    }
}

/// A coordinator in `mode` whose queue runs nothing on its own, with
/// `config`. The folder goes with it.
fn quiet_coordinator(
    mode: Mode,
    config: crate::workspace::Config,
) -> (tempfile::TempDir, crate::coordinator::Coordinator) {
    use crate::workspace::{MeowHome, Workspace};
    let tmp = tempfile::tempdir().unwrap();
    let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
    let (mut workspace, _) =
        Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
    workspace.set_mode(mode).unwrap();
    let coordinator = crate::coordinator::Coordinator::start(workspace, config).unwrap();
    (tmp, coordinator)
}

fn no_cve_config() -> crate::workspace::Config {
    let mut config = crate::workspace::Config::default();
    config.cve.enabled = false;
    config
}

fn strings_of(list: &[&str]) -> Vec<String> {
    list.iter().map(|item| (*item).to_owned()).collect()
}

/// What the dns stage saves for a dual-stack name: the system's order, and
/// the address the scan goes to.
fn dual_stack(ipv6: bool) -> Found {
    let ips = strings_of(&["203.0.113.7", "2001:db8::7"]);
    Found {
        primary: crate::osint::primary_address(&ips, ipv6),
        ips,
        ..Found::default()
    }
}

#[test]
fn the_dns_stage_s_addresses_keep_their_order() {
    let target = Target::parse("dual.example.org").unwrap();
    let found = Found {
        ips: strings_of(&["203.0.113.9", "198.51.100.20", "2001:db8::7", "203.0.113.9"]),
        primary: Some("203.0.113.9".to_owned()),
        ..Found::default()
    }
    .checked(&target);
    // Not as text: "198..." and "2001:..." would come first.
    assert_eq!(found.ips, ["203.0.113.9", "198.51.100.20", "2001:db8::7"]);
    assert_eq!(found.primary.as_deref(), Some("203.0.113.9"));
    // Only one of its own addresses.
    let planted = Found {
        primary: Some("192.0.2.99".to_owned()),
        ..found.clone()
    }
    .checked(&target);
    assert_eq!(planted.primary, None);
    // And read back as saved.
    let db = Db::open_in_memory().unwrap();
    let id = enqueue(&db, "dual.example.org", Mode::Mild, &[]).unwrap();
    found.save(&db, id, Stage::Dns).unwrap();
    assert_eq!(Found::load(&db, id, Stage::Dns, &target), found);
}

#[test]
fn trace_goes_to_the_address_the_port_inventory_scanned() {
    // It runs after the port inventory.
    let at = |stage: Stage| STAGES.iter().position(|s| *s == stage).unwrap();
    assert!(at(Stage::Ports) < at(Stage::Trace));

    let (_tmp, coordinator) = quiet_coordinator(Mode::Light, no_cve_config());
    let state = coordinator.state();
    let name = "dual.example.org";
    let target = Target::parse(name).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let first = |id: i64| {
        runtime
            .block_on(resolve_target_ips(&state, id, &target))
            .first()
            .map(ToString::to_string)
    };
    // Before the scan: the address nmap scans, IPv4 unless `-6`, whatever
    // the text order of the addresses.
    for (ipv6, expected) in [(false, "203.0.113.7"), (true, "2001:db8::7")] {
        let id = enqueue(&state.db_lock(), name, Mode::Mild, &[]).unwrap();
        dual_stack(ipv6)
            .save(&state.db_lock(), id, Stage::Dns)
            .unwrap();
        assert_eq!(first(id).as_deref(), Some(expected), "-6: {ipv6}");
    }
    // DNS published one address; the scanner resolved the name (with the
    // user's /etc/hosts) to another and scanned that.
    let id = enqueue(&state.db_lock(), name, Mode::Mild, &[]).unwrap();
    dual_stack(false)
        .save(&state.db_lock(), id, Stage::Dns)
        .unwrap();
    let ports = Found {
        up: 1,
        hosts: BTreeMap::from([("192.0.2.10".to_owned(), vec![80])]),
        ..Found::default()
    };
    ports.save(&state.db_lock(), id, Stage::Ports).unwrap();
    assert_eq!(first(id).as_deref(), Some("192.0.2.10"));
    coordinator.shutdown();
}

/// Mail-dns records on the address the scan went to, which has the name:
/// not on another of its addresses that sorts first as text.
#[test]
fn mail_dns_records_on_the_scanned_address_of_a_dual_stack_name() {
    use crate::osint::tests::{stand_in_dns, stand_in_doh, stand_in_resolver, Reply};
    let (_tmp, coordinator) = quiet_coordinator(Mode::Light, no_cve_config());
    let state = coordinator.state();
    let name = "dual.example.org";
    let target = Target::parse(name).unwrap();
    let id = enqueue(&state.db_lock(), name, Mode::Mild, &[]).unwrap();
    dual_stack(false)
        .save(&state.db_lock(), id, Stage::Dns)
        .unwrap();
    let task = task(&state.db_lock(), id).unwrap().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (server, _) = stand_in_dns(|name, _| match name {
            "dual.example.org" => Reply::Address([203, 0, 113, 7]),
            _ => Reply::NxDomain,
        })
        .await;
        let (doh, _) = stand_in_doh(None).await;
        let cx = stages::Ctx::new(&state, &task, &target, Stage::MailDns).unwrap();
        let end = stages::mail_dns_with(&cx, stand_in_resolver(vec![server], &doh))
            .await
            .unwrap();
        assert!(matches!(end, StageEnd::Done(_)));
    });
    let graph = state.graph();
    let graded: Vec<&str> = graph
        .hosts
        .values()
        .filter(|h| h.dns_security.is_some())
        .map(|h| h.address.as_str())
        .collect();
    assert_eq!(graded, ["203.0.113.7"]);
    assert!(!graph.hosts.contains_key("2001:db8::7"));
    drop(graph);
    coordinator.shutdown();
}

/// crt.sh is not asked about a name with any address that is not public,
/// whichever comes first. 3fff::/20 (RFC 9637) is a public address here.
#[test]
fn subdomains_keeps_a_name_with_any_internal_address_off_crt_sh() {
    let (_tmp, coordinator) = quiet_coordinator(Mode::Light, no_cve_config());
    let state = coordinator.state();
    let name = "mixed.example.org";
    let target = Target::parse(name).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for ips in [&["3fff::7", "fd00::5"][..], &["3fff::7", "240.0.0.7"]] {
        let id = enqueue(&state.db_lock(), name, Mode::Mild, &[]).unwrap();
        let ips = strings_of(ips);
        Found {
            primary: crate::osint::primary_address(&ips, false),
            ips: ips.clone(),
            ..Found::default()
        }
        .save(&state.db_lock(), id, Stage::Dns)
        .unwrap();
        let task = task(&state.db_lock(), id).unwrap().unwrap();
        let cx = stages::Ctx::new(&state, &task, &target, Stage::Subdomains).unwrap();
        let said = match runtime.block_on(stages::subdomains(&cx)).unwrap() {
            StageEnd::Skipped(why) => why,
            StageEnd::Done(what) => format!("done: {what}"),
            StageEnd::ModeChanged => "mode changed".to_owned(),
        };
        assert!(said.contains("not sent to crt.sh"), "{ips:?}: {said}");
    }
    coordinator.shutdown();
}

/// The UDP scan takes the operator's up check and address family, and a
/// scan that found no host up says so, not "0 UDP services".
#[cfg(unix)]
#[test]
fn the_udp_scan_takes_the_up_check_flags_and_says_when_no_host_was_up() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let calls = dir.path().join("calls");
    let nmap = dir.path().join("nmap");
    std::fs::write(
        &nmap,
        format!(
            "#!/bin/sh
echo \"$*\" >> '{}'
out=''; prev=''; pn=0
\
             for a in \"$@\"; do [ \"$prev\" = '-oX' ] && out=\"$a\"; [ \"$a\" = '-Pn' ] && pn=1; prev=\"$a\"; done
\
             if [ $pn = 1 ]; then cat > \"$out\" <<'XML'
\
             <nmaprun><host><status state=\"up\"/><address addr=\"203.0.113.9\" addrtype=\"ipv4\"/><ports>\
             <port protocol=\"udp\" portid=\"161\"><state state=\"open\"/><service name=\"snmp\"/></port>\
             </ports></host><runstats><hosts up=\"1\" down=\"0\" total=\"1\"/></runstats></nmaprun>
XML
\
             else cat > \"$out\" <<'XML'
\
             <nmaprun><runstats><hosts up=\"0\" down=\"1\" total=\"1\"/></runstats></nmaprun>
XML
fi
",
            calls.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&nmap, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = no_cve_config();
    config.recon.nmap = nmap.to_string_lossy().into_owned();
    let (_tmp, coordinator) = quiet_coordinator(Mode::Aggressive, config);
    let state = coordinator.state();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let udp = |target: &str, flags: &[&str]| {
        let parsed = Target::parse(target).unwrap();
        let id = enqueue(
            &state.db_lock(),
            target,
            Mode::Aggressive,
            &strings_of(flags),
        )
        .unwrap();
        let task = task(&state.db_lock(), id).unwrap().unwrap();
        let mut cx = stages::Ctx::new(&state, &task, &parsed, Stage::Udp).unwrap();
        // As root.
        cx.privileged = true;
        let end = runtime.block_on(stages::udp(&cx)).unwrap();
        let args = std::fs::read_to_string(&calls)
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .to_owned();
        (end, args)
    };
    let (end, args) = udp("203.0.113.9", &[]);
    assert!(!args.contains("-Pn"), "{args}");
    let StageEnd::Skipped(why) = end else {
        panic!("not skipped");
    };
    assert!(why.starts_with("nothing answered nmap's up check"), "{why}");
    assert!(why.contains("`-- -Pn`"), "{why}");

    let (end, args) = udp("203.0.113.9", &["-Pn"]);
    assert!(args.contains(" -Pn "), "{args}");
    let StageEnd::Done(what) = end else {
        panic!("not done");
    };
    assert!(what.starts_with("1 UDP services answered"), "{what}");

    // A name scanned at its IPv6 address, as the TCP scans do.
    let (_, args) = udp("dual.example.org", &["-6", "-n"]);
    assert_eq!(args.matches(" -6 ").count(), 1, "{args}");
    assert!(
        args.contains(" -n ") && args.ends_with("-- dual.example.org"),
        "{args}"
    );
    coordinator.shutdown();
}

#[test]
fn the_mail_dns_stage_keeps_an_internal_target_off_doh() {
    use crate::coordinator::Coordinator;
    use crate::osint::tests::{stand_in_dns, stand_in_doh, stand_in_resolver, taken, Reply};
    use crate::workspace::{Config, MeowHome, Workspace};

    let tmp = tempfile::tempdir().unwrap();
    let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
    // Light: the queue runs nothing on its own.
    let (workspace, _) =
        Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
    let mut config = Config::default();
    config.cve.enabled = false;
    let coordinator = Coordinator::start(workspace, config).unwrap();
    let state = coordinator.state();
    // A name under a public suffix that the dns stage found private.
    let name = "dc01.corp.example.org";
    let target = Target::parse(name).unwrap();
    let id = enqueue(&state.db_lock(), name, Mode::Mild, &[]).unwrap();
    let dns = Found {
        ips: vec!["10.0.0.5".into()],
        ..Found::default()
    };
    dns.save(&state.db_lock(), id, Stage::Dns).unwrap();
    let task = task(&state.db_lock(), id).unwrap().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // The system resolver answers nothing, which would send a public
        // name over DNS-over-HTTPS.
        let (server, asked) = stand_in_dns(|_, _| Reply::ServFail).await;
        let (doh, doh_asked) = stand_in_doh(None).await;
        let cx = stages::Ctx::new(&state, &task, &target, Stage::MailDns).unwrap();
        let end = stages::mail_dns_with(&cx, stand_in_resolver(vec![server], &doh))
            .await
            .unwrap();
        // Nothing answered: no grade, and the stage says why.
        let said = match end {
            StageEnd::Skipped(why) => why,
            StageEnd::Done(what) => format!("done: {what}"),
            StageEnd::ModeChanged => "mode changed".to_owned(),
        };
        assert_eq!(said, "DNS lookups failed");
        assert!(state
            .graph()
            .hosts
            .values()
            .all(|h| h.dns_security.is_none()));
        assert!(taken(&asked).contains(&format!("16 _dmarc.{name}")));
        assert!(taken(&doh_asked).is_empty(), "{:?}", taken(&doh_asked));
    });
    coordinator.shutdown();
}

#[test]
fn mail_dns_puts_every_name_of_a_long_record_into_the_vault() {
    use crate::evidence::{Confidence, EvidenceRecord, Source};
    use crate::graph::{DnsCheck, DnsSecurity};
    use crate::vault::Vault;
    // Longer than the graph keeps of a check.
    let spf = format!(
        "v=spf1 {}include:_spf.acme-holding.zz -all",
        "ip4:192.0.2.1 ".repeat(40)
    );
    let observations = vec![Observation::DnsSecurity {
        address: "203.0.113.30".into(),
        info: Box::new(DnsSecurity {
            domain: "shop.acme-corp.zz".into(),
            grade: "A".into(),
            checks: vec![DnsCheck {
                name: "SPF".into(),
                status: "ok".into(),
                value: spf.clone(),
                advice: String::new(),
            }],
            ..DnsSecurity::default()
        }),
        record: EvidenceRecord::observed(Source::Dns, Confidence::High, "x"),
    }];
    let mut vault = Vault::ephemeral();
    stages::register_mail_dns(&mut vault, &observations);
    let mut graph = Graph::default();
    graph.apply_all(observations);
    let kept = &graph.hosts["203.0.113.30"]
        .dns_security
        .as_ref()
        .unwrap()
        .checks[0];
    assert!(!kept.value.contains("acme-holding"), "{}", kept.value);
    // Only the stage saw the whole record.
    vault.register_graph(&graph);
    let masked = vault.mask_text(&format!("SPF for shop.acme-corp.zz: {spf}"));
    assert!(!masked.contains("acme-holding"), "{masked}");
    assert!(!masked.contains("acme-corp"), "{masked}");
}

/// The waf-cdn stage once took the database lock while already holding it:
/// the queue stopped there, and so did leaving the session.
#[test]
fn the_waf_cdn_stage_does_not_deadlock_on_the_database() {
    use crate::coordinator::Coordinator;
    use crate::workspace::{Config, MeowHome, Workspace};

    let tmp = tempfile::tempdir().unwrap();
    let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
    let (workspace, _) =
        Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
    let mut config = Config::default();
    config.cve.enabled = false;
    let coordinator = Coordinator::start(workspace, config).unwrap();
    let state = coordinator.state();

    let address = "192.0.2.10".to_owned();
    let id = enqueue(&state.db_lock(), &address, Mode::Mild, &[]).unwrap();
    let ports = Found {
        up: 1,
        hosts: BTreeMap::from([(address.clone(), vec![80])]),
        web: vec![(address.clone(), 80, false)],
        ..Found::default()
    };
    ports.save(&state.db_lock(), id, Stage::Ports).unwrap();
    let task = task(&state.db_lock(), id).unwrap().unwrap();

    // On its own thread: a deadlock blocks the thread, so no async timeout
    // could fire.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let runner = Arc::clone(&state);
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let end = runtime.block_on(async {
            let target = Target::parse(&address).unwrap();
            let cx = stages::Ctx::new(&runner, &task, &target, Stage::WafCdn)?;
            stages::waf_cdn(&cx).await
        });
        let _ = done_tx.send(end.map(|end| match end {
            StageEnd::Done(detail) | StageEnd::Skipped(detail) => detail,
            StageEnd::ModeChanged => "mode changed".to_owned(),
        }));
    });
    let detail = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the waf-cdn stage hung")
        .unwrap();
    assert!(detail.contains("no blocking WAF/CDN detected"), "{detail}");
    coordinator.shutdown();
}

/// Terminal text can call any host of a recon target open, with any
/// software. The CVE stage looks up what the task's own scans found at once
/// and in full; the rest is looked up as text is: later, and only so much.
#[test]
fn the_cve_stage_looks_up_its_own_findings_first_and_text_only_so_much() {
    use crate::coordinator::Coordinator;
    use crate::evidence::{Confidence, EvidenceRecord, Source};
    use crate::workspace::{Config, MeowHome, Workspace};
    use axum::routing::{get, post};
    use serde_json::json;

    // A stand-in for NVD, OSV and the KEV list that answers nothing and
    // keeps the NVD questions it was asked.
    let asked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&asked);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let nvd = move |query: axum::extract::Query<
                std::collections::HashMap<String, String>,
            >| async move {
                if let Some(words) = query.get("keywordSearch") {
                    log.lock().unwrap().push(words.clone());
                }
                axum::Json(json!({ "totalResults": 0, "vulnerabilities": [] }))
            };
            let app = axum::Router::new()
                .route("/nvd", get(nvd))
                .route(
                    "/kev",
                    get(|| async { axum::Json(json!({ "vulnerabilities": [] })) }),
                )
                .route(
                    "/osv/v1/querybatch",
                    post(|| async { axum::Json(json!({ "results": [] })) }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    let base = rx.recv().unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
    let (workspace, _) =
        Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light).unwrap();
    let mut config = Config::default();
    config.cve.nvd_api_key = Some("stand-in".into());
    config.cve.nvd_url = format!("{base}/nvd");
    config.cve.osv_url = format!("{base}/osv");
    config.cve.kev_url = format!("{base}/kev");
    let coordinator = Coordinator::start(workspace, config).unwrap();
    let state = coordinator.state();
    state.limit_text_questions(1);

    // The scan found 203.0.113.200 with OpenSSH; text added two ports to
    // it, and a host the scan never saw.
    let port = |address: &str, port: u16, product: &str, source, confidence| Observation::Port {
        address: address.into(),
        port,
        protocol: "tcp".into(),
        state: "open".into(),
        service: None,
        product: Some(product.into()),
        version: Some(if product == "OpenSSH" { "9.6p1" } else { "1.0" }.into()),
        extra_info: None,
        cpes: Vec::new(),
        record: EvidenceRecord::observed(source, confidence, "x"),
    };
    let scanned = "203.0.113.200";
    state.graph().apply_all(vec![
        port(scanned, 22, "OpenSSH", Source::NmapXml, Confidence::High),
        port(scanned, 2222, "ProdY", Source::PtyRegex, Confidence::Medium),
        port(scanned, 2223, "ProdZ", Source::PtyRegex, Confidence::Medium),
        port(
            "203.0.113.1",
            80,
            "ProdX",
            Source::PtyRegex,
            Confidence::Medium,
        ),
    ]);
    let range = target("203.0.113.0/24");
    let id = enqueue(&state.db_lock(), "203.0.113.0/24", Mode::Mild, &[]).unwrap();
    let found = |hosts, udp| Found {
        hosts,
        udp,
        ..Found::default()
    };
    found(BTreeMap::from([(scanned.to_owned(), vec![22])]), Vec::new())
        .save(&state.db_lock(), id, Stage::Ports)
        .unwrap();
    found(BTreeMap::new(), vec![(scanned.to_owned(), 161)])
        .save(&state.db_lock(), id, Stage::Udp)
        .unwrap();
    assert_eq!(
        own_ports(&state, id, &range),
        BTreeMap::from([(
            scanned.to_owned(),
            BTreeSet::from(["22/tcp".to_owned(), "161/udp".to_owned()])
        )])
    );

    let task = task(&state.db_lock(), id).unwrap().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let end = runtime
        .block_on(async {
            let cx = stages::Ctx::new(&state, &task, &range, Stage::Cves)?;
            stages::cves(&cx).await
        })
        .unwrap();
    assert!(matches!(end, StageEnd::Done(_)));
    // What the scan found first and in full; one question text may ask.
    assert_eq!(*asked.lock().unwrap(), ["OpenSSH 9.6p1", "ProdY 1.0"]);
    // The host only text knows was queued as text: nothing left to ask.
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        asked.lock().unwrap().len(),
        2,
        "{:?}",
        asked.lock().unwrap()
    );
    let notices = state.snapshot()["notices"].to_string();
    assert!(
        notices.contains("reached this session's limit"),
        "{notices}"
    );
    coordinator.shutdown();
}
