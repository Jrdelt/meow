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
        true,
        Path::new("o.xml")
    )
    .args
    .contains(&"-6".to_owned()));
    validate_nmap_flags(&command.args[..command.args.len() - 4]).unwrap();
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
    let observations = parsers::nmap::parse(xml).unwrap();
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
    assert!(notices[0].contains("-sS replaced with -sT"));
    assert!(notices[1].contains("removed -O"));

    // UDP needs root: left out, with a way to do it by hand.
    let (user, notices) = adapt_for_privilege(strings(&["-sU", "-sSU", "-T3"]), false);
    assert_eq!(user, strings(&["-sT", "-T3"]));
    assert_eq!(notices.len(), 2);
    assert!(
        notices[0].contains("left out the UDP scan in -sU"),
        "{notices:?}"
    );
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
        "-sS -T3 --top-ports 1000 -oX /w/tmp/nmap_ports_7.xml -- 10.0.0.0/24"
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
        "-sT -T3 -p 80,443 -oX /w/tmp/nmap_ports_7.xml -- 10.0.0.5"
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
            format!("{expected} -oX /w/tmp/nmap_ports_7.xml -- 10.0.0.5"),
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
        "-sS -T4 -p- -O -6 -oX /w/tmp/nmap_ports_7.xml -- 2001:db8::/64"
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
         -p 22,443,8080 -oX /t/svc.xml -- 10.0.0.5"
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
    assert!(args(&command).contains("-6 -p 80 -oX /t/svc.xml -- 2001:db8::a"));
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

#[test]
fn task_rows_track_stage_status() {
    let db = Db::open_in_memory().unwrap();
    let id = enqueue(&db, "10.0.0.0/24", Mode::Mild, &strings(&["-p", "80"])).unwrap();
    let row = task(&db, id).unwrap().unwrap();
    assert_eq!(row.target, "10.0.0.0/24");
    assert_eq!(row.mode, Mode::Mild);
    assert_eq!(row.extra_flags, ["-p", "80"]);
    let statuses = |db: &Db| -> Vec<String> {
        task(db, id)
            .unwrap()
            .unwrap()
            .stages
            .iter()
            .map(|s| s.status.clone())
            .collect()
    };
    assert_eq!(statuses(&db), ["pending"; STAGES.len()]);
    assert_eq!(row.describe(), "recon 10.0.0.0/24: lan pending");

    // Every stage before `services` is done; `services` is running.
    let running = STAGES.iter().position(|s| *s == Stage::Services).unwrap();
    for s in &STAGES[..running] {
        set_stage(&db, id, *s, "done", "ok").unwrap();
    }
    set_stage(&db, id, Stage::Services, "running", "").unwrap();
    assert_eq!(unfinished(&db).unwrap().len(), 1);

    // The session dies here; on reopen the running stage is interrupted.
    assert_eq!(mark_running_interrupted(&db).unwrap(), 1);
    let after = statuses(&db);
    assert!(after[..running].iter().all(|s| s == "done"), "{after:?}");
    assert_eq!(after[running], "interrupted");
    assert!(
        after[running + 1..].iter().all(|s| s == "pending"),
        "{after:?}"
    );
    let row = task(&db, id).unwrap().unwrap();
    assert!(row.unfinished());
    assert_eq!(row.describe(), "recon 10.0.0.0/24: services interrupted");

    decline(&db, id).unwrap();
    let declined = statuses(&db);
    assert!(
        declined[..running].iter().all(|s| s == "done"),
        "{declined:?}"
    );
    assert!(
        declined[running..].iter().all(|s| s == "skipped"),
        "{declined:?}"
    );
    assert!(unfinished(&db).unwrap().is_empty());
    assert_eq!(
        task(&db, id).unwrap().unwrap().describe(),
        "recon 10.0.0.0/24: finished"
    );
    assert_eq!(task(&db, 999).unwrap(), None);
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
        enqueue(&db, "10.0.0.6", Mode::Mild, &[]).unwrap();
        decline(&db, first).unwrap();
    }
    assert_eq!(count_unfinished(&path), 1);
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
    let (facts, secrets) = stages::script_facts(
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
