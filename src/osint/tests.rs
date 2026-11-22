use super::*;

#[test]
fn internal_names_and_private_reverse_names_stay_off_public_services() {
    assert_eq!(
        reverse_name_address("5.0.0.10.in-addr.arpa"),
        Some("10.0.0.5".parse().unwrap())
    );
    let v6: IpAddr = "2001:db8::567:89ab".parse().unwrap();
    assert_eq!(reverse_name_address(&reverse_dns_name(v6)), Some(v6));
    assert_eq!(reverse_name_address("1.2.in-addr.arpa"), None);
    for private in [
        reverse_dns_name("10.0.0.5".parse().unwrap()),
        reverse_dns_name("192.168.1.1".parse().unwrap()),
        reverse_dns_name("fd00::1".parse().unwrap()),
        "db.acme.corp".to_owned(),
        "printer.local".to_owned(),
        "nas.home.arpa".to_owned(),
        "app.internal".to_owned(),
        "fileserver".to_owned(),
    ] {
        assert!(!may_ask_public_services(&private), "{private}");
    }
    for public in [
        reverse_dns_name("45.33.32.156".parse().unwrap()),
        "scanme.nmap.org".to_owned(),
        "example.com".to_owned(),
    ] {
        assert!(may_ask_public_services(&public), "{public}");
    }
}

#[tokio::test]
async fn crt_sh_is_not_asked_about_an_internal_name() {
    // A stand-in for the log: nothing leaves this machine, whatever the
    // check decides.
    let (crt_sh, asked) = stand_in_doh(None).await;
    for (domain, address) in [
        ("db.acme.corp", "10.0.0.5"),
        ("portal.client.com", "10.0.0.7"),
    ] {
        // How the stage decides.
        let internal = is_internal_target(domain, &[address.to_owned()]).await;
        let error = format!(
            "{:#}",
            run_subdomains_at(&crt_sh, domain, address, internal)
                .await
                .unwrap_err()
        );
        assert!(error.contains("not sent to crt.sh"), "{domain}: {error}");
    }
    assert!(taken(&asked).is_empty(), "{:?}", taken(&asked));
}

#[test]
fn a_reverse_record_is_a_claim_and_takes_no_name_from_another_host() {
    use crate::graph::Graph;
    let mut graph = Graph::default();
    let rec = EvidenceRecord::observed(Source::NmapXml, Confidence::High, "scan");
    graph.apply(Observation::Port {
        address: "portal.example".into(),
        port: 443,
        protocol: "tcp".into(),
        state: "open".into(),
        service: None,
        product: None,
        version: None,
        extra_info: None,
        cpes: vec![],
        record: rec,
    });
    graph.apply(Observation::Note {
        address: Some("portal.example".into()),
        text: "in scope".into(),
        record: EvidenceRecord::observed(Source::ManualNote, Confidence::Medium, "x"),
    });
    let before = graph.hosts["portal.example"].clone();
    // What the dns stage records for a PTR answer.
    graph.apply(Observation::Hostname {
        address: "10.0.0.66".into(),
        hostname: "portal.example".into(),
        record: EvidenceRecord::observed(
            Source::Dns,
            Confidence::Medium,
            "66.0.0.10.in-addr.arpa IN PTR portal.example",
        ),
    });
    assert_eq!(graph.hosts["portal.example"], before);
    assert_eq!(
        graph.host("portal.example").unwrap().address,
        "portal.example"
    );
}

fn build_kexinit_fixture(kex: &str, hostkeys: &str, ciphers: &str, macs: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(20u8); // SSH_MSG_KEXINIT
    payload.extend_from_slice(&[0x42u8; 16]); // 16-byte cookie
    let lists = [
        kex,
        hostkeys,
        ciphers,
        ciphers,
        macs,
        macs,
        "none,zlib@openssh.com",
        "none,zlib@openssh.com",
        "",
        "",
    ];
    for list in lists {
        payload.extend_from_slice(&(list.len() as u32).to_be_bytes());
        payload.extend_from_slice(list.as_bytes());
    }
    payload.push(0); // first_kex_packet_follows = FALSE
    payload.extend_from_slice(&0u32.to_be_bytes()); // reserved = 0

    let pad_len = 8usize;
    let pkt_len = 1 + payload.len() + pad_len;
    let mut framed = Vec::with_capacity(4 + pkt_len);
    framed.extend_from_slice(&(pkt_len as u32).to_be_bytes());
    framed.push(pad_len as u8);
    framed.extend_from_slice(&payload);
    framed.extend_from_slice(&vec![0u8; pad_len]);
    framed
}

#[test]
fn ssh_msg_kexinit_parser_extracts_algorithms_and_flags_weak_ones() {
    let fixture = build_kexinit_fixture(
        "curve25519-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
        "rsa-sha2-512,ssh-rsa,ssh-dss",
        "chacha20-poly1305@openssh.com,aes128-ctr,3des-cbc,arcfour",
        "umac-128-etm@openssh.com,hmac-sha1,hmac-md5",
    );

    let parsed = parse_ssh_kexinit(&fixture).expect("valid SSH_MSG_KEXINIT fixture");
    assert_eq!(
        parsed.kex_algorithms,
        [
            "curve25519-sha256",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group1-sha1"
        ]
    );
    assert_eq!(
        parsed.server_host_key_algorithms,
        ["rsa-sha2-512", "ssh-rsa", "ssh-dss"]
    );
    assert_eq!(
        parsed.encryption_algorithms_c2s,
        [
            "chacha20-poly1305@openssh.com",
            "aes128-ctr",
            "3des-cbc",
            "arcfour"
        ]
    );
    assert_eq!(
        parsed.mac_algorithms_c2s,
        ["umac-128-etm@openssh.com", "hmac-sha1", "hmac-md5"]
    );

    let weak = parsed.weak_algorithms();
    assert!(weak.contains(&"kex:diffie-hellman-group14-sha1".to_owned()));
    assert!(weak.contains(&"kex:diffie-hellman-group1-sha1".to_owned()));
    assert!(weak.contains(&"hostkey:ssh-rsa".to_owned()));
    assert!(weak.contains(&"hostkey:ssh-dss".to_owned()));
    assert!(weak.contains(&"cipher:3des-cbc".to_owned()));
    assert!(weak.contains(&"cipher:arcfour".to_owned()));
    assert!(weak.contains(&"mac:hmac-sha1".to_owned()));
    assert!(weak.contains(&"mac:hmac-md5".to_owned()));

    // Modern hardened config produces zero weak algorithms.
    let modern = build_kexinit_fixture(
        "curve25519-sha256,diffie-hellman-group16-sha512",
        "ssh-ed25519,rsa-sha2-512",
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
        "hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
    );
    let parsed_modern = parse_ssh_kexinit(&modern).unwrap();
    assert!(parsed_modern.weak_algorithms().is_empty());

    // Rejects truncated or non-KEXINIT packets.
    assert!(parse_ssh_kexinit(&[0, 0, 0, 5, 0, 21]).is_err());
    assert!(parse_ssh_kexinit(&fixture[..20]).is_err());
}

#[test]
fn team_cymru_and_rdap_parsers_extract_asn_prefix_org_and_country() {
    let origin = "63949 | 45.33.32.0/24 | US | arin | 2010-02-02";
    assert_eq!(
        parse_cymru_origin(origin),
        Some((
            63949,
            Some("45.33.32.0/24".to_owned()),
            Some("US".to_owned())
        ))
    );
    let desc = "63949 | US | arin | 2012-07-20 | LINO-1 - Akamai Connected Cloud, US";
    assert_eq!(
        parse_cymru_asn(desc),
        Some("LINO-1 - Akamai Connected Cloud, US".to_owned())
    );

    let rdap_json: Value = serde_json::json!({
        "handle": "NET-45-33-32-0-1",
        "name": "LINODE-US",
        "country": "US",
        "arin_originas0_originautnums": [63949],
        "cidr0_cidrs": [
            { "v4prefix": "45.33.32.0", "length": 24 }
        ],
        "entities": [
            {
                "handle": "LINO-1",
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Akamai Connected Cloud"]
                    ]
                ]
            }
        ]
    });
    let (asn, org, prefix, country) = parse_rdap_response(&rdap_json).unwrap();
    assert_eq!(asn, Some(63949));
    assert_eq!(org.as_deref(), Some("Akamai Connected Cloud (LINODE-US)"));
    assert_eq!(prefix.as_deref(), Some("45.33.32.0/24"));
    assert_eq!(country.as_deref(), Some("US"));
}

#[test]
fn http_header_waf_favicon_and_crtsh_parsers_handle_real_fixtures() {
    let headers = vec![
        ("Server".to_owned(), "Apache/2.4.7 (Ubuntu)".to_owned()),
        ("X-Powered-By".to_owned(), "PHP/8.1.2".to_owned()),
        ("X-Frame-Options".to_owned(), "SAMEORIGIN".to_owned()),
        ("CF-Ray".to_owned(), "84a1b2c3d4e5-SJC".to_owned()),
    ];
    let analysis = analyze_http_headers(&headers);
    assert_eq!(analysis.server.as_deref(), Some("Apache/2.4.7 (Ubuntu)"));
    assert_eq!(analysis.powered_by.as_deref(), Some("PHP/8.1.2"));
    assert_eq!(analysis.waf.as_deref(), Some("Cloudflare"));
    assert_eq!(
        analysis
            .present_security
            .get("X-Frame-Options")
            .map(String::as_str),
        Some("SAMEORIGIN")
    );
    assert_eq!(
        analysis.missing_security,
        [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options"
        ]
    );

    let crtsh_fixture = r#"[
        {"name_value": "*.scanme.org\nscanme.org\nchat.scanme.org", "common_name": "scanme.org"},
        {"name_value": "SCANME.ORG\napi.scanme.org\nevil-scanme.org"},
        {"name_value": "sub.api.scanme.org\nnot-a-domain/path"}
    ]"#;
    let subs = parse_crtsh_json(crtsh_fixture, "scanme.org", 50).unwrap();
    assert_eq!(
        subs,
        [
            "scanme.org",
            "chat.scanme.org",
            "api.scanme.org",
            "sub.api.scanme.org"
        ]
    );

    // MurmurHash3 deterministic check and framework lookup.
    assert_eq!(murmur3_32(b"hello", 0), 613153351);
    assert_eq!(lookup_favicon_framework(116323821), Some("Spring Boot"));
    assert_eq!(lookup_favicon_framework(81586312), Some("Jenkins"));
    assert!(distro_backport_note("OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13").is_some());
}

#[tokio::test]
async fn scripts_are_read_from_the_site_and_html_answers_are_skipped() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = std::sync::Arc::clone(&asked);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            let path = request.split_whitespace().nth(1).unwrap_or("").to_owned();
            log.lock().unwrap().push(path.clone());
            let (kind, body) = match path.as_str() {
                "/app.js" => ("application/javascript", "fetch('/api/v2/orders')"),
                "/spa.js" => ("text/html", "<!doctype html><html></html>"),
                _ => ("text/plain", "not found"),
            };
            let status = if path == "/missing.js" {
                "404 Not Found"
            } else {
                "200 OK"
            };
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(reply.as_bytes()).await;
        }
    });
    let paths: Vec<String> = [
        "/app.js",
        "/spa.js",
        "/missing.js",
        "//elsewhere.test/x.js",
        "relative.js",
    ]
    .iter()
    .map(|p| (*p).to_owned())
    .collect();
    let got = fetch_scripts("127.0.0.1", None, port, false, &paths, 1024)
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].0, "/app.js");
    assert!(got[0].1.contains("/api/v2/orders"));
    // Paths that leave the site are never asked for.
    let asked = asked.lock().unwrap();
    assert!(
        !asked
            .iter()
            .any(|p| p.contains("elsewhere") || p.contains("relative")),
        "{asked:?}"
    );
}

#[test]
fn cookie_values_are_left_out_of_header_evidence() {
    assert_eq!(
        redact_cookie_value("Set-Cookie", "sid=abc123; Path=/; HttpOnly"),
        "sid=<value left out>; Path=/; HttpOnly"
    );
    assert_eq!(
        redact_cookie_value("set-cookie", "a=b"),
        "a=<value left out>"
    );
    assert_eq!(redact_cookie_value("Server", "nginx"), "nginx");
}

#[test]
fn srv_caa_ds_and_dnskey_answers_are_read_and_queries_carry_edns0() {
    // A response to `example.test` with one answer of `qtype`.
    fn answer(qtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut packet = build_dns_query(0x1234, "example.test", qtype).unwrap();
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0xC00Cu16.to_be_bytes());
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(rdata);
        packet
    }
    let mut srv = vec![0, 0, 0, 5, 0x01, 0x85];
    for label in ["dc1", "example", "test"] {
        srv.push(label.len() as u8);
        srv.extend_from_slice(label.as_bytes());
    }
    srv.push(0);
    assert_eq!(
        parse_dns_wire_response(&answer(33, &srv), 0x1234, 33),
        ["0 5 389 dc1.example.test"]
    );
    let mut caa = vec![0, 5];
    caa.extend_from_slice(b"issueletsencrypt.org");
    assert_eq!(
        parse_dns_wire_response(&answer(257, &caa), 0x1234, 257),
        ["0 issue \"letsencrypt.org\""]
    );
    assert_eq!(
        parse_dns_wire_response(&answer(43, &[0x09, 0x43, 13, 2, 0xAB, 0xCD]), 0x1234, 43),
        ["2371 13 2"]
    );
    assert_eq!(
        parse_dns_wire_response(&answer(48, &[0x01, 0x01, 3, 13, 0x99]), 0x1234, 48),
        ["257 3 13"]
    );
    // A CAA tag longer than the record is refused, not read past the end.
    assert!(parse_dns_wire_response(&answer(257, &[0, 40, b'i']), 0x1234, 257).is_empty());

    let plain = build_dns_query(7, "example.test", 48).unwrap();
    let extended = with_edns0(plain.clone());
    assert_eq!(&extended[10..12], &[0, 1]);
    assert_eq!(extended.len(), plain.len() + 11);
    assert_eq!(
        &extended[plain.len()..plain.len() + 5],
        &[0, 0, 41, 0x04, 0xD0]
    );
    assert_eq!(dns_rcode(&[0, 7, 0x81, 0x81]), Some(1));
}

#[test]
fn dns_doh_and_wire_parsers_extract_records_and_filter_txt() {
    let doh = serde_json::json!({
        "Status": 0,
        "Answer": [
            {"name": "scanme.nmap.org.", "type": 1, "TTL": 3600, "data": "45.33.32.156"},
            {"name": "scanme.nmap.org.", "type": 28, "TTL": 3600, "data": "2600:3c01::f03c:91ff:fe18:bb2f"}
        ]
    });
    assert_eq!(parse_doh_records(&doh, 1), ["45.33.32.156"]);
    assert_eq!(
        parse_doh_records(&doh, 28),
        ["2600:3c01::f03c:91ff:fe18:bb2f"]
    );
    assert!(is_notable_txt("v=spf1 include:_spf.google.com ~all"));
    assert!(is_notable_txt("v=DMARC1; p=reject;"));
    assert!(is_notable_txt("google-site-verification=abc123xyz"));
    assert!(!is_notable_txt("hello world random note"));
    assert_eq!(
        reverse_dns_name(IpAddr::V4(Ipv4Addr::new(45, 33, 32, 156))),
        "156.32.33.45.in-addr.arpa"
    );
}

#[test]
fn a_txt_record_split_into_strings_is_joined_as_the_wire_parser_joins_it() {
    // An SPF record over 255 bytes comes as several strings; DNS-over-HTTPS
    // writes them in presentation form. They are joined without spaces.
    let doh = serde_json::json!({
        "Status": 0,
        "Answer": [
            {"name": "example.test.", "type": 16, "TTL": 300,
             "data": "\"v=spf1 include:_spf.acme-a.zz \" \"include:_spf.acme-b.zz -all\""},
            {"name": "example.test.", "type": 16, "TTL": 300,
             "data": "\"say \\\"hi\\\"\\059 back\\\\slash\""},
            {"name": "example.test.", "type": 16, "TTL": 300, "data": "\"v=DMARC1; p=reject\""},
            {"name": "example.test.", "type": 16, "TTL": 300, "data": "unquoted text as is"}
        ]
    });
    assert_eq!(
        parse_doh_records(&doh, 16),
        [
            "v=spf1 include:_spf.acme-a.zz include:_spf.acme-b.zz -all",
            "say \"hi\"; back\\slash",
            "v=DMARC1; p=reject",
            "unquoted text as is",
        ]
    );
    // The wire parser gives the same record from the same strings.
    let mut packet = vec![0, 9, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    packet.extend_from_slice(&build_dns_query(9, "example.test", 16).unwrap()[12..]);
    let strings: [&[u8]; 2] = [
        b"v=spf1 include:_spf.acme-a.zz ",
        b"include:_spf.acme-b.zz -all",
    ];
    let rdata: Vec<u8> = strings
        .iter()
        .flat_map(|s| std::iter::once(s.len() as u8).chain(s.iter().copied()))
        .collect();
    packet.extend_from_slice(&[0xC0, 12, 0, 16, 0, 1, 0, 0, 1, 44]);
    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    packet.extend_from_slice(&rdata);
    assert_eq!(
        parse_dns_wire_response(&packet, 9, 16),
        parse_doh_records(&doh, 16)[..1]
    );
}

#[test]
fn a_long_txt_record_is_kept_whole_and_cut_only_between_terms() {
    // A TXT answer in both forms, its text in strings of at most 255 bytes.
    let answers = |record: &str| {
        let strings: Vec<&str> = record
            .as_bytes()
            .chunks(250)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();
        let doh = serde_json::json!({
            "Status": 0,
            "Answer": [{
                "name": "example.test.", "type": 16, "TTL": 300,
                "data": strings.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(" "),
            }]
        });
        let mut packet = vec![0, 9, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        packet.extend_from_slice(&build_dns_query(9, "example.test", 16).unwrap()[12..]);
        let rdata: Vec<u8> = strings
            .iter()
            .flat_map(|s| std::iter::once(s.len() as u8).chain(s.bytes()))
            .collect();
        packet.extend_from_slice(&[0xC0, 12, 0, 16, 0, 1, 0, 0, 1, 44]);
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);
        (
            parse_doh_records(&doh, 16),
            parse_dns_wire_response(&packet, 9, 16),
        )
    };
    // 416 bytes: byte 400 falls inside `acmeholdingmail`, which has no dot
    // to be found by, and the request to the model takes 400 at most.
    let spf = format!(
        "v=spf1 {}include:acmeholdingmail.ag -all",
        "ip4:192.0.2.1 ".repeat(27)
    );
    let at = spf.find("acmeholdingmail").unwrap();
    assert!(at < 400 && at + "acmeholdingmail".len() > 400);
    let (doh, wire) = answers(&spf);
    assert_eq!(doh, [spf.as_str()]);
    assert_eq!(wire, doh);
    // Longer than is kept: cut after a whole term.
    let longer = format!("v=spf1 {}-all", "ip4:192.0.2.1 ".repeat(80));
    let (doh, wire) = answers(&longer);
    assert!(
        doh[0].len() <= 1024 && doh[0].len() > 1000,
        "{}",
        doh[0].len()
    );
    assert!(doh[0].ends_with(" ip4:192.0.2.1"), "{}", doh[0]);
    assert_eq!(wire, doh);
}

#[test]
fn traceroute_detailed_parser_extracts_hops_labels_filtered_stars_and_rtt() {
    let sample = "\
traceroute to 45.33.32.156 (45.33.32.156), 15 hops max, 60 byte packets
 1  192.168.0.1  1.8 ms
 2  96.120.1.1  9.4 ms
 3  be-202-seattle.comcast.net (68.86.1.1)  12.1 ms
 4  * * *
 5  173.230.159.1 (Linode Edge - Fremont, CA)  22.6 ms
 6  45.33.32.156  23.1 ms
";
    let hops = parse_traceroute_detailed(
        sample,
        "45.33.32.156",
        Some("192.168.0.1"),
        Some("scanme.nmap.org"),
    );
    assert_eq!(hops.len(), 6);
    assert_eq!(hops[0].hop, 1);
    assert_eq!(hops[0].address, "192.168.0.1");
    assert_eq!(hops[0].label.as_deref(), Some("Local Router"));
    assert_eq!(hops[0].rtt_ms, Some(1.8));
    assert!(hops[0].formatted().contains("Hop 1: 192.168.0.1"));
    assert!(hops[0].formatted().contains("(Local Router)"));
    assert!(hops[0].formatted().contains("1.8 ms"));

    assert_eq!(hops[1].hop, 2);
    assert_eq!(hops[1].address, "96.120.1.1");
    assert_eq!(hops[1].label.as_deref(), Some("ISP Regional Node"));
    assert_eq!(hops[1].rtt_ms, Some(9.4));

    assert_eq!(hops[3].hop, 4);
    assert_eq!(hops[3].address, "* * *");
    assert_eq!(
        hops[3].label.as_deref(),
        Some("isp-transit / ICMP filtered")
    );
    assert_eq!(hops[3].rtt_ms, None);
    assert!(hops[3].formatted().ends_with('—'));

    assert_eq!(hops[4].hop, 5);
    assert_eq!(hops[4].address, "173.230.159.1");
    assert_eq!(hops[4].label.as_deref(), Some("Linode Edge - Fremont, CA"));
    assert_eq!(hops[4].rtt_ms, Some(22.6));

    assert_eq!(hops[5].hop, 6);
    assert_eq!(hops[5].address, "45.33.32.156");
    assert_eq!(hops[5].label.as_deref(), Some("scanme.nmap.org"));
    assert_eq!(hops[5].rtt_ms, Some(23.1));

    // Round-trip parsing of formatted Hop lines.
    let formatted: String = hops
        .iter()
        .map(TraceHop::formatted)
        .collect::<Vec<_>>()
        .join("\n");
    let reparsed = parse_traceroute_detailed(
        &formatted,
        "45.33.32.156",
        Some("192.168.0.1"),
        Some("scanme.nmap.org"),
    );
    assert_eq!(reparsed, hops);
}

#[tokio::test]
async fn resolved_ip_policy_blocks_loopback_and_imds_for_external_domains() {
    assert!(is_allowed_resolved_ip_for_name(
        "app.lab.local",
        "10.0.0.5".parse().unwrap()
    ));
    assert!(is_allowed_resolved_ip_for_name(
        "localhost",
        "127.0.0.1".parse().unwrap()
    ));
    assert!(is_allowed_resolved_ip_for_name(
        "localhost.",
        "::1".parse().unwrap()
    ));
    for blocked in [
        "100.100.100.200",
        "fd00:ec2::254",
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "169.254.169.254",
        "fe80::1",
        "0.0.0.0",
        "::",
        "255.255.255.255",
        "224.0.0.1",
    ] {
        assert!(
            !is_allowed_resolved_ip_for_name("evil.example", blocked.parse().unwrap()),
            "{blocked} should be rejected for evil.example"
        );
    }
    assert!(
        inspect_web_endpoint("169.254.169.254", Some("evil.example"), 80, false)
            .await
            .is_err()
    );
    assert!(
        inspect_web_endpoint("127.0.0.1", Some("evil.example"), 80, false)
            .await
            .is_err()
    );
}

/// What a stand-in DNS server says to a question.
#[derive(Clone, Copy)]
pub(crate) enum Reply {
    Address([u8; 4]),
    NxDomain,
    ServFail,
    Refused,
    NoData,
}

pub(crate) type Asked = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// A stand-in for this machine's DNS server on 127.0.0.1, answering by
/// `reply`, and the questions it was asked (`TYPE name`).
pub(crate) async fn stand_in_dns(reply: fn(&str, u16) -> Reply) -> (SocketAddr, Asked) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let asked = Asked::default();
    let log = std::sync::Arc::clone(&asked);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let query = &buf[..n];
            let mut at = 12;
            let mut labels = Vec::new();
            while at < n && query[at] != 0 {
                let len = query[at] as usize;
                labels.push(String::from_utf8_lossy(&query[at + 1..at + 1 + len]).into_owned());
                at += len + 1;
            }
            let name = labels.join(".");
            let qtype = u16::from_be_bytes([query[at + 1], query[at + 2]]);
            log.lock().unwrap().push(format!("{qtype} {name}"));
            let (rcode, rdata) = match reply(&name, qtype) {
                Reply::Address(ip) if qtype == 1 => (0u16, Some(ip)),
                Reply::Address(_) | Reply::NoData => (0, None),
                Reply::NxDomain => (3, None),
                Reply::ServFail => (2, None),
                Reply::Refused => (5, None),
            };
            let mut packet = query[..2].to_vec();
            packet.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
            packet.extend_from_slice(&[0, 1, 0, u8::from(rdata.is_some()), 0, 0, 0, 0]);
            packet.extend_from_slice(&query[12..at + 5]);
            if let Some(ip) = rdata {
                packet.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                packet.extend_from_slice(&ip);
            }
            let _ = sock.send_to(&packet, peer).await;
        }
    });
    (addr, asked)
}

/// A stand-in DNS-over-HTTPS service on 127.0.0.1 that answers `a` to an
/// A question and "no records" to the others, and the questions it was
/// asked (`TYPE name`).
pub(crate) async fn stand_in_doh(a: Option<[u8; 4]>) -> (String, Asked) {
    stand_in_doh_saying(0, a).await
}

/// [`stand_in_doh`] with `status` as the answers' Status: 2 is SERVFAIL.
pub(crate) async fn stand_in_doh_saying(status: u8, a: Option<[u8; 4]>) -> (String, Asked) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/dns-query",
        listener.local_addr().unwrap().port()
    );
    let asked = Asked::default();
    let log = std::sync::Arc::clone(&asked);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            let target = request.split_whitespace().nth(1).unwrap_or("").to_owned();
            let query = url::Url::parse(&format!("http://stand-in.invalid{target}")).unwrap();
            let field = |key: &str| {
                query
                    .query_pairs()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            };
            log.lock()
                .unwrap()
                .push(format!("{} {}", field("type"), field("name")));
            let body = match a.filter(|_| field("type") == "A") {
                Some(ip) => format!(
                    r#"{{"Status":{status},"Answer":[{{"name":"{}","type":1,"TTL":60,"data":"{}"}}]}}"#,
                    field("name"),
                    std::net::Ipv4Addr::from(ip)
                ),
                None => format!(r#"{{"Status":{status},"Answer":[]}}"#),
            };
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(reply.as_bytes()).await;
        }
    });
    (url, asked)
}

pub(crate) fn stand_in_resolver(servers: Vec<SocketAddr>, doh: &str) -> Resolver {
    // Straight to the stand-in, whatever proxy the machine sets.
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    Resolver::with(client, servers, vec![doh.to_owned()])
}

pub(crate) fn taken(asked: &Asked) -> Vec<String> {
    asked.lock().unwrap().clone()
}

/// Interfaces by name, as `if_nametoindex` would find them.
fn stand_in_zone(zone: &str) -> Option<u32> {
    match zone {
        "eth0" => Some(2),
        "wlan0" | "en0" => Some(6),
        "utun3" => Some(18),
        other => other.parse().ok().filter(|index| *index != 0),
    }
}

#[test]
fn resolv_conf_names_the_servers_and_nothing_stands_in_for_none() {
    let text = "# comment\nsearch corp.example.org\nnameserver 192.0.2.53\n\
                nameserver 192.0.2.53\nnameserverx 198.51.100.1\n\
                nameserver fe80::53%eth0\n  nameserver 2001:db8::53 # trailing\n\
                nameserver fe80::54%7\nnameserver fe80::55%nosuch0\nnameserver fe80::56\n";
    let servers = parse_resolv_conf_with(text, &stand_in_zone);
    let shown: Vec<String> = servers.iter().map(ToString::to_string).collect();
    // A link-local server keeps its interface, named or numbered; one on
    // an interface this machine does not have, or on none, is left out.
    assert_eq!(
        shown,
        [
            "192.0.2.53:53",
            "[fe80::53%2]:53",
            "[2001:db8::53]:53",
            "[fe80::54%7]:53"
        ]
    );
    let SocketAddr::V6(link) = servers[1] else {
        panic!("{servers:?}")
    };
    assert_eq!(link.scope_id(), 2);
    // The system's own interfaces: the loopback one exists everywhere.
    let lo = if cfg!(target_os = "linux") {
        "lo"
    } else {
        "lo0"
    };
    let real = parse_resolv_conf(&format!(
        "nameserver fe80::1%{lo}\nnameserver fe80::2%nosuch0\n"
    ));
    assert_eq!(real.len(), 1, "{real:?}");
    assert!(matches!(real[0], SocketAddr::V6(v6) if v6.scope_id() != 0));
    // No file, or one without servers: no public resolver takes their place.
    assert!(parse_resolv_conf("").is_empty());
    assert!(parse_resolv_conf("search example.org\n").is_empty());
}

#[test]
fn a_system_answer_is_final_only_when_it_answers_the_question() {
    let question = build_dns_query(0x4242, "www.example.org", 16).unwrap();
    let with_flags = |flags: u16| {
        let mut packet = question.clone();
        packet[2..4].copy_from_slice(&flags.to_be_bytes());
        packet
    };
    let none = DnsAnswer::Answered(Vec::new());
    let read = |packet: &[u8]| read_dns_answer(packet, 0x4242, "www.example.org", 16);
    // NOERROR without the record (NODATA) and NXDOMAIN are answers, also
    // from an authoritative server that does not recurse.
    assert_eq!(read(&with_flags(0x8180)), none);
    assert_eq!(read(&with_flags(0x8183)), none);
    assert_eq!(read(&with_flags(0x8400)), none);
    // SERVFAIL, REFUSED, a referral and an answer cut short are not.
    for flags in [0x8182, 0x8185, 0x8100, 0x8380] {
        assert_eq!(read(&with_flags(flags)), DnsAnswer::Nothing, "{flags:#x}");
    }
    assert_eq!(read(&with_flags(0x8181)), DnsAnswer::EdnsRefused);
    // Another question, another transaction, or no answer at all: nothing.
    let mut other = build_dns_query(0x4242, "mail.example.org", 16).unwrap();
    other[2..4].copy_from_slice(&0x8183u16.to_be_bytes());
    assert_eq!(read(&other), DnsAnswer::Nothing);
    let nxdomain = with_flags(0x8183);
    assert_eq!(
        read_dns_answer(&nxdomain, 0x4243, "www.example.org", 16),
        DnsAnswer::Nothing
    );
    assert_eq!(
        read_dns_answer(&nxdomain, 0x4242, "www.example.org", 1),
        DnsAnswer::Nothing
    );
    assert_eq!(read(&with_flags(0x0100)), DnsAnswer::Nothing);
    assert_eq!(read(&question[..10]), DnsAnswer::Nothing);
    // Names are compared without regard to case.
    assert_eq!(
        read_dns_answer(&nxdomain, 0x4242, "WWW.Example.org.", 16),
        none
    );
}

#[tokio::test]
async fn doh_is_asked_only_when_the_system_resolver_gives_no_answer() {
    let (server, asked) = stand_in_dns(|name, _| match name {
        "gone.example.org" => Reply::NxDomain,
        "www.example.org" => Reply::NoData,
        "refused.example.org" => Reply::Refused,
        _ => Reply::ServFail,
    })
    .await;
    let (doh, doh_asked) = stand_in_doh(None).await;
    let resolver = stand_in_resolver(vec![server], &doh);
    // A final answer, records or none, is not asked of anyone else.
    assert_eq!(
        resolver.resolve("gone.example.org", 1).await,
        Lookup::NoRecords
    );
    assert_eq!(
        resolver.resolve("www.example.org", 16).await,
        Lookup::NoRecords
    );
    assert!(taken(&doh_asked).is_empty());
    // No answer: a public name goes over DNS-over-HTTPS (which says there
    // is none), a private one not.
    assert_eq!(
        resolver.resolve("broken.example.org", 15).await,
        Lookup::NoRecords
    );
    assert_eq!(
        resolver.resolve("refused.example.org", 15).await,
        Lookup::NoRecords
    );
    let private_ptr = reverse_dns_name("10.0.0.5".parse().unwrap());
    assert_eq!(resolver.resolve(&private_ptr, 12).await, Lookup::Failed);
    assert_eq!(resolver.resolve("dc01.corp.local", 1).await, Lookup::Failed);
    assert_eq!(
        taken(&doh_asked),
        ["MX broken.example.org", "MX refused.example.org"]
    );
    assert_eq!(taken(&asked).len(), 6);
}

#[tokio::test]
async fn without_a_system_resolver_only_public_names_go_out_and_only_over_doh() {
    let (doh, doh_asked) = stand_in_doh(None).await;
    let resolver = stand_in_resolver(Vec::new(), &doh);
    for (name, rrtype) in [
        (reverse_dns_name("10.0.0.5".parse().unwrap()), 12),
        ("dc01.corp.local".to_owned(), 16),
        ("_ldap._tcp.dc._msdcs.corp.local".to_owned(), 33),
        ("_dmarc.dc01.corp.local".to_owned(), 16),
        ("www.example.org".to_owned(), 16),
    ] {
        assert!(resolver.resolve(&name, rrtype).await.records().is_empty());
    }
    assert_eq!(taken(&doh_asked), ["TXT www.example.org"]);
}

#[tokio::test]
async fn an_internal_target_is_never_asked_over_doh() {
    // The system resolver answers nothing (SERVFAIL), which would send a
    // public name over DNS-over-HTTPS; it knows the target's own name.
    let (server, asked) = stand_in_dns(|name, _| match name {
        "dc01.corp.example.org" => Reply::Address([10, 0, 0, 5]),
        _ => Reply::ServFail,
    })
    .await;
    let (doh, doh_asked) = stand_in_doh(None).await;
    let target = Target::parse("dc01.corp.example.org").unwrap();
    // The dns stage: the system resolved the name to a private address.
    let (_, ips, _) = run_dns_with(
        &target,
        stand_in_resolver(vec![server], &doh),
        (vec!["10.0.0.5".to_owned()], Vec::new()),
        false,
    )
    .await;
    assert_eq!(ips, ["10.0.0.5"]);
    assert!(taken(&asked).contains(&"16 dc01.corp.example.org".to_owned()));
    assert!(taken(&doh_asked).is_empty(), "{:?}", taken(&doh_asked));
    // The mail-dns stage for that target.
    assert!(is_internal_target("dc01.corp.example.org", &ips).await);
    assert!(is_internal_target("dc01.corp.local", &[]).await);
    assert_eq!(
        internal_target_addresses("dc01.corp.example.org", &ips).await,
        Some(ips.clone())
    );
    assert_eq!(
        internal_target_addresses("printer.corp.local", &["10.0.0.9".to_owned()]).await,
        Some(vec!["10.0.0.9".to_owned()])
    );
    let mail_dns = |internal: bool| {
        crate::maildns::run_on(
            stand_in_resolver(vec![server], &doh),
            "dc01.corp.example.org",
            "10.0.0.5",
            &[],
            internal.then_some(ips.as_slice()),
        )
    };
    mail_dns(true).await.unwrap();
    let mail = taken(&asked);
    assert!(mail.contains(&"16 _dmarc.dc01.corp.example.org".to_owned()));
    assert!(mail
        .iter()
        .any(|q| q.ends_with("._domainkey.dc01.corp.example.org")));
    assert!(taken(&doh_asked).is_empty(), "{:?}", taken(&doh_asked));
    // Not internal: what the system cannot answer goes over DoH.
    mail_dns(false).await.unwrap();
    assert!(
        taken(&doh_asked).contains(&"TXT _dmarc.dc01.corp.example.org".to_owned()),
        "{:?}",
        taken(&doh_asked)
    );
    doh_asked.lock().unwrap().clear();

    // A public name the system cannot resolve still has DNS-over-HTTPS.
    let public = Target::parse("www.example.org").unwrap();
    run_dns_with(
        &public,
        stand_in_resolver(vec![server], &doh),
        (Vec::new(), Vec::new()),
        false,
    )
    .await;
    assert!(taken(&doh_asked).contains(&"A www.example.org".to_owned()));
}

#[tokio::test]
async fn an_address_only_doh_gives_is_reported_and_never_the_target_s() {
    // The system resolver refuses the name (a policy, a sinkhole); public
    // DNS has an address for it.
    let (server, _) = stand_in_dns(|_, _| Reply::Refused).await;
    let (doh, doh_asked) = stand_in_doh(Some([203, 0, 113, 66])).await;
    let target = Target::parse("www.example.org").unwrap();
    let (observations, ips, summary) = run_dns_with(
        &target,
        stand_in_resolver(vec![server], &doh),
        (Vec::new(), Vec::new()),
        false,
    )
    .await;
    assert!(taken(&doh_asked).contains(&"A www.example.org".to_owned()));
    assert!(ips.is_empty(), "{ips:?}");
    assert!(
        summary.starts_with("1 A,") && summary.contains("does not resolve"),
        "{summary}"
    );
    let text = format!("{observations:?}");
    assert!(text.contains("A record: 203.0.113.66"), "{text}");
    assert!(
        !observations
            .iter()
            .any(|o| matches!(o, Observation::Hostname { .. })),
        "{text}"
    );
}

#[tokio::test]
async fn the_dns_stage_takes_the_addresses_the_system_resolves() {
    // DNS publishes one address; the system (`/etc/hosts`) gives another,
    // the one the scanner scans.
    let (server, asked) = stand_in_dns(|name, _| match name {
        "www.example.org" => Reply::Address([198, 51, 100, 66]),
        _ => Reply::NxDomain,
    })
    .await;
    let (doh, _) = stand_in_doh(None).await;
    let target = Target::parse("www.example.org").unwrap();
    let (observations, ips, _) = run_dns_with(
        &target,
        stand_in_resolver(vec![server], &doh),
        (vec!["192.0.2.10".to_owned()], Vec::new()),
        false,
    )
    .await;
    assert_eq!(ips, ["192.0.2.10"]);
    let resolved: Vec<&str> = observations
        .iter()
        .filter_map(|o| match o {
            Observation::Hostname { address, .. } => Some(address.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(resolved, ["192.0.2.10"]);
    assert!(!format!("{observations:?}").contains("198.51.100.66"));
    // DNS is asked for the name's address once, only to learn whether it
    // knows the name (its "no such record" counts then).
    let a_asked = taken(&asked)
        .iter()
        .filter(|q| *q == "1 www.example.org")
        .count();
    assert_eq!(a_asked, 1, "{:?}", taken(&asked));
    // The system's own resolution reads /etc/hosts and its like.
    let (v4, _) = system_addresses("localhost").await;
    assert!(v4.contains(&"127.0.0.1".to_owned()), "{v4:?}");
}

/// A resolver that sends each name where `routes` say, with `doh` for
/// DNS-over-HTTPS.
fn stand_in_routed(routes: DnsRoutes, doh: &str) -> Resolver {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    Resolver::with_routes(client, routes, vec![doh.to_owned()])
}

fn route_to(domain: &str, servers: Option<Vec<SocketAddr>>) -> DomainRoute {
    DomainRoute {
        domain: domain.to_owned(),
        exact: false,
        network: None,
        servers,
        order: 0,
    }
}

fn routed(routes: &DnsRoutes, name: &str) -> (Vec<String>, bool) {
    let route = routes.route(name);
    let servers = route.servers.iter().map(ToString::to_string).collect();
    (servers, route.matched)
}

/// `scutil --dns` on a Mac with a split-tunnel VPN (two domains), a
/// tailnet, a reverse zone on another port and the multicast DNS domains.
const SCUTIL_DNS: &str = "\
DNS configuration

resolver #1
  search domain[0] : home.example.net
  nameserver[0] : 192.0.2.1
  nameserver[1] : fe80::1%en0
  nameserver[2] : fe80::2
  if_index : 6 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

resolver #3
  domain   : 254.169.in-addr.arpa
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300200

resolver #4
  domain   : corp.example.com
  search domain[0] : corp.example.com
  nameserver[0] : 198.51.100.53
  nameserver[1] : 198.51.100.54
  if_index : 18 (utun3)
  flags    : Supplemental, Request A records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 102400

resolver #5
  domain   : eu.corp.example.com
  nameserver[0] : 203.0.113.53
  if_index : 18 (utun3)
  flags    : Supplemental, Request A records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 102401

resolver #6
  domain   : tail0123.example.net.
  nameserver[0] : 203.0.113.100
  if_index : 23 (utun4)
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 102402

resolver #7
  domain   : 10.in-addr.arpa
  nameserver[0] : 198.51.100.53
  port     : 5353
  flags    : Supplemental, Request A records
  order    : 102403

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : home.example.net
  nameserver[0] : 192.0.2.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : scoped.example.org
  nameserver[0] : 198.51.100.99
  if_index : 18 (utun3)
  flags    : Scoped, Request A records
  reach    : 0x00000003 (Reachable,Transient Connection)
";

#[test]
fn macos_resolvers_are_read_from_scutil_and_chosen_by_domain() {
    let routes = parse_scutil_dns(SCUTIL_DNS, &stand_in_zone);
    // The default resolver; a link-local server keeps its interface, from
    // its zone or the resolver's if_index.
    let default: Vec<String> = routes.default.iter().map(ToString::to_string).collect();
    assert_eq!(
        default,
        ["192.0.2.1:53", "[fe80::1%6]:53", "[fe80::2%6]:53"]
    );
    let vpn = vec!["198.51.100.53:53".to_owned(), "198.51.100.54:53".to_owned()];
    assert_eq!(
        routed(&routes, "intranet.corp.example.com"),
        (vpn.clone(), true)
    );
    assert_eq!(routed(&routes, "Corp.Example.com."), (vpn.clone(), true));
    assert_eq!(
        routed(&routes, "_ldap._tcp.dc._msdcs.corp.example.com"),
        (vpn, true)
    );
    // The longest domain wins.
    assert_eq!(
        routed(&routes, "db.eu.corp.example.com"),
        (vec!["203.0.113.53:53".to_owned()], true)
    );
    assert_eq!(
        routed(&routes, "host.tail0123.example.net"),
        (vec!["203.0.113.100:53".to_owned()], true)
    );
    assert_eq!(
        routed(&routes, "5.0.0.10.in-addr.arpa"),
        (vec!["198.51.100.53:5353".to_owned()], true)
    );
    // Multicast DNS: no unicast server at all.
    assert_eq!(routed(&routes, "printer.local"), (Vec::new(), true));
    // Everything else, and a name that only ends the same way, goes to the
    // default; so do the names of resolvers for scoped questions.
    for name in [
        "www.example.org",
        "notcorp.example.com",
        "a.scoped.example.org",
    ] {
        assert_eq!(routed(&routes, name), (default.clone(), false), "{name}");
    }
    assert_eq!(routes.domains.len(), 6, "{routes:?}");
    // Nothing to go by: no default and no routes.
    assert_eq!(parse_scutil_dns("", &stand_in_zone), DnsRoutes::default());
}

#[test]
fn macos_resolver_files_name_a_domain_and_its_servers() {
    let route = parse_resolver_file(
        "corp.example.com",
        "# VPN\nnameserver 198.51.100.53\nnameserver fe80::53%utun3\nport 5353\nsearch_order 1\n",
        &stand_in_zone,
    )
    .unwrap();
    assert_eq!(route.domain, "corp.example.com");
    assert_eq!(route.order, 1);
    let servers: Vec<String> = route
        .servers
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(servers, ["198.51.100.53:5353", "[fe80::53%18]:5353"]);
    let named = parse_resolver_file(
        "lab",
        "domain lab.example.org\nnameserver 192.0.2.9\n",
        &stand_in_zone,
    )
    .unwrap();
    assert_eq!(named.domain, "lab.example.org");
    assert!(parse_resolver_file("empty.example.org", "# none\n", &stand_in_zone).is_none());
    assert!(parse_resolver_file("bad name", "nameserver 192.0.2.9\n", &stand_in_zone).is_none());
}

#[test]
fn windows_nrpt_rules_route_by_the_most_specific_namespace() {
    let rule = |names: &[&str], servers: &str, options: u32| NrptRule {
        names: names.iter().map(|n| (*n).to_owned()).collect(),
        servers: servers.to_owned(),
        options,
    };
    let local = vec![
        rule(
            &[".corp.example.com"],
            "198.51.100.53; 198.51.100.54",
            NRPT_OVERRIDE_DNS,
        ),
        // DNSSEC only: it says nothing about where questions go.
        rule(&["build.corp.example.com"], "", 0x2),
        rule(&["10.0.0.0/8"], "198.51.100.53", NRPT_OVERRIDE_DNS),
        rule(&[".lab.example.org"], "203.0.113.53", 0),
    ];
    let routes = DnsRoutes {
        default: vec!["192.0.2.1:53".parse().unwrap()],
        domains: nrpt_routes(&local, &stand_in_zone),
    };
    let default = vec!["192.0.2.1:53".to_owned()];
    let vpn = vec!["198.51.100.53:53".to_owned(), "198.51.100.54:53".to_owned()];
    assert_eq!(
        routed(&routes, "intranet.corp.example.com"),
        (vpn.clone(), true)
    );
    assert_eq!(routed(&routes, "corp.example.com"), (vpn.clone(), true));
    assert_eq!(
        routed(&routes, "build.corp.example.com"),
        (default.clone(), false)
    );
    assert_eq!(
        routed(&routes, "x.build.corp.example.com"),
        (vpn.clone(), true)
    );
    assert_eq!(
        routed(&routes, "5.0.0.10.in-addr.arpa"),
        (vec!["198.51.100.53:53".to_owned()], true)
    );
    for name in [
        "5.0.0.11.in-addr.arpa",
        "www.lab.example.org",
        "www.example.org",
    ] {
        assert_eq!(routed(&routes, name), (default.clone(), false), "{name}");
    }
    // A rule for every name (a full-tunnel VPN) yields to the specific ones.
    let mut all = local.clone();
    all.push(rule(&["."], "192.0.2.53", NRPT_OVERRIDE_DNS));
    let routes = DnsRoutes {
        default: vec!["192.0.2.1:53".parse().unwrap()],
        domains: nrpt_routes(&all, &stand_in_zone),
    };
    assert_eq!(
        routed(&routes, "www.example.org"),
        (vec!["192.0.2.53:53".to_owned()], true)
    );
    assert_eq!(routed(&routes, "intranet.corp.example.com"), (vpn, true));
    // Group Policy's rules replace the local ones when there are any.
    let policy = vec![rule(&[".example.org"], "192.0.2.7", NRPT_OVERRIDE_DNS)];
    assert_eq!(effective_nrpt(policy.clone(), local.clone()), policy);
    assert_eq!(effective_nrpt(Vec::new(), local.clone()), local);
}

#[tokio::test]
async fn split_dns_names_go_to_their_own_servers_and_a_default_none_is_not_final() {
    // The VPN's server knows the internal domain; the default one (the
    // Wi-Fi's) knows nothing of it.
    let (vpn, vpn_asked) = stand_in_dns(|name, _| match name {
        "intranet.corp.example.com" => Reply::Address([10, 0, 0, 5]),
        _ => Reply::NxDomain,
    })
    .await;
    let (wifi, wifi_asked) = stand_in_dns(|_, _| Reply::NxDomain).await;
    let (doh, doh_asked) = stand_in_doh(None).await;
    let routes = DnsRoutes {
        default: vec![wifi],
        domains: vec![
            route_to("corp.example.com", Some(vec![vpn])),
            route_to("local", Some(Vec::new())),
        ],
    };
    let mut resolver = stand_in_routed(routes, &doh);
    resolver.keep_private("intranet.corp.example.com", &["10.0.0.5".to_owned()]);
    // The domain's names: its own server, whose "none" is final.
    assert_eq!(
        resolver
            .resolve("_dmarc.intranet.corp.example.com", 16)
            .await,
        Lookup::NoRecords
    );
    assert_eq!(
        resolver.resolve("intranet.corp.example.com", 1).await,
        Lookup::Found(vec!["10.0.0.5".to_owned()])
    );
    // A name outside it goes to the default server, which does not know
    // the target: its "none" proves nothing.
    assert_eq!(
        resolver.resolve("_dmarc.example.com", 16).await,
        Lookup::Unconfirmed
    );
    // A multicast DNS name: no unicast server is asked.
    assert_eq!(resolver.resolve("printer.local", 1).await, Lookup::Failed);
    // The default server never heard the internal names; DoH heard nothing.
    assert_eq!(taken(&wifi_asked), ["16 _dmarc.example.com"]);
    assert!(
        taken(&vpn_asked)
            .iter()
            .all(|q| q.ends_with(".corp.example.com")),
        "{:?}",
        taken(&vpn_asked)
    );
    assert!(taken(&doh_asked).is_empty(), "{:?}", taken(&doh_asked));
}

#[tokio::test]
async fn a_default_none_counts_for_an_internal_target_only_if_the_server_knows_it() {
    let (doh, doh_asked) = stand_in_doh(None).await;
    // A domain controller as the only DNS server: it knows the target.
    let (dc, _) = stand_in_dns(|name, _| match name {
        "dc01.corp.example.org" => Reply::Address([10, 0, 0, 5]),
        _ => Reply::NxDomain,
    })
    .await;
    let mut resolver = stand_in_resolver(vec![dc], &doh);
    resolver.keep_private("dc01.corp.example.org", &["10.0.0.5".to_owned()]);
    assert_eq!(
        resolver.resolve("_dmarc.dc01.corp.example.org", 16).await,
        Lookup::NoRecords
    );
    // A target the hosts file names: the DNS server knows nothing of it.
    let (other, asked) = stand_in_dns(|_, _| Reply::NxDomain).await;
    let mut resolver = stand_in_resolver(vec![other], &doh);
    resolver.keep_private(
        "target.example.org",
        &["10.0.0.9".to_owned(), "fd00::9".to_owned()],
    );
    for _ in 0..3 {
        assert_eq!(
            resolver.resolve("_dmarc.target.example.org", 16).await,
            Lookup::Unconfirmed
        );
    }
    // Asked about the target once, A then AAAA.
    let about: Vec<String> = taken(&asked)
        .into_iter()
        .filter(|q| q.ends_with(" target.example.org"))
        .collect();
    assert_eq!(about, ["1 target.example.org", "28 target.example.org"]);
    // A server that answers every name (NXDOMAIN rewritten, a captive
    // portal, a wildcard parent zone) does not know the target either: it
    // gives another address than the hosts file.
    let (hijack, asked) = stand_in_dns(|_, qtype| match qtype {
        1 => Reply::Address([198, 51, 100, 7]),
        28 => Reply::NoData,
        _ => Reply::NxDomain,
    })
    .await;
    let mut resolver = stand_in_resolver(vec![hijack], &doh);
    resolver.keep_private("intranet.example.org", &["10.0.0.5".to_owned()]);
    assert_eq!(
        resolver.resolve("_dmarc.intranet.example.org", 16).await,
        Lookup::Unconfirmed
    );
    // Only A: the system has no IPv6 address for it.
    assert_eq!(
        taken(&asked),
        ["16 _dmarc.intranet.example.org", "1 intranet.example.org"]
    );
    // The dns stage for that target claims no missing record.
    let (observations, _, summary) = run_dns_with(
        &Target::parse("intranet.example.org").unwrap(),
        stand_in_resolver(vec![hijack], &doh),
        (vec!["10.0.0.5".to_owned()], Vec::new()),
        false,
    )
    .await;
    assert!(!format!("{observations:?}").contains("no AAAA record"));
    assert!(
        summary.ends_with("; this machine's DNS server does not know the name"),
        "{summary}"
    );
    // The same server for a target whose address it does give.
    let mut resolver = stand_in_resolver(vec![hijack], &doh);
    resolver.keep_private("intranet.example.org", &["198.51.100.7".to_owned()]);
    assert_eq!(
        resolver.resolve("_dmarc.intranet.example.org", 16).await,
        Lookup::NoRecords
    );
    // With no address from the system, nothing proves the server knows it.
    let (dc, dc_asked) = stand_in_dns(|name, _| match name {
        "dc01.corp.example.org" => Reply::Address([10, 0, 0, 5]),
        _ => Reply::NxDomain,
    })
    .await;
    let mut resolver = stand_in_resolver(vec![dc], &doh);
    resolver.keep_private("dc01.corp.example.org", &[]);
    assert_eq!(
        resolver.resolve("_dmarc.dc01.corp.example.org", 16).await,
        Lookup::Unconfirmed
    );
    assert_eq!(taken(&dc_asked), ["16 _dmarc.dc01.corp.example.org"]);
    // For a public target, the system's "none" is final.
    let public = stand_in_resolver(vec![other], &doh);
    assert_eq!(
        public.resolve("_dmarc.www.example.org", 16).await,
        Lookup::NoRecords
    );
    assert!(taken(&doh_asked).is_empty(), "{:?}", taken(&doh_asked));
}

#[tokio::test]
async fn up_to_three_servers_are_asked_as_the_system_does() {
    let (first, _) = stand_in_dns(|_, _| Reply::ServFail).await;
    let (second, _) = stand_in_dns(|_, _| Reply::Refused).await;
    let (third, third_asked) = stand_in_dns(|_, _| Reply::Address([192, 0, 2, 7])).await;
    let (fourth, fourth_asked) = stand_in_dns(|_, _| Reply::Address([192, 0, 2, 8])).await;
    let (doh, doh_asked) = stand_in_doh(None).await;
    let resolver = stand_in_resolver(vec![first, second, third, fourth], &doh);
    assert_eq!(
        resolver.resolve("www.example.org", 1).await,
        Lookup::Found(vec!["192.0.2.7".to_owned()])
    );
    assert_eq!(taken(&third_asked), ["1 www.example.org"]);
    assert!(taken(&fourth_asked).is_empty());
    assert!(taken(&doh_asked).is_empty());
}

#[tokio::test]
async fn a_failed_lookup_is_never_reported_as_a_missing_record() {
    // Every DNS server fails (a domain with broken DNSSEC), and so does
    // DNS-over-HTTPS.
    let (failing, _) = stand_in_dns(|_, _| Reply::ServFail).await;
    let (doh, doh_asked) = stand_in_doh_saying(2, None).await;
    let target = Target::parse("www.example.org").unwrap();
    let (observations, _, summary) = run_dns_with(
        &target,
        stand_in_resolver(vec![failing], &doh),
        (Vec::new(), Vec::new()),
        false,
    )
    .await;
    assert!(taken(&doh_asked).contains(&"AAAA www.example.org".to_owned()));
    let text = format!("{observations:?}");
    assert!(!text.contains("no AAAA record"), "{text}");
    assert!(
        observations
            .iter()
            .any(|o| matches!(o, Observation::HostMeta { ipv6_dns: None, .. })),
        "{text}"
    );
    assert!(summary.ends_with("; some DNS lookups failed"), "{summary}");
    // When DNS says there is none, that is said.
    let (nodata, _) = stand_in_dns(|_, _| Reply::NoData).await;
    let (observations, _, summary) = run_dns_with(
        &target,
        stand_in_resolver(vec![nodata], &doh),
        (Vec::new(), Vec::new()),
        false,
    )
    .await;
    assert!(format!("{observations:?}").contains("no AAAA record published"));
    assert!(!summary.contains("failed"), "{summary}");
    // An internal target: only a server that knows it may say "none".
    let internal = (vec!["192.0.2.10".to_owned()], Vec::new());
    let (observations, _, summary) = run_dns_with(
        &target,
        stand_in_resolver(vec![nodata], &doh),
        internal.clone(),
        false,
    )
    .await;
    assert!(!format!("{observations:?}").contains("no AAAA record"));
    assert!(
        summary.ends_with("; this machine's DNS server does not know the name"),
        "{summary}"
    );
    let (knows, _) = stand_in_dns(|name, _| match name {
        "www.example.org" => Reply::Address([192, 0, 2, 10]),
        _ => Reply::NoData,
    })
    .await;
    let (observations, _, _) = run_dns_with(
        &target,
        stand_in_resolver(vec![knows], &doh),
        internal,
        false,
    )
    .await;
    assert!(format!("{observations:?}").contains("no AAAA record published"));
    // An address whose PTR lookup failed has not "no PTR record".
    let address = Target::parse("192.0.2.10").unwrap();
    let ptr = |server| {
        run_dns_with(
            &address,
            stand_in_resolver(vec![server], &doh),
            (Vec::new(), Vec::new()),
            false,
        )
    };
    assert_eq!(ptr(failing).await.2, "PTR lookup failed");
    assert_eq!(ptr(nodata).await.2, "no PTR record");
}

#[tokio::test]
async fn mail_dns_ends_without_a_grade_when_no_lookup_answers() {
    // The audit's run: every question gets SERVFAIL, DoH too.
    let (failing, asked) = stand_in_dns(|_, _| Reply::ServFail).await;
    let (doh, _) = stand_in_doh_saying(2, None).await;
    let (observations, summary) = crate::maildns::run_on(
        stand_in_resolver(vec![failing], &doh),
        "pub.example.org",
        "192.0.2.10",
        &[],
        None,
    )
    .await
    .unwrap();
    assert!(observations.is_empty(), "{observations:?}");
    assert_eq!(summary, "DNS lookups failed");
    // It stopped after the first questions.
    assert_eq!(taken(&asked).len(), 3, "{:?}", taken(&asked));
    // An internal target this machine's DNS server does not know.
    let (other, _) = stand_in_dns(|_, _| Reply::NxDomain).await;
    let (observations, summary) = crate::maildns::run_on(
        stand_in_resolver(vec![other], &doh),
        "intranet.example.org",
        "10.0.0.5",
        &[],
        Some(&["10.0.0.5".to_owned()]),
    )
    .await
    .unwrap();
    assert!(observations.is_empty(), "{observations:?}");
    assert_eq!(
        summary,
        "DNS lookups failed: this machine's DNS server does not know intranet.example.org"
    );
}

#[cfg(windows)]
#[test]
fn windows_dns_servers_are_read_from_socket_addresses() {
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN,
        SOCKADDR_IN6, SOCKADDR_IN6_0,
    };
    let v4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes([192, 0, 2, 53]),
            },
        },
        sin_zero: [0; 8],
    };
    let size = |n: usize| i32::try_from(n).unwrap();
    // SAFETY: each pointer is to a live socket address at least that long.
    let read =
        |ptr: *const SOCKADDR, len: i32| unsafe { dns::windows_dns::socket_address(ptr, len) };
    let len4 = size(std::mem::size_of::<SOCKADDR_IN>());
    assert_eq!(
        read(std::ptr::from_ref(&v4).cast(), len4),
        Some("192.0.2.53:53".parse().unwrap())
    );
    assert_eq!(read(std::ptr::from_ref(&v4).cast(), 4), None);
    assert_eq!(read(std::ptr::null(), len4), None);
    let v6 = |ip: &str, scope: u32| SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: ip.parse::<Ipv6Addr>().unwrap().octets(),
            },
        },
        Anonymous: SOCKADDR_IN6_0 {
            sin6_scope_id: scope,
        },
    };
    let len6 = size(std::mem::size_of::<SOCKADDR_IN6>());
    let link = v6("fe80::53", 7);
    assert_eq!(
        read(std::ptr::from_ref(&link).cast(), len6),
        Some(SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::53".parse().unwrap(),
            53,
            0,
            7
        )))
    );
    // Windows' stand-ins for "no IPv6 DNS server" are left out.
    let placeholder = v6("fec0:0:0:ffff::1", 0);
    assert_eq!(read(std::ptr::from_ref(&placeholder).cast(), len6), None);
    // The real list: every server on port 53, none a stand-in.
    for server in dns::windows_dns::servers() {
        assert_eq!(server.port(), 53);
        assert!(!server.ip().to_string().starts_with("fec0:"), "{server}");
    }
}

/// A helper program of a probe (traceroute, openssl) is one of the
/// session's programs: when the session closes it is gone with what it
/// started, and the probe waiting for it returns at once.
#[cfg(unix)]
#[tokio::test]
async fn a_probes_program_ends_when_the_session_closes() {
    let tools = Tracker::new();
    let mut slow = tokio::process::Command::new("/bin/sh");
    slow.args(["-c", "sleep 300 & echo \"$$ $!\"; wait"]);
    configure_osint_command(&mut slow);
    let (mut child, group) = tools.spawn(&mut slow).unwrap();
    // Its first line: its own process id and that of what it started.
    let mut said = Vec::new();
    let mut stdout = child.stdout.take().unwrap();
    while !said.contains(&b'\n') {
        let mut byte = [0u8; 1];
        assert_eq!(stdout.read(&mut byte).await.unwrap(), 1, "it ended early");
        said.push(byte[0]);
    }
    child.stdout = Some(stdout);
    let pids: Vec<libc::pid_t> = String::from_utf8_lossy(&said)
        .split_whitespace()
        .map(|pid| pid.parse().unwrap())
        .collect();
    assert_eq!(pids.len(), 2);
    assert_eq!(tools.running(), 1);

    let closing = tools.clone();
    let closer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        closing.close();
    });
    let started = std::time::Instant::now();
    // Far less than the time the probe would wait for it.
    let read = wait_bounded_stdout(child, group, 4096, Duration::from_secs(60)).await;
    assert!(started.elapsed() < Duration::from_secs(10), "{read:?}");
    closer.await.unwrap();
    assert_eq!(tools.running(), 0);
    for pid in pids {
        crate::procs::tests::wait_gone(pid);
    }
    // And none starts in a session that is over.
    let mut late = tokio::process::Command::new("/bin/sh");
    late.args(["-c", "sleep 300"]);
    configure_osint_command(&mut late);
    assert!(tools.spawn(&mut late).is_err());
}

/// A shell script in `dir` named `name` that runs `body`.
#[cfg(unix)]
fn stand_in(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The process id a stand-in wrote to `file`.
#[cfg(unix)]
fn pid_in(file: &std::path::Path) -> libc::pid_t {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(pid) = std::fs::read_to_string(file)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            return pid;
        }
        assert!(std::time::Instant::now() < deadline, "no pid in {file:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A program still printing at its deadline: what it printed is kept, but
/// for the line it had not finished, and it ends with all it started.
#[cfg(unix)]
#[tokio::test]
async fn a_program_cut_off_at_its_deadline_keeps_what_it_printed() {
    let tmp = tempfile::tempdir().unwrap();
    let pid = tmp.path().join("pid");
    let script = stand_in(
        tmp.path(),
        "slow",
        &format!(
            "printf ' 1  198.51.100.1  0.5 ms\\n 2  198.51.100.2  3.1 ms\\n 3  198.51.1'\n\
             sleep 300 &\necho $! > '{}'\nwait",
            pid.display()
        ),
    );
    let tools = Tracker::new();
    let mut command = tokio::process::Command::new(&script);
    configure_osint_command(&mut command);
    let (child, group) = tools.spawn(&mut command).unwrap();
    let started = std::time::Instant::now();
    let printed = read_bounded(child, group, 4096, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(printed.timed_out);
    assert_eq!(
        printed.text,
        " 1  198.51.100.1  0.5 ms\n 2  198.51.100.2  3.1 ms\n"
    );
    crate::procs::tests::wait_gone(pid_in(&pid));
    assert_eq!(tools.running(), 0);

    // Past the size cap: whole lines only, and not "timed out".
    let mut command = tokio::process::Command::new(&script);
    configure_osint_command(&mut command);
    let (child, group) = tools.spawn(&mut command).unwrap();
    let printed = read_bounded(child, group, 30, Duration::from_secs(10))
        .await
        .unwrap();
    assert!(!printed.timed_out);
    assert_eq!(printed.text, " 1  198.51.100.1  0.5 ms\n");

    // A program that ends: all it printed.
    let quick = stand_in(tmp.path(), "quick", "printf 'one\\ntwo'");
    let mut command = tokio::process::Command::new(&quick);
    configure_osint_command(&mut command);
    let (child, group) = tools.spawn(&mut command).unwrap();
    assert_eq!(
        wait_bounded_stdout(child, group, 4096, Duration::from_secs(10)).await,
        Some("one\ntwo".to_owned())
    );
}

/// The traceroute of the audit: four hops at once, then a silent route
/// until the tool is stopped. The four hops are the route; no other tool
/// starts once the time is up.
#[cfg(unix)]
#[tokio::test]
async fn trace_keeps_the_hops_a_stalled_tool_printed() {
    let tmp = tempfile::tempdir().unwrap();
    let pid = tmp.path().join("pid");
    let stalled = stand_in(
        tmp.path(),
        "traceroute",
        &format!(
            "echo \"traceroute to $9 ($9), 15 hops max, 60 byte packets\"\n\
             echo ' 1  198.51.100.1  0.512 ms'\necho ' 2  198.51.100.2  3.120 ms'\n\
             echo ' 3  198.51.100.3  9.870 ms'\necho ' 4  198.51.100.4  12.400 ms'\n\
             echo ' 5  *'\nsleep 300 &\necho $! > '{}'\nwait",
            pid.display()
        ),
    );
    let started_file = tmp.path().join("second-started");
    let second = stand_in(
        tmp.path(),
        "tracepath",
        &format!("touch '{}'", started_file.display()),
    );
    let target: IpAddr = "203.0.113.9".parse().unwrap();
    let commands = trace_commands(&target.to_string());
    let commands = vec![
        (stalled, commands[0].1.clone()),
        (second, commands[1].1.clone()),
    ];
    let tools = Tracker::new();
    let started = std::time::Instant::now();
    let (observations, summary) = trace_with(
        &tools,
        target,
        Some("192.0.2.1"),
        &commands,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(summary, "4 intermediate hops");
    let hops = [
        "198.51.100.1",
        "198.51.100.2",
        "198.51.100.3",
        "198.51.100.4",
    ];
    let text = format!("{observations:?}");
    match &observations[0] {
        Observation::HostMeta {
            address, hops: got, ..
        } => {
            assert_eq!(address, "203.0.113.9");
            assert_eq!(got, &hops);
        }
        other => panic!("{other:?}"),
    }
    // The target did not answer: no hop, and no time, is made up for it.
    assert!(
        text.contains("route path (4 hops, target did not answer"),
        "{text}"
    );
    assert!(
        !text.contains("Target Host") && !text.contains("Hop 6"),
        "{text}"
    );
    crate::procs::tests::wait_gone(pid_in(&pid));
    assert!(
        !started_file.exists(),
        "a second tool ran after the time was up"
    );
    assert_eq!(tools.running(), 0);
}

/// A route the tool gave no hop of is not recorded: not the gateway, not
/// the target, not a time.
#[cfg(unix)]
#[tokio::test]
async fn trace_without_hops_records_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let target: IpAddr = "203.0.113.9".parse().unwrap();
    let args = trace_commands(&target.to_string())[0].1.clone();
    let tools = Tracker::new();
    for (name, body) in [
        ("silent", "exit 0"),
        ("filtered", "echo 'traceroute to 203.0.113.9'\necho ' 1  * * *'\necho ' 2  * * *'\necho ' 3  * * *'"),
        ("unreachable", "echo 'connect: Network is unreachable'\nexit 2"),
    ] {
        let program = stand_in(tmp.path(), name, body);
        let (observations, summary) = trace_with(
            &tools,
            target,
            Some("192.0.2.1"),
            &[(program, args.clone())],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(observations.is_empty(), "{name}: {observations:?}");
        assert_eq!(summary, "traceroute gave no hops", "{name}");
    }
    // None installed.
    let error = trace_with(&tools, target, None, &[], Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("not installed"), "{error:#}");
}

/// What the tool gave, and nothing else: the target's own time when it
/// answered, the local router only when it was a hop.
#[cfg(unix)]
#[tokio::test]
async fn trace_records_only_the_hops_the_tool_gave() {
    let tmp = tempfile::tempdir().unwrap();
    let target: IpAddr = "203.0.113.9".parse().unwrap();
    let args = trace_commands(&target.to_string())[0].1.clone();
    let program = stand_in(
        tmp.path(),
        "traceroute",
        "echo ' 1  198.51.100.1  0.5 ms'\necho ' 2  *'\necho ' 3  203.0.113.9  14.2 ms'",
    );
    let tools = Tracker::new();
    let (observations, summary) = trace_with(
        &tools,
        target,
        Some("192.0.2.1"),
        &[(program, args)],
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(summary, "1 intermediate hops");
    let Observation::Fact { claim, record, .. } = &observations[1] else {
        panic!("{observations:?}");
    };
    assert_eq!(
        claim,
        "route path (3 hops (14.2 ms)): 198.51.100.1 -> 203.0.113.9"
    );
    assert!(
        !record.evidence.contains("192.0.2.1"),
        "{}",
        record.evidence
    );
    assert!(!record.evidence.contains("1.5 ms"), "{}", record.evidence);
    assert_eq!(
        record.evidence.matches("Hop ").count(),
        3,
        "{}",
        record.evidence
    );
}

#[cfg(unix)]
#[test]
fn trace_tools_fit_in_the_stage_s_time() {
    let commands = trace_commands("203.0.113.9");
    let line = |at: usize| format!("{} {}", commands[at].0, commands[at].1.join(" "));
    assert_eq!(line(0), "traceroute -n -q 1 -w 1 -m 15 203.0.113.9");
    assert_eq!(line(1), "tracepath -n -m 15 203.0.113.9");
    // One 1 s probe a hop; three 1 s tries a hop.
    assert!(TRACE_TIMEOUT >= Duration::from_secs(15 * 3));
}

#[cfg(windows)]
#[test]
fn tracert_fits_in_the_stage_s_time() {
    let commands = trace_commands("203.0.113.9");
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].0, "tracert");
    assert_eq!(
        commands[0].1,
        ["-d", "-h", "15", "-w", "500", "203.0.113.9"]
    );
    // Three probes of 0.5 s for each of 15 silent hops.
    assert!(TRACE_TIMEOUT >= Duration::from_millis(15 * 3 * 500));
}

#[test]
fn reserved_ipv4_ranges_are_not_public() {
    for reserved in ["0.1.2.3", "240.0.0.7", "250.1.2.3", "255.255.255.254"] {
        assert!(is_non_public_ip(reserved.parse().unwrap()), "{reserved}");
    }
    // Both IPv6 documentation prefixes: 2001:db8::/32 and 3fff::/20.
    for documentation in ["2001:db8::7", "3fff::7", "3fff:fff:ffff::1"] {
        assert!(
            is_non_public_ip(documentation.parse().unwrap()),
            "{documentation}"
        );
    }
}

#[tokio::test]
async fn a_name_with_any_internal_address_is_internal() {
    // Whatever address comes first.
    for known in [
        &["240.0.0.7", "fd00::5"][..],
        &["fd00::5", "240.0.0.7"],
        &["2001:db8::7", "10.0.0.5"],
    ] {
        let known: Vec<String> = known.iter().map(|ip| (*ip).to_owned()).collect();
        assert!(
            is_internal_target("mixed.example.org", &known).await,
            "{known:?}"
        );
    }
}

/// The address a name's facts go on is the one nmap scans: its first IPv4
/// address, or with `-6` its first IPv6 one, whatever the text order.
#[tokio::test]
async fn the_dns_stage_records_on_the_address_the_scan_goes_to() {
    let ips = |list: &[&str]| list.iter().map(|ip| (*ip).to_owned()).collect::<Vec<_>>();
    let dual = ips(&["203.0.113.7", "203.0.113.70", "2001:db8::7", "2001:db8::70"]);
    assert_eq!(
        primary_address(&dual, false).as_deref(),
        Some("203.0.113.7")
    );
    assert_eq!(primary_address(&dual, true).as_deref(), Some("2001:db8::7"));
    let v6_only = ips(&["2001:db8::7"]);
    assert_eq!(
        primary_address(&v6_only, false).as_deref(),
        Some("2001:db8::7")
    );
    let v4_only = ips(&["203.0.113.7"]);
    assert_eq!(
        primary_address(&v4_only, true).as_deref(),
        Some("203.0.113.7")
    );
    assert_eq!(primary_address(&[], false), None);

    let (server, _) = stand_in_dns(|name, _| match name {
        "dual.example.org" => Reply::Address([203, 0, 113, 7]),
        _ => Reply::NxDomain,
    })
    .await;
    let (doh, _) = stand_in_doh(None).await;
    let target = Target::parse("dual.example.org").unwrap();
    for (ipv6, bound) in [(false, "203.0.113.7"), (true, "2001:db8::7")] {
        let (observations, found, _) = run_dns_with(
            &target,
            stand_in_resolver(vec![server], &doh),
            (ips(&["203.0.113.7"]), ips(&["2001:db8::7"])),
            ipv6,
        )
        .await;
        // In the system's order.
        assert_eq!(found, ["203.0.113.7", "2001:db8::7"]);
        let named: Vec<&str> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::Hostname {
                    address, hostname, ..
                } if hostname == "dual.example.org" => Some(address.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(named, [bound], "-6: {ipv6}");
    }
}
