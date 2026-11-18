//! Certificates and TLS versions: the `tls-audit` stage.

use super::*;

// ---------------------------------------------------------------------------
// 7. TLS Audit (`tls-audit` task)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsAuditResult {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub sans: Vec<String>,
    pub supported_versions: Vec<String>,
    pub weak_ciphers: Vec<String>,
    pub raw_evidence: String,
}

/// Parses `openssl s_client` + `openssl x509 -noout -subject -issuer -dates -ext subjectAltName`
/// output into structured certificate metadata.
pub fn parse_openssl_cert_output(text: &str) -> TlsAuditResult {
    let mut out = TlsAuditResult {
        raw_evidence: sanitize(text, 1200),
        ..TlsAuditResult::default()
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("subject=") {
            out.subject = Some(sanitize(rest.trim(), 180));
        } else if let Some(rest) = trimmed.strip_prefix("issuer=") {
            out.issuer = Some(sanitize(rest.trim(), 180));
        } else if let Some(rest) = trimmed.strip_prefix("notBefore=") {
            out.not_before = Some(sanitize(rest.trim(), 64));
        } else if let Some(rest) = trimmed.strip_prefix("notAfter=") {
            out.not_after = Some(sanitize(rest.trim(), 64));
        } else if trimmed.contains("DNS:") {
            for part in trimmed.split(',') {
                if let Some(dns) = part.trim().strip_prefix("DNS:") {
                    let clean_san = sanitize(&dns.trim().to_ascii_lowercase(), 160);
                    if !clean_san.is_empty() && !out.sans.contains(&clean_san) {
                        out.sans.push(clean_san);
                    }
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("Protocol  :") {
            let proto = sanitize(rest.trim(), 32);
            if !proto.is_empty() && !out.supported_versions.contains(&proto) {
                out.supported_versions.push(proto);
            }
        } else if let Some(rest) = trimmed.strip_prefix("Cipher    :") {
            let cipher = sanitize(rest.trim(), 64);
            let upper = cipher.to_ascii_uppercase();
            if (upper.contains("RC4")
                || upper.contains("3DES")
                || upper.contains("DES-CBC3")
                || upper.contains("NULL")
                || upper.contains("EXPORT")
                || upper.contains("MD5"))
                && !out.weak_ciphers.contains(&cipher)
            {
                out.weak_ciphers.push(cipher);
            }
        }
    }
    out
}

/// Inspects the peer TLS certificate and protocol versions on `(address, port)`.
pub async fn run_tls_audit(
    address: &str,
    hostname: Option<&str>,
    port: u16,
) -> Result<(Vec<Observation>, String)> {
    let sni = hostname.unwrap_or(address);
    if address.is_empty()
        || address.starts_with('-')
        || address.chars().any(|c| c.is_control() || c.is_whitespace())
        || sni.is_empty()
        || sni.starts_with('-')
        || sni.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        bail!("invalid address or SNI for TLS audit");
    }
    let connect_target = match HostAddr::parse(address) {
        Some(HostAddr::Ip {
            addr: IpAddr::V6(v6),
            zone: Some(z),
        }) => format!("[{v6}%{z}]:{port}"),
        Some(HostAddr::Ip {
            addr: IpAddr::V6(v6),
            zone: None,
        }) => format!("[{v6}]:{port}"),
        _ => format!("{address}:{port}"),
    };

    let mut result = TlsAuditResult::default();
    let mut openssl_available = false;
    let openssl_bin = crate::tools::find_program("openssl");

    // 1. Inspect certificate + default negotiated TLS protocol via `openssl s_client`.
    if let Some(ref openssl_path) = openssl_bin {
        let mut s_client = tokio::process::Command::new(openssl_path);
        s_client.args(["s_client", "-connect", &connect_target, "-servername", sni]);
        configure_osint_command(&mut s_client);

        if let Ok(child) = s_client.spawn() {
            openssl_available = true;
            if let Some(stdout) =
                wait_bounded_stdout(child, 128 * 1024, Duration::from_secs(6)).await
            {
                result = parse_openssl_cert_output(&stdout);

                // If a PEM certificate block was returned, parse Subject/Issuer/Dates/SANs with `openssl x509`.
                if let Some(begin_idx) = stdout.find("-----BEGIN CERTIFICATE-----") {
                    let rest = &stdout[begin_idx..];
                    let end_marker = "-----END CERTIFICATE-----";
                    if let Some(end_rel) = rest.find(end_marker) {
                        let pem_block = &rest[..end_rel + end_marker.len()];
                        if pem_block.len() <= 32 * 1024 {
                            let mut x509 = tokio::process::Command::new(openssl_path);
                            x509.args([
                                "x509",
                                "-noout",
                                "-subject",
                                "-issuer",
                                "-dates",
                                "-ext",
                                "subjectAltName",
                            ]);
                            configure_osint_command(&mut x509);
                            x509.stdin(Stdio::piped());
                            if let Ok(mut xchild) = x509.spawn() {
                                if let Some(mut stdin) = xchild.stdin.take() {
                                    let _ = stdin.write_all(pem_block.as_bytes()).await;
                                }
                                if let Some(xtext) =
                                    wait_bounded_stdout(xchild, 32 * 1024, Duration::from_secs(3))
                                        .await
                                {
                                    let parsed_x509 = parse_openssl_cert_output(&xtext);
                                    if parsed_x509.subject.is_some() {
                                        result.subject = parsed_x509.subject;
                                    }
                                    if parsed_x509.issuer.is_some() {
                                        result.issuer = parsed_x509.issuer;
                                    }
                                    if parsed_x509.not_before.is_some() {
                                        result.not_before = parsed_x509.not_before;
                                    }
                                    if parsed_x509.not_after.is_some() {
                                        result.not_after = parsed_x509.not_after;
                                    }
                                    for san in parsed_x509.sans {
                                        if !result.sans.contains(&san) {
                                            result.sans.push(san);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Check TLS 1.0, 1.1, 1.2, 1.3 support if openssl is available.
    if openssl_available {
        if let Some(ref openssl_path) = openssl_bin {
            for (flag, label) in [
                ("-tls1", "TLSv1.0"),
                ("-tls1_1", "TLSv1.1"),
                ("-tls1_2", "TLSv1.2"),
                ("-tls1_3", "TLSv1.3"),
            ] {
                let mut probe = tokio::process::Command::new(openssl_path);
                probe.args([
                    "s_client",
                    "-connect",
                    &connect_target,
                    "-servername",
                    sni,
                    flag,
                ]);
                configure_osint_command(&mut probe);
                if let Ok(child) = probe.spawn() {
                    if let Some(text) =
                        wait_bounded_stdout(child, 64 * 1024, Duration::from_secs(4)).await
                    {
                        if (text.contains("BEGIN CERTIFICATE")
                            || (text.contains("Cipher is ") && !text.contains("Cipher is (NONE)")))
                            && !result.supported_versions.iter().any(|v| v == label)
                        {
                            result.supported_versions.push(label.to_owned());
                        }
                    }
                }
            }
        }
    }

    let mut observations = Vec::new();
    let ev = if result.raw_evidence.is_empty() {
        format!("TLS audit on {connect_target}")
    } else {
        result.raw_evidence.clone()
    };

    if let Some(subj) = &result.subject {
        let issuer = result.issuer.as_deref().unwrap_or("unknown");
        let valid_until = result.not_after.as_deref().unwrap_or("unknown");
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!(
                "TLS certificate Subject: {subj} (Issuer: {issuer}, NotAfter: {valid_until})"
            ),
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    for san in &result.sans {
        observations.push(Observation::TlsSan {
            address: address.to_owned(),
            port,
            san: san.clone(),
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    if !result.supported_versions.is_empty() {
        let deprecated: Vec<&str> = result
            .supported_versions
            .iter()
            .map(String::as_str)
            .filter(|v| matches!(*v, "TLSv1" | "TLSv1.0" | "TLSv1.1" | "SSLv3"))
            .collect();
        let claim = if deprecated.is_empty() {
            format!(
                "supported TLS versions: {}",
                result.supported_versions.join(", ")
            )
        } else {
            format!(
                "deprecated TLS versions supported: {} (all offered: {})",
                deprecated.join(", "),
                result.supported_versions.join(", ")
            )
        };
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim,
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    if !result.weak_ciphers.is_empty() {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!(
                "weak TLS ciphers negotiated: {}",
                result.weak_ciphers.join(", ")
            ),
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    if result.subject.is_some()
        || !result.supported_versions.is_empty()
        || !result.weak_ciphers.is_empty()
    {
        observations.push(Observation::WebMeta {
            address: address.to_owned(),
            port,
            http: Box::new(HttpInfo {
                scheme: "https".to_owned(),
                tls_subject: result.subject.clone(),
                tls_issuer: result.issuer.clone(),
                tls_not_before: result.not_before,
                tls_not_after: result.not_after,
                tls_versions: result.supported_versions.clone(),
                tls_weak_ciphers: result.weak_ciphers,
                ..HttpInfo::default()
            }),
            record: EvidenceRecord::observed(Source::TlsCert, Confidence::High, &ev),
        });
    }

    let summary = if !result.supported_versions.is_empty() {
        format!("{port}/tcp ({})", result.supported_versions.join(", "))
    } else if result.subject.is_some() {
        format!("{port}/tcp cert inspected")
    } else {
        format!("{port}/tcp no TLS details")
    };
    Ok((observations, summary))
}
