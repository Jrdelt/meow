//! SSH algorithm inventory: the `ssh-audit` stage (RFC 4253 `SSH_MSG_KEXINIT`, no login).

use super::*;

// ---------------------------------------------------------------------------
// 8. SSH Audit (`ssh-audit` task — RFC 4253 `SSH_MSG_KEXINIT`)
// ---------------------------------------------------------------------------

pub const WEAK_SSH_KEX: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==",
    "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==",
];

pub const WEAK_SSH_HOST_KEYS: &[&str] = &["ssh-dss", "ssh-rsa", "ssh-dss-cert-v01@openssh.com"];

pub const WEAK_SSH_CIPHERS: &[&str] = &[
    "3des-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
];

pub const WEAK_SSH_MACS: &[&str] = &[
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKexInit {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_c2s: Vec<String>,
    pub encryption_algorithms_s2c: Vec<String>,
    pub mac_algorithms_c2s: Vec<String>,
    pub mac_algorithms_s2c: Vec<String>,
    pub compression_algorithms_c2s: Vec<String>,
    pub compression_algorithms_s2c: Vec<String>,
}

impl SshKexInit {
    /// Returns all deprecated/weak algorithms offered across KEX, host keys,
    /// ciphers, and MACs.
    pub fn weak_algorithms(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut check = |category: &str, offered: &[String], weak_list: &[&str]| {
            for alg in offered {
                if weak_list.contains(&alg.as_str()) {
                    let entry = format!("{category}:{alg}");
                    if !out.contains(&entry) {
                        out.push(entry);
                    }
                }
            }
        };
        check("kex", &self.kex_algorithms, WEAK_SSH_KEX);
        check(
            "hostkey",
            &self.server_host_key_algorithms,
            WEAK_SSH_HOST_KEYS,
        );
        check("cipher", &self.encryption_algorithms_c2s, WEAK_SSH_CIPHERS);
        check("cipher", &self.encryption_algorithms_s2c, WEAK_SSH_CIPHERS);
        check("mac", &self.mac_algorithms_c2s, WEAK_SSH_MACS);
        check("mac", &self.mac_algorithms_s2c, WEAK_SSH_MACS);
        out
    }
}

/// Parses an RFC 4253 `SSH_MSG_KEXINIT` packet from either:
/// - A full binary SSH packet (`uint32 packet_length`, `byte padding_length`,
///   `byte msg_code == 20`, 16-byte cookie, 10 `name-list`s), OR
/// - The unframed payload starting directly at `byte msg_code == 20`.
pub fn parse_ssh_kexinit(bytes: &[u8]) -> Result<SshKexInit> {
    if bytes.len() > MAX_SSH_PACKET_BYTES {
        bail!("SSH_MSG_KEXINIT exceeds {MAX_SSH_PACKET_BYTES} byte limit");
    }
    let payload = if bytes.first() == Some(&20) {
        bytes
    } else if bytes.len() >= 6 {
        let pkt_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let pad_len = bytes[4] as usize;
        if pkt_len < 2 + pad_len || pkt_len > MAX_SSH_PACKET_BYTES || 4 + pkt_len > bytes.len() {
            bail!("invalid SSH binary packet length ({pkt_len})");
        }
        let payload_end = 4 + pkt_len - pad_len;
        if payload_end <= 5 || bytes[5] != 20 {
            bail!(
                "expected SSH_MSG_KEXINIT (20), got message code {}",
                bytes.get(5).copied().unwrap_or(0)
            );
        }
        &bytes[5..payload_end]
    } else {
        bail!("SSH packet too short ({} bytes)", bytes.len());
    };

    // payload[0] == 20 (SSH_MSG_KEXINIT), payload[1..17] == 16-byte random cookie.
    if payload.len() < 17 {
        bail!("SSH_MSG_KEXINIT payload shorter than 17-byte header + cookie");
    }
    let mut offset = 17usize;
    let mut lists: Vec<Vec<String>> = Vec::with_capacity(10);
    for _ in 0..10 {
        if offset + 4 > payload.len() {
            bail!("truncated name-list length in SSH_MSG_KEXINIT");
        }
        let len = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;
        if len > MAX_SSH_PACKET_BYTES || offset + len > payload.len() {
            bail!("name-list length ({len}) exceeds SSH_MSG_KEXINIT payload bounds");
        }
        let raw = std::str::from_utf8(&payload[offset..offset + len])
            .context("non-ASCII algorithm name in SSH_MSG_KEXINIT")?;
        offset += len;
        let items: Vec<String> = raw
            .split(',')
            .map(|s| sanitize(s.trim(), 96))
            .filter(|s| !s.is_empty())
            .take(128)
            .collect();
        lists.push(items);
    }

    Ok(SshKexInit {
        kex_algorithms: lists.remove(0),
        server_host_key_algorithms: lists.remove(0),
        encryption_algorithms_c2s: lists.remove(0),
        encryption_algorithms_s2c: lists.remove(0),
        mac_algorithms_c2s: lists.remove(0),
        mac_algorithms_s2c: lists.remove(0),
        compression_algorithms_c2s: lists.remove(0),
        compression_algorithms_s2c: lists.remove(0),
    })
}

/// Connects to an SSH port, exchanges the `SSH-2.0` identification banner,
/// reads `SSH_MSG_KEXINIT` (RFC 4253), and closes the socket immediately
/// without attempting authentication.
pub async fn audit_ssh_port(address: &str, port: u16) -> Result<(Vec<Observation>, String)> {
    let connect_addr = match HostAddr::parse(address) {
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
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&connect_addr))
        .await
        .context("SSH connection timed out")?
        .with_context(|| format!("cannot connect to {connect_addr}"))?;

    // 1. Read server identification string (RFC 4253 §4.2 allows preamble lines before `SSH-`).
    let mut buf = Vec::with_capacity(256);
    let mut total_bytes = 0usize;
    let mut lines_read = 0usize;
    let mut server_banner = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while total_bytes < 4096 {
        let mut byte = [0u8; 1];
        let read_res = tokio::time::timeout_at(deadline, stream.read(&mut byte)).await;
        match read_res {
            Ok(Ok(1)) => {
                total_bytes += 1;
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    lines_read += 1;
                    let line = String::from_utf8_lossy(&buf);
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("SSH-") {
                        server_banner = sanitize(trimmed.trim_end(), 200);
                        buf.clear();
                        break;
                    }
                    buf.clear();
                    if lines_read > 16 {
                        bail!("SSH server sent too many preamble lines without SSH- banner");
                    }
                }
            }
            _ => bail!("timed out or EOF reading SSH banner"),
        }
    }
    if server_banner.is_empty() {
        bail!("no SSH- banner received from {connect_addr}");
    }

    // 2. Send client identification string and read binary packets until `SSH_MSG_KEXINIT` (20),
    // skipping optional pre-KEXINIT `SSH_MSG_IGNORE` (2) / `SSH_MSG_DEBUG` (4) packets.
    tokio::time::timeout(
        Duration::from_secs(3),
        stream.write_all(b"SSH-2.0-meow_0.2.0\r\n"),
    )
    .await
    .context("SSH banner write timed out")?
    .context("cannot write SSH client banner")?;

    let mut kex_pkt = None;
    for _ in 0..4 {
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
            .await
            .context("timed out waiting for SSH_MSG_KEXINIT")?
            .context("EOF waiting for SSH_MSG_KEXINIT")?;
        let pkt_len = u32::from_be_bytes(len_buf) as usize;
        if !(2..=MAX_SSH_PACKET_BYTES).contains(&pkt_len) {
            bail!("invalid SSH packet length {pkt_len}");
        }
        let mut pkt = vec![0u8; 4 + pkt_len];
        pkt[..4].copy_from_slice(&len_buf);
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut pkt[4..]))
            .await
            .context("timed out reading SSH packet body")?
            .context("EOF reading SSH packet body")?;
        let msg_type = pkt.get(5).copied().unwrap_or(0);
        if msg_type == 2 || msg_type == 4 {
            continue;
        }
        kex_pkt = Some(pkt);
        break;
    }

    // Drop stream immediately — zero authentication or key exchange reply sent.
    drop(stream);

    let pkt = kex_pkt.context("SSH server did not send SSH_MSG_KEXINIT")?;
    let kex = parse_ssh_kexinit(&pkt)?;
    let weak = kex.weak_algorithms();
    let ev = serde_json::json!({
        "banner": server_banner,
        "kex": kex.kex_algorithms,
        "host_key": kex.server_host_key_algorithms,
        "ciphers_c2s": kex.encryption_algorithms_c2s,
        "macs_c2s": kex.mac_algorithms_c2s,
        "weak": weak,
    })
    .to_string();

    let mut observations = Vec::new();
    observations.push(Observation::Fact {
        address: address.to_owned(),
        port: Some(port),
        protocol: "tcp".to_owned(),
        claim: format!(
            "SSH KEXINIT algorithms: {} kex, {} hostkey, {} ciphers, {} MACs (ground-truth runtime config)",
            kex.kex_algorithms.len(),
            kex.server_host_key_algorithms.len(),
            kex.encryption_algorithms_c2s.len(),
            kex.mac_algorithms_c2s.len()
        ),
        record: EvidenceRecord::observed(Source::SshKex, Confidence::High, &ev),
    });

    if !weak.is_empty() {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: format!(
                "weak/deprecated SSH algorithms offered (unaffected by distro backporting): {}",
                weak.join(", ")
            ),
            record: EvidenceRecord::observed(Source::SshKex, Confidence::High, &ev),
        });
    } else {
        observations.push(Observation::Fact {
            address: address.to_owned(),
            port: Some(port),
            protocol: "tcp".to_owned(),
            claim: "SSH KEXINIT offers only modern algorithms (no SHA-1 KEX, DSA, CBC/RC4, or MD5/SHA-1 MACs)".to_owned(),
            record: EvidenceRecord::observed(Source::SshKex, Confidence::High, &ev),
        });
    }

    let summary = if weak.is_empty() {
        format!("{port}/tcp (0 weak algorithms)")
    } else {
        format!("{port}/tcp ({} weak algorithms)", weak.len())
    };
    Ok((observations, summary))
}
