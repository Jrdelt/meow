//! Building the `nmap`, `katana` and `feroxbuster` commands, and checking
//! the flags an operator adds.

use super::*;

// ---------------------------------------------------------------------------
// Command builders
// ---------------------------------------------------------------------------

/// True when the process may send raw packets (root / elevated).
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // SAFETY: IsUserAnAdmin takes no arguments.
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
    }
}

const HIGH_RATE_FLAGS: &[&str] = &["-T4", "-T5", "-A"];
pub(super) const MAX_NMAP_FLAGS: usize = 32;
const SAFE_SERVICE_SCRIPTS: &[&str] = &[
    "ssl-cert",
    "http-server-header",
    "http-title",
    "ssh-hostkey",
    "banner",
];

/// nmap script categories an operator may ask for. Whatever is chosen,
/// scripts that are also in [`SCRIPT_NEVER`] do not run.
pub const SCRIPT_CATEGORIES: &[&str] = &["default", "safe", "vuln", "discovery", "version"];
/// Categories that log in, guess passwords, crash or exploit services, send
/// data to third parties or reach beyond the target.
pub(super) const SCRIPT_NEVER: &str =
    "intrusive or external or brute or dos or exploit or fuzzer or malware or broadcast";

fn is_operator_script_list(val: &str) -> bool {
    !val.is_empty()
        && val
            .split(',')
            .all(|item| SCRIPT_CATEGORIES.contains(&item) || SAFE_SERVICE_SCRIPTS.contains(&item))
}

/// The operator's flags, sorted into the stage each belongs to: port
/// choice, up check, timing and OS detection run in the port stage; version
/// detection and scripts in the service stage, on the open ports only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconFlags {
    pub ports: Vec<String>,
    pub versions: Vec<String>,
    /// Script categories and built-in script names.
    pub scripts: Vec<String>,
    /// Host-discovery, DNS, and address-family flags needed by both nmap stages.
    pub shared: Vec<String>,
}

impl ReconFlags {
    /// Whether nmap is asked for IPv6 (`-6`, unless a later `-4`): a name
    /// is then scanned at its first IPv6 address.
    pub fn ipv6(&self) -> bool {
        self.shared
            .iter()
            .rev()
            .find(|flag| *flag == "-4" || *flag == "-6")
            .is_some_and(|flag| flag == "-6")
    }
}

pub fn split_recon_flags(flags: &[String]) -> ReconFlags {
    let mut out = ReconFlags::default();
    let add_scripts = |out: &mut ReconFlags, list: &str| {
        for item in list.split(',') {
            if !out.scripts.iter().any(|known| known == item) {
                out.scripts.push(item.to_owned());
            }
        }
    };
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "-sC" => add_scripts(&mut out, "default"),
            // -A is -O -sV -sC (and a traceroute, left out).
            "-A" => {
                out.ports.push("-O".to_owned());
                add_scripts(&mut out, "default");
            }
            "--script" => {
                if let Some(list) = flags.next() {
                    add_scripts(&mut out, list);
                }
            }
            "-sV" => {} // the service stage always runs version detection
            "--version-light" | "--version-all" => out.versions.push(flag.clone()),
            "--version-intensity" => {
                out.versions.push(flag.clone());
                out.versions.extend(flags.next().cloned());
            }
            other => {
                if let Some(list) = other.strip_prefix("--script=") {
                    add_scripts(&mut out, list);
                } else if other.starts_with("--version-intensity=") {
                    out.versions.push(flag.clone());
                } else if is_scan_technique_flag(other)
                    && other[2..].contains('V')
                    && other.len() > 3
                {
                    // -sSV: the scan type stays here, V is the service stage's.
                    out.ports.push(other.replacen('V', "", 1));
                } else {
                    if is_host_probe_flag(other)
                        || matches!(other, "-n" | "-R" | "--system-dns" | "-4" | "-6")
                    {
                        out.shared.push(flag.clone());
                    }
                    out.ports.push(flag.clone());
                }
            }
        }
    }
    out
}

/// The nmap `--script` expression for the built-in scripts plus the
/// operator's choice, with the never-run categories excluded. Anything that
/// is neither a known category nor a built-in script is left out, whatever
/// the caller checked: a script file or expression never reaches nmap.
pub(super) fn script_expression(builtin: &[&str], chosen: &[String]) -> String {
    let mut names: Vec<String> = builtin.iter().map(|name| (*name).to_owned()).collect();
    let mut categories = Vec::new();
    for item in chosen {
        if SCRIPT_CATEGORIES.contains(&item.as_str()) {
            categories.push(item.as_str());
        } else if SAFE_SERVICE_SCRIPTS.contains(&item.as_str()) && !names.contains(item) {
            names.push(item.clone());
        }
    }
    let mut parts = names;
    if !categories.is_empty() {
        parts.push(format!(
            "(({}) and not ({SCRIPT_NEVER}))",
            categories.join(" or ")
        ));
    }
    parts.join(" or ")
}

/// Which of `flags` are high-rate: `-T4`, `-T5` (also written `-T 4`),
/// `-A`, and the rate and parallelism floors (`--min-rate 1000`).
pub fn high_rate_flags(flags: &[String]) -> Vec<String> {
    const FLOORS: &[&str] = &["--min-rate", "--min-parallelism", "--min-hostgroup"];
    let mut found = Vec::new();
    let mut i = 0;
    while i < flags.len() {
        let flag = flags[i].as_str();
        let value = flags.get(i + 1).map(String::as_str);
        if HIGH_RATE_FLAGS.contains(&flag) {
            found.push(flag.to_owned());
        } else if flag == "-T" && matches!(value, Some("4" | "5")) {
            found.push(format!("-T {}", value.unwrap_or_default()));
            i += 1;
        } else if FLOORS.contains(&flag) {
            found.push(
                format!("{flag} {}", value.unwrap_or_default())
                    .trim_end()
                    .to_owned(),
            );
            i += 1;
        } else if FLOORS
            .iter()
            .any(|floor| flag.starts_with(&format!("{floor}=")))
        {
            found.push(flag.to_owned());
        }
        i += 1;
    }
    found
}

fn is_port_spec(val: &str) -> bool {
    if val.is_empty() || val.len() > 256 {
        return false;
    }
    if val == "-" {
        return true;
    }
    if val.starts_with('-') {
        return false;
    }
    val.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b',' | b'-' | b':' | b'_'))
}

fn is_uint_in(val: &str, min: u32, max: u32) -> bool {
    !val.is_empty()
        && val.bytes().all(|b| b.is_ascii_digit())
        && val.parse::<u32>().is_ok_and(|n| (min..=max).contains(&n))
}

fn is_nmap_duration(val: &str) -> bool {
    let digits = val
        .strip_suffix("ms")
        .or_else(|| val.strip_suffix(['s', 'm', 'h']))
        .unwrap_or(val);
    !digits.is_empty()
        && digits.len() <= 12
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits.parse::<u64>().is_ok()
}

fn is_exclude_list(val: &str) -> bool {
    !val.is_empty()
        && val.len() <= 512
        && val.split(',').all(|item| {
            !item.is_empty()
                && (item.parse::<ipnetwork::IpNetwork>().is_ok() || HostAddr::parse(item).is_some())
        })
}

fn is_safe_service_script_list(val: &str) -> bool {
    !val.is_empty()
        && val
            .split(',')
            .all(|script| SAFE_SERVICE_SCRIPTS.contains(&script))
}

fn is_scan_technique_flag(flag: &str) -> bool {
    if matches!(flag, "-sn" | "-sP" | "-sO") {
        return true;
    }
    if !flag.starts_with("-s") || flag.starts_with("--") || !(3..=5).contains(&flag.len()) {
        return false;
    }
    let mut seen = 0u32;
    for c in flag[2..].chars() {
        if !matches!(
            c,
            'S' | 'T' | 'U' | 'A' | 'W' | 'M' | 'N' | 'F' | 'X' | 'Y' | 'Z' | 'V'
        ) {
            return false;
        }
        let bit = 1u32 << (c as u8 - b'A');
        if seen & bit != 0 {
            return false;
        }
        seen |= bit;
    }
    true
}

fn is_host_probe_flag(flag: &str) -> bool {
    if matches!(flag, "-Pn" | "-P0" | "-PE" | "-PP" | "-PM") {
        return true;
    }
    for prefix in ["-PS", "-PA", "-PU", "-PY"] {
        if flag == prefix {
            return true;
        }
        if let Some(ports) = flag.strip_prefix(prefix) {
            return !ports.starts_with('-') && is_port_spec(ports);
        }
    }
    false
}

/// `operator`: flags typed on `meow recon`, which may also choose script
/// categories (`-sC`, `-A`, `--script default`); presets from
/// `config.toml` may not.
fn validate_flags_inner(
    flags: &[String],
    allow_service_scripts: bool,
    operator: bool,
) -> Result<()> {
    if flags.len() > MAX_NMAP_FLAGS {
        bail!("too many nmap flags (at most {MAX_NMAP_FLAGS} allowed)");
    }
    let mut i = 0;
    while i < flags.len() {
        let arg = flags[i].as_str();
        if arg.is_empty() || arg.chars().any(|c| c.is_control()) {
            bail!("invalid nmap flag {arg:?}");
        }
        if !arg.starts_with('-') || arg == "-" || arg == "--" {
            bail!("unexpected nmap argument '{arg}': only safe nmap option flags are allowed");
        }

        if matches!(
            arg,
            "-O" | "-F"
                | "-r"
                | "-n"
                | "-R"
                | "-4"
                | "-6"
                | "-v"
                | "-vv"
                | "-d"
                | "-dd"
                | "-p-"
                | "--open"
                | "--reason"
                | "--system-dns"
                | "--osscan-limit"
                | "--osscan-guess"
                | "--fuzzy"
                | "--version-light"
                | "--version-all"
                | "--defeat-rst-ratelimit"
                | "--defeat-icmp-ratelimit"
                | "-T0"
                | "-T1"
                | "-T2"
                | "-T3"
                | "-T4"
                | "-T5"
        ) || (operator && matches!(arg, "-sC" | "-A"))
            || is_scan_technique_flag(arg)
            || is_host_probe_flag(arg)
        {
            i += 1;
            continue;
        }

        if let Some(inline) = arg.strip_prefix("-p") {
            if !arg.starts_with("--") {
                if inline.is_empty() {
                    let Some(val) = flags.get(i + 1).map(String::as_str) else {
                        bail!("nmap flag '-p' requires a port range");
                    };
                    if !is_port_spec(val) {
                        bail!("invalid port specification '{val}' for '-p'");
                    }
                    i += 2;
                    continue;
                } else if !inline.starts_with(|c: char| c.is_ascii_digit()) {
                    // nmap reads `-po`, `-pri` or `-pro` as shortened long
                    // options (--port-ratio, --privileged, --proxies), not
                    // as ports: the next value would become a scan target.
                    bail!(
                        "write the port list after a space: '-p {inline}' (attached to '-p' it must start with a digit)"
                    );
                } else if is_port_spec(inline) {
                    i += 1;
                    continue;
                } else {
                    bail!("invalid port specification '{inline}' in '{arg}'");
                }
            }
        }
        if arg == "-T" {
            let Some(val) = flags.get(i + 1).map(String::as_str) else {
                bail!("nmap flag '-T' requires a timing template (0-5)");
            };
            if !is_uint_in(val, 0, 5) {
                bail!("invalid timing template '{val}' for '-T' (expected 0-5)");
            }
            i += 2;
            continue;
        }

        if arg.starts_with("--") {
            let (name, inline_val) = match arg.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (arg, None),
            };
            let take_val = |i: &mut usize| -> Result<&str> {
                if let Some(v) = inline_val {
                    *i += 1;
                    Ok(v)
                } else if let Some(v) = flags.get(*i + 1).map(String::as_str) {
                    if v.is_empty() || v.chars().any(|c| c.is_control()) {
                        bail!("invalid value for nmap flag '{name}'");
                    }
                    *i += 2;
                    Ok(v)
                } else {
                    bail!("nmap flag '{name}' requires a value");
                }
            };

            match name {
                "--ports" | "--exclude-ports" => {
                    let val = take_val(&mut i)?;
                    if !is_port_spec(val) || val == "-" {
                        bail!("invalid port specification '{val}' for '{name}'");
                    }
                    continue;
                }
                "--top-ports" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 1, 65535) {
                        bail!("invalid value '{val}' for '--top-ports' (expected 1..65535)");
                    }
                    continue;
                }
                "--version-intensity" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 0, 9) {
                        bail!("invalid value '{val}' for '--version-intensity' (expected 0..9)");
                    }
                    continue;
                }
                "--max-retries" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 0, 30) {
                        bail!("invalid value '{val}' for '--max-retries' (expected 0..30)");
                    }
                    continue;
                }
                "--min-rate" | "--max-rate" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 1, 1_000_000) {
                        bail!("invalid value '{val}' for '{name}'");
                    }
                    continue;
                }
                "--min-parallelism"
                | "--max-parallelism"
                | "--min-hostgroup"
                | "--max-hostgroup" => {
                    let val = take_val(&mut i)?;
                    if !is_uint_in(val, 1, 10_000) {
                        bail!("invalid value '{val}' for '{name}'");
                    }
                    continue;
                }
                "--host-timeout"
                | "--scan-delay"
                | "--max-scan-delay"
                | "--min-rtt-timeout"
                | "--max-rtt-timeout"
                | "--initial-rtt-timeout" => {
                    let val = take_val(&mut i)?;
                    if !is_nmap_duration(val) {
                        bail!("invalid duration '{val}' for '{name}'");
                    }
                    continue;
                }
                "--exclude" => {
                    let val = take_val(&mut i)?;
                    if !is_exclude_list(val) {
                        bail!("invalid target list '{val}' for '--exclude'");
                    }
                    continue;
                }
                "--script" if allow_service_scripts => {
                    let val = take_val(&mut i)?;
                    if !is_safe_service_script_list(val) {
                        bail!(
                            "nmap '--script' in service presets may only name built-in header/TLS scripts ({})",
                            SAFE_SERVICE_SCRIPTS.join(", ")
                        );
                    }
                    continue;
                }
                "--script" if operator => {
                    let val = take_val(&mut i)?;
                    if !is_operator_script_list(val) {
                        bail!(
                            "nmap '--script' takes script categories ({}) or built-in scripts ({}); \
                             scripts that are intrusive, brute-force, denial-of-service, exploits, \
                             external or broadcast never run. For anything else run nmap yourself \
                             and import the result with `meow add`",
                            SCRIPT_CATEGORIES.join(", "),
                            SAFE_SERVICE_SCRIPTS.join(", ")
                        );
                    }
                    continue;
                }
                _ => bail!(
                    "nmap flag '{name}' is not allowed in recon (scripts, file outputs, and target files are refused)"
                ),
            }
        }

        bail!(
            "nmap flag '{arg}' is not allowed in recon (scripts, file outputs, and target files are refused)"
        );
    }
    Ok(())
}

/// Validates extra operator `nmap` flags passed to `meow recon <target> -- ...`.
pub fn validate_nmap_flags(flags: &[String]) -> Result<()> {
    validate_flags_inner(flags, false, true)
}

/// Validates `nmap_ports` and `nmap_services` preset lists from `config.toml`
/// and `profile.toml`.
pub fn validate_preset_nmap_flags(ports: &[String], services: &[String]) -> Result<()> {
    validate_flags_inner(ports, false, false).context("invalid recon nmap_ports preset")?;
    validate_flags_inner(services, true, false).context("invalid recon nmap_services preset")?;
    Ok(())
}

/// Adapts nmap flags to an unprivileged process: `-sS` (raw SYN scan)
/// becomes `-sT` (connect scan) and `-O` (OS detection) is removed, since
/// both need raw sockets. Returns the flags and a notice for each change.
pub fn adapt_for_privilege(flags: Vec<String>, privileged: bool) -> (Vec<String>, Vec<String>) {
    if privileged {
        return (flags, Vec::new());
    }
    let is_raw_tcp = |c: char| matches!(c, 'S' | 'A' | 'W' | 'M' | 'N' | 'F' | 'X' | 'Y' | 'Z');
    let to_connect = |chars: &str| -> String {
        let mut out = String::new();
        for c in chars.chars() {
            let mapped = if is_raw_tcp(c) { 'T' } else { c };
            if !out.contains(mapped) {
                out.push(mapped);
            }
        }
        out
    };
    let mut out = Vec::with_capacity(flags.len());
    let mut notices = Vec::new();
    for flag in flags {
        if flag == "-O" {
            notices.push("Not root: no OS detection (-O)".to_owned());
        } else if flag == "-sO" {
            notices.push("Not root: no IP protocol scan (-sO)".to_owned());
        } else if is_scan_technique_flag(&flag) && flag[2..].contains('U') {
            // A UDP scan needs raw sockets: nmap would refuse the whole run.
            let without_u: String = flag[2..].chars().filter(|&c| c != 'U').collect();
            let rest = to_connect(&without_u);
            notices.push(format!(
                "Not root: no UDP scan ({flag}) \u{b7} `sudo nmap -sU -oX udp.xml <target>`, \
                 then `meow add udp.xml`"
            ));
            if !rest.is_empty() {
                out.push(format!("-s{rest}"));
            }
        } else if flag.starts_with("-s")
            && !flag.starts_with("--")
            && flag[2..].chars().any(is_raw_tcp)
        {
            let replaced = format!("-s{}", to_connect(&flag[2..]));
            notices.push("Not root: connect scan instead of SYN scan".to_owned());
            out.push(replaced);
        } else {
            out.push(flag);
        }
    }
    (out, notices)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCommand {
    pub program: String,
    pub args: Vec<String>,
    pub output: PathBuf,
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// How many hosts nmap itself found up (`<hosts up="N" ...>` in its XML).
pub(super) fn nmap_hosts_up(xml: &str) -> Option<u64> {
    let at = xml.find("<hosts ")?;
    let rest = &xml[at..];
    let value = rest.split("up=\"").nth(1)?.split('"').next()?;
    value.parse().ok()
}

/// Said when nothing answered nmap's host discovery: nmap then scans no
/// ports at all, so a host that is on but ignores those probes looks absent.
pub(super) fn discovery_hint(flags: &[String]) -> String {
    if flags.iter().any(|flag| flag == "-Pn" || flag == "-P0") {
        return "; nothing answered, even scanning without the up check".to_owned();
    }
    "; nothing answered nmap's up check (ping and probes to ports 80 and 443), so no ports \
     were scanned. If the host is on, run again with `-- -Pn` to scan it anyway, or with \
     other probes such as `-- -PS22,445,3389`"
        .to_owned()
}

/// Added to every nmap command of meow's own: nmap then writes a
/// `taskprogress` element into its XML output every few seconds, which is
/// where the progress shown for a scan comes from. Not a flag an operator
/// or a preset may give (see [`validate_nmap_flags`]), so it is never there
/// twice.
pub const NMAP_STATS: [&str; 2] = ["--stats-every", "5s"];

/// Flags that say which ports to scan.
fn chooses_ports(flag: &str) -> bool {
    flag == "-F"
        || flag.starts_with("--ports")
        || flag.starts_with("--top-ports")
        || flag.starts_with("--port-ratio")
        || (flag.starts_with("-p") && !flag.starts_with("--"))
}

/// The preset's flags without its own choice of ports (`--top-ports 1000`,
/// `-p-`, `-F`). nmap applies `--top-ports` within any `-p` range, so an
/// operator's `-p-` next to the preset's `--top-ports 1000` would still
/// scan only 1,000 ports.
fn without_port_choice(flags: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(flags.len());
    let mut flags = flags.into_iter();
    while let Some(flag) = flags.next() {
        if !chooses_ports(&flag) {
            out.push(flag);
            continue;
        }
        // `-p 80`, `--ports 80`, `--top-ports 1000`, `--port-ratio 0.1` take
        // their value as the next argument; `-p-`, `-p80`, `--top-ports=1000` do not.
        if matches!(
            flag.as_str(),
            "-p" | "--ports" | "--top-ports" | "--port-ratio"
        ) {
            flags.next();
        }
    }
    out
}

/// Stage 1: port inventory.
pub fn ports_command(
    settings: &ReconSettings,
    preset: &Preset,
    target: &Target,
    extra: &[String],
    privileged: bool,
    output: &Path,
) -> (ToolCommand, Vec<String>) {
    // Ports the operator names replace the preset's choice of ports.
    let mut flags = if extra.iter().any(|flag| chooses_ports(flag)) {
        without_port_choice(preset.nmap_ports.clone())
    } else {
        preset.nmap_ports.clone()
    };
    flags.extend(extra.iter().cloned());
    let (mut args, notices) = adapt_for_privilege(flags, privileged);
    let ipv6 = match target {
        Target::Host(host) => host.ip().is_some_and(|ip| ip.is_ipv6()),
        Target::Network(network) => network.is_ipv6(),
    };
    if ipv6 && !args.iter().any(|a| a == "-6") {
        args.push("-6".to_owned());
    }
    args.extend(strings(&NMAP_STATS));
    args.extend([
        "-oX".to_owned(),
        path_arg(output),
        "--".to_owned(),
        target.to_string(),
    ]);
    (
        ToolCommand {
            program: settings.nmap.clone(),
            args,
            output: output.to_path_buf(),
        },
        notices,
    )
}

/// The UDP services worth knowing about, by port. Scanned by name rather
/// than nmap's "top ports": every one of these says something about the
/// network or is a known way in.
pub const UDP_PORTS: &str =
    "U:53,67,69,88,111,123,137,161,389,500,514,520,623,1194,1434,1900,2049,4500,5060,5353,5683,11211,51820";

/// What an open UDP service means for a test, and for the defender.
pub fn udp_note(port: u16) -> Option<&'static str> {
    Some(match port {
        53 => "DNS server: check whether it answers recursive queries for anyone (open resolver) or allows zone transfers",
        69 => "TFTP: no authentication; files can often be read by name (configs, firmware)",
        111 => "RPC portmapper: lists the RPC services (NFS, NIS) the host offers",
        123 => "NTP: check for the monlist command (amplification) and what version it reports",
        137 => "NetBIOS name service: gives away the machine and domain names",
        161 => "SNMP: v1/v2c sends its community string in the clear; default communities (public/private) can expose the whole configuration",
        389 => "CLDAP: Active Directory answers it; it can be abused for amplification",
        500 | 4500 => "IKE (IPsec VPN): the VPN gateway; aggressive mode can leak a crackable pre-shared key hash",
        514 => "Syslog: logs sent in the clear; anyone can write fake entries",
        520 => "RIP: routing protocol exposed; routes can be read or injected",
        623 => "IPMI (BMC): IPMI 2.0 hands out password hashes before login (RAKP, CVE-2013-4786); the management controller of a server",
        1194 => "OpenVPN",
        1434 => "SQL Server Browser: lists the SQL Server instances and their ports",
        1900 => "SSDP/UPnP: device discovery exposed; used for amplification",
        2049 => "NFS: check which exports are offered and to whom",
        5060 => "SIP: VoIP signalling; extensions can often be enumerated",
        5353 => "mDNS: announces the device's services and names beyond the local network",
        5683 => "CoAP (IoT): often unauthenticated device control; used for amplification",
        11211 => "memcached: no authentication by default; a large amplification source",
        51820 => "WireGuard VPN",
        67 => "DHCP server",
        88 => "Kerberos: an Active Directory domain controller or Kerberos realm",
        _ => return None,
    })
}

/// The UDP scan (aggressive mode, as root): the services in [`UDP_PORTS`]
/// on `targets`, with a light version probe to tell open from no answer.
/// `shared`: the up-check, DNS and address-family flags the port scan ran
/// with (see [`ReconFlags::shared`]).
pub fn udp_command(
    settings: &ReconSettings,
    targets: &[String],
    shared: &[String],
    ipv6: bool,
    output: &Path,
) -> ToolCommand {
    let mut args: Vec<String> = [
        "-sU",
        "-sV",
        "--version-intensity",
        "2",
        "-T4",
        "--max-retries",
        "1",
        "--host-timeout",
        "15m",
        "-p",
        UDP_PORTS,
    ]
    .iter()
    .map(|a| (*a).to_owned())
    .collect();
    for flag in shared {
        if !args.contains(flag) {
            args.push(flag.clone());
        }
    }
    if ipv6 && !args.iter().any(|a| a == "-6") {
        args.push("-6".to_owned());
    }
    args.extend(strings(&NMAP_STATS));
    args.extend(["-oX".to_owned(), path_arg(output), "--".to_owned()]);
    args.extend(targets.iter().cloned());
    ToolCommand {
        program: settings.nmap.clone(),
        args,
        output: output.to_path_buf(),
    }
}

/// Stage 2: service inventory, only on the ports stage 1 found open.
pub fn services_command(
    settings: &ReconSettings,
    preset: &Preset,
    extra: &ReconFlags,
    address: &str,
    ports: &[u16],
    privileged: bool,
    output: &Path,
) -> (ToolCommand, Vec<String>) {
    let mut flags = preset.nmap_services.clone();
    if !extra.scripts.is_empty() {
        // One --script with everything: the built-in scripts stay.
        let mut builtin: Vec<String> = Vec::new();
        let mut index = 0;
        while index < flags.len() {
            if flags[index] == "--script" && index + 1 < flags.len() {
                let list = flags.remove(index + 1);
                flags.remove(index);
                builtin.extend(list.split(',').filter(|s| !s.is_empty()).map(str::to_owned));
            } else if let Some(list) = flags[index].strip_prefix("--script=") {
                let list = list.to_owned();
                flags.remove(index);
                builtin.extend(list.split(',').filter(|s| !s.is_empty()).map(str::to_owned));
            } else {
                index += 1;
            }
        }
        let builtin_refs: Vec<&str> = builtin.iter().map(String::as_str).collect();
        flags.push("--script".to_owned());
        flags.push(script_expression(&builtin_refs, &extra.scripts));
    }
    flags.extend(extra.versions.iter().cloned());
    for shared in &extra.shared {
        if !flags.contains(shared) {
            flags.push(shared.clone());
        }
    }
    let (mut args, notices) = adapt_for_privilege(flags, privileged);
    let ipv6 = HostAddr::parse(address)
        .and_then(|h| h.ip())
        .is_some_and(|ip| ip.is_ipv6());
    if ipv6 && !args.iter().any(|a| a == "-6") {
        args.push("-6".to_owned());
    }
    let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
    args.extend(["-p".to_owned(), ports.join(",")]);
    args.extend(strings(&NMAP_STATS));
    args.extend([
        "-oX".to_owned(),
        path_arg(output),
        "--".to_owned(),
        address.to_owned(),
    ]);
    (
        ToolCommand {
            program: settings.nmap.clone(),
            args,
            output: output.to_path_buf(),
        },
        notices,
    )
}

/// Stage 3: web link and JavaScript route crawl.
pub fn crawl_command(
    settings: &ReconSettings,
    preset: &Preset,
    url: &str,
    output: &Path,
) -> ToolCommand {
    let depth = preset.katana_depth.to_string();
    let mut command = ToolCommand {
        program: settings.katana.clone(),
        args: strings(&[
            "-u",
            url,
            "-jsonl",
            "-silent",
            "-nc",
            "-jc",
            // Stay on the host being crawled. The default scope is the root
            // domain, which an IP address does not have, so links to other
            // sites (and to `localhost`) would be followed.
            "-fs",
            "fqdn",
            "-dr",
            "-ct",
            "5m",
            "-d",
            &depth,
            "-o",
            &path_arg(output),
        ]),
        output: output.to_path_buf(),
    };
    // A rate-limited mode holds the crawl to the same requests per second
    // as the directory stage; katana's own default is 150.
    if let Some(rate) = preset.ferox_rate_limit {
        command.args.extend(["-rl".to_owned(), rate.to_string()]);
    }
    command
}

/// Stage 4: directory and endpoint inventory. `--rate-limit` (with
/// `--scan-limit 1` and `--auto-bail`) and `--auto-tune` exclude each other.
pub fn dirs_command(
    settings: &ReconSettings,
    preset: &Preset,
    url: &str,
    wordlist: &Path,
    output: &Path,
) -> ToolCommand {
    let mut args = strings(&["-u", url, "--quiet", "--no-state"]);
    match preset.ferox_rate_limit {
        Some(rate) => args.extend(strings(&[
            "--rate-limit",
            &rate.to_string(),
            "--scan-limit",
            "1",
            "--auto-bail",
            "--time-limit",
            "10m",
        ])),
        None => args.extend(strings(&["--auto-tune", "--time-limit", "15m"])),
    }
    args.extend(strings(&[
        "--json",
        "-o",
        &path_arg(output),
        "-w",
        &path_arg(wordlist),
    ]));
    ToolCommand {
        program: settings.feroxbuster.clone(),
        args,
        output: output.to_path_buf(),
    }
}
