//! The recon stages, one function each, and what every stage is given.

use super::*;

mod passive;
mod scan;
mod web;

pub(crate) use passive::*;
pub(crate) use scan::*;
pub(crate) use web::*;

/// What every stage gets: the session, the task and its target, and the
/// settings and limits of the mode it runs in.
pub(crate) struct Ctx<'a> {
    pub state: &'a Arc<State>,
    pub task: &'a TaskRow,
    pub target: &'a Target,
    pub stage: Stage,
    pub settings: ReconSettings,
    pub mode: Mode,
    pub preset: Preset,
    pub limits: RunLimits,
    pub privileged: bool,
    tmp: PathBuf,
}

impl<'a> Ctx<'a> {
    pub fn new(
        state: &'a Arc<State>,
        task: &'a TaskRow,
        target: &'a Target,
        stage: Stage,
    ) -> Result<Self> {
        let settings = state.config.recon.clone();
        let mode = running_mode(state, task);
        let preset = settings.preset(mode, &state.profile_recon());
        validate_preset_nmap_flags(&preset.nmap_ports, &preset.nmap_services)?;
        // A stored task is only as trustworthy as the workspace's database, so
        // its flags are checked before every stage, not only when it is queued.
        validate_nmap_flags(&task.extra_flags)?;
        Ok(Self {
            state,
            task,
            target,
            stage,
            limits: settings.limits(),
            settings,
            mode,
            preset,
            privileged: is_privileged(),
            tmp: state.workspace_dir().join("tmp"),
        })
    }

    /// Whether the stage may go on: the session is open and the mode is
    /// still the one the stage started in. Asked before every tool and
    /// while one runs.
    pub fn same_mode(&self) -> bool {
        !self.state.is_closing() && running_mode(self.state, self.task) == self.mode
    }

    /// Runs one of the stage's tools until it ends, the mode changes or the
    /// session closes. What its output file says about how far it is goes
    /// through `shape`, where the stage adds what it knows itself.
    pub async fn run_tool(
        &self,
        command: &ToolCommand,
        output: OutputKind,
        shape: impl Fn(Progress) -> Progress,
    ) -> RunOutcome {
        run_tool_watched(
            command,
            self.limits,
            self.state.tools(),
            || self.same_mode(),
            output,
            |progress| self.report(shape(progress)),
        )
        .await
    }

    /// The flags the port scan runs with, the mode's preset's and then the
    /// operator's, sorted as [`split_recon_flags`] does. Their up check,
    /// DNS and address family (`shared`) hold for every nmap scan and for
    /// the address a name is scanned at.
    pub fn scan_flags(&self) -> ReconFlags {
        let mut flags = self.preset.nmap_ports.clone();
        flags.extend(self.task.extra_flags.iter().cloned());
        split_recon_flags(&flags)
    }

    /// Where the nmap scans go. For a name the dns stage resolved, its
    /// address of the family scanned (see [`Found::primary`]): the scans,
    /// the route and what the stages find about the name are then about
    /// one address, even when the name's addresses change between lookups.
    /// Otherwise the target as given.
    pub fn scan_target(&self) -> Target {
        if let Target::Host(HostAddr::Name(_)) = self.target {
            let dns = Found::load(&self.state.db_lock(), self.task.id, Stage::Dns, self.target);
            let ipv6 = self.scan_flags().ipv6();
            let primary = dns
                .primary
                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                .filter(|ip| ip.is_ipv6() == ipv6);
            if let Some(addr) = primary {
                return Target::Host(HostAddr::Ip { addr, zone: None });
            }
        }
        self.target.clone()
    }

    /// Why a scan of a name found nothing up, when the `dns` stage found
    /// this system resolves it to no address of the family scanned: no up
    /// check can help that. `None` for an address or a range, or when
    /// `dns` did not say.
    pub fn no_address(&self) -> Option<String> {
        let Target::Host(HostAddr::Name(_)) = self.target else {
            return None;
        };
        let dns = Found::saved(&self.state.db_lock(), self.task.id, Stage::Dns, self.target)?;
        let ips: Vec<std::net::IpAddr> = dns.ips.iter().filter_map(|ip| ip.parse().ok()).collect();
        let ipv6 = self.scan_flags().ipv6();
        let why = match (ips.is_empty(), dns.unresolved) {
            (true, Some(crate::osint::Unresolved::NoRecords)) => {
                "the name has no address (no A or AAAA record)"
            }
            (true, Some(crate::osint::Unresolved::Failed)) => {
                "the name did not resolve (DNS lookup failed)"
            }
            (true, Some(crate::osint::Unresolved::NotHere)) => {
                "this system does not resolve the name"
            }
            (true, None) => return None,
            _ if ips.iter().any(|ip| ip.is_ipv6() == ipv6) => return None,
            _ if ipv6 => "this system resolves the name to no IPv6 address: run again with `-- -4`",
            _ => "this system resolves the name only to IPv6 addresses: run again with `-- -6`",
        };
        Some(format!("; {why}"))
    }

    /// Says how far the stage is, for the map and the HUD.
    pub fn report(&self, progress: Progress) {
        self.state.set_progress(self.task.id, self.stage, progress);
    }

    /// Says that `done` of the stage's `total` items are handled.
    pub fn progress(&self, done: usize, total: usize) {
        self.report(Progress::items(done, total));
    }

    /// A file for this stage's tool output in the workspace's `tmp/`.
    pub fn out(&self, suffix: &str) -> PathBuf {
        self.tmp.join(format!(
            "{}_{}{suffix}",
            stage_file(self.stage),
            self.task.id
        ))
    }
}
