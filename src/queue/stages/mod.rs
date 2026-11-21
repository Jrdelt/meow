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
