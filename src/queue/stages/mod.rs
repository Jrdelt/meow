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

    /// Whether the mode is still the one the stage started in: asked
    /// before every tool and while one runs.
    pub fn same_mode(&self) -> bool {
        running_mode(self.state, self.task) == self.mode
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
