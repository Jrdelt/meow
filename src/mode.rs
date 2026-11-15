//! Discovery load/rate profile shared by the CLI, `config.toml` and
//! `profile.toml`.

use std::fmt;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Ordered from the gentlest to the most active.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, ValueEnum, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Passive only: zero outbound packets (default)
    #[default]
    Light,
    /// Rate-limited active discovery
    Mild,
    /// Auto-tuned active discovery
    Aggressive,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Light => "light",
            Mode::Mild => "mild",
            Mode::Aggressive => "aggressive",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
