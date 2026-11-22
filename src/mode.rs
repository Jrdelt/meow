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
    /// Passive only: no packets to hosts (default)
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

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "light" => Some(Mode::Light),
            "mild" => Some(Mode::Mild),
            "aggressive" => Some(Mode::Aggressive),
            _ => None,
        }
    }
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
            .ok_or_else(|| format!("unknown mode '{s}' (expected light, mild or aggressive)"))
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
