//! The colours of meow's full-screen terminal views: the setup and the HUD.
//!
//! They follow the terminal's own theme, light or dark: text keeps the
//! terminal's foreground, and status words use its green, yellow and red.
//! meow's lime (the map's `#c8f02b`) is only ever a background under black
//! text, so it reads the same in every theme.

use ratatui::style::{Color, Modifier, Style};

/// meow's lime in the 256-colour palette (`#d7ff00`).
pub const LIME: Color = Color::Indexed(190);
/// Black that no theme remaps (the 256-colour cube's `#000000`).
pub const INK: Color = Color::Indexed(16);

/// Secondary text and idle borders: the terminal's own text colour, faint.
/// Not `DarkGray`: that is the background colour in some themes (Solarized
/// Dark), where everything drawn in it vanished.
pub const DIM: Style = Style::new().add_modifier(Modifier::DIM);
pub const GOOD: Style = Style::new().fg(Color::Green);
pub const WARN: Style = Style::new().fg(Color::Yellow);
pub const BAD: Style = Style::new().fg(Color::Red);
/// Panel titles and row labels: the text colour, bold.
pub const TITLE: Style = Style::new().add_modifier(Modifier::BOLD);
/// The border of the panel that has the keys.
pub const FOCUS: Style = Style::new().fg(Color::Green);
/// The selected row and the current step: black on lime.
pub const SELECTED: Style = Style::new().fg(INK).bg(LIME).add_modifier(Modifier::BOLD);
/// The session's name at the top: the same lime badge.
pub const BRAND: Style = SELECTED;
