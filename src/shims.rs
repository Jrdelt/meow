//! Non-invasive per-session shell shims.
//!
//! The user's own startup files are never modified. Instead, each session
//! generates small startup files under `<workspace>/tmp/shell/` that load
//! the user's real startup files and attach hooks which:
//!
//! * append every command to `replay.sh` in two stages: `# [CWD] <dir>` and
//!   the command before it runs, `# [EXIT] <code>` once it has finished;
//! * record the current directory in `last_cwd` for the next session;
//! * refresh `$MEOW_MODE` from `profile.toml` at each prompt.
//!
//! zsh is pointed at the shim directory through `ZDOTDIR` only until its first
//! startup file has run. That file restores the user's `ZDOTDIR` at once, so
//! the system-wide files that follow (on macOS they decide where Terminal
//! keeps the shell history) and the user's own `.zshrc` see the same
//! environment as in a shell started without meow.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result};

use crate::workspace::{create_private_dir, private_open_options, write_private_atomic, Workspace};

const REPLAY_HEADER: &str = "\
# meow replay log. One entry per command:
#   # [CWD] <directory the command was started in>
#   <the command as typed>
#   # [EXIT] <exit code>   (absent if the session ended while it was running)
";

/// Shared by bash and zsh: re-read the mode from `profile.toml`.
const SH_REFRESH_MODE: &str = r##"_meow_refresh_mode() {
  local line
  [[ -r $_meow_profile ]] || return 0
  while IFS= read -r line; do
    case $line in
      'mode = "'*'"')
        line=${line#'mode = "'}
        export MEOW_MODE=${line%'"'}
        ;;
    esac
  done < "$_meow_profile"
}
"##;

/// Shared by bash and zsh: light mode cannot stop a command typed by hand,
/// but it says so before a high-rate scan starts.
const SH_RATE_WARNING: &str = r##"_meow_rate_warning() {
  [[ ${MEOW_MODE-} == light ]] || return 0
  case " $1 " in
    *nmap*' -T4 '* | *nmap*' -T5 '* | *nmap*' -A '* | *masscan* | *' --min-rate '*)
      printf '%s\n' "[meow] light mode: this command uses a high-rate scan flag. \
Run \`meow mode mild\` (or aggressive) first if that is intended." >&2
      ;;
  esac
}
"##;

const ZSH_ENV: &str = r##"# meow session shim (generated, rewritten at every session start).
# zsh reads this file because meow starts it with ZDOTDIR pointing here. The
# first thing it does is hand ZDOTDIR back, so every later startup file (the
# system's and your own) loads exactly as it does without meow. Then it loads
# your own .zshenv and, in an interactive shell, attaches the meow hooks.
if [[ -n ${MEOW_ORIG_ZDOTDIR-} ]]; then
  export ZDOTDIR=$MEOW_ORIG_ZDOTDIR
else
  unset ZDOTDIR
fi
unset MEOW_ORIG_ZDOTDIR
if [[ -f ${ZDOTDIR:-$HOME}/.zshenv ]]; then
  source "${ZDOTDIR:-$HOME}/.zshenv"
fi
if [[ -o interactive ]]; then
  source @HOOKS@
fi
"##;

const ZSH_HOOKS: &str = r##"# meow session hooks for zsh (generated).
typeset -g _meow_replay=@REPLAY@
typeset -g _meow_last_cwd=@LAST_CWD@
typeset -g _meow_profile=@PROFILE@
typeset -g _meow_pending=

@REFRESH_MODE@
@RATE_WARNING@
# Stage 1: before the command runs.
_meow_preexec() {
  local cmd=${1:-$3}
  _meow_pending=1
  _meow_rate_warning "$cmd"
  {
    print -r -- "# [CWD] $PWD"
    if [[ -z $cmd ]] || [[ -o hist_ignore_space && $cmd == ' '* ]]; then
      print -r -- '# [UNRECORDED] command kept out of the shell history'
    else
      print -r -- "$cmd"
    fi
  } 2>/dev/null >> "$_meow_replay"
}

# Stage 2: after it has finished, before the next prompt.
_meow_precmd() {
  local code=$?
  if [[ -n $_meow_pending ]]; then
    _meow_pending=
    print -r -- "# [EXIT] $code" 2>/dev/null >> "$_meow_replay"
  fi
  print -r -- "$PWD" 2>/dev/null >| "$_meow_last_cwd"
  _meow_refresh_mode
  return $code
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec _meow_preexec
add-zsh-hook precmd _meow_precmd
# Run first so $? is still the command's own exit code.
precmd_functions=(_meow_precmd ${precmd_functions:#_meow_precmd})
"##;

const BASH_RC: &str = r##"# meow session shim (generated, rewritten at every session start).
# Loads your own ~/.bashrc, then attaches the meow hooks.
if [ -f "$HOME/.bashrc" ]; then
  . "$HOME/.bashrc"
fi
. @HOOKS@
"##;

const BASH_HOOKS: &str = r##"# meow session hooks for bash (generated).
_meow_replay=@REPLAY@
_meow_last_cwd=@LAST_CWD@
_meow_profile=@PROFILE@
_meow_pending=@PENDING@
_meow_histnum=
_meow_ready=
_meow_cwd=$PWD

@REFRESH_MODE@
@RATE_WARNING@
# Sets _meow_h_num / _meow_h_cmd from the newest history entry.
_meow_history_last() {
  local entry re='^[[:space:]]*([0-9]+)[* ] (.*)$'
  _meow_h_num= _meow_h_cmd=
  entry=$(HISTTIMEFORMAT='' builtin history 1 2>/dev/null)
  if [[ $entry =~ $re ]]; then
    _meow_h_num=${BASH_REMATCH[1]}
    _meow_h_cmd=${BASH_REMATCH[2]}
  fi
}

# A command line is identified by a new history number, so duplicates must
# get one too. Lines you keep out of history (leading space) stay out and
# are logged without their text.
_meow_fix_histcontrol() {
  local item out='' IFS=:
  for item in ${HISTCONTROL-}; do
    case $item in
      ignoreboth) item=ignorespace ;;
      ignoredups | erasedups) continue ;;
    esac
    out=${out:+$out:}$item
  done
  HISTCONTROL=$out
}
[[ -n ${HISTCONTROL-} ]] && _meow_fix_histcontrol

# Stage 1 (bash 4.4+): runs from PS0, in a subshell, before the command.
_meow_preexec() {
  _meow_history_last
  _meow_rate_warning "$_meow_h_cmd"
  {
    printf '# [CWD] %s\n' "$PWD"
    if [[ -n $_meow_h_num && $_meow_h_num != "$_meow_histnum" ]]; then
      printf '%s\n' "$_meow_h_cmd"
    else
      printf '%s\n' '# [UNRECORDED] command kept out of the shell history'
    fi
  } 2>/dev/null >> "$_meow_replay"
  printf '1\n' 2>/dev/null >| "$_meow_pending"
}

# Stage 2: runs from PROMPT_COMMAND after the command has finished.
_meow_precmd() {
  local code=$?
  if [[ -s $_meow_pending ]]; then
    printf '# [EXIT] %s\n' "$code" 2>/dev/null >> "$_meow_replay"
    : 2>/dev/null >| "$_meow_pending"
  fi
  printf '%s\n' "$PWD" 2>/dev/null >| "$_meow_last_cwd"
  _meow_refresh_mode
  _meow_history_last
  _meow_histnum=$_meow_h_num
  return $code
}

# Bash older than 4.4 has no PS0: log the whole entry once the command is
# done, using the directory remembered from the previous prompt.
_meow_precmd_legacy() {
  local code=$?
  _meow_history_last
  if [[ -n $_meow_ready && -n $_meow_h_num && $_meow_h_num != "$_meow_histnum" ]]; then
    {
      printf '# [CWD] %s\n' "$_meow_cwd"
      printf '%s\n' "$_meow_h_cmd"
      printf '# [EXIT] %s\n' "$code"
    } 2>/dev/null >> "$_meow_replay"
  fi
  _meow_ready=1
  _meow_histnum=$_meow_h_num
  _meow_cwd=$PWD
  printf '%s\n' "$PWD" 2>/dev/null >| "$_meow_last_cwd"
  _meow_refresh_mode
  return $code
}

if [[ -z ${MEOW_BASH_LEGACY-} ]] &&
  ((BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4))); then
  _meow_hook=_meow_precmd
  PS0='$(_meow_preexec)'"${PS0-}"
else
  _meow_hook=_meow_precmd_legacy
fi
# Run first so $? is still the command's own exit code.
if [[ $(declare -p PROMPT_COMMAND 2>/dev/null) == 'declare -a'* ]]; then
  PROMPT_COMMAND=("$_meow_hook" "${PROMPT_COMMAND[@]}")
else
  PROMPT_COMMAND="$_meow_hook${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
fi
unset _meow_hook
"##;

const POWERSHELL_INIT: &str = r##"# meow session hooks for PowerShell (generated).
# Your profile has already been loaded by PowerShell itself. PowerShell has
# no pre-execution hook, so each entry is written when the command finishes.
$global:__meow = @{
    Replay  = @REPLAY@
    LastCwd = @LAST_CWD@
    Profile = @PROFILE@
    LastId  = 0
    Cwd     = (Get-Location).ProviderPath
    Prompt  = $function:prompt
}
$__meowLast = Get-History -Count 1
if ($__meowLast) { $global:__meow.LastId = $__meowLast.Id }
Remove-Variable __meowLast

function global:prompt {
    $ok = $?
    $code = $global:LASTEXITCODE
    try {
        $last = Get-History -Count 1
        if ($last -and $last.Id -ne $global:__meow.LastId) {
            $global:__meow.LastId = $last.Id
            $exit = if ($ok) { 0 } elseif ($code) { $code } else { 1 }
            $entry = "# [CWD] $($global:__meow.Cwd)`n$($last.CommandLine)`n# [EXIT] $exit`n"
            [System.IO.File]::AppendAllText($global:__meow.Replay, $entry)
        }
        $location = Get-Location
        if ($location.Provider.Name -eq 'FileSystem') {
            $global:__meow.Cwd = $location.ProviderPath
            [System.IO.File]::WriteAllText($global:__meow.LastCwd, "$($location.ProviderPath)`n")
        }
        foreach ($line in [System.IO.File]::ReadAllLines($global:__meow.Profile)) {
            if ($line -match '^mode = "(.+)"$') { $env:MEOW_MODE = $Matches[1] }
        }
    } catch { }
    $global:LASTEXITCODE = $code
    & $global:__meow.Prompt
}
"##;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Zsh,
    Bash,
    PowerShell,
    /// Any other shell: it runs, but without replay hooks.
    Other,
}

impl ShellKind {
    /// Classifies a shell by its program name (`/bin/zsh`, `pwsh.exe`, ...).
    pub fn detect(program: &str) -> Self {
        let name = program
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(program)
            .to_ascii_lowercase();
        match name.strip_suffix(".exe").unwrap_or(&name) {
            "zsh" => ShellKind::Zsh,
            "bash" => ShellKind::Bash,
            "pwsh" | "powershell" => ShellKind::PowerShell,
            _ => ShellKind::Other,
        }
    }
}

/// How to start the session shell so that it loads the shims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellLaunch {
    pub kind: ShellKind,
    pub args: Vec<String>,
    pub env: Vec<(String, OsString)>,
}

impl ShellLaunch {
    /// False when the shell is of a kind that cannot be hooked.
    pub fn hooked(&self) -> bool {
        self.kind != ShellKind::Other
    }
}

/// Quotes `text` as one single-quoted word for bash and zsh.
fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Quotes `text` as a single-quoted PowerShell string literal.
fn ps_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not valid UTF-8", path.display()))
}

fn ensure_replay_log(path: &Path) -> Result<()> {
    match private_open_options()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => file
            .write_all(REPLAY_HEADER.as_bytes())
            .with_context(|| format!("cannot write {}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).with_context(|| format!("cannot create {}", path.display())),
    }
}

/// Writes this session's shims for the shell `program` and returns how to
/// launch it. `original_zdotdir` is the user's own `$ZDOTDIR`, if set.
pub fn prepare(
    workspace: &Workspace,
    program: &str,
    original_zdotdir: Option<OsString>,
) -> Result<ShellLaunch> {
    let kind = ShellKind::detect(program);
    let mut launch = ShellLaunch {
        kind,
        args: Vec::new(),
        env: Vec::new(),
    };
    if kind == ShellKind::Other {
        return Ok(launch);
    }

    let dir = workspace.tmp_dir().join("shell");
    create_private_dir(&dir)?;
    ensure_replay_log(&workspace.replay_path())?;

    let quote: fn(&str) -> String = match kind {
        ShellKind::PowerShell => ps_quote,
        _ => sh_quote,
    };
    let pending = dir.join("pending");
    let hooks = dir.join(match kind {
        ShellKind::Zsh => "hooks.zsh",
        _ => "hooks.bash",
    });
    let fill = |template: &str| -> Result<String> {
        Ok(template
            .replace("@REFRESH_MODE@", SH_REFRESH_MODE)
            .replace("@RATE_WARNING@", SH_RATE_WARNING)
            .replace("@REPLAY@", &quote(utf8(&workspace.replay_path())?))
            .replace("@LAST_CWD@", &quote(utf8(&workspace.last_cwd_path())?))
            .replace("@PROFILE@", &quote(utf8(&workspace.profile_path())?))
            .replace("@PENDING@", &quote(utf8(&pending)?))
            .replace("@HOOKS@", &quote(utf8(&hooks)?)))
    };
    let write = |name: &str, template: &str| -> Result<()> {
        write_private_atomic(&dir.join(name), fill(template)?.as_bytes())
    };

    match kind {
        ShellKind::Zsh => {
            write(".zshenv", ZSH_ENV)?;
            write("hooks.zsh", ZSH_HOOKS)?;
            // Earlier versions kept ZDOTDIR here until a `.zshrc` shim had
            // run; zsh now reads the user's own `.zshrc` directly.
            match std::fs::remove_file(dir.join(".zshrc")) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    return Err(e).context("cannot remove the old .zshrc shim");
                }
                _ => {}
            }
            launch.env.push(("ZDOTDIR".to_owned(), dir.into()));
            // Always set, so a stale inherited value can never be used.
            launch.env.push((
                "MEOW_ORIG_ZDOTDIR".to_owned(),
                original_zdotdir.unwrap_or_default(),
            ));
        }
        ShellKind::Bash => {
            write("bashrc", BASH_RC)?;
            write("hooks.bash", BASH_HOOKS)?;
            write_private_atomic(&pending, b"")?;
            launch.args = vec!["--rcfile".to_owned(), utf8(&dir.join("bashrc"))?.to_owned()];
        }
        ShellKind::PowerShell => {
            write("init.ps1", POWERSHELL_INIT)?;
            launch.args = vec![
                "-NoLogo".to_owned(),
                "-NoExit".to_owned(),
                "-File".to_owned(),
                utf8(&dir.join("init.ps1"))?.to_owned(),
            ];
        }
        ShellKind::Other => {}
    }
    Ok(launch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::Mode;
    use crate::workspace::MeowHome;
    use std::fs;

    fn workspace(tmp: &tempfile::TempDir) -> Workspace {
        let home = MeowHome::at(tmp.path().join("it's home")).unwrap();
        Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light)
            .unwrap()
            .0
    }

    fn read(path: impl AsRef<Path>) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn assert_filled(text: &str) {
        for placeholder in [
            "@REFRESH_MODE@",
            "@RATE_WARNING@",
            "@REPLAY@",
            "@LAST_CWD@",
            "@PROFILE@",
            "@PENDING@",
            "@HOOKS@",
        ] {
            assert!(
                !text.contains(placeholder),
                "{placeholder} left in:\n{text}"
            );
        }
    }

    #[test]
    fn shells_are_classified_by_program_name() {
        for (program, kind) in [
            ("/bin/zsh", ShellKind::Zsh),
            ("zsh", ShellKind::Zsh),
            ("/usr/local/bin/bash", ShellKind::Bash),
            ("C:\\Program Files\\Git\\bin\\bash.exe", ShellKind::Bash),
            ("powershell.exe", ShellKind::PowerShell),
            ("PowerShell.EXE", ShellKind::PowerShell),
            (
                "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
                ShellKind::PowerShell,
            ),
            ("/usr/bin/pwsh", ShellKind::PowerShell),
            ("/bin/sh", ShellKind::Other),
            ("/usr/bin/fish", ShellKind::Other),
            ("wsl.exe", ShellKind::Other),
            ("/opt/zsh-tools/run", ShellKind::Other),
        ] {
            assert_eq!(ShellKind::detect(program), kind, "{program}");
        }
    }

    #[test]
    fn quoting_survives_awkward_paths() {
        assert_eq!(sh_quote("/a b/it's"), r"'/a b/it'\''s'");
        assert_eq!(ps_quote("C:\\it's\\$x"), "'C:\\it''s\\$x'");
    }

    #[test]
    fn unhooked_shells_get_no_files() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        let launch = prepare(&ws, "/bin/sh", None).unwrap();
        assert!(!launch.hooked());
        assert!(launch.args.is_empty() && launch.env.is_empty());
        assert!(!ws.tmp_dir().join("shell").exists());
        assert!(!ws.replay_path().exists());
    }

    #[test]
    fn bash_launch_uses_an_rcfile_with_quoted_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        let launch = prepare(&ws, "/bin/bash", None).unwrap();
        let dir = ws.tmp_dir().join("shell");
        assert!(launch.hooked() && launch.env.is_empty());
        assert_eq!(
            launch.args,
            ["--rcfile", dir.join("bashrc").to_str().unwrap()]
        );

        let rc = read(dir.join("bashrc"));
        assert!(rc.contains(r#". "$HOME/.bashrc""#));
        assert!(rc.find(".bashrc").unwrap() < rc.find("hooks.bash").unwrap());
        let hooks = read(dir.join("hooks.bash"));
        // The workspace path contains a quote and must stay one shell word.
        assert!(hooks.contains(r"it'\''s home"), "{hooks}");
        assert!(hooks.contains("PS0='$(_meow_preexec)'"));
        assert!(hooks.contains("PROMPT_COMMAND="));
        assert_filled(&hooks);
        assert_eq!(read(dir.join("pending")), "");
    }

    #[test]
    fn zsh_launch_redirects_zdotdir_and_remembers_the_original() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        let dir = ws.tmp_dir().join("shell");

        let launch = prepare(&ws, "zsh", Some("/custom/zdot".into())).unwrap();
        assert!(launch.args.is_empty());
        assert_eq!(
            launch.env,
            [
                ("ZDOTDIR".to_owned(), OsString::from(&dir)),
                ("MEOW_ORIG_ZDOTDIR".to_owned(), "/custom/zdot".into()),
            ]
        );
        let launch = prepare(&ws, "zsh", None).unwrap();
        assert_eq!(launch.env[1], ("MEOW_ORIG_ZDOTDIR".to_owned(), "".into()));

        // ZDOTDIR is handed back before anything else is loaded, and never
        // pointed at the shim directory again.
        let env = read(dir.join(".zshenv"));
        let restore = env.find("unset ZDOTDIR").unwrap();
        assert!(restore < env.find("/.zshenv").unwrap(), "{env}");
        assert!(restore < env.find("hooks.zsh").unwrap(), "{env}");
        assert_eq!(env.matches("ZDOTDIR=").count(), 1, "{env}");
        assert!(env.contains("export ZDOTDIR=$MEOW_ORIG_ZDOTDIR"), "{env}");
        assert_filled(&env);
        let hooks = read(dir.join("hooks.zsh"));
        assert!(hooks.contains("add-zsh-hook preexec _meow_preexec"));
        assert!(hooks.contains("add-zsh-hook precmd _meow_precmd"));
        assert_filled(&hooks);

        // zsh reads the user's own .zshrc; a shim left by an older version
        // is removed.
        assert!(!dir.join(".zshrc").exists());
        fs::write(dir.join(".zshrc"), "stale").unwrap();
        prepare(&ws, "zsh", None).unwrap();
        assert!(!dir.join(".zshrc").exists());
    }

    #[test]
    fn powershell_launch_runs_the_init_script_and_stays_open() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        let launch = prepare(&ws, "pwsh.exe", None).unwrap();
        let init = ws.tmp_dir().join("shell").join("init.ps1");
        assert_eq!(
            launch.args,
            ["-NoLogo", "-NoExit", "-File", init.to_str().unwrap()]
        );
        let script = read(&init);
        assert!(script.contains("function global:prompt"));
        assert!(script.contains("$global:LASTEXITCODE"));
        assert!(script.contains("it''s home"), "{script}");
        assert_filled(&script);
    }

    #[test]
    fn replay_log_gets_a_header_once_and_is_never_truncated() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        prepare(&ws, "bash", None).unwrap();
        assert_eq!(read(ws.replay_path()), REPLAY_HEADER);

        fs::write(ws.replay_path(), format!("{REPLAY_HEADER}ls\n")).unwrap();
        prepare(&ws, "zsh", None).unwrap();
        assert_eq!(read(ws.replay_path()), format!("{REPLAY_HEADER}ls\n"));
    }

    #[cfg(unix)]
    #[test]
    fn generated_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        prepare(&ws, "bash", None).unwrap();
        prepare(&ws, "zsh", None).unwrap();
        let dir = ws.tmp_dir().join("shell");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&dir), 0o700);
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            assert_eq!(mode(&path), 0o600, "{}", path.display());
        }
        assert_eq!(mode(&ws.replay_path()), 0o600);
    }
}
