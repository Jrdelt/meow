//! Non-invasive per-session shell shims.
//!
//! The user's own startup files are never modified. Instead, each session
//! generates small startup files under `<workspace>/tmp/shell/` that load
//! the user's real startup files and attach hooks which:
//!
//! * append every command to `replay.sh` in two stages: `# [CWD] <dir>` and
//!   the command before it runs, `# [EXIT] <code>` once it has finished;
//! * record the current directory in `last_cwd` for the next session;
//! * refresh `$MEOW_MODE` from `profile.toml` at each prompt;
//! * keep the shell history in a file of the workspace's own, one per
//!   shell (`zsh_history`, ...), so a session recalls only the workspace's
//!   commands and none reach your usual one. `HISTFILE` is set again at
//!   every prompt, and the file is checked like the others before the shell
//!   may write it.
//!
//! zsh is pointed at the shim directory through `ZDOTDIR` only until its first
//! startup file has run. That file restores the user's `ZDOTDIR` at once, so
//! the system-wide files that follow and the user's own `.zshrc` see the same
//! environment as in a shell started without meow. Those files may set
//! `HISTFILE`, so zsh moves to the workspace file at its first prompt.
//! A read-only `HISTFILE` is left alone in both shells.
//! `SHELL_SESSIONS_DISABLE=1` turns off macOS Terminal's per-tab history,
//! which would otherwise copy the session's commands into `~/.zsh_history`
//! or `~/.bash_history` when the shell exits.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::workspace::{
    create_private_subdir, private_open_options, write_private_atomic, Workspace,
};

const REPLAY_HEADER: &str = "\
# meow replay log. One entry per command:
#   # [CWD] <directory the command was started in>
#   <the command as typed>
#   # [EXIT] <exit code>   (absent if the session ended while it was running)
";

/// Said once when the workspace history file is gone, or was replaced by a
/// link or by a file of another account, during the session. Placed inside
/// single quotes: no `'` in it.
const HISTORY_LOST: &str =
    "[meow] The workspace history file was removed or replaced: history is no longer saved.";

/// Shared by bash and zsh: whether meow may write the file `$1`. Not a
/// link, this user's own or not there yet, in a folder of this user's: an
/// account that swapped the session's folder for its own (one it could
/// write to) gets nothing written into its files.
const SH_OURS: &str = r##"_meow_ours() {
  [[ ! -L $1 && -O ${1%/*} ]] && { [[ ! -e $1 ]] || [[ -O $1 ]]; }
}
"##;

/// Shared by bash and zsh: re-read the mode from `profile.toml`.
const SH_REFRESH_MODE: &str = r##"_meow_refresh_mode() {
  local line
  [[ -f $_meow_profile && ! -L $_meow_profile && -O $_meow_profile ]] || return 0
  while IFS= read -r line; do
    case $line in
      'mode = "'*'"')
        line=${line#'mode = "'}
        line=${line%'"'}
        case $line in
          light | mild | aggressive) export MEOW_MODE=$line ;;
        esac
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
typeset -g _meow_history=@HISTORY@
typeset -g _meow_pending=
typeset -g _meow_tty_frozen=
typeset -g _meow_history_on=
typeset -g _meow_history_lost=

@OURS@
@REFRESH_MODE@
@RATE_WARNING@
# Keeps HISTFILE on this workspace's file: sourcing a startup file again, or
# a prompt hook, may point it back at your usual one. It is exported, so a
# nested zsh or `exec zsh` keeps it unless its startup file sets another.
# A file that is gone, or was replaced by a link (a `git pull` in this
# folder) or by another account's file, is never read or written again.
# A read-only HISTFILE stays.
_meow_pin_history() {
  [[ $_meow_history_on == on && ${(t)HISTFILE-} != *readonly* ]] || return 0
  if [[ -z $_meow_history_lost && -f $_meow_history && ! -L $_meow_history && -O $_meow_history ]]; then
    [[ ${HISTFILE-} == "$_meow_history" ]] || export HISTFILE=$_meow_history
  else
    if [[ -z $_meow_history_lost ]]; then
      _meow_history_lost=1
      print -r -- '@HISTORY_LOST@' >&2
    fi
    unset HISTFILE
    SAVEHIST=0
  fi
  return 0
}

# Every startup file has run, and may have set HISTFILE. Drop it so the list
# they loaded is never written back, then start a new list on this
# workspace's own file (HISTSIZE and SAVEHIST stay yours).
_meow_start_history() {
  setopt local_options no_warn_create_global
  unset HISTFILE
  if [[ -f $_meow_history && ! -L $_meow_history && -O $_meow_history ]]; then
    fc -p "$_meow_history"
    export HISTFILE
  else
    fc -p
  fi
}

# Runs meow's prompt hook first, so $? is still the command's exit code, and
# the history pin last, after any hook of yours.
_meow_order_hooks() {
  local -a rest
  rest=(${precmd_functions[@]:+${precmd_functions[@]:#_meow_precmd}})
  rest=(${rest[@]:+${rest[@]:#_meow_pin_history}})
  precmd_functions=(_meow_precmd $rest _meow_pin_history)
}

# Stage 1: before the command runs.
_meow_preexec() {
  local cmd=${1-}
  [[ -n $cmd ]] || cmd=${3-}
  _meow_pending=1
  _meow_rate_warning "$cmd"
  _meow_ours "$_meow_replay" && {
    print -r -- "# [CWD] ${PWD//[$'\r\n']/ }"
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
  if [[ -z $_meow_tty_frozen ]]; then
    _meow_tty_frozen=1
    # Freeze the cooked tty state after startup scripts finish so a SIGKILLed
    # child program cannot leave the session shell stuck in raw mode (~ISIG).
    ttyctl -f 2>/dev/null || true
  fi
  if [[ -z $_meow_history_on ]]; then
    _meow_history_on=off
    if [[ ${(t)HISTFILE-} != *readonly* ]]; then
      _meow_history_on=on
      # fcntl locking leaves no history.LOCK link in the workspace.
      setopt hist_fcntl_lock
      _meow_start_history
      # Your own prompt hooks run after this one; from the next prompt on
      # the pin runs after them, and at this one a scheduled event does.
      zmodload zsh/sched 2>/dev/null && sched +0 _meow_pin_history
    fi
  fi
  _meow_pin_history
  if [[ ${precmd_functions[1]-} != _meow_precmd || ${precmd_functions[-1]-} != _meow_pin_history ]]; then
    _meow_order_hooks
  fi
  if [[ -n $_meow_pending ]]; then
    _meow_pending=
    _meow_ours "$_meow_replay" && print -r -- "# [EXIT] $code" 2>/dev/null >> "$_meow_replay"
  fi
  [[ $PWD == *[$'\r\n']* ]] || ! _meow_ours "$_meow_last_cwd" || print -r -- "$PWD" 2>/dev/null >| "$_meow_last_cwd"
  _meow_refresh_mode
  return $code
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec _meow_preexec
add-zsh-hook precmd _meow_precmd
# Each command line is pinned too, before it is saved: this covers `exit`.
add-zsh-hook zshaddhistory _meow_pin_history
_meow_order_hooks
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
_meow_history=@HISTORY@
_meow_history_lost=
_meow_history_fixed=

# True while HISTFILE is read-only, as some setups make it: it then stays.
_meow_histfile_fixed() {
  local flags
  flags=$(declare -p HISTFILE 2>/dev/null)
  flags=${flags#declare -}
  [[ ${flags%% *} == *r* ]]
}

# Keeps HISTFILE on this workspace's file: sourcing ~/.bashrc again may point
# it back at your usual one. It is exported, so a nested bash keeps it unless
# its startup file sets another. A file that is gone, or was replaced by a
# link (a `git pull` in this folder) or by another account's file, is never
# written: /dev/null takes it.
_meow_pin_history() {
  local file=$_meow_history
  [[ -z $_meow_history_fixed ]] || return 0
  if [[ -z $_meow_history_lost ]] && ! [[ -f $file && ! -L $file && -O $file ]]; then
    _meow_history_lost=1
    printf '%s\n' '@HISTORY_LOST@' >&2
  fi
  [[ -z $_meow_history_lost ]] || file=/dev/null
  [[ ${HISTFILE-} != "$file" ]] || return 0
  if _meow_histfile_fixed; then
    _meow_history_fixed=1
  else
    export HISTFILE=$file
  fi
}

# This session's own history. Bash reads HISTFILE by itself once this rcfile
# is done, so clearing the list here leaves exactly that file's entries.
if _meow_histfile_fixed; then
  _meow_history_fixed=1
else
  export HISTFILE=$_meow_history
  builtin history -c
fi

@OURS@
@REFRESH_MODE@
@RATE_WARNING@
# Sets _meow_h_num / _meow_h_cmd from the newest history entry without
# touching BASH_REMATCH.
_meow_history_last() {
  local entry trimmed rest
  _meow_h_num= _meow_h_cmd=
  entry=$(HISTTIMEFORMAT='' builtin history 1 2>/dev/null)
  trimmed=${entry#"${entry%%[![:space:]]*}"}
  _meow_h_num=${trimmed%%[!0-9]*}
  [[ -n $_meow_h_num ]] || return 0
  rest=${trimmed#"$_meow_h_num"}
  case $rest in
    '* '* | '  '*) _meow_h_cmd=${rest#??} ;;
    *) _meow_h_num= ;;
  esac
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
  _meow_ours "$_meow_replay" && {
    printf '# [CWD] %s\n' "${PWD//[$'\r\n']/ }"
    if [[ -n $_meow_h_num && $_meow_h_num != "$_meow_histnum" ]]; then
      printf '%s\n' "$_meow_h_cmd"
    else
      printf '%s\n' '# [UNRECORDED] command kept out of the shell history'
    fi
  } 2>/dev/null >> "$_meow_replay"
  _meow_ours "$_meow_pending" && printf '1\n' 2>/dev/null >| "$_meow_pending"
}

# Stage 2: runs from PROMPT_COMMAND after the command has finished.
_meow_precmd() {
  local code=$?
  _meow_pin_history
  if [[ -f $_meow_pending && ! -L $_meow_pending && -O $_meow_pending && -s $_meow_pending ]]; then
    _meow_ours "$_meow_replay" && printf '# [EXIT] %s\n' "$code" 2>/dev/null >> "$_meow_replay"
    : 2>/dev/null >| "$_meow_pending"
  fi
  [[ $PWD == *[$'\r\n']* ]] || ! _meow_ours "$_meow_last_cwd" || printf '%s\n' "$PWD" 2>/dev/null >| "$_meow_last_cwd"
  _meow_refresh_mode
  _meow_history_last
  _meow_histnum=$_meow_h_num
  return $code
}

# Bash older than 4.4 has no PS0: log the whole entry once the command is
# done, using the directory remembered from the previous prompt.
_meow_precmd_legacy() {
  local code=$?
  _meow_pin_history
  _meow_history_last
  if [[ -n $_meow_ready && -n $_meow_h_num && $_meow_h_num != "$_meow_histnum" ]]; then
    _meow_ours "$_meow_replay" && {
      printf '# [CWD] %s\n' "${_meow_cwd//[$'\r\n']/ }"
      printf '%s\n' "$_meow_h_cmd"
      printf '# [EXIT] %s\n' "$code"
    } 2>/dev/null >> "$_meow_replay"
  fi
  _meow_ready=1
  _meow_histnum=$_meow_h_num
  _meow_cwd=$PWD
  [[ $PWD == *[$'\r\n']* ]] || ! _meow_ours "$_meow_last_cwd" || printf '%s\n' "$PWD" 2>/dev/null >| "$_meow_last_cwd"
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
# Run first so $? is still the command's own exit code. The history pin
# runs again last, after your own prompt commands.
if [[ $(declare -p PROMPT_COMMAND 2>/dev/null) == 'declare -a'* ]]; then
  PROMPT_COMMAND=("$_meow_hook" "${PROMPT_COMMAND[@]}" _meow_pin_history)
else
  PROMPT_COMMAND="$_meow_hook${PROMPT_COMMAND:+; $PROMPT_COMMAND
}${PROMPT_COMMAND:+_meow_pin_history}"
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
    LastErr = $(if ($global:Error.Count -gt 0) { $global:Error[0] } else { $null })
    Utf8    = (New-Object System.Text.UTF8Encoding $false)
    Cwd     = (Get-Location).ProviderPath
    Prompt  = $function:prompt
    History = $null
}
$__meowLast = Get-History -Count 1
if ($__meowLast) { $global:__meow.LastId = $__meowLast.Id }
Remove-Variable __meowLast
# Up-arrow and Ctrl-R recall only this workspace's commands.
if (Get-Module PSReadLine) {
    try {
        Set-PSReadLineOption -HistorySavePath @HISTORY@
        $global:__meow.History = @HISTORY@
    } catch { }
}

function global:prompt {
    $ok = $?
    $code = $global:LASTEXITCODE
    try {
        $isSafeTarget = {
            param([string]$p)
            if ([System.IO.File]::Exists($p) -or [System.IO.Directory]::Exists($p)) {
                $attr = [System.IO.File]::GetAttributes($p)
                return -not ($attr -band [System.IO.FileAttributes]::ReparsePoint) -and -not ($attr -band [System.IO.FileAttributes]::Directory)
            }
            return $true
        }
        # A history file replaced by a link (a `git pull` in this folder) is
        # never written.
        if ($global:__meow.History -and -not (& $isSafeTarget $global:__meow.History)) {
            $global:__meow.History = $null
            try { Set-PSReadLineOption -HistorySaveStyle SaveNothing } catch { }
            [Console]::Error.WriteLine('@HISTORY_LOST@')
        }
        $errTop = if ($global:Error.Count -gt 0) { $global:Error[0] } else { $null }
        $newErr = $errTop -and -not [object]::ReferenceEquals($errTop, $global:__meow.LastErr)
        $global:__meow.LastErr = $errTop
        $last = Get-History -Count 1
        if ($last -and $last.Id -ne $global:__meow.LastId) {
            $global:__meow.LastId = $last.Id
            $exit = if ($ok) {
                0
            } elseif ($newErr -and $errTop.FullyQualifiedErrorId -ne 'NativeCommandError') {
                1
            } elseif ($code) {
                $code
            } else {
                1
            }
            $cleanCwd = ($global:__meow.Cwd -replace "[\r\n]+", " ")
            $recordedCmd = if ($last.CommandLine -match '^\s') {
                '# [UNRECORDED] command kept out of the shell history'
            } else {
                $last.CommandLine
            }
            $entry = "# [CWD] $cleanCwd`n$recordedCmd`n# [EXIT] $exit`n"
            if (& $isSafeTarget $global:__meow.Replay) {
                [System.IO.File]::AppendAllText($global:__meow.Replay, $entry, $global:__meow.Utf8)
            }
        }
        $location = Get-Location
        if ($location.Provider.Name -eq 'FileSystem') {
            $global:__meow.Cwd = $location.ProviderPath
            if ($location.ProviderPath -notmatch "[\r\n]" -and (& $isSafeTarget $global:__meow.LastCwd)) {
                [System.IO.File]::WriteAllText($global:__meow.LastCwd, "$($location.ProviderPath)`n", $global:__meow.Utf8)
            }
        }
        $profInfo = New-Object System.IO.FileInfo($global:__meow.Profile)
        if ($profInfo.Exists -and -not ($profInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and $profInfo.Length -le 65536) {
            foreach ($line in [System.IO.File]::ReadAllLines($global:__meow.Profile, $global:__meow.Utf8)) {
                if ($line -match '^mode = "(light|mild|aggressive)"$') { $env:MEOW_MODE = $Matches[1] }
            }
        }
    } catch { }
    $global:LASTEXITCODE = $code
    & $global:__meow.Prompt
}
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Undefined -Force -ErrorAction SilentlyContinue
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
        match program_name(program).as_str() {
            "zsh" => ShellKind::Zsh,
            "bash" => ShellKind::Bash,
            "pwsh" | "powershell" => ShellKind::PowerShell,
            _ => ShellKind::Other,
        }
    }
}

/// `/usr/bin/zsh` -> `zsh`, `C:\...\pwsh.exe` -> `pwsh`.
fn program_name(program: &str) -> String {
    let name = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    match name.strip_suffix(".exe") {
        Some(stem) => stem.to_owned(),
        None => name,
    }
}

/// The fish history session for the workspace in `dir`. fish keeps it in
/// its own data folder, so the name comes from a hash of the workspace
/// folder: one list per workspace, never shared by two.
fn fish_history_name(dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let dir = resolved(dir);
    let digest = Sha256::digest(dir.as_os_str().as_encoded_bytes());
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("meow_{hex}")
}

/// `dir` with links resolved; for one that is gone (a session folder that
/// was moved), as far as it is still there.
fn resolved(dir: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(dir) {
        return real;
    }
    for base in dir.ancestors().skip(1) {
        if let Ok(real) = std::fs::canonicalize(base) {
            let rest = dir.strip_prefix(base).unwrap_or(dir);
            if rest
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
            {
                return real.join(rest);
            }
            break;
        }
    }
    dir.to_path_buf()
}

/// fish's data folder: `$XDG_DATA_HOME/fish`, else `~/.local/share/fish`.
fn fish_data() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| dirs::home_dir().map(|home| home.join(".local").join("share")))
}

/// The file fish keeps that history in, in its data folder.
pub fn fish_history_file(dir: &Path) -> Option<PathBuf> {
    Some(fish_history_in(&fish_data()?, dir))
}

fn fish_history_in(data: &Path, dir: &Path) -> PathBuf {
    data.join("fish")
        .join(format!("{}_history", fish_history_name(dir)))
}

/// Removes fish's history of the workspace in `dir`: a workspace made anew
/// in the same place must not inherit it.
pub fn forget_fish_history(dir: &Path) {
    if let Some(file) = fish_history_file(dir) {
        let _ = std::fs::remove_file(file);
    }
}

/// Gives the session the user moved from `old` to `new` the history fish
/// kept for it there. Without one, a list fish kept for an earlier
/// workspace in the new place is dropped: it is not this one's.
pub fn move_fish_history(old: &Path, new: &Path) {
    if let Some(data) = fish_data() {
        move_fish_history_in(&data, old, new);
    }
}

fn move_fish_history_in(data: &Path, old: &Path, new: &Path) {
    let (from, to) = (fish_history_in(data, old), fish_history_in(data, new));
    if from != to && std::fs::rename(&from, &to).is_err() {
        let _ = std::fs::remove_file(&to);
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

/// Quotes `text` as a single-quoted PowerShell string literal, doubling both
/// ASCII `'` and the Unicode single-quote characters PowerShell's lexer treats
/// as string delimiters.
fn ps_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for ch in text.chars() {
        if matches!(ch, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            out.push(ch);
            out.push(ch);
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not valid UTF-8", path.display()))
}

/// Makes sure `path` is a private regular file of its own, creating it with
/// `initial` as its content when missing. An existing file is never
/// truncated. `what` names it in errors.
fn ensure_private_file(path: &Path, initial: &[u8], what: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                anyhow::bail!(
                    "{} is a symbolic link; refusing to write {what}",
                    path.display()
                );
            }
            if !meta.is_file() {
                anyhow::bail!(
                    "{} is not a regular file; refusing to write {what}",
                    path.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if meta.nlink() > 1 {
                    anyhow::bail!(
                        "{} has multiple hard links; refusing to write {what}",
                        path.display()
                    );
                }
                let file = private_open_options()
                    .write(true)
                    .open(path)
                    .with_context(|| format!("cannot open {}", path.display()))?;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("cannot set permissions on {}", path.display()))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut file = private_open_options()
                .write(true)
                .create_new(true)
                .open(path)
                .with_context(|| format!("cannot create {}", path.display()))?;
            file.write_all(initial)
                .with_context(|| format!("cannot write {}", path.display()))
        }
        Err(e) => Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

/// Replaces each `@NAME@` in `template` with its value in `values`, in one
/// pass: a value is never searched again, so a path that holds `@HISTORY@`
/// stays inside its quotes. Any other `@` is kept as it is.
fn fill_template(template: &str, values: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(template.len() + 4096);
    let mut rest = template;
    while let Some(at) = rest.find('@') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let found = after.find('@').and_then(|end| {
            let name = &after[..end];
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (end, value))
        });
        match found {
            Some((end, value)) => {
                out.push_str(value);
                rest = &after[end + 1..];
            }
            None => {
                out.push('@');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// macOS Terminal's `/etc/zshrc_Apple_Terminal` and `/etc/bashrc_Apple_Terminal`
/// give each tab its own history file and merge it into `~/.zsh_history` or
/// `~/.bash_history` on exit. The session shell shares the outer tab's
/// `TERM_SESSION_ID`, so it would also write into that tab's restore files.
fn no_terminal_sessions() -> (String, OsString) {
    ("SHELL_SESSIONS_DISABLE".to_owned(), "1".into())
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
        if program_name(program) == "fish" {
            // fish gets no hooks, but keeps a history of its own under this
            // name, in fish's data folder (see `fish_history_file`).
            launch.env.push((
                "fish_history".to_owned(),
                fish_history_name(&workspace.dir).into(),
            ));
        }
        return Ok(launch);
    }

    let dir = workspace.tmp_dir().join("shell");
    create_private_subdir(&workspace.tmp_dir())?;
    create_private_subdir(&dir)?;
    ensure_private_file(
        &workspace.replay_path(),
        REPLAY_HEADER.as_bytes(),
        "replay log",
    )?;
    let history = workspace.history_path(match kind {
        ShellKind::Zsh => "zsh",
        ShellKind::Bash => "bash",
        _ => "powershell",
    });
    ensure_private_file(&history, b"", "shell history")?;

    let quote: fn(&str) -> String = match kind {
        ShellKind::PowerShell => ps_quote,
        _ => sh_quote,
    };
    let pending = dir.join("pending");
    let hooks = dir.join(match kind {
        ShellKind::Zsh => "hooks.zsh",
        _ => "hooks.bash",
    });
    let values = [
        ("OURS", SH_OURS.to_owned()),
        ("REFRESH_MODE", SH_REFRESH_MODE.to_owned()),
        ("RATE_WARNING", SH_RATE_WARNING.to_owned()),
        ("HISTORY_LOST", HISTORY_LOST.to_owned()),
        ("REPLAY", quote(utf8(&workspace.replay_path())?)),
        ("LAST_CWD", quote(utf8(&workspace.last_cwd_path())?)),
        ("PROFILE", quote(utf8(&workspace.profile_path())?)),
        ("HISTORY", quote(utf8(&history)?)),
        ("PENDING", quote(utf8(&pending)?)),
        ("HOOKS", quote(utf8(&hooks)?)),
    ];
    let fill = |template: &str| -> Result<String> { Ok(fill_template(template, &values)) };
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
            launch.env.push(no_terminal_sessions());
        }
        ShellKind::Bash => {
            write("bashrc", BASH_RC)?;
            write("hooks.bash", BASH_HOOKS)?;
            write_private_atomic(&pending, b"")?;
            launch.args = vec!["--rcfile".to_owned(), utf8(&dir.join("bashrc"))?.to_owned()];
            launch.env.push(no_terminal_sessions());
        }
        ShellKind::PowerShell => {
            // Windows PowerShell 5.1 parses BOM-less .ps1 files in the legacy
            // ANSI codepage; prepending a UTF-8 BOM preserves non-ASCII paths.
            let mut content = vec![0xEF, 0xBB, 0xBF];
            content.extend_from_slice(fill(POWERSHELL_INIT)?.as_bytes());
            write_private_atomic(&dir.join("init.ps1"), &content)?;
            launch.args = vec![
                "-NoLogo".to_owned(),
                "-NoExit".to_owned(),
                "-ExecutionPolicy".to_owned(),
                "Bypass".to_owned(),
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
    use crate::workspace::{MeowHome, HISTORY_SHELLS};
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
            "@OURS@",
            "@REFRESH_MODE@",
            "@RATE_WARNING@",
            "@REPLAY@",
            "@LAST_CWD@",
            "@PROFILE@",
            "@PENDING@",
            "@HOOKS@",
            "@HISTORY@",
            "@HISTORY_LOST@",
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
        assert_eq!(
            ps_quote("C:\\bob\u{2019}s\\$(calc)"),
            "'C:\\bob\u{2019}\u{2019}s\\$(calc)'"
        );
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
        for shell in HISTORY_SHELLS {
            assert!(!ws.history_path(shell).exists(), "{shell}");
        }
    }

    #[test]
    fn fish_gets_a_history_of_its_own_and_no_files() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        let launch = prepare(&ws, "/usr/bin/fish", None).unwrap();
        assert!(!launch.hooked() && launch.args.is_empty());
        let name = fish_history_name(&ws.dir);
        assert_eq!(
            launch.env,
            [("fish_history".to_owned(), name.clone().into())]
        );
        assert!(!ws.tmp_dir().join("shell").exists());
        for shell in HISTORY_SHELLS {
            assert!(!ws.history_path(shell).exists(), "{shell}");
        }

        // fish accepts only letters, digits and `_`. The name is the same
        // for every path of one folder, and differs for names that look
        // alike, and for the same name in another folder.
        assert!(name.starts_with("meow_") && name.len() == 21, "{name}");
        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        assert_eq!(fish_history_name(&ws.dir.join("tmp").join("..")), name);
        let names: std::collections::HashSet<String> = ["web-01", "web_01", "web.01"]
            .iter()
            .map(|n| fish_history_name(&tmp.path().join(n)))
            .chain([fish_history_name(&tmp.path().join("other").join("acme"))])
            .chain([name.clone()])
            .collect();
        assert_eq!(names.len(), 5);
        assert_eq!(
            fish_history_in(Path::new("/data"), &ws.dir),
            Path::new("/data/fish").join(format!("{name}_history"))
        );
    }

    /// fish keeps a session's history by its folder's path: a session
    /// the user moved takes its list along, and none left at the new
    /// place by an earlier one.
    #[cfg(unix)]
    #[test]
    fn a_moved_session_keeps_its_fish_history() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        fs::create_dir_all(data.join("fish")).unwrap();
        // Named through a link, as a folder typed at the prompt may be.
        let real = tmp.path().join("real");
        fs::create_dir_all(real.join("proj/meow/acme")).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let old = link.join("proj/meow/acme");
        let name = fish_history_name(&old);
        fs::write(fish_history_in(&data, &old), "- cmd: echo mine\n").unwrap();
        fs::rename(real.join("proj"), real.join("moved")).unwrap();
        // Gone, it has the name it had.
        assert_eq!(fish_history_name(&old), name);
        let real_proj = fs::canonicalize(&real).unwrap().join("proj/meow/acme");
        assert_eq!(resolved(&old), real_proj);
        // `..` in what is gone is not guessed at.
        assert_eq!(resolved(&link.join("x/../y")), link.join("x/../y"));
        let new = real.join("moved/meow/acme");
        assert_ne!(fish_history_name(&new), name);
        // Another session's list there before.
        fs::write(fish_history_in(&data, &new), "- cmd: theirs\n").unwrap();
        move_fish_history_in(&data, &old, &new);
        assert!(!fish_history_in(&data, &old).exists());
        assert_eq!(
            fs::read_to_string(fish_history_in(&data, &new)).unwrap(),
            "- cmd: echo mine\n"
        );
        // Moved again with no list of its own: the one there goes.
        let again = tmp.path().join("again/meow/acme");
        fs::create_dir_all(&again).unwrap();
        fs::write(fish_history_in(&data, &again), "- cmd: theirs\n").unwrap();
        move_fish_history_in(&data, &old, &again);
        assert!(!fish_history_in(&data, &again).exists());
    }

    #[test]
    fn each_shell_has_a_history_file_of_its_own() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        for (program, shell, file) in [
            ("zsh", "zsh", "hooks.zsh"),
            ("bash", "bash", "hooks.bash"),
            ("pwsh", "powershell", "init.ps1"),
        ] {
            prepare(&ws, program, None).unwrap();
            let text = read(ws.tmp_dir().join("shell").join(file));
            let path = ws.history_path(shell);
            assert!(path.ends_with(format!("{shell}_history")));
            assert_eq!(read(&path), "");
            let quoted = match shell {
                "powershell" => ps_quote(path.to_str().unwrap()),
                _ => sh_quote(path.to_str().unwrap()),
            };
            assert!(text.contains(&quoted), "{text}");
            for other in HISTORY_SHELLS.iter().filter(|other| **other != shell) {
                let other = format!("{other}_history");
                assert!(!text.contains(&other), "{other} in:\n{text}");
            }
        }
    }

    /// A path that holds a placeholder's text stays inside its quotes: the
    /// values are filled in one pass.
    #[test]
    fn placeholders_in_paths_are_not_filled_again() {
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join("home")).unwrap();
        let made = Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Light)
            .unwrap()
            .0;
        // meow refuses to open a session at such a path; the hooks must
        // still keep it one quoted word.
        let odd = tmp.path().join("p@HISTORY@$(touch x)@HOOKS@'@REPLAY@");
        fs::rename(&made.dir, &odd).unwrap();
        let ws = Workspace { dir: odd, ..made };
        prepare(&ws, "bash", None).unwrap();
        let hooks = read(ws.tmp_dir().join("shell").join("hooks.bash"));
        let line =
            |name: &str, path: &Path| format!("\n{name}={}\n", sh_quote(path.to_str().unwrap()));
        assert!(
            hooks.contains(&line("_meow_replay", &ws.replay_path())),
            "{hooks}"
        );
        assert!(
            hooks.contains(&line("_meow_history", &ws.history_path("bash"))),
            "{hooks}"
        );
        // Inside quotes the path's own `'` is written as `'\''`.
        let dir = ws.dir.to_str().unwrap().replace('\'', r"'\''");
        assert_filled(&hooks.replace(&dir, ""));
        let rc = read(ws.tmp_dir().join("shell").join("bashrc"));
        let hooks_path = ws.tmp_dir().join("shell").join("hooks.bash");
        assert!(
            rc.contains(&format!(". {}\n", sh_quote(hooks_path.to_str().unwrap()))),
            "{rc}"
        );

        prepare(&ws, "pwsh", None).unwrap();
        let script = read(ws.tmp_dir().join("shell").join("init.ps1"));
        let replay = ps_quote(ws.replay_path().to_str().unwrap());
        assert!(
            script.contains(&format!("Replay  = {replay}\n")),
            "{script}"
        );

        // Only names it knows are filled; any other `@` stays.
        let values = [("A", "1".to_owned()), ("B", "@A@".to_owned())];
        assert_eq!(
            fill_template("x@A@y@B@ @C@ a@b [@] @A", &values),
            "x1y@A@ @C@ a@b [@] @A"
        );
    }

    #[test]
    fn bash_launch_uses_an_rcfile_with_quoted_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        let launch = prepare(&ws, "/bin/bash", None).unwrap();
        let dir = ws.tmp_dir().join("shell");
        assert!(launch.hooked());
        assert_eq!(
            launch.env,
            [("SHELL_SESSIONS_DISABLE".to_owned(), "1".into())]
        );
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

        // The history moves to the workspace file and the list is emptied;
        // bash loads that file by itself after the rcfile, exactly once.
        // Not when HISTFILE is read-only.
        let history = format!(
            "\n_meow_history={}\n",
            sh_quote(ws.history_path("bash").to_str().unwrap())
        );
        let start = &hooks[hooks.find(&history).expect(&hooks)..];
        let start = &start[start.find("\nif _meow_histfile_fixed; then\n").unwrap()..];
        let set = start.find("  export HISTFILE=$_meow_history\n").unwrap();
        assert!(
            set < start.find("  builtin history -c\n").unwrap(),
            "{hooks}"
        );
        assert!(!hooks.contains("history -r"), "{hooks}");
        assert_eq!(read(ws.history_path("bash")), "");

        // Every prompt sets it again, or moves it to /dev/null once the
        // file is gone or a link.
        for hook in ["_meow_precmd() {", "_meow_precmd_legacy() {"] {
            let body = &hooks[hooks.find(hook).unwrap()..];
            assert!(
                body.starts_with(&format!("{hook}\n  local code=$?\n  _meow_pin_history\n")),
                "{hooks}"
            );
        }
        let pin = &hooks[hooks.find("_meow_pin_history() {").unwrap()..];
        assert!(
            pin.contains("! [[ -f $file && ! -L $file && -O $file ]]"),
            "{hooks}"
        );
        assert!(pin.contains("file=/dev/null"), "{hooks}");
        assert!(pin.contains(HISTORY_LOST), "{hooks}");
        // ... and again after your own prompt commands.
        assert!(
            hooks.contains("(\"$_meow_hook\" \"${PROMPT_COMMAND[@]}\" _meow_pin_history)"),
            "{hooks}"
        );
        assert!(
            hooks.contains("; $PROMPT_COMMAND\n}${PROMPT_COMMAND:+_meow_pin_history}\""),
            "{hooks}"
        );
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
                ("SHELL_SESSIONS_DISABLE".to_owned(), "1".into()),
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
        assert!(hooks.contains("ttyctl -f"));
        assert_filled(&hooks);

        // The startup files set HISTFILE after the hooks are sourced, so the
        // switch happens once, in the first precmd. The list they loaded is
        // left without a file and never saved back. A read-only HISTFILE
        // stays.
        let quoted = sh_quote(ws.history_path("zsh").to_str().unwrap());
        assert!(
            hooks.contains(&format!("typeset -g _meow_history={quoted}\n")),
            "{hooks}"
        );
        let start = &hooks[hooks.find("_meow_start_history() {").unwrap()..];
        let unset = start.find("unset HISTFILE\n").unwrap();
        let push = start.find("fc -p \"$_meow_history\"\n").unwrap();
        assert!(unset < push, "{hooks}");
        assert!(start[push..].starts_with("fc -p \"$_meow_history\"\n    export HISTFILE\n"));
        assert!(!hooks.contains("fc -p -a"), "{hooks}");
        let precmd = &hooks[hooks.find("_meow_precmd() {").unwrap()..];
        let once = precmd.find("if [[ -z $_meow_history_on ]]").unwrap();
        let free = precmd
            .find("if [[ ${(t)HISTFILE-} != *readonly* ]]")
            .unwrap();
        let lock = precmd.find("setopt hist_fcntl_lock\n").unwrap();
        let switch = precmd.find("_meow_start_history\n").unwrap();
        assert!(once < free && free < lock && lock < switch, "{hooks}");

        // Then HISTFILE is set again at every prompt, after your own prompt
        // hooks too (a scheduled event at the first prompt), and before
        // each line is saved.
        let sched = precmd.find("sched +0 _meow_pin_history\n").unwrap();
        assert!(switch < sched, "{hooks}");
        assert!(
            precmd.find("\n  _meow_pin_history\n").unwrap() > sched,
            "{hooks}"
        );
        assert!(
            hooks.contains("precmd_functions=(_meow_precmd $rest _meow_pin_history)"),
            "{hooks}"
        );
        assert!(hooks.contains("add-zsh-hook zshaddhistory _meow_pin_history\n"));
        assert!(hooks.ends_with("_meow_order_hooks\n"), "{hooks}");
        let pin = &hooks[hooks.find("_meow_pin_history() {").unwrap()..];
        let pin = &pin[..pin.find("\n}\n").unwrap()];
        assert!(pin.contains("export HISTFILE=$_meow_history"), "{pin}");
        assert!(pin.contains("unset HISTFILE\n    SAVEHIST=0"), "{pin}");
        assert!(pin.ends_with("return 0"), "{pin}");

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
            [
                "-NoLogo",
                "-NoExit",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                init.to_str().unwrap()
            ]
        );
        let bytes = fs::read(&init).unwrap();
        assert_eq!(
            &bytes[..3],
            b"\xEF\xBB\xBF",
            "init.ps1 must carry UTF-8 BOM"
        );
        let script = read(&init);
        assert!(script.contains("function global:prompt"));
        assert!(script.contains("$global:LASTEXITCODE"));
        assert!(script.contains("ReferenceEquals"));
        assert!(script.contains("it''s home"), "{script}");
        assert_filled(&script);

        // PSReadLine's saved history is per workspace, and nothing happens
        // without PSReadLine. A file replaced by a link is not written.
        let path = ps_quote(ws.history_path("powershell").to_str().unwrap());
        let set = format!(
            "if (Get-Module PSReadLine) {{\n    try {{\n        Set-PSReadLineOption -HistorySavePath {path}\n        $global:__meow.History = {path}\n    }} catch {{ }}\n}}"
        );
        assert!(script.contains(&set), "{script}");
        assert!(
            script.contains(
                "if ($global:__meow.History -and -not (& $isSafeTarget $global:__meow.History)) {"
            ),
            "{script}"
        );
        assert!(script.contains("-HistorySaveStyle SaveNothing"), "{script}");
        assert!(script.contains(&format!("[Console]::Error.WriteLine('{HISTORY_LOST}')")));
    }

    #[test]
    fn replay_log_gets_a_header_once_and_is_never_truncated() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        prepare(&ws, "bash", None).unwrap();
        assert_eq!(read(ws.replay_path()), REPLAY_HEADER);

        fs::write(ws.replay_path(), format!("{REPLAY_HEADER}ls\n")).unwrap();
        fs::write(ws.history_path("zsh"), "echo inside-1\n").unwrap();
        prepare(&ws, "zsh", None).unwrap();
        assert_eq!(read(ws.replay_path()), format!("{REPLAY_HEADER}ls\n"));
        assert_eq!(read(ws.history_path("zsh")), "echo inside-1\n");
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
        assert_eq!(mode(&ws.history_path("zsh")), 0o600);
        assert_eq!(mode(&ws.history_path("bash")), 0o600);
        fs::set_permissions(ws.history_path("zsh"), fs::Permissions::from_mode(0o644)).unwrap();
        prepare(&ws, "zsh", None).unwrap();
        assert_eq!(mode(&ws.history_path("zsh")), 0o600);
    }

    /// The check the hooks run before each write, in the shells themselves:
    /// a file of another account, or any file in a folder of another
    /// account (a session folder swapped for one of its own), is never
    /// written.
    #[cfg(unix)]
    #[test]
    fn hooks_write_only_files_of_the_users_own() {
        let shells: Vec<String> = ["bash", "zsh"]
            .iter()
            .filter_map(|name| {
                ["/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]
                    .iter()
                    .map(|dir| format!("{dir}/{name}"))
                    .find(|path| Path::new(path).exists())
            })
            .collect();
        let tmp = tempfile::tempdir().unwrap();
        let mine = tmp.path().join("mine");
        fs::write(&mine, "").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&mine, &link).unwrap();
        let mut cases = vec![
            (tmp.path().join("missing"), true),
            (mine.clone(), true),
            (link, false),
        ];
        // SAFETY: no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            let chown = |path: &Path| {
                let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: a valid C string; the test runs as root.
                assert_eq!(unsafe { libc::lchown(path.as_ptr(), 4242, 4242) }, 0);
            };
            let theirs = tmp.path().join("theirs");
            fs::write(&theirs, "").unwrap();
            chown(&theirs);
            let their_folder = tmp.path().join("their-folder");
            fs::create_dir(&their_folder).unwrap();
            fs::write(their_folder.join("mine"), "").unwrap();
            chown(&their_folder);
            cases.extend([
                (theirs, false),
                (their_folder.join("mine"), false),
                (their_folder.join("missing"), false),
            ]);
        } else {
            // Files and folders of root's.
            cases.extend([
                (PathBuf::from("/etc/hosts"), false),
                (PathBuf::from("/etc/meow-missing"), false),
            ]);
        }
        for shell in &shells {
            for (path, ours) in &cases {
                let script = format!(
                    "{SH_OURS}_meow_ours {} && echo yes || echo no",
                    sh_quote(path.to_str().unwrap())
                );
                let out = std::process::Command::new(shell)
                    .args(["-c", &script])
                    .output()
                    .unwrap();
                let said = String::from_utf8_lossy(&out.stdout);
                let expected = if *ours { "yes" } else { "no" };
                assert_eq!(said.trim(), expected, "{shell} {}", path.display());
            }
        }
    }

    #[test]
    fn replay_log_refuses_symlinks_and_hooks_guard_mode_and_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = workspace(&tmp);
        prepare(&ws, "bash", None).unwrap();
        let bash_hooks = read(ws.tmp_dir().join("shell").join("hooks.bash"));
        assert!(bash_hooks
            .contains("[[ -f $_meow_profile && ! -L $_meow_profile && -O $_meow_profile ]]"));
        assert!(bash_hooks.contains("light | mild | aggressive) export MEOW_MODE=$line"));
        // Every file the hooks write is checked first: not a link, and
        // this user's own, in a folder of this user's.
        assert!(bash_hooks.contains(SH_OURS), "{bash_hooks}");
        for file in ["$_meow_replay", "$_meow_last_cwd", "$_meow_pending"] {
            assert!(
                bash_hooks.contains(&format!("_meow_ours \"{file}\"")),
                "{file}"
            );
        }
        assert!(
            !bash_hooks.contains("[[ ! -L $_meow_replay ]]"),
            "{bash_hooks}"
        );
        prepare(&ws, "zsh", None).unwrap();
        let zsh_hooks = read(ws.tmp_dir().join("shell").join("hooks.zsh"));
        assert!(zsh_hooks.contains(SH_OURS), "{zsh_hooks}");
        for file in ["$_meow_replay", "$_meow_last_cwd"] {
            assert!(
                zsh_hooks.contains(&format!("_meow_ours \"{file}\"")),
                "{file}"
            );
        }
        assert!(zsh_hooks.contains("-L $_meow_history && -O $_meow_history ]]"));
        fs::remove_file(ws.history_path("zsh")).unwrap();

        prepare(&ws, "pwsh.exe", None).unwrap();
        let ps_init = read(ws.tmp_dir().join("shell").join("init.ps1"));
        assert!(ps_init.contains("ReparsePoint"));
        assert!(ps_init.contains(r#"^mode = "(light|mild|aggressive)"$"#));
        assert!(ps_init.contains("# [UNRECORDED] command kept out of the shell history"));

        #[cfg(unix)]
        {
            let target = tmp.path().join("outside-replay.sh");
            fs::write(&target, "secret").unwrap();
            fs::remove_file(ws.replay_path()).unwrap();
            std::os::unix::fs::symlink(&target, ws.replay_path()).unwrap();
            let err = prepare(&ws, "bash", None).unwrap_err();
            assert!(
                err.to_string().contains("symbolic link"),
                "expected symlink refusal, got: {err:#}"
            );

            fs::remove_file(ws.replay_path()).unwrap();
            fs::hard_link(&target, ws.replay_path()).unwrap();
            let err = prepare(&ws, "bash", None).unwrap_err();
            assert!(
                err.to_string().contains("hard links"),
                "expected hardlink refusal, got: {err:#}"
            );

            // The same for the shell history.
            fs::remove_file(ws.replay_path()).unwrap();
            fs::remove_file(ws.history_path("bash")).unwrap();
            std::os::unix::fs::symlink(&target, ws.history_path("bash")).unwrap();
            let err = prepare(&ws, "bash", None).unwrap_err();
            assert!(
                err.to_string()
                    .contains("symbolic link; refusing to write shell history"),
                "expected symlink refusal, got: {err:#}"
            );
            fs::remove_file(ws.history_path("bash")).unwrap();
            fs::hard_link(&target, ws.history_path("zsh")).unwrap();
            let err = prepare(&ws, "zsh", None).unwrap_err();
            assert!(
                err.to_string().contains("hard links"),
                "expected hardlink refusal, got: {err:#}"
            );
            assert_eq!(read(&target), "secret");
        }
    }
}
