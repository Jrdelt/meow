//! The programs a session starts, kept track of so that none outlives it.
//!
//! Every scanner and helper program of the recon queue is started through a
//! [`Tracker`]: on Unix as the leader of a process group of its own, on
//! Windows inside a Job Object with kill-on-close. The [`Group`] that comes
//! back ends the whole group when it is dropped, and [`Tracker::close`] ends
//! every group at once when the session does.
//!
//! That covers every way out that still runs meow's own code. For the ways
//! that do not (`SIGKILL`, a crash), a Unix session has two more lists of
//! what it runs. The guard: a second `meow` process (`meow __guard`) in a
//! session of its own, which is told every group over a pipe and kills the
//! ones still listed when the pipe closes. And the record: one small file
//! per running tool in `~/.meow/run`, which the next start of meow reads to
//! stop what a session left running when it and its guard were killed
//! together ([`sweep`]). A tool puts itself on both lists before it becomes
//! the tool, so it never runs unlisted. On Windows the Job Objects close
//! with the process.
//!
//! The limit of all of it: a tool is stopped by its process group. A
//! program that a tool starts in a session or group of its own (`setsid`,
//! `sudo` with a terminal of its own) is in none of meow's groups, and is
//! not stopped.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// The hidden subcommand that runs [`guard_main`].
pub const GUARD_COMMAND: &str = "__guard";
/// The folder in `~/.meow` where a session writes down the tools it runs.
pub const RUN_DIR: &str = "run";
/// What it means to run without the guard.
pub const UNGUARDED: &str =
    "scans still stop when the session ends, but would keep running if meow itself were killed";

const CLOSED: &str = "the session is closing";

#[cfg(unix)]
type Id = libc::pid_t;
#[cfg(windows)]
type Id = usize;

/// The process trees of one session.
#[derive(Clone, Default)]
pub struct Tracker(Arc<Shared>);

#[derive(Default)]
struct Shared {
    /// The session is over: what runs was killed and nothing new starts.
    /// Asked several times a second by whatever runs, so not behind the lock.
    closed: AtomicBool,
    live: Mutex<Live>,
}

#[derive(Default)]
struct Live {
    tools: Vec<Tool>,
    #[cfg(unix)]
    lists: Lists,
    /// What happened to the guard, until someone has been told.
    fault: Option<String>,
}

/// One running tool: the group it leads (Unix) or the job it is in.
struct Tool {
    id: Id,
    #[cfg(unix)]
    plan: Arc<Plan>,
}

/// Where a Unix session lists its tools for the day it is killed.
#[cfg(unix)]
#[derive(Default)]
struct Lists {
    /// The number the next tool is listed under.
    next_slot: u32,
    guard: Option<guard::Link>,
    /// This `meow`, for starting the guard (again).
    program: Option<std::path::PathBuf>,
    guard_starts: u32,
    book: Option<record::Book>,
    /// Said once each: the guard was started again, the guard is gone.
    said_again: bool,
    said_gone: bool,
}

/// The most guards one session starts: one that keeps dying is given up.
#[cfg(unix)]
const MAX_GUARD_STARTS: u32 = 8;

/// What a new tool does before it becomes the tool: it puts itself on the
/// guard's list and writes its record.
#[cfg(unix)]
struct Plan {
    /// Only the start it was made for: a command that is started again
    /// gets a plan of its own, and this one then does nothing.
    armed: AtomicBool,
    slot: u32,
    /// The pipe to the guard, as the new process inherits it.
    guard: Option<std::os::fd::RawFd>,
    page: Option<record::Page>,
}

#[cfg(unix)]
impl Plan {
    /// Runs in the new process between `fork` and `exec`. That process is a
    /// copy of one thread of meow: only async-signal-safe calls, no
    /// allocation and no lock.
    fn announce(&self) {
        if !self.armed.load(Ordering::Relaxed) {
            return;
        }
        // SAFETY: plain system calls. The group is its own already (the
        // standard library made it so before this runs); said again, so
        // that nothing here depends on that order.
        let pid = unsafe {
            libc::setpgid(0, 0);
            libc::getpid()
        };
        if let Some(pipe) = self.guard {
            let mut line = [0u8; GUARD_LINE];
            let len = guard_line(b'+', self.slot, Some(pid), &mut line);
            // SAFETY: writes `len` bytes of a buffer that long to a
            // descriptor inherited from meow. A guard that is gone must
            // not end the tool with SIGPIPE: meow notices and starts
            // another.
            unsafe {
                let before = libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                libc::write(pipe, line.as_ptr().cast(), len);
                libc::signal(libc::SIGPIPE, before);
            }
        }
        if let Some(page) = &self.page {
            page.write(pid);
        }
    }
}

/// The longest line of the guard's protocol: a sign, a tool's number, a
/// space, a process id and the end of the line.
#[cfg(unix)]
const GUARD_LINE: usize = 24;

/// Writes one line of the guard's protocol into `line` and returns its
/// length: `+<slot> <group>` when a tool starts, `-<slot>` when it has
/// ended. Without allocating: a new tool writes its own line.
#[cfg(unix)]
fn guard_line(sign: u8, slot: u32, group: Option<Id>, line: &mut [u8; GUARD_LINE]) -> usize {
    let mut len = 0;
    push_bytes(line, &mut len, &[sign]);
    push_number(line, &mut len, u64::from(slot));
    if let Some(group) = group {
        push_bytes(line, &mut len, b" ");
        push_number(line, &mut len, u64::try_from(group).unwrap_or(0));
    }
    push_bytes(line, &mut len, b"\n");
    len
}

/// Appends `bytes` to `text` at `*at`, as far as there is room.
#[cfg(unix)]
fn push_bytes(text: &mut [u8], at: &mut usize, bytes: &[u8]) {
    for byte in bytes {
        if let Some(place) = text.get_mut(*at) {
            *place = *byte;
            *at += 1;
        }
    }
}

/// Appends `number` in decimal to `text` at `*at`, as far as there is room.
#[cfg(unix)]
fn push_number(text: &mut [u8], at: &mut usize, mut number: u64) {
    let mut digits = [0u8; 20];
    let mut count = 0;
    loop {
        if let Some(place) = digits.get_mut(count) {
            *place = b'0' + (number % 10) as u8;
        }
        count += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        if let Some(digit) = digits.get(count) {
            push_bytes(text, at, &[*digit]);
        }
    }
}

impl Shared {
    fn live(&self) -> MutexGuard<'_, Live> {
        // A panic elsewhere must not leave scanners running.
        self.live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(unix)]
impl Live {
    /// The plan for the tool that is about to start.
    fn plan(&mut self, program: &std::ffi::OsStr) -> Arc<Plan> {
        let slot = self.lists.next_slot;
        self.lists.next_slot = slot.wrapping_add(1);
        Arc::new(Plan {
            armed: AtomicBool::new(true),
            slot,
            guard: self.lists.guard.as_ref().map(guard::Link::pipe),
            page: self
                .lists
                .book
                .as_ref()
                .and_then(|book| book.page(slot, program)),
        })
    }

    /// One line to the guard. If it cannot be told, another takes its
    /// place.
    fn tell(&mut self, sign: u8, slot: u32, group: Option<Id>) {
        let Some(link) = self.lists.guard.as_mut() else {
            return;
        };
        if let Err(error) = link.tell(sign, slot, group) {
            self.replace_guard(&error.to_string());
        }
    }

    /// Takes a tool off both lists: it has ended, or never started (it may
    /// have listed itself before it failed to become the program).
    fn unlist(&mut self, plan: &Plan) {
        self.tell(b'-', plan.slot, None);
        if let Some(page) = &plan.page {
            page.remove();
        }
    }

    fn start_guard(&mut self) -> io::Result<guard::Link> {
        let Some(program) = self.lists.program.as_deref() else {
            return Err(io::Error::other("no path to this program"));
        };
        if self.lists.guard_starts >= MAX_GUARD_STARTS {
            return Err(io::Error::other("it stopped too often"));
        }
        self.lists.guard_starts += 1;
        guard::Link::start(program)
    }

    /// The guard can no longer be told what runs: it was killed, or its
    /// pipe is full. It must not act on what it was told before, so it is
    /// ended, and a new one is started and told what runs now.
    fn replace_guard(&mut self, why: &str) {
        if let Some(link) = self.lists.guard.take() {
            link.abandon();
        }
        let started = self.start_guard().and_then(|mut link| {
            for tool in &self.tools {
                if let Err(error) = link.tell(b'+', tool.plan.slot, Some(tool.id)) {
                    link.abandon();
                    return Err(error);
                }
            }
            Ok(link)
        });
        match started {
            Ok(link) => {
                self.lists.guard = Some(link);
                if !std::mem::replace(&mut self.lists.said_again, true) {
                    self.fault = Some(format!(
                        "the scan guard stopped ({why}) and was started again"
                    ));
                }
            }
            Err(error) => {
                if !std::mem::replace(&mut self.lists.said_gone, true) {
                    self.fault = Some(format!(
                        "the scan guard stopped ({why}) and did not start again ({error}): {UNGUARDED}"
                    ));
                }
            }
        }
    }
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts `command` as a tree of its own. Refused once the session is
    /// closing.
    pub fn spawn(
        &self,
        command: &mut tokio::process::Command,
    ) -> io::Result<(tokio::process::Child, Group)> {
        // Held across the start: a session that closes meanwhile waits for
        // the new group to be listed, and then kills it with the others.
        let mut live = self.0.live();
        if self.is_closed() {
            return Err(io::Error::other(CLOSED));
        }
        #[cfg(unix)]
        {
            let plan = live.plan(command.as_std().get_program());
            command.process_group(0);
            let hook = Arc::clone(&plan);
            // SAFETY: `Plan::announce` keeps to what is allowed between
            // `fork` and `exec`.
            unsafe {
                command.pre_exec(move || {
                    hook.announce();
                    Ok(())
                });
            }
            let started = command.spawn();
            self.adopt(&mut live, started, &plan, tokio::process::Child::id)
        }
        #[cfg(windows)]
        {
            let child = command.spawn()?;
            let id = child.raw_handle().and_then(job::attach);
            Ok((child, self.adopt(&mut live, id)))
        }
    }

    /// [`Tracker::spawn`] for a program that is waited for on a thread.
    pub fn spawn_std(
        &self,
        command: &mut std::process::Command,
    ) -> io::Result<(std::process::Child, Group)> {
        let mut live = self.0.live();
        if self.is_closed() {
            return Err(io::Error::other(CLOSED));
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let plan = live.plan(command.get_program());
            command.process_group(0);
            let hook = Arc::clone(&plan);
            // SAFETY: as in `spawn`.
            unsafe {
                command.pre_exec(move || {
                    hook.announce();
                    Ok(())
                });
            }
            let started = command.spawn();
            self.adopt(&mut live, started, &plan, |child| Some(child.id()))
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let child = command.spawn()?;
            let id = job::attach(child.as_raw_handle());
            Ok((child, self.adopt(&mut live, id)))
        }
    }

    /// Lists what `started` started, or takes back what it listed of
    /// itself if it did not start.
    #[cfg(unix)]
    fn adopt<C>(
        &self,
        live: &mut Live,
        started: io::Result<C>,
        plan: &Arc<Plan>,
        pid: impl Fn(&C) -> Option<u32>,
    ) -> io::Result<(C, Group)> {
        plan.armed.store(false, Ordering::SeqCst);
        let child = match started {
            Ok(child) => child,
            Err(error) => {
                live.unlist(plan);
                return Err(error);
            }
        };
        let id = pid(&child).and_then(group_id);
        match id {
            Some(id) => {
                live.tools.push(Tool {
                    id,
                    plan: Arc::clone(plan),
                });
                // Said by the tool itself already; said again, which is
                // also how a guard that is gone is found out.
                live.tell(b'+', plan.slot, Some(id));
            }
            None => live.unlist(plan),
        }
        let shared = Arc::clone(&self.0);
        Ok((child, Group { shared, id }))
    }

    #[cfg(windows)]
    fn adopt(&self, live: &mut Live, id: Option<Id>) -> Group {
        if let Some(id) = id {
            live.tools.push(Tool { id });
        }
        Group {
            shared: Arc::clone(&self.0),
            id,
        }
    }

    /// The session is over: kills every tree now and refuses new ones.
    pub fn close(&self) {
        // First, and without the lock: whatever asks from now on stops.
        self.0.closed.store(true, Ordering::SeqCst);
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut live = self.0.live();
        for tool in &live.tools {
            kill_group(tool.id);
        }
        #[cfg(unix)]
        {
            for page in live.tools.iter().filter_map(|tool| tool.plan.page.as_ref()) {
                page.remove();
            }
            if let Some(link) = live.lists.guard.take() {
                link.finish();
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::SeqCst)
    }

    /// How many trees are running.
    pub fn running(&self) -> usize {
        self.0.live().tools.len()
    }

    /// What happened to the guard, said once.
    pub fn take_fault(&self) -> Option<String> {
        self.0.live().fault.take()
    }

    /// Starts the guard: `program` is this `meow`. Without it everything
    /// else still works; only a meow that is killed outright leaves its
    /// scanners running until the next start.
    #[cfg(unix)]
    pub fn watch(&self, program: &std::path::Path) -> io::Result<()> {
        let mut live = self.0.live();
        if self.is_closed() {
            return Err(io::Error::other(CLOSED));
        }
        live.lists.program = Some(program.to_path_buf());
        let link = live.start_guard()?;
        if let Some(old) = live.lists.guard.replace(link) {
            old.abandon();
        }
        Ok(())
    }

    /// Looks whether the guard still runs, and starts another if not: a
    /// long scan is then guarded again before it ends.
    #[cfg(unix)]
    pub fn check_guard(&self) {
        let mut live = self.0.live();
        if self.is_closed() {
            return;
        }
        if live.lists.guard.as_mut().is_some_and(guard::Link::exited) {
            live.replace_guard("it is no longer running");
        }
    }

    /// Keeps the record of running tools in `dir` (`~/.meow/run`).
    #[cfg(unix)]
    pub fn record_in(&self, dir: &std::path::Path) -> io::Result<()> {
        let book = record::Book::open(dir)?;
        self.0.live().lists.book = Some(book);
        Ok(())
    }

    /// The guard's process id, if one is running.
    #[cfg(unix)]
    pub fn guard_pid(&self) -> Option<u32> {
        self.0.live().lists.guard.as_ref().map(guard::Link::pid)
    }
}

/// One program and everything it started. Dropping it ends them all.
pub struct Group {
    shared: Arc<Shared>,
    id: Option<Id>,
}

impl Group {
    /// Ends every process of the tree now.
    pub fn kill(&self) {
        if let Some(id) = self.id {
            kill_group(id);
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        let mut live = self.shared.live();
        let tool = live
            .tools
            .iter()
            .position(|tool| tool.id == id)
            .map(|at| live.tools.remove(at));
        kill_group(id);
        #[cfg(windows)]
        {
            let _ = tool;
            job::close(id);
        }
        #[cfg(unix)]
        if let Some(tool) = tool {
            live.unlist(&tool.plan);
        }
    }
}

/// Stops what a session left running when it and its guard were killed
/// together: the tools in the record in `dir` whose session is gone.
/// Returns their names. For the start of every session, before it runs
/// anything itself.
pub fn sweep(dir: &std::path::Path) -> Vec<String> {
    #[cfg(unix)]
    {
        record::sweep(dir)
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Vec::new()
    }
}

/// The group a just-started program leads. Never 0 or 1, which would name
/// meow's own group or every process.
#[cfg(unix)]
fn group_id(pid: u32) -> Option<Id> {
    Id::try_from(pid).ok().filter(|pid| *pid > 1)
}

#[cfg(unix)]
fn kill_group(id: Id) {
    // SAFETY: a plain system call. `id` is a process meow started as the
    // leader of a group of its own (see `group_id`), so this signals that
    // group and never meow's.
    unsafe {
        libc::killpg(id, libc::SIGKILL);
    }
}

#[cfg(windows)]
fn kill_group(id: Id) {
    job::terminate(id);
}

/// Job Objects: closing the handle ends every process the tool started.
#[cfg(windows)]
mod job {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// A new job with kill-on-close holding `process`; its handle as a
    /// number, so that it can be listed and used from any thread.
    pub fn attach(process: std::os::windows::io::RawHandle) -> Option<usize> {
        // SAFETY: all pointers are valid for the duration of each call and
        // the structure is plain data that may be zero-initialised.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) != 0;
            if !configured || AssignProcessToJobObject(job, process as _) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(job as usize)
        }
    }

    pub fn terminate(job: usize) {
        // SAFETY: `job` is a Job Object handle from `attach` that is still
        // open: it is closed only under the tracker's lock, after it was
        // taken off the list this is called from.
        unsafe {
            TerminateJobObject(job as HANDLE, 1);
        }
    }

    pub fn close(job: usize) {
        // SAFETY: the handle came from `attach` and is closed exactly once,
        // by the group that owns it.
        unsafe {
            CloseHandle(job as HANDLE);
        }
    }
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

/// What the guard keeps: the groups to kill when its pipe closes.
///
/// The protocol is one line per event: `+<slot> <pgid>` when a tool starts
/// (said by the tool itself before it becomes the tool, and again by meow)
/// and `-<slot>` when it has ended or did not start. The slot is a number
/// meow gives each tool, so that it can take back one whose process id it
/// never learned. Anything else is ignored.
#[cfg(unix)]
#[derive(Debug)]
struct Guarded {
    /// Groups that are never listed: the guard's own and meow's.
    refused: Vec<libc::pid_t>,
    /// Slot and group of every listed tool.
    groups: Vec<(u32, libc::pid_t)>,
    line: Vec<u8>,
    /// The line being read is too long: it is dropped whole.
    overlong: bool,
}

/// The most groups the guard lists. Recon runs one tool at a time.
#[cfg(unix)]
const MAX_GUARDED: usize = 64;
/// A sign, the ten digits of the largest slot, a space and the ten digits
/// of the largest process id.
#[cfg(unix)]
const MAX_GUARD_LINE: usize = GUARD_LINE - 2;

#[cfg(unix)]
impl Guarded {
    fn new(refused: &[libc::pid_t]) -> Self {
        Self {
            refused: refused.to_vec(),
            groups: Vec::new(),
            line: Vec::with_capacity(MAX_GUARD_LINE),
            overlong: false,
        }
    }

    /// Takes bytes as they arrive, in whatever pieces.
    fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                if !self.overlong {
                    let line = std::mem::take(&mut self.line);
                    self.apply(&line);
                }
                self.line.clear();
                self.overlong = false;
            } else if self.line.len() < MAX_GUARD_LINE {
                self.line.push(byte);
            } else {
                self.overlong = true;
            }
        }
    }

    /// One whole line. Returns whether it changed the list.
    fn apply(&mut self, line: &[u8]) -> bool {
        let number = |digits: &[u8]| {
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            std::str::from_utf8(digits).ok()?.parse::<u32>().ok()
        };
        let Some((sign, rest)) = line.split_first() else {
            return false;
        };
        match sign {
            b'+' => {
                let mut words = rest.splitn(2, |byte| *byte == b' ');
                let slot = words.next().and_then(number);
                let group = words
                    .next()
                    .and_then(number)
                    .and_then(|group| libc::pid_t::try_from(group).ok())
                    .filter(|group| *group > 1 && !self.refused.contains(group));
                let (Some(slot), Some(group)) = (slot, group) else {
                    return false;
                };
                // Said twice (by the tool and by meow), listed once.
                if self.groups.iter().any(|(known, _)| *known == slot)
                    || self.groups.len() >= MAX_GUARDED
                {
                    return false;
                }
                self.groups.push((slot, group));
                true
            }
            b'-' => {
                let Some(slot) = number(rest) else {
                    return false;
                };
                let before = self.groups.len();
                self.groups.retain(|(known, _)| *known != slot);
                self.groups.len() != before
            }
            _ => false,
        }
    }
}

#[cfg(unix)]
mod guard {
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, ChildStdin, Command, Stdio};

    /// The session's end of the guard: its process and the pipe to it.
    pub struct Link {
        child: Child,
        pipe: ChildStdin,
    }

    impl Link {
        pub fn start(program: &Path) -> io::Result<Self> {
            let mut command = Command::new(program);
            command
                .arg(super::GUARD_COMMAND)
                .env_clear()
                .current_dir("/")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // SAFETY: only async-signal-safe calls between fork and exec.
            unsafe {
                command.pre_exec(|| {
                    // A session of its own: closing the terminal sends it
                    // nothing, and no terminal can.
                    if libc::setsid() == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    // Kept across exec, so there is no moment without them.
                    super::ignore_end_signals();
                    Ok(())
                });
            }
            let mut child = command.spawn()?;
            let Some(pipe) = child.stdin.take() else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other("no pipe to the guard"));
            };
            // A write never waits: the session does not hang on its guard.
            // SAFETY: plain calls on a descriptor this process owns.
            let nonblocking = unsafe {
                let flags = libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL);
                flags != -1
                    && libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) != -1
            };
            let link = Self { child, pipe };
            if !nonblocking {
                let error = io::Error::last_os_error();
                link.abandon();
                return Err(error);
            }
            Ok(link)
        }

        pub fn pid(&self) -> u32 {
            self.child.id()
        }

        /// The pipe's descriptor: a new tool writes its own line to it.
        pub fn pipe(&self) -> RawFd {
            self.pipe.as_raw_fd()
        }

        /// The guard's process has ended (it was killed).
        pub fn exited(&mut self) -> bool {
            !matches!(self.child.try_wait(), Ok(None))
        }

        /// One line of the protocol. Short enough to be written whole or
        /// not at all.
        pub fn tell(&mut self, sign: u8, slot: u32, group: Option<libc::pid_t>) -> io::Result<()> {
            let mut line = [0u8; super::GUARD_LINE];
            let len = super::guard_line(sign, slot, group, &mut line);
            match self.pipe.write(&line[..len]) {
                Ok(written) if written == len => Ok(()),
                Ok(_) => Err(io::Error::other("the pipe to it is full")),
                Err(error) => Err(error),
            }
        }

        /// The session is over: the pipe closes, the guard kills what it
        /// still lists and exits.
        pub fn finish(self) {
            let Self { child, pipe } = self;
            drop(pipe);
            reap(child);
        }

        /// Ends the guard without letting it kill anything.
        pub fn abandon(self) {
            let Self { mut child, pipe } = self;
            let _ = child.kill();
            drop(pipe);
            reap(child);
        }
    }

    /// Waits for the guard on a thread of its own: leaving never waits.
    fn reap(mut child: Child) {
        let _ = std::thread::Builder::new()
            .name("meow-guard-reap".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
    }
}

/// The guard is not ended by what ends a session: a closed terminal, an
/// interrupt, a request to stop.
#[cfg(unix)]
fn ignore_end_signals() {
    for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
        // SAFETY: a plain system call that sets a disposition; async-signal-safe.
        unsafe {
            libc::signal(signal, libc::SIG_IGN);
        }
    }
}

/// `meow __guard`: reads group ids from standard input until it closes,
/// then kills the groups still listed and exits. Started by a session
/// only; it does nothing else. Returns the exit code.
#[cfg(unix)]
pub fn guard_main() -> u8 {
    use std::io::{IsTerminal, Read};

    let input = std::io::stdin();
    // SAFETY: fstat on descriptor 0 into a zeroed, correctly sized buffer.
    let is_pipe = unsafe {
        let mut stat: libc::stat = std::mem::zeroed();
        libc::fstat(0, &mut stat) == 0 && (stat.st_mode & libc::S_IFMT) == libc::S_IFIFO
    };
    if input.is_terminal() || !is_pipe {
        eprintln!("meow: {GUARD_COMMAND} is started by a session, not by hand");
        return 2;
    }
    ignore_end_signals();
    // A name of its own: `killall meow` and `pkill -x meow` then end the
    // session, which stops its scans in order, and leave the guard to do
    // its work if they do not.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: names this thread from a NUL-terminated string.
    unsafe {
        libc::prctl(libc::PR_SET_NAME, GUARD_NAME.as_ptr());
    }
    // SAFETY: plain system calls without preconditions.
    let (own, parent) = unsafe { (libc::getpgrp(), libc::getpgid(libc::getppid())) };
    let mut guarded = Guarded::new(&[own, parent]);
    let mut input = input.lock();
    let mut buffer = [0u8; 256];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => guarded.feed(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            // Unreadable is as good as closed: nothing more will be told.
            Err(_) => break,
        }
    }
    for (_, group) in &guarded.groups {
        kill_group(*group);
    }
    0
}

/// What the guard is called in a process list (Linux).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const GUARD_NAME: &std::ffi::CStr = c"meow-guard";

#[cfg(not(unix))]
pub fn guard_main() -> u8 {
    eprintln!("meow: {GUARD_COMMAND} is not used on this system");
    2
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

/// Which process is which: a process id is given to another program once
/// its process is gone, so a process is known by its id and the moment it
/// started.
#[cfg(unix)]
mod identity {
    /// A running process: when it started (in the system's own unit; only
    /// ever compared) and whose it is.
    pub struct Seen {
        pub start: u64,
        pub uid: libc::uid_t,
    }

    /// Field 22 of `/proc/<pid>/stat`: the start time in clock ticks since
    /// the system started. The program's name (field 2, in brackets) may
    /// hold spaces and brackets of its own, so the fields are counted from
    /// its last bracket. Allocates nothing: a new tool reads its own.
    #[cfg(any(target_os = "linux", target_os = "android", test))]
    pub fn start_in_stat(stat: &[u8]) -> Option<u64> {
        let name_end = stat.iter().rposition(|byte| *byte == b')')?;
        let digits = stat
            .get(name_end + 1..)?
            .split(|byte| *byte == b' ' || *byte == b'\n')
            .filter(|field| !field.is_empty())
            .nth(19)?;
        if digits.len() > 19 {
            return None;
        }
        let mut start = 0u64;
        for digit in digits {
            if !digit.is_ascii_digit() {
                return None;
            }
            start = start * 10 + u64::from(digit - b'0');
        }
        (start > 0).then_some(start)
    }

    /// The real user id in `/proc/<pid>/status` (`Uid:` and four numbers).
    #[cfg(any(target_os = "linux", target_os = "android", test))]
    pub fn uid_in_status(status: &str) -> Option<libc::uid_t> {
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    mod system {
        use super::{start_in_stat, uid_in_status, Seen};
        use std::io::Read;

        fn read(path: &str) -> Option<Vec<u8>> {
            let mut text = Vec::new();
            std::fs::File::open(path)
                .ok()?
                .take(4096)
                .read_to_end(&mut text)
                .ok()?;
            Some(text)
        }

        pub fn seen(pid: libc::pid_t) -> Option<Seen> {
            let start = start_in_stat(&read(&format!("/proc/{pid}/stat"))?)?;
            let status = read(&format!("/proc/{pid}/status"))?;
            let uid = uid_in_status(&String::from_utf8_lossy(&status))?;
            Some(Seen { start, uid })
        }

        /// When the calling process started, or 0. Only async-signal-safe
        /// calls: for between `fork` and `exec`.
        pub fn own_start() -> u64 {
            let mut stat = [0u8; 1024];
            // SAFETY: opens a fixed path and reads into a buffer of the
            // size given.
            let read = unsafe {
                let file = libc::open(
                    c"/proc/self/stat".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                );
                if file < 0 {
                    return 0;
                }
                let read = libc::read(file, stat.as_mut_ptr().cast(), stat.len());
                libc::close(file);
                read
            };
            usize::try_from(read)
                .ok()
                .and_then(|read| stat.get(..read))
                .and_then(start_in_stat)
                .unwrap_or(0)
        }

        /// Start times count from the system's start: a record of an
        /// earlier one names nothing that runs.
        pub fn boot() -> String {
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|id| id.trim().to_owned())
                .filter(|id| super::super::record::is_boot(id))
                .unwrap_or_else(|| "-".to_owned())
        }
    }

    #[cfg(target_os = "macos")]
    mod system {
        use super::Seen;

        fn info(pid: libc::pid_t) -> Option<libc::proc_bsdinfo> {
            let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
            // SAFETY: the buffer is `size` bytes of plain data, and is
            // used only when the call says it filled all of it.
            unsafe {
                let filled = libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    info.as_mut_ptr().cast(),
                    size,
                );
                (filled == size).then(|| info.assume_init())
            }
        }

        /// Microseconds since 1970.
        fn start(info: &libc::proc_bsdinfo) -> u64 {
            info.pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(info.pbi_start_tvusec)
        }

        pub fn seen(pid: libc::pid_t) -> Option<Seen> {
            let info = info(pid)?;
            Some(Seen {
                start: start(&info),
                uid: info.pbi_ruid,
            })
            .filter(|seen| seen.start > 0)
        }

        /// When the calling process started, or 0. One system call: for
        /// between `fork` and `exec`.
        pub fn own_start() -> u64 {
            // SAFETY: a plain system call.
            info(unsafe { libc::getpid() }).map_or(0, |info| start(&info))
        }

        /// Start times are dates here: they need no system start to
        /// count from.
        pub fn boot() -> String {
            "-".to_owned()
        }
    }

    /// Elsewhere nothing says when a process started: no record is kept.
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    mod system {
        use super::Seen;

        pub fn seen(_pid: libc::pid_t) -> Option<Seen> {
            None
        }

        pub fn own_start() -> u64 {
            0
        }

        pub fn boot() -> String {
            "-".to_owned()
        }
    }

    pub use system::{boot, own_start, seen};
}

/// The record of running tools: one file per tool in `~/.meow/run`, named
/// `<session's process id>.<slot>`, of one line:
///
/// `meow-run 1 <boot> <session pid> <session start> <group> <start> <name>`
///
/// Written by the tool itself before it becomes the tool and removed by
/// its session when it ends. Read by [`sweep`] at the next start of meow.
#[cfg(unix)]
mod record {
    use std::ffi::{CString, OsStr};
    use std::io::{self, Read};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use super::{identity, push_bytes, push_number};

    const MAGIC: &str = "meow-run";
    const VERSION: &str = "1";
    /// More than the longest record: six numbers, a boot id and a name.
    const MAX_BYTES: usize = 256;
    /// The longest name of a tool that is kept.
    const MAX_NAME: usize = 32;
    /// The most files one sweep looks at.
    const MAX_ENTRIES: usize = 512;
    /// How a record is called while its tool writes it.
    const DRAFT: &str = ".new";
    /// A draft older than this was never finished.
    const DRAFT_AGE: Duration = Duration::from_secs(60);

    /// Where a session writes its tools down.
    pub struct Book {
        dir: PathBuf,
        owner: libc::pid_t,
        /// How every record of this session begins.
        head: Vec<u8>,
    }

    impl Book {
        pub fn open(dir: &Path) -> io::Result<Self> {
            crate::workspace::create_private_dir(dir).map_err(io::Error::other)?;
            // SAFETY: plain system calls.
            let (owner, user) = unsafe { (libc::getpid(), libc::geteuid()) };
            if std::fs::symlink_metadata(dir)?.uid() != user {
                return Err(io::Error::other("the folder for it is someone else's"));
            }
            let Some(own) = identity::seen(owner) else {
                return Err(io::Error::other(
                    "this system does not say when a process started",
                ));
            };
            let head = format!(
                "{MAGIC} {VERSION} {} {owner} {} ",
                identity::boot(),
                own.start
            );
            Ok(Self {
                dir: dir.to_path_buf(),
                owner,
                head: head.into_bytes(),
            })
        }

        /// The record of the tool in `slot`, for it to write.
        pub fn page(&self, slot: u32, program: &OsStr) -> Option<Page> {
            let path = self.dir.join(format!("{}.{slot}", self.owner));
            let mut draft = path.clone().into_os_string();
            draft.push(DRAFT);
            Some(Page {
                path: CString::new(path.into_os_string().into_vec()).ok()?,
                draft: CString::new(draft.into_vec()).ok()?,
                head: self.head.clone(),
                tail: format!(" {}\n", tool_name(program)).into_bytes(),
            })
        }
    }

    /// A tool's file name as plain letters; `tool` if nothing is left.
    fn tool_name(program: &OsStr) -> String {
        let name: String = Path::new(program)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
            .bytes()
            .filter(|byte| name_byte(*byte))
            .take(MAX_NAME)
            .map(char::from)
            .collect();
        if name.is_empty() {
            "tool".to_owned()
        } else {
            name
        }
    }

    fn name_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
    }

    /// One tool's record.
    pub struct Page {
        path: CString,
        draft: CString,
        head: Vec<u8>,
        tail: Vec<u8>,
    }

    impl Page {
        /// Writes the record of the calling process, which is `pid` and
        /// about to become the tool. Only async-signal-safe calls and no
        /// allocation: this runs between `fork` and `exec`. Written under
        /// another name first, so that a record is always a whole one.
        pub fn write(&self, pid: libc::pid_t) {
            let start = identity::own_start();
            let Ok(group) = u64::try_from(pid) else {
                return;
            };
            if start == 0 || group <= 1 {
                return;
            }
            let mut text = [0u8; MAX_BYTES];
            let mut len = 0;
            push_bytes(&mut text, &mut len, &self.head);
            push_number(&mut text, &mut len, group);
            push_bytes(&mut text, &mut len, b" ");
            push_number(&mut text, &mut len, start);
            push_bytes(&mut text, &mut len, &self.tail);
            let flags =
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            // SAFETY: both paths are NUL-terminated strings made before
            // the fork, and `len` bytes of `text` are initialised.
            unsafe {
                let file = libc::open(self.draft.as_ptr(), flags, 0o600 as libc::c_uint);
                if file < 0 {
                    return;
                }
                let written = libc::write(file, text.as_ptr().cast(), len);
                libc::close(file);
                if usize::try_from(written).is_ok_and(|written| written == len) {
                    libc::rename(self.draft.as_ptr(), self.path.as_ptr());
                } else {
                    libc::unlink(self.draft.as_ptr());
                }
            }
        }

        /// The tool has ended, or never started.
        pub fn remove(&self) {
            for path in [&self.path, &self.draft] {
                let _ = std::fs::remove_file(OsStr::from_bytes(path.as_bytes()));
            }
        }
    }

    /// What one record says.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct Entry {
        pub boot: String,
        pub owner: libc::pid_t,
        pub owner_start: u64,
        pub group: libc::pid_t,
        pub start: u64,
        pub name: String,
    }

    /// A boot id as the system writes it, or `-` where there is none.
    pub fn is_boot(text: &str) -> bool {
        !text.is_empty()
            && text.len() <= 40
            && text
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    }

    fn number(text: &str) -> Option<u64> {
        if text.is_empty() || text.len() > 19 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    }

    fn process(text: &str) -> Option<libc::pid_t> {
        libc::pid_t::try_from(number(text)?)
            .ok()
            .filter(|pid| *pid > 1)
    }

    /// Reads one record: exactly what [`Page::write`] writes, or nothing.
    pub(super) fn parse(text: &str) -> Option<Entry> {
        let mut words = text.strip_suffix('\n')?.split(' ');
        if words.next()? != MAGIC || words.next()? != VERSION {
            return None;
        }
        let entry = Entry {
            boot: words.next().filter(|boot| is_boot(boot))?.to_owned(),
            owner: process(words.next()?)?,
            owner_start: number(words.next()?).filter(|start| *start > 0)?,
            group: process(words.next()?)?,
            start: number(words.next()?).filter(|start| *start > 0)?,
            name: words
                .next()
                .filter(|name| {
                    !name.is_empty() && name.len() <= MAX_NAME && name.bytes().all(name_byte)
                })?
                .to_owned(),
        };
        words.next().is_none().then_some(entry)
    }

    /// `<digits>.<digits>`, and whether it is still being written.
    fn record_name(name: &OsStr) -> Option<bool> {
        let name = name.to_str()?;
        let (name, draft) = match name.strip_suffix(DRAFT) {
            Some(name) => (name, true),
            None => (name, false),
        };
        let (owner, slot) = name.split_once('.')?;
        (number(owner).is_some() && number(slot).is_some()).then_some(draft)
    }

    /// The text of a record: a small regular file of this user's, read
    /// without following a link or waiting on a pipe.
    fn read(path: &Path, user: libc::uid_t) -> Option<String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .ok()?;
        let meta = file.metadata().ok()?;
        if !meta.is_file() || meta.uid() != user || meta.len() > MAX_BYTES as u64 {
            return None;
        }
        let mut text = String::new();
        file.take(MAX_BYTES as u64).read_to_string(&mut text).ok()?;
        Some(text)
    }

    /// Whether the group `record` names is the tool it was written for,
    /// still running.
    ///
    /// A record is only a hint, and is believed as far as the system
    /// confirms it: the group is killed only if its leader is a running
    /// process of this user that started at the very moment the record
    /// says, and is not meow itself. A process id that has been given to
    /// another program since does not pass, and neither does a record
    /// someone made up: whoever can write one that passes can read that
    /// process's start time and write into this user's private folder, and
    /// so can already kill the process without meow.
    fn still_runs(record: &Entry, own: &[libc::pid_t]) -> bool {
        if own.contains(&record.group) {
            return false;
        }
        let Some(seen) = identity::seen(record.group) else {
            return false;
        };
        // SAFETY: plain system calls.
        let (user, leads) =
            unsafe { (libc::getuid(), libc::getpgid(record.group) == record.group) };
        leads && seen.start == record.start && seen.uid == user
    }

    pub fn sweep(dir: &Path) -> Vec<String> {
        let mut stopped = Vec::new();
        // SAFETY: plain system calls.
        let (user, own) = unsafe {
            (
                libc::geteuid(),
                [
                    libc::getpid(),
                    libc::getpgrp(),
                    libc::getpgid(libc::getppid()),
                ],
            )
        };
        // Only this user's own folder is a record.
        let own_dir =
            std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir() && meta.uid() == user);
        let Some(entries) = own_dir.then(|| std::fs::read_dir(dir).ok()).flatten() else {
            return stopped;
        };
        let boot = identity::boot();
        for entry in entries.flatten().take(MAX_ENTRIES) {
            let Some(draft) = record_name(&entry.file_name()) else {
                continue;
            };
            let path = entry.path();
            if draft {
                // Its tool may be writing it right now.
                let old = std::fs::symlink_metadata(&path)
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|at| SystemTime::now().duration_since(at).ok())
                    .is_none_or(|age| age > DRAFT_AGE);
                if old {
                    let _ = std::fs::remove_file(&path);
                }
                continue;
            }
            let record = read(&path, user).as_deref().and_then(parse);
            if let Some(record) = record.filter(|record| record.boot == boot) {
                // A session that still runs keeps its own list.
                if identity::seen(record.owner).is_some_and(|seen| seen.start == record.owner_start)
                {
                    continue;
                }
                if still_runs(&record, &own) {
                    // SAFETY: a plain system call on a group that
                    // `still_runs` found to be a tool's.
                    unsafe {
                        libc::killpg(record.group, libc::SIGKILL);
                    }
                    stopped.push(record.name);
                }
            }
            // Acted on, out of date or not a record: gone either way.
            let _ = std::fs::remove_file(&path);
        }
        stopped
    }
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{Duration, Instant};

    /// Running and not a zombie: a killed child that its parent has not
    /// collected yet still answers signal 0, on macOS too.
    fn alive(pid: libc::pid_t) -> bool {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            return !status.lines().any(|line| {
                line.strip_prefix("State:")
                    .is_some_and(|state| state.trim_start().starts_with('Z'))
            });
        }
        // No /proc (macOS): ps says Z for a zombie and nothing once it is
        // gone.
        if let Ok(out) = std::process::Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
        {
            let stat = String::from_utf8_lossy(&out.stdout);
            let stat = stat.trim();
            return !stat.is_empty() && !stat.starts_with('Z');
        }
        // SAFETY: signal 0 only asks whether the process exists.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    pub(crate) fn wait_gone(pid: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while alive(pid) {
            assert!(Instant::now() < deadline, "process {pid} is still running");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A script that starts a child of its own, writes both process ids
    /// to `pids` and waits.
    pub(crate) fn tool(dir: &Path, pids: &Path) -> std::process::Command {
        let path = dir.join("tool");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nsleep 300 &\necho \"$$ $!\" > '{}'\nwait\n",
                pids.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut command = std::process::Command::new(path);
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        command
    }

    pub(crate) fn started(pids: &Path) -> Vec<libc::pid_t> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let ids: Vec<libc::pid_t> = std::fs::read_to_string(pids)
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(|pid| pid.parse().ok())
                .collect();
            if ids.len() == 2 {
                return ids;
            }
            assert!(Instant::now() < deadline, "the tool did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn the_guard_lists_groups_and_refuses_everything_else() {
        let mut guarded = Guarded::new(&[4000, 4100]);
        assert!(guarded.apply(b"+0 1234"));
        assert!(guarded.apply(b"+1 77"));
        assert_eq!(guarded.groups, [(0, 1234), (1, 77)]);
        // Said twice (by the tool and by meow), listed once; ended, gone.
        assert!(!guarded.apply(b"+0 1234"));
        assert!(!guarded.apply(b"+0 99"), "a slot names one tool");
        assert!(guarded.apply(b"-0"));
        assert!(!guarded.apply(b"-0"));
        assert_eq!(guarded.groups, [(1, 77)]);

        // Every process, the caller's own group, the guard's and meow's.
        for refused in [
            &b"+5 0"[..],
            b"+5 1",
            b"+5 -1",
            b"+5 -77",
            b"+5 4000",
            b"+5 4100",
            b"-4000",
        ] {
            assert!(!guarded.apply(refused), "{refused:?}");
        }
        // Not the protocol: no sign, another sign, no number, not a number,
        // more than a process id holds, the line of an earlier version.
        for junk in [
            &b""[..],
            b"+",
            b"-",
            b"77",
            b"5 77",
            b"*5 77",
            b"+77",
            b"+5",
            b"+5 ",
            b"+ 77",
            b"+5  77",
            b"+5 7 7",
            b"+5 77 ",
            b" +5 77",
            b"+5 0x4d",
            b"+5 77\r",
            b"+5 99999999999",
            b"+5 2147483648",
            b"+99999999999 77",
            b"-1 77",
            b"- 1",
            "+5 \u{664}\u{662}".as_bytes(),
        ] {
            assert!(!guarded.apply(junk), "{junk:?}");
        }
        assert_eq!(guarded.groups, [(1, 77)]);

        // Never more than the limit, however many it is told.
        let mut guarded = Guarded::new(&[]);
        for id in 2..10_000 {
            guarded.apply(format!("+{id} {id}").as_bytes());
        }
        assert_eq!(guarded.groups.len(), MAX_GUARDED);
        assert!(!guarded.apply(b"+20000 20000"));
        assert!(guarded.apply(b"-2"));
        assert!(guarded.apply(b"+20000 20000"));
    }

    #[test]
    fn the_guard_reads_lines_in_any_pieces_and_drops_long_ones() {
        let mut guarded = Guarded::new(&[]);
        guarded.feed(b"+0 12");
        assert!(guarded.groups.is_empty(), "no line yet");
        guarded.feed(b"34\n+1 5");
        guarded.feed(b"6\n-0\n+2 78\n+3 9");
        // The last line never ended: it is not acted on.
        assert_eq!(guarded.groups, [(1, 56), (2, 78)]);

        // A line too long is dropped whole, not cut into a shorter number,
        // and the line after it is read as usual.
        let mut guarded = Guarded::new(&[]);
        guarded.feed(b"+1 1234567890123456789012345\n+7 42\n");
        assert_eq!(guarded.groups, [(7, 42)]);
        let mut flood = vec![b'9'; 100_000];
        flood.splice(0..0, *b"+1 ");
        guarded.feed(&flood);
        assert!(guarded.line.len() <= MAX_GUARD_LINE);
        guarded.feed(b"\n+8 43\n\n\n-7\n");
        assert_eq!(guarded.groups, [(8, 43)]);

        // What meow and a new tool write is what the guard reads, up to
        // the largest numbers there are.
        let mut line = [0u8; GUARD_LINE];
        let len = guard_line(b'+', u32::MAX, Some(libc::pid_t::MAX), &mut line);
        assert_eq!(&line[..len], b"+4294967295 2147483647\n");
        assert_eq!(len - 1, MAX_GUARD_LINE);
        guarded.feed(&line[..len]);
        assert_eq!(guarded.groups.last(), Some(&(u32::MAX, libc::pid_t::MAX)));
        let len = guard_line(b'-', u32::MAX, None, &mut line);
        assert_eq!(&line[..len], b"-4294967295\n");
        guarded.feed(&line[..len]);
        assert_eq!(guarded.groups, [(8, 43)]);
        let len = guard_line(b'+', 0, Some(2), &mut line);
        assert_eq!(&line[..len], b"+0 2\n");
    }

    /// A stand-in for `meow __guard` that keeps what it is told in `told`.
    fn listener(dir: &Path, told: &Path) -> std::path::PathBuf {
        let path = dir.join("listener");
        std::fs::write(
            &path,
            format!("#!/bin/sh\nexec cat >> '{}'\n", told.display()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_tool_lists_itself_before_it_becomes_the_tool() {
        let dir = tempfile::tempdir().unwrap();
        let (told, run) = (dir.path().join("told"), dir.path().join("run"));
        let tracker = Tracker::new();
        tracker.watch(&listener(dir.path(), &told)).unwrap();
        let recorded = identity::seen(std::process::id() as libc::pid_t).is_some();
        if recorded {
            tracker.record_in(&run).unwrap();
        }
        let records = || -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&run)
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            names.sort();
            names
        };
        let said = || std::fs::read_to_string(&told).unwrap_or_default();

        // A program that cannot be started: meow never learns the process
        // id, so only the new process itself can have said it; and what it
        // said is taken back.
        let mut missing = std::process::Command::new(dir.path().join("no-such-tool"));
        assert!(tracker.spawn_std(&mut missing).is_err());
        wait_for("the listing to be taken back", || {
            said().ends_with("\n-0\n")
        });
        let first = said();
        let listed = first
            .strip_prefix("+0 ")
            .and_then(|rest| rest.split_once('\n'));
        let (pid, rest) = listed.unwrap_or_else(|| panic!("{first:?}"));
        assert!(
            pid.parse::<libc::pid_t>().is_ok_and(|pid| pid > 1),
            "{first:?}"
        );
        assert_eq!(rest, "-0\n");
        assert_eq!(records(), Vec::<String>::new());
        assert_eq!(tracker.running(), 0);

        // One that starts: listed by itself and again by meow, written
        // down with the moment it started, and taken off both lists when
        // it has ended.
        let pids = dir.path().join("pids");
        let (mut child, group) = tracker.spawn_std(&mut tool(dir.path(), &pids)).unwrap();
        let ids = started(&pids);
        let line = format!("+1 {}\n", ids[0]);
        wait_for("both listings", || said().matches(&line).count() == 2);
        if recorded {
            let name = format!("{}.1", std::process::id());
            assert_eq!(records(), std::slice::from_ref(&name));
            let text = std::fs::read_to_string(run.join(&name)).unwrap();
            let entry = record::parse(&text).unwrap_or_else(|| panic!("{text:?}"));
            assert_eq!(entry.owner, std::process::id() as libc::pid_t);
            assert_eq!(entry.group, ids[0]);
            assert_eq!(entry.start, identity::seen(ids[0]).unwrap().start);
            assert_eq!(entry.name, "tool");
            use std::os::unix::fs::MetadataExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().mode() & 0o777;
            assert_eq!((mode(&run), mode(&run.join(&name))), (0o700, 0o600));
            // A session that runs keeps its own list: a sweep leaves it.
            assert_eq!(sweep(&run), Vec::<String>::new());
            assert_eq!(records(), [name]);
            assert!(alive(ids[0]));
        }
        drop(group);
        let _ = child.wait();
        wait_for("the end to be said", || said().ends_with("\n-1\n"));
        assert_eq!(records(), Vec::<String>::new());

        // A command started twice lists itself once each time.
        let mut twice = tool(dir.path(), &pids);
        for slot in [2, 3] {
            std::fs::remove_file(&pids).unwrap();
            let (mut child, group) = tracker.spawn_std(&mut twice).unwrap();
            let ids = started(&pids);
            let line = format!("+{slot} {}\n", ids[0]);
            wait_for("both listings", || said().matches(&line).count() == 2);
            assert_eq!(said().matches(&format!(" {}\n", ids[0])).count(), 2);
            drop(group);
            let _ = child.wait();
        }
        tracker.close();
    }

    #[test]
    fn a_guard_that_dies_is_replaced_and_told_what_runs() {
        let dir = tempfile::tempdir().unwrap();
        let told = dir.path().join("told");
        let tracker = Tracker::new();
        tracker.watch(&listener(dir.path(), &told)).unwrap();
        let pids = dir.path().join("pids");
        let (mut child, group) = tracker.spawn_std(&mut tool(dir.path(), &pids)).unwrap();
        let ids = started(&pids);
        let first = tracker.guard_pid().unwrap();
        tracker.check_guard();
        assert_eq!(tracker.guard_pid(), Some(first), "it runs: left alone");
        assert_eq!(tracker.take_fault(), None);

        // Killed while a tool runs: found at the next look, replaced, and
        // the new one is told the tool. Said once.
        let said = || std::fs::read_to_string(&told).unwrap_or_default();
        let line = format!("+0 {}\n", ids[0]);
        wait_for("both listings", || said().matches(&line).count() == 2);
        // SAFETY: a signal to the stand-in this test started.
        unsafe { libc::kill(first as libc::pid_t, libc::SIGKILL) };
        wait_for("a new guard", || {
            tracker.check_guard();
            tracker.guard_pid().is_some_and(|pid| pid != first)
        });
        wait_for("the tool to be listed again", || {
            said().matches(&line).count() == 3
        });
        let fault = tracker.take_fault().unwrap();
        assert_eq!(
            fault,
            "the scan guard stopped (it is no longer running) and was started again"
        );
        assert!(alive(ids[0]), "the tool was not touched");

        // Again, found this time by telling it something; nothing more is
        // said.
        let second = tracker.guard_pid().unwrap();
        // SAFETY: as above.
        unsafe { libc::kill(second as libc::pid_t, libc::SIGKILL) };
        wait_gone(second as libc::pid_t);
        drop(group);
        let _ = child.wait();
        assert!(tracker.guard_pid().is_some_and(|pid| pid != second));
        assert_eq!(tracker.take_fault(), None);

        // One that cannot be started again is given up, and that is said.
        std::fs::remove_file(dir.path().join("listener")).unwrap();
        let third = tracker.guard_pid().unwrap();
        // SAFETY: as above.
        unsafe { libc::kill(third as libc::pid_t, libc::SIGKILL) };
        wait_for("the guard to be given up", || {
            tracker.check_guard();
            tracker.guard_pid().is_none()
        });
        let fault = tracker.take_fault().unwrap();
        assert!(
            fault.starts_with(
                "the scan guard stopped (it is no longer running) and did not start again ("
            ) && fault.ends_with(UNGUARDED),
            "{fault}"
        );
        // Tools still start and end without it.
        let (mut child, group) = tracker.spawn_std(&mut tool(dir.path(), &pids)).unwrap();
        drop(group);
        let _ = child.wait();
        tracker.close();
    }

    #[test]
    fn a_process_is_known_by_its_start_time_and_its_user() {
        // The name may hold spaces and brackets; field 22 is counted from
        // its last one.
        let stat = b"4242 (a) b) c) S 1 4242 4242 0 -1 4194304 139 0 0 0 0 0 0 0 20 0 1 0 \
            7654321 2420736 185 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n";
        assert_eq!(identity::start_in_stat(stat), Some(7654321));
        for broken in [
            &b""[..],
            b"4242 (sh",
            b"4242 (sh) S 1 2 3",
            b"4242 (sh) S 1 4242 4242 0 -1 4194304 139 0 0 0 0 0 0 0 20 0 1 0 12x4 5",
            b"4242 (sh) S 1 4242 4242 0 -1 4194304 139 0 0 0 0 0 0 0 20 0 1 0 0 5",
            b"4242 (sh) S 1 4242 4242 0 -1 4194304 139 0 0 0 0 0 0 0 20 0 1 0 \
              99999999999999999999 5",
        ] {
            assert_eq!(identity::start_in_stat(broken), None, "{broken:?}");
        }
        assert_eq!(
            identity::uid_in_status("Name:\tsh\nUid:\t1000\t0\t0\t0\nGid:\t5\t5\t5\t5\n"),
            Some(1000)
        );
        assert_eq!(identity::uid_in_status("Name:\tUid:\nGid:\t5\n"), None);
        assert_eq!(identity::uid_in_status("Uid:\tx\n"), None);

        // This process, where the system says: the same moment each time,
        // read both ways, and not the moment another process started.
        let own = std::process::id() as libc::pid_t;
        let Some(seen) = identity::seen(own) else {
            return;
        };
        assert_eq!(identity::own_start(), seen.start);
        assert_eq!(identity::seen(own).unwrap().start, seen.start);
        // SAFETY: a plain system call.
        assert_eq!(seen.uid, unsafe { libc::getuid() });
        assert!(identity::seen(libc::pid_t::MAX).is_none());
    }

    #[test]
    fn a_record_is_read_as_written_or_not_at_all() {
        let boot = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let line = format!("meow-run 1 {boot} 4000 111 4242 222 nmap\n");
        assert_eq!(
            record::parse(&line),
            Some(record::Entry {
                boot: boot.to_owned(),
                owner: 4000,
                owner_start: 111,
                group: 4242,
                start: 222,
                name: "nmap".to_owned(),
            })
        );
        assert!(record::parse("meow-run 1 - 4000 111 4242 222 feroxbuster-2.11\n").is_some());
        for broken in [
            String::new(),
            "\n".to_owned(),
            line.trim_end().to_owned(),
            format!("{line}\n"),
            format!("{line}more\n"),
            line.replace("meow-run", "meow-ran"),
            line.replace(" 1 ", " 2 "),
            line.replace(boot, "boot id"),
            line.replace(boot, &"a".repeat(41)),
            line.replace("4000", "1"),
            line.replace("4000", "0"),
            line.replace("4000", "-4000"),
            line.replace("4242", "1"),
            line.replace("4242", "99999999999"),
            line.replace("111", "0"),
            line.replace("222", "0"),
            line.replace("222", "2e2"),
            line.replace("222", ""),
            line.replace("nmap", ""),
            line.replace("nmap", "nmap extra"),
            line.replace("nmap", "n\u{1b}[2Jmap"),
            line.replace("nmap", &"n".repeat(33)),
            line.replace(' ', "  "),
            line.replace(' ', "\t"),
        ] {
            assert_eq!(record::parse(&broken), None, "{broken:?}");
        }
    }

    /// What a session that was killed with its guard leaves behind is
    /// stopped at the next start: only a tool that is still the one its
    /// record names, and never anything else.
    #[test]
    fn a_sweep_stops_only_what_a_dead_session_left_running() {
        use std::os::unix::process::CommandExt;
        let own = std::process::id() as libc::pid_t;
        let Some(me) = identity::seen(own) else {
            // Nothing says when a process started here: no record is kept.
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        crate::workspace::create_private_dir(&run).unwrap();
        let boot = identity::boot();
        let group = || {
            let mut sleep = std::process::Command::new("sleep");
            sleep.arg("300").process_group(0);
            let child = sleep.spawn().unwrap();
            let pid = child.id() as libc::pid_t;
            (child, pid, identity::seen(pid).unwrap().start)
        };
        // A session that is gone: a process id that was this test's child.
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let dead = gone.id() as libc::pid_t;
        gone.wait().unwrap();
        let write = |name: &str, text: String| std::fs::write(run.join(name), text).unwrap();
        let line = |owner: libc::pid_t, owner_start: u64, group: libc::pid_t, start: u64| {
            format!("meow-run 1 {boot} {owner} {owner_start} {group} {start} nmap\n")
        };

        let (mut left, left_pid, left_start) = group();
        let (mut reused, reused_pid, reused_start) = group();
        let (mut kept, kept_pid, kept_start) = group();
        let (mut other_boot, other_pid, other_start) = group();
        // Left running by a session that is gone.
        write("900.0", line(dead, 5, left_pid, left_start));
        // The same, but the process id now belongs to another program.
        write("900.1", line(dead, 5, reused_pid, reused_start + 1));
        // Of a session that still runs (this one).
        write("900.2", line(own, me.start, kept_pid, kept_start));
        // The session's process id is in use again, by another program.
        let (mut again, again_pid, again_start) = group();
        write("900.3", line(own, me.start + 1, again_pid, again_start));
        // From before the system was started again.
        write(
            "900.4",
            line(dead, 5, other_pid, other_start).replace(&boot, "0000-other"),
        );
        // This test itself, its group and the one it was started from.
        // SAFETY: plain system calls.
        let (mine, parent) = unsafe { (libc::getpgrp(), libc::getpgid(libc::getppid())) };
        write("900.5", line(dead, 5, own, me.start));
        if let Some(seen) = identity::seen(mine) {
            write("900.6", line(dead, 5, mine, seen.start));
        }
        if let Some(seen) = identity::seen(parent) {
            write("900.7", line(dead, 5, parent, seen.start));
        }
        // A process that leads no group of its own.
        let mut member = std::process::Command::new("sleep")
            .arg("300")
            .spawn()
            .unwrap();
        let member_pid = member.id() as libc::pid_t;
        write(
            "900.8",
            line(
                dead,
                5,
                member_pid,
                identity::seen(member_pid).unwrap().start,
            ),
        );
        // Not records: junk, a link to one, a folder, another name.
        write("900.9", "kill 1\n".to_owned());
        write("901.0", "x".repeat(100_000));
        std::os::unix::fs::symlink(run.join("900.2"), run.join("901.1")).unwrap();
        std::fs::create_dir(run.join("901.2")).unwrap();
        write("notes.txt", line(dead, 5, kept_pid, kept_start));
        // Half written, just now and long ago.
        write("902.0.new", "meow-run 1".to_owned());
        write("902.1.new", "meow-run 1".to_owned());
        let long_ago = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(run.join("902.1.new"))
            .unwrap()
            .set_modified(long_ago)
            .unwrap();

        assert_eq!(sweep(&run), ["nmap", "nmap"]);
        assert!(!left.wait().unwrap().success(), "left running: stopped");
        assert!(
            !again.wait().unwrap().success(),
            "its session is gone, whatever has that process id now"
        );
        std::thread::sleep(Duration::from_millis(100));
        for (what, child) in [
            ("another program", &mut reused),
            ("a running session's", &mut kept),
            ("another boot's", &mut other_boot),
            ("no group leader", &mut member),
        ] {
            assert!(child.try_wait().unwrap().is_none(), "{what} was stopped");
        }
        // What was acted on or is out of date is gone; a running session's
        // record, a fresh draft and what is no record stay.
        let mut names: Vec<String> = std::fs::read_dir(&run)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["900.2", "901.2", "902.0.new", "notes.txt"]);
        // Said again, it does nothing.
        assert_eq!(sweep(&run), Vec::<String>::new());
        assert!(kept.try_wait().unwrap().is_none());

        // A folder that is not this user's own private one is no record:
        // a link to it, or nothing at all.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&run, &link).unwrap();
        write("900.0", line(dead, 5, kept_pid, kept_start));
        assert_eq!(sweep(&link), Vec::<String>::new());
        assert_eq!(sweep(&dir.path().join("none")), Vec::<String>::new());
        assert!(kept.try_wait().unwrap().is_none());
        for mut child in [reused, kept, other_boot, member] {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    #[test]
    fn a_dropped_group_takes_everything_it_started_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let tracker = Tracker::new();
        let (mut child, group) = tracker.spawn_std(&mut tool(dir.path(), &pids)).unwrap();
        let ids = started(&pids);
        assert_eq!(tracker.running(), 1);
        // Its own group, not the one the tests run in.
        // SAFETY: plain system calls.
        unsafe {
            assert_eq!(libc::getpgid(ids[0]), ids[0]);
            assert_ne!(libc::getpgid(ids[0]), libc::getpgrp());
        }
        drop(group);
        let _ = child.wait();
        for id in ids {
            wait_gone(id);
        }
        assert_eq!(tracker.running(), 0);
    }

    #[test]
    fn closing_kills_what_runs_and_starts_nothing_new() {
        let dir = tempfile::tempdir().unwrap();
        let pids = dir.path().join("pids");
        let tracker = Tracker::new();
        let (mut child, group) = tracker.spawn_std(&mut tool(dir.path(), &pids)).unwrap();
        let ids = started(&pids);
        assert!(!tracker.is_closed());

        tracker.close();
        assert!(tracker.is_closed());
        let _ = child.wait();
        for id in ids {
            wait_gone(id);
        }
        let refused = tracker.spawn_std(&mut tool(dir.path(), &pids));
        assert!(refused.is_err());
        // Listed until its owner lets go of it.
        assert_eq!(tracker.running(), 1);
        drop(group);
        assert_eq!(tracker.running(), 0);
        // Another session's tracker is not this one's.
        assert!(!Tracker::new().is_closed());
    }
}
