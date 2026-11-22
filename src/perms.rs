//! Whether an account other than this user could change a file or folder:
//! write permission for others, for a group that is not this user's alone,
//! or an access list (ACL) entry that lets someone else write.
//!
//! A folder another account can write to lets that account rename what is
//! in it and put something of its own in its place, whatever the
//! permissions of the entries themselves. meow keeps sessions, and runs
//! code it updates, only in places no other account can change that way.
//!
//! On Windows the same is read from an item's owner and access list
//! ([`foreign`]).

#[cfg(unix)]
pub use unix::{others_can_change, why_others_can_change};
#[cfg(windows)]
pub use windows::foreign;

/// Why an account other than this user could change a file or folder.
#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Write permission for all others, or an access list entry that lets
    /// another account write.
    Others,
    /// Write permission for a group other users are in.
    Group,
    /// Who may write cannot be read here (an SMB share keeps its access
    /// list on the server): the item is taken as others may.
    Unreadable(&'static str),
}

#[cfg(any(unix, test))]
impl Why {
    /// The reason in a few words, for `what` ("it", "a folder above it").
    pub fn says(self, what: &str) -> String {
        match self {
            Why::Others => format!("other users can write to {what}"),
            Why::Group => format!("a group shared with other users can write to {what}"),
            Why::Unreadable(place) => format!("meow cannot read who may write to {what} ({place})"),
        }
    }
}

/// What an item's access list says.
#[cfg(any(unix, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Acl {
    /// It has one, which lets others write or not.
    Says(bool),
    /// It has none, or its file system keeps none.
    None,
    /// Its file system may keep one that cannot be read here (NFS
    /// without one shown, FUSE): its mode bits may not tell it all.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android", test)),
        allow(dead_code)
    )]
    Unknown(&'static str),
    /// Its file system keeps one where it cannot be read, and makes up the
    /// mode bits (an SMB share): nothing here tells who may write.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android", test)),
        allow(dead_code)
    )]
    Hidden(&'static str),
}

/// Why others could change an item with these mode bits, owning group and
/// access list (`None` when it could not be read), if they could. On macOS
/// (`additive`) an access list is checked first and the mode bits still
/// grant what it does not decide, so group write counts beside it; a
/// Linux access list holds the group bits itself.
#[cfg(any(unix, test))]
fn why_from(
    mode: u32,
    gid: u32,
    acl: Option<Acl>,
    additive: bool,
    private: impl Fn(u32) -> bool,
) -> Option<Why> {
    if mode & 0o002 != 0 {
        return Some(Why::Others);
    }
    let group_writes = mode & 0o020 != 0;
    let shared_group = || (group_writes && !private(gid)).then_some(Why::Group);
    match acl {
        Some(Acl::Says(true)) => Some(Why::Others),
        Some(Acl::Says(false)) if additive => shared_group(),
        Some(Acl::Says(false)) => None,
        // Without an access list the group bits are the group's.
        Some(Acl::None) => shared_group(),
        // One may be kept where it cannot be read: any group counts.
        Some(Acl::Unknown(place)) => group_writes.then_some(Why::Unreadable(place)),
        Some(Acl::Hidden(place)) => Some(Why::Unreadable(place)),
        None => Some(Why::Unreadable("an unreadable access list")),
    }
}

/// Write permission in a permission set (`rwx` = 4, 2, 1).
#[cfg(any(target_os = "linux", target_os = "android", test))]
const WRITE: u16 = 0o2;

/// One entry of a Linux access list (`system.posix_acl_access`).
#[cfg(any(target_os = "linux", target_os = "android", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PosixEntry {
    tag: u16,
    perm: u16,
    id: u32,
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
mod posix_tag {
    pub const USER_OBJ: u16 = 0x01;
    pub const USER: u16 = 0x02;
    pub const GROUP_OBJ: u16 = 0x04;
    pub const GROUP: u16 = 0x08;
    pub const MASK: u16 = 0x10;
    pub const OTHER: u16 = 0x20;
}

/// The entries of a `system.posix_acl_access` value: a version (2), then
/// eight bytes per entry, all little-endian. `None` for anything else.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_posix_acl(bytes: &[u8]) -> Option<Vec<PosixEntry>> {
    let (version, rest) = bytes.split_first_chunk::<4>()?;
    let (entries, left) = rest.as_chunks::<8>();
    if u32::from_le_bytes(*version) != 2 || !left.is_empty() {
        return None;
    }
    Some(
        entries
            .iter()
            .map(|[t0, t1, p0, p1, i0, i1, i2, i3]| PosixEntry {
                tag: u16::from_le_bytes([*t0, *t1]),
                perm: u16::from_le_bytes([*p0, *p1]),
                id: u32::from_le_bytes([*i0, *i1, *i2, *i3]),
            })
            .collect(),
    )
}

/// Whether a Linux access list lets anyone but `me` write. The owning
/// group (`owner_gid`) and named groups count unless `private` says the
/// group is this user's alone. Named entries and the owning group are
/// limited by the mask, as the kernel does. An entry of a kind this does
/// not know counts as letting others write.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn posix_acl_lets_others_write(
    entries: &[PosixEntry],
    me: u32,
    owner_gid: u32,
    private: impl Fn(u32) -> bool,
) -> bool {
    use posix_tag::*;
    let mask = entries
        .iter()
        .find(|entry| entry.tag == MASK)
        .map_or(0o7, |entry| entry.perm);
    entries.iter().any(|entry| {
        let writes = entry.perm & WRITE != 0;
        let writes_masked = entry.perm & mask & WRITE != 0;
        match entry.tag {
            USER_OBJ | MASK => false,
            USER => entry.id != me && writes_masked,
            GROUP_OBJ => writes_masked && !private(owner_gid),
            GROUP => writes_masked && !private(entry.id),
            OTHER => writes,
            _ => true,
        }
    })
}

/// One entry of an NFSv4 access list (`system.nfs4_acl`), which the Linux
/// NFS client shows in place of a POSIX one.
#[cfg(any(target_os = "linux", target_os = "android", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Nfs4Entry {
    kind: u32,
    flags: u32,
    mask: u32,
    who: String,
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
mod nfs4 {
    pub const ALLOW: u32 = 0;
    pub const INHERIT_ONLY: u32 = 0x08;
    pub const IDENTIFIER_GROUP: u32 = 0x40;
    /// Write data (add a file), append (add a folder), delete a child,
    /// delete, write the access list, take ownership.
    pub const WRITES: u32 = 0x02 | 0x04 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000;
}

/// The entries of a `system.nfs4_acl` value (XDR, big-endian): a count,
/// then for each entry its type, flags, access mask and principal (a
/// length, then the name padded to four bytes). `None` for anything else.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_nfs4_acl(bytes: &[u8]) -> Option<Vec<Nfs4Entry>> {
    fn word(rest: &mut &[u8]) -> Option<u32> {
        let (head, tail) = rest.split_first_chunk::<4>()?;
        *rest = tail;
        Some(u32::from_be_bytes(*head))
    }
    let mut rest = bytes;
    let count = word(&mut rest)?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let (kind, flags, mask) = (word(&mut rest)?, word(&mut rest)?, word(&mut rest)?);
        let len = usize::try_from(word(&mut rest)?).ok()?;
        let padded = len.checked_add(3)? & !3;
        let name = rest.get(..len)?;
        rest = rest.get(padded..)?;
        let who = std::str::from_utf8(name).ok()?.to_owned();
        entries.push(Nfs4Entry {
            kind,
            flags,
            mask,
            who,
        });
    }
    rest.is_empty().then_some(entries)
}

/// Whether an NFSv4 access list lets anyone but the owner change the item:
/// an allow entry with a right that writes, for anyone but `OWNER@`, the
/// owning group (`owner_gid`) when `private` says it is this user's alone,
/// or this user (`me`, by number or by `my_name`). Deny entries only take
/// rights away and are not weighed; a principal this cannot match counts
/// as another account.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn nfs4_acl_lets_others_write(
    entries: &[Nfs4Entry],
    me: u32,
    my_name: Option<&str>,
    owner_gid: u32,
    private: impl Fn(u32) -> bool,
) -> bool {
    entries.iter().any(|entry| {
        if entry.kind != nfs4::ALLOW
            || entry.flags & nfs4::INHERIT_ONLY != 0
            || entry.mask & nfs4::WRITES == 0
        {
            return false;
        }
        let number = entry.who.parse::<u32>().ok();
        match entry.who.as_str() {
            "OWNER@" => false,
            "GROUP@" => !private(owner_gid),
            _ if entry.flags & nfs4::IDENTIFIER_GROUP != 0 => !number.is_some_and(&private),
            _ => {
                let mine = number == Some(me)
                    || my_name.is_some_and(|name| entry.who.split('@').next() == Some(name));
                !mine
            }
        }
    })
}

/// What a macOS access list allows that changes a file or folder.
#[cfg(any(target_os = "macos", test))]
const MACOS_WRITE_RIGHTS: &[&str] = &[
    "write",
    "append",
    "delete",
    "add_file",
    "add_subdirectory",
    "delete_child",
    "writeattr",
    "writeextattr",
    "writesecurity",
    "chown",
];

/// Whether a macOS access list, as `acl_to_text` writes it, lets anyone but
/// `me` change the item: an `allow` entry with a right that writes, for
/// another user or for a group that is not this user's alone. `deny`
/// entries (`group:everyone deny delete` on home folders) take nothing
/// away from the owner. A line this cannot read, or an account it cannot
/// name, counts as letting others write. Each entry is
/// `tag:uuid:name:id:allow|deny[,flags]:rights`:
///
/// ```text
/// !#acl 1
/// user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5:bob:501:allow,file_inherit:read,write
/// ```
#[cfg(any(target_os = "macos", test))]
fn macos_acl_lets_others_write(text: &str, me: u32, private: impl Fn(u32) -> bool) -> bool {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("!#"))
        .any(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let [tag, _uuid, _name, id, kind, ..] = fields[..] else {
                return true;
            };
            let rights = fields.get(5).copied().unwrap_or("");
            match kind.split(',').next() {
                Some("deny") => return false,
                Some("allow") => {}
                _ => return true,
            }
            if !rights
                .split(',')
                .any(|right| MACOS_WRITE_RIGHTS.contains(&right.trim()))
            {
                return false;
            }
            match (tag, id.parse::<u32>()) {
                ("user", Ok(uid)) => uid != me,
                ("group", Ok(gid)) => !private(gid),
                _ => true,
            }
        })
}

/// Whether group `gid` holds this user (`user`) alone: it has the user's
/// name, no other member, and no other account has it as primary group.
/// Anything not known counts as shared.
#[cfg(any(unix, test))]
fn is_private_group(
    group_name: Option<&str>,
    members: &[String],
    user: Option<&str>,
    other_account_has_it: bool,
) -> bool {
    match (group_name, user) {
        (Some(group), Some(user)) => {
            group == user && members.iter().all(|member| member == user) && !other_account_has_it
        }
        _ => false,
    }
}

#[cfg(unix)]
mod unix {
    use std::collections::HashMap;
    use std::ffi::{CStr, CString};
    use std::fs::Metadata;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    use super::{Acl, Why};

    /// Whether an account other than this user could change `path`, whose
    /// metadata is `meta` ([`why_others_can_change`]).
    pub fn others_can_change(path: &Path, meta: &Metadata) -> bool {
        why_others_can_change(path, meta).is_some()
    }

    /// Why an account other than this user could change `path`, whose
    /// metadata is `meta`, if it could: write permission for others, for a
    /// group that is not this user's alone, or an access list entry that
    /// lets someone else write. When the access list cannot be read, the
    /// answer is yes. The access list read is that of what `meta`
    /// describes: a link given with the metadata of what it leads to is
    /// read as that. A sticky folder still counts: callers that accept one
    /// (like `/tmp` above a folder) look at that bit themselves.
    pub fn why_others_can_change(path: &Path, meta: &Metadata) -> Option<Why> {
        let mode = meta.mode();
        if mode & 0o002 != 0 {
            return Some(Why::Others);
        }
        if meta.file_type().is_symlink() {
            // A link has no access list; what matters is its folder.
            return None;
        }
        super::why_from(
            mode,
            meta.gid(),
            acl_lets_others_write(path, meta).ok(),
            cfg!(target_os = "macos"),
            group_is_private,
        )
    }

    fn me() -> u32 {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// An extended attribute's value, or why there is none.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    enum Xattr {
        Value(Vec<u8>),
        /// The item has none.
        Missing,
        /// Its file system keeps none of that name.
        Unsupported,
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn read_xattr(path: &CStr, name: &CStr) -> io::Result<Xattr> {
        const MAX: usize = 64 * 1024;
        let mut value = vec![0u8; 256];
        loop {
            // SAFETY: valid C strings, and a buffer of `value.len()` bytes.
            let got = unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            if got >= 0 {
                value.truncate(got as usize);
                return Ok(Xattr::Value(value));
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ENODATA) => return Ok(Xattr::Missing),
                Some(code) if code == libc::ENOTSUP || code == libc::EOPNOTSUPP => {
                    return Ok(Xattr::Unsupported)
                }
                Some(libc::ERANGE) if value.len() < MAX => value.resize(MAX, 0),
                _ => return Err(error),
            }
        }
    }

    /// The kinds of file system whose access lists are not POSIX ones.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    enum Mount {
        Nfs,
        Smb,
        Fuse,
        Other,
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn mount_of(path: &CStr) -> io::Result<Mount> {
        // SAFETY: zeroed is a valid `statfs`; it is filled by the call.
        let mut info: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: a valid C string and a pointer to a `statfs`.
        if unsafe { libc::statfs(path.as_ptr(), &mut info) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // The magic numbers in <linux/magic.h>; only the low 32 bits count.
        Ok(match info.f_type as u32 {
            0x6969 => Mount::Nfs,
            0x517b | 0xff53_4d42 | 0xfe53_4d42 => Mount::Smb,
            0x6573_5546 => Mount::Fuse,
            _ => Mount::Other,
        })
    }

    /// What the access list of `path` says, following links. Read as POSIX
    /// one, or as the NFSv4 one an NFS mount shows instead. An SMB share
    /// keeps its list on the server, where this cannot read it, and its
    /// mode bits are made up by the mount: others may write.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn acl_lets_others_write(path: &Path, meta: &Metadata) -> io::Result<Acl> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let value = match read_xattr(&path, c"system.posix_acl_access")? {
            Xattr::Value(value) => value,
            Xattr::Missing => return Ok(Acl::None),
            Xattr::Unsupported => {
                return match mount_of(&path)? {
                    Mount::Nfs => match read_xattr(&path, c"system.nfs4_acl")? {
                        Xattr::Value(value) => {
                            let entries = super::parse_nfs4_acl(&value)
                                .ok_or_else(|| io::Error::other("unreadable access list"))?;
                            Ok(Acl::Says(super::nfs4_acl_lets_others_write(
                                &entries,
                                me(),
                                user_name(me()).as_deref(),
                                meta.gid(),
                                group_is_private,
                            )))
                        }
                        Xattr::Missing | Xattr::Unsupported => Ok(Acl::Unknown("an NFS share")),
                    },
                    // It keeps its access list on the server.
                    Mount::Smb => Ok(Acl::Hidden("an SMB share")),
                    Mount::Fuse => Ok(Acl::Unknown("a FUSE file system")),
                    Mount::Other => Ok(Acl::None),
                };
            }
        };
        let entries = super::parse_posix_acl(&value)
            .ok_or_else(|| io::Error::other("unreadable access list"))?;
        Ok(Acl::Says(super::posix_acl_lets_others_write(
            &entries,
            me(),
            meta.gid(),
            group_is_private,
        )))
    }

    /// What the access list of `path` says, following links as the
    /// metadata callers pass does. It adds to the mode bits (see
    /// [`super::why_from`]).
    #[cfg(target_os = "macos")]
    fn acl_lets_others_write(path: &Path, _meta: &Metadata) -> io::Result<Acl> {
        use std::ffi::{c_char, c_int, c_void};
        /// `ACL_TYPE_EXTENDED` in `<sys/acl.h>`.
        const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
        extern "C" {
            fn acl_get_file(path: *const c_char, kind: c_int) -> *mut c_void;
            fn acl_to_text(acl: *mut c_void, len: *mut isize) -> *mut c_char;
            fn acl_free(item: *mut c_void) -> c_int;
        }
        let path = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: a valid C string; the result is freed below.
        let acl = unsafe { acl_get_file(path.as_ptr(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            // ENOENT: no access list. The others: none can be kept there.
            return match error.raw_os_error() {
                Some(libc::ENOENT | libc::EINVAL | libc::ENOTSUP | libc::ENOSYS) => Ok(Acl::None),
                _ => Err(error),
            };
        }
        // SAFETY: `acl` is a valid access list; the text is freed below.
        let text = unsafe { acl_to_text(acl, std::ptr::null_mut()) };
        let read = if text.is_null() {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: `acl_to_text` returns a NUL-terminated string.
            let owned = unsafe { CStr::from_ptr(text) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: allocated by `acl_to_text`, freed once.
            unsafe { acl_free(text.cast()) };
            Ok(owned)
        };
        // SAFETY: allocated by `acl_get_file`, freed once.
        unsafe { acl_free(acl) };
        Ok(Acl::Says(super::macos_acl_lets_others_write(
            &read?,
            me(),
            group_is_private,
        )))
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    fn acl_lets_others_write(_path: &Path, _meta: &Metadata) -> io::Result<Acl> {
        Ok(Acl::None)
    }

    #[cfg(test)]
    thread_local! {
        /// Set by tests: what [`group_is_private`] answers on this thread.
        static PRIVATE_GROUP: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    /// Runs `body` with every group counted as private (`true`) or shared.
    #[cfg(test)]
    pub fn with_private_group<T>(private: bool, body: impl FnOnce() -> T) -> T {
        let before = PRIVATE_GROUP.with(|cell| cell.replace(Some(private)));
        let result = body();
        PRIVATE_GROUP.with(|cell| cell.set(before));
        result
    }

    /// Whether only this user can be in group `gid`: the group has the
    /// user's name and no other member, and no other account has it as its
    /// primary group (a user private group). macOS gives every standard
    /// user the group `staff` (20), which is never private. Remembered per
    /// group for the life of the process.
    pub fn group_is_private(gid: u32) -> bool {
        #[cfg(test)]
        if let Some(private) = PRIVATE_GROUP.with(std::cell::Cell::get) {
            return private;
        }
        if cfg!(target_os = "macos") && gid == 20 {
            return false;
        }
        static KNOWN: OnceLock<Mutex<HashMap<u32, bool>>> = OnceLock::new();
        let known = KNOWN.get_or_init(Mutex::default);
        if let Some(&private) = known.lock().unwrap_or_else(|p| p.into_inner()).get(&gid) {
            return private;
        }
        let private = look_up_private(gid);
        known
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(gid, private);
        private
    }

    /// The user and group database is read under one lock: `getpwent`
    /// walks shared state.
    static ACCOUNTS: Mutex<()> = Mutex::new(());
    /// More accounts than any machine has: past this, the answer is "shared".
    const MAX_ACCOUNTS: usize = 1_000_000;

    fn look_up_private(gid: u32) -> bool {
        let _accounts = ACCOUNTS.lock().unwrap_or_else(|p| p.into_inner());
        let me = me();
        let user = user_name(me);
        let Some((name, members)) = group_entry(gid) else {
            return false;
        };
        let Some(other) = other_account_with_group(gid, me) else {
            return false;
        };
        super::is_private_group(Some(&name), &members, user.as_deref(), other)
    }

    fn user_name(uid: u32) -> Option<String> {
        let mut buf = vec![0 as libc::c_char; 1024];
        loop {
            // SAFETY: zeroed is a valid `passwd`; it is filled by the call.
            let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::passwd = std::ptr::null_mut();
            // SAFETY: valid pointers to an entry, a buffer of its length
            // and the result.
            let code = unsafe {
                libc::getpwuid_r(uid, &mut entry, buf.as_mut_ptr(), buf.len(), &mut found)
            };
            if code == libc::ERANGE && buf.len() < 1 << 20 {
                buf.resize(buf.len() * 4, 0);
                continue;
            }
            if code != 0 || found.is_null() || entry.pw_name.is_null() {
                return None;
            }
            // SAFETY: a NUL-terminated name inside `buf`.
            let name = unsafe { CStr::from_ptr(entry.pw_name) };
            return name.to_str().ok().map(str::to_owned);
        }
    }

    /// The name and members of group `gid`.
    fn group_entry(gid: u32) -> Option<(String, Vec<String>)> {
        let mut buf = vec![0 as libc::c_char; 4096];
        loop {
            // SAFETY: zeroed is a valid `group`; it is filled by the call.
            let mut entry: libc::group = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::group = std::ptr::null_mut();
            // SAFETY: valid pointers to an entry, a buffer of its length
            // and the result.
            let code = unsafe {
                libc::getgrgid_r(gid, &mut entry, buf.as_mut_ptr(), buf.len(), &mut found)
            };
            if code == libc::ERANGE && buf.len() < 1 << 24 {
                buf.resize(buf.len() * 4, 0);
                continue;
            }
            if code != 0 || found.is_null() || entry.gr_name.is_null() {
                return None;
            }
            // SAFETY: NUL-terminated strings inside `buf`, and a
            // NULL-terminated list of them.
            unsafe {
                let name = CStr::from_ptr(entry.gr_name).to_str().ok()?.to_owned();
                let mut members = Vec::new();
                let mut at = entry.gr_mem;
                while !at.is_null() && !(*at).is_null() {
                    members.push(CStr::from_ptr(*at).to_string_lossy().into_owned());
                    at = at.add(1);
                }
                return Some((name, members));
            }
        }
    }

    /// `Some(true)` when an account other than `me` has `gid` as primary
    /// group, `None` when the accounts cannot all be read.
    fn other_account_with_group(gid: u32, me: u32) -> Option<bool> {
        // SAFETY: walks the account database; serialised by `ACCOUNTS`.
        unsafe {
            libc::setpwent();
            let mut found = Some(false);
            let mut seen = 0usize;
            loop {
                let entry = libc::getpwent();
                if entry.is_null() {
                    break;
                }
                seen += 1;
                if seen > MAX_ACCOUNTS {
                    found = None;
                    break;
                }
                if (*entry).pw_gid == gid && (*entry).pw_uid != me {
                    found = Some(true);
                    break;
                }
            }
            libc::endpwent();
            found
        }
    }

    /// Gives account `uid` write access to `path` through an access list,
    /// as `setfacl -m u:<uid>:rwx` does. False where the file system keeps
    /// no access lists.
    #[cfg(all(test, any(target_os = "linux", target_os = "android")))]
    pub fn grant_write_acl(path: &Path, uid: u32) -> bool {
        let entry = |tag: u16, perm: u16, id: u32| {
            let mut bytes = Vec::new();
            bytes.extend(tag.to_le_bytes());
            bytes.extend(perm.to_le_bytes());
            bytes.extend(id.to_le_bytes());
            bytes
        };
        let mut acl = 2u32.to_le_bytes().to_vec();
        acl.extend(entry(0x01, 7, u32::MAX));
        acl.extend(entry(0x02, 7, uid));
        acl.extend(entry(0x04, 5, u32::MAX));
        acl.extend(entry(0x10, 7, u32::MAX));
        acl.extend(entry(0x20, 5, u32::MAX));
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid C strings and a buffer of the length given.
        let set = unsafe {
            libc::setxattr(
                path.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        if set != 0 {
            eprintln!(
                "note: no access lists here ({}); skipping",
                io::Error::last_os_error()
            );
        }
        set == 0
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn others_write_bits_and_shared_groups_count() {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("d");
            std::fs::create_dir(&dir).unwrap();
            let check = |mode: u32| {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
                let meta = std::fs::metadata(&dir).unwrap();
                (
                    with_private_group(true, || others_can_change(&dir, &meta)),
                    with_private_group(false, || others_can_change(&dir, &meta)),
                )
            };
            assert_eq!(check(0o700), (false, false));
            assert_eq!(check(0o755), (false, false));
            // Group write: only a group that is the user's alone is fine.
            assert_eq!(check(0o775), (false, true));
            assert_eq!(check(0o2775), (false, true));
            assert_eq!(check(0o757), (true, true));
            assert_eq!(check(0o1777), (true, true));
        }

        #[test]
        fn the_users_own_group_is_looked_up_without_failing() {
            // Whatever this machine's accounts are, the answer is stable.
            // SAFETY: no preconditions.
            let gid = unsafe { libc::getegid() };
            assert_eq!(group_is_private(gid), group_is_private(gid));
            if cfg!(target_os = "macos") {
                assert!(!group_is_private(20));
            }
            // A group nobody has.
            assert!(!group_is_private(4_294_967_000));
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[test]
        fn a_linux_access_list_that_lets_another_account_write_counts() {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("d");
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            if !grant_write_acl(&dir, me().wrapping_add(4242)) {
                return;
            }
            let meta = std::fs::metadata(&dir).unwrap();
            // The mode shows the mask (rwx) in the group bits.
            assert_eq!(meta.mode() & 0o777, 0o775);
            assert!(with_private_group(true, || others_can_change(&dir, &meta)));
            // Once the mask takes write away, nobody else can write.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let meta = std::fs::metadata(&dir).unwrap();
            assert!(!with_private_group(false, || others_can_change(
                &dir, &meta
            )));
        }
    }
}

/// What keeps a file or folder on Windows from being this user's alone.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Foreign {
    /// Another account owns it: an owner can always let itself write.
    Owner,
    /// An entry of its access list lets another account change it.
    Writable,
}

/// A Windows security identifier (SID): its authority and sub-authorities.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sid {
    authority: u64,
    subs: Vec<u32>,
}

#[cfg(any(windows, test))]
impl Sid {
    /// The SID at the start of `bytes`, and its length: revision 1, the
    /// number of sub-authorities, the authority in six big-endian bytes,
    /// then each sub-authority in four little-endian ones.
    fn parse(bytes: &[u8]) -> Option<(Self, usize)> {
        let &[revision, count, ..] = bytes else {
            return None;
        };
        let len = 8 + 4 * usize::from(count);
        if revision != 1 || count > 15 || bytes.len() < len {
            return None;
        }
        let authority = bytes[2..8]
            .iter()
            .fold(0u64, |value, &byte| (value << 8) | u64::from(byte));
        let subs = bytes[8..len]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect();
        Some((Self { authority, subs }, len))
    }

    /// This user, or an account that can change any file anyway: SYSTEM,
    /// Administrators and TrustedInstaller.
    fn is_trusted_owner(&self, user: &Self) -> bool {
        self == user
            || matches!(
                (self.authority, self.subs.as_slice()),
                (5, [18])
                    | (5, [32, 544])
                    | (
                        5,
                        [
                            80,
                            956_008_885,
                            3_418_522_649,
                            1_831_038_044,
                            1_853_292_631,
                            2_271_478_464
                        ]
                    )
            )
    }

    /// [`Sid::is_trusted_owner`], or CREATOR OWNER and OWNER RIGHTS, which
    /// stand for the owner (checked on its own).
    fn is_trusted_entry(&self, user: &Self) -> bool {
        self.is_trusted_owner(user)
            || matches!((self.authority, self.subs.as_slice()), (3, [0 | 4]))
    }
}

/// Rights that let an account change a file or folder, what is in it, or
/// who may: write or append (in a folder: add a file or folder), delete it
/// or what is in it, change its access list or owner, and the generic
/// rights that hold these.
#[cfg(any(windows, test))]
const CHANGE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA, FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// What a self-relative security descriptor `sd` (with owner and access
/// list) says keeps what it guards from being `user`'s alone: an owner
/// other than [`Sid::is_trusted_owner`], or an allow entry that applies
/// to the item itself (inherited ones too; inherit-only ones do not) and
/// gives another account a right in [`CHANGE_RIGHTS`]. No access list at
/// all lets everyone in. Deny entries are not counted.
#[cfg(any(windows, test))]
fn foreign_in(sd: &[u8], user: &Sid) -> std::io::Result<Option<Foreign>> {
    const SE_DACL_PRESENT: u16 = 0x0004;
    const SE_SELF_RELATIVE: u16 = 0x8000;
    const INHERIT_ONLY_ACE: u8 = 0x08;
    let unreadable = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cannot read its access list",
        )
    };
    let u16_at = |bytes: &[u8], at: usize| {
        bytes
            .get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u32_at = |bytes: &[u8], at: usize| {
        bytes
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let offset = |at: usize| u32_at(sd, at).and_then(|value| usize::try_from(value).ok());
    let control = u16_at(sd, 2).ok_or_else(unreadable)?;
    if sd.first() != Some(&1) || control & SE_SELF_RELATIVE == 0 {
        return Err(unreadable());
    }
    let owner = offset(4)
        .filter(|&at| at != 0)
        .and_then(|at| Sid::parse(sd.get(at..)?))
        .ok_or_else(unreadable)?
        .0;
    if !owner.is_trusted_owner(user) {
        return Ok(Some(Foreign::Owner));
    }
    let dacl = offset(16).ok_or_else(unreadable)?;
    if control & SE_DACL_PRESENT == 0 || dacl == 0 {
        return Ok(Some(Foreign::Writable));
    }
    let acl = sd.get(dacl..).ok_or_else(unreadable)?;
    let size = usize::from(u16_at(acl, 2).ok_or_else(unreadable)?);
    let count = u16_at(acl, 4).ok_or_else(unreadable)?;
    let acl = acl
        .get(..size)
        .filter(|_| size >= 8)
        .ok_or_else(unreadable)?;
    let mut at = 8;
    for _ in 0..count {
        let ace = acl.get(at..).ok_or_else(unreadable)?;
        let ace_size = usize::from(u16_at(ace, 2).ok_or_else(unreadable)?);
        let ace = ace
            .get(..ace_size)
            .filter(|_| ace_size >= 8)
            .ok_or_else(unreadable)?;
        at += ace_size;
        let (kind, flags) = (ace[0], ace[1]);
        if flags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let mask = u32_at(ace, 4).ok_or_else(unreadable)?;
        let sid_at = match kind {
            // Allowed, allowed with a condition.
            0 | 9 => 8,
            // Allowed for an object type: its flags say which of two
            // GUIDs come before the SID.
            5 | 11 => {
                let object = u32_at(ace, 8).ok_or_else(unreadable)?;
                12 + 16 * usize::from(object & 1 != 0) + 16 * usize::from(object & 2 != 0)
            }
            // A compound entry (impersonation) names two accounts.
            4 if mask & CHANGE_RIGHTS != 0 => return Ok(Some(Foreign::Writable)),
            // Deny, audit and label entries let nobody write.
            _ => continue,
        };
        if mask & CHANGE_RIGHTS == 0 {
            continue;
        }
        let (sid, _) = ace
            .get(sid_at..)
            .and_then(Sid::parse)
            .ok_or_else(unreadable)?;
        if !sid.is_trusted_entry(user) {
            return Ok(Some(Foreign::Writable));
        }
    }
    Ok(None)
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::path::Path;
    use std::sync::OnceLock;

    use super::{foreign_in, Foreign, Sid};

    /// What keeps `path` from being this user's alone, read from its owner
    /// and access list ([`foreign_in`]): `None` when it is. The item is
    /// read as itself: a link is not followed.
    pub fn foreign(path: &Path) -> io::Result<Option<Foreign>> {
        foreign_in(&descriptor(path)?, current_user()?)
    }

    /// The user this process runs as.
    fn current_user() -> io::Result<&'static Sid> {
        static USER: OnceLock<Sid> = OnceLock::new();
        if let Some(user) = USER.get() {
            return Ok(user);
        }
        let user = read_current_user()?;
        Ok(USER.get_or_init(|| user))
    }

    fn read_current_user() -> io::Result<Sid> {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo handle of this process is always valid and
        // never closed; `token` is a valid place for the handle opened.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Room for a TOKEN_USER and the longest SID (68 bytes), in u64
        // words so it is aligned for the structure.
        let mut buffer = vec![0u64; 64];
        let size =
            u32::try_from(std::mem::size_of_val(buffer.as_slice())).map_err(io::Error::other)?;
        let mut used = 0u32;
        // SAFETY: the token is open for queries; the buffer is `size`
        // writable bytes, aligned for a TOKEN_USER and alive through the
        // call; `used` is a valid place for the length written.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut used,
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: the token handle is open, and closed once, here.
        unsafe {
            CloseHandle(token);
        }
        if read == 0 {
            return Err(error);
        }
        // SAFETY: the call wrote a TOKEN_USER at the start of the buffer.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // The SID it points to lies in the same buffer, after it.
        let bytes: Vec<u8> = buffer.iter().flat_map(|word| word.to_ne_bytes()).collect();
        sid.addr()
            .checked_sub(buffer.as_ptr().addr())
            .and_then(|at| Sid::parse(bytes.get(at..)?))
            .map(|(sid, _)| sid)
            .ok_or_else(|| io::Error::other("cannot read this user's SID"))
    }

    /// The owner and access list of `path`, as a self-relative security
    /// descriptor.
    fn descriptor(path: &Path) -> io::Result<Vec<u8>> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
        use windows_sys::Win32::Security::{
            GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        };
        /// A descriptor is some hundreds of bytes; one that claims to need
        /// more than this is not read.
        const MAX: u32 = 1024 * 1024;
        // Opened for its security alone, folders too, as itself (never
        // what a link points to), and in nobody's way.
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let mut size: u32 = 1024;
        for _ in 0..4 {
            // In u64 words: aligned for the descriptor.
            let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
            let mut needed = 0u32;
            // SAFETY: the handle is open until `file` is dropped; the
            // buffer is `size` writable bytes, aligned and alive through
            // the call; `needed` is a valid place for the length needed.
            let read = unsafe {
                GetKernelObjectSecurity(
                    file.as_raw_handle(),
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    buffer.as_mut_ptr().cast(),
                    size,
                    &mut needed,
                )
            };
            if read != 0 {
                return Ok(buffer
                    .iter()
                    .flat_map(|word| word.to_ne_bytes())
                    .take(size as usize)
                    .collect());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
                || needed <= size
                || needed > MAX
            {
                return Err(error);
            }
            size = needed;
        }
        Err(io::Error::other("its security descriptor keeps growing"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Runs icacls (`System32`) on `path` with `args`.
        fn icacls(path: &Path, args: &[&str]) {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
            let status =
                std::process::Command::new(Path::new(&root).join("System32").join("icacls.exe"))
                    .arg(path)
                    .args(args)
                    .stdout(std::process::Stdio::null())
                    .status()
                    .unwrap();
            assert!(status.success(), "icacls {args:?}");
        }

        #[test]
        fn a_folder_of_this_users_own_is_not_foreign() {
            let tmp = tempfile::tempdir().unwrap();
            let file = tmp.path().join("f.txt");
            std::fs::write(&file, "x").unwrap();
            assert_eq!(foreign(tmp.path()).unwrap(), None);
            assert_eq!(foreign(&file).unwrap(), None);
        }

        #[test]
        fn an_entry_that_lets_everyone_write_makes_it_foreign() {
            let tmp = tempfile::tempdir().unwrap();
            let folder = tmp.path().join("shared");
            std::fs::create_dir(&folder).unwrap();
            let file = folder.join("f.txt");
            std::fs::write(&file, "x").unwrap();
            // Everyone may change the file, read-only first.
            icacls(&file, &["/grant", "*S-1-1-0:(R)"]);
            assert_eq!(foreign(&file).unwrap(), None);
            icacls(&file, &["/grant", "*S-1-1-0:(M)"]);
            assert_eq!(foreign(&file).unwrap(), Some(Foreign::Writable));
            // As C:\ gives Authenticated Users: inherit-only on the folder,
            // which then counts for what is made in it, not for itself.
            icacls(&folder, &["/grant", "*S-1-5-11:(OI)(CI)(IO)(M)"]);
            assert_eq!(foreign(&folder).unwrap(), None);
            let made = folder.join("new.txt");
            std::fs::write(&made, "x").unwrap();
            assert_eq!(foreign(&made).unwrap(), Some(Foreign::Writable));
            icacls(&folder, &["/grant", "*S-1-5-11:(OI)(CI)(M)"]);
            assert_eq!(foreign(&folder).unwrap(), Some(Foreign::Writable));
        }

        #[test]
        fn a_link_is_read_as_itself() {
            let tmp = tempfile::tempdir().unwrap();
            let target = tmp.path().join("target");
            std::fs::create_dir(&target).unwrap();
            icacls(&target, &["/grant", "*S-1-1-0:(OI)(CI)(M)"]);
            let link = tmp.path().join("link");
            // Making a link needs a right not every account has.
            if std::os::windows::fs::symlink_dir(&target, &link).is_ok() {
                assert_eq!(foreign(&link).unwrap(), None);
            }
            assert_eq!(foreign(&target).unwrap(), Some(Foreign::Writable));
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
pub(crate) use unix::grant_write_acl;
#[cfg(unix)]
#[cfg(test)]
pub(crate) use unix::with_private_group;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_access_lists_are_read_with_their_mask() {
        use posix_tag::*;
        let entry = |tag, perm, id| PosixEntry { tag, perm, id };
        let me = 1000;
        let private = |gid: u32| gid == 1000;
        let base = [
            entry(USER_OBJ, 7, u32::MAX),
            entry(GROUP_OBJ, 5, u32::MAX),
            entry(OTHER, 5, u32::MAX),
        ];
        let with = |extra: &[PosixEntry]| {
            let mut all = base.to_vec();
            all.extend_from_slice(extra);
            all
        };
        let writes = |entries: &[PosixEntry], owner_gid| {
            posix_acl_lets_others_write(entries, me, owner_gid, private)
        };
        assert!(!writes(&base, 1000));
        // Another user with write, and the mask allows it.
        let bob = with(&[entry(USER, 7, 1001), entry(MASK, 7, u32::MAX)]);
        assert!(writes(&bob, 1000));
        // The same entry under a mask without write does nothing.
        let masked = with(&[entry(USER, 7, 1001), entry(MASK, 5, u32::MAX)]);
        assert!(!writes(&masked, 1000));
        // An entry for this user is fine; read-only for another is fine.
        assert!(!writes(
            &with(&[entry(USER, 7, me), entry(MASK, 7, u32::MAX)]),
            1000
        ));
        assert!(!writes(
            &with(&[entry(USER, 5, 1001), entry(MASK, 7, u32::MAX)]),
            1000
        ));
        // A named group: only one that is the user's alone.
        assert!(!writes(
            &with(&[entry(GROUP, 7, 1000), entry(MASK, 7, u32::MAX)]),
            1000
        ));
        assert!(writes(
            &with(&[entry(GROUP, 7, 100), entry(MASK, 7, u32::MAX)]),
            1000
        ));
        // The owning group with write, private or shared.
        let group_writes = [
            entry(USER_OBJ, 7, u32::MAX),
            entry(GROUP_OBJ, 7, u32::MAX),
            entry(OTHER, 5, u32::MAX),
        ];
        assert!(!writes(&group_writes, 1000));
        assert!(writes(&group_writes, 100));
        // Others with write; an entry of an unknown kind.
        assert!(writes(&[entry(OTHER, 7, u32::MAX)], 1000));
        assert!(writes(&[entry(0x40, 0, 0)], 1000));
    }

    #[test]
    fn linux_access_list_values_are_parsed_strictly() {
        let mut value = 2u32.to_le_bytes().to_vec();
        value.extend([0x02, 0, 7, 0, 0xe9, 0x03, 0, 0]);
        assert_eq!(
            parse_posix_acl(&value),
            Some(vec![PosixEntry {
                tag: 0x02,
                perm: 7,
                id: 1001
            }])
        );
        assert_eq!(parse_posix_acl(&value[..10]), None);
        let mut v1 = value.clone();
        v1[0] = 1;
        assert_eq!(parse_posix_acl(&v1), None);
        assert_eq!(parse_posix_acl(&[]), None);
    }

    /// An NFSv4 access list as the Linux NFS client shows it.
    fn nfs4_value(entries: &[(u32, u32, u32, &str)]) -> Vec<u8> {
        let mut value = u32::try_from(entries.len()).unwrap().to_be_bytes().to_vec();
        for (kind, flags, mask, who) in entries {
            for word in [*kind, *flags, *mask, u32::try_from(who.len()).unwrap()] {
                value.extend(word.to_be_bytes());
            }
            value.extend(who.as_bytes());
            value.resize(value.len().next_multiple_of(4), 0);
        }
        value
    }

    #[test]
    fn nfs4_access_list_values_are_parsed_strictly() {
        let value = nfs4_value(&[(0, 0, 0x16, "OWNER@"), (1, 0x40, 0x2, "staff@example.com")]);
        assert_eq!(
            parse_nfs4_acl(&value),
            Some(vec![
                Nfs4Entry {
                    kind: 0,
                    flags: 0,
                    mask: 0x16,
                    who: "OWNER@".into()
                },
                Nfs4Entry {
                    kind: 1,
                    flags: 0x40,
                    mask: 0x2,
                    who: "staff@example.com".into()
                },
            ])
        );
        assert_eq!(parse_nfs4_acl(&nfs4_value(&[])), Some(Vec::new()));
        // Cut short, padding left out, bytes left over, a count too high.
        assert_eq!(parse_nfs4_acl(&value[..value.len() - 1]), None);
        assert_eq!(parse_nfs4_acl(&value[..value.len() - 3]), None);
        let mut longer = value.clone();
        longer.extend([0, 0, 0, 0]);
        assert_eq!(parse_nfs4_acl(&longer), None);
        let mut more = value.clone();
        more[3] = 9;
        assert_eq!(parse_nfs4_acl(&more), None);
        assert_eq!(parse_nfs4_acl(&[]), None);
    }

    #[test]
    fn nfs4_access_lists_count_allow_entries_that_write() {
        const READ: u32 = 0x01 | 0x20 | 0x80 | 0x2_0000;
        const WRITE: u32 = 0x02 | 0x04 | 0x40;
        let me = 1000;
        let private = |gid: u32| gid == 1000;
        let writes = |entries: &[(u32, u32, u32, &str)], owner_gid: u32| {
            let entries = parse_nfs4_acl(&nfs4_value(entries)).unwrap();
            nfs4_acl_lets_others_write(&entries, me, Some("j"), owner_gid, private)
        };
        // What a server shows for 0755.
        let mode_755 = [
            (0, 0, READ | WRITE | 0x4_0000, "OWNER@"),
            (0, 0, READ, "GROUP@"),
            (0, 0, READ, "EVERYONE@"),
        ];
        assert!(!writes(&mode_755, 1000));
        assert!(!writes(&mode_755, 100));
        // 0775: only a group that is the user's alone.
        let mode_775 = [
            (0, 0, READ | WRITE, "OWNER@"),
            (0, 0, READ | WRITE, "GROUP@"),
        ];
        assert!(!writes(&mode_775, 1000));
        assert!(writes(&mode_775, 100));
        // Another account given write (setfacl on the server), by number or
        // by name; everyone.
        assert!(writes(&[(0, 0, WRITE, "1001")], 1000));
        assert!(writes(&[(0, 0, 0x02, "bob@example.com")], 1000));
        assert!(writes(&[(0, 0, 0x40, "EVERYONE@")], 1000));
        assert!(writes(&[(0, 0, 0x4_0000, "1001")], 1000));
        // This user, by number or by name, is fine.
        assert!(!writes(&[(0, 0, WRITE, "1000")], 100));
        assert!(!writes(&[(0, 0, WRITE, "j@example.com")], 100));
        // A named group: one the user has alone, by number; any other.
        assert!(!writes(&[(0, 0x40, WRITE, "1000")], 100));
        assert!(writes(&[(0, 0x40, WRITE, "100")], 1000));
        assert!(writes(&[(0, 0x40, WRITE, "j@example.com")], 1000));
        // Deny entries, entries only passed on to new items, and reading.
        assert!(!writes(&[(1, 0, WRITE, "1001")], 1000));
        assert!(!writes(&[(0, 0x08 | 0x01, WRITE, "1001")], 1000));
        assert!(!writes(&[(0, 0, READ, "1001")], 1000));
    }

    #[test]
    fn macos_access_lists_count_allow_entries_that_write() {
        let me = 501;
        let private = |_gid: u32| false;
        let writes = |text: &str| macos_acl_lets_others_write(text, me, private);
        let header = "!#acl 1\n";
        // The entry every home folder has.
        assert!(!writes(&format!(
            "{header}group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:delete\n"
        )));
        assert!(writes(&format!(
            "{header}user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F6:bob:502:allow:read,write\n"
        )));
        assert!(writes(&format!(
            "{header}group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:list,add_file,search\n"
        )));
        assert!(writes(&format!(
            "{header}user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F6:bob:502:allow:delete_child\n"
        )));
        // Flags follow the kind of entry.
        assert!(writes(&format!(
            "{header}user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F6:bob:502:allow,file_inherit,directory_inherit:append\n"
        )));
        assert!(!writes(&format!(
            "{header}group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny,inherited:delete\n"
        )));
        // An account the system cannot name, and a deny with no rights.
        assert!(writes(&format!(
            "{header}user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F7:::allow:write\n"
        )));
        assert!(!writes(&format!(
            "{header}user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F7:::deny\n"
        )));
        // Reading only, or this user, is fine.
        assert!(!writes(&format!(
            "{header}user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F6:bob:502:allow:read,list,search\n"
        )));
        assert!(!writes(&format!(
            "{header}user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5:me:501:allow:read,write\n"
        )));
        // A group that is the user's alone.
        assert!(!macos_acl_lets_others_write(
            "group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF000001F5:me:501:allow:write\n",
            me,
            |gid| gid == 501
        ));
        // What cannot be read counts as writing.
        assert!(writes("something odd\n"));
        assert!(writes("user:x:bob:notanumber:allow:write\n"));
        assert!(writes("user:x:bob:502:maybe:write\n"));
        assert!(!writes(header));
        assert!(!writes(""));
    }

    /// Why others could change an item, as callers say it: SMB, NFS or
    /// FUSE without a readable access list is no permission chmod fixes.
    #[test]
    fn the_reason_others_could_write_is_told() {
        let private = |gid: u32| gid == 1000;
        let staff = 20;
        let why = |mode, gid, acl, additive| why_from(mode, gid, acl, additive, private);
        // Mode bits alone.
        assert_eq!(why(0o757, 1000, Some(Acl::None), false), Some(Why::Others));
        assert_eq!(why(0o775, staff, Some(Acl::None), false), Some(Why::Group));
        assert_eq!(why(0o775, 1000, Some(Acl::None), false), None);
        assert_eq!(why(0o755, staff, Some(Acl::None), false), None);
        // A Linux access list holds the group bits itself.
        assert_eq!(why(0o775, staff, Some(Acl::Says(false)), false), None);
        assert_eq!(
            why(0o755, 1000, Some(Acl::Says(true)), false),
            Some(Why::Others)
        );
        // macOS checks its list first and the mode bits still grant what
        // the list does not decide: `everyone deny delete` on a folder
        // with group write for staff lets every staff account write.
        assert_eq!(
            why(0o775, staff, Some(Acl::Says(false)), true),
            Some(Why::Group)
        );
        assert_eq!(why(0o755, staff, Some(Acl::Says(false)), true), None);
        assert_eq!(why(0o775, 1000, Some(Acl::Says(false)), true), None);
        assert_eq!(
            why(0o755, 1000, Some(Acl::Says(true)), true),
            Some(Why::Others)
        );
        // A list kept where it cannot be read.
        assert_eq!(
            why(0o700, 1000, Some(Acl::Hidden("an SMB share")), false),
            Some(Why::Unreadable("an SMB share"))
        );
        assert_eq!(
            why(0o775, 1000, Some(Acl::Unknown("an NFS share")), false),
            Some(Why::Unreadable("an NFS share"))
        );
        assert_eq!(
            why(0o755, 1000, Some(Acl::Unknown("an NFS share")), false),
            None
        );
        assert_eq!(
            why(0o755, 1000, None, false),
            Some(Why::Unreadable("an unreadable access list"))
        );
        assert_eq!(why(0o757, 1000, None, false), Some(Why::Others));
        // As callers say it.
        assert_eq!(Why::Others.says("it"), "other users can write to it");
        assert_eq!(
            Why::Group.says("it"),
            "a group shared with other users can write to it"
        );
        assert_eq!(
            Why::Unreadable("an SMB share").says("a folder above it"),
            "meow cannot read who may write to a folder above it (an SMB share)"
        );
    }

    #[test]
    fn a_group_is_private_only_with_the_users_name_and_nobody_else() {
        let none: Vec<String> = Vec::new();
        let only_me = vec!["j".to_owned()];
        let also_bob = vec!["j".to_owned(), "bob".to_owned()];
        assert!(is_private_group(Some("j"), &none, Some("j"), false));
        assert!(is_private_group(Some("j"), &only_me, Some("j"), false));
        assert!(!is_private_group(Some("j"), &also_bob, Some("j"), false));
        assert!(!is_private_group(Some("j"), &none, Some("j"), true));
        assert!(!is_private_group(Some("users"), &none, Some("j"), false));
        assert!(!is_private_group(Some("staff"), &only_me, Some("j"), false));
        assert!(!is_private_group(None, &none, Some("j"), false));
        assert!(!is_private_group(Some("j"), &none, None, false));
    }
}

/// Windows access lists, read from bytes laid out as Windows gives them.
#[cfg(test)]
mod windows_access_list_tests {
    use super::*;

    const ME: (u64, &[u32]) = (5, &[21, 1, 2, 3, 1001]);
    const OTHER_USER: (u64, &[u32]) = (5, &[21, 1, 2, 3, 1002]);
    const SYSTEM: (u64, &[u32]) = (5, &[18]);
    const ADMINISTRATORS: (u64, &[u32]) = (5, &[32, 544]);
    const TRUSTED_INSTALLER: (u64, &[u32]) = (
        5,
        &[
            80,
            956_008_885,
            3_418_522_649,
            1_831_038_044,
            1_853_292_631,
            2_271_478_464,
        ],
    );
    const USERS: (u64, &[u32]) = (5, &[32, 545]);
    const AUTHENTICATED_USERS: (u64, &[u32]) = (5, &[11]);
    const EVERYONE: (u64, &[u32]) = (1, &[0]);
    const CREATOR_OWNER: (u64, &[u32]) = (3, &[0]);
    const OWNER_RIGHTS: (u64, &[u32]) = (3, &[4]);

    const FULL: u32 = 0x001F_01FF;
    const MODIFY: u32 = 0x0013_01BF;
    const READ_EXECUTE: u32 = 0x0012_00A9;
    const WRITE: u32 = 0x0000_0116;
    const ALLOW: u8 = 0;
    const DENY: u8 = 1;
    const INHERITED: u8 = 0x10;
    const INHERIT_ONLY: u8 = 0x08;
    const OI_CI_IO: u8 = 0x0B;

    fn sid((authority, subs): (u64, &[u32])) -> Vec<u8> {
        let mut bytes = vec![1, u8::try_from(subs.len()).unwrap()];
        bytes.extend(&authority.to_be_bytes()[2..]);
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }

    fn user() -> Sid {
        Sid::parse(&sid(ME)).unwrap().0
    }

    /// An entry: its header (type, flags, size), mask, then `body` (the SID,
    /// or what comes before it too).
    fn entry_with(kind: u8, flags: u8, mask: u32, body: &[u8]) -> Vec<u8> {
        let size = u16::try_from(8 + body.len()).unwrap();
        let mut bytes = vec![kind, flags];
        bytes.extend(size.to_le_bytes());
        bytes.extend(mask.to_le_bytes());
        bytes.extend(body);
        bytes
    }

    fn entry(kind: u8, flags: u8, mask: u32, who: (u64, &[u32])) -> Vec<u8> {
        entry_with(kind, flags, mask, &sid(who))
    }

    /// A self-relative descriptor with `owner` and, when given, an access
    /// list of `entries`.
    fn descriptor(owner: (u64, &[u32]), entries: Option<&[Vec<u8>]>) -> Vec<u8> {
        let owner = sid(owner);
        let mut control: u16 = 0x8000;
        let dacl_at = 20 + owner.len();
        let mut acl = Vec::new();
        if let Some(entries) = entries {
            control |= 0x0004;
            let body: Vec<u8> = entries.concat();
            acl.extend([2, 0]);
            acl.extend(u16::try_from(8 + body.len()).unwrap().to_le_bytes());
            acl.extend(u16::try_from(entries.len()).unwrap().to_le_bytes());
            acl.extend([0, 0]);
            acl.extend(body);
        }
        let mut bytes = vec![1, 0];
        bytes.extend(control.to_le_bytes());
        bytes.extend(20u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        let dacl_offset = if entries.is_some() { dacl_at } else { 0 };
        bytes.extend(u32::try_from(dacl_offset).unwrap().to_le_bytes());
        bytes.extend(owner);
        bytes.extend(acl);
        bytes
    }

    /// What a profile folder holds: SYSTEM, Administrators and the user.
    fn own_entries() -> Vec<Vec<u8>> {
        vec![
            entry(ALLOW, INHERITED, FULL, SYSTEM),
            entry(ALLOW, INHERITED, FULL, ADMINISTRATORS),
            entry(ALLOW, INHERITED, FULL, ME),
        ]
    }

    fn verdict(owner: (u64, &[u32]), extra: &[Vec<u8>]) -> Option<Foreign> {
        let entries: Vec<Vec<u8>> = own_entries().into_iter().chain(extra.to_vec()).collect();
        foreign_in(&descriptor(owner, Some(&entries)), &user()).unwrap()
    }

    #[test]
    fn a_folder_of_the_users_profile_is_the_users_alone() {
        assert_eq!(verdict(ME, &[]), None);
        // Owners that can change any file anyway.
        for owner in [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER] {
            assert_eq!(verdict(owner, &[]), None);
        }
        // Others may read and run.
        let read = entry(ALLOW, INHERITED, READ_EXECUTE, USERS);
        assert_eq!(verdict(ME, &[read]), None);
        // TrustedInstaller's full control, as system files have it.
        let installer = entry(ALLOW, 0, FULL, TRUSTED_INSTALLER);
        assert_eq!(verdict(ME, &[installer]), None);
    }

    #[test]
    fn another_owner_counts() {
        assert_eq!(verdict(OTHER_USER, &[]), Some(Foreign::Owner));
        assert_eq!(verdict(USERS, &[]), Some(Foreign::Owner));
    }

    /// PoC (SUP-3): a folder made under C:\ inherits Authenticated Users:
    /// Modify, so every account can change it while the owner stays the
    /// user.
    #[test]
    fn an_entry_that_lets_another_account_change_it_counts() {
        let modify = entry(ALLOW, INHERITED, MODIFY, AUTHENTICATED_USERS);
        assert_eq!(verdict(ME, &[modify]), Some(Foreign::Writable));
        let write = entry(ALLOW, 0, WRITE, EVERYONE);
        assert_eq!(verdict(ME, &[write]), Some(Foreign::Writable));
        let other = entry(ALLOW, 0, FULL, OTHER_USER);
        assert_eq!(verdict(ME, &[other]), Some(Foreign::Writable));
        // Each right that changes it, alone.
        for right in [
            0x0000_0002,
            0x0000_0004,
            0x0000_0040,
            0x0001_0000,
            0x0004_0000,
            0x0008_0000,
            0x1000_0000,
            0x4000_0000,
        ] {
            let alone = entry(ALLOW, 0, right, USERS);
            assert_eq!(verdict(ME, &[alone]), Some(Foreign::Writable), "{right:#x}");
        }
        // Rights that do not: reading, and its attributes and times.
        for right in [READ_EXECUTE, 0x0000_0100, 0x0000_0010, 0x8000_0000] {
            let harmless = entry(ALLOW, 0, right, EVERYONE);
            assert_eq!(verdict(ME, &[harmless]), None, "{right:#x}");
        }
    }

    #[test]
    fn inherit_only_entries_do_not_count_for_the_item_itself() {
        // C:\ itself: Authenticated Users may change what is made in it.
        let template = entry(ALLOW, OI_CI_IO, MODIFY, AUTHENTICATED_USERS);
        assert_eq!(verdict(ME, &[template]), None);
        let inherited_template = entry(ALLOW, INHERITED | INHERIT_ONLY, FULL, EVERYONE);
        assert_eq!(verdict(ME, &[inherited_template]), None);
        // Once it applies to the item too, it counts.
        let both = entry(ALLOW, 0x03, MODIFY, AUTHENTICATED_USERS);
        assert_eq!(verdict(ME, &[both]), Some(Foreign::Writable));
    }

    #[test]
    fn deny_entries_and_owner_placeholders_do_not_count() {
        let deny = entry(DENY, 0, FULL, EVERYONE);
        assert_eq!(verdict(ME, &[deny]), None);
        // Both stand for the owner, who is checked on its own.
        for placeholder in [CREATOR_OWNER, OWNER_RIGHTS] {
            let owner = entry(ALLOW, 0, FULL, placeholder);
            assert_eq!(verdict(ME, &[owner]), None);
        }
        let creator = entry(ALLOW, 0, FULL, CREATOR_OWNER);
        assert_eq!(verdict(OTHER_USER, &[creator]), Some(Foreign::Owner));
    }

    #[test]
    fn conditional_object_and_compound_entries_are_read() {
        // Allowed with a condition: the SID, then the condition.
        let mut body = sid(EVERYONE);
        body.extend([0x61, 0x72, 0x74, 0x78]);
        let callback = entry_with(9, 0, MODIFY, &body);
        assert_eq!(verdict(ME, &[callback]), Some(Foreign::Writable));
        // Allowed for an object type, with each of its GUIDs or none.
        for flags in [0u32, 1, 2, 3] {
            let mut body = flags.to_le_bytes().to_vec();
            let guids = usize::from(flags & 1 != 0) + usize::from(flags & 2 != 0);
            body.extend(vec![0xAB; 16 * guids]);
            body.extend(sid(EVERYONE));
            for kind in [5, 11] {
                let object = entry_with(kind, 0, MODIFY, &body);
                assert_eq!(
                    verdict(ME, &[object]),
                    Some(Foreign::Writable),
                    "{kind} {flags}"
                );
            }
            let mut mine = flags.to_le_bytes().to_vec();
            mine.extend(vec![0xAB; 16 * guids]);
            mine.extend(sid(ME));
            assert_eq!(verdict(ME, &[entry_with(5, 0, MODIFY, &mine)]), None);
        }
        let compound = entry_with(4, 0, MODIFY, &[0; 20]);
        assert_eq!(verdict(ME, &[compound]), Some(Foreign::Writable));
        let compound_read = entry_with(4, 0, READ_EXECUTE, &[0; 20]);
        assert_eq!(verdict(ME, &[compound_read]), None);
        // Audit and label entries let nobody write.
        let label = entry(0x11, 0, 0x1, (16, &[12288]));
        assert_eq!(verdict(ME, &[label]), None);
    }

    #[test]
    fn no_access_list_lets_everyone_in_and_an_empty_one_nobody() {
        let none = descriptor(ME, None);
        assert_eq!(foreign_in(&none, &user()).unwrap(), Some(Foreign::Writable));
        let empty = descriptor(ME, Some(&[]));
        assert_eq!(foreign_in(&empty, &user()).unwrap(), None);
        // Present, but at offset 0: none either.
        let mut zero = descriptor(ME, Some(&[]));
        zero[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(foreign_in(&zero, &user()).unwrap(), Some(Foreign::Writable));
    }

    #[test]
    fn a_descriptor_that_cannot_be_read_is_an_error() {
        let good = descriptor(ME, Some(&own_entries()));
        assert_eq!(foreign_in(&good, &user()).unwrap(), None);
        // Cut short anywhere.
        for len in 0..good.len() {
            assert!(foreign_in(&good[..len], &user()).is_err(), "{len}");
        }
        let mut changed = good.clone();
        changed[0] = 2;
        assert!(foreign_in(&changed, &user()).is_err(), "revision");
        let mut absolute = good.clone();
        absolute[3] &= 0x7F;
        assert!(foreign_in(&absolute, &user()).is_err(), "not self-relative");
        let mut no_owner = good.clone();
        no_owner[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(foreign_in(&no_owner, &user()).is_err(), "no owner");
        let mut more = good.clone();
        let dacl = 20 + sid(ME).len();
        more[dacl + 4] += 1;
        assert!(foreign_in(&more, &user()).is_err(), "an entry too many");
        let mut long_sid = sid(ME);
        long_sid[1] = 16;
        assert!(Sid::parse(&long_sid).is_none());
        assert_eq!(Sid::parse(&sid(ME)).unwrap().1, 28);
        assert_eq!(
            user(),
            Sid {
                authority: 5,
                subs: vec![21, 1, 2, 3, 1001]
            }
        );
    }
}
