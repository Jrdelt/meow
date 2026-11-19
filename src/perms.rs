//! Whether an account other than this user could change a file or folder:
//! write permission for others, for a group that is not this user's alone,
//! or an access list (ACL) entry that lets someone else write.
//!
//! A folder another account can write to lets that account rename what is
//! in it and put something of its own in its place, whatever the
//! permissions of the entries themselves. meow keeps sessions, and runs
//! code it updates, only in places no other account can change that way.

#[cfg(unix)]
pub use unix::others_can_change;

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

    /// Whether an account other than this user could change `path`, whose
    /// metadata is `meta`: write permission for others, for a group that is
    /// not this user's alone, or an access list entry that lets someone
    /// else write. When the access list cannot be read, the answer is yes.
    /// A sticky folder still counts: callers that accept one (like `/tmp`
    /// above a folder) look at that bit themselves.
    pub fn others_can_change(path: &Path, meta: &Metadata) -> bool {
        let mode = meta.mode();
        if mode & 0o002 != 0 {
            return true;
        }
        if meta.file_type().is_symlink() {
            // A link has no access list; what matters is its folder.
            return false;
        }
        match acl_lets_others_write(path, meta) {
            Ok(Acl::Says(writes)) => writes,
            // Without an access list the group bits are the group's.
            Ok(Acl::None) => mode & 0o020 != 0 && !group_is_private(meta.gid()),
            // One may be kept where it cannot be read: any group counts.
            Ok(Acl::Unknown) => mode & 0o020 != 0,
            Err(_) => true,
        }
    }

    /// What an item's access list says.
    enum Acl {
        /// It has one, which lets others write or not.
        Says(bool),
        /// It has none, or its file system keeps none.
        None,
        /// Its file system may keep one that cannot be read here (NFS
        /// without one shown, FUSE): its mode bits may not tell it all.
        #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
        Unknown,
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

    /// What the access list of `path` says. Read as POSIX one, or as the
    /// NFSv4 one an NFS mount shows instead. An SMB share keeps its list on
    /// the server, where this cannot read it, and its mode bits are made
    /// up by the mount: that is an error (others may write).
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
                        Xattr::Missing | Xattr::Unsupported => Ok(Acl::Unknown),
                    },
                    Mount::Smb => Err(io::Error::other(
                        "an SMB share keeps its access list on the server",
                    )),
                    Mount::Fuse => Ok(Acl::Unknown),
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

    #[cfg(target_os = "macos")]
    fn acl_lets_others_write(path: &Path, _meta: &Metadata) -> io::Result<Acl> {
        use std::ffi::{c_char, c_int, c_void};
        /// `ACL_TYPE_EXTENDED` in `<sys/acl.h>`.
        const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
        extern "C" {
            fn acl_get_link_np(path: *const c_char, kind: c_int) -> *mut c_void;
            fn acl_to_text(acl: *mut c_void, len: *mut isize) -> *mut c_char;
            fn acl_free(item: *mut c_void) -> c_int;
        }
        let path = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: a valid C string; the result is freed below.
        let acl = unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) };
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
        // SAFETY: allocated by `acl_get_link_np`, freed once.
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
