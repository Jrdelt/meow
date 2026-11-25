//! Where a scanned server is, from a location database on this disk: DB-IP
//! Lite (CC BY 4.0), downloaded by `install.sh` into `~/.meow/geo`. The
//! address is looked up in the files; nothing is sent anywhere.
//!
//! The database readers are loaded lazily on first lookup and cached in memory
//! across lookups until the file metadata changes.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::evidence::sanitize;
use crate::location::Place;

/// The folder under `~/.meow` the database files live in.
pub const DIR: &str = "geo";
pub const CITY_FILE: &str = "dbip-city-lite.mmdb";
pub const ASN_FILE: &str = "dbip-asn-lite.mmdb";
/// The credit DB-IP's licence asks for, with its link.
pub const CREDIT: &str = "IP Geolocation by DB-IP";
pub const CREDIT_URL: &str = "https://db-ip.com";
const FIELD_MAX: usize = 80;
const MAX_CITY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ASN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize, Default)]
struct Named {
    #[serde(default)]
    names: BTreeMap<String, String>,
}

impl Named {
    fn english(&self) -> Option<String> {
        self.names
            .get("en")
            .or_else(|| self.names.values().next())
            .map(|name| sanitize(name, FIELD_MAX))
            .filter(|name| !name.is_empty())
    }
}

#[derive(Deserialize, Default)]
struct Coordinates {
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Deserialize, Default)]
struct CityRecord {
    #[serde(default)]
    city: Named,
    #[serde(default)]
    country: Named,
    #[serde(default)]
    subdivisions: Vec<Named>,
    #[serde(default)]
    location: Coordinates,
}

#[derive(Deserialize, Default)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

struct CachedReader {
    len: u64,
    modified: Option<SystemTime>,
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

#[derive(Default)]
struct GeoCache {
    city: Option<CachedReader>,
    asn: Option<CachedReader>,
}

/// The database files in `dir` (`~/.meow/geo`), loaded lazily on first use
/// and shared across lookups without re-reading ~135 MB per host.
#[derive(Clone)]
pub struct GeoDb {
    dir: Option<PathBuf>,
    cache: Arc<Mutex<GeoCache>>,
}

impl std::fmt::Debug for GeoDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoDb").field("dir", &self.dir).finish()
    }
}

fn load_mmdb(
    dir: &Path,
    name: &str,
    max_bytes: u64,
    slot: &mut Option<CachedReader>,
) -> Result<Arc<maxminddb::Reader<Vec<u8>>>> {
    let dir_meta = fs::symlink_metadata(dir).context("cannot read the location database")?;
    if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
        bail!(
            "cannot read the location database: {} is not a location database folder",
            dir.display()
        );
    }
    let path = dir.join(name);
    let meta = fs::symlink_metadata(&path).context("cannot read the location database")?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        bail!(
            "cannot read the location database: {} is not a location database file",
            path.display()
        );
    }
    if meta.len() > max_bytes {
        bail!(
            "cannot read the location database: {} is not a location database meow will load (over {} MB)",
            path.display(),
            max_bytes / (1024 * 1024)
        );
    }
    let modified = meta.modified().ok();
    if let Some(cached) = slot {
        if cached.len == meta.len() && cached.modified == modified {
            return Ok(Arc::clone(&cached.reader));
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(&path)
        .context("cannot read the location database")?;
    let opened_meta = file
        .metadata()
        .context("cannot read the location database")?;
    let len = opened_meta.len();
    if !opened_meta.is_file() || len > max_bytes {
        bail!(
            "cannot read the location database: {} is not a location database meow will load",
            path.display()
        );
    }
    let opened_modified = opened_meta.modified().ok();
    let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(max_bytes + 1)
        .read_to_end(&mut buf)
        .context("cannot read the location database")?;
    if buf.len() as u64 > max_bytes {
        bail!(
            "cannot read the location database: {} is not a location database meow will load",
            path.display()
        );
    }
    let reader =
        Arc::new(maxminddb::Reader::from_source(buf).context("cannot read the location database")?);
    *slot = Some(CachedReader {
        len,
        modified: opened_modified,
        reader: Arc::clone(&reader),
    });
    Ok(reader)
}

impl GeoDb {
    pub fn new(dir: &Path) -> Self {
        Self::from_optional_dir(Some(dir.to_path_buf()))
    }

    pub fn from_optional_dir(dir: Option<PathBuf>) -> Self {
        Self {
            dir: dir.filter(|p| !p.as_os_str().is_empty()),
            cache: Arc::new(Mutex::new(GeoCache::default())),
        }
    }

    /// Whether the city file is there to look in.
    pub fn available(&self) -> bool {
        let Some(dir) = &self.dir else { return false };
        fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_dir())
            && fs::symlink_metadata(dir.join(CITY_FILE)).is_ok_and(|m| m.file_type().is_file())
    }

    /// Where `address` is, by the files; `None` when they do not know it.
    pub fn lookup(&self, address: IpAddr) -> Result<Option<Place>> {
        let address = address.to_canonical();
        let dir = self
            .dir
            .as_deref()
            .context("cannot read the location database")?;
        let (city, asn_reader) = {
            let mut guard = self
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let city = load_mmdb(dir, CITY_FILE, MAX_CITY_BYTES, &mut guard.city)?;
            let asn = load_mmdb(dir, ASN_FILE, MAX_ASN_BYTES, &mut guard.asn).ok();
            (city, asn)
        };
        let Some(found) = city
            .lookup(address)
            .context("the location database could not be searched")?
            .decode::<CityRecord>()
            .context("the location database's entry could not be read")?
        else {
            return Ok(None);
        };
        let (Some(latitude), Some(longitude)) = (found.location.latitude, found.location.longitude)
        else {
            return Ok(None);
        };
        if !is_valid_position(latitude, longitude) {
            return Ok(None);
        }
        // The network is a bonus: without the ASN file the place still stands.
        let network = asn_reader
            .and_then(|asn| asn.lookup(address).ok()?.decode::<AsnRecord>().ok()?)
            .and_then(|asn| {
                let name = asn
                    .autonomous_system_organization
                    .map(|name| sanitize(&name, FIELD_MAX))
                    .filter(|name| !name.is_empty());
                match (asn.autonomous_system_number, name) {
                    (Some(number), Some(name)) => Some(format!("AS{number} {name}")),
                    (Some(number), None) => Some(format!("AS{number}")),
                    (None, name) => name,
                }
            });
        Ok(Some(Place {
            city: found.city.english(),
            region: found.subdivisions.first().and_then(Named::english),
            country: found.country.english(),
            latitude,
            longitude,
            public_address: Some(address.to_string()),
            network,
        }))
    }
}

/// Whether `address` can only be on a local/non-public network (no place of its own).
pub fn is_local(address: IpAddr) -> bool {
    match address.to_canonical() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                // "This network" 0.0.0.0/8 (RFC 1122).
                || octets[0] == 0
                // Carrier-grade NAT, 100.64.0.0/10 (RFC 6598).
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
                // Benchmarking lab networks, 198.18.0.0/15 (RFC 2544).
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
                // Reserved future-use block, 240.0.0.0/4 (RFC 1112).
                || (octets[0] & 0xf0) == 240
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            let first = segs[0];
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local fc00::/7 and link-local fe80::/10.
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
            {
                return true;
            }
            // NAT64 Well-Known Prefix 64:ff9b::/96 (RFC 6052): check embedded IPv4.
            if segs[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
                let embedded = Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    segs[6] as u8,
                    (segs[7] >> 8) as u8,
                    segs[7] as u8,
                );
                return is_local(IpAddr::V4(embedded));
            }
            false
        }
    }
}

/// Whether `latitude` and `longitude` name a place on Earth.
pub(crate) fn is_valid_position(latitude: f64, longitude: f64) -> bool {
    latitude.is_finite()
        && longitude.is_finite()
        && (-90.0..=90.0).contains(&latitude)
        && (-180.0..=180.0).contains(&longitude)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_position_lies_on_earth() {
        assert!(is_valid_position(90.0, -180.0));
        assert!(is_valid_position(-90.0, 180.0));
        assert!(!is_valid_position(90.5, 0.0));
        assert!(!is_valid_position(0.0, -180.5));
        assert!(!is_valid_position(f64::NAN, 0.0));
        assert!(!is_valid_position(0.0, f64::INFINITY));
    }

    #[test]
    fn local_addresses_have_no_place_of_their_own() {
        for local in [
            "0.1.2.3",
            "192.168.0.153",
            "10.0.22.140",
            "172.16.1.4",
            "100.64.3.2",
            "198.18.0.5",
            "240.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "fe80::1",
            "fd12:3456::1",
            "::1",
            "::ffff:192.168.0.153",
            "::ffff:127.0.0.1",
            "64:ff9b::192.168.0.153",
            "64:ff9b::127.0.0.1",
        ] {
            assert!(is_local(local.parse().unwrap()), "{local}");
        }
        for public in [
            "8.8.8.8",
            "203.0.113.7",
            "2001:4860:4860::8888",
            "64:ff9b::8.8.8.8",
        ] {
            assert!(!is_local(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn without_the_files_there_is_nothing_to_look_in() {
        let empty = GeoDb::from_optional_dir(Some(PathBuf::new()));
        assert!(!empty.available());
        assert!(empty.lookup("8.8.8.8".parse().unwrap()).is_err());

        let dir = tempfile::tempdir().unwrap();
        let db = GeoDb::new(dir.path());
        assert!(!db.available());
        let error = db.lookup("8.8.8.8".parse().unwrap()).unwrap_err();
        assert!(format!("{error:#}").contains("cannot read the location database"));

        // A file far too large to be one is refused before it is read
        // (sparse here: it takes no disk space).
        let huge = fs::File::create(dir.path().join(CITY_FILE)).unwrap();
        huge.set_len(MAX_CITY_BYTES + 1).unwrap();
        assert!(db.available());
        let error = db.lookup("8.8.8.8".parse().unwrap()).unwrap_err();
        assert!(
            format!("{error:#}").contains("not a location database"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_pipes_are_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.mmdb");
        fs::write(&outside, b"not mmdb").unwrap();

        let geo = dir.path().join("geo");
        fs::create_dir(&geo).unwrap();
        let city = geo.join(CITY_FILE);
        std::os::unix::fs::symlink(&outside, &city).unwrap();

        let db = GeoDb::new(&geo);
        assert!(!db.available());
        assert!(db.lookup("8.8.8.8".parse().unwrap()).is_err());
        fs::remove_file(&city).unwrap();

        let c_path = std::ffi::CString::new(city.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(!db.available());
        assert!(db.lookup("8.8.8.8".parse().unwrap()).is_err());
    }
}
