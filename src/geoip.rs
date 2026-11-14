//! Where a scanned server is, from a location database on this disk: DB-IP
//! Lite (CC BY 4.0), downloaded by `install.sh` into `~/.meow/geo`. The
//! address is looked up in the files; nothing is sent anywhere.
//!
//! The files are read for each lookup and let go again (the city file is
//! about 135 MB), so a session does not hold them; the coordinator keeps
//! the answers.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
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

/// The database files in `dir` (`~/.meow/geo`).
#[derive(Debug, Clone)]
pub struct GeoDb {
    dir: PathBuf,
}

impl GeoDb {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// Whether the city file is there to look in.
    pub fn available(&self) -> bool {
        self.dir.join(CITY_FILE).is_file()
    }

    /// Where `address` is, by the files; `None` when they do not know it.
    /// Slow-ish (it reads the files): call it off the async threads.
    pub fn lookup(&self, address: IpAddr) -> Result<Option<Place>> {
        let city = maxminddb::Reader::open_readfile(self.dir.join(CITY_FILE))
            .context("cannot read the location database")?;
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
        let sane = latitude.is_finite()
            && longitude.is_finite()
            && (-90.0..=90.0).contains(&latitude)
            && (-180.0..=180.0).contains(&longitude);
        if !sane {
            return Ok(None);
        }
        // The network is a bonus: without the ASN file the place still stands.
        let network = maxminddb::Reader::open_readfile(self.dir.join(ASN_FILE))
            .ok()
            .and_then(|asn| asn.lookup(address).ok()?.decode::<AsnRecord>().ok()?)
            .and_then(|asn| {
                let name = asn
                    .autonomous_system_organization
                    .map(|name| sanitize(&name, FIELD_MAX));
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

/// Whether `address` can only be on a local network (no place of its own).
pub fn is_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                // Carrier-grade NAT, 100.64.0.0/10.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique local fc00::/7 and link-local fe80::/10.
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_addresses_have_no_place_of_their_own() {
        for local in [
            "192.168.0.153",
            "10.0.22.140",
            "172.16.1.4",
            "100.64.3.2",
            "127.0.0.1",
            "169.254.1.1",
            "fe80::1",
            "fd12:3456::1",
            "::1",
        ] {
            assert!(is_local(local.parse().unwrap()), "{local}");
        }
        for public in ["8.8.8.8", "203.0.113.7", "2001:4860:4860::8888"] {
            assert!(!is_local(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn without_the_files_there_is_nothing_to_look_in() {
        let dir = tempfile::tempdir().unwrap();
        let db = GeoDb::new(dir.path());
        assert!(!db.available());
        let error = db.lookup("8.8.8.8".parse().unwrap()).unwrap_err();
        assert!(format!("{error:#}").contains("cannot read the location database"));
    }
}
