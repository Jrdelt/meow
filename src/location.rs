//! Where this machine roughly is: the estimated place of its public address.
//!
//! A private address (192.168.x.x, 10.x.x.x) has no location, so the
//! estimate needs the address the rest of the world sees, which only an
//! outside service can tell. The request carries nothing about the operator
//! or the targets: it has no parameters, and the service learns only the
//! address it comes from. It is made when the map asks for it, then again
//! only when this machine's network changes. While a VPN carries all
//! traffic nothing is looked up: the answer would be the VPN's exit.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::evidence::sanitize;
use crate::graph::LocalNet;
use crate::observer;

/// Answers with the caller's public address and its estimated place.
pub const LOOKUP_URL: &str = "https://ipinfo.io/json";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const FIELD_MAX: usize = 80;

/// `[location]` in `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocationSettings {
    pub enabled: bool,
    /// A service that answers JSON for the caller (ipinfo.io, ipapi.co,
    /// ifconfig.co and ip-api.com answers are all understood).
    pub url: String,
}

impl Default for LocationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            url: LOOKUP_URL.to_owned(),
        }
    }
}

/// An estimated place.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Place {
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    /// The public address the service saw.
    pub public_address: Option<String>,
    /// The network it belongs to, as the service names it (an ISP).
    pub network: Option<String>,
}

/// What the map shows about where this machine is.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Location {
    /// An estimate from the public address. `vpn` names VPNs that are up
    /// but carry only some networks, so the estimate is still this
    /// machine's own connection.
    Found {
        place: Place,
        source: String,
        vpn: Vec<String>,
    },
    /// A VPN carries all traffic: nothing was looked up.
    HiddenByVpn { vpn: Vec<String> },
    /// The service did not answer, or not with a place.
    Unavailable { reason: String },
    /// Turned off in `config.toml`.
    Off,
}

/// What to do for the network as it is now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Off,
    Hidden(Vec<String>),
    Lookup { partial_vpns: Vec<String> },
}

pub fn plan(settings: &LocationSettings, local: &LocalNet) -> Plan {
    if !settings.enabled {
        return Plan::Off;
    }
    let vpns = observer::active_vpns(local);
    let all: Vec<String> = vpns
        .iter()
        .filter(|(_, all)| *all)
        .map(|(name, _)| name.clone())
        .collect();
    if !all.is_empty() {
        return Plan::Hidden(all);
    }
    Plan::Lookup {
        partial_vpns: vpns.into_iter().map(|(name, _)| name).collect(),
    }
}

/// Changes when the answer could: another VPN, gateway or address.
pub fn network_key(local: &LocalNet) -> String {
    let vpns: Vec<String> = observer::active_vpns(local)
        .into_iter()
        .map(|(name, all)| format!("{name}:{all}"))
        .collect();
    let mut gateways: Vec<String> = local
        .routes
        .iter()
        .filter(|route| observer::is_default_route(route))
        .map(|route| {
            format!(
                "{}@{}",
                route.gateway.as_deref().unwrap_or("-"),
                route.interface
            )
        })
        .collect();
    gateways.sort();
    format!(
        "{}|{}|{}",
        vpns.join(","),
        gateways.join(","),
        observer::primary_address(local).unwrap_or_default()
    )
}

fn text(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(|found| sanitize(found, FIELD_MAX))
        .filter(|found| !found.is_empty())
}

fn number(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| {
        let found = value.get(*key)?;
        found
            .as_f64()
            .or_else(|| found.as_str().and_then(|s| s.trim().parse().ok()))
    })
}

/// Reads a lookup service's answer. `None` when it holds no usable place
/// (no coordinates, or the service says the address is private).
pub fn parse(value: &Value) -> Option<Place> {
    if value.get("bogon").and_then(Value::as_bool) == Some(true)
        || value.get("status").and_then(Value::as_str) == Some("fail")
    {
        return None;
    }
    let (latitude, longitude) = match value.get("loc").and_then(Value::as_str) {
        // ipinfo.io: "47.6588,-117.4260"
        Some(loc) => {
            let (lat, lon) = loc.split_once(',')?;
            (lat.trim().parse().ok()?, lon.trim().parse().ok()?)
        }
        None => (
            number(value, &["latitude", "lat"])?,
            number(value, &["longitude", "lon", "lng"])?,
        ),
    };
    let sane = latitude.is_finite()
        && longitude.is_finite()
        && (-90.0..=90.0).contains(&latitude)
        && (-180.0..=180.0).contains(&longitude);
    if !sane {
        return None;
    }
    Some(Place {
        city: text(value, &["city"]),
        region: text(value, &["region", "region_name", "regionName"]),
        country: text(value, &["country_name", "country"]),
        latitude,
        longitude,
        public_address: text(value, &["ip", "query"]),
        network: text(value, &["org", "asn_org", "isp"]),
    })
}

/// Asks the service at `url` where this machine's public address is.
pub async fn lookup(url: &str) -> Result<Place> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent("meow")
        .build()
        .context("cannot create the HTTP client")?;
    let response = http
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .context("the location service did not answer")?;
    if !response.status().is_success() {
        bail!("the location service answered HTTP {}", response.status());
    }
    let body: Value = response
        .json()
        .await
        .context("the location service sent something other than JSON")?;
    parse(&body).context("the location service's answer held no place")
}

/// The host part of `url`, to say where an estimate came from.
pub fn source(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Interface, Route};
    use serde_json::json;

    fn local(vpn_routes: &[&str]) -> LocalNet {
        let mut local = LocalNet {
            interfaces: vec![
                Interface {
                    name: "en0".into(),
                    kind: "wifi".into(),
                    up: true,
                    addresses: vec!["192.168.0.81/24".into()],
                },
                Interface {
                    name: "utun4".into(),
                    kind: "vpn".into(),
                    up: true,
                    addresses: vec!["172.16.1.4/27".into()],
                },
            ],
            ..LocalNet::default()
        };
        local.routes.push(Route {
            destination: "0.0.0.0/0".into(),
            gateway: Some("192.168.0.1".into()),
            interface: "en0".into(),
        });
        for destination in vpn_routes {
            local.routes.push(Route {
                destination: (*destination).into(),
                gateway: Some("172.16.1.1".into()),
                interface: "utun4".into(),
            });
        }
        local
    }

    #[test]
    fn a_vpn_carrying_everything_hides_the_location() {
        let settings = LocationSettings::default();
        // Split tunnel: only some networks go through the VPN, so the
        // lookup still sees this machine's own connection.
        assert_eq!(
            plan(&settings, &local(&["10.0.22.0/24"])),
            Plan::Lookup {
                partial_vpns: vec!["utun4".into()]
            }
        );
        // Full tunnel, as VPN clients usually do it: both halves.
        assert_eq!(
            plan(&settings, &local(&["0.0.0.0/1", "128.0.0.0/1"])),
            Plan::Hidden(vec!["utun4".into()])
        );
        assert_eq!(
            plan(&settings, &local(&["0.0.0.0/0"])),
            Plan::Hidden(vec!["utun4".into()])
        );
        let off = LocationSettings {
            enabled: false,
            ..LocationSettings::default()
        };
        assert_eq!(plan(&off, &local(&[])), Plan::Off);
        // The key moves when the VPN starts carrying everything.
        assert_ne!(
            network_key(&local(&["10.0.22.0/24"])),
            network_key(&local(&["0.0.0.0/1", "128.0.0.0/1"]))
        );
    }

    #[test]
    fn answers_from_the_common_services_are_understood() {
        // ipinfo.io (documentation addresses only).
        let ipinfo = json!({ "ip": "203.0.113.7", "city": "Spokane", "region": "Washington",
            "country": "US", "loc": "47.6588,-117.4260", "org": "AS64500 Example ISP" });
        let place = parse(&ipinfo).unwrap();
        assert_eq!(place.city.as_deref(), Some("Spokane"));
        assert_eq!(place.region.as_deref(), Some("Washington"));
        assert_eq!(place.country.as_deref(), Some("US"));
        assert_eq!((place.latitude, place.longitude), (47.6588, -117.426));
        assert_eq!(place.public_address.as_deref(), Some("203.0.113.7"));
        assert_eq!(place.network.as_deref(), Some("AS64500 Example ISP"));

        // ipapi.co and ifconfig.co: numbers, a full country name.
        let ipapi = json!({ "ip": "203.0.113.7", "city": "Lyon", "region": "Auvergne-Rhone-Alpes",
            "country": "FR", "country_name": "France", "latitude": 45.75, "longitude": 4.85 });
        let place = parse(&ipapi).unwrap();
        assert_eq!(
            (place.country.as_deref(), place.latitude),
            (Some("France"), 45.75)
        );
        // ip-api.com: lat/lon, regionName, query.
        let ip_api = json!({ "status": "success", "query": "203.0.113.7", "city": "Osaka",
            "regionName": "Osaka", "country": "Japan", "lat": 34.69, "lon": 135.5 });
        assert_eq!(parse(&ip_api).unwrap().region.as_deref(), Some("Osaka"));

        // No place: private address, failure, missing or impossible coordinates.
        assert_eq!(parse(&json!({ "ip": "192.168.0.81", "bogon": true })), None);
        assert_eq!(
            parse(&json!({ "status": "fail", "message": "private range" })),
            None
        );
        assert_eq!(parse(&json!({ "city": "Nowhere" })), None);
        assert_eq!(parse(&json!({ "loc": "123.0,10.0" })), None);
        // Text from the service is cleaned before it is shown.
        let hostile = json!({ "loc": "1,2", "city": "Evil\u{1b}[31mTown" });
        assert_eq!(
            parse(&hostile).unwrap().city.as_deref(),
            Some("Evil[31mTown")
        );
    }

    #[tokio::test]
    async fn lookup_asks_the_service_and_reads_its_answer() {
        use axum::{routing::get, Json, Router};
        let app = Router::new()
            .route(
                "/json",
                get(|| async {
                    Json(json!({ "ip": "203.0.113.7", "city": "Spokane", "loc": "47.6,-117.4" }))
                }),
            )
            .route("/broken", get(|| async { "not json" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let place = lookup(&format!("{base}/json")).await.unwrap();
        assert_eq!(place.city.as_deref(), Some("Spokane"));
        let error = lookup(&format!("{base}/broken")).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("other than JSON"),
            "{error:#}"
        );
        assert_eq!(source("https://ipinfo.io/json"), "ipinfo.io");
    }
}
