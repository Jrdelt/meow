//! The small satellite map around the location estimate.
//!
//! Map pictures come as tiles: 256-pixel squares of a world map in the Web
//! Mercator projection, numbered by zoom level, column and row. When an
//! estimate arrives meow fetches the few tiles around it (at most six), keeps
//! them in memory for the session and serves them to the map page itself, so
//! the page never contacts anything outside. Fetching them tells the tile
//! service roughly which area is being looked at, the area the estimate
//! already names; the requests carry nothing else.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use serde::Serialize;

/// Sentinel-2 cloudless 2016 by EOX: cloud-free satellite pictures of the
/// whole world, released under CC BY 4.0 with the credit below. (Its 2017
/// layer answers blank tiles at the zoom levels used here; later years are
/// for non-commercial use only.)
pub const TILES_URL: &str = "https://tiles.maps.eox.at/wmts/1.0.0/s2cloudless_3857/default/GoogleMapsCompatible/{z}/{y}/{x}.jpg";
const EOX_HOST: &str = "tiles.maps.eox.at";
const EOX_URL: &str = "https://cloudless.eox.at";

/// The rough area drawn around the estimate. Locating a public address
/// usually finds the right city but can be off by tens of kilometres, and
/// the lookup services do not say how sure they are.
pub const ROUGH_RADIUS_M: f64 = 25_000.0;

/// The map's size on the page, in CSS pixels (drawn round); the estimate
/// is its middle.
pub const VIEW_WIDTH: u32 = 200;
pub const VIEW_HEIGHT: u32 = 200;

const TILE_PIXELS: f64 = 256.0;
/// Zoom levels the map may be shown at; between whole levels the tiles are
/// drawn smaller. They come from the next whole level up, so they are drawn
/// at half to full size and stay sharp on dense screens.
const MIN_ZOOM: f64 = 2.0;
const MAX_ZOOM: f64 = 12.0;
/// The circle is this share of the round map across: it nearly fills it.
const CIRCLE_SHARE: f64 = 0.8;
/// A click on the map zooms this many levels closer (4 times), never past
/// `CLOSEST_ZOOM`, where the satellite pictures run out of detail.
pub const CLOSER_ZOOM: f64 = 2.0;
const CLOSEST_ZOOM: f64 = 14.0;
/// Web Mercator stops here; the poles are infinitely far away.
const MAX_LATITUDE: f64 = 85.051_128_78;
const EQUATOR_M: f64 = 40_075_016.686;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// A tile is tens of kilobytes; anything near this is not a map picture.
const PICTURE_MAX_BYTES: usize = 1024 * 1024;

/// One tile of the map, and where it is drawn.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TileSpot {
    pub z: u8,
    pub x: u32,
    pub y: u32,
    /// Its top left corner, in CSS pixels from the map's top left. Tiles
    /// stick out past the edges and are clipped there.
    pub left: f64,
    pub top: f64,
}

/// What the page needs to draw the map.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MapView {
    pub width: u32,
    pub height: u32,
    /// The size each tile is drawn at, in CSS pixels.
    pub tile_size: f64,
    pub tiles: Vec<TileSpot>,
    /// The rough area: its radius on the page and on the ground.
    pub radius: f64,
    pub radius_m: f64,
    /// The credit the pictures' licence asks for, shown with the map.
    pub credit: String,
    pub credit_url: Option<String>,
    /// The same place `CLOSER_ZOOM` levels closer, shown on a click.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closer: Option<Box<MapView>>,
}

/// A fetched tile, kept in memory and served to the map page.
#[derive(Debug, Clone)]
pub struct Picture {
    pub z: u8,
    pub x: u32,
    pub y: u32,
    pub media_type: &'static str,
    pub bytes: Bytes,
}

fn world_pixels(zoom: u8) -> f64 {
    TILE_PIXELS * f64::from(1u32 << zoom)
}

fn clamp_latitude(latitude: f64) -> f64 {
    latitude.clamp(-MAX_LATITUDE, MAX_LATITUDE)
}

/// Where a place lies on the world map at `zoom`, in pixels from the map's
/// top left corner.
pub fn world_point(latitude: f64, longitude: f64, zoom: u8) -> (f64, f64) {
    let size = world_pixels(zoom);
    let phi = clamp_latitude(latitude).to_radians();
    let x = (longitude + 180.0) / 360.0 * size;
    let y = (1.0 - phi.tan().asinh() / std::f64::consts::PI) / 2.0 * size;
    (x, y)
}

/// Metres on the ground per world map pixel, at `latitude` and `zoom`.
pub fn metres_per_pixel(latitude: f64, zoom: u8) -> f64 {
    EQUATOR_M * clamp_latitude(latitude).to_radians().cos() / world_pixels(zoom)
}

/// The zoom, with a fraction, at which the rough area is `CIRCLE_SHARE` of
/// the map's height across.
pub fn shown_zoom(latitude: f64) -> f64 {
    let across = CIRCLE_SHARE * f64::from(VIEW_HEIGHT);
    let across_at_zero = 2.0 * ROUGH_RADIUS_M / metres_per_pixel(latitude, 0);
    (across / across_at_zero).log2().clamp(MIN_ZOOM, MAX_ZOOM)
}

/// The whole zoom level the tiles for a shown zoom come from.
fn tile_zoom(shown: f64) -> u8 {
    shown.floor() as u8 + 1
}

fn round_to(value: f64, step: f64) -> f64 {
    (value / step).round() * step
}

/// The tile numbers along one axis that cover `length` pixels from `from`.
fn span(from: f64, length: f64) -> std::ops::RangeInclusive<i64> {
    let first = (from / TILE_PIXELS).floor() as i64;
    let last = ((from + length) / TILE_PIXELS).ceil() as i64 - 1;
    first..=last
}

/// The map around a place: which tiles, and where each one is drawn, with
/// the closer view a click shows.
pub fn view(latitude: f64, longitude: f64, template: &str) -> MapView {
    let mut view = view_at(latitude, longitude, template, 0.0);
    view.closer = Some(Box::new(view_at(
        latitude,
        longitude,
        template,
        CLOSER_ZOOM,
    )));
    view
}

/// The map `closer` zoom levels in from the one that shows the rough area.
fn view_at(latitude: f64, longitude: f64, template: &str, closer: f64) -> MapView {
    let shown = (shown_zoom(latitude) + closer).min(CLOSEST_ZOOM);
    let zoom = tile_zoom(shown);
    // CSS pixels per tile pixel: from a half up to (not quite) one.
    let scale = 2f64.powf(shown - f64::from(zoom));
    let (centre_x, centre_y) = world_point(latitude, longitude, zoom);
    let width = f64::from(VIEW_WIDTH) / scale;
    let height = f64::from(VIEW_HEIGHT) / scale;
    let (left, top) = (centre_x - width / 2.0, centre_y - height / 2.0);
    let columns = 1i64 << zoom;
    let mut tiles = Vec::new();
    for row in span(top, height) {
        // Above the north edge or below the south edge there is no world.
        if !(0..columns).contains(&row) {
            continue;
        }
        for column in span(left, width) {
            tiles.push(TileSpot {
                z: zoom,
                // Past the date line the map goes on round the world.
                x: column.rem_euclid(columns) as u32,
                y: row as u32,
                left: round_to((column as f64 * TILE_PIXELS - left) * scale, 0.001),
                top: round_to((row as f64 * TILE_PIXELS - top) * scale, 0.001),
            });
        }
    }
    let (credit, credit_url) = credit(template);
    MapView {
        width: VIEW_WIDTH,
        height: VIEW_HEIGHT,
        tile_size: round_to(TILE_PIXELS * scale, 0.001),
        tiles,
        radius: round_to(
            ROUGH_RADIUS_M / metres_per_pixel(latitude, zoom) * scale,
            0.1,
        ),
        radius_m: ROUGH_RADIUS_M,
        credit,
        credit_url,
        closer: None,
    }
}

/// The address of one tile.
pub fn tile_url(template: &str, z: u8, x: u32, y: u32) -> String {
    template
        .replace("{z}", &z.to_string())
        .replace("{x}", &x.to_string())
        .replace("{y}", &y.to_string())
}

fn host(template: &str) -> String {
    url::Url::parse(&tile_url(template, 0, 0, 0))
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The credit for the pictures at `template`. EOX asks for its own wording
/// with a link, naming the year of the Sentinel-2 data.
fn credit(template: &str) -> (String, Option<String>) {
    let host = host(template);
    if host == EOX_HOST {
        if let Some(rest) = template.split("s2cloudless").nth(1) {
            // `s2cloudless_3857` is 2016; later layers carry their year.
            let year = rest
                .strip_prefix('-')
                .and_then(|rest| rest.get(..4))
                .filter(|year| year.bytes().all(|b| b.is_ascii_digit()))
                .unwrap_or("2016");
            return (
                format!(
                    "EOxCloudless {EOX_URL} by EOX IT Services GmbH \
                     (Contains modified Copernicus Sentinel data {year})"
                ),
                Some(EOX_URL.to_owned()),
            );
        }
    }
    (format!("Map pictures from {host}"), None)
}

/// A tile address must be http(s) and name the zoom, column and row.
pub fn check_template(template: &str) -> Result<()> {
    for part in ["{z}", "{x}", "{y}"] {
        if !template.contains(part) {
            bail!("the map picture address '{template}' lacks {part}");
        }
    }
    let url = url::Url::parse(&tile_url(template, 0, 0, 0))
        .with_context(|| format!("the map picture address '{template}' is not a web address"))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        bail!("the map picture address '{template}' must start with https://");
    }
    Ok(())
}

/// The picture's type from its first bytes. Only JPEG and PNG are kept, so
/// nothing else is ever served to the page as a picture.
pub fn picture_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else {
        None
    }
}

async fn fetch_one(http: &reqwest::Client, template: &str, spot: &TileSpot) -> Result<Picture> {
    let mut response = http
        .get(tile_url(template, spot.z, spot.x, spot.y))
        .send()
        .await
        .context("the map picture service did not answer")?;
    if !response.status().is_success() {
        bail!(
            "the map picture service answered HTTP {}",
            response.status()
        );
    }
    let too_big = || {
        anyhow::anyhow!(
            "a map picture was larger than {} KB",
            PICTURE_MAX_BYTES / 1024
        )
    };
    if response
        .content_length()
        .is_some_and(|length| length > PICTURE_MAX_BYTES as u64)
    {
        return Err(too_big());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("a map picture was cut off")?
    {
        if bytes.len() + chunk.len() > PICTURE_MAX_BYTES {
            return Err(too_big());
        }
        bytes.extend_from_slice(&chunk);
    }
    let media_type = picture_type(&bytes)
        .context("the map picture service sent something other than a JPEG or PNG picture")?;
    Ok(Picture {
        z: spot.z,
        x: spot.x,
        y: spot.y,
        media_type,
        bytes: Bytes::from(bytes),
    })
}

/// Fetches every tile of `view` at once; all of them, or an error.
pub async fn fetch(template: &str, view: &MapView) -> Result<Vec<Picture>> {
    check_template(template)?;
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        // The picture service names the pictures; it does not get to send
        // this machine's requests on to another address.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("meow")
        .build()
        .context("cannot create the HTTP client")?;
    futures_util::future::try_join_all(
        view.tiles
            .iter()
            .map(|spot| fetch_one(&http, template, spot)),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covered(view: &MapView, x: f64, y: f64) -> bool {
        view.tiles.iter().any(|tile| {
            (tile.left..tile.left + view.tile_size).contains(&x)
                && (tile.top..tile.top + view.tile_size).contains(&y)
        })
    }

    #[test]
    fn places_land_where_web_mercator_puts_them() {
        // The middle of the world map, and its top left corner.
        assert_eq!(world_point(0.0, 0.0, 1), (256.0, 256.0));
        let (x, y) = world_point(MAX_LATITUDE, -180.0, 3);
        assert_eq!(x, 0.0);
        assert!(y.abs() < 1e-6, "{y}");
        // Beyond the projection's limit a place stays on the map's edge.
        assert_eq!(
            world_point(90.0, 10.0, 4),
            world_point(MAX_LATITUDE, 10.0, 4)
        );
        // Spokane is in tile column 44, row 89 at zoom 8, as on any web map.
        let (x, y) = world_point(47.6588, -117.426, 8);
        assert_eq!(((x / 256.0) as u32, (y / 256.0) as u32), (44, 89));
        // A pixel is 156.5 km wide at zoom 0 on the equator, half at 60°.
        assert!((metres_per_pixel(0.0, 0) - 156_543.034).abs() < 0.01);
        assert!((metres_per_pixel(60.0, 0) - 78_271.517).abs() < 0.01);
    }

    #[test]
    fn the_rough_area_always_fits_and_stays_visible() {
        let height = f64::from(VIEW_HEIGHT);
        for latitude in [
            -89.9, -85.0, -60.0, -33.9, 0.0, 29.4, 47.6588, 64.1, 78.2, 89.9,
        ] {
            let view = view(latitude, 10.0, TILES_URL);
            let across = 2.0 * view.radius;
            // The circle fills the map the same at every latitude.
            assert!(
                (across - CIRCLE_SHARE * height).abs() < 0.2,
                "{latitude}: {across}"
            );
            assert!(
                !view.tiles.is_empty() && view.tiles.len() <= 12,
                "{latitude}"
            );
            assert!((0.5..1.0).contains(&(view.tile_size / TILE_PIXELS)));
            assert!(view.tiles.iter().all(|tile| tile.y < 1 << tile.z));
            assert_eq!(view.radius_m, ROUGH_RADIUS_M);
        }
        assert_eq!(tile_zoom(shown_zoom(0.0)), 9);
        // A click goes four times closer, with tiles of its own.
        let near = view(47.6588, -117.426, TILES_URL);
        let closer = near.closer.as_deref().unwrap();
        assert_eq!(closer.tiles[0].z, tile_zoom(shown_zoom(47.6588) + 2.0));
        assert!((closer.radius / near.radius - 4.0).abs() < 0.01);
        assert!(closer.closer.is_none() && closer.tiles.len() <= 12);
        assert!(
            (shown_zoom(47.6588) - 8.40).abs() < 0.01,
            "{}",
            shown_zoom(47.6588)
        );
    }

    #[test]
    fn the_tiles_cover_the_map_and_go_on_past_the_date_line() {
        for (latitude, longitude) in [(47.6588, -117.426), (0.0, 0.0), (-33.9, 151.2)] {
            let view = view(latitude, longitude, TILES_URL);
            assert!(view
                .tiles
                .iter()
                .all(|tile| tile.z == tile_zoom(shown_zoom(latitude))));
            for y in (0..VIEW_HEIGHT).step_by(5) {
                for x in (0..VIEW_WIDTH).step_by(5) {
                    assert!(
                        covered(&view, f64::from(x), f64::from(y)),
                        "({latitude}, {longitude}): {x},{y} is not covered"
                    );
                }
            }
        }
        // Next to the date line the first column follows the last one.
        let fiji = view(-17.7, 179.95, TILES_URL);
        let last = (1u32 << fiji.tiles[0].z) - 1;
        let left_of = |x: u32| {
            fiji.tiles
                .iter()
                .find(|tile| tile.x == x)
                .map(|tile| tile.left)
                .unwrap()
        };
        assert!(left_of(0) > left_of(last));
        assert!(covered(&fiji, 0.0, 0.0) && covered(&fiji, 199.0, 199.0));
    }

    #[test]
    fn tile_addresses_and_their_credits() {
        assert_eq!(
            tile_url(TILES_URL, 9, 88, 179),
            "https://tiles.maps.eox.at/wmts/1.0.0/s2cloudless_3857/default/GoogleMapsCompatible/9/179/88.jpg"
        );
        assert!(check_template(TILES_URL).is_ok());
        assert!(check_template("http://127.0.0.1:9/{z}/{x}/{y}").is_ok());
        for bad in [
            "https://tile.example.org/{z}/{x}.png",
            "file:///tiles/{z}/{x}/{y}.png",
            "ftp://tile.example.org/{z}/{x}/{y}.png",
            "{z}/{x}/{y}",
        ] {
            assert!(check_template(bad).is_err(), "{bad}");
        }
        let eox = view(0.0, 0.0, TILES_URL);
        assert_eq!(
            eox.credit,
            "EOxCloudless https://cloudless.eox.at by EOX IT Services GmbH \
             (Contains modified Copernicus Sentinel data 2016)"
        );
        assert_eq!(eox.credit_url.as_deref(), Some("https://cloudless.eox.at"));
        let later = TILES_URL.replace("s2cloudless_3857", "s2cloudless-2024_3857");
        assert!(view(0.0, 0.0, &later).credit.ends_with("data 2024)"));
        let other = view(0.0, 0.0, "https://tile.example.org/{z}/{x}/{y}.png");
        assert_eq!(other.credit, "Map pictures from tile.example.org");
        assert_eq!(other.credit_url, None);
    }

    #[test]
    fn only_pictures_are_kept() {
        assert_eq!(
            picture_type(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10]),
            Some("image/jpeg")
        );
        assert_eq!(
            picture_type(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"),
            Some("image/png")
        );
        assert_eq!(picture_type(b"<!doctype html><script>"), None);
        assert_eq!(picture_type(b""), None);
    }

    #[tokio::test]
    async fn the_tiles_are_fetched_and_checked() {
        use axum::extract::{Path, State};
        use axum::routing::get;
        use std::sync::{Arc, Mutex};

        const JPEG: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, b'J', b'F', b'I', b'F'];
        let asked: Arc<Mutex<Vec<String>>> = Arc::default();
        let app = axum::Router::new()
            .route(
                "/ok/{z}/{x}/{y}",
                get(
                    |State(asked): State<Arc<Mutex<Vec<String>>>>,
                     Path((z, x, y)): Path<(u8, u32, u32)>,
                     uri: axum::http::Uri| async move {
                        asked.lock().unwrap().push(uri.to_string());
                        assert!(z > 0 && x < 1 << z && y < 1 << z);
                        JPEG
                    },
                ),
            )
            .route("/page/{z}/{x}/{y}", get(|| async { "<!doctype html>" }))
            .route(
                "/moved/{z}/{x}/{y}",
                get(|Path((z, x, y)): Path<(u8, u32, u32)>| async move {
                    axum::response::Redirect::to(&format!("/ok/{z}/{x}/{y}"))
                }),
            )
            .route(
                "/huge/{z}/{x}/{y}",
                get(|| async {
                    let mut huge = JPEG.to_vec();
                    huge.resize(PICTURE_MAX_BYTES + 1, 0);
                    huge
                }),
            )
            .with_state(Arc::clone(&asked));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let template = format!("{base}/ok/{{z}}/{{x}}/{{y}}");
        let view = view(47.6588, -117.426, &template);
        let pictures = fetch(&template, &view).await.unwrap();
        assert_eq!(pictures.len(), view.tiles.len());
        for (picture, spot) in pictures.iter().zip(&view.tiles) {
            assert_eq!((picture.z, picture.x, picture.y), (spot.z, spot.x, spot.y));
            assert_eq!(picture.media_type, "image/jpeg");
            assert_eq!(&picture.bytes[..], JPEG);
        }
        // Each request names one tile and nothing else.
        let mut asked = asked.lock().unwrap().clone();
        asked.sort();
        let mut expected: Vec<String> = view
            .tiles
            .iter()
            .map(|tile| format!("/ok/{}/{}/{}", tile.z, tile.x, tile.y))
            .collect();
        expected.sort();
        assert_eq!(asked, expected);

        for (path, why) in [
            ("page", "other than a JPEG or PNG"),
            ("huge", "larger than 1024 KB"),
            ("missing", "HTTP 404"),
            // A redirect is an answer, not somewhere to go.
            ("moved", "HTTP 303"),
        ] {
            let template = format!("{base}/{path}/{{z}}/{{x}}/{{y}}");
            let error = fetch(&template, &view).await.unwrap_err();
            assert!(format!("{error:#}").contains(why), "{path}: {error:#}");
        }
        let error = fetch("ftp://example.org/{z}/{x}/{y}", &view)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("https://"), "{error:#}");
    }
}
