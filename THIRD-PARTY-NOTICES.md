# Third-Party Notices

meow itself is released under the MIT License (see [LICENSE](LICENSE)). It also
uses or downloads the following third-party parts, under their own licenses.

1. Cytoscape.js (`assets/cytoscape.min.js`, `assets/cytoscape.LICENSE`)
   Copyright (c) 2016-2025, The Cytoscape Consortium.
   Licensed under the MIT License (full text in `assets/cytoscape.LICENSE` and
   `THIRD-PARTY-CYTOSCAPE.LICENSE` in release archives).

2. DB-IP IP-to-City and IP-to-ASN Lite (`~/.meow/geo/dbip-city-lite.mmdb` and
   `~/.meow/geo/dbip-asn-lite.mmdb`, downloaded on demand by `install.sh`,
   `install.ps1`, and `meow tools`)
   IP Geolocation by DB-IP (https://db-ip.com).
   Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0:
   https://creativecommons.org/licenses/by/4.0/).

3. EOX Sentinel-2 cloudless satellite tiles (fetched on demand when
   `[location] enabled = true` and `map = true`)
   Default `s2cloudless_3857` (2016) layer:
   Sentinel-2 cloudless - https://s2maps.eu by EOX IT Services GmbH
   (Contains modified Copernicus Sentinel data 2016 & 2017), licensed under
   Creative Commons Attribution 4.0 International (CC BY 4.0).
   Note: EOX annual layers from 2017 onward (`s2cloudless-2017` and newer) are
   licensed under CC BY-NC-SA 4.0 unless commercially licensed from EOX
   (https://cloudless.eox.at).

4. SecLists `Discovery/Web-Content/common.txt` (`~/.meow/wordlists/common.txt`
   and Homebrew `pkgshare/wordlists/common.txt`, downloaded on demand)
   Copyright (c) Daniel Miessler and contributors
   (https://github.com/danielmiessler/SecLists).
   Licensed under the MIT License.
