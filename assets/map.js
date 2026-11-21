// meow topology map. Everything shown here comes from scanned systems, so
// text is only ever inserted with textContent, never as HTML.
(function () {
  'use strict';

  function scriptToken() {
    try {
      var script = document.currentScript;
      if (!script || !script.src) { return ''; }
      return new URL(script.src, location.href).searchParams.get('token') || '';
    } catch (_) {
      return '';
    }
  }

  var token = new URLSearchParams(location.search).get('token') || scriptToken();
  // Kept in this tab's own storage, which browsers keep apart for each
  // port, so that a reload (with the token gone from the address bar) can
  // find it again. Never a cookie: those reach every port of 127.0.0.1.
  try { if (/^[0-9a-f]{64}$/.test(token)) { sessionStorage.setItem('meow-map-token', token); } } catch (_) {}
  if (location.search && window.history && typeof window.history.replaceState === 'function') {
    window.history.replaceState(null, '', location.pathname);
  }
  // A value only the session that served this page knows. Whatever answers
  // on this port after the session has ended does not have it.
  var pageKey = (document.querySelector('meta[name="meow-page"]') || {}).content || '';
  var ended = false;
  var hasOwn = Object.prototype.hasOwnProperty;
  // Lookup tables keyed by host names and addresses: a host may be called
  // `constructor` or `__proto__`, which every plain object already has.
  function table() { return Object.create(null); }
  function own(object, key) {
    return object && hasOwn.call(object, key) ? object[key] : undefined;
  }
  var noteDrafts = table();
  var socket = null;
  var state = null;
  var selected = null;
  var drawn = '';
  var pendingAiScroll = false;
  var lastAiKey = '';

  // The map is drawn top-down, like a home-network diagram: the Internet
  // cloud at the top, your router (or access point) under it, and every
  // device on your network in one row below the router, each on its own
  // drop from one bar: solid when wired, dotted on Wi-Fi. meow can only see
  // how this machine connects, so the other devices are drawn the same way
  // (the legend says so). You come last in the row, and what only this
  // machine uses (a VPN, a virtual network) hangs below you. A long row
  // scrolls left and right instead of shrinking.
  // Plenty of room between devices, so nothing looks cluttered.
  var STEP = 250, SUB_STEP = 215;           // in the row; below you
  var YOU_Y = -360, GW_Y = -190, EGRESS_Y = -20, CLOUD_Y = 155, TARGET_Y = 365;
  var BAR_Y = 110, ROW_Y = 215;
  var traceExpanded = false;
  // Room kept around the drawing, in screen pixels, and the zooms it is
  // shown at: never blown up past MAX_ZOOM, and never shrunk below
  // READABLE_ZOOM while the card can grow taller instead (up to CARD_MAX).
  var FIT_PADDING = 40, MAX_ZOOM = 1.2, READABLE_ZOOM = 0.75, CARD_MAX = 1200;
  // Browsers refuse canvases much wider than this (CSS pixels, at 2x).
  var MAX_WIDTH = 15000;
  var askedWhere = false;

  var LINE = { wifi: '#9aa3ad', ethernet: '#9aa3ad', other: '#9aa3ad', vpn: '#1aa6b3',
    virtual: '#8a73d6', unknown: '#9aa3ad' };
  var TEXT = '#2b2f36';
  var FONT = 'system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif';

  // role, how the detail panel names it
  var ROLES = [
    ['internet', 'the Internet'],
    ['router', 'a router'],
    ['firewall', 'a firewall'],
    ['server', 'a server'],
    ['segment', 'a network'],
    ['switch', 'a switch'],
    ['client', 'a client'],
    ['you', 'you']
  ];
  var PICTURES = ROLES.map(function (role) { return role[0]; }).concat(['printer']);

  function withToken(path) {
    return token ? path + '?token=' + encodeURIComponent(token) : path;
  }

  function safeHttpUrl(url) {
    if (typeof url !== 'string' || /[\u0000-\u001f\u007f]/.test(url)) { return false; }
    try {
      var parsed = new URL(url);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (_) {
      return false;
    }
  }

  function icon(role) {
    return withToken('/assets/icon-' + role + '.svg');
  }

  var cy = cytoscape({
    container: document.getElementById('cy'),
    maxZoom: 2.2,
    minZoom: 0.05,
    // Sized and scrolled by the page (fitDrawing): the wheel and trackpad
    // scroll, they do not zoom.
    userZoomingEnabled: false,
    userPanningEnabled: false,
    boxSelectionEnabled: false,
    style: [
      { selector: 'node', style: {
        'shape': 'rectangle', 'width': 76, 'height': 60, 'background-opacity': 0, 'border-width': 0,
        'background-fit': 'contain', 'background-clip': 'none',
        'label': 'data(text)', 'font-family': FONT, 'font-size': 13, 'color': TEXT, 'line-height': 1.3,
        'text-wrap': 'wrap', 'text-max-width': 230, 'text-valign': 'bottom', 'text-halign': 'center',
        'text-margin-y': 6, 'text-background-color': '#ffffff', 'text-background-opacity': 0.92,
        'text-background-padding': 2, 'underlay-shape': 'ellipse', 'underlay-padding': 14, 'underlay-opacity': 0,
        'overlay-padding': 8, 'overlay-opacity': 0, 'z-index': 10 } }
    ].concat(PICTURES.map(function (name) {
      return { selector: 'node[icon = "' + name + '"]', style: { 'background-image': icon(name) } };
    })).concat([
      // What a device asks of you: a soft glow behind it, amber or red.
      { selector: 'node.warn', style: { 'underlay-color': '#f2b84b', 'underlay-opacity': 0.45 } },
      { selector: 'node.bad', style: { 'underlay-color': '#e5534b', 'underlay-opacity': 0.45 } },
      { selector: 'node.kev', style: { 'underlay-opacity': 0.7, 'underlay-padding': 20 } },
      { selector: 'node.none', style: { 'color': '#6b7178' } },
      { selector: 'node.you', style: { 'font-weight': 700, 'color': '#1f6fb2' } },
      { selector: 'node.hub', style: { 'width': 96, 'height': 74, 'font-size': 13.5 } },
      { selector: 'node.egress', style: {
        'width': 82, 'height': 64, 'font-size': 12.5, 'font-weight': 600, 'color': '#1f2d3d',
        'text-max-width': 260 } },
      { selector: 'node.cloud', style: {
        'width': 148, 'height': 100, 'text-valign': 'bottom', 'text-margin-y': 4, 'font-size': 13, 'font-weight': 700,
        'color': '#1f2d3d', 'text-max-width': 260 } },
      { selector: 'node.hop', style: {
        'width': 52, 'height': 42, 'font-size': 12, 'color': '#2b2f36',
        'text-halign': 'right', 'text-valign': 'center', 'text-margin-x': 10, 'text-margin-y': 0,
        'text-max-width': 360 } },
      { selector: 'node.waf', style: {
        'width': 74, 'height': 58, 'font-size': 12.5, 'font-weight': 600, 'color': '#1f5f8b',
        'text-max-width': 240 } },
      { selector: 'node.asn-box', style: {
        'shape': 'round-rectangle', 'background-color': '#f4f7fb', 'background-opacity': 0.9,
        'border-width': 2, 'border-style': 'dashed', 'border-color': '#4a6fa5',
        'padding': 26, 'text-valign': 'top', 'text-halign': 'center', 'text-margin-y': -6,
        'font-size': 13, 'font-weight': 700, 'color': '#1f2d3d', 'text-max-width': 360,
        'text-background-color': '#ffffff', 'text-background-opacity': 0.96, 'text-background-padding': 4,
        'z-index': 2 } },
      { selector: 'node.title', style: {
        'width': 1, 'height': 1, 'events': 'no', 'text-valign': 'top', 'text-halign': 'right',
        'text-margin-y': 0, 'font-weight': 700, 'font-size': 13, 'color': 'data(color)', 'text-max-width': 360 } },
      // The router's name beside it, clear of the line down to the devices.
      { selector: 'node.side', style: {
        'text-halign': 'right', 'text-valign': 'center', 'text-margin-x': 10, 'text-margin-y': 0,
        'text-justification': 'left' } },
      { selector: 'node.ownbar', style: {
        'shape': 'round-rectangle', 'height': 4, 'width': 'data(width)', 'background-opacity': 1,
        'background-color': '#9aa3ad', 'label': '', 'events': 'no' } },
      { selector: 'node.anchor', style: { 'width': 1, 'height': 1, 'label': '', 'events': 'no' } },
      { selector: 'node:selected', style: { 'overlay-color': '#1f6fb2', 'overlay-opacity': 0.14 } },
      { selector: 'edge', style: {
        'curve-style': 'taxi', 'taxi-direction': 'horizontal', 'taxi-turn': '50%', 'width': 2.2,
        'line-color': 'data(color)', 'target-arrow-shape': 'none', 'z-index': 5,
        'label': 'data(text)', 'font-family': FONT, 'font-size': 12, 'color': 'data(color)',
        'text-background-color': '#ffffff', 'text-background-opacity': 0.9, 'text-background-padding': 3 } },
      { selector: 'edge.down', style: { 'taxi-direction': 'vertical' } },
      // From the router to each device: straight, solid when wired, dotted on Wi-Fi.
      { selector: 'edge.straight', style: { 'curve-style': 'straight', 'width': 2.2 } },
      { selector: 'edge.wifi', style: { 'line-style': 'dotted', 'width': 2.6 } },
      // To a network below the rings: across only after clearing them.
      { selector: 'edge.low', style: { 'taxi-turn': '92%' } },
      { selector: 'edge.thin', style: { 'curve-style': 'straight', 'width': 1.4 } },
      { selector: 'edge.dashed', style: { 'line-style': 'dashed', 'line-dash-pattern': [8, 6], 'width': 2.6 } }
    ])
  });

  function byId(id) { return document.getElementById(id); }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
    return node;
  }

  // The page is a dashboard of cards. Inside a card a fact is one row: its
  // label on the left, its value (text or a node) on the right.
  function row(label, value, valueClass) {
    var line = el('div', 'row');
    line.appendChild(typeof label === 'string' ? el('span', 'label', label) : label);
    var holder = line.appendChild(el('div', 'value' + (valueClass ? ' ' + valueClass : '')));
    if (typeof value === 'string') { holder.textContent = value; } else if (value) { holder.appendChild(value); }
    return line;
  }

  // A hover hint: the long explanation, kept off the page.
  function hint(node, text) {
    if (text) { node.title = text; }
    return node;
  }
  // "no HttpOnly: page scripts can read it" -> "no HttpOnly".
  function short(text) {
    return String(text || '').split(/: | \(/)[0];
  }

  function card(title) {
    var box = el('section', 'card');
    box.appendChild(el('h2', null, title));
    return box;
  }

  function flash(message) {
    var box = byId('flash') || document.body.appendChild(el('div'));
    box.id = 'flash';
    box.textContent = message;
    clearTimeout(flash.timer);
    flash.timer = setTimeout(function () { box.remove(); }, 6000);
  }

  function connected() {
    return !!socket && socket.readyState === WebSocket.OPEN;
  }

  function send(command) {
    if (connected()) {
      socket.send(JSON.stringify(command));
    } else {
      flash('Not connected to the session.');
    }
  }

  var reconnectDelay = 2000;
  var reconnectTimer = null;
  function connect() {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
    if (ended) { return; }
    var proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
    var ws = new WebSocket(proto + location.host + withToken('/ws'));
    socket = ws;
    ws.onopen = function () {
      if (socket !== ws) { return; }
      byId('conn').textContent = 'live';
      byId('conn').className = 'badge on';
    };
    ws.onmessage = function (event) {
      if (socket !== ws) { return; }
      var message;
      try {
        message = JSON.parse(event.data);
      } catch (_) {
        return;
      }
      if (!message || typeof message !== 'object') { return; }
      if (message.type === 'state') {
        if (!pageKey || message.key !== pageKey) {
          // Not the session this page came from: another program now has
          // its port. Nothing it sends is shown.
          ended = true;
          ws.close();
          return;
        }
        reconnectDelay = 2000;
        state = message.state;
        render();
        // Where this machine is: asked once, when the map first opens.
        if (!askedWhere) {
          askedWhere = true;
          send({ cmd: 'locate' });
        }
      } else if (message.type === 'progress') {
        // How far the running stages are, sent alone while a tool counts
        // its results: only the strip is drawn again, not the cards.
        if (state && message.key === pageKey) { reconProgress(message); }
      } else if (message.type === 'result' && !message.ok) {
        flash(message.error || 'Command failed.');
      }
    };
    ws.onclose = function () {
      if (socket !== ws) { return; }
      byId('conn').textContent = ended ? 'session ended' : 'session closed';
      byId('conn').className = 'badge off';
      reconStill();
      if (!ended) {
        var wait = reconnectDelay;
        reconnectDelay = Math.min(30000, Math.round(reconnectDelay * 1.5));
        clearTimeout(reconnectTimer);
        reconnectTimer = setTimeout(connect, wait);
      }
    };
  }

  function renderHeader() {
    var sessionName = String(state.session || '');
    var mode = String(state.mode || 'light').replace(/[^a-z0-9_-]/gi, '');
    byId('session').textContent = sessionName;
    byId('avatar').textContent = sessionName.slice(0, 1).toUpperCase();
    byId('mode').textContent = 'mode ' + mode;
    byId('mode').className = 'badge mode-' + mode;
    // One line of status, like a finished lookup: what there is, what to do.
    var hostsMap = (state.graph && state.graph.hosts) || {};
    var hosts = Object.keys(hostsMap);
    var total = { total: 0, kev: 0 };
    hosts.forEach(function (key) {
      var counts = cveCounts(key);
      total.total += counts.total;
      total.kev += counts.kev;
    });
    var parts = [hosts.length + (hosts.length === 1 ? ' host' : ' hosts')];
    parts.push(cveWords(total) || 'no CVEs');
    byId('counts').textContent = parts.join(' · ');
    document.title = 'meow: ' + sessionName;
  }

  // Natural order for addresses: 10.0.0.9 before 10.0.0.10.
  function sortKey(data) {
    return String((data && (data.address || data.label || data.id)) || '').replace(/\d+/g, function (digits) {
      return ('00000' + digits).slice(-6);
    });
  }

  // Turns the session's nodes and links into the illustration.
  // Red: a CVE that is known exploited, critical or high. Yellow: other CVEs.
  function status(d) {
    if (!d || d.kind !== 'host') { return 'none'; }
    if (d.serious_cves) { return 'bad'; }
    if (d.cves) { return 'warn'; }
    return 'ok';
  }
  var SEVERITY = { bad: 0, warn: 1, ok: 2, none: 3 };
  var PRINTER = /(^|[\s,])(9100|515|631)\/tcp|ipp|printer|jetdirect/i;

  function plan(nodes, edges) {
    var data = table(), out = table(), pos = table(), classes = table(), elements = [], lines = [],
      placed = table(), networkOf = table(), asnBoxes = [];
    (nodes || []).forEach(function (node) { data[node.data.id] = Object.assign({}, node.data); out[node.data.id] = []; });
    if (!data.local) { data.local = { id: 'local', kind: 'local', label: 'You' }; out.local = []; }
    (edges || []).forEach(function (edge) {
      var e = edge.data;
      if (out[e.source] && data[e.target]) { out[e.source].push({ to: e.target, kind: e.kind }); }
    });
    function linked(id, kinds) {
      return (out[id] || []).filter(function (e) { return kinds.indexOf(e.kind) >= 0; })
        .map(function (e) { return e.to; });
    }
    function bySeverity(a, b) {
      var sa = SEVERITY[status(data[a])], sb = SEVERITY[status(data[b])];
      if (sa !== sb) { return sa - sb; }
      var ka = sortKey(data[a]), kb = sortKey(data[b]);
      return ka < kb ? -1 : (ka > kb ? 1 : 0);
    }
    function picture(d) {
      if (d.id === 'local') { return 'you'; }
      if (d.id === 'internet') { return 'internet'; }
      if (d.kind === 'gateway' || d.role === 'router') { return 'router'; }
      if (d.kind === 'interface') { return 'segment'; }
      if (PRINTER.test(d.ports_line || '')) { return 'printer'; }
      if (d.role === 'firewall') { return 'firewall'; }
      return d.role === 'server' ? 'server' : 'client';
    }

    var internetVia = linked('internet', ['internet']);
    var outside = [];
    internetVia.forEach(function (g) {
      linked(g, ['routed']).forEach(function (h) { if (outside.indexOf(h) < 0) { outside.push(h); } });
    });
    outside.sort(function (a, b) {
      var aa = (data[a] && data[a].asn) || '', ab = (data[b] && data[b].asn) || '';
      if (aa !== ab) { return aa < ab ? -1 : 1; }
      return bySeverity(a, b);
    });

    function activeTraceSource() {
      if (selected && data[selected] && data[selected].trace_hops && data[selected].trace_hops.length) {
        return data[selected];
      }
      for (var i = 0; i < outside.length; i++) {
        var od = data[outside[i]];
        if (od && od.trace_hops && od.trace_hops.length) { return od; }
      }
      return data.internet || null;
    }

    function caption(id) {
      var d = data[id], parts = [];
      if (id === 'local') {
        var mine = d.caption && d.caption.split('\n')[1];
        parts.push(mine ? ('You · ' + mine) : 'You');
      } else if (id === 'internet') {
        var ts = activeTraceSource();
        var hc = (ts && ts.hop_count) || (d && d.hop_count) || 0;
        var rtt = (ts && ts.rtt_ms !== undefined && ts.rtt_ms !== null) ? ts.rtt_ms
          : ((d && d.rtt_ms !== undefined && d.rtt_ms !== null) ? d.rtt_ms : null);
        var meta = [];
        if (hc) { meta.push(hc + (hc === 1 ? ' hop' : ' hops')); }
        if (rtt !== null) { meta.push(Math.round(rtt) + ' ms'); }
        parts.push('Internet' + (meta.length ? ' (' + meta.join(' · ') + ')' : ''));
        if ((ts && ts.trace_hops && ts.trace_hops.length) || hc) {
          parts.push(traceExpanded ? '▴ hide traceroute' : '▾ click to expand traceroute');
        }
      } else if (d.kind === 'egress' || d.kind === 'hop' || d.kind === 'waf' || d.kind === 'asn') {
        parts.push(d.label || id);
      } else if (d.kind === 'host') {
        var dot = d.serious_cves ? ' \ud83d\udd34' : (d.cves ? ' \ud83d\udfe1' : (d.open_ports ? ' \ud83d\udfe2' : ''));
        var primary = (d.primary_hostname && d.primary_hostname !== d.address)
          ? (d.primary_hostname + ' (' + d.address + ')')
          : (d.address || d.label);
        parts.push(primary + dot);
        var sub = [];
        if (d.ports_compact) {
          sub.push(d.ports_compact + (d.open_ports ? ' (' + d.open_ports + ' open)' : ''));
        } else if (d.open_ports) {
          sub.push(d.open_ports + ' open');
        }
        if (d.city) { sub.push(d.city); }
        if (sub.length) { parts.push(sub.join(' · ')); }
        if (d.cves) { parts.push(cveWords({ total: d.cves, kev: d.kev || 0 })); }
      } else if (d.kind === 'gateway') {
        parts.push('Gateway · ' + (d.label || id.replace(/^gw:/, '')));
      } else if (d.kind === 'interface') {
        parts.push((d.caption || d.label || id).split('\n')[0]);
      } else {
        parts.push(d.label || id);
      }
      return parts.join('\n');
    }
    function put(id, x, y, extra) {
      var d = data[id];
      pos[id] = { x: x, y: y };
      var cls = [status(d)];
      if (d.kind === 'host' && d.kev) { cls.push('kev'); }
      classes[id] = cls.concat(extra || []).join(' ');
      if (!d.icon && d.kind !== 'title' && d.kind !== 'asn') { d.icon = picture(d); }
      placed[id] = true;
    }
    function link(from, to, color, kind, text) {
      lines.push({ group: 'edges', classes: kind || '',
        data: { id: 'l:' + from + '>' + to, source: from, target: to, color: color || '#9aa3ad', text: text || '' } });
    }
    function title(id, text, x, y, color) {
      data[id] = { id: id, kind: 'title', label: text, color: color };
      pos[id] = { x: x, y: y };
      classes[id] = 'title';
    }
    // A point where lines meet or bend.
    function anchor(x, y) {
      var id = 'a:' + Math.round(x) + ',' + Math.round(y);
      data[id] = { id: id, kind: 'anchor' };
      pos[id] = { x: x, y: y };
      classes[id] = 'anchor';
      return id;
    }

    var networks = (nodes || []).filter(function (n) { return n.data.kind === 'interface'; }).map(function (n) { return n.data.id; });
    function leadsOut(id) {
      return internetVia.indexOf(id) >= 0 || linked(id, ['gateway']).some(function (g) { return internetVia.indexOf(g) >= 0; });
    }
    var home = networks.filter(leadsOut)[0] ||
      networks.filter(function (n) { return ['vpn', 'virtual'].indexOf(data[n].link) < 0; })[0];
    var vpns = networks.filter(function (n) { return n !== home && data[n].link === 'vpn'; });
    var others = networks.filter(function (n) { return n !== home && vpns.indexOf(n) < 0; });
    var ownNets = vpns.concat(others);

    // Top-down OPSEC & transit pipeline:
    // [ You · 192.168.0.184 ]
    //          ┆ (Wi-Fi en0)
    // [ Gateway · 192.168.0.1 ]
    //          │
    // [ WAN Egress · 73.x.x.x (Comcast) ]
    //          │
    //    ☁️ Internet (8 hops · 23ms)
    //          │
    // ┌─ AS63949 · Akamai / Linode ──────┐
    // │  🖥️ scanme.org (45.33.32.156) 🟡 │
    // │     22, 80, 9929/tcp · Fremont   │
    // └──────────────────────────────────┘
    var hub = null, rowLeft = 0;
    if (home) {
      var gateways = linked(home, ['gateway']).sort(bySeverity);
      hub = gateways[0] || home;
      var tree = data[home].link === 'wifi' ? 'straight wifi' : 'straight';
      var homeLabel = caption(home);
      put('local', 0, YOU_Y, ['you']);
      put(hub, 0, GW_Y, ['hub', 'side']);
      if (data[home].network) { networkOf[hub] = data[home].network; }
      link('local', hub, LINE.ethernet, tree, '(' + homeLabel + ')');

      // Local LAN peers hang to the left of the gateway so the vertical
      // You -> Gateway -> WAN Egress -> Internet -> Target spine stays clean.
      var lanPeers = gateways.slice(1).concat(linked(home, ['neighbour', 'direct']).filter(function (id) {
        return id !== hub && id !== 'local' && !placed[id];
      }).sort(bySeverity));
      if (lanPeers.length) {
        var barY = GW_Y + 85;
        rowLeft = -lanPeers.length * STEP;
        lanPeers.forEach(function (id, i) {
          put(id, -(i + 1) * STEP, GW_Y + 150);
        });
        link(hub, anchor(0, barY), LINE.ethernet, tree);
        link(anchor(rowLeft, barY), anchor(0, barY), LINE.ethernet, tree);
        lanPeers.forEach(function (id) {
          link(anchor(pos[id].x, barY), id, LINE.ethernet, tree);
        });
      }

      if (data.internet && internetVia.length) {
        var vpnList = (state && state.machine && state.machine.vpn) || [];
        var where = (state && state.location) || null;
        var vpnAll = (where && where.status === 'hidden_by_vpn') || vpnList.some(function (line) {
          return /default route|all IPv[46]/i.test(line);
        });
        if (vpnAll || vpnList.length) {
          var vNames = vpnList.map(vpnName).join(', ') || 'VPN';
          data['egress:wan'] = {
            id: 'egress:wan', kind: 'egress', role: 'firewall', icon: 'firewall',
            why: 'active VPN exit tunnel carrying outbound traffic',
            label: 'VPN Exit · ' + vNames + '\n' + (vpnAll ? 'OPSEC: traffic tunneled' : 'split-tunnel VPN active'),
            vpn: vNames
          };
          put('egress:wan', 0, EGRESS_Y, ['egress']);
          link(hub, 'egress:wan', LINE.vpn, 'straight dashed', 'VPN');
        } else {
          var pubIp = (where && where.place && where.place.public_address) || '';
          var isp = (where && where.place && (where.place.network || placeName(where.place))) || '';
          var egressHead = 'WAN Egress' + (pubIp ? ' · ' + pubIp : '') + (isp ? ' (' + isp + ')' : '');
          data['egress:wan'] = {
            id: 'egress:wan', kind: 'egress', role: 'router', icon: 'router',
            why: 'your public WAN egress IP and ISP seen by remote targets',
            label: egressHead + '\nno VPN',
            public_address: pubIp,
            isp: isp
          };
          put('egress:wan', 0, EGRESS_Y, ['egress']);
          link(hub, 'egress:wan', LINE.ethernet, 'straight');
        }

        put('internet', 0, CLOUD_Y, ['cloud']);
        link('egress:wan', 'internet', vpnAll ? LINE.vpn : LINE.ethernet, vpnAll ? 'straight dashed' : 'straight');

        var transitBottomId = 'internet';
        var targetBaseY = TARGET_Y;
        var ts = activeTraceSource();
        var activeHops = (ts && ts.trace_hops) || [];
        if (traceExpanded && activeHops.length) {
          activeHops.forEach(function (hop, idx) {
            var hopId = 'hop:' + hop.hop;
            var rttText = (hop.rtt_ms !== null && hop.rtt_ms !== undefined) ? (hop.rtt_ms.toFixed(1) + ' ms') : '—';
            var where = hopPlace(hop);
            var hopLabel = 'Hop ' + hop.hop + ': ' + hop.address +
              (hop.label ? '  (' + hop.label + ')' : '') + '   ' + rttText +
              (where ? '\n' + where : '');
            data[hopId] = {
              id: hopId, kind: 'hop', role: hop.address === '* * *' ? 'segment' : 'router',
              icon: hop.address === '* * *' ? 'segment' : 'router',
              why: hop.is_target
                ? 'the target itself, the last hop of the traceroute'
                : 'intermediate traceroute hop ' + hop.hop,
              label: hopLabel,
              hop: hop
            };
            var hy = CLOUD_Y + 135 + idx * 92;
            put(hopId, 0, hy, ['hop']);
            link(transitBottomId, hopId, LINE.ethernet, 'straight');
            transitBottomId = hopId;
          });
          targetBaseY = CLOUD_Y + 135 + activeHops.length * 92 + 125;
        }

        var shownOutside = outside.filter(function (h) { return !placed[h]; }).slice(0, 6);
        outside.slice(6).forEach(function (h) { placed[h] = true; });
        var asnSeen = table();
        shownOutside.forEach(function (h, i) {
          var hx = -(shownOutside.length - 1) / 2 * STEP + i * STEP;
          var hd = data[h];
          var hasWaf = !!(hd && hd.waf_cdn);
          var hy = targetBaseY + (hasWaf ? 155 : 0);

          if (hd && hd.asn) {
            var asnId = 'asn:' + hd.asn;
            if (!own(asnSeen, asnId)) {
              var asnHeader = hd.asn + (hd.bgp_prefix ? ' · ' + hd.bgp_prefix : '');
              var asnNodeData = {
                id: asnId, kind: 'asn', role: 'segment',
                why: 'autonomous system / cloud provider grouping sibling hosts',
                label: asnHeader, text: asnHeader, asn: hd.asn, bgp_prefix: hd.bgp_prefix || ''
              };
              asnSeen[asnId] = asnNodeData;
              asnBoxes.push({ group: 'nodes', data: asnNodeData, classes: 'asn-box' });
            }
            hd.parent = asnId;
          }

          put(h, hx, hy);
          if (hasWaf) {
            var wafId = 'waf:' + h;
            data[wafId] = {
              id: wafId, kind: 'waf', role: 'firewall', icon: 'firewall',
              why: 'WAF / CDN proxy detected in front of ' + (hd.address || h),
              label: 'WAF / CDN · ' + hd.waf_cdn,
              waf: hd.waf_cdn,
              target: hd.address || h
            };
            put(wafId, hx, targetBaseY - 10, ['waf']);
            link(transitBottomId, wafId, LINE.ethernet, shownOutside.length === 1 ? 'straight' : 'down');
            link(wafId, h, LINE.ethernet, 'straight');
          } else {
            link(transitBottomId, h, LINE.ethernet, shownOutside.length === 1 ? 'straight' : 'down');
          }
        });
      }
    } else {
      put('local', 0, 0, ['you']);
    }

    // Networks only this machine is on (a VPN, a virtual network) branch
    // to the right of You so they stay clear of the vertical transit spine.
    var you = pos.local, hubs = [];
    ownNets.forEach(function (net) {
      var color = LINE[data[net].link] || LINE.other;
      var hubId = data[net].link === 'vpn' ? (linked(net, ['gateway']).sort(bySeverity)[0] || net) : net;
      var members = (hubId !== net ? linked(hubId, ['routed']) : [])
        .concat(linked(net, ['gateway', 'neighbour', 'direct']))
        .filter(function (id, i, all) { return id !== hubId && !placed[id] && all.indexOf(id) === i; })
        .sort(bySeverity);
      members.slice(6).forEach(function (h) { placed[h] = true; });
      members = members.slice(0, 6);
      hubs.push({ net: net, hub: hubId, color: color, members: members,
        width: Math.max(1, Math.min(3, members.length)) * SUB_STEP });
    });
    var hubY = you.y + 170;
    var x0 = you.x + STEP * 0.9;
    hubs.forEach(function (h, k) {
      x0 += (k ? hubs[k - 1].width / 2 + 60 : 0) + h.width / 2;
      put(h.hub, x0, hubY, ['hub']);
      networkOf[h.hub] = h.hub === h.net ? (data[h.net].network || '')
        : caption(h.net) + (data[h.net].network ? ' · ' + data[h.net].network : '');
      h.members.forEach(function (m, i) {
        var across = Math.min(3, h.members.length), r = Math.floor(i / 3), j = i % 3;
        put(m, x0 + (j - (across - 1) / 2) * SUB_STEP, hubY + 175 + r * 170);
        link(h.hub, m, h.color, 'down');
      });
    });
    if (hubs.length === 1) {
      link('local', hubs[0].hub, hubs[0].color, 'dashed down');
    } else if (hubs.length > 1) {
      var first = pos[hubs[0].hub].x, last = pos[hubs[hubs.length - 1].hub].x, barY2 = you.y + 85;
      data.ownbar = { id: 'ownbar', kind: 'bar', width: last - first + 8 };
      pos.ownbar = { x: (first + last) / 2, y: barY2 };
      classes.ownbar = 'ownbar';
      link('local', anchor(you.x, barY2), '#9aa3ad', 'thin');
      hubs.forEach(function (h) { link(anchor(pos[h.hub].x, barY2), h.hub, h.color, 'dashed down'); });
    }

    // Hosts this machine has no route to, in a group of their own.
    var rest = (nodes || []).map(function (n) { return n.data.id; }).filter(function (id) {
      return !placed[id] && ['interface', 'internet'].indexOf(data[id].kind) < 0;
    }).sort(bySeverity);
    if (rest.length) {
      var y0 = Object.keys(pos).reduce(function (y, id) { return Math.max(y, pos[id].y); }, 0) + 230;
      title('title:unknown', 'Route not known', rowLeft - 50, y0 - 62, '#6b7178');
      rest.forEach(function (h, i) { put(h, rowLeft + (i % 6) * SUB_STEP, y0 + Math.floor(i / 6) * 170); });
    }

    asnBoxes.forEach(function (box) { elements.push(box); });
    Object.keys(pos).forEach(function (id) {
      var d = Object.assign({}, data[id]);
      d.text = d.kind === 'title' ? d.label
        : (['bar', 'anchor'].indexOf(d.kind) >= 0 ? '' : caption(id));
      if (networkOf[id]) { d.text += '\n' + networkOf[id]; }
      elements.push({ group: 'nodes', data: d, classes: classes[id] });
    });
    return { elements: elements.concat(lines), positions: pos };
  }

  function renderGraph() {
    var key = JSON.stringify([
      state.topology,
      state.location && state.location.status,
      state.location && state.location.place,
      state.machine && state.machine.vpn,
      traceExpanded
    ]);
    if (key === drawn) { return; }
    var first = !drawn;
    drawn = key;
    var picture = plan(state.topology.nodes, state.topology.edges);
    cy.elements().remove();
    cy.add(picture.elements);
    cy.layout({
      name: 'preset', fit: false,
      positions: function (node) { return picture.positions[node.id()]; }
    }).run();
    fitDrawing(first);
    if (selected && cy.$id(selected).length) { cy.$id(selected).select(); }
  }

  // The drawing fills the card's height (never blown up past MAX_ZOOM). A
  // tall drawing makes the card taller rather than unreadably small, and a
  // row of devices wider than the card makes the canvas wider instead: the
  // card then scrolls left and right, opening on the router.
  function fitDrawing(recentre) {
    var card = byId('card-map'), scroller = byId('scroller'), canvas = byId('cy');
    var all = cy.elements();
    if (!all.length) { return; }
    var bb = all.boundingBox(), zoom = MAX_ZOOM, width = scroller.clientWidth;
    if (!isFinite(bb.x1) || !isFinite(bb.y1)) { return; }
    var bw = Math.max(1, bb.w || 0), bh = Math.max(1, bb.h || 0);
    card.style.height = '';
    card.style.maxHeight = '';
    var short = Math.ceil(bh * READABLE_ZOOM + 2 * FIT_PADDING) - scroller.clientHeight;
    // Expanded, the card is the window: the drawing shrinks to fit it.
    if (short > 0 && !mapExpanded) {
      card.style.maxHeight = 'none';
      card.style.height = Math.min(CARD_MAX, card.offsetHeight + short) + 'px';
    }
    if (!scroller.clientHeight || !scroller.clientWidth) { return; }
    cy.resize();
    // Twice: a scrollbar, once there, takes some of the height.
    for (var pass = 0; pass < 2; pass++) {
      // As big as the height allows; smaller to fit the width, but only
      // down to READABLE_ZOOM: past that the row scrolls instead.
      var fitWidth = (scroller.clientWidth - 2 * FIT_PADDING) / bw;
      var fitHeight = (scroller.clientHeight - 2 * FIT_PADDING) / bh;
      zoom = Math.max(0.05, Math.min(MAX_ZOOM, fitHeight, Math.max(fitWidth, READABLE_ZOOM)));
      width = Math.max(scroller.clientWidth, Math.ceil(bw * zoom + 2 * FIT_PADDING));
      if (width > MAX_WIDTH) {
        width = MAX_WIDTH;
        zoom = Math.max(0.05, (MAX_WIDTH - 2 * FIT_PADDING) / bw);
      }
      if (canvas.style.width !== width + 'px') {
        canvas.style.width = width + 'px';
        cy.resize();
      }
    }
    if (!zoom || !isFinite(zoom)) { return; }
    var height = scroller.clientHeight;
    cy.viewport({ zoom: zoom, pan: {
      x: (width - bw * zoom) / 2 - bb.x1 * zoom,
      y: (height - bh * zoom) / 2 - bb.y1 * zoom
    } });
    var wide = width > scroller.clientWidth;
    byId('scroll-hint').hidden = !wide;
    if (recentre) {
      var router = cy.$('node.side');
      scroller.scrollLeft = router.length ? router.renderedPosition().x - scroller.clientWidth / 2 : 0;
    }
    if (!wide) { dodgeOverlay(); }
  }

  // The location card floats over the drawing's top-right corner. When a
  // device or label would be under it, slide the drawing left, as far as
  // the room on the left allows; the reader can fold the card for the rest.
  function dodgeOverlay() {
    var box = byId('where').firstElementChild;
    if (!box || !box.offsetWidth) { return; }
    var stage = byId('scroller').getBoundingClientRect(), over = box.getBoundingClientRect();
    var edge = over.left - stage.left - 12, below = over.bottom - stage.top + 8;
    var reach = -Infinity, start = Infinity;
    cy.elements().forEach(function (item) {
      var bb = item.renderedBoundingBox({ includeLabels: true });
      if (!isFinite(bb.x1)) { return; }
      start = Math.min(start, bb.x1);
      if (bb.y1 < below) { reach = Math.max(reach, bb.x2); }
    });
    var overlap = reach - edge;
    if (!(overlap > 0) || !isFinite(start)) { return; }
    var shift = Math.min(overlap, Math.max(0, start - 16));
    if (shift > 0) { cy.panBy({ x: -shift, y: 0 }); }
    // Still over a device: fold the card into its pill, unless the reader
    // opened it on purpose. It opens again when the window gets wider.
    if (whereFolded || whereChosen) { return; }
    var hidden = cy.nodes().some(function (node) {
      var bb = node.renderedBoundingBox({ includeLabels: true });
      return stage.left + bb.x1 < over.right && stage.left + bb.x2 > over.left &&
        stage.top + bb.y1 < over.bottom && stage.top + bb.y2 > over.top;
    });
    if (hidden) {
      whereFolded = whereAutoFolded = true;
      renderWhere();
    }
  }

  // Above the drawing: a note when a VPN is up, and where this machine
  // roughly is: a small satellite map with a pin and a circle for the rough
  // area, or a compass when there are no pictures. The session serves the
  // pictures; this page fetches nothing from anywhere else.
  var SVG_NS = 'http://www.w3.org/2000/svg';
  var whereDrawn = '';
  var mapCloser = false;   // the reader clicked the round map to zoom in
  function svg(tag, attrs, parent) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs).forEach(function (key) { node.setAttribute(key, attrs[key]); });
    if (parent) { parent.appendChild(node); }
    return node;
  }
  function compass() {
    var face = svg('svg', { width: 44, height: 44, viewBox: '0 0 46 46', 'aria-hidden': 'true' });
    svg('circle', { cx: 23, cy: 23, r: 21, fill: '#ffffff', stroke: '#9aa3ad', 'stroke-width': 1.5 }, face);
    [['N', 23, 10.5], ['E', 37.5, 26], ['S', 23, 41.5], ['W', 8.5, 26]].forEach(function (mark) {
      var letter = svg('text', { x: mark[1], y: mark[2], 'text-anchor': 'middle', 'font-size': 8,
        'font-weight': 700, 'font-family': FONT, fill: mark[0] === 'N' ? '#e5534b' : '#4a5260' }, face);
      letter.textContent = mark[0];
    });
    svg('path', { d: 'M23 13 L26.5 23 L19.5 23 Z', fill: '#e5534b' }, face);
    svg('path', { d: 'M23 33 L26.5 23 L19.5 23 Z', fill: '#4a5260' }, face);
    svg('circle', { cx: 23, cy: 23, r: 1.6, fill: '#ffffff' }, face);
    return face;
  }
  function degrees(value, positive, negative) {
    return Math.abs(value).toFixed(2) + '° ' + (value >= 0 ? positive : negative);
  }
  function placeName(place) {
    return [place.city, place.region].filter(Boolean).join(', ') || place.country || 'Unnamed place';
  }
  function placeWords(box, where) {
    var place = where.place;
    box.appendChild(el('strong', null, placeName(place)));
    box.appendChild(el('span', null, degrees(place.latitude, 'N', 'S') + ', ' + degrees(place.longitude, 'E', 'W')));
  }
  function estimatedFrom(where) {
    var place = where.place;
    return 'Estimated from ' + (place.public_address || 'your public address') +
      (place.network ? ' (' + place.network + ')' : '') + ' by ' + where.source + '.';
  }
  // The pictures' licence asks for visible attribution and a link: Sentinel-2
  // cloudless by EOX (CC BY 4.0 for 2016; CC BY-NC-SA 4.0 for later years)
  // with modified Copernicus Sentinel data.
  function credit(view) {
    var box = el('span', 'attribution');
    box.title = view.credit || '';
    if (!safeHttpUrl(view.credit_url)) {
      box.textContent = view.credit || '';
      return box;
    }
    var isEox = /(?:cloudless\.eox\.at|s2maps\.eu)/i.test(view.credit_url);
    var yearMatch = /Sentinel data (\d{4})/i.exec(view.credit || '');
    var year = yearMatch ? yearMatch[1] : '';
    var licence = year && year !== '2016' ? 'CC BY-NC-SA 4.0' : 'CC BY 4.0';
    var link = box.appendChild(el('a', null,
      isEox ? 'Sentinel-2 cloudless by EOX (' + licence + ')' : (view.credit || view.credit_url)));
    link.href = view.credit_url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    if (isEox) {
      box.appendChild(document.createTextNode(
        ' \u00b7 Contains modified Copernicus Sentinel data' + (year ? ' ' + year : '')));
    }
    return box;
  }

  // The satellite map: the picture with the rough area circled and a pin
  // at the estimate; the place and its coordinates under it. The details
  // stay in the tooltip.
  function satellite(where, extra) {
    var closer = mapCloser && where.map.closer;
    var view = closer || where.map, place = where.place;
    var card = el('div', 'satellite');
    card.title = 'Rough area: within about ' + Math.round(view.radius_m / 1000) + ' km of the pin. ' +
      estimatedFrom(where);
    var picture = card.appendChild(el('div', 'picture'));
    // A click zooms in around the pin, and out again.
    if (where.map.closer) {
      picture.className = 'picture ' + (closer ? 'zoom-out' : 'zoom-in');
      picture.title = closer ? 'Click to zoom out' : 'Click to zoom in';
      picture.addEventListener('click', function () {
        mapCloser = !mapCloser;
        renderWhere();
      });
    }
    picture.style.width = view.width + 'px';
    picture.style.height = view.height + 'px';
    picture.setAttribute('role', 'img');
    picture.setAttribute('aria-label', 'Satellite picture around ' + placeName(place) +
      ', with a pin at the estimate and its rough area circled');
    view.tiles.forEach(function (tile) {
      var img = picture.appendChild(el('img', 'tile'));
      img.alt = '';
      // A hair larger, so no seam shows between tiles.
      img.width = view.tile_size + 0.5;
      img.height = view.tile_size + 0.5;
      img.style.left = tile.left + 'px';
      img.style.top = tile.top + 'px';
      img.src = withToken('/map/tile/' + encodeURIComponent(tile.z) + '/' +
        encodeURIComponent(tile.x) + '/' + encodeURIComponent(tile.y));
    });
    var x = view.width / 2, y = view.height / 2;
    var marks = svg('svg', { 'class': 'marks', width: view.width, height: view.height,
      viewBox: '0 0 ' + view.width + ' ' + view.height, 'aria-hidden': 'true' }, picture);
    svg('circle', { cx: x, cy: y, r: view.radius, fill: 'rgba(160, 210, 90, .30)',
      stroke: '#111418', 'stroke-width': 2.5 }, marks);
    // A pin whose tip is the estimate.
    var pin = svg('g', { transform: 'translate(' + x + ' ' + y + ') scale(1.15)' }, marks);
    svg('ellipse', { cx: 0, cy: 0, rx: 4.5, ry: 1.8, fill: 'rgba(0, 0, 0, .35)' }, pin);
    svg('path', { d: 'M0 0 C-1.8 -5 -8 -8.6 -8 -15 A8 8 0 1 1 8 -15 C8 -8.6 1.8 -5 0 0 Z',
      fill: '#5b82d9', stroke: '#3c5fae', 'stroke-width': 1 }, pin);
    svg('circle', { cx: 0, cy: -15, r: 3.2, fill: '#ffffff' }, pin);
    // Under the map: the place, its coordinates, and the credit the
    // pictures' licence asks for.
    var words = card.appendChild(el('div', 'place'));
    words.appendChild(el('strong', null, placeName(place)));
    words.appendChild(el('span', null, degrees(place.latitude, 'N', 'S') + ', ' +
      degrees(place.longitude, 'E', 'W')));
    if (extra) { extra(words); }
    words.appendChild(credit(view));
    return card;
  }

  // The selected device's own addresses, under its map.
  function addressLines(box, target) {
    var known = target.addresses || {};
    box.appendChild(el('span', 'address', 'IPv4 ' + ((known.ipv4 || []).join(', ') || 'not seen')));
    box.appendChild(el('span', 'address', 'IPv6 ' + ((known.ipv6 || []).join(', ') || 'not seen')));
  }
  function dbCredit(box, target) {
    if (!target.credit) { return; }
    var line = box.appendChild(el('span', 'attribution'));
    if (safeHttpUrl(target.credit_url)) {
      var link = line.appendChild(el('a', null, target.credit));
      link.href = target.credit_url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
    } else {
      line.textContent = target.credit;
    }
  }
  // The address of the device selected on the drawing, if it has one.
  function selectedAddress() {
    if (!selected) { return null; }
    var match = /^(?:host|nb):(.+)$/.exec(selected);
    return match ? match[1] : null;
  }
  // The round map for the selected device: its place from the database on
  // this machine, or yours when it is on your network.
  function targetView(box, target) {
    if (target.status === 'looking') {
      box.appendChild(el('span', 'dim', 'Locating ' + target.address + '\u2026'));
      return;
    }
    if (target.place && target.map) {
      var where = { place: target.place, map: target.map,
        source: target.status === 'local' ? 'your own estimate' : 'the location database on this machine' };
      var card = box.appendChild(satellite(where, function (words) {
        if (target.status === 'local') { words.appendChild(el('span', 'dim', 'On your network, near you')); }
        addressLines(words, target);
        dbCredit(words, target);
      }));
      card.title = target.address + ': ' + (target.status === 'local'
        ? 'on your network, so it is where you are.' : estimatedFrom(where));
      return;
    }
    var off = box.appendChild(el('div', 'compass off'));
    off.appendChild(compass());
    var why = off.appendChild(el('div', 'words'));
    why.appendChild(el('strong', null, target.place ? placeName(target.place) : 'Location unknown'));
    if (target.status === 'local') { why.appendChild(el('span', 'dim', 'On your network, near you')); }
    if (target.note) { why.appendChild(el('span', 'dim', target.note)); }
    addressLines(why, target);
    dbCredit(why, target);
  }

  // The location card folds into a pill: when the reader folds it (kept
  // for this tab), or by itself when it would hide part of the drawing (on
  // a narrow screen it starts folded).
  var whereFolded = window.innerWidth < 700, whereChosen = false;
  try {
    var foldedBefore = sessionStorage.getItem('meow-map-where');
    if (foldedBefore) { whereFolded = foldedBefore === 'folded'; whereChosen = true; }
  } catch (_) {}
  var whereAutoFolded = whereFolded && !whereChosen;
  function foldWhere(folded) {
    whereFolded = folded;
    whereChosen = true;
    whereAutoFolded = false;
    try { sessionStorage.setItem('meow-map-where', folded ? 'folded' : 'open'); } catch (_) {}
    renderWhere();
  }
  window.addEventListener('resize', function () {
    // Folded by itself: try it open again; it folds back if still in the way.
    if (whereAutoFolded && window.innerWidth >= 700) {
      whereFolded = whereAutoFolded = false;
      renderWhere();
    }
    fitDrawing(false);
  });

  // Expand: the map and the side column fill the window; Esc goes back.
  var mapExpanded = false;
  function expandMap(on) {
    mapExpanded = on;
    document.body.classList.toggle('map-full', on);
    var button = byId('map-full');
    button.setAttribute('aria-pressed', on ? 'true' : 'false');
    button.textContent = on ? 'Back (Esc)' : 'Expand';
    cy.resize();
    fitDrawing(true);
  }
  byId('map-full').addEventListener('click', function () { expandMap(!mapExpanded); });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && mapExpanded) { expandMap(false); }
  });
  // Extracts the VPN adapter name from `"{name} {cidr}: carries ..."` across
  // Linux/macOS (`tun0`, `utun3`) and Windows (`WireGuard Tunnel`) + IPv6.
  function vpnName(line) {
    var text = String(line || '');
    var split = /^(.*):\s+(?:carries\b|no route\b)/.exec(text);
    if (split) {
      var head = split[1].replace(/\s+\S+$/, '').trim();
      if (head) { return head; }
    }
    return text.split(/\s+/)[0].replace(/:$/, '');
  }
  function renderWhere() {
    var vpn = (state.machine && state.machine.vpn) || [];
    var where = state.location;
    // Drawn again only when something changed, so the pictures load once.
    var target = state.target && state.target.address === selectedAddress() ? state.target : null;
    var key = JSON.stringify([vpn, where, mapCloser, target, whereFolded]);
    if (key === whereDrawn) { return; }
    whereDrawn = key;
    // Top right: a blue pill when a VPN is up, the round map under it.
    var box = clear(byId('where')).appendChild(el('div', 'where-side'));
    if (whereFolded) {
      box.className = 'where-side folded';
      if (vpn.length) { box.appendChild(el('span', 'vpn-pill', 'VPN ' + vpn.map(vpnName).join(', '))); }
      var place = target && target.place ? placeName(target.place)
        : where && where.status === 'found' && where.place ? placeName(where.place) : 'Location';
      var open = box.appendChild(el('button', 'where-open', place + ' \u25be'));
      open.type = 'button';
      open.title = 'Show the location map';
      open.addEventListener('click', function () { foldWhere(false); });
      fitDrawing(false);
      return;
    }
    if (vpn.length) {
      var names = vpn.map(vpnName).join(', ');
      var all = (where && where.status === 'hidden_by_vpn') || vpn.some(function (line) {
        return /default route|all IPv[46]/i.test(line);
      });
      var pill = box.appendChild(el('span', 'vpn-pill', 'VPN ' + names + (all ? ' \u00b7 location hidden' : '')));
      pill.title = vpn.join('\n') + '\n' + (all
        ? 'It carries all traffic, so no location is shown (a lookup would only find the VPN\'s exit).'
        : 'It carries only some networks, so the location shown is your own connection\'s.');
    }
    if (target) {
      targetView(box, target);
    } else if (where && where.status === 'found' && where.map) {
      box.appendChild(satellite(where));
    } else if (where && where.status === 'found') {
      var card = box.appendChild(el('div', 'compass'));
      card.appendChild(compass());
      var words = card.appendChild(el('div', 'words'));
      placeWords(words, where);
      card.title = estimatedFrom(where) + (where.map_error ? ' No map: ' + where.map_error : '');
    } else if (where && where.status === 'unavailable') {
      var off = box.appendChild(el('div', 'compass off'));
      off.appendChild(compass());
      var why = off.appendChild(el('div', 'words'));
      why.appendChild(el('strong', null, 'Location unknown'));
      why.appendChild(el('span', 'dim', where.reason));
    }
    // Something shown: a button folds it into a pill, out of the drawing.
    if (box.firstChild) {
      var fold = box.appendChild(el('button', 'where-fold', '\u2212'));
      fold.type = 'button';
      fold.title = 'Fold the location map';
      fold.setAttribute('aria-label', 'Fold the location map');
      fold.addEventListener('click', function () { foldWhere(true); });
    }
    fitDrawing(false);
  }

  function renderLegend() {
    var legend = byId('legend');
    [['warn', 'CVEs'], ['bad', 'critical, high or exploited']].forEach(function (key) {
      var item = legend.appendChild(el('span', 'item'));
      item.appendChild(el('span', 'glow ' + key[0]));
      item.appendChild(el('span', null, key[1]));
    });
    [['solid', 'wired', LINE.ethernet], ['dotted', 'Wi-Fi', LINE.ethernet],
     ['dashed', 'VPN', LINE.vpn], ['dashed', 'virtual network', LINE.virtual]].forEach(function (key) {
      var item = legend.appendChild(el('span', 'item'));
      var bar = item.appendChild(el('span', 'bar ' + key[0]));
      bar.style.borderColor = key[2];
      item.appendChild(el('span', null, key[1]));
    });
    legend.title = 'Other devices are drawn connected the way you are (assumed: meow only sees your own link).';
    var more = legend.appendChild(el('span', 'item note', 'Scroll sideways for more'));
    more.id = 'scroll-hint';
    more.hidden = true;
  }

  // Why a node is drawn the way it is. A hint, not a finding.
  function drawnAs(data) {
    var name = '';
    ROLES.forEach(function (role) { if (role[0] === data.role) { name = role[1]; } });
    return el('div', 'dim drawn', name && data.why ? 'Shown as ' + name + ': ' + data.why + '.' : '');
  }

  function renderList(target, items, empty, build) {
    clear(target);
    if (!items.length) { target.appendChild(el('li', 'dim', empty)); }
    items.forEach(function (item) { target.appendChild(build(item)); });
  }

  // A small round mark beside a value: ok, warn, bad or info.
  function mark(kind) {
    return el('span', 'mark ' + kind, { ok: '✓', warn: '!', bad: '✕', info: 'i' }[kind]);
  }

  // A value with a mark after it, for the right-hand side of a row.
  function marked(text, kind) {
    var holder = el('span', null, text + ' ');
    holder.appendChild(mark(kind));
    return holder;
  }

  // <details> keep the state the reader left them in across refreshes.
  var unfolded = table();
  function fold(key, className, openByDefault) {
    var box = el('details', className);
    box.open = hasOwn.call(unfolded, key) ? unfolded[key] : !!openByDefault;
    box.addEventListener('toggle', function () { unfolded[key] = box.open; });
    return box;
  }

  // Recon progress: a strip above the map, one row for each target (the
  // run that has work to do, else the newest): a bar with one segment per
  // stage, and one line of text.
  // The page renders again on every push and a clock ticks in between, so
  // a row is built once and only what changed is written after that.
  var RECON_ROWS = 3, RECON_TARGETS = 12, RECON_STAGES = 32, RECON_EARLIER = 8, RECON_SCAN = 2000;
  var STATUS_WORD = { pending: 'waiting', running: 'running', done: 'done', skipped: 'skipped',
    failed: 'failed', interrupted: 'stopped' };
  var STATUS_CUE = { pending: '\u00b7', running: '\u25b8', done: '\u2713', skipped: '\u2013',
    failed: '\u2715', interrupted: '\u25a0' };
  var reconViews = [], reconByKey = table(), reconOrder = null, reconWatched = table();
  var reconHeight = 0, reconTimer = null;
  // The state the strip was last drawn from, and when it arrived.
  var reconState = null, reconArrived = 0;

  // Text from the session on one line, cut to `max` characters.
  function plain(value, max) {
    if (typeof value !== 'string' && typeof value !== 'number') { return ''; }
    var text = String(value).slice(0, max * 4)
      .replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028-\u202e\u2066-\u2069]+/g, ' ').trim();
    return text.length > max ? text.slice(0, max - 1) + '\u2026' : text;
  }
  // A count from the session: a whole number from 0 to `max`, or null.
  function whole(value, max) {
    return typeof value === 'number' && isFinite(value) && value >= 0 ? Math.min(max, Math.floor(value)) : null;
  }
  // An RFC 3339 time as milliseconds, or null.
  function stamp(value) {
    if (typeof value !== 'string' || value.length > 40 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d/.test(value)) { return null; }
    var at = Date.parse(value);
    return isFinite(at) ? at : null;
  }
  // 192 -> "3:12", 3723 -> "1:02:03"
  function clockText(seconds) {
    var s = Math.max(0, Math.min(359999, Math.floor(seconds) || 0));
    var two = function (n) { return (n < 10 ? '0' : '') + n; };
    var h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60);
    return (h ? h + ':' + two(m) : String(m)) + ':' + two(s % 60);
  }
  function leftText(seconds) {
    var minutes = Math.round(seconds / 60);
    if (seconds < 60) { return 'under 1 min left'; }
    if (minutes < 60) { return 'about ' + minutes + ' min left'; }
    return 'about ' + Math.floor(minutes / 60) + ' h ' + (minutes % 60 ? minutes % 60 + ' min ' : '') + 'left';
  }
  function setText(node, text) {
    if (node.textContent !== text) { node.textContent = text; }
  }
  // Right-to-left text, kept from reordering what stands beside it.
  function apart(text) {
    return /[\u0590-\u08ff\ufb1d-\ufefc]/.test(text) ? '\u2068' + text + '\u2069' : text;
  }

  // The session's clock as an offset from this page's steady one: elapsed
  // times tick between pushes and do not follow this machine's clock.
  var clockOffset = null, clockFromSession = false;
  function steady() {
    return window.performance && performance.now ? performance.now() : Date.now();
  }
  function syncClock(nowUtc) {
    var at = stamp(nowUtc);
    if (at === null) {
      if (clockOffset === null || clockFromSession) { clockOffset = Date.now() - steady(); }
      clockFromSession = false;
      return;
    }
    // A stamp is a little behind by the time it is read (more so when cut
    // to whole seconds): keep the latest reading, unless the clock moved.
    var fresh = at - steady();
    clockOffset = clockFromSession && Math.abs(fresh - clockOffset) < 2000 ? Math.max(clockOffset, fresh) : fresh;
    clockFromSession = true;
  }
  function sessionNow() { return steady() + clockOffset; }

  function took(stage) {
    return stage.status !== 'running' && stage.started !== null && stage.finished !== null &&
      stage.finished >= stage.started ? stage.finished - stage.started : null;
  }

  // What the session says about one run, checked and cut to size.
  function reconStages(task) {
    var list = Array.isArray(task.stages) ? task.stages : [], stages = [];
    for (var i = 0; i < list.length && i < RECON_STAGES; i++) {
      var raw = list[i] && typeof list[i] === 'object' ? list[i] : {};
      var status = typeof raw.status === 'string' && hasOwn.call(STATUS_WORD, raw.status) ? raw.status : 'pending';
      var stage = { name: plain(raw.stage, 24) || '?', status: status, detail: plain(raw.detail, 300),
        started: stamp(raw.started_utc), finished: stamp(raw.finished_utc), progress: null };
      if (status === 'running') {
        var p = raw.progress && typeof raw.progress === 'object' ? raw.progress : {};
        var percent = whole(p.percent, 100), done = whole(p.done, 1e9), total = whole(p.total, 1e9);
        stage.progress = { part: null, items: '', percent: percent === null ? '' : percent + '%',
          eta: whole(p.eta_s, 359999), note: plain(p.note, 80) };
        // "3/9", "42%", or both ("1/4" and "42%"): the percent is then of
        // the item it is on.
        var items = done !== null && total ? Math.min(done, total) : null;
        if (items !== null) {
          stage.progress.part = Math.min(1, (items + (percent || 0) / 100) / total);
          stage.progress.items = items + '/' + total;
        } else if (percent !== null) {
          stage.progress.part = percent / 100;
        }
      }
      stages.push(stage);
    }
    return stages;
  }
  // What a running stage's tool says: "1/4 \u00b7 Service scan 42%",
  // "SYN Stealth Scan 75%", "3/9", "412 URLs so far". A percent is of the
  // scan named with it: nmap starts it over with each of its scans.
  function figure(progress) {
    if (!progress) { return ''; }
    var scan = progress.percent ? (progress.note ? apart(progress.note) + ' ' : '') + progress.percent : apart(progress.note);
    return [progress.items, scan].filter(Boolean).join(' \u00b7 ');
  }
  // A recon ends with its session: the stage that was running is stopped
  // for good, and the stages after it are left out with these words.
  var CLOSED_DETAIL = 'stopped: the session was closed', NOT_RUN_DETAIL = 'not run: the session was closed';
  function notRun(stage) {
    return stage.status === 'skipped' && /^not run: /.test(stage.detail);
  }
  // Has work to do in its session: waiting, running, or stopped by light mode.
  function live(stage) {
    return stage.status === 'pending' || stage.status === 'running' ||
      (stage.status === 'interrupted' && stage.detail !== CLOSED_DETAIL);
  }
  function reconCounts(stages) {
    var count = { pending: 0, running: 0, done: 0, skipped: 0, failed: 0, interrupted: 0, live: 0, notRun: 0 };
    stages.forEach(function (stage) {
      count[stage.status] += 1;
      if (live(stage)) { count.live += 1; }
      if (notRun(stage)) { count.notRun += 1; }
    });
    return count;
  }
  // The end of a session dropped it before any of its stages ran.
  function dropped(count) {
    return count.notRun > 0 && !(count.done || count.failed || count.interrupted);
  }
  // 0: a stage is running. 1: stages are left. 2: nothing is left.
  function reconRank(count) {
    return count.running ? 0 : count.live ? 1 : 2;
  }
  // "stopped", then why: a reason that starts with the word says it once.
  function statusWords(stage) {
    var word = STATUS_WORD[stage.status], detail = stage.detail;
    if (!detail) { return [word]; }
    return detail.slice(0, word.length).toLowerCase() === word ? [apart(detail)] : [word, apart(detail)];
  }
  // "services · done · 3 open ports · took 0:42": a segment's hint.
  function describeStage(stage) {
    var words = statusWords(stage), parts = [apart(stage.name), words[0]], spent = took(stage);
    if (figure(stage.progress)) { parts.push(figure(stage.progress)); }
    if (words.length > 1) { parts.push(words[1]); }
    if (spent !== null) { parts.push('took ' + clockText(spent / 1000)); }
    return parts.join(' \u00b7 ');
  }

  function reconModel(entry) {
    var task = entry.task, stages = entry.stages, count = entry.count, total = stages.length;
    var model = { stages: stages, running: -1, older: entry.older, olderCount: entry.olderCount,
      others: [entry.queued ? '+' + entry.queued + ' queued' : '', entry.notRun ? '+' + entry.notRun + ' not run' : '']
        .filter(Boolean).join(', '),
      id: plain(task.id, 20), mode: plain(task.mode, 16).replace(/[^a-z0-9_-]/gi, ''),
      when: stamp(task.created_utc) === null ? '' : String(task.created_utc).replace('T', ' ').slice(0, 16),
      cut: (Array.isArray(task.stages) ? task.stages.length : 0) - total };
    var spent = 0, timed = false, first = { failed: null, interrupted: null, skipped: null }, left = null;
    stages.forEach(function (stage, index) {
      var time = took(stage);
      if (time !== null) { spent += time; timed = true; }
      if (stage.status === 'running' && model.running < 0) { model.running = index; }
      if (hasOwn.call(first, stage.status) && !first[stage.status]) { first[stage.status] = stage; }
      if (!left && notRun(stage)) { left = stage; }
    });
    model.shape = model.id + '\n' + stages.map(function (stage) { return stage.name; }).join('\n');

    var now = model.running >= 0 ? stages[model.running] : null;
    // Stages that are over, however they ended, but not the ones the end
    // of the session left out: the HUD's "7/17", and how full the bar is.
    var over = count.done + count.skipped + count.failed - count.notRun;
    // "done" counts the stages that are done, and nothing else.
    var parts = [], of = count.done + ' of ' + total + ' done';
    var problem = entry.rank === 1 ? first.interrupted || first.failed : first.failed;
    if (now) {
      parts.push('stage ' + (model.running + 1) + ' of ' + total);
      if (count.failed) { parts.push(count.failed + ' failed'); }
      var said = figure(now.progress);
      parts.push(apart(now.name) + (said ? ' \u00b7 ' + said : ' running'));
      model.note = problem ? describeStage(problem) : '';
    } else if (entry.rank === 1) {
      if (count.done) { parts.push(of); }
      if (count.failed) { parts.push(count.failed + ' failed'); }
      var why = first.interrupted ? first.interrupted.detail : null;
      parts.push(why === null ? 'waiting' : /light mode/i.test(why) ? 'stopped \u2014 light mode' : 'stopped');
      model.note = problem ? describeStage(problem) : '';
    } else if (entry.dropped) {
      // Its session ended before it began.
      parts.push('not run \u2014 session closed');
      model.note = describeStage(left);
    } else if (first.interrupted || left) {
      // Its session ended while it ran: it does not go on.
      parts.push('stopped \u2014 session closed', of);
      if (count.failed) { parts.push(count.failed + ' failed'); }
      model.note = describeStage(first.interrupted || left);
    } else if (total && count.skipped === total) {
      parts.push('skipped');
      model.note = first.skipped.detail;
    } else {
      parts.push(total ? 'done' + (timed ? ' in ' + clockText(spent / 1000) : '') : 'no stages');
      if (count.failed) { parts.push(count.failed + ' failed'); }
      if (count.skipped) { parts.push(count.skipped + ' skipped'); }
      model.note = problem ? describeStage(problem) : '';
    }
    model.main = parts.join(' \u00b7 ');
    var settled = over + (now && now.progress.part ? now.progress.part : 0);
    model.percent = total ? Math.round(100 * settled / total) : 0;
    return model;
  }

  // Which segment of a row an event happened on, or -1.
  function segmentAt(view, target) {
    for (var node = target; node && node !== view.list; node = node.parentNode) {
      if (node.parentNode === view.list) { return Array.prototype.indexOf.call(view.list.children, node); }
    }
    return -1;
  }
  // The line under the bar: the stage under the pointer or the keyboard,
  // or else what the running stage is doing (or what went wrong).
  function paintNote(view) {
    var index = view.hover >= 0 ? view.hover : view.focused;
    var stage = index >= 0 && view.model ? view.model.stages[index] : null;
    var text = stage ? describeStage(stage) : view.model ? view.model.note : '';
    if (view.noteText === text) { return; }
    view.noteText = text;
    view.note.textContent = text;
    view.note.title = text;
    view.note.className = stage ? 'recon-note peek' : 'recon-note';
  }
  function moveFocus(view, index) {
    if (index < 0 || index >= view.segs.length || index === view.at) { return; }
    view.segs[view.at].node.tabIndex = -1;
    view.at = index;
    view.segs[index].node.tabIndex = 0;
  }

  function reconView(key) {
    var view = { key: key, model: null, shape: null, segs: [], at: 0, hover: -1, focused: -1,
      noteText: null, meterText: null, lines: null, eta: null, etaAt: 0 };
    view.item = el('li', 'recon-task');
    var head = view.item.appendChild(el('div', 'recon-head'));
    var name = head.appendChild(hint(el('div', 'recon-name'), key));
    name.appendChild(el('span', 'recon-word', 'Recon '));
    name.appendChild(el('span', null, key));
    view.queued = name.appendChild(el('span', 'recon-queued'));
    var text = head.appendChild(el('div', 'recon-text'));
    view.main = text.appendChild(el('span'));
    view.left = text.appendChild(el('span', 'recon-left'));
    view.clock = head.appendChild(hint(el('div', 'recon-clock'), 'Time in this stage'));
    var bar = view.item.appendChild(el('div', 'recon-bar'));
    view.meter = bar.appendChild(el('div', 'recon-meter'));
    view.meter.setAttribute('role', 'progressbar');
    view.meter.setAttribute('aria-valuemin', '0');
    view.meter.setAttribute('aria-valuemax', '100');
    view.meter.setAttribute('aria-label', 'Recon ' + key);
    view.list = bar.appendChild(el('div', 'recon-segs'));
    view.list.setAttribute('role', 'list');
    view.list.setAttribute('aria-label', 'Stages');
    // One stop for the Tab key per bar; the arrow keys walk its stages.
    view.list.addEventListener('keydown', function (event) {
      var last = view.segs.length - 1, to = -1;
      if (event.key === 'ArrowRight') { to = Math.min(last, view.at + 1); }
      if (event.key === 'ArrowLeft') { to = Math.max(0, view.at - 1); }
      if (event.key === 'Home') { to = 0; }
      if (event.key === 'End') { to = last; }
      if (to < 0 || last < 0) { return; }
      event.preventDefault();
      moveFocus(view, to);
      view.segs[view.at].node.focus();
    });
    view.list.addEventListener('focusin', function (event) {
      view.focused = segmentAt(view, event.target);
      moveFocus(view, view.focused);
      paintNote(view);
    });
    view.list.addEventListener('focusout', function () { view.focused = -1; paintNote(view); });
    view.list.addEventListener('mouseover', function (event) {
      view.hover = segmentAt(view, event.target);
      paintNote(view);
    });
    view.list.addEventListener('mouseleave', function () { view.hover = -1; paintNote(view); });
    var foot = view.item.appendChild(el('div', 'recon-foot'));
    view.note = foot.appendChild(el('div', 'recon-note'));
    view.more = foot.appendChild(fold('recon:' + key, 'recon-more', false));
    var summary = view.more.appendChild(hint(el('summary', null, 'Stages'), 'Every stage of this run, and its other runs'));
    view.panel = view.more.appendChild(el('div', 'recon-stages'));
    // Filled just before it opens, so it never opens empty.
    summary.addEventListener('click', function () { paintStages(view, true); });
    view.more.addEventListener('toggle', function () { paintStages(view); });
    return view;
  }

  // The time left and the time in the running stage: all that changes
  // between pushes. Returns the milliseconds until it changes again, or 0.
  function paintClock(view) {
    var model = view.model, stage = model && model.running >= 0 ? model.stages[model.running] : null;
    var now = sessionNow(), left = '', clock = '', next = 0;
    // The time left when the state was made, less the time since. One
    // that has run out is no longer known.
    var remaining = stage && view.eta !== null ? view.eta - (steady() - view.etaAt) / 1000 : 0;
    if (remaining > 0) {
      left = ' \u00b7 ' + leftText(remaining);
      next = 1000;
    }
    if (stage && stage.started !== null) {
      clock = clockText((now - stage.started) / 1000);
      next = 1000 - Math.max(0, now - stage.started) % 1000;
    }
    setText(view.left, left);
    setText(view.clock, clock);
    return next;
  }
  function reconTick() {
    clearTimeout(reconTimer);
    reconTimer = null;
    var wait = 0;
    reconViews.forEach(function (view) {
      var next = paintClock(view);
      if (next && (!wait || next < wait)) { wait = next; }
    });
    if (wait) { reconTimer = setTimeout(reconTick, wait + 20); }
  }
  // The session has gone (its terminal was closed) or cannot be reached.
  // Its recons ended with it, so they are shown as the next session will
  // find them: the running stage stopped, the ones after it left out, in
  // the words the session itself stores. Nothing ticks until it is back.
  function reconStill() {
    var tasks = state && Array.isArray(state.tasks) ? state.tasks : [], stopped = false;
    tasks.forEach(function (task) {
      (task && Array.isArray(task.stages) ? task.stages : []).forEach(function (stage) {
        if (!stage || typeof stage !== 'object') { return; }
        if (stage.status === 'running') {
          stage.status = 'interrupted';
          stage.detail = CLOSED_DETAIL;
        } else if (stage.status === 'pending' || (stage.status === 'interrupted' && stage.detail !== CLOSED_DETAIL)) {
          stage.status = 'skipped';
          stage.detail = NOT_RUN_DETAIL;
        } else {
          return;
        }
        delete stage.progress;
        stopped = true;
      });
    });
    if (stopped) { renderRecon(); }
    byId('recon').classList.add('still');
    reconTick();
  }

  function paintRow(view, model) {
    view.model = model;
    if (view.shape !== model.shape) {
      view.shape = model.shape;
      clear(view.list);
      view.at = 0;
      view.hover = view.focused = -1;
      view.eta = null;
      view.segs = model.stages.map(function (stage, index) {
        var node = view.list.appendChild(el('span', 'seg'));
        node.setAttribute('role', 'listitem');
        node.tabIndex = index ? -1 : 0;
        var seg = { node: node, look: '', width: '', text: '', most: 0, lost: false };
        seg.fill = node.appendChild(el('span', 'fill'));
        seg.cue = node.appendChild(el('span', 'cue'));
        node.appendChild(el('span', 'name', stage.name));
        return seg;
      });
      view.list.className = 'recon-segs' + (view.segs.length > 18 ? ' many' : '');
    }
    model.stages.forEach(function (stage, index) {
      var seg = view.segs[index], part = stage.progress ? stage.progress.part : null;
      if (stage.status !== 'running') {
        seg.most = 0;
        seg.lost = false;
      } else if (part !== null) {
        // nmap starts its figures over with each of its scans. A fill
        // that would shrink turns to the striped one of a share not
        // known, for the rest of the stage.
        if (part + 0.005 < seg.most) { seg.lost = true; }
        seg.most = Math.max(seg.most, part);
      }
      if (seg.lost) { part = null; }
      var look = stage.status + (stage.progress && part === null ? ' unknown' : '');
      if (seg.look !== look) {
        seg.look = look;
        seg.node.className = 'seg ' + look;
        seg.cue.textContent = STATUS_CUE[stage.status];
      }
      var width = part === null ? '' : Math.round(part * 100) + '%';
      if (seg.width !== width) { seg.width = width; seg.fill.style.width = width; }
      var text = describeStage(stage);
      if (seg.text !== text) {
        seg.text = text;
        hint(seg.node, text).setAttribute('aria-label', text);
      }
    });
    var now = model.running >= 0 ? model.stages[model.running] : null;
    // The time left is the time left when this state was made.
    view.eta = now ? now.progress.eta : null;
    view.etaAt = reconArrived;
    setText(view.main, model.main);
    setText(view.queued, model.others ? ' ' + model.others : '');
    var meter = model.percent + ' ' + model.main;
    if (view.meterText !== meter) {
      view.meterText = meter;
      view.meter.setAttribute('aria-valuenow', String(model.percent));
      view.meter.setAttribute('aria-valuetext', model.main);
    }
    paintNote(view);
    paintStages(view);
  }

  // Behind "Stages": one line per stage, then the other runs of the
  // target (all kept in the workspace). Built when opened.
  function paintStages(view, opening) {
    var model = view.model;
    if (!(opening || view.more.open) || !model) { return; }
    var lines = model.stages.map(function (stage) {
      var words = statusWords(stage), spent = took(stage);
      if (spent !== null) { words.push('took ' + clockText(spent / 1000)); }
      return { stage: stage, text: words.join(' \u00b7 ') };
    });
    var facts = [model.id ? '#' + model.id : '', model.mode, model.when].filter(Boolean).join(' \u00b7 ');
    var sig = facts + '\n' + model.olderCount + '\n' + lines.map(function (line) {
      return line.stage.name + ' ' + line.stage.status + ' ' + line.text;
    }).join('\n');
    if (view.lines === sig) { return; }
    view.lines = sig;
    clear(view.panel);
    if (facts) { view.panel.appendChild(el('div', 'dim', facts)); }
    var list = view.panel.appendChild(el('div', 'recon-lines'));
    lines.forEach(function (line) {
      var label = el('span', 'label');
      label.appendChild(el('span', 'recon-cue ' + line.stage.status, STATUS_CUE[line.stage.status]));
      label.appendChild(document.createTextNode(' ' + line.stage.name));
      list.appendChild(row(label, line.text, line.stage.status));
    });
    if (model.cut > 0) { view.panel.appendChild(el('div', 'dim', model.cut + ' more stages not shown')); }
    if (model.olderCount) {
      var past = view.panel.appendChild(fold('runs:' + view.key, 'names', false));
      past.appendChild(el('summary', null, 'Other runs (' + model.olderCount + ')'));
      model.older.forEach(function (run) {
        var count = reconCounts(reconStages(run)), words = [];
        ['running', 'done', 'failed', 'interrupted', 'skipped', 'pending'].forEach(function (status) {
          if (count[status]) { words.push(count[status] + ' ' + STATUS_WORD[status]); }
        });
        var when = stamp(run.created_utc) === null ? '' : String(run.created_utc).replace('T', ' ').slice(0, 16);
        var line = past.appendChild(el('div', 'fact'));
        line.appendChild(el('div', null, '#' + plain(run.id, 20) + (when ? '  ' + when : '')));
        line.appendChild(el('div', 'dim', words.join(' \u00b7 ')));
      });
      if (model.olderCount > model.older.length) {
        past.appendChild(el('div', 'fact dim', (model.olderCount - model.older.length) + ' more not shown'));
      }
    }
  }

  // The strip's height is taken off the map's, so both fit the window.
  function reconFit() {
    var box = byId('recon'), height = box.hidden ? 0 : box.offsetHeight + 14;
    if (height === reconHeight) { return; }
    reconHeight = height;
    byId('top').style.setProperty('--recon-h', height + 'px');
    cy.resize();
    fitDrawing(false);
  }
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(reconFit).observe(byId('recon'));
  } else {
    window.addEventListener('resize', reconFit);
  }

  // A progress message: how far the running stages are, and the session's
  // clock. It changes nothing else, so nothing else is drawn again: the
  // cards keep their selection and every click reaches its button.
  var RECON_TICKS = 64;
  function reconProgress(message) {
    var said = table(), list = Array.isArray(message.running) ? message.running : [];
    for (var i = 0; i < list.length && i < RECON_TICKS; i++) {
      var tick = list[i];
      if (tick && typeof tick === 'object' && tick.progress && typeof tick.progress === 'object') {
        said[plain(tick.task, 20) + '\n' + plain(tick.stage, 24)] = tick.progress;
      }
    }
    (Array.isArray(state.tasks) ? state.tasks : []).forEach(function (task) {
      if (!task || typeof task !== 'object' || !Array.isArray(task.stages)) { return; }
      task.stages.forEach(function (stage) {
        if (!stage || typeof stage !== 'object' || stage.status !== 'running') { return; }
        var progress = own(said, plain(task.id, 20) + '\n' + plain(stage.stage, 24));
        if (progress) { stage.progress = progress; } else { delete stage.progress; }
      });
    });
    if (typeof message.now_utc === 'string') { state.now_utc = message.now_utc; }
    // The time left counts from this message.
    reconState = null;
    renderRecon();
  }

  function renderRecon() {
    syncClock(state.now_utc);
    if (state !== reconState) {
      reconState = state;
      reconArrived = steady();
    }
    // Each target once: the run that has work to do (the one running, else
    // the oldest that waits: tasks run oldest first), else the newest that
    // began, else the newest. Newer runs that wait behind it are counted as
    // queued, newer ones a session's end dropped as not run. The session
    // lists the newest first. The HUD picks the same way.
    var tasks = Array.isArray(state.tasks) ? state.tasks : [];
    var groups = table(), keyed = [], entries = [];
    for (var i = 0; i < tasks.length && i < RECON_SCAN; i++) {
      var task = tasks[i];
      if (!task || typeof task !== 'object') { continue; }
      var key = plain(task.target, 120) || '?';
      var group = own(groups, key);
      if (!group) {
        group = groups[key] = { key: key, runs: [] };
        keyed.push(group);
      }
      group.runs.push({ task: task, at: i });
    }
    var targets = keyed.length;
    keyed.slice(0, 10 * RECON_TARGETS).forEach(function (group) {
      var runs = group.runs, pick = -1, queued = 0, older = [];
      runs.forEach(function (run, j) {
        run.stages = reconStages(run.task);
        run.count = reconCounts(run.stages);
        if (pick < 0 && run.count.running) { pick = j; }
      });
      for (var j = runs.length - 1; pick < 0 && j >= 0; j--) {
        if (runs[j].count.live) { pick = j; }
      }
      for (var k = 0; pick < 0 && k < runs.length; k++) {
        if (!dropped(runs[k].count)) { pick = k; }
      }
      pick = Math.max(0, pick);
      var notRun = 0;
      runs.forEach(function (run, j) {
        if (j === pick) { return; }
        if (j < pick && run.count.live) {
          queued += 1;
        } else {
          if (j < pick && dropped(run.count)) { notRun += 1; }
          older.push(run.task);
        }
      });
      var chosen = runs[pick];
      entries.push({ key: group.key, task: chosen.task, index: chosen.at, stages: chosen.stages,
        count: chosen.count, rank: reconRank(chosen.count), queued: queued, notRun: notRun,
        dropped: dropped(chosen.count), older: older.slice(0, RECON_EARLIER), olderCount: older.length });
    });
    // Shown in full, three rows at most: what is running, what waits its
    // turn (the next one first), then what finished while this page
    // watched; a lone finished run when there is nothing else. The others
    // fold away under them.
    var chosen = entries.slice().sort(function (a, b) {
      return a.rank - b.rank || a.dropped - b.dropped ||
        (a.rank === 1 ? b.index - a.index : a.index - b.index);
    }).slice(0, RECON_TARGETS);
    var watched = table(), top = [], rest = [];
    chosen.forEach(function (item) {
      var mark = item.key + '\n' + plain(item.task.id, 20);
      if (item.rank < 2 || own(reconWatched, mark)) {
        watched[mark] = true;
        if (top.length < RECON_ROWS) { top.push(item); return; }
      }
      rest.push(item);
    });
    reconWatched = watched;
    if (!top.length && rest.length) { top.push(rest.shift()); }
    var hidden = targets - chosen.length;

    var list = byId('recon-list'), box = byId('recon');
    var order = JSON.stringify([top.map(function (item) { return item.key; }),
      rest.map(function (item) { return item.key; }), hidden]);
    var changed = order !== reconOrder;
    if (changed) {
      reconOrder = order;
      var views = table();
      reconViews = [];
      var place = function (parent) {
        return function (item) {
          var view = views[item.key] = own(reconByKey, item.key) || reconView(item.key);
          reconViews.push(view);
          parent.appendChild(view.item);
        };
      };
      clear(list);
      top.forEach(place(list));
      if (rest.length || hidden) {
        var more = list.appendChild(el('li', 'recon-rest')).appendChild(fold('recon-rest', 'recon-fold', false));
        more.appendChild(el('summary', null, (rest.length + hidden) + ' more'));
        var inner = more.appendChild(el('ul'));
        rest.forEach(place(inner));
        if (hidden) { inner.appendChild(el('li', 'dim', hidden + ' not shown')); }
      }
      reconByKey = views;
      box.hidden = !reconViews.length;
      document.body.classList.toggle('recon-on', reconViews.length > 0);
    }
    top.concat(rest).forEach(function (item) { paintRow(own(reconByKey, item.key), reconModel(item)); });
    box.classList.remove('still');
    reconTick();
    if (changed) { reconFit(); }
  }

  function selectedNodeData() {
    if (!selected || !state) { return null; }
    var node = cy.$id(selected);
    if (node && !node.empty()) { return node.data(); }
    var nodes = (state.topology && state.topology.nodes) || [];
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].data && nodes[i].data.id === selected) { return nodes[i].data; }
    }
    return null;
  }

  // "This machine": address -> type -> OS -> version, then a row per
  // subject. The long tables (routes, neighbours, every interface) are
  // cards of their own further down the page.
  var machineDrawn = '';

  function renderMachine() {
    var machine = state.machine || { vpn: [], sections: [] };
    var vpn = byId('vpn');
    vpn.textContent = machine.vpn.length ? 'VPN ' + machine.vpn.map(vpnName).join(', ') : 'no VPN';
    vpn.className = machine.vpn.length ? 'badge ok' : 'badge';
    vpn.title = machine.vpn.join('\n') || 'No VPN interface with an address was found.';

    var key = JSON.stringify(machine);
    if (key === machineDrawn) { return; }
    machineDrawn = key;
    var box = clear(byId('machine'));
    var parts = (machine.headline || '').split(' -> ');
    ['Address', 'Machine', 'System', 'Version'].forEach(function (label, index) {
      box.appendChild(row(label, parts[index] || 'not known'));
    });
    var tables = clear(byId('machine-cards'));
    machine.sections.forEach(function (section) {
      var lines = el('div');
      section.lines.forEach(function (line) {
        lines.appendChild(el('div', section.warn ? 'warn-text' : null, line));
      });
      if (section.open) {
        // One short value; the sentence it came from is the hint.
        var text = section.lines.join(' ');
        var tools = (text.match(/`([^`]+)`/g) || []).map(function (t) { return t.slice(1, -1); });
        var value = /not installed/.test(text) && tools.length ? tools.join(', ') + ' not installed'
          : text.length > 32 ? short(text) : text;
        box.appendChild(hint(row(section.title, value, section.warn ? 'warn-text' : null), section.lines.join('\n')));
        return;
      }
      // A table with nothing in it is left out.
      if (/\(0\)$/.test(section.title) || !section.lines.length ||
          (section.lines.length === 1 && /^none$/i.test(section.lines[0]))) {
        return;
      }
      var table = tables.appendChild(card(section.title));
      lines.className = 'lines';
      table.appendChild(lines);
    });
    if (machine.observed_utc) {
      box.title = 'Read from this machine at ' + machine.observed_utc.slice(11, 19) +
        ' UTC. Nothing was sent to find this out.';
    }
  }

  var locatedFor = null;
  function select(id) {
    selected = id;
    cy.elements().unselect();
    if (id) { cy.$id(id).select(); }
    // The round map follows the selected device, and comes back to you.
    var address = selectedAddress();
    if (address !== locatedFor) {
      locatedFor = address;
      mapCloser = false;
      send({ cmd: 'locate_host', address: address });
    }
    renderDetail();
    renderHosts();
    renderCves();
    renderWhere();
    renderAiPanel();
  }

  var MULTI_TLDS = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'org.au',
    'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.mx', 'co.za', 'co.in', 'com.sg', 'com.hk'];

  function rootDomainOf(hostname) {
    var clean = String(hostname || '').trim().replace(/^\*\./, '').replace(/\.$/, '').toLowerCase();
    if (!clean || /^\d+\.\d+\.\d+\.\d+$/.test(clean) || clean.indexOf(':') >= 0) { return ''; }
    var parts = clean.split('.');
    if (parts.length < 2) { return ''; }
    var lastTwo = parts[parts.length - 2] + '.' + parts[parts.length - 1];
    if (parts.length >= 3 && MULTI_TLDS.indexOf(lastTwo) >= 0) {
      return parts[parts.length - 3] + '.' + lastTwo;
    }
    return lastTwo;
  }

  function associatedNamesFor(host, data) {
    if (data && ((data.associated_domains && data.associated_domains.length) ||
        (data.associated_hosts && data.associated_hosts.length))) {
      return {
        domains: (data.associated_domains || []).slice(),
        hosts: (data.associated_hosts || []).slice()
      };
    }
    var raw = (host && host.hostnames) ? host.hostnames.slice() : [];
    var dSet = table(), subSet = table(), apexSet = table();
    raw.forEach(function (n) {
      var clean = String(n || '').trim().replace(/^\*\./, '').replace(/\.$/, '').toLowerCase();
      if (!clean || (host && clean === host.address)) { return; }
      var root = rootDomainOf(clean);
      if (root) {
        dSet[root] = true;
        if (clean !== root) { subSet[clean] = true; } else { apexSet[clean] = true; }
      } else {
        subSet[clean] = true;
      }
    });
    var domains = Object.keys(dSet).sort();
    var hostNames = Object.keys(subSet).sort();
    if (!hostNames.length) { hostNames = Object.keys(apexSet).sort(); }
    return { domains: domains, hosts: hostNames };
  }

  // Associated Hosts: Domains (e.g. nmap.org) and Hosts (e.g. scanme.nmap.org).
  function renderHosts() {
    var list = clear(byId('hosts'));
    var hosts = state.topology.nodes.filter(function (node) { return node.data.kind === 'host'; });
    hosts.sort(function (a, b) { return sortKey(a.data) < sortKey(b.data) ? -1 : 1; });
    if (!hosts.length) {
      list.appendChild(hint(el('p', 'note', 'No hosts yet.'), 'Work in the session shell, or import a scan with `meow add <file>`.'));
    } else {
      var selData = selectedNodeData();
      var onlyAddr = selData && selData.kind === 'host' && selData.address ? selData.address : null;
      var targetNodes = onlyAddr
        ? hosts.filter(function (n) { return n.data.address === onlyAddr; })
        : hosts;

      var domainMap = table();
      var hostRows = [];
      targetNodes.forEach(function (node) {
        var d = node.data;
        var hObj = (state.graph && state.graph.hosts && own(state.graph.hosts, d.address)) || null;
        var assoc = associatedNamesFor(hObj, d);
        assoc.domains.forEach(function (dom) {
          if (!own(domainMap, dom)) { domainMap[dom] = []; }
          if (domainMap[dom].indexOf(d) < 0) { domainMap[dom].push(d); }
        });
        if (assoc.hosts.length) {
          assoc.hosts.forEach(function (hName) {
            hostRows.push({ label: hName, data: d });
          });
        } else {
          hostRows.push({ label: d.address, data: d });
        }
      });

      var domainKeys = Object.keys(domainMap).sort();
      list.appendChild(el('h3', null, 'Domains'));
      if (domainKeys.length) {
        domainKeys.forEach(function (dom) {
          var linkedNodes = domainMap[dom];
          var firstNode = linkedNodes[0];
          var domBtn = el('button', 'link', dom);
          domBtn.addEventListener('click', function () { select(firstNode.id); });
          var addrs = linkedNodes.map(function (n) { return n.address; }).join(', ');
          var domLine = list.appendChild(row(domBtn, addrs, 'dim'));
          if (firstNode.id === selected) { domLine.className += ' current'; }
        });
      } else {
        list.appendChild(el('div', 'dim', 'None resolved'));
      }

      list.appendChild(el('h3', null, 'Hosts'));
      hostRows.forEach(function (entry) {
        var data = entry.data;
        var name = el('button', 'link', entry.label);
        name.addEventListener('click', function () { select(data.id); });
        var facts = [];
        if (entry.label !== data.address) { facts.push(data.address); }
        facts.push(data.open_ports + (data.open_ports === 1 ? ' port' : ' ports'));
        var kind = 'ok';
        if (data.cves) {
          facts.push(data.cves + (data.cves === 1 ? ' CVE' : ' CVEs'));
          kind = data.serious_cves ? 'bad' : 'warn';
        }
        var line = list.appendChild(row(name, marked(facts.join(' · '), kind)));
        if (data.id === selected) { line.className += ' current'; }
      });
    }

    // Names that were only printed in the session shell or a log, usually
    // inside a URL. Nothing was seen on them and no address is known, so
    // they are listed here and not drawn as machines.
    var mentioned = state.topology.mentioned || [];
    if (mentioned.length) {
      var names = list.appendChild(fold('mentioned', 'names', false));
      names.appendChild(hint(el('summary', null, 'Names only mentioned (' + mentioned.length + ')'),
        'Seen in the terminal, a log or the certificate logs. meow has not connected to them.'));
      mentioned.forEach(function (entry) {
        var what = (entry.ports || []).join(', ') || 'no port';
        if (entry.paths) { what += ' · ' + entry.paths + (entry.paths === 1 ? ' path' : ' paths'); }
        // How the name answers in DNS: one only a wildcard answers for may
        // not exist, so it is faded.
        if (entry.dns_status === 'wildcard') {
          var faded = names.appendChild(row(entry.name, marked('wildcard only, may not exist', 'warn')));
          faded.className += ' faded';
          faded.title = entry.dns || '';
          return;
        }
        if (entry.dns_status === 'gone') { what = 'no DNS record now · ' + what; }
        if (entry.dns_status === 'resolves') { what = (entry.dns || 'resolves') + ' · ' + what; }
        names.appendChild(row(entry.name, what, 'dim'));
      });
    }
  }

  function renderSide() {
    renderMachine();
    renderHosts();
    renderCves();

    var notices = (state.notices || []).slice(-25).reverse();
    byId('notices-count').textContent = notices.length ? '(' + notices.length + ')' : '';
    renderList(byId('notices'), notices, 'Nothing yet.', function (notice) {
      var item = el('li');
      item.appendChild(el('span', 'dim', String(notice.at || '').slice(11, 19) + ' '));
      item.appendChild(document.createTextNode(String(notice.text || '')));
      return item;
    });
  }

  function pathTree(node, budget) {
    var list = el('ul', 'tree');
    var children = (node && node.children) || {};
    Object.keys(children).forEach(function (name) {
      if (budget.left <= 0) { return; }
      var child = own(children, name);
      if (!child) { return; }
      budget.left -= 1;
      var hasChildren = child.children && Object.keys(child.children).length > 0;
      var item = el('li', null, '/' + name + (hasChildren ? '/' : ''));
      if (child.status) { item.appendChild(el('span', 'dim', ' ' + child.status)); }
      if (hasChildren) { item.appendChild(pathTree(child, budget)); }
      list.appendChild(item);
    });
    return list;
  }

  // How many CVEs a host has, how many are known exploited, and how many
  // are known exploited, critical or high (drawn red).
  function cveCounts(address) {
    var counts = { total: 0, kev: 0, serious: 0 };
    (own(state.cves || {}, address) || []).forEach(function (group) {
      counts.kev += group.kev || 0;
      (group.cves || []).forEach(function (entry) {
        counts.total += 1;
        if (entry.serious) { counts.serious += 1; }
      });
    });
    return counts;
  }

  // "3 CVEs (1 known exploited)"
  function cveWords(counts) {
    if (!counts.total) { return ''; }
    return counts.total + (counts.total === 1 ? ' CVE' : ' CVEs') +
      (counts.kev ? ' (' + counts.kev + ' known exploited)' : '');
  }

  // One CVE: its ID, rating and title on a line that unfolds into the
  // release that fixes it.
  function cveItem(address, advisory, entry, withHost) {
    var kind = entry.serious ? 'bad' : 'warn';
    var item = fold('cve:' + address + ':' + advisory.id, 'item', false);
    var summary = item.appendChild(el('summary'));
    summary.appendChild(mark(kind));
    var line = summary.appendChild(el('span', 'what'));
    line.appendChild(el('span', 'cve-id', advisory.id));
    line.appendChild(el('span', 'sev ' + kind + '-text', entry.severity || 'unrated'));
    if (advisory.kev) { line.appendChild(el('span', 'kev', 'known exploited')); }
    var title = line.appendChild(el('span', 'title', advisory.title));
    title.title = advisory.title;
    if (advisory.fixed_in) {
      item.appendChild(row('Fixed in', advisory.fixed_in));
    } else if (advisory.last_affected) {
      item.appendChild(row('Affected up to', advisory.last_affected));
    }
    // The group heading names the software and version; a match on the
    // name alone is less sure, so it is said.
    var words = /^keywordSearch=(.*)$/.exec(String(advisory.matched || ''));
    if (words) { item.appendChild(row('Matched on', 'name search: ' + words[1])); }
    if (withHost) {
      var look = item.appendChild(el('div', 'actions')).appendChild(el('button', null, 'Show host'));
      look.addEventListener('click', function () { select('host:' + address); });
    }
    return item;
  }

  // The CVEs found from one piece of software: "nginx 1.18.0 · 443/tcp ·
  // fixed in 1.20.1", then each CVE, the most urgent first. At most
  // `budget.left` of them: the rest are counted.
  function cveGroup(address, host, group, open, withHost, budget) {
    var entries = group.cves || [];
    var serious = entries.some(function (entry) { return entry.serious; });
    var key = 'cves:' + address + ':' + group.software + ':' + (group.port || '');
    var section = fold(key, 'group ' + (serious ? 'bad' : 'warn'), open);
    var summary = section.appendChild(el('summary'));
    var parts = [group.software];
    if (group.port) { parts.push(group.port); }
    if (group.fix) { parts.push(group.fix); }
    summary.appendChild(el('span', 'name', parts.join(' · ')));
    summary.appendChild(el('span', 'dim', ' ' + cveWords({ total: entries.length, kev: group.kev || 0 })));
    // Said once on the host's own list, not again for each host of the overview.
    if (group.note && !withHost) { section.appendChild(el('p', 'note', group.note.replace(/`/g, '') + '.')); }
    var known = table();
    (host.advisories || []).forEach(function (advisory) { known[advisory.id] = advisory; });
    var shown = entries.slice(0, Math.max(0, budget.left));
    budget.left -= shown.length;
    shown.forEach(function (entry) {
      var advisory = own(known, entry.id);
      if (advisory) { section.appendChild(cveItem(address, advisory, entry, withHost)); }
    });
    if (entries.length > shown.length) {
      section.appendChild(el('p', 'note', '+' + (entries.length - shown.length) +
        (withHost ? ' more: select the host to see them' : ' more in the report')));
    }
    return section;
  }

  // How much the CVEs card draws: every state push rebuilds it.
  var CVES_PER_HOST = 200;
  var CVES_IN_OVERVIEW = 80;
  var HOSTS_IN_OVERVIEW = 20;
  var FIXES_IN_OVERVIEW = 20;

  // Whether CVEs could be looked up for a host: a version seen on a port.
  function hasVersions(host) {
    return Object.keys((host && host.ports) || {}).some(function (key) {
      var port = own(host.ports, key);
      return port && port.state === 'open' &&
        ((port.product && port.version) || (port.cpes || []).length > 0);
    });
  }

  // The CVEs card: what to update first, then the CVEs of each host by
  // the software and version they were found from. For the selected host,
  // or for every host when none is selected.
  function renderCves() {
    var box = clear(byId('cves'));
    var selData = selectedNodeData();
    var only = selData && selData.address ? selData.address : null;
    byId('cves-title').textContent = only ? 'CVEs for ' + only : 'CVEs';
    // What to do comes first: one line per piece of software, since one
    // update usually fixes every CVE found from it.
    var hostsMap = (state.graph && state.graph.hosts) || {};
    var byHost = state.cves || {};
    var addresses = Object.keys(byHost).filter(function (address) {
      return (!only || address === only) && own(hostsMap, address);
    });
    // The host with the most known exploited, then the most serious, CVEs first.
    addresses.sort(function (a, b) {
      var ca = cveCounts(a), cb = cveCounts(b);
      return (cb.kev - ca.kev) || (cb.serious - ca.serious) || (cb.total - ca.total) || (a < b ? -1 : a > b ? 1 : 0);
    });
    var fixes = state.fixes || {};
    var mine = table();
    ((state.graph && state.graph.local && state.graph.local.interfaces) || []).forEach(function (iface) {
      (iface.addresses || []).forEach(function (cidr) { mine[cidr.split('/')[0]] = true; });
    });
    // In the order of the CVEs below it.
    var plan = [];
    addresses.forEach(function (address) {
      (own(fixes, address) || []).forEach(function (fix) { plan.push({ address: address, fix: fix }); });
    });
    var planLeft = only ? 0 : Math.max(0, plan.length - FIXES_IN_OVERVIEW);
    if (planLeft) { plan = plan.slice(0, FIXES_IN_OVERVIEW); }
    if (plan.length) {
      var todo = box.appendChild(el('div', 'todo'));
      todo.appendChild(el('h3', null, 'What to update'));
      var elsewhere = false;
      plan.forEach(function (entry) {
        var fix = entry.fix;
        var here = !!mine[entry.address];
        elsewhere = elsewhere || !here;
        var line = todo.appendChild(el('div', 'fix'));
        line.appendChild(el('div', null, fix.action));
        line.appendChild(el('div', 'dim', 'On ' + entry.address + (here ? ' (this machine)' : ' (another machine, not this one)') +
          ' · fixes ' + cveWords({ total: fix.advisories, kev: fix.kev })));
      });
      if (planLeft) { todo.appendChild(el('p', 'note', '+' + planLeft + ' more: select a host to see its own')); }
      todo.appendChild(hint(el('p', 'note', 'Found by version number. Rescan after updating.'),
        (elsewhere ? 'An update has to be made on the machine named, by whoever looks after it. ' : '') +
        'A system that takes security updates from its vendor often has the fix under the same version number.'));
    }
    // Every host's CVEs would be thousands of rows on a large network:
    // the overview shows the first ones, a selected host its own.
    var budget = { left: only ? CVES_PER_HOST : CVES_IN_OVERVIEW };
    var hostsLeft = only ? 0 : Math.max(0, addresses.length - HOSTS_IN_OVERVIEW);
    addresses.slice(0, only ? 1 : HOSTS_IN_OVERVIEW).forEach(function (address) {
      var host = own(hostsMap, address);
      if (!only) {
        var head = box.appendChild(el('h3', 'cve-host'));
        var names = host.hostnames || [];
        var link = head.appendChild(el('button', 'link', names.length ? names[0] + ' (' + address + ')' : address));
        link.type = 'button';
        link.addEventListener('click', function () { select('host:' + address); });
        head.appendChild(el('span', 'dim', ' ' + cveWords(cveCounts(address))));
      }
      (own(byHost, address) || []).forEach(function (group, index) {
        var serious = (group.cves || []).some(function (entry) { return entry.serious; });
        box.appendChild(cveGroup(address, host, group, (index === 0 || serious) && budget.left > 0, !only, budget));
      });
    });
    if (hostsLeft) {
      box.appendChild(el('p', 'note', '+' + hostsLeft + (hostsLeft === 1 ? ' more host' : ' more hosts') +
        ' with CVEs: select one to see them, or see the report'));
    }
    if (!addresses.length) {
      var empty = only ? 'No CVEs found for this host.' : 'No CVEs found yet.';
      if (state.cve_lookups === false) {
        empty = 'CVE lookups are off.';
      } else if (only && !hasVersions(own(hostsMap, only))) {
        empty = 'No software version seen yet.';
      }
      box.appendChild(hint(el('p', 'note', empty),
        'CVEs are looked up from the software and version seen on each port.'));
    }
  }

  // The cards of a selected host: only the ones there is something to say in.
  // "2026-11-17T09:41:00Z" as "3 min ago", or the date when it is older.
  function sinceText(at) {
    var then = Date.parse(at || '');
    if (!isFinite(then)) { return ''; }
    var seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
    if (seconds < 60) { return seconds + ' s ago'; }
    if (seconds < 3600) { return Math.round(seconds / 60) + ' min ago'; }
    if (seconds < 86400) { return Math.round(seconds / 3600) + ' h ago'; }
    return String(at).slice(0, 10);
  }

  // Whether the host is there: what the scans saw, and what "Check now"
  // found. "Check now" makes one connection to each of a few known open
  // ports; light mode sends nothing, so there it is off.
  function statusCard(host) {
    var box = card('Server Status');
    var check = own((state && state.checks) || {}, host.address) || null;
    var facts = (host.facts || []).slice();
    Object.keys(host.ports || {}).forEach(function (key) {
      var port = own(host.ports, key);
      (port && port.facts || []).forEach(function (fact) { facts.push(fact); });
    });
    var seenUp = '', lastScan = '';
    facts.forEach(function (fact) {
      // A fact's record is stored flat beside its claim.
      var record = fact.record || fact;
      var at = String(record.timestamp_utc || '');
      if (!at) { return; }
      if (fact.claim === 'host is up' && at > seenUp) { seenUp = at; }
      if (record.source === 'nmap_xml' && at > lastScan) { lastScan = at; }
    });
    var openCount = Object.keys(host.ports || {}).filter(function (key) {
      var port = own(host.ports, key);
      return port && port.state === 'open';
    }).length;

    var status, kind;
    if (check && check.status === 'checking') { status = 'checking\u2026'; kind = 'info'; }
    else if (check && check.status === 'up') { status = 'up'; kind = 'ok'; }
    else if (check && check.status === 'down') { status = 'not answering'; kind = 'bad'; }
    else if (seenUp) { status = 'up when last scanned'; kind = 'ok'; }
    else if (openCount) { status = 'answered on open ports'; kind = 'ok'; }
    else { status = 'not checked yet'; kind = 'warn'; }
    box.appendChild(row('Status', marked(status, kind)));
    if (seenUp) {
      var seenRow = box.appendChild(row('Last seen up', sinceText(seenUp)));
      seenRow.title = seenUp.slice(0, 19).replace('T', ' ') + ' UTC';
    }
    if (lastScan && lastScan !== seenUp) { box.appendChild(row('Last scan', sinceText(lastScan))); }
    box.appendChild(row('Open ports', String(openCount)));
    if (check && check.status !== 'checking') {
      box.appendChild(row('Last checked', sinceText(check.at)));
      var answers = (check.ports || []).map(function (p) {
        return p.port + ' ' + p.state + (typeof p.ms === 'number' ? ' (' + p.ms.toFixed(0) + ' ms)' : '');
      });
      if (answers.length) { box.appendChild(row('Tried', answers.join(', '))); }
      var fastest = (check.ports || []).filter(function (p) { return typeof p.ms === 'number'; })
        .map(function (p) { return p.ms; }).sort(function (a, b) { return a - b; })[0];
      if (typeof fastest === 'number') { box.appendChild(row('Connect time', fastest.toFixed(1) + ' ms')); }
    }
    var light = state && state.mode === 'light';
    var actions = box.appendChild(el('div', 'actions'));
    var button = actions.appendChild(el('button', null, check && check.status === 'checking' ? 'Checking\u2026' : 'Check now'));
    button.disabled = !!light || !!(check && check.status === 'checking');
    button.addEventListener('click', function () {
      send({ cmd: 'check_host', address: host.address });
    });
    button.title = light
      ? 'Light mode sends no packets: switch to mild or aggressive to check.'
      : 'One connection to each of up to six known open ports (or 443, 80 and 22), and nothing else.';
    return box;
  }

  function hostCards(host, data) {
    var hostPorts = host.ports || {};

    // One line per port: number, state, service and the software that
    // answered, open ports first.
    var ports = card('Ports');
    var stateRank = function (state) {
      return state === 'open' ? 0 : /filtered/.test(state || '') ? 1 : 2;
    };
    var keys = Object.keys(hostPorts).filter(function (key) { return !!own(hostPorts, key); });
    keys.sort(function (a, b) {
      var pa = hostPorts[a], pb = hostPorts[b];
      return stateRank(pa.state) - stateRank(pb.state) || pa.number - pb.number || (a < b ? -1 : 1);
    });
    var grid = keys.length ? ports.appendChild(el('div', 'port-table')) : null;
    if (grid) {
      var head = grid.appendChild(el('div', 'port-line port-head'));
      ['Port', 'State', 'Service', 'Version'].forEach(function (name) { head.appendChild(el('span', null, name)); });
    }
    keys.forEach(function (key) {
      var port = own(hostPorts, key);
      var line = grid.appendChild(el('div', 'port-line'));
      line.appendChild(el('span', 'num', String(port.number) +
        (port.protocol && port.protocol !== 'tcp' ? '/' + port.protocol : '')));
      var stateText = String(port.state || 'unverified');
      var stateClass = stateText === 'open' ? 'open' : /filtered/.test(stateText) ? 'filtered' : 'closed';
      line.appendChild(el('span', 'state ' + stateClass, stateText));
      var service = /^(ssl\/http|https)$/.test(port.service || '') ? 'https' : (port.service || '—');
      var svc = line.appendChild(el('span', 'svc', service));
      svc.title = service;
      var software = [port.product, port.version].filter(Boolean).join(' ');
      var ver = line.appendChild(el('span', 'ver' + (software ? ' known' : ''), software || '—'));
      if (port.extra_info) { ver.appendChild(el('span', 'extra', ' (' + port.extra_info + ')')); }
    });
    if (!keys.length) { ports.appendChild(el('p', 'note', 'No ports yet.')); }
    var notOpen = host.not_open || {};
    Object.keys(notOpen).forEach(function (key) {
      var group = own(notOpen, key);
      if (!group) { return; }
      ports.appendChild(hint(el('p', 'note', group.count + ' ' + group.protocol + ' ' + group.state),
        group.ports ? group.ports.split(',').join(', ') : ''));
    });

    // What the web ports gave away: server headers, certificate names, paths.
    var web = card('Web & TLS');
    Object.keys(hostPorts).forEach(function (key) {
      var port = own(hostPorts, key);
      if (!port) { return; }
      var paths = port.paths && port.paths.children && Object.keys(port.paths.children).length;
      var sans = port.tls_sans || [];
      var http = port.http || null;
      if (!http && !sans.length && !paths) { return; }
      web.appendChild(el('h3', null, key));
      // What the site is built with; an outdated library carries why.
      if (http && http.tech && http.tech.length) {
        var stack = el('span');
        http.tech.forEach(function (name, index) {
          if (index) { stack.appendChild(document.createTextNode(', ')); }
          var old = /\(older than|end of life/.test(name);
          stack.appendChild(hint(el('span', old ? 'warn-text' : null, name.split(' (')[0] + (old ? ' \u26a0' : '')),
            old ? name : ''));
        });
        web.appendChild(row('Stack', stack));
      }
      if (http && http.header_grade) {
        var graded = el('span', 'grade-inline');
        var missingCount = (http.header_notes || []).filter(function (n) { return /^missing /.test(n); })
          .map(function (n) { return n.split(', ').length; })[0] || 0;
        if (missingCount) { graded.appendChild(el('span', 'dim', missingCount + ' missing ')); }
        graded.appendChild(el('span', 'grade small ' + gradeKind(http.header_grade), http.header_grade));
        web.appendChild(hint(row('Headers', graded), (http.header_notes || []).join('\n')));
      }
      if (http && http.cookies && http.cookies.length) {
        var jar = el('div');
        http.cookies.forEach(function (cookie) {
          var issues = (cookie.issues || []).map(short);
          var line = jar.appendChild(hint(el('div', 'cookie'), cookie.flags + ((cookie.issues || []).length
            ? '\n' + cookie.issues.join('\n') : '')));
          line.appendChild(el('span', null, cookie.name));
          if (issues.length) { line.appendChild(el('span', 'warn-text', ' \u2014 ' + issues.join(', '))); }
        });
        web.appendChild(row('Cookies', jar));
      }
      // Keys found in the site's scripts: only their vault placeholder.
      if (http && http.js_secrets && http.js_secrets.length) {
        var keys = el('div');
        http.js_secrets.forEach(function (secret) {
          keys.appendChild(hint(el('div', 'secret'), secret.file + ' \u00b7 ' + secret.preview))
            .appendChild(marked(short(secret.kind) + ' \u00b7 ' + secret.token, 'bad'));
        });
        web.appendChild(hint(row('Exposed keys', keys), 'The keys are in the vault, never shown here; ' +
          'the report lists them to rotate. Test them only within the engagement\u2019s scope.'));
      }
      if (http && http.js_endpoints && http.js_endpoints.length) {
        var named = fold('js-endpoints:' + key, 'names', false);
        named.appendChild(el('summary', null, 'JS endpoints (' + http.js_endpoints.length + ')'));
        var list = named.appendChild(el('pre', 'reply'));
        list.textContent = http.js_endpoints.join('\n');
        web.appendChild(named);
      }
      if (http && http.scripts && http.scripts.length) {
        var files = fold('js-files:' + key, 'names', false);
        files.appendChild(el('summary', null, 'Script files (' + http.scripts.length + ')'));
        var fileList = files.appendChild(el('pre', 'reply'));
        fileList.textContent = http.scripts.join('\n');
        web.appendChild(files);
      }
      // The stack already names the server and what powers it.
      var stacked = http && http.tech && http.tech.length;
      if (http && http.server && !stacked) { web.appendChild(row('Server', http.server)); }
      if (http && http.powered_by && !stacked) { web.appendChild(row('Powered by', http.powered_by)); }
      if (http && http.title) { web.appendChild(row('Title', http.title)); }
      if (http && http.waf) { web.appendChild(row('WAF / CDN', marked(http.waf, 'info'))); }
      if (http && http.favicon_hash !== null && http.favicon_hash !== undefined) {
        var fav = String(http.favicon_hash) + (http.favicon_framework ? ' (' + http.favicon_framework + ')' : '');
        web.appendChild(row('Favicon hash', fav));
      }
      if (http && http.location) { web.appendChild(row('Redirects to', http.location)); }
      if (http && http.security_headers && !http.header_grade) {
        var secHdrs = Array.isArray(http.security_headers)
          ? http.security_headers
          : Object.keys(http.security_headers).filter(function (k) {
              return own(http.security_headers, k) !== undefined;
            });
        if (secHdrs.length) {
          web.appendChild(row('Security headers', marked(secHdrs.join(', '), 'ok')));
        }
      }
      if (http && http.missing_headers && http.missing_headers.length && !http.header_grade) {
        web.appendChild(row('Missing headers', marked(http.missing_headers.join(', '), 'warn')));
      }
      if (http && http.tls_versions && http.tls_versions.length) {
        var hasLegacy = http.tls_versions.some(function (v) { return v === 'TLS 1.0' || v === 'TLS 1.1'; });
        web.appendChild(row('TLS versions', marked(http.tls_versions.join(', '), hasLegacy ? 'warn' : 'ok')));
      }
      if (http && http.tls_weak_ciphers && http.tls_weak_ciphers.length) {
        web.appendChild(row('Weak ciphers', marked(http.tls_weak_ciphers.join(', '), 'warn')));
      }
      if (http && (http.tls_subject || http.tls_issuer)) {
        var certParts = [http.tls_subject, http.tls_issuer ? 'issuer ' + http.tls_issuer : null].filter(Boolean);
        web.appendChild(row('Certificate', certParts.join(' · ')));
      }
      if (http && (http.tls_not_before || http.tls_not_after)) {
        web.appendChild(row('Valid', [http.tls_not_before || '?', http.tls_not_after || '?'].join(' \u2192 ')));
      }
      sans.forEach(function (name) { web.appendChild(row('Certificate name', name)); });
      if (http && http.robots_disallow && http.robots_disallow.length) {
        web.appendChild(row('robots.txt disallow', http.robots_disallow.join(', ')));
      }
      if (http && http.security_txt) {
        web.appendChild(row('security.txt', http.security_txt));
      }
      if (paths) { web.appendChild(pathTree(port.paths, { left: 300 })); }
    });

    var ai = card('Ask AI');
    var hasCves = (host.advisories || []).length > 0;
    var ask = ai.appendChild(el('div', 'actions'));
    [['local', '[L] Local'], ['cloud', '[C] Cloud triage'], ['research', '[R] Deep research']].forEach(function (tier) {
      var button = ask.appendChild(el('button', null, tier[1]));
      if (tier[0] === 'research' && !hasCves) {
        button.disabled = true;
        button.title = 'No CVEs found for this host yet.';
      }
      button.addEventListener('click', function () {
        pendingAiScroll = true;
        send({ cmd: 'ai', tier: tier[0], address: host.address });
      });
    });
    var budget = state.budget || {};
    if (budget.has_key) {
      ai.appendChild(row('Cloud today', '$' + (budget.spent_usd || 0).toFixed(4) + ' of $' +
        (budget.max_usd || 0).toFixed(2) + ', ' + (budget.calls || 0) + ' of ' + (budget.max_calls || 0) + ' calls'));
    } else if (budget.setup_unreadable) {
      ai.appendChild(hint(el('p', 'note', 'Cloud off: ~/.meow/ai.toml cannot be read.'),
        'Fix the file or run `meow setup`. Until then [C] answers with the local model and [R] is unavailable.'));
    } else {
      ai.appendChild(hint(el('p', 'note', 'No cloud key: run `meow setup`.'),
        '[C] answers with the local model and [R] is unavailable until a key is added. ' +
        'It applies to this session at once.'));
    }

    var note = card('Add a note');
    var box = note.appendChild(el('textarea'));
    box.placeholder = 'What you found by hand: credentials tried, versions seen, pkg:npm/name@1.2.3 ...';
    if (hasOwn.call(noteDrafts, host.address)) {
      box.value = noteDrafts[host.address];
    }
    box.addEventListener('input', function () {
      if (box.value) {
        noteDrafts[host.address] = box.value;
      } else {
        delete noteDrafts[host.address];
      }
    });
    var save = note.appendChild(el('div', 'actions')).appendChild(el('button', null, 'Save note'));
    save.addEventListener('click', function () {
      if (box.value.trim()) {
        send({ cmd: 'note', address: host.address, text: box.value });
        box.value = '';
        delete noteDrafts[host.address];
      }
    });
    return { status: statusCard(host), ports: ports, web: web.childNodes.length > 1 ? web : null,
      ai: ai, note: note };
  }

  // The selected host's cards sit in tabs under its name. The CVEs card
  // and the AI answer move into their tab while that host is selected,
  // and back to their own place on the page otherwise.
  var HOST_TABS = [['overview', 'Overview'], ['ports', 'Ports'], ['web', 'Web & TLS'], ['dns', 'DNS & Mail'],
    ['cves', 'CVEs'], ['notes', 'Notes & AI']];

  // A to F: green, amber or red.
  function gradeKind(grade) {
    return /^[AB]$/.test(grade) ? 'ok' : grade === 'C' ? 'warn' : /^[DF]$/.test(grade) ? 'bad' : 'info';
  }

  // DNS & Mail: the graded checks, the services the domain publishes, and
  // whether made-up names answer (wildcard DNS).
  function dnsCard(info) {
    var box = card('DNS & Mail \u2014 ' + info.domain);
    var badge = el('span', 'grade-inline');
    badge.appendChild(el('span', 'grade small ' + gradeKind(info.grade), info.grade || '?'));
    box.appendChild(hint(row('Grade', badge), 'SPF, DMARC, DKIM, CAA and DNSSEC graded together.'));
    (info.checks || []).forEach(function (check) {
      box.appendChild(hint(row(check.name, marked(check.value, check.status)), check.advice));
    });
    box.appendChild((info.wildcard || []).length
      ? hint(row('Wildcard', marked(info.wildcard.join(', '), 'warn')), 'Made-up names under the domain resolve.')
      : row('Wildcard', marked('none', 'ok')));
    var services = info.services || [];
    if (services.length) {
      box.appendChild(el('h3', null, 'Services (' + services.length + ')'));
    }
    services.forEach(function (service) {
      box.appendChild(hint(row(service.record, service.target), service.meaning));
    });
    var subs = info.subdomains || [];
    if (subs.length) {
      box.appendChild(el('h3', null, 'Certificate names (' + subs.length + ')'));
      subs.forEach(function (sub) {
        var value = sub.status === 'wildcard' ? marked('wildcard only', 'warn')
          : sub.status === 'gone' ? marked('no record', 'info')
          : marked((sub.addresses || []).join(', '), 'ok');
        var line = box.appendChild(row(sub.name, value));
        if (sub.status !== 'resolves') { line.className += ' faded'; }
      });
    }
    return box;
  }
  var hostTab = 'overview';
  try { hostTab = sessionStorage.getItem('meow-map-tab') || 'overview'; } catch (_) {}
  var movable = table();
  ['card-cves', 'card-ai'].forEach(function (id) {
    var node = byId(id);
    var home = document.createComment(' ' + id + ' ');
    node.parentNode.insertBefore(home, node);
    movable[id] = { node: node, home: home };
  });
  // Every moved card back home, before the panels it was in are cleared.
  function parkMovables() {
    Object.keys(movable).forEach(function (id) {
      var entry = movable[id];
      if (entry.home.nextSibling !== entry.node) {
        entry.home.parentNode.insertBefore(entry.node, entry.home.nextSibling);
      }
    });
  }

  // Overview: one line per tab, each a link to it.
  function glanceCard(host, made, cves) {
    var box = card('At a Glance');
    box.className += ' glance';
    function go(key, text, kind) {
      var holder = el('span', 'go');
      var link = holder.appendChild(el('button', 'link', text));
      link.type = 'button';
      link.addEventListener('click', function () { showTab(key, true); });
      if (kind) { holder.appendChild(document.createTextNode(' ')); holder.appendChild(mark(kind)); }
      return holder;
    }
    var ports = host.ports || {};
    var open = Object.keys(ports).map(function (key) { return own(ports, key); }).filter(function (port) {
      return port && port.state === 'open';
    }).sort(function (a, b) { return a.number - b.number; });
    var list = open.slice(0, 10).map(function (port) {
      return port.number + (port.protocol && port.protocol !== 'tcp' ? '/' + port.protocol : '') +
        (port.service ? ' ' + port.service : '');
    }).join(', ') + (open.length > 10 ? ', +' + (open.length - 10) + ' more' : '');
    box.appendChild(row('Open ports', go('ports', open.length ? list : 'none seen yet')));

    box.appendChild(row('CVEs', go('cves', cveWords(cves) || 'none found',
      cves.serious ? 'bad' : cves.total ? 'warn' : 'ok')));
    if (made.web) {
      // One short phrase per kind of problem, with the ports it was seen on.
      var oldTls = [], weak = [], missing = [], edges = [], oldLibs = [], keyCount = 0, worstGrade = '';
      Object.keys(ports).forEach(function (key) {
        var http = (own(ports, key) || {}).http;
        if (!http) { return; }
        var where = key.replace(/\/tcp$/, '');
        if ((http.tls_versions || []).some(function (v) { return v === 'TLS 1.0' || v === 'TLS 1.1'; })) {
          oldTls.push(where);
        }
        if ((http.tls_weak_ciphers || []).length) { weak.push(where); }
        if ((http.missing_headers || []).length) { missing.push(where); }
        if (http.waf && edges.indexOf(http.waf) < 0) { edges.push(http.waf); }
        if ((http.js_secrets || []).length) { keyCount += http.js_secrets.length; }
        if (http.header_grade && (!worstGrade || http.header_grade > worstGrade)) { worstGrade = http.header_grade; }
        (http.tech || []).forEach(function (name) {
          if (/\(older than|end of life/.test(name)) { oldLibs.push(name.split(' (')[0]); }
        });
      });
      var flagged = [];
      if (keyCount) { flagged.push(keyCount + (keyCount === 1 ? ' exposed key' : ' exposed keys') + ' in scripts'); }
      if (worstGrade && worstGrade !== 'A') { flagged.push('headers grade ' + worstGrade); }
      if (oldLibs.length) { flagged.push('outdated ' + oldLibs.join(', ')); }
      if (oldTls.length) { flagged.push('TLS 1.0/1.1 on ' + oldTls.join(', ')); }
      if (weak.length) { flagged.push('weak ciphers on ' + weak.join(', ')); }
      if (missing.length && !worstGrade) { flagged.push('headers missing on ' + missing.join(', ')); }
      var said = flagged.concat(edges);
      var webLink = go('web', said.slice(0, 3).join(' \u00b7 ') + (said.length > 3 ? ' +' + (said.length - 3) : '') ||
        'nothing flagged', keyCount ? 'bad' : flagged.length ? 'warn' : 'ok');
      box.appendChild(hint(row('Web & TLS', webLink), said.join('\n')));
    }
    if (host.dns_security) {
      var dnsInfo = host.dns_security;
      var weak = (dnsInfo.checks || []).filter(function (c) { return c.status === 'bad' || c.status === 'warn'; })
        .map(function (c) { return c.name; });
      box.appendChild(hint(row('DNS & Mail', go('dns', 'grade ' + (dnsInfo.grade || '?') +
        (weak.length ? ' \u00b7 ' + weak.length + ' to fix' : ''), gradeKind(dnsInfo.grade))), weak.join(', ')));
    }
    return box;
  }

  function showTab(key, focus, quiet) {
    if (!byId('tab-' + key)) { key = 'overview'; }
    Array.prototype.forEach.call(byId('host-tabs').querySelectorAll('[role="tab"]'), function (tab) {
      var on = tab.getAttribute('data-tab') === key;
      tab.setAttribute('aria-selected', on ? 'true' : 'false');
      tab.tabIndex = on ? 0 : -1;
      byId(tab.getAttribute('aria-controls')).hidden = !on;
      if (on && focus) { tab.focus(); }
    });
    if (!quiet) {
      hostTab = key;
      try { sessionStorage.setItem('meow-map-tab', key); } catch (_) {}
    }
  }

  function exposedKeys(host) {
    var ports = host.ports || {};
    return Object.keys(ports).reduce(function (sum, key) {
      var http = (own(ports, key) || {}).http;
      return sum + ((http && http.js_secrets) || []).length;
    }, 0);
  }

  function buildHostTabs(host, data, refocus) {
    var made = hostCards(host, data);
    var cves = cveCounts(host.address);
    var reply = state.ai || {};
    var aiHere = reply.address === host.address && !!(reply.running || reply.text || reply.error);
    var openPorts = Object.keys(host.ports || {}).filter(function (key) {
      var port = own(host.ports, key);
      return port && port.state === 'open';
    }).length;
    var content = {
      overview: [made.status, glanceCard(host, made, cves)],
      ports: [made.ports],
      web: made.web ? [made.web] : null,
      dns: host.dns_security ? [dnsCard(host.dns_security)] : null,
      cves: [movable['card-cves'].node],
      notes: aiHere ? [made.ai, made.note, movable['card-ai'].node] : [made.ai, made.note]
    };
    var badge = {
      ports: [String(openPorts), ''],
      web: exposedKeys(host) ? [exposedKeys(host) + (exposedKeys(host) === 1 ? ' key' : ' keys'), 'bad'] : null,
      dns: host.dns_security ? [host.dns_security.grade || '?',
        { ok: '', warn: 'warn', bad: 'bad', info: '' }[gradeKind(host.dns_security.grade)]] : null,
      cves: cves.total ? [String(cves.total), cves.serious ? 'bad' : 'warn'] : null,
      notes: aiHere ? [reply.running ? 'AI\u2026' : 'AI', reply.error ? 'bad' : 'info'] : null
    };
    var names = associatedNamesFor(host, data);
    byId('host-title').textContent = (names.hosts[0] && names.hosts[0] !== host.address
      ? names.hosts[0] + ' \u00b7 ' : '') + host.address;
    var tabs = clear(byId('host-tabs')), panels = byId('host-panels');
    HOST_TABS.forEach(function (entry) {
      var key = entry[0], items = content[key];
      if (!items) { return; }
      var tab = tabs.appendChild(el('button'));
      tab.type = 'button';
      tab.id = 'tab-' + key;
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-controls', 'panel-' + key);
      tab.setAttribute('data-tab', key);
      tab.appendChild(el('span', null, entry[1]));
      var count = own(badge, key);
      if (count) { tab.appendChild(el('span', 'count' + (count[1] ? ' ' + count[1] : ''), count[0])); }
      tab.addEventListener('click', function () { showTab(key, false); });
      var panel = panels.appendChild(el('div', 'panel'));
      panel.id = 'panel-' + key;
      panel.setAttribute('role', 'tabpanel');
      panel.setAttribute('aria-labelledby', tab.id);
      items.forEach(function (item) { panel.appendChild(item); });
    });
    byId('card-host').hidden = false;
    // The tab the reader chose stays open across refreshes and hosts; one
    // this host does not have shows Overview without forgetting the choice.
    showTab(hostTab, refocus, true);
  }

  // Arrow keys, Home and End move between tabs; 1 to 6 open one directly.
  byId('host-tabs').addEventListener('keydown', function (event) {
    var tabs = Array.prototype.slice.call(this.querySelectorAll('[role="tab"]'));
    var at = tabs.indexOf(document.activeElement);
    if (at < 0) { return; }
    var to = { ArrowRight: (at + 1) % tabs.length, ArrowLeft: (at - 1 + tabs.length) % tabs.length,
      Home: 0, End: tabs.length - 1 }[event.key];
    if (to === undefined) { return; }
    event.preventDefault();
    showTab(tabs[to].getAttribute('data-tab'), true);
  });
  document.addEventListener('keydown', function (event) {
    if (event.altKey || event.ctrlKey || event.metaKey || byId('card-host').hidden) { return; }
    var target = event.target;
    if (target && (/^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName) || target.isContentEditable)) { return; }
    var number = /^[1-9]$/.test(event.key) ? Number(event.key) : 0;
    var tabs = byId('host-tabs').querySelectorAll('[role="tab"]');
    if (!number || number > tabs.length) { return; }
    showTab(tabs[number - 1].getAttribute('data-tab'), false);
    byId('card-host').scrollIntoView({ block: 'nearest' });
  });

  function downloadReport(urlPath, fallbackName) {
    var link = document.createElement('a');
    link.href = withToken(urlPath);
    link.download = fallbackName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  function formatHopLine(hop) {
    var line;
    if (hop && hop.formatted) {
      line = hop.formatted;
    } else {
      var rtt = (hop && hop.rtt_ms !== null && hop.rtt_ms !== undefined) ? (hop.rtt_ms.toFixed(1) + ' ms') : '—';
      var lbl = (hop && hop.label) ? (' (' + hop.label + ') ') : ' ';
      line = 'Hop ' + (hop ? hop.hop : '?') + ': ' + (hop ? hop.address : '?') + lbl + rtt;
    }
    var where = hop ? hopPlace(hop) : '';
    return line + (where ? '  \u2014 ' + where : '');
  }

  function appendTracerouteSection(container, traceHops, openByDefault) {
    if (!traceHops || !traceHops.length) { return; }
    var section = container.appendChild(fold('trace:hops', 'names', openByDefault));
    section.appendChild(el('summary', null, 'Traceroute hops (' + traceHops.length + ')'));
    var pre = section.appendChild(el('pre', 'reply'));
    pre.textContent = traceHops.map(formatHopLine).join('\n');
    var toggleWrap = section.appendChild(el('div', 'actions'));
    var btn = toggleWrap.appendChild(el('button', null,
      traceExpanded ? 'Collapse traceroute on map' : 'Expand traceroute on map'));
    btn.addEventListener('click', function () {
      traceExpanded = !traceExpanded;
      drawn = '';
      renderGraph();
      renderDetail();
    });
  }

  // The selected node: its facts in the card beside the map, and for a host
  // one card per subject at the head of the cards below.
  var lastDetailId = null;
  function renderDetail() {
    var detail = byId('detail');
    var panels = byId('host-panels');
    // Keep cursor/focus and per-host note draft across live refreshes.
    var sameHost = selected && selected === lastDetailId;
    var draft = sameHost ? panels.querySelector('textarea') : null;
    var draftText = draft ? draft.value : '';
    var hadFocus = draft && document.activeElement === draft;
    var selStart = hadFocus ? draft.selectionStart : null;
    var selEnd = hadFocus ? draft.selectionEnd : null;
    var tabFocused = sameHost && document.activeElement &&
      document.activeElement.getAttribute && document.activeElement.getAttribute('role') === 'tab';
    lastDetailId = selected;
    clear(detail);
    parkMovables();
    clear(panels);
    clear(byId('host-tabs'));
    byId('card-host').hidden = true;
    var data = selectedNodeData();
    if (!data) {
      byId('detail-title').textContent = 'Selected';
      detail.appendChild(el('p', 'note', 'Click a node or host for details.'));
      var wsExport = detail.appendChild(el('div', 'actions'));
      var expAll = wsExport.appendChild(el('button', null, 'Export report (.md)'));
      expAll.addEventListener('click', function () {
        downloadReport('/api/report', 'engagement-report.md');
      });
      var printAll = wsExport.appendChild(el('button', null, 'Print / PDF'));
      printAll.addEventListener('click', function () { window.print(); });
      return;
    }
    var host = data.address && state.graph ? own(state.graph.hosts, data.address) : null;
    if (host) {
      if (sameHost && draftText) {
        noteDrafts[host.address] = draftText;
      }
      byId('detail-title').textContent = 'Host Info';
      // address -> type -> OS -> version, one row each.
      var parts = String(data.headline || '').split(' -> ');
      var guessed = / \(OS read off a service banner\)$/;
      var version = (parts[3] || '').replace(guessed, '');
      // Open ports have a card of their own; why the node is drawn as it is
      // and where the system came from are tooltips here.
      detail.appendChild(row('Address', parts[0] || host.address));
      var typeRow = detail.appendChild(row('Type', parts[1] || 'not known'));
      if (data.why) { typeRow.title = 'Drawn this way because ' + data.why + '.'; }
      var banner = guessed.test(parts[3] || '');
      var system = detail.appendChild(row('System', banner ? marked(parts[2] || 'not known', 'info') : (parts[2] || 'not known')));
      if (banner) { system.title = 'Read off a service banner, not reported by an OS scan.'; }
      detail.appendChild(row('Version', version || 'not known'));
      var assoc = associatedNamesFor(host, data);
      if (assoc.domains.length || assoc.hosts.length) {
        detail.appendChild(el('h3', null, 'Associated Hosts'));
        if (assoc.domains.length) {
          detail.appendChild(row('Domains', assoc.domains.join('\n')));
        }
        if (assoc.hosts.length) {
          detail.appendChild(row('Hosts', assoc.hosts.join('\n')));
        }
      }
      if (data.city) { detail.appendChild(row('Location', data.city)); }
      if (host.mac) { detail.appendChild(row('Hardware address', host.mac)); }
      if (host.asn) {
        var asnText = host.asn + (host.country ? ' (' + host.country + ')' : '');
        detail.appendChild(row('ASN / Org', asnText));
      }
      if (host.bgp_prefix) {
        detail.appendChild(row('BGP prefix', host.bgp_prefix));
      }
      if (host.ipv6_dns) {
        var hasV6 = host.ipv6_dns.indexOf('no AAAA') === -1;
        detail.appendChild(row('IPv6 DNS', marked(host.ipv6_dns, hasV6 ? 'ok' : 'info')));
      }
      if (host.waf_cdn) {
        detail.appendChild(row('WAF / CDN', marked(host.waf_cdn, 'info')));
      }
      var traceHops = data.trace_hops || [];
      var hops = host.hops || data.hops || [];
      var hopTotal = data.hop_count || traceHops.length || hops.length;
      if (hopTotal) {
        var rttSuffix = (data.rtt_ms !== undefined && data.rtt_ms !== null) ? (' · ' + data.rtt_ms.toFixed(1) + ' ms') : '';
        var routeRow = detail.appendChild(row('Route', marked(hopTotal + (hopTotal === 1 ? ' hop' : ' hops') + rttSuffix + ' -> ' + host.address, 'ok')));
        if (hops.length) { routeRow.title = hops.concat([host.address]).join(' -> '); }
        appendTracerouteSection(detail, traceHops, false);
      } else {
        detail.appendChild(row('Route', data.reachable ? marked('known', 'ok')
          : marked(data.by_name ? 'address not known' : 'none known', 'warn')));
      }
      var exportActions = detail.appendChild(el('div', 'actions'));
      var exportMd = exportActions.appendChild(el('button', null, 'Export report (.md)'));
      exportMd.addEventListener('click', function () {
        downloadReport('/api/report/' + encodeURIComponent(host.address), 'report-' + host.address + '.md');
      });
      var exportPdf = exportActions.appendChild(el('button', null, 'Print / PDF'));
      exportPdf.addEventListener('click', function () { window.print(); });
      buildHostTabs(host, data, tabFocused);
      var box = panels.querySelector('textarea');
      if (box && hadFocus) {
        box.focus();
        if (typeof selStart === 'number' && typeof selEnd === 'number') {
          try { box.setSelectionRange(selStart, selEnd); } catch (_) {}
        }
      }
      return;
    }
    byId('detail-title').textContent = String(data.caption || data.label || data.id || 'Selected').split('\n')[0];
    if (data.kind === 'interface') {
      var name = String(data.id || '').slice(3);
      if (data.network) { detail.appendChild(row('Network', data.network)); }
      ((state.graph && state.graph.local && state.graph.local.interfaces) || []).forEach(function (iface) {
        if (iface.name !== name) { return; }
        detail.appendChild(row('Interface', name + ' (' + iface.kind + (iface.up ? ', up' : ', down') + ')'));
        (iface.addresses || []).forEach(function (address) { detail.appendChild(row('This machine', address)); });
      });
      if (data.hidden_neighbours) {
        detail.appendChild(el('p', 'note', '+' + data.hidden_neighbours + ' more not drawn'));
      }
    } else if (data.kind === 'neighbour') {
      detail.appendChild(row('Address', data.label || ''));
      detail.appendChild(row('Hardware address', data.mac || ''));
      detail.appendChild(row('Seen on', data.interface || ''));

    } else if (data.kind === 'egress') {
      byId('detail-title').textContent = data.vpn ? 'VPN Exit' : 'Public WAN Egress';
      if (data.vpn) {
        detail.appendChild(row('Tunnel', marked(data.vpn, 'ok')));
        detail.appendChild(row('OPSEC status', marked('VPN active', 'ok')));
      } else {
        detail.appendChild(row('Public IP', data.public_address || 'resolving...'));
        detail.appendChild(row('ISP / Network', data.isp || 'not known'));
        detail.appendChild(row('OPSEC status', marked('no VPN (direct WAN egress)', 'warn')));
      }

    } else if (data.kind === 'internet') {
      byId('detail-title').textContent = 'Internet Transit';
      var netHops = data.trace_hops || [];
      if (data.hop_count) {
        detail.appendChild(row('Transit hops', String(data.hop_count)));
      }
      if (data.rtt_ms !== undefined && data.rtt_ms !== null) {
        detail.appendChild(row('Round-trip latency', data.rtt_ms.toFixed(1) + ' ms'));
      }
      if (netHops.length) {
        appendTracerouteSection(detail, netHops, true);
      } else {
        detail.appendChild(el('p', 'note', 'Run `recon <target>` for hops.'));
      }
    } else if (data.kind === 'hop' && data.hop) {
      appendHopDetail(detail, data.hop);
    } else if (data.kind === 'waf') {
      byId('detail-title').textContent = 'WAF / CDN Edge';
      detail.appendChild(row('Provider', marked(data.waf || 'WAF / CDN', 'info')));
      if (data.target) { detail.appendChild(row('Protected origin', data.target)); }

    } else if (data.kind === 'asn') {
      byId('detail-title').textContent = 'Cloud / ASN Group';
      detail.appendChild(row('ASN / Provider', data.asn || data.label || ''));
      if (data.bgp_prefix) { detail.appendChild(row('BGP prefix', data.bgp_prefix)); }

    } else {
      detail.appendChild(row('Name', data.label || data.id || ''));
    }
    detail.appendChild(drawnAs(data));
  }

  // Where a hop's address is, in words: "Fremont, California, United States".
  function hopPlace(hop) {
    var loc = hop.location;
    if (!loc) { return ''; }
    return [loc.city, loc.region, loc.country].filter(Boolean).join(', ');
  }

  // Everything known about one traceroute hop: where it is, whose network
  // it is, what kind of address, the latency it adds; for the last hop, what
  // recon found about the target.
  function appendHopDetail(detail, hop) {
    byId('detail-title').textContent = hop.is_target
      ? 'Traceroute Hop ' + hop.hop + ' (target)'
      : 'Traceroute Hop ' + hop.hop;
    detail.appendChild(row('Hop', String(hop.hop)));
    detail.appendChild(row('Address', hop.address || '* * *'));
    if (hop.scope) { detail.appendChild(row('Address type', hop.scope)); }
    if (hop.label && hop.label !== hop.network && hop.label !== hop.reverse_dns) {
      detail.appendChild(row('Node / Role', hop.label));
    }
    if (hop.reverse_dns) { detail.appendChild(row('Reverse DNS', hop.reverse_dns)); }
    var place = hopPlace(hop);
    if (place) {
      detail.appendChild(row('Location', place));
      var loc = hop.location;
      if (typeof loc.latitude === 'number' && typeof loc.longitude === 'number') {
        detail.appendChild(row('Coordinates', loc.latitude.toFixed(3) + ', ' + loc.longitude.toFixed(3) + ' (approximate)'));
      }
    } else if (hop.scope && /^public/.test(hop.scope)) {
      detail.appendChild(row('Location', 'not in the location database'));
    } else if (hop.scope && hop.address && hop.address.indexOf('*') < 0) {
      detail.appendChild(row('Location', 'none: not a public address'));
    }
    if (hop.network) { detail.appendChild(row('Network / ASN', hop.network)); }
    var rtt = (hop.rtt_ms !== null && hop.rtt_ms !== undefined) ? hop.rtt_ms.toFixed(1) + ' ms' : '—';
    detail.appendChild(row('RTT latency', rtt));
    if (typeof hop.rtt_delta_ms === 'number') {
      var delta = hop.rtt_delta_ms;
      var deltaText = (delta >= 0 ? '+' : '') + delta.toFixed(1) + ' ms vs previous hop';
      detail.appendChild(row('Added latency', delta >= 40 ? marked(deltaText + ' (long link)', 'info') : deltaText));
    }
    var target = hop.target;
    if (target) {
      detail.appendChild(el('h3', null, 'Target'));
      if (target.hostnames && target.hostnames.length) { detail.appendChild(row('Names', target.hostnames.join(', '))); }
      if (target.asn) { detail.appendChild(row('ASN / Provider', target.asn)); }
      if (target.bgp_prefix) { detail.appendChild(row('BGP prefix', target.bgp_prefix)); }
      if (target.country) { detail.appendChild(row('Country (registry)', target.country)); }
      if (target.waf_cdn) { detail.appendChild(row('WAF / CDN', marked(target.waf_cdn, 'info'))); }
      if (target.os) { detail.appendChild(row('Operating system', target.os)); }
      detail.appendChild(row('Open ports', String(target.open_ports || 0)));
      var pick = detail.appendChild(el('div', 'actions'));
      var go = pick.appendChild(el('button', null, 'Show host'));
      go.addEventListener('click', function () { select('host:' + hop.address); });
    }
    if (hop.location) {
      detail.title = 'Location from the offline DB-IP Lite database: city-level and approximate; ' +
        'routers are often registered where their network is, not where they stand.';
    }
  }

  // Finds where a code span closes: at the next run of as many backticks.
  // The longest run still ahead is known, so a span that never closes is
  // not looked for to the end of the text again for each run before it.
  function codeSpanCloser(text) {
    var starts = null;
    var longest = null;
    var next = 0;
    return function (ticks, from) {
      if (!starts) {
        starts = [];
        longest = [];
        var at = text.indexOf('`');
        while (at >= 0) {
          var stop = at;
          while (stop < text.length && text.charAt(stop) === '`') { stop += 1; }
          starts.push(at);
          longest.push(stop - at);
          at = text.indexOf('`', stop);
        }
        for (var k = longest.length - 2; k >= 0; k -= 1) {
          if (longest[k + 1] > longest[k]) { longest[k] = longest[k + 1]; }
        }
      }
      while (next < starts.length && starts[next] < from) { next += 1; }
      if (next >= starts.length || longest[next] < ticks.length) { return -1; }
      return text.indexOf(ticks, from);
    };
  }

  function appendInlineCodeOnly(parent, text) {
    var buf = '';
    var i = 0;
    var closeSpan = codeSpanCloser(text);
    function flush() {
      if (buf) {
        parent.appendChild(document.createTextNode(buf));
        buf = '';
      }
    }
    while (i < text.length) {
      if (text.charAt(i) === '`') {
        var tickEnd = i;
        while (tickEnd < text.length && text.charAt(tickEnd) === '`') { tickEnd += 1; }
        var ticks = text.slice(i, tickEnd);
        var closeIdx = closeSpan(ticks, tickEnd);
        if (closeIdx > tickEnd) {
          flush();
          parent.appendChild(el('code', null, text.slice(tickEnd, closeIdx)));
          i = closeIdx + ticks.length;
          continue;
        }
        buf += ticks;
        i = tickEnd;
        continue;
      }
      buf += text.charAt(i);
      i += 1;
    }
    flush();
  }

  // Inline Markdown formatting built strictly out of text nodes and safe
  // inline elements (code, strong, em). No links or images are created from
  // AI or target text.
  function appendInlineFormatted(parent, text) {
    var buf = '';
    var i = 0;
    // Where the next `](` and the `)` after it are, looked for once and
    // used for every `[` before them (-2: not looked for, -1: none). Looked
    // for again at each `[`, they made `[]` repeated take seconds.
    var linkMid = -2;
    var linkClose = -2;
    var closeSpan = codeSpanCloser(text);
    function flush() {
      if (buf) {
        parent.appendChild(document.createTextNode(buf));
        buf = '';
      }
    }
    while (i < text.length) {
      var ch = text.charAt(i);
      if (ch === '`') {
        var tickEnd = i;
        while (tickEnd < text.length && text.charAt(tickEnd) === '`') { tickEnd += 1; }
        var ticks = text.slice(i, tickEnd);
        var closeIdx = closeSpan(ticks, tickEnd);
        if (closeIdx > tickEnd) {
          flush();
          parent.appendChild(el('code', null, text.slice(tickEnd, closeIdx)));
          i = closeIdx + ticks.length;
          continue;
        }
        buf += ticks;
        i = tickEnd;
        continue;
      }
      if (ch === '[') {
        if (linkMid !== -1 && linkMid <= i) { linkMid = text.indexOf('](', i + 1); }
        var mid = linkMid;
        if (mid > i + 1) {
          var label = text.slice(i + 1, mid);
          if (label.indexOf('[') < 0 && label.indexOf('\n') < 0) {
            if (linkClose !== -1 && linkClose < mid + 2) { linkClose = text.indexOf(')', mid + 2); }
            var closeParen = linkClose;
            if (closeParen > mid + 2) {
              var rawUrl = text.slice(mid + 2, closeParen).trim();
              if (/^https?:\/\/\S+$/.test(rawUrl)) {
                flush();
                if (label.trim() && label.trim() !== rawUrl) {
                  parent.appendChild(document.createTextNode(label + ' ('));
                  parent.appendChild(el('code', null, rawUrl));
                  parent.appendChild(document.createTextNode(')'));
                } else {
                  parent.appendChild(el('code', null, rawUrl));
                }
                i = closeParen + 1;
                continue;
              }
            }
          }
        }
      }
      if (ch === '*' && text.charAt(i + 1) === '*') {
        if (text.charAt(i + 2) !== '*') {
          var boldEnd = text.indexOf('**', i + 2);
          if (boldEnd > i + 2) {
            flush();
            var strong = parent.appendChild(el('strong'));
            appendInlineCodeOnly(strong, text.slice(i + 2, boldEnd));
            i = boldEnd + 2;
            continue;
          }
        }
        var starEnd = i;
        while (starEnd < text.length && text.charAt(starEnd) === '*') { starEnd += 1; }
        buf += text.slice(i, starEnd);
        i = starEnd;
        continue;
      }
      if (ch === '*') {
        var prev = i === 0 ? ' ' : text.charAt(i - 1);
        var afterOpen = text.charAt(i + 1);
        if (afterOpen && afterOpen !== ' ' && /[\s(\[{"']/.test(prev)) {
          var emEnd = text.indexOf('*', i + 1);
          if (emEnd > i + 1 && text.charAt(emEnd - 1) !== ' ' && text.charAt(emEnd + 1) !== '*') {
            var next = emEnd + 1 >= text.length ? ' ' : text.charAt(emEnd + 1);
            if (/[\s)\]}.,;:!?"']/.test(next)) {
              flush();
              var em = parent.appendChild(el('em'));
              appendInlineCodeOnly(em, text.slice(i + 1, emEnd));
              i = emEnd + 1;
              continue;
            }
          }
        }
      }
      buf += ch;
      i += 1;
    }
    flush();
  }

  function parseCodeFence(line) {
    var m = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
    if (!m) { return null; }
    if (m[1].charAt(0) === '`' && m[2].indexOf('`') >= 0) { return null; }
    var lang = m[2].trim().split(/\s+/)[0] || '';
    return { fenceChar: m[1].charAt(0), fenceLen: m[1].length, lang: lang };
  }

  function isHrLine(line) {
    return /^ {0,3}(?:(?:-\s*){3,}|(?:\*\s*){3,}|(?:_\s*){3,})$/.test(line);
  }

  function isHeadingLine(line) {
    return /^ {0,3}#{1,6}\s+\S/.test(line);
  }

  function isTableRow(line) {
    return line.indexOf('|') >= 0;
  }

  function splitTableCells(line) {
    var trimmed = line.trim();
    if (trimmed.charAt(0) === '|') { trimmed = trimmed.slice(1); }
    if (trimmed.charAt(trimmed.length - 1) === '|') { trimmed = trimmed.slice(0, -1); }
    return trimmed.split('|').map(function (c) { return c.trim(); });
  }

  function isTableSeparator(line) {
    if (!isTableRow(line)) { return false; }
    var cells = splitTableCells(line);
    if (!cells.length) { return false; }
    return cells.every(function (c) { return /^:?-{3,}:?$/.test(c); });
  }

  // A table row has at most this many cells: the rest of it goes in the
  // last one. Short rows get empty cells up to the header's count, only so
  // many per reply: a wide header over many '|' rows asked for millions.
  var MAX_TABLE_COLUMNS = 32;
  var MAX_TABLE_PADDING = 2000;

  function tableCells(line) {
    var cells = splitTableCells(line);
    if (cells.length <= MAX_TABLE_COLUMNS) { return cells; }
    var kept = cells.slice(0, MAX_TABLE_COLUMNS - 1);
    kept.push(cells.slice(MAX_TABLE_COLUMNS - 1).join(' | '));
    return kept;
  }

  function matchListItem(line) {
    if (isHrLine(line)) { return null; }
    var u = /^(\s*)[-*+]\s+(.*)$/.exec(line);
    if (u) { return { type: 'ul', indent: u[1].length, num: 1, text: u[2] }; }
    var o = /^(\s*)(\d+)[.)]\s+(.*)$/.exec(line);
    if (o) { return { type: 'ol', indent: o[1].length, num: parseInt(o[2], 10) || 1, text: o[3] }; }
    return null;
  }

  function renderAiMarkdown(container, rawText) {
    var lines = String(rawText || '').replace(/\r\n?/g, '\n').split('\n');
    var i = 0;
    var padding = MAX_TABLE_PADDING;
    while (i < lines.length) {
      var line = lines[i];
      if (!/\S/.test(line)) {
        i += 1;
        continue;
      }
      var fence = parseCodeFence(line);
      if (fence) {
        i += 1;
        var closeRe = new RegExp('^ {0,3}' + fence.fenceChar + '{' + fence.fenceLen + ',}\\s*$');
        var codeLines = [];
        while (i < lines.length && !closeRe.test(lines[i])) {
          codeLines.push(lines[i]);
          i += 1;
        }
        if (i < lines.length) { i += 1; }
        var block = container.appendChild(el('div', 'code-block'));
        if (fence.lang) {
          block.appendChild(el('div', 'code-lang', fence.lang));
        }
        var pre = block.appendChild(el('pre'));
        pre.appendChild(el('code', null, codeLines.join('\n')));
        continue;
      }
      var headMatch = /^ {0,3}(#{1,6})\s+/.exec(line);
      if (headMatch) {
        // Closing #s and spaces are cut here, not by the expression: one
        // that looks for them at the end of the line goes back over all its
        // spaces again for each one, for many seconds on a long line.
        var heading = line.slice(headMatch[0].length);
        var headEnd = heading.length;
        while (headEnd > 0 && heading.charAt(headEnd - 1) === '#') { headEnd -= 1; }
        var hNode = container.appendChild(el(headMatch[1].length <= 2 ? 'h3' : 'h4'));
        appendInlineFormatted(hNode, heading.slice(0, headEnd).trimEnd());
        i += 1;
        continue;
      }
      if (isHrLine(line)) {
        container.appendChild(el('hr'));
        i += 1;
        continue;
      }
      if (isTableRow(line) && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
        var headers = tableCells(line);
        var tbl = container.appendChild(el('table'));
        var thead = tbl.appendChild(el('thead'));
        var headTr = thead.appendChild(el('tr'));
        headers.forEach(function (cell) {
          var th = headTr.appendChild(el('th'));
          appendInlineFormatted(th, cell);
        });
        i += 2;
        var tbody = tbl.appendChild(el('tbody'));
        while (i < lines.length && /\S/.test(lines[i]) && isTableRow(lines[i])) {
          var rowCells = tableCells(lines[i]);
          var width = rowCells.length;
          if (width < headers.length && headers.length - width <= padding) {
            padding -= headers.length - width;
            width = headers.length;
          }
          var tr = tbody.appendChild(el('tr'));
          for (var c = 0; c < width; c += 1) {
            var td = tr.appendChild(el('td'));
            appendInlineFormatted(td, rowCells[c] || '');
          }
          i += 1;
        }
        continue;
      }
      if (/^ {0,3}>/.test(line)) {
        var bq = container.appendChild(el('blockquote'));
        var quotePara = [];
        while (i < lines.length && /^ {0,3}>/.test(lines[i])) {
          var qText = lines[i].replace(/^ {0,3}>\s?/, '');
          if (!/\S/.test(qText)) {
            if (quotePara.length) {
              var qp = bq.appendChild(el('p'));
              appendInlineFormatted(qp, quotePara.join(' '));
              quotePara = [];
            }
          } else {
            quotePara.push(qText.trim());
          }
          i += 1;
        }
        if (quotePara.length) {
          var lastQp = bq.appendChild(el('p'));
          appendInlineFormatted(lastQp, quotePara.join(' '));
        }
        continue;
      }
      var firstItem = matchListItem(line);
      if (firstItem) {
        var listEl = container.appendChild(el(firstItem.type));
        if (firstItem.type === 'ol' && firstItem.num > 1) {
          listEl.start = firstItem.num;
        }
        var baseIndent = firstItem.indent;
        var lastLi = null;
        var subList = null;
        var subType = null;
        while (i < lines.length) {
          if (!/\S/.test(lines[i])) {
            var nextIdx = i + 1;
            while (nextIdx < lines.length && !/\S/.test(lines[nextIdx])) { nextIdx += 1; }
            if (nextIdx >= lines.length) { i = nextIdx; break; }
            var peekItem = matchListItem(lines[nextIdx]);
            if (peekItem && (peekItem.type === firstItem.type || peekItem.indent >= baseIndent + 2)) {
              i = nextIdx;
            } else {
              break;
            }
          }
          if (parseCodeFence(lines[i]) || isHeadingLine(lines[i]) || isHrLine(lines[i]) || /^ {0,3}>/.test(lines[i])) {
            break;
          }
          var item = matchListItem(lines[i]);
          if (item) {
            if (item.indent >= baseIndent + 2 && lastLi) {
              if (!subList || subType !== item.type) {
                subList = lastLi.appendChild(el(item.type));
                subType = item.type;
              }
              var subLi = subList.appendChild(el('li'));
              appendInlineFormatted(subLi, item.text);
              i += 1;
              continue;
            }
            if (item.type === firstItem.type) {
              lastLi = listEl.appendChild(el('li'));
              subList = null;
              subType = null;
              appendInlineFormatted(lastLi, item.text);
              i += 1;
              continue;
            }
            break;
          }
          if (/^\s{2,}\S/.test(lines[i]) && lastLi) {
            lastLi.appendChild(document.createTextNode(' '));
            appendInlineFormatted(lastLi, lines[i].trim());
            i += 1;
            continue;
          }
          break;
        }
        continue;
      }
      var paraLines = [];
      while (i < lines.length && /\S/.test(lines[i])) {
        if (paraLines.length && (
          parseCodeFence(lines[i]) ||
          isHeadingLine(lines[i]) ||
          isHrLine(lines[i]) ||
          /^ {0,3}>/.test(lines[i]) ||
          matchListItem(lines[i]) ||
          (isTableRow(lines[i]) && i + 1 < lines.length && isTableSeparator(lines[i + 1]))
        )) {
          break;
        }
        paraLines.push(lines[i].trim());
        i += 1;
      }
      if (paraLines.length) {
        var p = container.appendChild(el('p'));
        appendInlineFormatted(p, paraLines.join(' '));
      }
    }
  }

  var TIER_TITLES = {
    local: '[L] Local Triage',
    cloud: '[C] Cloud Triage',
    research: '[R] Grounded Research'
  };

  // A triage answer has a red-team part and a blue-team part. Each goes in
  // its own panel, side by side; anything before them stays above. An answer
  // without them (research, an older reply) is shown as it is.
  var TEAM_HEADINGS = [
    { re: /^##\s+Red Team\b.*$/m, cls: 'team-red', title: 'Red Team \u2014 Authorized Pen Test' },
    { re: /^##\s+Blue Team\b.*$/m, cls: 'team-blue', title: 'Blue Team \u2014 SOC Defense' }
  ];
  // Formatting is for a reply of some pages. Past that, the rest is shown
  // as it is: no reply keeps the page busy, however it is written.
  var MAX_MARKDOWN = 50000;

  function renderTriage(container, text) {
    if (text.length > MAX_MARKDOWN) {
      var cut = MAX_MARKDOWN;
      var unit = text.charCodeAt(cut - 1);
      if (unit >= 0xd800 && unit <= 0xdbff) { cut -= 1; }
      renderTriage(container, text.slice(0, cut));
      container.appendChild(el('pre', 'reply', text.slice(cut)));
      return;
    }
    var found = TEAM_HEADINGS.map(function (team) {
      var match = team.re.exec(text);
      return match ? { team: team, at: match.index, after: match.index + match[0].length } : null;
    }).filter(Boolean).sort(function (a, b) { return a.at - b.at; });
    if (!found.length) {
      renderAiMarkdown(container, text);
      return;
    }
    var before = text.slice(0, found[0].at);
    if (/\S/.test(before)) { renderAiMarkdown(container.appendChild(el('div')), before); }
    var columns = container.appendChild(el('div', 'teams'));
    found.forEach(function (part, index) {
      var end = index + 1 < found.length ? found[index + 1].at : text.length;
      var panel = columns.appendChild(el('section', 'team ' + part.team.cls));
      panel.appendChild(el('h3', 'team-title', part.team.title));
      renderAiMarkdown(panel.appendChild(el('div', 'team-body')), text.slice(part.after, end));
    });
  }

  function renderAiPanel() {
    if (!state) { return; }
    var panel = byId('card-ai');
    if (!panel) { return; }
    var reply = state.ai || {};
    if (!reply.running && !reply.text && !reply.error) {
      panel.hidden = true;
      lastAiKey = '';
      return;
    }
    panel.hidden = false;
    var onSameHost = !!(reply.address && selectedAddress() === reply.address);
    var aiKey = JSON.stringify([
      !!reply.running,
      reply.tier || '',
      reply.address || '',
      reply.summary || '',
      reply.error || '',
      onSameHost,
      reply.text || ''
    ]);
    if (aiKey !== lastAiKey) {
      lastAiKey = aiKey;
      var tierLabel = own(TIER_TITLES, reply.tier) || 'AI Triage';
      byId('ai-title').textContent = tierLabel + (reply.address ? ' \u2014 ' + reply.address : '');

      var badges = clear(byId('ai-badges'));
      if (reply.running) {
        badges.appendChild(el('span', 'badge warn', 'streaming\u2026'));
      } else if (reply.error) {
        badges.appendChild(el('span', 'badge bad', 'error'));
      } else {
        badges.appendChild(el('span', 'badge ok', 'complete'));
      }

      if (reply.address && !onSameHost) {
        var hostBtn = badges.appendChild(el('button', null, 'Select ' + reply.address));
        hostBtn.addEventListener('click', function () {
          select('host:' + reply.address);
        });
      }

      if (reply.text) {
        var rawCopy = String(reply.text);
        var copyBtn = badges.appendChild(el('button', null, 'Copy Markdown'));
        copyBtn.addEventListener('click', function () {
          if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            navigator.clipboard.writeText(rawCopy).then(function () {
              copyBtn.textContent = 'Copied';
              setTimeout(function () { copyBtn.textContent = 'Copy Markdown'; }, 1800);
            }, function () {
              flash('Clipboard copy was blocked by the browser.');
            });
          } else {
            flash('Clipboard API is unavailable in this browser.');
          }
        });
      }

      var meta = byId('ai-meta');
      if (reply.summary) {
        meta.hidden = false;
        meta.textContent = reply.summary;
      } else if (reply.running) {
        meta.hidden = false;
        meta.textContent = 'Streaming response for ' + (reply.address || 'selected host') + '\u2026';
      } else {
        meta.hidden = true;
        meta.textContent = '';
      }

      var body = clear(byId('ai-body'));
      if (reply.text) {
        renderTriage(body, String(reply.text));
      } else if (reply.running) {
        body.appendChild(el('p', 'dim', 'Waiting for first tokens from model\u2026'));
      }

      var errBox = byId('ai-error');
      if (reply.error) {
        errBox.hidden = false;
        errBox.textContent = reply.error;
      } else {
        errBox.hidden = true;
        errBox.textContent = '';
      }
    }

    if (pendingAiScroll) {
      pendingAiScroll = false;
      panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function render() {
    renderHeader();
    renderRecon();
    renderGraph();
    renderWhere();
    renderSide();
    renderDetail();
    renderAiPanel();
  }

  cy.on('tap', 'node', function (event) {
    var id = event.target.id();
    if (id === 'internet') {
      traceExpanded = !traceExpanded;
      drawn = '';
      renderGraph();
    }
    select(id);
  });
  // Dragging the empty background scrolls the row, like the scrollbar.
  var dragFrom = null;
  function pointerX(event) {
    var e = event.originalEvent;
    if (!e) { return null; }
    var touch = e.touches && e.touches[0];
    return touch ? touch.clientX : e.clientX;
  }
  cy.on('tapstart', function (event) {
    var x = pointerX(event);
    dragFrom = event.target === cy && x !== null ? { x: x, left: byId('scroller').scrollLeft } : null;
  });
  cy.on('tapdrag', function (event) {
    var x = pointerX(event);
    if (dragFrom && x !== null) { byId('scroller').scrollLeft = dragFrom.left - (x - dragFrom.x); }
  });
  cy.on('tapend', function () { dragFrom = null; });
  cy.on('tap', function (event) {
    if (event.target === cy) { select(null); }
  });

  renderLegend();
  connect();
})();
