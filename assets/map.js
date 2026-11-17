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

  function send(command) {
    if (socket && socket.readyState === WebSocket.OPEN) {
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
      } else if (message.type === 'result' && !message.ok) {
        flash(message.error || 'Command failed.');
      }
    };
    ws.onclose = function () {
      if (socket !== ws) { return; }
      byId('conn').textContent = ended ? 'session ended' : 'session closed';
      byId('conn').className = 'badge off';
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
    var confirmed = 0, open = 0;
    hosts.forEach(function (key) {
      var host = own(hostsMap, key);
      if (!host) { return; }
      (host.advisories || []).forEach(function (advisory) {
        if (advisory.verification_status === 'Confirmed') { confirmed += 1; }
        if (advisory.verification_status === 'UnverifiedHypothesis') { open += 1; }
      });
    });
    var parts = [hosts.length + (hosts.length === 1 ? ' host' : ' hosts')];
    parts.push(open + ' to verify');
    parts.push(confirmed + ' confirmed');
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
  function status(d) {
    if (!d || d.kind !== 'host') { return 'none'; }
    if (d.confirmed) { return 'bad'; }
    if (d.hypotheses) { return 'warn'; }
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
        var dot = d.confirmed ? ' \ud83d\udd34' : (d.hypotheses ? ' \ud83d\udfe1' : (d.open_ports ? ' \ud83d\udfe2' : ''));
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
        var counts = [];
        if (d.confirmed) { counts.push(d.confirmed + ' confirmed'); }
        if (d.hypotheses) { counts.push(d.hypotheses + ' to verify'); }
        if (counts.length) { parts.push(counts.join(' · ')); }
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
    [['warn', 'to verify'], ['bad', 'confirmed']].forEach(function (key) {
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
    legend.appendChild(el('span', 'item note', 'Other devices are drawn connected the way you are (assumed: meow only sees your own link).'));
    var hint = legend.appendChild(el('span', 'item note', 'More devices to the side: scroll left and right, or drag the background.'));
    hint.id = 'scroll-hint';
    hint.hidden = true;
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
        box.appendChild(row(section.title, lines));
        return;
      }
      var table = tables.appendChild(card(section.title));
      lines.className = 'lines';
      table.appendChild(lines);
    });
    if (machine.observed_utc) {
      box.appendChild(el('p', 'note', 'Read from this machine at ' + machine.observed_utc.slice(11, 19) +
        ' UTC. Nothing was sent to find this out.'));
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
    renderAdvisory();
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
      list.appendChild(el('p', 'note', 'None yet. Work in the session shell, or import a scan with `meow add <file>`.'));
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
        if (data.hypotheses) { facts.push(data.hypotheses + ' to verify'); kind = 'warn'; }
        if (data.confirmed) { facts.push(data.confirmed + ' confirmed'); kind = 'bad'; }
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
      names.appendChild(el('summary', null, 'Names only mentioned (' + mentioned.length + ')'));
      names.appendChild(el('p', 'note', 'These appeared in the terminal or a log, usually inside a URL. ' +
        'meow has not contacted them and they are not part of the network drawn above.'));
      mentioned.forEach(function (entry) {
        var what = (entry.ports || []).join(', ') || 'no port';
        if (entry.paths) { what += ' · ' + entry.paths + (entry.paths === 1 ? ' path' : ' paths'); }
        names.appendChild(row(entry.name, what, 'dim'));
      });
    }
  }

  function renderSide() {
    renderMachine();
    renderHosts();
    renderAdvisory();

    // The newest run of each target in full; earlier runs of the same
    // target (all kept in the workspace) fold away under it.
    var latest = [];
    var earlier = table();
    (state.tasks || []).forEach(function (task) {
      if (hasOwn.call(earlier, task.target)) { earlier[task.target].push(task); return; }
      earlier[task.target] = [];
      latest.push(task);
    });
    renderList(byId('tasks'), latest, 'No recon tasks yet.', function (task) {
      var item = el('li');
      item.appendChild(el('div', 'label', 'recon ' + task.target));
      (task.stages || []).forEach(function (stage) {
        var kind = { done: 'ok', running: 'warn', failed: 'bad', interrupted: 'bad' }[stage.status] || 'info';
        var line = item.appendChild(row(stage.stage, marked(stage.status, kind)));
        line.title = stage.detail || '';
        // Why a stage was skipped or failed, and how to fix it, in plain view.
        if (stage.detail && (stage.status === 'skipped' || stage.status === 'failed')) {
          item.appendChild(el('div', 'note why', stage.detail));
        }
      });
      var older = earlier[task.target];
      if (older.length) {
        var past = item.appendChild(fold('runs:' + task.target, 'names', false));
        past.appendChild(el('summary', null, 'Earlier runs (' + older.length + ')'));
        older.forEach(function (run) {
          var when = (run.created_utc || '').replace('T', ' ').slice(0, 16);
          var line = past.appendChild(el('div', 'fact'));
          line.appendChild(el('div', null, '#' + run.id + (when ? '  ' + when : '')));
          line.appendChild(el('div', 'dim', (run.stages || []).map(function (stage) {
            return stage.stage + ' ' + stage.status;
          }).join(' · ')));
        });
      }
      return item;
    });

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

  // One advisory: a line that unfolds into its checklist and the verdict.
  function advisoryItem(address, advisory, kind, withHost) {
    var item = fold('advisory:' + address + ':' + advisory.id, 'item', false);
    var summary = item.appendChild(el('summary'));
    summary.appendChild(mark(kind));
    var text = summary.appendChild(el('span', 'what'));
    var title = text.appendChild(el('span', 'title', advisory.id + '  ' + advisory.title));
    title.title = advisory.title;
    var where = [];
    if (withHost) { where.push(address); }
    if (advisory.port) { where.push(advisory.port); }
    if (advisory.severity) { where.push(advisory.severity + (advisory.cvss ? ' ' + advisory.cvss : '')); }
    if (advisory.kev) { where.push('in the CISA known-exploited catalog'); }
    if (advisory.fixed_in) { where.push('fixed in ' + advisory.fixed_in); }
    else if (advisory.last_affected) { where.push('affected up to ' + advisory.last_affected); }
    where.push(advisory.matched);
    text.appendChild(el('span', 'dim', where.join(' · ')));

    var status = advisory.verification_status;
    var checks = own(own(state.checklists, address), advisory.id) || {};
    (checks.items || []).forEach(function (check) {
      var label = el('span', 'label', check.label);
      item.appendChild(row(label, marked(check.detail, check.done ? 'ok' : 'warn')));
    });
    if (checks.research_ready && status === 'UnverifiedHypothesis') {
      item.appendChild(el('div', 'badge ok', '[R] Deep Research Ready'));
    }
    var actions = item.appendChild(el('div', 'actions'));
    function verdict(label, value) {
      var button = actions.appendChild(el('button', null, label));
      button.addEventListener('click', function () {
        send({ cmd: 'verdict', address: address, advisory: advisory.id, status: value });
      });
    }
    if (status === 'UnverifiedHypothesis') {
      verdict('Confirm', 'Confirmed');
      verdict('False positive', 'FalsePositive');
    } else {
      verdict('Reopen', 'UnverifiedHypothesis');
    }
    var look = actions.appendChild(el('button', null, 'Show host'));
    look.addEventListener('click', function () { select('host:' + address); });
    return item;
  }

  // The Advisory card: everything that needs a decision, most urgent first.
  // For the selected host, or for every host when none is selected.
  function renderAdvisory() {
    var box = clear(byId('advisory'));
    var selData = selectedNodeData();
    var only = selData && selData.address ? selData.address : null;
    byId('advisory-title').textContent = only ? 'Advisory for ' + only : 'Advisory';
    var groups = [
      { name: 'Confirmed', kind: 'bad', open: true, items: [] },
      { name: 'Known exploited, to verify', kind: 'issue', open: true, items: [] },
      { name: 'To verify', kind: 'warn', open: false, items: [] },
      { name: 'Informational', kind: 'info', open: false, items: [] },
      { name: 'False positives', kind: 'ok', open: false, items: [] }
    ];
    // What to do comes first: one line per piece of software, since one
    // update usually answers every advisory matched on it.
    var fixes = state.fixes || {};
    var mine = table();
    ((state.graph && state.graph.local && state.graph.local.interfaces) || []).forEach(function (iface) {
      (iface.addresses || []).forEach(function (cidr) { mine[cidr.split('/')[0]] = true; });
    });
    var plan = [];
    Object.keys(fixes).forEach(function (address) {
      if (only && address !== only) { return; }
      (own(fixes, address) || []).forEach(function (fix) { plan.push({ address: address, fix: fix }); });
    });
    if (plan.length) {
      var todo = box.appendChild(el('div', 'todo'));
      todo.appendChild(el('h3', null, 'What to update'));
      var elsewhere = false;
      plan.forEach(function (entry) {
        var fix = entry.fix;
        var here = !!mine[entry.address];
        elsewhere = elsewhere || !here;
        var count = fix.advisories + (fix.advisories === 1 ? ' advisory' : ' advisories') +
          (fix.kev ? ', ' + fix.kev + ' known exploited' : '');
        var line = todo.appendChild(el('div', 'fix'));
        line.appendChild(el('div', null, fix.action));
        line.appendChild(el('div', 'dim', 'On ' + entry.address + (here ? ' (this machine)' : ' (another machine, not this one)') +
          ' · answers ' + count));
      });
      todo.appendChild(el('p', 'note', (elsewhere ? 'An update has to be made on the machine named, by whoever looks after it. ' : '') +
        'Every entry below was matched by version number only and is not proof: a system that takes security updates ' +
        'from its vendor often has the fix under the same version number. After updating, scan again; what no longer matches is removed.'));
    }
    var hostsMap = (state.graph && state.graph.hosts) || {};
    Object.keys(hostsMap).forEach(function (address) {
      if (only && address !== only) { return; }
      var host = own(hostsMap, address);
      if (!host) { return; }
      // Known-exploited first, then by severity score.
      var ordered = (host.advisories || []).slice().sort(function (a, b) {
        return (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || (b.cvss || 0) - (a.cvss || 0);
      });
      ordered.forEach(function (advisory) {
        var status = advisory.verification_status;
        var group = status === 'Confirmed' ? 0 : (status === 'FalsePositive' ? 4 : (advisory.kev ? 1 : 2));
        groups[group].items.push({ address: address, advisory: advisory });
      });
    });
    var localNet = (state.graph && state.graph.local) || {};
    var notes = (localNet.warnings || []).concat(localNet.notes || []);
    var shown = 0;
    groups.forEach(function (group) {
      var count = group.name === 'Informational' ? notes.length : group.items.length;
      if (!count) { return; }
      // The most urgent group that has anything in it starts unfolded.
      var open = group.open || shown === 0;
      shown += count;
      var section = box.appendChild(fold('group:' + group.name, 'group ' + group.kind, open));
      var summary = section.appendChild(el('summary'));
      summary.appendChild(el('span', 'name', group.name));
      summary.appendChild(el('span', 'dim', ' (' + count + ')'));
      if (group.name === 'Informational') {
        notes.forEach(function (text) {
          var line = section.appendChild(el('div', 'plain'));
          line.appendChild(mark('info'));
          line.appendChild(el('span', null, text));
        });
        return;
      }
      group.items.slice(0, 80).forEach(function (entry) {
        section.appendChild(advisoryItem(entry.address, entry.advisory, group.kind === 'issue' ? 'bad' : group.kind, !only));
      });
      if (group.items.length > 80) {
        section.appendChild(el('p', 'note', (group.items.length - 80) + ' more not shown; see `meow hud` or the report.'));
      }
    });
    if (!shown) {
      box.appendChild(el('p', 'note', only
        ? 'Nothing matched for this host. Matches from the vulnerability databases appear here as hypotheses to verify.'
        : 'Nothing to decide yet. When the software meow sees matches a known vulnerability, it appears here as a hypothesis to verify, never as a finding.'));
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
      var seenRow = box.appendChild(row('Seen up by a scan', sinceText(seenUp)));
      seenRow.title = seenUp.slice(0, 19).replace('T', ' ') + ' UTC';
    }
    if (lastScan && lastScan !== seenUp) { box.appendChild(row('Last scan result', sinceText(lastScan))); }
    box.appendChild(row('Open ports known', String(openCount)));
    if (check && check.status !== 'checking') {
      box.appendChild(row('Last checked', sinceText(check.at)));
      var answers = (check.ports || []).map(function (p) {
        return p.port + ' ' + p.state + (typeof p.ms === 'number' ? ' (' + p.ms.toFixed(0) + ' ms)' : '');
      });
      if (answers.length) { box.appendChild(row('Ports tried', answers.join(', '))); }
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
    box.appendChild(el('p', 'note', light
      ? 'Light mode sends no packets: switch to mild or aggressive to check.'
      : 'Check now makes one connection to each of up to six known open ports (or 443, 80 and 22), and nothing else.'));
    return box;
  }

  function hostCards(host, data) {
    var cards = [statusCard(host)];
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
    if (!keys.length) { ports.appendChild(el('p', 'note', 'No port seen yet.')); }
    var notOpen = host.not_open || {};
    Object.keys(notOpen).forEach(function (key) {
      var group = own(notOpen, key);
      if (!group) { return; }
      ports.appendChild(el('p', 'note', 'Tried and ' + group.state + ' (' + group.count + ' ' + group.protocol +
        (group.count === 1 ? ' port' : ' ports') + ')' + (group.ports ? ': ' + group.ports.split(',').join(', ') : '.')));
    });
    cards.push(ports);

    // What the web ports gave away: server headers, certificate names, paths.
    var web = card('Web');
    Object.keys(hostPorts).forEach(function (key) {
      var port = own(hostPorts, key);
      if (!port) { return; }
      var paths = port.paths && port.paths.children && Object.keys(port.paths.children).length;
      var sans = port.tls_sans || [];
      var http = port.http || null;
      if (!http && !sans.length && !paths) { return; }
      web.appendChild(el('h3', null, key));
      if (http && http.server) { web.appendChild(row('Server', http.server)); }
      if (http && http.powered_by) { web.appendChild(row('Powered by', http.powered_by)); }
      if (http && http.title) { web.appendChild(row('Title', http.title)); }
      if (http && http.waf) { web.appendChild(row('WAF / CDN', marked(http.waf, 'info'))); }
      if (http && http.favicon_hash !== null && http.favicon_hash !== undefined) {
        var fav = String(http.favicon_hash) + (http.favicon_framework ? ' (' + http.favicon_framework + ')' : '');
        web.appendChild(row('Favicon hash', fav));
      }
      if (http && http.location) { web.appendChild(row('Redirects to', http.location)); }
      if (http && http.security_headers) {
        var secHdrs = Array.isArray(http.security_headers)
          ? http.security_headers
          : Object.keys(http.security_headers).filter(function (k) {
              return own(http.security_headers, k) !== undefined;
            });
        if (secHdrs.length) {
          web.appendChild(row('Security headers', marked(secHdrs.join(', '), 'ok')));
        }
      }
      if (http && http.missing_headers && http.missing_headers.length) {
        web.appendChild(row('Missing headers', marked(http.missing_headers.join(', '), 'warn')));
      }
      if (http && http.tls_versions && http.tls_versions.length) {
        var hasLegacy = http.tls_versions.some(function (v) { return v === 'TLS 1.0' || v === 'TLS 1.1'; });
        web.appendChild(row('TLS versions', marked(http.tls_versions.join(', '), hasLegacy ? 'warn' : 'ok')));
      }
      if (http && http.tls_weak_ciphers && http.tls_weak_ciphers.length) {
        web.appendChild(row('Weak TLS ciphers', marked(http.tls_weak_ciphers.join(', '), 'warn')));
      }
      if (http && (http.tls_subject || http.tls_issuer)) {
        var certParts = [http.tls_subject, http.tls_issuer ? 'issuer ' + http.tls_issuer : null].filter(Boolean);
        web.appendChild(row('TLS certificate', certParts.join(' · ')));
      }
      if (http && (http.tls_not_before || http.tls_not_after)) {
        web.appendChild(row('Cert validity', [http.tls_not_before || '?', http.tls_not_after || '?'].join(' -> ')));
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
    if (web.childNodes.length > 1) { cards.push(web); }

    var ai = card('Ask AI');
    var lists = own(state.checklists, host.address) || {};
    var ready = Object.keys(lists).some(function (id) {
      var list = own(lists, id);
      return !!(list && list.research_ready);
    });
    var ask = ai.appendChild(el('div', 'actions'));
    [['local', '[L] Local'], ['cloud', '[C] Cloud triage'], ['research', '[R] Deep research']].forEach(function (tier) {
      var button = ask.appendChild(el('button', null, tier[1]));
      if (tier[0] === 'research' && !ready) {
        button.disabled = true;
        button.title = 'Needs stack and route evidence first (see the checklist).';
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
    } else {
      ai.appendChild(el('p', 'note', 'No cloud API key yet: [C] answers with the local model and [R] is ' +
        'unavailable. Run `meow setup` in any terminal to add your own key or to choose your local model. ' +
        'It applies to this session at once.'));
    }
    var reply = state.ai || {};
    if (reply.address === host.address && (reply.running || reply.text || reply.error)) {
      ai.appendChild(row('Status', reply.running
        ? marked('streaming below ...', 'info')
        : (reply.error ? marked('error (see below)', 'bad') : marked('ready below', 'ok'))));
      var jumpWrap = ai.appendChild(el('div', 'actions'));
      var jumpBtn = jumpWrap.appendChild(el('button', null, 'Jump to triage output ↓'));
      jumpBtn.addEventListener('click', function () {
        var panel = byId('card-ai');
        if (panel && !panel.hidden) {
          panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    }
    cards.push(ai);

    var evidence = card('Evidence');
    var facts = (host.facts || []).slice();
    Object.keys(hostPorts).forEach(function (key) {
      var port = own(hostPorts, key);
      if (!port) { return; }
      (port.facts || []).forEach(function (fact) { facts.push(fact); });
    });
    facts.forEach(function (fact) {
      var line = evidence.appendChild(el('div', 'fact'));
      line.appendChild(el('div', null, fact.claim));
      line.appendChild(el('div', 'dim', fact.source + ' · ' + fact.confidence + ' · ' + fact.verification_status));
    });
    if (!facts.length) { evidence.appendChild(el('p', 'note', 'Nothing recorded yet.')); }
    cards.push(evidence);

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
    cards.push(note);
    return cards;
  }

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
    var cards = byId('host-cards');
    // Keep cursor/focus and per-host note draft across live refreshes.
    var sameHost = selected && selected === lastDetailId;
    var draft = sameHost ? cards.querySelector('textarea') : null;
    var draftText = draft ? draft.value : '';
    var hadFocus = draft && document.activeElement === draft;
    var selStart = hadFocus ? draft.selectionStart : null;
    var selEnd = hadFocus ? draft.selectionEnd : null;
    lastDetailId = selected;
    clear(detail);
    clear(cards);
    var data = selectedNodeData();
    if (!data) {
      byId('detail-title').textContent = 'Selected';
      detail.appendChild(el('p', 'note', 'Click a node on the map, or a host in the list below, to see what is ' +
        'known about it.'));
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
      hostCards(host, data).forEach(function (one) { cards.appendChild(one); });
      var box = cards.querySelector('textarea');
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
        detail.appendChild(el('p', 'note', data.hidden_neighbours + ' more devices in the neighbour table are not drawn.'));
      }
    } else if (data.kind === 'neighbour') {
      detail.appendChild(row('Address', data.label || ''));
      detail.appendChild(row('Hardware address', data.mac || ''));
      detail.appendChild(row('Seen on', data.interface || ''));
      detail.appendChild(el('p', 'note', 'It becomes a host once a scan, an imported file or the terminal output mentions it.'));
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
      detail.appendChild(el('p', 'note', 'This is the public egress point that remote targets see when meow connects to them.'));
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
        detail.appendChild(el('p', 'note', 'Run `recon <target>` to measure intermediate traceroute hops and round-trip latency across the Internet.'));
      }
    } else if (data.kind === 'hop' && data.hop) {
      appendHopDetail(detail, data.hop);
    } else if (data.kind === 'waf') {
      byId('detail-title').textContent = 'WAF / CDN Edge';
      detail.appendChild(row('Provider', marked(data.waf || 'WAF / CDN', 'info')));
      if (data.target) { detail.appendChild(row('Protected origin', data.target)); }
      detail.appendChild(el('p', 'note', 'Detected before directory scanning (`dirs`) runs so meow avoids wasting requests or getting your egress IP blocked by a strict WAF.'));
    } else if (data.kind === 'asn') {
      byId('detail-title').textContent = 'Cloud / ASN Group';
      detail.appendChild(row('ASN / Provider', data.asn || data.label || ''));
      if (data.bgp_prefix) { detail.appendChild(row('BGP prefix', data.bgp_prefix)); }
      detail.appendChild(el('p', 'note', 'Sibling targets hosted in the same autonomous system are grouped together on the map.'));
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
      detail.appendChild(el('p', 'note', 'Location from the offline DB-IP Lite database: city-level and approximate; routers are often registered where their network is, not where they stand.'));
    }
  }

  function appendInlineCodeOnly(parent, text) {
    var buf = '';
    var i = 0;
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
        var closeIdx = text.indexOf(ticks, tickEnd);
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
        var closeIdx = text.indexOf(ticks, tickEnd);
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
        var mid = text.indexOf('](', i + 1);
        if (mid > i + 1) {
          var label = text.slice(i + 1, mid);
          if (label.indexOf('[') < 0 && label.indexOf('\n') < 0) {
            var closeParen = text.indexOf(')', mid + 2);
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
      var headMatch = /^ {0,3}(#{1,6})\s+(.*?)\s*#*$/.exec(line);
      if (headMatch) {
        var hNode = container.appendChild(el(headMatch[1].length <= 2 ? 'h3' : 'h4'));
        appendInlineFormatted(hNode, headMatch[2]);
        i += 1;
        continue;
      }
      if (isHrLine(line)) {
        container.appendChild(el('hr'));
        i += 1;
        continue;
      }
      if (isTableRow(line) && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
        var headers = splitTableCells(line);
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
          var rowCells = splitTableCells(lines[i]);
          var tr = tbody.appendChild(el('tr'));
          for (var c = 0; c < Math.max(headers.length, rowCells.length); c += 1) {
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
  function renderTriage(container, text) {
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
