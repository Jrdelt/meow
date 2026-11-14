// meow topology map. Everything shown here comes from scanned systems, so
// text is only ever inserted with textContent, never as HTML.
(function () {
  'use strict';

  var token = new URLSearchParams(location.search).get('token') || '';
  var socket = null;
  var state = null;
  var selected = null;
  var drawn = '';

  // The map is drawn like a home-network illustration: the router (or
  // access point) in the middle, the Internet cloud off to the top right,
  // and the devices on your network around the router, each on a straight
  // line to it: solid when wired, dotted when on Wi-Fi. meow can only see
  // how this machine connects, so the other devices are drawn the same way
  // (the legend says so). What only this machine uses (a VPN, a virtual
  // network) hangs below you.
  var RING1 = { rx: 300, ry: 205 }, RING2 = { rx: 470, ry: 320 };
  // Slots around the router, in degrees (0 = right, 90 = down), most
  // wanted first. The top right is left free for the cloud.
  // The outer ring sits between the inner ring's places, so every straight
  // line from the router passes between devices, not through them.
  var SLOTS1 = [20, 160, 200, 125, 235, 90, 55, 268];
  var SLOTS2 = [180, 142, 218, 108, 252, 72, 40, 285];
  // With networks of your own below you, the lower right stays theirs.
  var BUSY_BELOW_YOU = [40];
  var CLOUD = { x: 360, y: -230 };
  // Room kept around the fitted drawing, in screen pixels.
  var FIT_PADDING = 40;
  var expanded = {};    // networks the reader unfolded, by network id
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

  function icon(role) {
    return '/assets/icon-' + role + '.svg?token=' + encodeURIComponent(token);
  }

  var cy = cytoscape({
    container: document.getElementById('cy'),
    maxZoom: 2.2,
    minZoom: 0.2,
    style: [
      { selector: 'node', style: {
        'shape': 'rectangle', 'width': 76, 'height': 60, 'background-opacity': 0, 'border-width': 0,
        'background-fit': 'contain', 'background-clip': 'none',
        'label': 'data(text)', 'font-family': FONT, 'font-size': 13, 'color': TEXT, 'line-height': 1.3,
        'text-wrap': 'wrap', 'text-max-width': 200, 'text-valign': 'bottom', 'text-halign': 'center',
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
      { selector: 'node.hub', style: { 'width': 104, 'height': 80, 'font-size': 14 } },
      { selector: 'node.cloud', style: {
        'width': 170, 'height': 118, 'text-valign': 'center', 'text-margin-y': 8, 'font-size': 17, 'font-weight': 700,
        'color': '#1f2d3d' } },
      { selector: 'node.title', style: {
        'width': 1, 'height': 1, 'events': 'no', 'text-valign': 'top', 'text-halign': 'right',
        'text-margin-y': 0, 'font-weight': 700, 'font-size': 13, 'color': 'data(color)', 'text-max-width': 360 } },
      { selector: 'node.more', style: {
        'shape': 'round-rectangle', 'width': 96, 'height': 34, 'background-opacity': 1, 'background-color': '#ffffff',
        'border-width': 1.5, 'border-style': 'dashed', 'border-color': '#9aa3ad',
        'text-valign': 'center', 'text-margin-y': 0, 'color': '#4a5260' } },
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
      { selector: 'edge.spoke', style: { 'curve-style': 'straight', 'width': 2.2 } },
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

  function connect() {
    var ws = new WebSocket('ws://' + location.host + '/ws?token=' + encodeURIComponent(token));
    socket = ws;
    ws.onopen = function () {
      byId('conn').textContent = 'live';
      byId('conn').className = 'badge on';
    };
    ws.onmessage = function (event) {
      var message = JSON.parse(event.data);
      if (message.type === 'state') {
        state = message.state;
        render();
        // Where this machine is: asked once, when the map first opens.
        if (!askedWhere) {
          askedWhere = true;
          send({ cmd: 'locate' });
        }
      } else if (message.type === 'result' && !message.ok) {
        flash(message.error);
      }
    };
    ws.onclose = function () {
      byId('conn').textContent = 'session closed';
      byId('conn').className = 'badge off';
      setTimeout(connect, 2000);
    };
  }

  function renderHeader() {
    byId('session').textContent = state.session;
    byId('avatar').textContent = state.session.slice(0, 1).toUpperCase();
    byId('mode').textContent = 'mode ' + state.mode;
    byId('mode').className = 'badge mode-' + state.mode;
    // One line of status, like a finished lookup: what there is, what to do.
    var hosts = Object.keys(state.graph.hosts);
    var confirmed = 0, open = 0;
    hosts.forEach(function (key) {
      state.graph.hosts[key].advisories.forEach(function (advisory) {
        if (advisory.verification_status === 'Confirmed') { confirmed += 1; }
        if (advisory.verification_status === 'UnverifiedHypothesis') { open += 1; }
      });
    });
    var parts = [hosts.length + (hosts.length === 1 ? ' host' : ' hosts')];
    parts.push(open + ' to verify');
    parts.push(confirmed + ' confirmed');
    byId('counts').textContent = parts.join(' · ');
    document.title = 'meow: ' + state.session;
  }

  // Natural order for addresses: 10.0.0.9 before 10.0.0.10.
  function sortKey(data) {
    return String(data.address || data.label || data.id).replace(/\d+/g, function (digits) {
      return ('00000' + digits).slice(-6);
    });
  }

  // Turns the session's nodes and links into the illustration.
  function status(d) {
    if (d.kind !== 'host') { return 'none'; }
    if (d.confirmed) { return 'bad'; }
    if (d.hypotheses) { return 'warn'; }
    return 'ok';
  }
  var SEVERITY = { bad: 0, warn: 1, ok: 2, none: 3 };
  var PRINTER = /(^|[\s,])(9100|515|631)\/tcp|ipp|printer|jetdirect/i;

  function plan(nodes, edges) {
    var data = {}, out = {}, pos = {}, classes = {}, elements = [], lines = [], placed = {}, networkOf = {};
    nodes.forEach(function (node) { data[node.data.id] = node.data; out[node.data.id] = []; });
    edges.forEach(function (edge) {
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
    function caption(id) {
      var d = data[id], parts = [];
      if (id === 'local') {
        parts.push('You');
        var mine = d.caption && d.caption.split('\n')[1];
        if (mine) { parts.push(mine); }
      } else if (id === 'internet') {
        parts.push('Internet');
      } else if (d.kind === 'host') {
        parts.push(d.address || d.label);
        var counts = [];
        if (d.confirmed) { counts.push(d.confirmed + ' confirmed'); }
        if (d.hypotheses) { counts.push(d.hypotheses + ' to verify'); }
        if (counts.length) { parts.push(counts.join(' · ')); }
      } else if (d.kind === 'gateway') {
        parts.push((internetVia.indexOf(id) >= 0 ? 'Router ' : 'Gateway ') + d.label);
      } else if (d.kind === 'interface') {
        parts.push((d.caption || d.label).split('\n')[0]);
      } else {
        parts.push(d.label);
      }
      return parts.join('\n');
    }
    function put(id, x, y, extra) {
      var d = data[id];
      pos[id] = { x: x, y: y };
      classes[id] = [status(d)].concat(extra || []).join(' ');
      if (!d.icon && d.kind !== 'more' && d.kind !== 'title') { d.icon = picture(d); }
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
    function more(key, hidden, unfolded) {
      var id = 'more:' + key;
      data[id] = { id: id, kind: 'more', label: unfolded ? 'show fewer' : '+' + hidden + ' more' };
      return id;
    }
    // Ids on one row starting at x, `step` apart.
    function row(ids, x, y, step) {
      ids.forEach(function (id, i) { put(id, x + i * step, y); });
    }

    var internetVia = linked('internet', ['internet']);
    var networks = nodes.filter(function (n) { return n.data.kind === 'interface'; }).map(function (n) { return n.data.id; });
    function leadsOut(id) {
      return internetVia.indexOf(id) >= 0 || linked(id, ['gateway']).some(function (g) { return internetVia.indexOf(g) >= 0; });
    }
    var home = networks.filter(leadsOut)[0] ||
      networks.filter(function (n) { return ['vpn', 'virtual'].indexOf(data[n].link) < 0; })[0];
    var vpns = networks.filter(function (n) { return n !== home && data[n].link === 'vpn'; });
    var others = networks.filter(function (n) { return n !== home && vpns.indexOf(n) < 0; });
    var own = vpns.concat(others);

    // Your home network: the router in the middle, devices around it.
    var hub = null;
    if (home) {
      var gateways = linked(home, ['gateway']).sort(bySeverity);
      hub = gateways[0] || home;
      put(hub, 0, 0, ['hub']);
      // Only this machine's own link is known; the others are drawn alike.
      var wireless = data[home].link === 'wifi';
      // The network's name goes under the router's own.
      networkOf[hub] = caption(home) + (data[home].network ? ' · ' + data[home].network : '');
      var devices = gateways.slice(1).concat(linked(home, ['neighbour', 'direct']).filter(function (id) {
        return id !== hub && !placed[id];
      }).sort(bySeverity));
      var outer = own.length ? SLOTS2.filter(function (a) { return BUSY_BELOW_YOU.indexOf(a) < 0; }) : SLOTS2;
      var slots = SLOTS1.map(function (a) { return [a, RING1]; }).concat(outer.map(function (a) { return [a, RING2]; }));
      // Two rings hold you, the devices and, when there are more, the
      // "+N more" in the last place.
      var cap = slots.length - 2;
      var hidden = 0, unfolded = devices.length > cap && expanded[home];
      if (devices.length > cap && !expanded[home]) {
        devices.slice(cap).forEach(function (id) { placed[id] = true; });
        hidden = devices.length - cap;
        devices = devices.slice(0, cap);
      }
      var around = ['local'].concat(devices);
      if (hidden || unfolded) { around.push(more(home, hidden, unfolded)); }
      // Unfolded: further rings, as many as it takes, clear of the cloud
      // and of what hangs below you.
      for (var ring = 3; slots.length < around.length; ring++) {
        var step = 360 / (8 + ring * 4);
        for (var a = step / 2; a < 360; a += step) {
          if ((a > 292 && a < 358) || (own.length && a > 5 && a < 85)) { continue; }
          slots.push([a, { rx: RING2.rx + (ring - 2) * 170, ry: RING2.ry + (ring - 2) * 120 }]);
        }
      }
      around.forEach(function (id, i) {
        var angle = slots[i][0] * Math.PI / 180, r = slots[i][1];
        put(id, Math.cos(angle) * r.rx, Math.sin(angle) * r.ry, id === 'local' ? ['you'] : []);
        if (id.indexOf('more:') === 0) { classes[id] = 'none more'; }
        // Every device, and the "+N more" standing for the rest, on its line.
        link(hub, id, LINE.ethernet, wireless ? 'spoke wifi' : 'spoke');
      });
      // The Internet, joined to the router like a modem, and what was
      // reached there beside it.
      if (data.internet && internetVia.length) {
        put('internet', CLOUD.x, CLOUD.y, ['cloud']);
        link(hub, 'internet', LINE.ethernet);
        var outside = [];
        internetVia.forEach(function (g) {
          linked(g, ['routed']).forEach(function (h) { if (!placed[h] && outside.indexOf(h) < 0) { outside.push(h); } });
        });
        outside.sort(bySeverity).slice(0, 4).forEach(function (h, i) {
          put(h, CLOUD.x + 190 + i * 130, CLOUD.y - 20);
          link('internet', h, LINE.ethernet, 'thin');
        });
        outside.slice(4).forEach(function (h) { placed[h] = true; });
      }
    } else {
      put('local', 0, 0, ['you']);
    }

    // Networks only this machine is on (a VPN, a virtual network) hang
    // below you, not off the router: the rest of your network does not use
    // them. Each has its hub (the VPN's gateway, or a switch) and what is
    // behind it underneath.
    var you = pos.local, hubs = [];
    own.forEach(function (net) {
      var color = LINE[data[net].link] || LINE.other;
      var hubId = data[net].link === 'vpn' ? (linked(net, ['gateway']).sort(bySeverity)[0] || net) : net;
      var members = (hubId !== net ? linked(hubId, ['routed']) : [])
        .concat(linked(net, ['gateway', 'neighbour', 'direct']))
        .filter(function (id, i, all) { return id !== hubId && !placed[id] && all.indexOf(id) === i; })
        .sort(bySeverity);
      members.slice(6).forEach(function (h) { placed[h] = true; });
      members = members.slice(0, 6);
      hubs.push({ net: net, hub: hubId, color: color, members: members,
        width: Math.max(1, Math.min(3, members.length)) * 140 });
    });
    var hubY = you.y + 230, x0 = you.x;
    hubs.forEach(function (h, k) {
      if (k > 0) { x0 += hubs[k - 1].width / 2 + h.width / 2 + 40; }
      put(h.hub, x0, hubY, ['hub']);
      // A gateway is named as such, so it also gets its network's name;
      // a network's own switch only needs the address range.
      networkOf[h.hub] = h.hub === h.net ? (data[h.net].network || '')
        : caption(h.net) + (data[h.net].network ? ' · ' + data[h.net].network : '');
      h.members.forEach(function (m, i) {
        var across = Math.min(3, h.members.length), r = Math.floor(i / 3), j = i % 3;
        put(m, x0 + (j - (across - 1) / 2) * 140, hubY + 175 + r * 150);
        link(h.hub, m, h.color, 'down');
      });
    });
    if (hubs.length === 1) {
      link('local', hubs[0].hub, hubs[0].color, 'dashed down');
    } else if (hubs.length > 1) {
      // A short bar under you, one dashed drop to each network.
      var first = pos[hubs[0].hub].x, last = pos[hubs[hubs.length - 1].hub].x, barY = you.y + 120;
      data.ownbar = { id: 'ownbar', kind: 'bar', width: last - first + 8 };
      pos.ownbar = { x: (first + last) / 2, y: barY };
      classes.ownbar = 'ownbar';
      var point = function (x) {
        var id = 'a:own:' + Math.round(x);
        data[id] = { id: id, kind: 'anchor' };
        pos[id] = { x: x, y: barY };
        classes[id] = 'anchor';
        return id;
      };
      link('local', point(you.x), '#9aa3ad', 'thin');
      hubs.forEach(function (h) { link(point(pos[h.hub].x), h.hub, h.color, 'dashed down'); });
    }

    // Hosts this machine has no route to, in a group of their own.
    var rest = nodes.map(function (n) { return n.data.id; }).filter(function (id) {
      return !placed[id] && ['interface', 'internet'].indexOf(data[id].kind) < 0;
    }).sort(bySeverity);
    if (rest.length) {
      var y0 = RING2.ry + 250;
      title('title:unknown', 'Route not known', -RING2.rx - 50, y0 - 62, '#6b7178');
      rest.forEach(function (h, i) { put(h, -RING2.rx + (i % 6) * 150, y0 + Math.floor(i / 6) * 140); });
    }

    Object.keys(pos).forEach(function (id) {
      var d = Object.assign({}, data[id]);
      d.text = d.kind === 'title' || d.kind === 'more' ? d.label
        : (['bar', 'anchor'].indexOf(d.kind) >= 0 ? '' : caption(id));
      if (networkOf[id]) { d.text += '\n' + networkOf[id]; }
      elements.push({ group: 'nodes', data: d, classes: classes[id] });
    });
    return { elements: elements.concat(lines), positions: pos };
  }

  function renderGraph() {
    var key = JSON.stringify(state.topology) + JSON.stringify(expanded);
    if (key === drawn) { return; }
    drawn = key;
    var picture = plan(state.topology.nodes, state.topology.edges);
    cy.elements().remove();
    cy.add(picture.elements);
    cy.layout({
      name: 'preset', fit: true, padding: FIT_PADDING,
      positions: function (node) { return picture.positions[node.id()]; }
    }).run();
    if (selected && cy.$id(selected).length) { cy.$id(selected).select(); }
  }

  // Above the drawing: a note when a VPN is up, and where this machine
  // roughly is: a small satellite map with a pin and a circle for the rough
  // area, or a compass when there are no pictures. The session serves the
  // pictures; this page fetches nothing from anywhere else.
  var SVG_NS = 'http://www.w3.org/2000/svg';
  var whereDrawn = '';
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
    return [place.city, place.region, place.country].filter(Boolean).join(', ') || 'Unnamed place';
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
  // The pictures' licence asks for its credit as given, with its link.
  function credit(view) {
    var line = el('span', 'dim credit', 'Imagery: ');
    var at = view.credit_url ? view.credit.indexOf(view.credit_url) : -1;
    if (at < 0) {
      line.appendChild(document.createTextNode(view.credit));
      return line;
    }
    line.appendChild(document.createTextNode(view.credit.slice(0, at)));
    var link = line.appendChild(el('a', null, view.credit_url));
    link.href = view.credit_url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    line.appendChild(document.createTextNode(view.credit.slice(at + view.credit_url.length)));
    return line;
  }
  function satellite(where) {
    var view = where.map;
    var card = el('div', 'satellite');
    var picture = card.appendChild(el('div', 'picture'));
    picture.style.width = view.width + 'px';
    picture.style.height = view.height + 'px';
    picture.setAttribute('role', 'img');
    picture.setAttribute('aria-label', 'Satellite picture around ' + placeName(where.place) +
      ', with a pin at the estimate and its rough area circled');
    view.tiles.forEach(function (tile) {
      var img = picture.appendChild(el('img', 'tile'));
      img.alt = '';
      img.width = view.tile_size;
      img.height = view.tile_size;
      img.style.left = tile.left + 'px';
      img.style.top = tile.top + 'px';
      img.src = '/map/tile/' + tile.z + '/' + tile.x + '/' + tile.y + '?token=' + encodeURIComponent(token);
    });
    var x = view.width / 2, y = view.height / 2;
    var marks = svg('svg', { 'class': 'marks', width: view.width, height: view.height,
      viewBox: '0 0 ' + view.width + ' ' + view.height, 'aria-hidden': 'true' }, picture);
    svg('circle', { cx: x, cy: y, r: view.radius, fill: 'rgba(80, 160, 255, .22)',
      stroke: '#a9d4ff', 'stroke-width': 1.6 }, marks);
    // A pin whose tip is the estimate.
    var pin = svg('g', { transform: 'translate(' + x + ' ' + y + ')' }, marks);
    svg('ellipse', { cx: 0, cy: 0, rx: 4.5, ry: 1.8, fill: 'rgba(0, 0, 0, .35)' }, pin);
    svg('path', { d: 'M0 0 C-1.8 -5 -8 -8.6 -8 -15 A8 8 0 1 1 8 -15 C8 -8.6 1.8 -5 0 0 Z',
      fill: '#e5534b', stroke: '#ffffff', 'stroke-width': 1.4 }, pin);
    svg('circle', { cx: 0, cy: -15, r: 3, fill: '#ffffff' }, pin);
    var words = card.appendChild(el('div', 'words'));
    placeWords(words, where);
    words.appendChild(el('span', 'dim', 'Circle: rough area, about ' + Math.round(view.radius_m / 1000) +
      ' km around the pin.'));
    words.appendChild(el('span', 'dim', estimatedFrom(where)));
    words.appendChild(credit(view));
    return card;
  }
  // The fitted drawing starts just below the note and the location card,
  // so neither covers part of it: only the canvas' empty margin is under
  // them.
  function fitStage() {
    var where = byId('where');
    var top = Math.max(64, Math.ceil(where.offsetTop + where.offsetHeight + 12 - FIT_PADDING));
    var canvas = byId('cy');
    if (canvas.style.top === top + 'px') { return; }
    canvas.style.top = top + 'px';
    cy.resize();
    if (cy.elements().length) { cy.fit(cy.elements(), FIT_PADDING); }
  }
  window.addEventListener('resize', fitStage);
  function renderWhere() {
    var vpn = (state.machine && state.machine.vpn) || [];
    var where = state.location;
    // Drawn again only when something changed, so the pictures load once.
    var key = JSON.stringify([vpn, where]);
    if (key === whereDrawn) { return; }
    whereDrawn = key;
    var box = clear(byId('where'));
    if (vpn.length) {
      var names = vpn.map(function (line) { return line.split(':')[0]; }).join(', ');
      var all = (where && where.status === 'hidden_by_vpn') || vpn.some(function (line) {
        return /default route|all IPv4/.test(line);
      });
      var note = box.appendChild(el('div', 'vpn-note'));
      note.appendChild(el('strong', null, 'VPN detected'));
      note.appendChild(el('span', null, ' ' + names + (all
        ? ': it carries all traffic, so no location is shown (a lookup would only find the VPN\'s exit).'
        : ': it carries only some networks, so the location shown is your own connection\'s.')));
    }
    if (where && where.status === 'found' && where.map) {
      box.appendChild(satellite(where));
    } else if (where && where.status === 'found') {
      var card = box.appendChild(el('div', 'compass'));
      card.appendChild(compass());
      var words = card.appendChild(el('div', 'words'));
      placeWords(words, where);
      words.appendChild(el('span', 'dim', estimatedFrom(where)));
      if (where.map_error) { words.appendChild(el('span', 'dim', 'No map: ' + where.map_error)); }
    } else if (where && where.status === 'unavailable') {
      var off = box.appendChild(el('div', 'compass off'));
      off.appendChild(compass());
      var why = off.appendChild(el('div', 'words'));
      why.appendChild(el('strong', null, 'Location unknown'));
      why.appendChild(el('span', 'dim', where.reason));
    }
    fitStage();
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
  }

  // Why a node is drawn the way it is. A hint, not a finding.
  function drawnAs(data) {
    var name = '';
    ROLES.forEach(function (role) { if (role[0] === data.role) { name = role[1]; } });
    return el('div', 'dim drawn', name ? 'Shown as ' + name + ': ' + data.why + '.' : '');
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
  var unfolded = {};
  function fold(key, className, openByDefault) {
    var box = el('details', className);
    box.open = key in unfolded ? unfolded[key] : !!openByDefault;
    box.addEventListener('toggle', function () { unfolded[key] = box.open; });
    return box;
  }

  // "This machine": address -> type -> OS -> version, then a row per
  // subject. The long tables (routes, neighbours, every interface) are
  // cards of their own further down the page.
  var machineDrawn = '';

  function renderMachine() {
    var machine = state.machine || { vpn: [], sections: [] };
    var vpn = byId('vpn');
    vpn.textContent = machine.vpn.length ? 'VPN ' + machine.vpn.map(function (line) {
      return line.split(':')[0];
    }).join(', ') : 'no VPN';
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

  function select(id) {
    selected = id;
    cy.elements().unselect();
    if (id) { cy.$id(id).select(); }
    renderDetail();
    renderHosts();
    renderAdvisory();
  }

  // Every host as one row: what it is, and what there is to look at.
  function renderHosts() {
    var list = clear(byId('hosts'));
    var hosts = state.topology.nodes.filter(function (node) { return node.data.kind === 'host'; });
    hosts.sort(function (a, b) { return sortKey(a.data) < sortKey(b.data) ? -1 : 1; });
    if (!hosts.length) {
      list.appendChild(el('p', 'note', 'None yet. Work in the session shell, or import a scan with `meow add <file>`.'));
    }
    hosts.forEach(function (node) {
      var data = node.data;
      var name = el('button', 'link', data.address);
      name.addEventListener('click', function () { select(data.id); });
      var facts = [data.caption.split('\n')[0], data.open_ports + (data.open_ports === 1 ? ' port' : ' ports')];
      var kind = 'ok';
      if (data.hypotheses) { facts.push(data.hypotheses + ' to verify'); kind = 'warn'; }
      if (data.confirmed) { facts.push(data.confirmed + ' confirmed'); kind = 'bad'; }
      var line = list.appendChild(row(name, marked(facts.join(' · '), kind)));
      if (data.id === selected) { line.className += ' current'; }
    });

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
        var what = entry.ports.join(', ') || 'no port';
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
    var earlier = {};
    (state.tasks || []).forEach(function (task) {
      if (task.target in earlier) { earlier[task.target].push(task); return; }
      earlier[task.target] = [];
      latest.push(task);
    });
    renderList(byId('tasks'), latest, 'No recon tasks yet.', function (task) {
      var item = el('li');
      item.appendChild(el('div', 'label', 'recon ' + task.target));
      task.stages.forEach(function (stage) {
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
          line.appendChild(el('div', 'dim', run.stages.map(function (stage) {
            return stage.stage + ' ' + stage.status;
          }).join(' · ')));
        });
      }
      return item;
    });

    var notices = (state.notices || []).slice(-25).reverse();
    renderList(byId('notices'), notices, 'Nothing yet.', function (notice) {
      var item = el('li');
      item.appendChild(el('span', 'dim', notice.at.slice(11, 19) + ' '));
      item.appendChild(document.createTextNode(notice.text));
      return item;
    });
  }

  function pathTree(node, budget) {
    var list = el('ul', 'tree');
    Object.keys(node.children || {}).forEach(function (name) {
      if (budget.left <= 0) { return; }
      budget.left -= 1;
      var child = node.children[name];
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
    var checks = ((state.checklists[address] || {})[advisory.id] || {});
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
    var node = selected ? cy.$id(selected) : null;
    var only = node && !node.empty() && node.data('address') ? node.data('address') : null;
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
    var mine = {};
    (state.graph.local.interfaces || []).forEach(function (iface) {
      (iface.addresses || []).forEach(function (cidr) { mine[cidr.split('/')[0]] = true; });
    });
    var plan = [];
    Object.keys(fixes).forEach(function (address) {
      if (only && address !== only) { return; }
      fixes[address].forEach(function (fix) { plan.push({ address: address, fix: fix }); });
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
    Object.keys(state.graph.hosts).forEach(function (address) {
      if (only && address !== only) { return; }
      // Known-exploited first, then by severity score.
      var ordered = state.graph.hosts[address].advisories.slice().sort(function (a, b) {
        return (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || (b.cvss || 0) - (a.cvss || 0);
      });
      ordered.forEach(function (advisory) {
        var status = advisory.verification_status;
        var group = status === 'Confirmed' ? 0 : (status === 'FalsePositive' ? 4 : (advisory.kev ? 1 : 2));
        groups[group].items.push({ address: address, advisory: advisory });
      });
    });
    var notes = (state.graph.local.warnings || []).concat(state.graph.local.notes || []);
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
  function hostCards(host, data) {
    var cards = [];

    var ports = card('Open Ports');
    var closed = [];
    Object.keys(host.ports).forEach(function (key) {
      var port = host.ports[key];
      if (port.state !== 'open') { closed.push(key + ' (' + port.state + ')'); return; }
      var what = [port.service, port.product, port.version].filter(Boolean).join(' ');
      ports.appendChild(row(key, marked(what || 'open', 'ok')));
    });
    if (!data.open_ports) { ports.appendChild(el('p', 'note', 'None seen open.')); }
    if (closed.length) { ports.appendChild(el('p', 'note', 'Not seen open: ' + closed.join(', '))); }
    cards.push(ports);

    // What the web ports gave away: server headers, certificate names, paths.
    var web = card('Web');
    Object.keys(host.ports).forEach(function (key) {
      var port = host.ports[key];
      var paths = port.paths && port.paths.children && Object.keys(port.paths.children).length;
      var sans = port.tls_sans || [];
      if (!port.http && !sans.length && !paths) { return; }
      web.appendChild(el('h3', null, key));
      if (port.http && port.http.server) { web.appendChild(row('Server', port.http.server)); }
      if (port.http && port.http.location) { web.appendChild(row('Redirects to', port.http.location)); }
      sans.forEach(function (name) { web.appendChild(row('Certificate name', name)); });
      if (paths) { web.appendChild(pathTree(port.paths, { left: 300 })); }
    });
    if (web.childNodes.length > 1) { cards.push(web); }

    var ai = card('Ask AI');
    var ready = Object.keys(state.checklists[host.address] || {}).some(function (id) {
      return state.checklists[host.address][id].research_ready;
    });
    var ask = ai.appendChild(el('div', 'actions'));
    [['local', '[L] Local'], ['cloud', '[C] Cloud triage'], ['research', '[R] Deep research']].forEach(function (tier) {
      var button = ask.appendChild(el('button', null, tier[1]));
      if (tier[0] === 'research' && !ready) {
        button.disabled = true;
        button.title = 'Needs stack and route evidence first (see the checklist).';
      }
      button.addEventListener('click', function () {
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
      var answer = ai.appendChild(el('div', 'box'));
      answer.appendChild(el('div', 'dim', reply.running ? 'Running ...' : (reply.summary || '')));
      answer.appendChild(el('pre', 'reply', reply.text || ''));
      if (reply.error) { answer.appendChild(el('div', 'bad-text', reply.error)); }
    }
    cards.push(ai);

    var evidence = card('Evidence');
    var facts = (host.facts || []).slice();
    Object.keys(host.ports).forEach(function (key) {
      (host.ports[key].facts || []).forEach(function (fact) { facts.push(fact); });
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
    var save = note.appendChild(el('div', 'actions')).appendChild(el('button', null, 'Save note'));
    save.addEventListener('click', function () {
      if (box.value.trim()) {
        send({ cmd: 'note', address: host.address, text: box.value });
        box.value = '';
      }
    });
    cards.push(note);
    return cards;
  }

  // The selected node: its facts in the card beside the map, and for a host
  // one card per subject at the head of the cards below.
  function renderDetail() {
    var detail = byId('detail');
    var cards = byId('host-cards');
    // Keep a half-written note when the state refreshes.
    var draft = cards.querySelector('textarea');
    var draftText = draft ? draft.value : '';
    var hadFocus = draft && document.activeElement === draft;
    clear(detail);
    clear(cards);
    var node = selected ? cy.$id(selected) : null;
    if (!node || node.empty()) {
      byId('detail-title').textContent = 'Selected';
      detail.appendChild(el('p', 'note', 'Click a node on the map, or a host in the list below, to see what is ' +
        'known about it.'));
      return;
    }
    var data = node.data();
    var host = data.address ? state.graph.hosts[data.address] : null;
    if (host) {
      byId('detail-title').textContent = 'Host Info';
      // address -> type -> OS -> version, one row each.
      var parts = data.headline.split(' -> ');
      var guessed = / \(OS read off a service banner\)$/;
      var version = (parts[3] || '').replace(guessed, '');
      // Open ports have a card of their own; why the node is drawn as it is
      // and where the system came from are tooltips here.
      detail.appendChild(row('Address', parts[0]));
      detail.appendChild(row('Type', parts[1])).title = 'Drawn this way because ' + data.why + '.';
      var banner = guessed.test(parts[3] || '');
      var system = detail.appendChild(row('System', banner ? marked(parts[2], 'info') : parts[2]));
      if (banner) { system.title = 'Read off a service banner, not reported by an OS scan.'; }
      detail.appendChild(row('Version', version));
      (host.hostnames || []).forEach(function (name) { detail.appendChild(row('Name', name)); });
      if (host.mac) { detail.appendChild(row('Hardware address', host.mac)); }
      detail.appendChild(row('Route', data.reachable ? marked('known', 'ok')
        : marked(data.by_name ? 'address not known' : 'none known', 'warn')));
      hostCards(host, data).forEach(function (one) { cards.appendChild(one); });
      var box = cards.querySelector('textarea');
      if (box && draftText) { box.value = draftText; }
      if (box && hadFocus) { box.focus(); }
      return;
    }
    byId('detail-title').textContent = data.caption.split('\n')[0];
    if (data.kind === 'interface') {
      var name = data.id.slice(3);
      if (data.network) { detail.appendChild(row('Network', data.network)); }
      (state.graph.local.interfaces || []).forEach(function (iface) {
        if (iface.name !== name) { return; }
        detail.appendChild(row('Interface', name + ' (' + iface.kind + (iface.up ? ', up' : ', down') + ')'));
        iface.addresses.forEach(function (address) { detail.appendChild(row('This machine', address)); });
      });
      if (data.hidden_neighbours) {
        detail.appendChild(el('p', 'note', data.hidden_neighbours + ' more devices in the neighbour table are not drawn.'));
      }
    } else if (data.kind === 'neighbour') {
      detail.appendChild(row('Address', data.label));
      detail.appendChild(row('Hardware address', data.mac));
      detail.appendChild(row('Seen on', data.interface));
      detail.appendChild(el('p', 'note', 'It becomes a host once a scan, an imported file or the terminal output mentions it.'));
    } else if (data.kind === 'internet') {
      detail.appendChild(el('p', 'note', 'meow has sent nothing there to find this out.'));
    } else {
      detail.appendChild(row('Name', data.label));
    }
    detail.appendChild(drawnAs(data));
  }

  function render() {
    renderHeader();
    renderGraph();
    renderWhere();
    renderSide();
    renderDetail();
  }

  cy.on('tap', 'node', function (event) {
    var id = event.target.id();
    if (id.indexOf('more:') === 0) {  // unfold or fold a busy line
      var key = id.slice(5);
      expanded[key] = !expanded[key];
      renderGraph();
      return;
    }
    select(id);
  });
  cy.on('tap', function (event) {
    if (event.target === cy) { select(null); }
  });

  renderLegend();
  connect();
})();
