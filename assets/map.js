// meow topology map. Everything shown here comes from scanned systems, so
// text is only ever inserted with textContent, never as HTML.
(function () {
  'use strict';

  var token = new URLSearchParams(location.search).get('token') || '';
  var socket = null;
  var state = null;
  var selected = null;
  var drawn = '';

  // The map is a top-down network diagram: the Internet and whatever lies
  // beyond a gateway at the top, gateways below that, one bar per network
  // this machine is on, and the devices on each network underneath its bar.
  var PITCH = 112;      // between devices side by side
  var ROW = 104;        // between rows of devices
  var PER_ROW = 6;      // devices per row under a bar
  var MAX_DEVICES = 12; // a busier network folds the rest into "+N more"
  var GAP = 120;        // between networks
  var Y_BEYOND = -330, Y_GATEWAY = -200, Y_BAR = -90, Y_DEVICES = 10;
  var expanded = {};    // networks the reader unfolded, by network id

  // Bar colour by the kind of connection.
  var LINE = { wifi: '#8d939b', ethernet: '#8d939b', other: '#8d939b', vpn: '#39c5cf',
    virtual: '#9d8ce0', unknown: '#6b7178' };
  var TEXT = '#e7e9ec';
  var FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif';

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

  function icon(role) {
    return '/assets/icon-' + role + '.svg?token=' + encodeURIComponent(token);
  }

  var cy = cytoscape({
    container: document.getElementById('cy'),
    maxZoom: 2,
    minZoom: 0.2,
    style: [
      { selector: 'node', style: {
        'shape': 'round-rectangle', 'width': 46, 'height': 46,
        'background-color': '#16191d', 'border-width': 2, 'border-color': '#3a3f47',
        'background-fit': 'contain', 'background-width': '70%', 'background-height': '70%',
        'label': 'data(text)', 'font-family': FONT, 'font-size': 11, 'color': TEXT, 'line-height': 1.25,
        'text-wrap': 'wrap', 'text-max-width': PITCH + 40, 'text-valign': 'bottom', 'text-halign': 'center',
        'text-margin-y': 6, 'text-background-color': '#111316', 'text-background-opacity': 0.9,
        'text-background-padding': 2, 'overlay-padding': 6, 'overlay-opacity': 0 } }
    ].concat(ROLES.map(function (role) {
      return { selector: 'node[icon = "' + role[0] + '"]', style: { 'background-image': icon(role[0]) } };
    })).concat([
      // What a device asks of you: nothing, to verify, confirmed; grey is not scanned.
      { selector: 'node.ok', style: { 'border-color': '#3fb950' } },
      { selector: 'node.warn', style: { 'border-color': '#e3b341', 'border-width': 3 } },
      { selector: 'node.bad', style: { 'border-color': '#f85149', 'border-width': 3 } },
      { selector: 'node.kev', style: { 'border-style': 'double', 'border-width': 6 } },
      { selector: 'node.you', style: { 'border-color': '#c8f02b', 'border-width': 3, 'color': '#c8f02b', 'font-weight': 700 } },
      { selector: 'node.internet', style: { 'width': 64, 'height': 52, 'border-width': 1 } },
      { selector: 'node.bar', style: {
        'shape': 'round-rectangle', 'height': 8, 'width': 'data(width)', 'border-width': 0,
        'background-color': 'data(color)', 'background-image': 'none', 'label': '' } },
      { selector: 'node.title', style: {
        'width': 1, 'height': 1, 'border-width': 0, 'background-opacity': 0, 'events': 'no',
        'text-valign': 'top', 'text-halign': 'right', 'text-margin-y': -8, 'text-margin-x': 0,
        'font-weight': 700, 'font-size': 12, 'color': 'data(color)', 'text-max-width': 320 } },
      { selector: 'node.anchor', style: {
        'width': 1, 'height': 1, 'border-width': 0, 'background-opacity': 0, 'background-image': 'none',
        'overlay-opacity': 0, 'events': 'no', 'label': '' } },
      { selector: 'node.more', style: {
        'height': 28, 'width': 80, 'border-style': 'dashed', 'border-width': 1, 'background-image': 'none',
        'text-valign': 'center', 'text-margin-y': 0, 'color': '#8d939b' } },
      { selector: 'node:selected', style: { 'overlay-color': '#c8f02b', 'overlay-opacity': 0.2 } },
      { selector: 'edge', style: { 'curve-style': 'straight', 'width': 2, 'line-color': '#4a4f57', 'target-arrow-shape': 'none' } },
      { selector: 'edge.uplink', style: { 'width': 2.5, 'line-color': '#8d939b' } },
      { selector: 'edge.tunnel', style: { 'width': 2.5, 'line-color': 'data(color)', 'line-style': 'dashed', 'line-dash-pattern': [7, 5],
        'curve-style': 'taxi', 'taxi-direction': 'horizontal', 'taxi-turn': '100%' } }
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

  // Turns the session's nodes and links into the diagram.
  function status(d) {
    if (d.kind !== 'host') { return 'none'; }
    if (d.confirmed) { return 'bad'; }
    if (d.hypotheses) { return 'warn'; }
    return 'ok';
  }
  var SEVERITY = { bad: 0, warn: 1, ok: 2, none: 3 };

  function plan(nodes, edges) {
    var data = {}, out = {}, pos = {}, classes = {}, texts = {}, elements = [], wires = [], placed = {};
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
    function iconFor(d) {
      if (d.id === 'local') { return 'you'; }
      if (d.kind === 'gateway') { return 'router'; }
      if (d.kind === 'neighbour') { return 'client'; }
      return d.role === 'segment' ? 'client' : (d.role || 'client');
    }
    function caption(id) {
      var d = data[id], parts = [];
      if (id === 'local') {
        parts.push('You');
        var mine = d.caption && d.caption.split('\n')[1];
        if (mine) { parts.push(mine); }
      } else if (d.kind === 'host') {
        parts.push(d.address || d.label);
        var counts = [];
        if (d.confirmed) { counts.push(d.confirmed + ' confirmed'); }
        if (d.hypotheses) { counts.push(d.hypotheses + ' to verify'); }
        if (counts.length) { parts.push(counts.join(' · ')); }
      } else if (d.kind === 'gateway') {
        parts.push((internetVia.indexOf(id) >= 0 ? 'router ' : 'gateway ') + d.label);
      } else {
        parts.push(d.label);
      }
      return parts.join('\n');
    }
    function put(id, x, y, extra) {
      var d = data[id] || {};
      pos[id] = { x: x, y: y };
      classes[id] = [status(d)].concat(extra || []).join(' ');
      // Only devices carry a picture: not bars, labels or "+N more".
      var plain = (extra || []).some(function (c) { return c === 'bar' || c === 'more'; }) || d.kind === 'more';
      if (!plain) { d.icon = d.icon || iconFor(d); }
      placed[id] = true;
    }
    function wire(from, to, kind, color) {
      wires.push({ group: 'edges', data: { id: 'w:' + from + '>' + to, source: from, target: to, color: color || '#4a4f57' }, classes: kind || '' });
    }
    // A point on a bar right above or below `x`, so wires meet it upright.
    function anchor(bar, x, y) {
      var id = 'a:' + bar + ':' + Math.round(x);
      if (!pos[id]) {
        data[id] = { id: id, kind: 'anchor' };
        pos[id] = { x: x, y: y };
        classes[id] = 'anchor';
      }
      return id;
    }
    // Ids spread evenly around `cx` on one row.
    function spread(ids, cx, y, extra) {
      ids.forEach(function (id, i) { put(id, cx + (i - (ids.length - 1) / 2) * PITCH, y, extra); });
    }

    var internetVia = linked('internet', ['internet']);
    var networks = nodes.filter(function (n) { return n.data.kind === 'interface'; }).map(function (n) { return n.data.id; });
    function leadsOut(id) {
      return internetVia.indexOf(id) >= 0 || linked(id, ['gateway']).some(function (g) { return internetVia.indexOf(g) >= 0; });
    }
    networks.sort(function (a, b) {
      var ra = leadsOut(a) ? 0 : (data[a].link === 'vpn' ? 1 : (data[a].link === 'virtual' ? 3 : 2));
      var rb = leadsOut(b) ? 0 : (data[b].link === 'vpn' ? 1 : (data[b].link === 'virtual' ? 3 : 2));
      return ra - rb || (a < b ? -1 : 1);
    });
    var lost = linked('local', ['unknown']);

    // Lay the networks out left to right, each as wide as its widest row.
    var x = 0, youAt = null;
    networks.forEach(function (net, n) {
      var color = LINE[data[net].link] || LINE.other;
      var gateways = linked(net, ['gateway']).sort(bySeverity);
      var devices = linked(net, ['neighbour', 'direct']).filter(function (id) {
        return gateways.indexOf(id) < 0 && !placed[id];
      }).sort(bySeverity);
      var hidden = 0;
      if (devices.length > MAX_DEVICES && !expanded[net]) {
        devices.slice(MAX_DEVICES - 1).forEach(function (id) { placed[id] = true; });
        hidden = devices.length - (MAX_DEVICES - 1);
        devices = devices.slice(0, MAX_DEVICES - 1);
      }
      // You sit on the first network, at the right end of its first row,
      // next to the networks you also belong to.
      var row = devices.slice();
      if (n === 0) { row.splice(Math.min(row.length, PER_ROW - 1), 0, 'local'); }
      if (hidden) {
        var more = 'more:' + net;
        data[more] = { id: more, kind: 'more', label: '+' + hidden + ' more', caption: '+' + hidden + ' more' };
        row.push(more);
      } else if (devices.length >= MAX_DEVICES) {
        var fewer = 'more:' + net;
        data[fewer] = { id: fewer, kind: 'more', label: 'show fewer', caption: 'show fewer' };
        row.push(fewer);
      }
      var beyond = [];
      gateways.forEach(function (g) {
        if (internetVia.indexOf(g) >= 0 && !placed.internet && data.internet) { beyond.push('internet'); }
        linked(g, ['routed']).sort(bySeverity).forEach(function (h) { if (beyond.indexOf(h) < 0) { beyond.push(h); } });
      });
      var perRow = Math.min(Math.max(row.length, 1), PER_ROW);
      var stagger = row.length > PER_ROW ? 0.5 : 0;  // later rows sit between the ones above
      var width = (Math.max(perRow, gateways.length, beyond.length, 2) + stagger) * PITCH;
      var cx = x + width / 2;

      // The bar and its name.
      data[net].width = width - PITCH * 0.3;
      data[net].color = color;
      put(net, cx, Y_BAR, ['bar']);
      var title = 'title:' + net;
      data[title] = { id: title, kind: 'title', label: data[net].caption.replace('\n', '  ·  '), color: color };
      pos[title] = { x: x + PITCH * 0.15, y: Y_BAR };
      classes[title] = 'title';

      // Devices underneath, row by row.
      for (var r = 0; r * PER_ROW < row.length; r++) {
        var slice = row.slice(r * PER_ROW, (r + 1) * PER_ROW);
        // Rows after the first sit half a step over, so their wires up to
        // the bar pass between the devices above them.
        var shift = r % 2 === 1 ? PITCH / 2 : (stagger ? -PITCH / 4 : 0);
        spread(slice, cx + shift, Y_DEVICES + r * ROW, []);
        slice.forEach(function (id) {
          if (id === 'local') { classes[id] += ' you'; youAt = id; }
          if (id.indexOf('more:') === 0) { classes[id] = 'none more'; }
          wire(id, anchor(net, pos[id].x, Y_BAR));
        });
      }
      // Gateways above the bar, and what lies beyond them above that.
      spread(gateways, cx, Y_GATEWAY, []);
      gateways.forEach(function (g) { wire(g, anchor(net, pos[g].x, Y_BAR), 'uplink'); });
      spread(beyond, cx, Y_BEYOND, []);
      beyond.forEach(function (b) {
        if (b === 'internet') { classes[b] += ' internet'; }
        var via = gateways.filter(function (g) {
          return (b === 'internet' && internetVia.indexOf(g) >= 0) || linked(g, ['routed']).indexOf(b) >= 0;
        })[0];
        if (via) { wire(b, via, 'uplink'); }
      });
      x += width + GAP;
    });

    // Your own connection to every other network: a dashed line from you.
    if (!youAt) {
      put('local', x + PITCH / 2, Y_DEVICES, ['you']);
      x += PITCH + GAP;
    }
    networks.slice(youAt ? 1 : 0).forEach(function (net) {
      var left = pos[net].x - data[net].width / 2;
      wire('local', anchor(net, left + 4, Y_BAR), 'tunnel', data[net].color);
    });
    // Hosts this machine has no route to, in a group of their own.
    var rest = lost.concat(nodes.map(function (n) { return n.data.id; }))
      .filter(function (id, i, all) { return !placed[id] && all.indexOf(id) === i && data[id].kind !== 'anchor'; });
    if (rest.length) {
      var title2 = 'title:unknown';
      data[title2] = { id: title2, kind: 'title', label: 'Route not known', color: LINE.unknown };
      pos[title2] = { x: x + PITCH * 0.15, y: Y_BAR };
      classes[title2] = 'title';
      for (var k = 0; k * PER_ROW < rest.length; k++) {
        var part = rest.slice(k * PER_ROW, (k + 1) * PER_ROW);
        var w = Math.min(rest.length, PER_ROW) * PITCH;
        spread(part, x + w / 2, Y_DEVICES + k * ROW, []);
      }
    }

    Object.keys(pos).forEach(function (id) {
      var d = Object.assign({}, data[id]);
      d.text = d.kind === 'title' ? d.label : (texts[id] || (d.kind === 'more' ? d.label : caption(id)));
      elements.push({ group: 'nodes', data: d, classes: classes[id] });
    });
    return { elements: elements.concat(wires), positions: pos };
  }

  function renderGraph() {
    var key = JSON.stringify(state.topology) + JSON.stringify(expanded);
    if (key === drawn) { return; }
    drawn = key;
    var picture = plan(state.topology.nodes, state.topology.edges);
    cy.elements().remove();
    cy.add(picture.elements);
    cy.layout({
      name: 'preset', fit: true, padding: 40,
      positions: function (node) { return picture.positions[node.id()]; }
    }).run();
    if (selected && cy.$id(selected).length) { cy.$id(selected).select(); }
  }

  function renderLegend() {
    var legend = byId('legend');
    [['ok', 'nothing to check'], ['warn', 'to verify'], ['bad', 'confirmed'], ['none', 'not scanned']].forEach(function (key) {
      var item = legend.appendChild(el('span', 'item'));
      item.appendChild(el('span', 'dot ' + key[0]));
      item.appendChild(el('span', null, key[1]));
    });
    [['net', 'Wi-Fi / Ethernet', LINE.wifi], ['vpn', 'VPN', LINE.vpn], ['virtual', 'virtual', LINE.virtual]].forEach(function (key) {
      var item = legend.appendChild(el('span', 'item'));
      var bar = item.appendChild(el('span', 'bar'));
      bar.style.background = key[2];
      item.appendChild(el('span', null, key[1]));
    });
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
