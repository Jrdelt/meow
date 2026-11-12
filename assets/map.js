// meow topology map. Everything shown here comes from scanned systems, so
// text is only ever inserted with textContent, never as HTML.
(function () {
  'use strict';

  var token = new URLSearchParams(location.search).get('token') || '';
  var socket = null;
  var state = null;
  var selected = null;
  var drawn = '';

  // Layout distances, in map units (one unit is one pixel at zoom 1).
  var NODE_W = 84, NODE_H = 63;
  var COLUMN = 172;     // between a node and the tier it fans out to
  var SELF_UP = 46;     // room a node needs above its centre ...
  var SELF_DOWN = 96;   // ... and below it, caption included
  var BUS_PITCH = 124;  // between neighbours along a bus line
  var BUS_DROP = 88;    // from the bus line to the first row above and below it
  var ROW_PITCH = 130;  // between rows on the same side of a crowded bus
  // A riser leaves the bus line in the middle of the gap between two devices.
  var BUS_STUB = (BUS_PITCH - NODE_W) / 2;

  // Rows on each side of a bus line: more as the segment gets crowded, so
  // the drawing grows in both directions instead of into one long line.
  function busRows(devices) {
    return devices <= 10 ? 1 : (devices <= 28 ? 2 : 3);
  }

  // The map is drawn like a hand-sketched network diagram: an Internet cloud
  // on the left, then routers, firewalls, servers, network segments and
  // clients in tiers to the right. Which picture a node gets ("role") is
  // decided by the session, together with the reason for it.
  var INK = '#2e2e2e';
  var HAND = '"Chalkboard SE", "Bradley Hand", "Segoe Print", "Comic Sans MS", cursive';
  // role, how the legend names it, how the detail panel names it
  var ROLES = [
    ['internet', 'Internet (default route)', 'the Internet'],
    ['router', 'Router or gateway', 'a router'],
    ['firewall', 'Firewall', 'a firewall'],
    ['server', 'Server (offers a service)', 'a server'],
    ['segment', 'Network segment', 'a network segment'],
    ['switch', '', 'a switch'],
    ['client', 'Client (no service seen)', 'a client'],
    ['you', 'You (this machine)', 'you']
  ];
  // Order among siblings: this machine first, clients last.
  var RANK = { internet: -1, you: 0, router: 1, firewall: 2, segment: 3, 'switch': 4, server: 5, client: 6 };

  function icon(role) {
    return '/assets/icon-' + role + '.svg?token=' + encodeURIComponent(token);
  }

  var cy = cytoscape({
    container: document.getElementById('cy'),
    maxZoom: 1.6,
    minZoom: 0.15,
    style: [
      { selector: 'node', style: {
        'shape': 'round-rectangle', 'width': NODE_W, 'height': NODE_H,
        'background-opacity': 0, 'background-fit': 'contain', 'background-clip': 'none',
        'border-width': 0, 'border-color': INK,
        'label': 'data(text)', 'font-family': HAND, 'font-size': 14, 'color': INK, 'line-height': 1.1,
        'text-wrap': 'wrap', 'text-max-width': BUS_PITCH - 8, 'text-valign': 'bottom', 'text-margin-y': 2,
        'underlay-shape': 'ellipse', 'underlay-padding': 10, 'underlay-opacity': 0,
        'overlay-shape': 'round-rectangle', 'overlay-padding': 7, 'overlay-opacity': 0 } }
    ].concat(ROLES.map(function (role) {
      return { selector: 'node[role = "' + role[0] + '"]', style: { 'background-image': icon(role[0]) } };
    })).concat([
      { selector: 'node[role = "internet"]', style: {
        'width': 156, 'height': 104, 'font-size': 18, 'text-valign': 'center', 'text-margin-y': 2 } },
      { selector: 'node[role = "you"]', style: { 'font-size': 16 } },
      // Devices above a bus line carry their caption on top, clear of the line.
      { selector: 'node.above', style: { 'text-valign': 'top', 'text-margin-y': -3 } },
      // A marker-pen blot behind a host that has something to look at.
      { selector: 'node[hypotheses > 0]', style: { 'underlay-color': '#f2c14e', 'underlay-opacity': 0.6 } },
      { selector: 'node[confirmed > 0]', style: { 'underlay-color': '#e2574c', 'underlay-opacity': 0.55 } },
      { selector: 'node[?kev]', style: { 'border-width': 3, 'border-style': 'dashed', 'border-color': '#b83227' } },
      { selector: 'node[kind = "host"][!reachable]', style: { 'background-image-opacity': 0.5, 'color': '#8f6200' } },
      { selector: 'node:selected', style: { 'overlay-color': '#1f6fb2', 'overlay-opacity': 0.16 } },
      { selector: 'edge', style: {
        'width': 1.9, 'line-color': '#454545', 'line-cap': 'round',
        'curve-style': 'straight', 'target-arrow-shape': 'none' } },
      // A fan-out line is drawn freehand: very slightly S-shaped.
      { selector: 'edge.fan', style: {
        'curve-style': 'unbundled-bezier', 'control-point-distances': '5 -5', 'control-point-weights': '0.3 0.7' } },
      // Out of a bus: along the line, then a short riser into the device.
      { selector: 'edge.bus', style: {
        'curve-style': 'taxi', 'taxi-direction': 'rightward', 'taxi-turn': -BUS_STUB, 'taxi-turn-min-distance': 2 } },
      // The link to the Internet is the classic lightning bolt.
      { selector: 'edge[kind = "internet"]', style: {
        'curve-style': 'segments', 'segment-distances': '-13 13', 'segment-weights': '0.44 0.56', 'width': 2.1 } },
      { selector: 'edge.extra', style: { 'line-style': 'dashed', 'width': 1.2, 'line-color': '#8c8c8c' } },
      { selector: 'edge[kind = "unknown"]', style: { 'line-style': 'dotted', 'line-color': '#c9972c' } }
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
    byId('mode').textContent = state.mode;
    byId('mode').className = 'badge mode-' + state.mode;
    var hosts = Object.keys(state.graph.hosts);
    var advisories = 0;
    hosts.forEach(function (key) { advisories += state.graph.hosts[key].advisories.length; });
    byId('counts').textContent = hosts.length + ' hosts, ' + advisories + ' advisories';
    document.title = 'meow map: ' + state.session;
  }

  // Natural order for addresses: 10.0.0.9 before 10.0.0.10.
  function sortKey(data) {
    return String(data.address || data.label || data.id).replace(/\d+/g, function (digits) {
      return ('00000' + digits).slice(-6);
    });
  }

  // Turns the session's nodes and links into a drawing: a tree that grows
  // to the right from the Internet cloud (or from this machine when there is
  // no default route). A node with a few children fans out to the next tier;
  // a network segment lines its devices up above and below a bus line, the
  // way a hub is drawn, and whatever leads further sits at the end of it.
  function plan(nodes, edges) {
    var data = {}, links = {}, parent = {}, kids = {}, box = {}, pos = {}, above = {};
    nodes.forEach(function (node) { data[node.data.id] = node.data; links[node.data.id] = []; });
    edges.forEach(function (edge) {
      var link = edge.data;
      if (links[link.source] && links[link.target]) {
        links[link.source].push(link.target);
        links[link.target].push(link.source);
      }
    });
    function before(a, b) {
      var byRank = (RANK[data[a].role] || 0) - (RANK[data[b].role] || 0);
      if (byRank) { return byRank; }
      var ka = sortKey(data[a]), kb = sortKey(data[b]);
      return ka < kb ? -1 : (ka > kb ? 1 : 0);
    }

    // Breadth first, so every node sits as close to the root as its links allow.
    var root = data.internet ? 'internet' : 'local';
    var order = [root];
    parent[root] = null;
    for (var i = 0; i < order.length; i++) {
      var id = order[i];
      kids[id] = [];
      links[id].slice().sort(before).forEach(function (next) {
        if (!(next in parent)) {
          parent[next] = order[i];
          kids[order[i]].push(next);
          order.push(next);
        }
      });
    }
    nodes.forEach(function (node) {  // nothing links it to the rest
      if (!(node.data.id in parent)) {
        parent[node.data.id] = root;
        kids[root].push(node.data.id);
        kids[node.data.id] = [];
      }
    });

    // How much room each subtree needs above and below its own axis.
    function measure(id) {
      var leaves = [], branches = [];
      kids[id].forEach(function (kid) {
        measure(kid);
        (kids[kid].length ? branches : leaves).push(kid);
      });
      var bus = leaves.length >= 2 && (data[id].role === 'segment' || leaves.length > 3);
      var rows = busRows(leaves.length);
      var reach = BUS_DROP + (rows - 1) * ROW_PITCH + SELF_DOWN;
      var stack = bus ? branches : kids[id];
      var offsets = [], total = 0;
      stack.forEach(function (kid) {
        offsets.push(total + box[kid].up);
        total += box[kid].up + box[kid].down;
      });
      var axis = stack.length ? (offsets[0] + offsets[offsets.length - 1]) / 2 : 0;
      var big = data[id].role === 'internet';
      box[id] = {
        bus: bus, rows: rows, leaves: leaves, stack: stack, offsets: offsets, axis: axis,
        up: Math.max(bus ? reach : (big ? 70 : SELF_UP), axis),
        down: Math.max(bus ? reach : (big ? 70 : SELF_DOWN), total - axis)
      };
    }
    function place(id, x, y) {
      var b = box[id], next = x + COLUMN;
      pos[id] = { x: x, y: y };
      if (b.bus) {
        // Column by column, nearest row first, alternating above and below.
        var perColumn = b.rows * 2;
        b.leaves.forEach(function (leaf, n) {
          var slot = n % perColumn;
          var drop = BUS_DROP + Math.floor(slot / 2) * ROW_PITCH;
          above[leaf] = slot % 2 === 0;
          pos[leaf] = { x: x + BUS_PITCH * (Math.floor(n / perColumn) + 1), y: y + (above[leaf] ? -drop : drop) };
        });
        next = x + BUS_PITCH * (Math.ceil(b.leaves.length / perColumn) + 1);
      }
      b.stack.forEach(function (kid, n) { place(kid, next, y - b.axis + b.offsets[n]); });
    }
    measure(root);
    place(root, 0, 0);

    var elements = nodes.map(function (node) {
      var d = Object.assign({}, node.data);
      var lines = [d.caption || d.label];
      if (d.confirmed) { lines.push(d.confirmed + ' confirmed'); }
      if (d.hypotheses) { lines.push(d.hypotheses + ' to verify'); }
      if (d.kind === 'host' && !d.reachable) { lines.push(d.by_name ? 'address not known' : 'no route known'); }
      d.text = lines.join('\n');
      return { group: 'nodes', data: d, classes: above[d.id] ? 'above' : '' };
    });
    edges.forEach(function (edge) {
      var d = Object.assign({}, edge.data), kind = 'extra';
      if (parent[d.source] === d.target) {  // always drawn from parent to child
        var swap = d.source;
        d.source = d.target;
        d.target = swap;
      }
      if (parent[d.target] === d.source) { kind = box[d.source].bus ? 'bus' : 'fan'; }
      elements.push({ group: 'edges', data: d, classes: kind });
    });
    return { elements: elements, positions: pos };
  }

  function renderGraph() {
    var key = JSON.stringify(state.topology);
    if (key === drawn) { return; }
    drawn = key;
    var picture = plan(state.topology.nodes, state.topology.edges);
    cy.elements().remove();
    cy.add(picture.elements);
    cy.layout({
      name: 'preset', fit: true, padding: 30,
      positions: function (node) { return picture.positions[node.id()]; }
    }).run();
    if (selected) { cy.$id(selected).select(); }
  }

  function renderLegend() {
    var legend = byId('legend');
    ROLES.forEach(function (role) {
      if (!role[1]) { return; }
      var item = legend.appendChild(el('span', 'item'));
      var picture = item.appendChild(el('img'));
      picture.src = icon(role[0]);
      picture.alt = '';
      item.appendChild(el('span', null, role[1]));
    });
    [['verify', 'to verify'], ['confirmed', 'confirmed'], ['kev', 'known exploited']].forEach(function (key) {
      var item = legend.appendChild(el('span', 'item'));
      item.appendChild(el('span', 'swatch ' + key[0]));
      item.appendChild(el('span', null, key[1]));
    });
  }

  // Why a node is drawn the way it is. A hint, not a finding.
  function drawnAs(data) {
    var name = '';
    ROLES.forEach(function (role) { if (role[0] === data.role) { name = role[2]; } });
    return el('div', 'dim drawn', name ? 'Shown as ' + name + ': ' + data.why + '.' : '');
  }

  function renderList(target, items, empty, build) {
    clear(target);
    if (!items.length) { target.appendChild(el('li', 'dim', empty)); }
    items.forEach(function (item) { target.appendChild(build(item)); });
  }

  // "This machine": the local connection, any VPN, and every table the
  // session read from the operating system. The first sections are always
  // in view; the long tables unfold on a click and stay as they were left.
  var machineDrawn = '';
  var unfolded = {};

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
    machine.sections.forEach(function (section) {
      var name = section.title.replace(/ \(\d+\)$/, '');
      var lines = section.lines.map(function (line) {
        return el('div', name === 'Route warnings' ? 'warn-text' : 'mono', line);
      });
      if (section.open) {
        box.appendChild(el('h3', null, section.title));
        lines.forEach(function (line) { box.appendChild(line); });
        return;
      }
      var fold = box.appendChild(el('details'));
      fold.open = !!unfolded[name];
      fold.appendChild(el('summary', null, section.title));
      lines.forEach(function (line) { fold.appendChild(line); });
      fold.addEventListener('toggle', function () { unfolded[name] = fold.open; });
    });
    if (machine.observed_utc) {
      box.appendChild(el('div', 'dim', 'Read from this machine at ' + machine.observed_utc.slice(11, 19) +
        ' UTC. Nothing was sent to find this out.'));
    }
  }

  function renderSide() {
    renderMachine();

    renderList(byId('tasks'), state.tasks || [], 'No recon tasks yet.', function (task) {
      var item = el('li');
      item.appendChild(el('span', 'mono', 'recon ' + task.target + ' '));
      task.stages.forEach(function (stage) {
        var kind = { done: 'ok', running: 'warn', failed: 'bad', interrupted: 'bad' }[stage.status] || '';
        var badge = el('span', 'badge ' + kind, stage.stage + ': ' + stage.status);
        badge.title = stage.detail || '';
        item.appendChild(badge);
        item.appendChild(document.createTextNode(' '));
      });
      return item;
    });

    var notices = (state.notices || []).slice(-25).reverse();
    renderList(byId('notices'), notices, 'Nothing yet.', function (notice) {
      var item = el('li');
      item.appendChild(el('span', 'dim mono', notice.at.slice(11, 19) + ' '));
      item.appendChild(document.createTextNode(notice.text));
      return item;
    });
  }

  function pathTree(node, budget) {
    var list = el('ul', 'tree mono');
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

  function advisoryCard(address, advisory) {
    var card = el('div', 'card');
    var head = card.appendChild(el('div', 'head'));
    head.appendChild(el('strong', 'mono', advisory.id));
    if (advisory.severity) { head.appendChild(el('span', 'badge', advisory.severity)); }
    if (advisory.kev) { head.appendChild(el('span', 'badge bad', 'CISA KEV')); }
    var status = advisory.verification_status;
    var kind = status === 'Confirmed' ? 'bad' : (status === 'FalsePositive' ? 'ok' : 'warn');
    head.appendChild(el('span', 'badge ' + kind, status));
    card.appendChild(el('div', null, advisory.title));
    card.appendChild(el('div', 'dim mono', (advisory.port ? advisory.port + '  ' : '') + advisory.matched));

    var checks = ((state.checklists[address] || {})[advisory.id] || {});
    var list = card.appendChild(el('ul'));
    (checks.items || []).forEach(function (check) {
      var item = el('li', check.done ? 'done' : 'todo', (check.done ? '[x] ' : '[ ] ') + check.label);
      item.appendChild(el('span', 'dim', ' ' + check.detail));
      list.appendChild(item);
    });
    if (checks.research_ready && status === 'UnverifiedHypothesis') {
      card.appendChild(el('div', 'badge ok', '[R] Deep Research Ready'));
    }

    var actions = card.appendChild(el('div', 'actions'));
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
    return card;
  }

  function factItem(fact) {
    var item = el('li');
    item.appendChild(document.createTextNode(fact.claim + ' '));
    item.appendChild(el('span', 'dim mono', fact.source + ' / ' + fact.confidence + ' / ' + fact.verification_status));
    return item;
  }

  function renderHost(detail, host) {
    byId('detail-title').textContent = host.address;
    var names = (host.hostnames || []).join(', ');
    if (names) { detail.appendChild(el('div', 'mono', names)); }
    if (host.os) { detail.appendChild(el('div', 'dim', host.os)); }

    detail.appendChild(el('h3', null, 'Ports'));
    var ports = detail.appendChild(el('ul', 'mono'));
    Object.keys(host.ports).forEach(function (key) {
      var port = host.ports[key];
      var text = [key, port.state, port.service, port.product, port.version].filter(Boolean).join(' ');
      var item = ports.appendChild(el('li', port.state === 'open' ? null : 'dim', text));
      if (port.http && port.http.server) { item.appendChild(el('div', 'dim', 'Server: ' + port.http.server)); }
      if ((port.tls_sans || []).length) { item.appendChild(el('div', 'dim', 'SAN: ' + port.tls_sans.join(', '))); }
      if (port.paths && port.paths.children && Object.keys(port.paths.children).length) {
        item.appendChild(pathTree(port.paths, { left: 300 }));
      }
    });
    if (!Object.keys(host.ports).length) { ports.appendChild(el('li', 'dim', 'none seen')); }

    detail.appendChild(el('h3', null, 'Hypotheses and findings'));
    if (!host.advisories.length) { detail.appendChild(el('div', 'dim', 'No advisories matched.')); }
    // Known-exploited first, then by severity score.
    var ordered = host.advisories.slice().sort(function (a, b) {
      return (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || (b.cvss || 0) - (a.cvss || 0);
    });
    ordered.slice(0, 60).forEach(function (advisory) {
      detail.appendChild(advisoryCard(host.address, advisory));
    });
    if (ordered.length > 60) {
      detail.appendChild(el('div', 'dim', (ordered.length - 60) + ' more not shown; see `meow hud` or the report.'));
    }

    detail.appendChild(el('h3', null, 'Ask AI'));
    var ready = Object.keys(state.checklists[host.address] || {}).some(function (id) {
      return state.checklists[host.address][id].research_ready;
    });
    var ask = detail.appendChild(el('div', 'actions'));
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
      detail.appendChild(el('div', 'dim', 'Cloud today: $' + (budget.spent_usd || 0).toFixed(4) + ' of $' +
        (budget.max_usd || 0).toFixed(2) + ', ' + (budget.calls || 0) + ' of ' + (budget.max_calls || 0) + ' calls'));
    } else {
      detail.appendChild(el('div', 'dim', 'No OpenRouter key in this session: [C] answers with the local model ' +
        'and [R] is unavailable. Leave the session, run `export OPENROUTER_API_KEY=...`, then start it again.'));
    }
    var ai = state.ai || {};
    if (ai.address === host.address && (ai.running || ai.text || ai.error)) {
      var reply = detail.appendChild(el('div', 'card'));
      reply.appendChild(el('div', 'dim', ai.running ? 'Running ...' : (ai.summary || '')));
      reply.appendChild(el('pre', 'reply', ai.text || ''));
      if (ai.error) { reply.appendChild(el('div', 'bad-text', ai.error)); }
    }

    detail.appendChild(el('h3', null, 'Evidence'));
    var facts = detail.appendChild(el('ul'));
    (host.facts || []).forEach(function (fact) { facts.appendChild(factItem(fact)); });
    Object.keys(host.ports).forEach(function (key) {
      (host.ports[key].facts || []).forEach(function (fact) { facts.appendChild(factItem(fact)); });
    });

    detail.appendChild(el('h3', null, 'Add a note'));
    var box = detail.appendChild(el('textarea'));
    box.placeholder = 'What you found by hand: credentials tried, versions seen, pkg:npm/name@1.2.3 ...';
    var save = detail.appendChild(el('div', 'actions')).appendChild(el('button', null, 'Save note'));
    save.addEventListener('click', function () {
      if (box.value.trim()) {
        send({ cmd: 'note', address: host.address, text: box.value });
        box.value = '';
      }
    });
  }

  function renderDetail() {
    var detail = byId('detail');
    // Keep a half-written note when the state refreshes.
    var draft = detail.querySelector('textarea');
    var draftText = draft ? draft.value : '';
    var hadFocus = draft && document.activeElement === draft;
    clear(detail);
    var node = selected ? cy.$id(selected) : null;
    if (!node || node.empty()) {
      byId('detail-title').textContent = 'Select a node';
      detail.appendChild(el('div', 'dim', 'Click a host to see its ports, paths, evidence and hypotheses.'));
      return;
    }
    var data = node.data();
    var host = data.address ? state.graph.hosts[data.address] : null;
    if (host) {
      renderHost(detail, host);
      detail.insertBefore(drawnAs(data), detail.firstChild);
      var box = detail.querySelector('textarea');
      if (box && draftText) { box.value = draftText; }
      if (box && hadFocus) { box.focus(); }
      return;
    }
    byId('detail-title').textContent = data.label;
    detail.appendChild(drawnAs(data));
    if (data.kind === 'interface') {
      var name = data.id.slice(3);
      if (data.network) { detail.appendChild(el('div', 'mono', 'network ' + data.network)); }
      (state.graph.local.interfaces || []).forEach(function (iface) {
        if (iface.name !== name) { return; }
        detail.appendChild(el('div', 'mono', iface.kind + (iface.up ? ', up' : ', down')));
        iface.addresses.forEach(function (address) { detail.appendChild(el('div', 'mono', 'this machine: ' + address)); });
      });
      if (data.hidden_neighbours) {
        detail.appendChild(el('div', 'dim', data.hidden_neighbours + ' more devices in the neighbour table are not drawn.'));
      }
    } else if (data.kind === 'neighbour') {
      detail.appendChild(el('div', 'mono', 'hardware address ' + data.mac));
      detail.appendChild(el('div', 'mono', 'seen on ' + data.interface));
      detail.appendChild(el('div', 'dim', 'It becomes a host once a scan, an imported file or the terminal output mentions it.'));
    } else if (data.kind === 'internet') {
      detail.appendChild(el('div', 'dim', 'meow has sent nothing there to find this out.'));
    }
  }

  function render() {
    renderHeader();
    renderGraph();
    renderSide();
    renderDetail();
  }

  cy.on('tap', 'node', function (event) {
    selected = event.target.id();
    renderDetail();
  });
  cy.on('tap', function (event) {
    if (event.target === cy) {
      selected = null;
      renderDetail();
    }
  });

  renderLegend();
  connect();
})();
