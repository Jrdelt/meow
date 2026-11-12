// meow topology map. Everything shown here comes from scanned systems, so
// text is only ever inserted with textContent, never as HTML.
(function () {
  'use strict';

  var token = new URLSearchParams(location.search).get('token') || '';
  var socket = null;
  var state = null;
  var selected = null;
  var drawn = '';

  var cy = cytoscape({
    container: document.getElementById('cy'),
    maxZoom: 1.8,
    style: [
      { selector: 'node', style: {
        'label': 'data(label)', 'color': '#d7dde8', 'font-size': 11, 'text-valign': 'bottom',
        'text-margin-y': 6, 'text-wrap': 'wrap', 'text-max-width': 150,
        'background-color': '#4a5568', 'width': 34, 'height': 34, 'border-width': 2, 'border-color': '#2c3545' } },
      { selector: 'node[kind = "local"]', style: { 'shape': 'round-rectangle', 'background-color': '#6cb6ff', 'width': 46, 'height': 30 } },
      { selector: 'node[kind = "interface"]', style: { 'shape': 'diamond', 'background-color': '#7f8ea3' } },
      { selector: 'node[kind = "gateway"]', style: { 'shape': 'hexagon', 'background-color': '#9f7aea' } },
      { selector: 'node[kind = "host"]', style: { 'background-color': '#3b8f6b' } },
      { selector: 'node[kind = "host"][hypotheses > 0]', style: { 'background-color': '#c9972c' } },
      { selector: 'node[kind = "host"][confirmed > 0]', style: { 'background-color': '#c0392b' } },
      { selector: 'node[?kev]', style: { 'border-color': '#ff6b6b', 'border-width': 4 } },
      { selector: 'node[kind = "host"][!reachable]', style: { 'border-style': 'dashed', 'border-color': '#f2c14e' } },
      { selector: 'node:selected', style: { 'border-color': '#ffffff', 'border-width': 4 } },
      { selector: 'edge', style: {
        'width': 1.5, 'line-color': '#3b475c', 'target-arrow-color': '#3b475c',
        'target-arrow-shape': 'triangle', 'curve-style': 'bezier' } },
      { selector: 'edge[kind = "routed"]', style: { 'line-style': 'dashed' } },
      { selector: 'edge[kind = "unknown"]', style: {
        'line-style': 'dotted', 'line-color': '#f2c14e', 'target-arrow-shape': 'none', 'opacity': 0.5 } }
    ]
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

  function renderGraph() {
    var elements = state.topology.nodes.concat(state.topology.edges);
    var key = JSON.stringify(elements);
    if (key === drawn) { return; }
    var firstDraw = drawn === '';
    drawn = key;
    cy.elements().remove();
    cy.add(elements);
    cy.layout({
      name: 'breadthfirst', directed: true, roots: cy.$id('local'),
      padding: 40, spacingFactor: 1.15, animate: !firstDraw, animationDuration: 250
    }).run();
    if (selected) { cy.$id(selected).select(); }
  }

  function renderList(target, items, empty, build) {
    clear(target);
    if (!items.length) { target.appendChild(el('li', 'dim', empty)); }
    items.forEach(function (item) { target.appendChild(build(item)); });
  }

  function renderSide() {
    var warnings = state.graph.local.warnings || [];
    byId('warnings').hidden = warnings.length === 0;
    renderList(byId('warning-list'), warnings, '', function (text) { return el('li', null, text); });

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
      var box = detail.querySelector('textarea');
      if (box && draftText) { box.value = draftText; }
      if (box && hadFocus) { box.focus(); }
      return;
    }
    byId('detail-title').textContent = data.label;
    if (data.kind === 'interface') {
      var name = data.id.slice(3);
      (state.graph.local.interfaces || []).forEach(function (iface) {
        if (iface.name !== name) { return; }
        detail.appendChild(el('div', 'mono', iface.kind + (iface.up ? ', up' : ', down')));
        iface.addresses.forEach(function (address) { detail.appendChild(el('div', 'mono', address)); });
      });
    } else {
      detail.appendChild(el('div', 'dim', data.kind));
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

  connect();
})();
