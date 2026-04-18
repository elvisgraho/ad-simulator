import { log } from './logger.js';
import { state, stepDelay } from './state.js';

export const initialElements = [
  { data: { id: 'dc01', name: 'DC01', type: 'dc', fqdn: 'dc01.corp.local', ip: '10.1.1.10' }, classes: 'cy-node cy-node-dc high-value', position: { x: 450, y: 100 } },
  { data: { id: 'ca01', name: 'CA01', type: 'ca', fqdn: 'ca01.corp.local', ip: '10.1.1.20' }, classes: 'cy-node cy-node-ca', position: { x: 600, y: 150 } },
  { data: { id: 'srv_web01', name: 'SRV-WEB-01', type: 'server', fqdn: 'srv-web-01.corp.local', ip: '10.1.5.20', spns: ['HTTP/srv-web-01.corp.local'] }, classes: 'cy-node cy-node-server', position: { x: 750, y: 250 } },
  { data: { id: 'srv_app01', name: 'SRV-APP-01', type: 'server', fqdn: 'srv-app-01.corp.local', ip: '10.1.5.30', unconstrained_delegation: true }, classes: 'cy-node cy-node-server delegation-unconstrained', position: { x: 750, y: 350 } },
  { data: { id: 'srv_sql01', name: 'SQL01', type: 'server', fqdn: 'sql01.corp.local', ip: '10.1.5.10' }, classes: 'cy-node cy-node-server', position: { x: 750, y: 450 } },
  { data: { id: 'srv_files01', name: 'FILES01', type: 'server', fqdn: 'files01.corp.local', ip: '10.1.5.40' }, classes: 'cy-node cy-node-server', position: { x: 750, y: 550 } },
  { data: { id: 'svc_sql01', name: 'svc_sql01', type: 'svc', sam: 'CORP\\svc_sql01', spns: ['MSSQLSvc/sql01.corp.local:1433'], ip: '10.1.5.10', ntlm_hash: 'SqlSvcHash1' }, classes: 'cy-node cy-node-svc', position: { x: 550, y: 400 } },
  { data: { id: 'svc_nopreauth', name: 'svc_nopreauth', type: 'svc', sam: 'CORP\\svc_nopreauth', no_preauth: true, ip: '10.1.5.11', ntlm_hash: 'NoPreauthHash' }, classes: 'cy-node cy-node-svc', position: { x: 550, y: 600 } },
  { data: { id: 'host1', name: 'WKSTN-01', type: 'host', fqdn: 'wkstn-01.corp.local', ip: '10.1.10.101' }, classes: 'cy-node cy-node-host', position: { x: 100, y: 450 } },
  { data: { id: 'host2', name: 'WKSTN-02', type: 'host', fqdn: 'wkstn-02.corp.local', ip: '10.1.10.102' }, classes: 'cy-node cy-node-host', position: { x: 350, y: 450 } },
  { data: { id: 'user1', name: 'Alice', type: 'user', sam: 'CORP\\Alice', ip: '10.1.10.50', ntlm_hash: 'AliceHash' }, classes: 'cy-node cy-node-user', position: { x: 100, y: 550 } },
  { data: { id: 'user2', name: 'Bob', type: 'user', sam: 'CORP\\Bob', ip: '10.1.10.51', ntlm_hash: 'BobHash' }, classes: 'cy-node cy-node-user', position: { x: 350, y: 550 } },
  { data: { id: 'admin1', name: 'DomainAdmin', type: 'admin', sam: 'CORP\\DomainAdmin', ip: '10.1.1.5', ntlm_hash: 'DAHash' }, classes: 'cy-node cy-node-admin high-value', position: { x: 225, y: 100 } },
  { data: { id: 'attacker', name: 'Attacker', type: 'attacker', ip: '192.168.1.100' }, classes: 'cy-node cy-node-attacker', position: { x: 200, y: 300 } },
  { data: { id: 'krbtgt', name: 'krbtgt', type: 'svc', sam: 'CORP\\krbtgt', ntlm_hash: 'KRBTGT_HASH_SECRET' }, classes: 'cy-node cy-node-svc high-value', style: { display: 'none' } },
];

export function initializeCytoscape(elements) {
  if (state.cy) state.cy.destroy();

  state.cy = cytoscape({
    container: document.getElementById('cy'),
    elements: JSON.parse(JSON.stringify(elements)),
    style: [
      {
        selector: 'node',
        style: {
          width: '60px', height: '60px',
          'background-color': '#2d2d30',
          'border-width': 2, 'border-color': '#555',
          label: (ele) => {
            const detail = ele.data('fqdn') || ele.data('sam') || '';
            const icons = { dc: '💾', ca: '📜', user: '👤', admin: '👑', svc: '⚙️', host: '💻', server: '🏢', attacker: '💀' };
            return `${icons[ele.data('type')] || '❓'}\n${detail}`;
          },
          'text-wrap': 'wrap', 'text-max-width': '80px', 'text-margin-y': 20,
          'font-size': '18px', color: '#cccccc',
          'text-outline-color': '#181818', 'text-outline-width': 2,
          'line-height': 1.1, padding: '0px',
          'text-valign': 'center', 'text-halign': 'center',
        },
      },
      { selector: '.cy-node-dc',       style: { 'background-color': '#0d2847', 'border-color': '#569cd6' } },
      { selector: '.cy-node-ca',       style: { 'background-color': '#2d2200', 'border-color': '#dcdcaa' } },
      { selector: '.cy-node-user',     style: { 'background-color': '#0d2117', 'border-color': '#4ec9b0' } },
      { selector: '.cy-node-admin',    style: { 'background-color': '#2d0808', 'border-color': '#f44747' } },
      { selector: '.cy-node-svc',      style: { 'background-color': '#252526', 'border-color': '#6e6e6e' } },
      { selector: '.cy-node-host',     style: { 'background-color': '#002728', 'border-color': '#0dcaf0' } },
      { selector: '.cy-node-server',   style: { 'background-color': '#1e1033', 'border-color': '#c586c0' } },
      { selector: '.cy-node-attacker', style: { 'background-color': '#2d0000', 'border-color': '#e03131' } },
      {
        selector: 'node.highlighted',
        style: { 'border-color': '#dcdcaa', 'border-width': 4, shape: 'ellipse', 'background-color': '#2d2900' },
      },
      {
        selector: 'node.compromised',
        style: { 'background-color': '#2d0000', 'border-color': '#e03131', 'border-width': 4, 'border-style': 'dashed', shape: 'octagon' },
      },
      { selector: '.delegation-unconstrained', style: { 'border-style': 'dotted', 'border-width': 3, 'border-color': '#6f42c1' } },
      { selector: '.delegation-constrained',   style: { 'border-style': 'dotted', 'border-width': 3, 'border-color': '#0dcaf0' } },
      { selector: '.high-value', style: { shape: 'star' } },
      {
        selector: 'edge',
        style: {
          width: 1.5, 'line-color': '#adb5bd',
          'target-arrow-shape': 'triangle', 'target-arrow-color': '#adb5bd',
          'curve-style': 'bezier', label: 'data(label)',
          'font-size': '18px', color: '#cccccc', 'text-rotation': 'autorotate',
          'text-background-color': '#1e1e1e', 'text-background-opacity': 0.9,
          'text-background-padding': '1px', 'text-background-shape': 'roundrectangle',
        },
      },
      { selector: '.kerberos-edge', style: { 'line-color': '#4dabf7', 'target-arrow-color': '#4dabf7', width: 2.5, 'z-index': 10 } },
      { selector: '.ldap-edge',     style: { 'line-color': '#ffec99', 'target-arrow-color': '#ffec99', width: 2.5, 'line-style': 'dashed', 'z-index': 10 } },
      { selector: '.drsuapi-edge',  style: { 'line-color': '#ff8787', 'target-arrow-color': '#ff8787', width: 3,   'line-style': 'dotted', 'z-index': 11 } },
      { selector: '.rpc-edge',      style: { 'line-color': '#fcc2d7', 'target-arrow-color': '#fcc2d7', width: 2,   'line-style': 'dotted', 'z-index': 9  } },
      { selector: '.smb-edge',      style: { 'line-color': '#ffa94d', 'target-arrow-color': '#ffa94d', width: 2.5, 'line-style': 'dashed', 'z-index': 9  } },
      { selector: '.ntlm-edge',     style: { 'line-color': '#f783ac', 'target-arrow-color': '#f783ac', width: 2.5, 'line-style': 'dashed', 'z-index': 10 } },
      { selector: '.dns-edge',      style: { 'line-color': '#b197fc', 'target-arrow-color': '#b197fc', width: 2,   'line-style': 'dotted', 'z-index': 8  } },
      { selector: '.http-edge',     style: { 'line-color': '#63e6be', 'target-arrow-color': '#63e6be', width: 2,                           'z-index': 8  } },
      { selector: '.attack-flow',   style: { 'line-color': '#e03131', 'target-arrow-color': '#e03131', width: 3,                           'z-index': 12 } },
      { selector: '.temp-edge',     style: { opacity: 0.9 } },
    ],
    layout: { name: 'preset' },
  });

  state.cy.on('mouseover', 'node', (e) => e.target.addClass('highlighted'));
  state.cy.on('mouseout', 'node', (e) => {
    if (!e.target.hasClass('compromised') && !e.target.scratch('_sim_highlighted')) {
      e.target.removeClass('highlighted');
    }
  });
  state.cy.nodes().grabify();
}

export function highlightElement(id, duration = stepDelay * 0.8, className = 'highlighted') {
  const ele = state.cy?.getElementById(id);
  if (ele?.length > 0) {
    ele.addClass(className);
    if (className === 'highlighted') {
      ele.scratch('_sim_highlighted', true);
      setTimeout(() => {
        const el = state.cy?.getElementById(id);
        if (el?.length > 0 && el.scratch('_sim_highlighted')) {
          el.removeClass(className);
          el.removeScratch('_sim_highlighted');
        }
      }, duration);
    }
  } else {
    console.warn(`Highlight target not found: ${id}`);
    log(`Warn: Cannot highlight missing element ${id}`, 'fail');
  }
}

export function addTemporaryEdge(sourceId, targetId, protocol, label = '', duration = stepDelay * 0.9) {
  const edgeClass = `temp-edge ${protocol.toLowerCase()}-edge`;
  const edgeId = `temp-${sourceId}-${targetId}-${Date.now()}-${Math.random().toString(16).substring(2)}`;
  const src = state.cy?.getElementById(sourceId);
  const tgt = state.cy?.getElementById(targetId);

  if (!src?.length) { log(`Error: Source node ${sourceId} not found.`, 'fail'); return null; }
  if (!tgt?.length) { log(`Error: Target node ${targetId} not found.`, 'fail'); return null; }

  try {
    const edge = state.cy.add({
      group: 'edges',
      data: { id: edgeId, source: sourceId, target: targetId, label: label || protocol.toUpperCase() },
      classes: edgeClass,
    });
    if (!state.isManualMode) {
      setTimeout(() => {
        try { const e = state.cy?.getElementById(edgeId); if (e?.length) state.cy.remove(e); } catch (_) {}
      }, duration);
    } else {
      state.manualStepEdges.push(edgeId);
    }
    return edge;
  } catch (err) {
    console.error(`Error adding edge ${edgeId}:`, err);
    log(`Error visualizing: ${sourceId} -> ${targetId} (${protocol})`, 'fail');
    return null;
  }
}
