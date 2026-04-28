import { log } from './logger.js';
import { state, stepDelay } from './state.js';

function svgIcon(innerPaths) {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" preserveAspectRatio="xMidYMid meet" fill="none" stroke-linecap="round" stroke-linejoin="round">${innerPaths}</svg>`
  )}`;
}

function paddedSvgIcon(innerPaths) {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32" preserveAspectRatio="xMidYMid meet" fill="none" stroke-linecap="round" stroke-linejoin="round">${innerPaths}</svg>`
  )}`;
}

function protocolToEdgeClass(protocol) {
  const normalized = String(protocol || '').trim().toLowerCase();
  const aliasMap = [
    [/^attack-flow$/, 'attack-flow-edge'],
    [/sync/, 'sync-edge'],
    [/saml/, 'saml-edge'],
    [/pta/, 'pta-edge'],
    [/oidc/, 'oidc-edge'],
    [/^prt$/, 'prt-edge'],
    [/^tpm$/, 'tpm-edge'],
    [/msgraph/, 'msgraph-edge'],
    [/imds/, 'imds-edge'],
    [/azurerm/, 'azurerm-edge'],
    [/drsuapi/, 'drsuapi-edge'],
    [/kerberos/, 'kerberos-edge'],
    [/ldap/, 'ldap-edge'],
    [/ntlm/, 'ntlm-edge'],
    [/dns/, 'dns-edge'],
    [/(llmnr|nbt-?ns)/, 'dns-edge'],
    [/(rpc|samr|nrpc|rprn|efsrpc|wmi|dcom)/, 'rpc-edge'],
    [/\bsmb\b/, 'smb-edge'],
    [/(http|session|trigger|sql|tds|db access|auth)/, 'http-edge'],
  ];

  for (const [pattern, edgeClass] of aliasMap) {
    if (pattern.test(normalized)) return edgeClass;
  }

  const slug = normalized.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return slug ? `${slug}-edge` : 'edge';
}

const NODE_ICONS = {
  dc: paddedSvgIcon(`
    <rect x="8" y="7.5" width="16" height="4" rx="1" stroke="#569cd6" stroke-width="1.5"/>
    <rect x="8" y="14" width="16" height="4" rx="1" stroke="#569cd6" stroke-width="1.5"/>
    <rect x="8" y="20.5" width="16" height="4" rx="1" stroke="#569cd6" stroke-width="1.5"/>
    <circle cx="20.5" cy="9.5" r="0.9" fill="#569cd6"/>
    <circle cx="20.5" cy="16" r="0.9" fill="#569cd6"/>
    <circle cx="20.5" cy="22.5" r="0.9" fill="#569cd6"/>`),

  ca: svgIcon(`
    <path d="M12 2L4 5v6c0 5.5 3.5 10.5 8 12 4.5-1.5 8-6.5 8-12V5L12 2z" stroke="#dcdcaa" stroke-width="1.5"/>
    <path d="M9 12l2 2 4-4" stroke="#dcdcaa" stroke-width="1.5"/>`),

  user: svgIcon(`
    <circle cx="12" cy="8" r="4" stroke="#4ec9b0" stroke-width="1.5"/>
    <path d="M4 20c0-4 3.6-7 8-7s8 3 8 7" stroke="#4ec9b0" stroke-width="1.5"/>`),

  admin: svgIcon(`
    <circle cx="12" cy="11" r="3.5" stroke="#f44747" stroke-width="1.5"/>
    <path d="M5 21c0-3.5 3.1-6 7-6s7 2.5 7 6" stroke="#f44747" stroke-width="1.5"/>
    <path d="M5 5.5l2.5 3.5L12 3.5l4.5 5.5L19 5.5V8H5z" fill="#f44747"/>`),

  svc: svgIcon(`
    <circle cx="12" cy="12" r="3" stroke="#9e9e9e" stroke-width="1.5"/>
    <path d="M12 2v2.5M12 19.5V22M4.22 4.22l1.77 1.77M18.01 18.01l1.77 1.77M2 12h2.5M19.5 12H22M4.22 19.78l1.77-1.77M18.01 5.99l1.77-1.77" stroke="#9e9e9e" stroke-width="1.5"/>`),

  host: svgIcon(`
    <rect x="3" y="4" width="18" height="13" rx="1" stroke="#0dcaf0" stroke-width="1.5"/>
    <path d="M3 21h18" stroke="#0dcaf0" stroke-width="1.5"/>
    <line x1="12" y1="17" x2="12" y2="21" stroke="#0dcaf0" stroke-width="1.5"/>`),

  server: svgIcon(`
    <rect x="4" y="2" width="16" height="9" rx="1" stroke="#c586c0" stroke-width="1.5"/>
    <rect x="4" y="13" width="16" height="9" rx="1" stroke="#c586c0" stroke-width="1.5"/>
    <circle cx="7.5" cy="6.5" r="1" fill="#c586c0"/>
    <circle cx="7.5" cy="17.5" r="1" fill="#c586c0"/>
    <line x1="11" y1="6.5" x2="17" y2="6.5" stroke="#c586c0" stroke-width="1.5"/>
    <line x1="11" y1="17.5" x2="17" y2="17.5" stroke="#c586c0" stroke-width="1.5"/>`),

  attacker: svgIcon(`
    <path d="M12 3a8 8 0 0 1 8 8c0 2.8-1.4 5.3-3.5 6.8v2.2a1 1 0 0 1-1 1H8.5a1 1 0 0 1-1-1v-2.2C5.4 16.3 4 13.8 4 11a8 8 0 0 1 8-8z" stroke="#e03131" stroke-width="1.5"/>
    <circle cx="9.5" cy="11" r="1.5" fill="#e03131"/>
    <circle cx="14.5" cy="11" r="1.5" fill="#e03131"/>
    <path d="M9 20h2v-2.5h2V20h2" stroke="#e03131" stroke-width="1.5"/>`),

  // ── Entra ID node types ──
  entra: paddedSvgIcon(`
    <rect x="10" y="13" width="12" height="10" rx="1.8" stroke="#0078d4" stroke-width="1.5" fill="none"/>
    <path d="M12 13v-3.5a4 4 0 0 1 8 0v3.5" stroke="#0078d4" stroke-width="1.5" fill="none"/>
    <circle cx="16" cy="18" r="1.4" fill="#0078d4"/>`),

  entrauser: svgIcon(`
    <circle cx="12" cy="8" r="4" stroke="#50b4e8" stroke-width="1.5" fill="none"/>
    <path d="M4 20c0-4 3.6-7 8-7s8 3 8 7" stroke="#50b4e8" stroke-width="1.5" fill="none"/>
    <path d="M17 3a3 3 0 0 1 3 3" stroke="#50b4e8" stroke-width="1.2" fill="none"/>`),

  entraadmin: svgIcon(`
    <circle cx="12" cy="11" r="3.5" stroke="#ff8c00" stroke-width="1.5" fill="none"/>
    <path d="M5 21c0-3.5 3.1-6 7-6s7 2.5 7 6" stroke="#ff8c00" stroke-width="1.5" fill="none"/>
    <path d="M8.5 4.5h7l.5 2.5-4 3-4-3 .5-2.5z" stroke="#ff8c00" stroke-width="1.5" fill="none"/>`),

  entradevice: svgIcon(`
    <rect x="3" y="4" width="18" height="13" rx="1" stroke="#50e6ff" stroke-width="1.5" fill="none"/>
    <path d="M3 21h18" stroke="#50e6ff" stroke-width="1.5"/>
    <line x1="12" y1="17" x2="12" y2="21" stroke="#50e6ff" stroke-width="1.5"/>
    <path d="M9 11l2 2 4-4" stroke="#50e6ff" stroke-width="1.5"/>`),

  entrasvc: svgIcon(`
    <rect x="3" y="3" width="18" height="18" rx="2" stroke="#8764b8" stroke-width="1.5" fill="none"/>
    <path d="M3 9h18" stroke="#8764b8" stroke-width="1.5"/>
    <circle cx="7" cy="6" r="1" fill="#8764b8"/>
    <circle cx="10" cy="6" r="1" fill="#8764b8"/>
    <path d="M8 14l2 2 4-4" stroke="#8764b8" stroke-width="1.5"/>`),

  entrami: svgIcon(`
    <rect x="5" y="8" width="14" height="11" rx="2" stroke="#00b294" stroke-width="1.5" fill="none"/>
    <circle cx="9" cy="13" r="1.5" fill="#00b294"/>
    <circle cx="15" cy="13" r="1.5" fill="#00b294"/>
    <path d="M9.5 17h5" stroke="#00b294" stroke-width="1.5"/>
    <path d="M12 4v4M10 4h4" stroke="#00b294" stroke-width="1.5"/>`),

  entrarsc: svgIcon(`
    <ellipse cx="12" cy="6" rx="7" ry="2.5" stroke="#107c10" stroke-width="1.5" fill="none"/>
    <path d="M5 6v12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V6" stroke="#107c10" stroke-width="1.5" fill="none"/>
    <line x1="5" y1="12" x2="19" y2="12" stroke="#107c10" stroke-width="1" stroke-dasharray="2 2"/>`),

  // Azure ARM / data-plane resource (Key Vault, Storage, etc. — Azure RBAC enforced)
  azurersc: svgIcon(`
    <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" stroke="#e86c00" stroke-width="1.5" fill="none"/>
    <path d="M12 3v18M4 7.5l8 4.5 8-4.5" stroke="#e86c00" stroke-width="1" stroke-dasharray="2 2"/>`),

  // ── Hybrid Identity node types ──
  aadconnect: svgIcon(`
    <rect x="2" y="5" width="20" height="14" rx="1.5" stroke="#4fd1aa" stroke-width="1.5"/>
    <path d="M7 10.5a4.5 4.5 0 0 1 3.5-3.5" stroke="#4fd1aa" stroke-width="1.5"/>
    <path d="M17 13.5a4.5 4.5 0 0 1-3.5 3.5" stroke="#4fd1aa" stroke-width="1.5"/>
    <polyline points="14.5,7.5 16.5,9 14.5,9" stroke="#4fd1aa" stroke-width="1.2"/>
    <polyline points="9.5,16.5 7.5,15 9.5,15" stroke="#4fd1aa" stroke-width="1.2"/>`),

  adfs: svgIcon(`
    <path d="M12 2L3 6v5c0 5.5 4 10.5 9 12 5-1.5 9-6.5 9-12V6L12 2z" stroke="#e8a838" stroke-width="1.5"/>
    <path d="M9 12h6" stroke="#e8a838" stroke-width="1.5"/>
    <circle cx="9" cy="12" r="1" fill="#e8a838"/>
    <circle cx="15" cy="12" r="1" fill="#e8a838"/>
    <path d="M12 7v3M12 14v3" stroke="#e8a838" stroke-width="1.2"/>`),
};

const NODE_TYPE_CLASSES = {
  dc: 'cy-node-dc',
  ca: 'cy-node-ca',
  user: 'cy-node-user',
  admin: 'cy-node-admin',
  svc: 'cy-node-svc',
  host: 'cy-node-host',
  server: 'cy-node-server',
  attacker: 'cy-node-attacker',
  entra: 'cy-node-entra',
  entrauser: 'cy-node-entrauser',
  entraadmin: 'cy-node-entraadmin',
  entradevice: 'cy-node-entradevice',
  entrasvc: 'cy-node-entrasvc',
  entrami: 'cy-node-entrami',
  entrarsc: 'cy-node-entrarsc',
  azurersc: 'cy-node-azurersc',
  aadconnect: 'cy-node-aadconnect',
  adfs: 'cy-node-adfs',
};

function normalizeGraphElements(elements) {
  const clonedElements = JSON.parse(JSON.stringify(elements));
  clonedElements.forEach((element) => {
    if (element.group === 'edges' || element.data?.source || element.data?.target) return;
    const typeClass = NODE_TYPE_CLASSES[element.data?.type];
    const stateClasses = (element.classes || '')
      .split(/\s+/)
      .filter((className) => className && className !== 'cy-node' && !className.startsWith('cy-node-'));
    element.classes = [...new Set([
      'cy-node',
      typeClass,
      ...stateClasses,
    ].filter(Boolean))].join(' ');
  });
  return clonedElements;
}

export const initialElements = [
  { data: { id: 'dc01', name: 'DC01', type: 'dc', fqdn: 'dc01.corp.local', ip: '10.1.1.10' }, classes: 'cy-node cy-node-dc high-value', position: { x: 470, y: 92 } },
  { data: { id: 'ca01', name: 'CA01', type: 'ca', fqdn: 'ca01.corp.local', ip: '10.1.1.20' }, classes: 'cy-node cy-node-ca', position: { x: 620, y: 92 } },
  { data: { id: 'srv_web01', name: 'SRV-WEB-01', type: 'server', fqdn: 'srv-web-01.corp.local', ip: '10.1.5.20', spns: ['HTTP/srv-web-01.corp.local'] }, classes: 'cy-node cy-node-server', position: { x: 770, y: 208 } },
  { data: { id: 'srv_app01', name: 'SRV-APP-01', type: 'server', fqdn: 'srv-app-01.corp.local', ip: '10.1.5.30', unconstrained_delegation: true }, classes: 'cy-node cy-node-server delegation-unconstrained', position: { x: 770, y: 312 } },
  { data: { id: 'srv_sql01', name: 'SQL01', type: 'server', fqdn: 'sql01.corp.local', ip: '10.1.5.10' }, classes: 'cy-node cy-node-server', position: { x: 770, y: 416 } },
  { data: { id: 'srv_files01', name: 'FILES01', type: 'server', fqdn: 'files01.corp.local', ip: '10.1.5.40' }, classes: 'cy-node cy-node-server', position: { x: 770, y: 520 } },
  { data: { id: 'svc_sql01', name: 'svc_sql01', type: 'svc', sam: 'CORP\\svc_sql01', spns: ['MSSQLSvc/sql01.corp.local:1433'], ip: '10.1.5.10', ntlm_hash: 'SqlSvcHash1' }, classes: 'cy-node cy-node-svc', position: { x: 585, y: 392 } },
  { data: { id: 'svc_nopreauth', name: 'svc_nopreauth', type: 'svc', sam: 'CORP\\svc_nopreauth', no_preauth: true, ip: '10.1.5.11', ntlm_hash: 'NoPreauthHash' }, classes: 'cy-node cy-node-svc', position: { x: 585, y: 520 } },
  { data: { id: 'host1', name: 'WKSTN-01', type: 'host', fqdn: 'wkstn-01.corp.local', ip: '10.1.10.101' }, classes: 'cy-node cy-node-host', position: { x: 120, y: 298 } },
  { data: { id: 'host2', name: 'WKSTN-02', type: 'host', fqdn: 'wkstn-02.corp.local', ip: '10.1.10.102' }, classes: 'cy-node cy-node-host', position: { x: 280, y: 298 } },
  { data: { id: 'user1', name: 'Alice', type: 'user', sam: 'CORP\\Alice', ip: '10.1.10.50', ntlm_hash: 'AliceHash' }, classes: 'cy-node cy-node-user', position: { x: 120, y: 430 } },
  { data: { id: 'user2', name: 'Bob', type: 'user', sam: 'CORP\\Bob', ip: '10.1.10.51', ntlm_hash: 'BobHash' }, classes: 'cy-node cy-node-user', position: { x: 280, y: 430 } },
  { data: { id: 'admin1', name: 'DomainAdmin', type: 'admin', sam: 'CORP\\DomainAdmin', ip: '10.1.1.5', ntlm_hash: 'DAHash' }, classes: 'cy-node cy-node-admin high-value', position: { x: 250, y: 92 } },
  { data: { id: 'attacker', name: 'Attacker', type: 'attacker', ip: '192.168.1.100' }, classes: 'cy-node cy-node-attacker', position: { x: 100, y: 182 } },
  { data: { id: 'krbtgt', name: 'krbtgt', type: 'svc', sam: 'CORP\\krbtgt', ntlm_hash: 'KRBTGT_HASH_SECRET' }, classes: 'cy-node cy-node-svc high-value', style: { display: 'none' } },
];

export const entraInitialElements = [
  // ── Identity plane ──
  { data: { id: 'ent_tenant', name: 'Entra ID', type: 'entra', tenantId: 'corp.onmicrosoft.com' }, classes: 'cy-node cy-node-entra high-value', position: { x: 500, y: 88 } },
  { data: { id: 'ent_admin',  name: 'EntraAdmin', type: 'entraadmin', upn: 'admin@corp.onmicrosoft.com', pimEligible: true }, classes: 'cy-node cy-node-entraadmin high-value', position: { x: 312, y: 88 } },

  // ── Client devices ──
  { data: { id: 'ent_dev1', name: 'LAPTOP-01', type: 'entradevice', deviceId: 'dev-01', entraJoined: true, tpm: true, whfb: true, intuneCompliant: true }, classes: 'cy-node cy-node-entradevice', position: { x: 145, y: 208 } },
  { data: { id: 'ent_dev2', name: 'LAPTOP-02', type: 'entradevice', deviceId: 'dev-02', entraRegistered: true, tpm: false, intuneCompliant: false }, classes: 'cy-node cy-node-entradevice', position: { x: 145, y: 332 } },

  // ── Users ──
  { data: { id: 'ent_user1', name: 'Alice', type: 'entrauser', upn: 'alice@corp.onmicrosoft.com', objectId: 'user-alice' }, classes: 'cy-node cy-node-entrauser', position: { x: 300, y: 272 } },
  { data: { id: 'ent_user2', name: 'Bob',   type: 'entrauser', upn: 'bob@corp.onmicrosoft.com',   objectId: 'user-bob'   }, classes: 'cy-node cy-node-entrauser', position: { x: 300, y: 396 } },

  // ── Workload identities ──
  { data: { id: 'ent_svc', name: 'AppReg-01', type: 'entrasvc', appId: 'app-01', objectId: 'svc-01' }, classes: 'cy-node cy-node-entrasvc', position: { x: 690, y: 248 } },
  { data: { id: 'ent_mi',  name: 'WebApp-MI', type: 'entrami',  objectId: 'mi-01', miType: 'SystemAssigned' }, classes: 'cy-node cy-node-entrami',  position: { x: 690, y: 372 } },

  // ── Resources ──
  { data: { id: 'ent_m365', name: 'M365 / Teams', type: 'entrarsc', url: 'https://teams.microsoft.com' }, classes: 'cy-node cy-node-entrarsc', position: { x: 700, y: 88 } },
  { data: { id: 'ent_kv',   name: 'Key Vault',    type: 'azurersc', url: 'https://corp-kv.vault.azure.net' }, classes: 'cy-node cy-node-azurersc', position: { x: 820, y: 248 } },

  // ── Threat actor ──
  { data: { id: 'ent_attacker', name: 'Attacker', type: 'attacker', ip: '185.220.x.x' }, classes: 'cy-node cy-node-attacker', position: { x: 120, y: 470 } },
];

export const hybridInitialElements = [
  // ── On-Premises ──
  { data: { id: 'hb_dc01', name: 'DC01', type: 'dc', fqdn: 'dc01.corp.local', ip: '10.1.1.10' }, classes: 'cy-node cy-node-dc high-value', position: { x: 180, y: 92 } },
  { data: { id: 'hb_adfs', name: 'ADFS01', type: 'adfs', fqdn: 'adfs.corp.local', ip: '10.1.2.20' }, classes: 'cy-node cy-node-adfs', position: { x: 60, y: 260 } },
  { data: { id: 'hb_aadconnect', name: 'AADConnect', type: 'aadconnect', fqdn: 'aadsync.corp.local', ip: '10.1.2.10', note: 'PHS/PTA/Writeback Agent' }, classes: 'cy-node cy-node-aadconnect', position: { x: 235, y: 260 } },
  { data: { id: 'hb_msol', name: 'MSOL_sync', type: 'svc', sam: 'CORP\\MSOL_ab12cd34', ntlm_hash: 'MSOLHash', note: 'DS-Replication-Get-Changes-All ACE' }, classes: 'cy-node cy-node-svc', position: { x: 370, y: 260 } },
  { data: { id: 'hb_user1', name: 'Alice', type: 'user', sam: 'CORP\\Alice', upn: 'alice@corp.com', synced: true, ip: '10.1.10.50' }, classes: 'cy-node cy-node-user', position: { x: 110, y: 500 } },
  { data: { id: 'hb_dev1', name: 'WKSTN-HYB', type: 'host', fqdn: 'wkstn-hyb.corp.local', haadj: true, tpm: true, ip: '10.1.10.110' }, classes: 'cy-node cy-node-host', position: { x: 270, y: 500 } },

  // ── Cloud (Entra ID) ──
  { data: { id: 'hb_entra', name: 'Entra ID', type: 'entra', tenantId: 'corp.onmicrosoft.com' }, classes: 'cy-node cy-node-entra high-value', position: { x: 640, y: 92 } },
  { data: { id: 'hb_m365', name: 'M365 / SharePoint', type: 'entrarsc', url: 'https://corp.sharepoint.com' }, classes: 'cy-node cy-node-entrarsc', position: { x: 800, y: 260 } },

  // ── Threat Actor ──
  { data: { id: 'hb_attacker', name: 'Attacker', type: 'attacker', ip: '10.1.100.50' }, classes: 'cy-node cy-node-attacker', position: { x: 455, y: 520 } },
];

export function fitGraphToViewport(padding = state.graphFitPadding) {
  if (!state.cy) return;
  const container = state.cy.container();
  const shortSide = Math.min(container?.clientWidth || 0, container?.clientHeight || 0);
  const responsivePadding = shortSide > 0
    ? Math.max(16, Math.min(padding, Math.round(shortSide * 0.045)))
    : padding;
  state.cy.fit(undefined, responsivePadding);
}

export function initializeCytoscape(elements) {
  if (state.cy) state.cy.destroy();

  state.cy = cytoscape({
    container: document.getElementById('cy'),
    elements: normalizeGraphElements(elements),
    userZoomingEnabled: false,
    fit: false,
    style: [
      {
        selector: 'node',
        style: {
          width: '56px', height: '56px',
          shape: 'ellipse',
          'background-color': '#2d2d30',
          'border-width': 2, 'border-color': '#555',
          'background-image': (ele) => NODE_ICONS[ele.data('type')] || '',
          'background-fit': 'none',
          'background-clip': 'node',
          'background-repeat': 'no-repeat',
          'background-position-x': '50%',
          'background-position-y': '50%',
          'background-image-opacity': 0.92,
          'background-width': '64%',
          'background-height': '64%',
          label: (ele) => ele.data('name'),
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': 10,
          'font-size': '11.5px',
          'font-weight': 600,
          'text-wrap': 'wrap',
          'text-max-width': '92px',
          color: '#cccccc',
          'text-outline-color': '#181818',
          'text-outline-width': 3,
        },
      },
      // Each type gets a distinct shape + color so nodes are recognizable at a glance
      { selector: '.cy-node-dc',       style: { shape: 'round-hexagon',  width: '80px', height: '64px', 'background-color': '#091d36', 'border-color': '#569cd6', 'border-width': 2.5, 'background-clip': 'node', 'background-position-x': '50%', 'background-position-y': '50%' } },
      { selector: '.cy-node-ca',       style: { shape: 'pentagon',       width: '58px', height: '58px', 'background-color': '#271e00', 'border-color': '#dcdcaa', 'background-clip': 'node' } },
      { selector: '.cy-node-user',     style: { shape: 'ellipse',        width: '52px', height: '52px', 'background-color': '#091f14', 'border-color': '#4ec9b0' } },
      { selector: '.cy-node-admin',    style: { shape: 'hexagon',        width: '60px', height: '60px', 'background-color': '#2a0606', 'border-color': '#f44747' } },
      { selector: '.cy-node-svc',      style: { shape: 'octagon',        width: '52px', height: '52px', 'background-color': '#1e1e20', 'border-color': '#7a7a7a' } },
      { selector: '.cy-node-host',     style: { shape: 'roundrectangle', width: '68px', height: '52px', 'background-color': '#001b24', 'border-color': '#0dcaf0', 'background-position-y': '50%' } },
      { selector: '.cy-node-server',   style: { shape: 'rectangle',      width: '72px', height: '52px', 'background-color': '#160c2a', 'border-color': '#c586c0', 'background-position-y': '50%' } },
      { selector: '.cy-node-attacker', style: { shape: 'hexagon',        width: '64px', height: '64px', 'background-color': '#280000', 'border-color': '#e03131', 'border-width': 2.5 } },
      {
        selector: 'node.highlighted',
        style: { 'border-color': '#ffe066', 'border-width': 3, 'background-color': '#2d2900' },
      },
      {
        selector: 'node.compromised',
        style: { 'background-color': '#2d0000', 'border-color': '#e03131', 'border-width': 3, 'border-style': 'dashed' },
      },
      { selector: '.delegation-unconstrained', style: { 'border-style': 'dotted', 'border-width': 3, 'border-color': '#6f42c1' } },
      { selector: '.delegation-constrained',   style: { 'border-style': 'dotted', 'border-width': 3, 'border-color': '#0dcaf0' } },
      // high-value gets a brighter border glow; shape/size come from the type selector above
      { selector: '.high-value', style: { 'border-width': 3.5, 'border-color': '#ffd700' } },
      {
        selector: 'edge',
        style: {
          width: 1.5, 'line-color': '#adb5bd',
          'target-arrow-shape': 'triangle', 'target-arrow-color': '#adb5bd',
          'curve-style': 'bezier', label: 'data(label)',
          'font-size': '10px', color: '#cccccc', 'text-rotation': 'autorotate',
          'text-background-color': '#1e1e1e', 'text-background-opacity': 0.9,
          'text-background-padding': '2px', 'text-background-shape': 'roundrectangle',
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

      // ── Entra ID node types ──
      { selector: '.cy-node-entra',       style: { shape: 'roundrectangle', width: '86px', height: '64px', 'background-color': '#001428', 'border-color': '#0078d4', 'border-width': 2.5, 'background-clip': 'node', 'background-position-x': '50%', 'background-position-y': '50%', 'corner-radius': '10px' } },
      { selector: '.cy-node-entrauser',   style: { shape: 'ellipse',        width: '52px', height: '52px', 'background-color': '#00182e', 'border-color': '#50b4e8' } },
      { selector: '.cy-node-entraadmin',  style: { shape: 'hexagon',        width: '62px', height: '62px', 'background-color': '#2a1400', 'border-color': '#ff8c00' } },
      { selector: '.cy-node-entradevice', style: { shape: 'roundrectangle', width: '68px', height: '52px', 'background-color': '#001c24', 'border-color': '#50e6ff', 'background-position-y': '50%' } },
      { selector: '.cy-node-entrasvc',    style: { shape: 'pentagon',       width: '58px', height: '58px', 'background-color': '#160d2c', 'border-color': '#8764b8', 'background-clip': 'node' } },
      { selector: '.cy-node-entrami',     style: { shape: 'octagon',        width: '56px', height: '56px', 'background-color': '#001c18', 'border-color': '#00b294' } },
      { selector: '.cy-node-entrarsc',    style: { shape: 'barrel',         width: '60px', height: '60px', 'background-color': '#001400', 'border-color': '#107c10' } },
      { selector: '.cy-node-azurersc',    style: { shape: 'hexagon',        width: '60px', height: '60px', 'background-color': '#1e0e00', 'border-color': '#e86c00' } },

      // ── Hybrid Identity node types ──
      { selector: '.cy-node-aadconnect', style: { shape: 'rectangle',      width: '76px', height: '52px', 'background-color': '#001c14', 'border-color': '#4fd1aa', 'border-width': 2, 'background-position-y': '50%' } },
      { selector: '.cy-node-adfs',       style: { shape: 'pentagon',       width: '60px', height: '60px', 'background-color': '#1e1400', 'border-color': '#e8a838', 'background-clip': 'node' } },

      // ── Hybrid protocol edges ──
      { selector: '.sync-edge',       style: { 'line-color': '#4fd1aa', 'target-arrow-color': '#4fd1aa', width: 2.5, 'line-style': 'dashed', 'z-index': 10 } },
      { selector: '.saml-edge',       style: { 'line-color': '#c084fc', 'target-arrow-color': '#c084fc', width: 2.5,                         'z-index': 10 } },
      { selector: '.pta-edge',        style: { 'line-color': '#fb923c', 'target-arrow-color': '#fb923c', width: 2,   'line-style': 'dashed', 'z-index': 10 } },
      { selector: '.attack-flow-edge',style: { 'line-color': '#e03131', 'target-arrow-color': '#e03131', width: 3,                           'z-index': 12 } },

      // ── Entra protocol edges ──
      { selector: '.oidc-edge',    style: { 'line-color': '#0078d4', 'target-arrow-color': '#0078d4', width: 2.5, 'z-index': 10 } },
      { selector: '.prt-edge',     style: { 'line-color': '#50b4e8', 'target-arrow-color': '#50b4e8', width: 2,   'line-style': 'dashed', 'z-index': 10 } },
      { selector: '.tpm-edge',     style: { 'line-color': '#f0a30a', 'target-arrow-color': '#f0a30a', width: 2.5, 'z-index': 11 } },
      { selector: '.msgraph-edge', style: { 'line-color': '#00b294', 'target-arrow-color': '#00b294', width: 2,   'z-index': 9  } },
      { selector: '.imds-edge',    style: { 'line-color': '#7a43b6', 'target-arrow-color': '#7a43b6', width: 2,   'line-style': 'dotted', 'z-index': 9 } },
      { selector: '.azurerm-edge', style: { 'line-color': '#e86c00', 'target-arrow-color': '#e86c00', width: 2,   'line-style': 'dashed', 'z-index': 9 } },
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

  if (!state._resizeHandler) {
    state._resizeHandler = () => {
      state.cy?.resize();
      fitGraphToViewport();
    };
    window.addEventListener('resize', state._resizeHandler);
  }
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
  const edgeClass = `temp-edge ${protocolToEdgeClass(protocol)}`;
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
