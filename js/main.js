import { initializeCytoscape, initialElements, entraInitialElements } from './graph.js';
import { startScenario, handleNextStep, resetSimulationState, updateButtonStates } from './engine.js';
import { log } from './logger.js';
import { state } from './state.js';

// Legitimate scenarios
import {
  legitimateLogonScenario, legitAdminGroupScenario, legitGpoUpdateScenario,
  legitCertRequestScenario, legitFileShareAccessScenario,
} from './scenarios/legit.js';

// Enumeration scenarios
import {
  attackSharpHoundScenario, attackLDAPReconScenario, attackDNSReconScenario,
  attackSMBShareEnumScenario, attackSAMRAbuseScenario,
} from './scenarios/enum.js';

// Credential attack scenarios
import {
  attackPasswordSprayScenario, attackKerberoastingScenario, attackASREPRoastingScenario,
  attackNTLMRelayScenario, attackLLMNRPoisoningScenario, attackPetitPotamScenario,
} from './scenarios/credential.js';

// Known vulnerability scenarios
import { attackZeroLogonScenario, attackPrintNightmareScenario } from './scenarios/vulns.js';

// Privilege escalation scenarios
import {
  attackLAPSAbuseScenario, attackGMSAAbuseScenario, attackUnconstrainedDelegationScenario,
  attackKCDAbuseScenario, attackRBCDScenario, attackGPOAbuseScenario,
  attackMS14068Scenario, attackShadowCredentialsScenario,
} from './scenarios/privilege.js';

// Lateral movement scenarios
import {
  attackPassTheTicketScenario, attackPassTheHashScenario, attackRemoteExecScenario,
  attackScheduledTaskScenario, attackWMIAbuseScenario,
} from './scenarios/lateral.js';

// Certificate / PKI scenarios
import {
  attackESC1Scenario, attackESC2Scenario, attackESC3Scenario,
  attackESC4Scenario, attackESC6Scenario, attackESC8Scenario,
} from './scenarios/certificates.js';

// Domain compromise & persistence scenarios
import {
  attackDCSyncScenario, attackSQLAccessScenario, attackNTDSExtractionScenario,
  attackGoldenTicketScenario, attackSilverTicketScenario, attackSkeletonKeyScenario,
  attackDSRMAbuseScenario, attackAdminSDHolderScenario,
} from './scenarios/persistence.js';

// Entra ID scenarios
import {
  entraInteractiveSignInScenario, entraWHfBSignInScenario, entraPRTSSOScenario,
  entraConditionalAccessScenario, entraManagedIdentityScenario, entraPIMActivationScenario,
  entraTpmAttestationScenario, entraMacOSSSOScenario,
} from './scenarios/entra_legit.js';

// Button → scenario mapping
const SCENARIO_MAP = {
  'btn-legit-logon':         legitimateLogonScenario,
  'btn-legit-admin-group':   legitAdminGroupScenario,
  'btn-legit-gpo':           legitGpoUpdateScenario,
  'btn-legit-cert':          legitCertRequestScenario,
  'btn-legit-fileshare':     legitFileShareAccessScenario,

  'btn-attack-sharphound':   attackSharpHoundScenario,
  'btn-attack-ldap':         attackLDAPReconScenario,
  'btn-attack-dns':          attackDNSReconScenario,
  'btn-attack-smb':          attackSMBShareEnumScenario,
  'btn-attack-samr':         attackSAMRAbuseScenario,

  'btn-attack-spray':        attackPasswordSprayScenario,
  'btn-attack-kerberoast':   attackKerberoastingScenario,
  'btn-attack-asrep':        attackASREPRoastingScenario,
  'btn-attack-ntlm':         attackNTLMRelayScenario,
  'btn-attack-llmnr':        attackLLMNRPoisoningScenario,
  'btn-attack-petitpotam':   attackPetitPotamScenario,

  'btn-attack-zerologon':    attackZeroLogonScenario,
  'btn-attack-printnightmare': attackPrintNightmareScenario,

  'btn-attack-laps':         attackLAPSAbuseScenario,
  'btn-attack-gmsa':         attackGMSAAbuseScenario,
  'btn-attack-uncon':        attackUnconstrainedDelegationScenario,
  'btn-attack-kcd':          attackKCDAbuseScenario,
  'btn-attack-rbcd':         attackRBCDScenario,
  'btn-attack-gpo-mod':      attackGPOAbuseScenario,
  'btn-attack-ms14':         attackMS14068Scenario,
  'btn-attack-shadow':       attackShadowCredentialsScenario,

  'btn-attack-ptt':          attackPassTheTicketScenario,
  'btn-attack-pth':          attackPassTheHashScenario,
  'btn-attack-remote-exec':  attackRemoteExecScenario,
  'btn-attack-scheduled':    attackScheduledTaskScenario,
  'btn-attack-wmi':          attackWMIAbuseScenario,

  'btn-attack-esc1':         attackESC1Scenario,
  'btn-attack-esc2':         attackESC2Scenario,
  'btn-attack-esc3':         attackESC3Scenario,
  'btn-attack-esc4':         attackESC4Scenario,
  'btn-attack-esc6':         attackESC6Scenario,
  'btn-attack-esc8':         attackESC8Scenario,

  'btn-attack-dcsync':       attackDCSyncScenario,
  'btn-attack-ntds':         attackNTDSExtractionScenario,
  'btn-attack-golden':       attackGoldenTicketScenario,
  'btn-attack-silver':       attackSilverTicketScenario,
  'btn-attack-skeleton':     attackSkeletonKeyScenario,
  'btn-attack-dsr':          attackDSRMAbuseScenario,
  'btn-attack-adminsd':      attackAdminSDHolderScenario,
};

function bind(id, cb) {
  document.getElementById(id)?.addEventListener('click', cb);
}

// Entra scenario map
const ENTRA_SCENARIO_MAP = {
  'btn-entra-interactive':   entraInteractiveSignInScenario,
  'btn-entra-whfb':          entraWHfBSignInScenario,
  'btn-entra-prt-sso':       entraPRTSSOScenario,
  'btn-entra-ca':            entraConditionalAccessScenario,
  'btn-entra-mi':            entraManagedIdentityScenario,
  'btn-entra-pim':           entraPIMActivationScenario,
  'btn-entra-tpm-provision': entraTpmAttestationScenario,
  'btn-entra-macos-sso':     entraMacOSSSOScenario,
};

// Wire all scenario buttons
Object.entries(SCENARIO_MAP).forEach(([id, scenario]) => {
  bind(id, () => startScenario(scenario));
});
Object.entries(ENTRA_SCENARIO_MAP).forEach(([id, scenario]) => {
  bind(id, () => startScenario(scenario));
});

// Control buttons
bind('btn-reset', () => resetSimulationState(true));
bind('btn-next-step', handleNextStep);
document.getElementById('chk-manual-mode')?.addEventListener('change', () => {});

// Mode switching
function switchMode(newMode) {
  if (state.mode === newMode) return;
  state.mode = newMode;
  resetSimulationState(true);
  initializeCytoscape(newMode === 'entra' ? entraInitialElements : initialElements);

  document.getElementById('scenarios-ad').style.display    = newMode === 'ad'    ? '' : 'none';
  document.getElementById('scenarios-entra').style.display = newMode === 'entra' ? '' : 'none';
  document.getElementById('legend-ad').style.display       = newMode === 'ad'    ? '' : 'none';
  document.getElementById('legend-entra').style.display    = newMode === 'entra' ? '' : 'none';

  document.querySelectorAll('.mode-btn').forEach(b => {
    b.classList.toggle('mode-btn-active', b.dataset.mode === newMode);
  });

  state.cy.ready(() => {
    log(`Switched to ${newMode === 'entra' ? 'Entra ID (Cloud)' : 'On-Premises AD'} simulation.`, 'info');
    updateButtonStates();
  });
}

bind('btn-mode-ad',    () => switchMode('ad'));
bind('btn-mode-entra', () => switchMode('entra'));

// Fit graph to current canvas
bind('btn-fit-graph', () => state.cy?.fit(undefined, 40));

// Log area drag-to-resize
(function () {
  const handle = document.getElementById('log-resize-handle');
  const logArea = document.getElementById('log-area');
  const vizArea = document.getElementById('visualization-area');
  if (!handle || !logArea || !vizArea) return;

  let dragging = false;
  let startY = 0;
  let startH = 0;

  handle.addEventListener('mousedown', (e) => {
    dragging = true;
    startY = e.clientY;
    startH = logArea.offsetHeight;
    handle.classList.add('dragging');
    document.body.style.cursor = 'ns-resize';
    document.body.style.userSelect = 'none';
  });

  document.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    const delta = startY - e.clientY;          // drag up → bigger log
    const maxH = vizArea.offsetHeight * 0.65;
    const minH = 70;
    const newH = Math.max(minH, Math.min(maxH, startH + delta));
    logArea.style.height = `${newH}px`;
    state.cy?.resize();
  });

  document.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove('dragging');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  });
})();

// Init
initializeCytoscape(initialElements);
state.cy.ready(() => {
  log('AD Simulation Environment Initialized. Ready.', 'info');
  updateButtonStates();
});
