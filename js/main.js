import { initializeCytoscape, initialElements, entraInitialElements, hybridInitialElements, fitGraphToViewport } from './graph.js';
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

// Entra ID legitimate scenarios
import {
  entraInteractiveSignInScenario, entraWHfBSignInScenario, entraPRTSSOScenario,
  entraConditionalAccessScenario, entraManagedIdentityScenario, entraPIMActivationScenario,
  entraTpmAttestationScenario, entraMacOSSSOScenario, entraPRTRotationScenario,
} from './scenarios/entra_legit.js';

// Entra ID attack scenarios
import {
  entraAzureHoundScenario, entraGraphEnumScenario,
  entraPasswordSprayScenario, entraMFAFatigueScenario,
  entraDeviceCodePhishingScenario, entraAITMScenario,
  entraPassThePRTScenario, entraConsentPhishingScenario,
  entraAppCredAbuseScenario, entraIMDSCredTheftScenario,
  entraPIMTakeoverScenario, entraIllicitConsentScenario,
  entraLegacyAuthAbuseScenario, entraImplicitTokenHarvestScenario,
  entraWIFAbuseScenario,
} from './scenarios/entra_attacks.js';

// Hybrid Identity legitimate scenarios
import {
  hybridDeltaSyncScenario, hybridPHSScenario, hybridPTAScenario,
  hybridPasswordWritebackScenario, hybridSeamlessSSOScenario,
  hybridCloudKerberosTrustScenario,
} from './scenarios/hybrid_legit.js';

// Hybrid Identity attack scenarios
import {
  hybridAADConnectDumpScenario, hybridDCSyncViaMSOLScenario,
  hybridSSOSilverTicketScenario, hybridGoldenSAMLScenario,
  hybridWritebackAbuseScenario, hybridPTAInterceptionScenario,
  hybridImmutableIDTakeoverScenario, hybridCloudKerberosForgeScenario,
  hybridGroupWritebackAbuseScenario,
} from './scenarios/hybrid_attacks.js';

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
  // Legitimate
  'btn-entra-interactive':   entraInteractiveSignInScenario,
  'btn-entra-whfb':          entraWHfBSignInScenario,
  'btn-entra-prt-sso':       entraPRTSSOScenario,
  'btn-entra-ca':            entraConditionalAccessScenario,
  'btn-entra-mi':            entraManagedIdentityScenario,
  'btn-entra-pim':           entraPIMActivationScenario,
  'btn-entra-tpm-provision': entraTpmAttestationScenario,
  'btn-entra-prt-rotation':  entraPRTRotationScenario,
  'btn-entra-macos-sso':     entraMacOSSSOScenario,
  // Enumeration
  'btn-entra-azurehound':    entraAzureHoundScenario,
  'btn-entra-graph-enum':    entraGraphEnumScenario,
  // Initial Access
  'btn-entra-spray':         entraPasswordSprayScenario,
  'btn-entra-mfa-fatigue':   entraMFAFatigueScenario,
  'btn-entra-devicecode':    entraDeviceCodePhishingScenario,
  'btn-entra-aitm':          entraAITMScenario,
  // Token & Session
  'btn-entra-prt-theft':     entraPassThePRTScenario,
  'btn-entra-consent-phish': entraConsentPhishingScenario,
  'btn-entra-implicit-token': entraImplicitTokenHarvestScenario,
  // Privilege Escalation
  'btn-entra-app-cred':      entraAppCredAbuseScenario,
  'btn-entra-imds-theft':    entraIMDSCredTheftScenario,
  'btn-entra-pim-takeover':  entraPIMTakeoverScenario,
  'btn-entra-wif-abuse':     entraWIFAbuseScenario,
  // Initial Access (legacy)
  'btn-entra-legacy-auth':   entraLegacyAuthAbuseScenario,
  // Persistence
  'btn-entra-illicit-consent': entraIllicitConsentScenario,
};

// Hybrid Identity scenario map
const HYBRID_SCENARIO_MAP = {
  // Legitimate
  'btn-hybrid-delta-sync':    hybridDeltaSyncScenario,
  'btn-hybrid-phs':           hybridPHSScenario,
  'btn-hybrid-pta':           hybridPTAScenario,
  'btn-hybrid-writeback':     hybridPasswordWritebackScenario,
  'btn-hybrid-seamless-sso':  hybridSeamlessSSOScenario,
  'btn-hybrid-cloud-krb':     hybridCloudKerberosTrustScenario,
  // Attacks
  'btn-hybrid-aadconnect-dump':  hybridAADConnectDumpScenario,
  'btn-hybrid-dcsync-msol':      hybridDCSyncViaMSOLScenario,
  'btn-hybrid-sso-silver':       hybridSSOSilverTicketScenario,
  'btn-hybrid-golden-saml':      hybridGoldenSAMLScenario,
  'btn-hybrid-writeback-abuse':  hybridWritebackAbuseScenario,
  'btn-hybrid-pta-intercept':    hybridPTAInterceptionScenario,
  // Sync Engine & Trust Attacks
  'btn-hybrid-immutableid':      hybridImmutableIDTakeoverScenario,
  'btn-hybrid-cloud-kbt-forge':  hybridCloudKerberosForgeScenario,
  'btn-hybrid-group-writeback':  hybridGroupWritebackAbuseScenario,
};

// Wire all scenario buttons
Object.entries(SCENARIO_MAP).forEach(([id, scenario]) => {
  bind(id, () => startScenario(scenario));
});
Object.entries(ENTRA_SCENARIO_MAP).forEach(([id, scenario]) => {
  bind(id, () => startScenario(scenario));
});
Object.entries(HYBRID_SCENARIO_MAP).forEach(([id, scenario]) => {
  bind(id, () => startScenario(scenario));
});

// Control buttons
bind('btn-reset', () => resetSimulationState(true));
bind('btn-next-step', handleNextStep);
document.getElementById('chk-manual-mode')?.addEventListener('change', () => {});

// Mode switching
const MODE_ELEMENTS = { ad: initialElements, entra: entraInitialElements, hybrid: hybridInitialElements };
const MODE_NAMES    = { ad: 'On-Premises AD', entra: 'Entra ID (Cloud)', hybrid: 'Hybrid Identity (On-Prem + Entra)' };
const MODE_GRAPH_PADDING = { ad: 40, entra: 40, hybrid: 90 };

function switchMode(newMode) {
  if (state.mode === newMode) return;
  state.mode = newMode;
  state.graphFitPadding = MODE_GRAPH_PADDING[newMode] || 40;
  resetSimulationState(true);
  initializeCytoscape(MODE_ELEMENTS[newMode] || initialElements);

  ['ad', 'entra', 'hybrid'].forEach(m => {
    const s = document.getElementById(`scenarios-${m}`);
    const l = document.getElementById(`legend-${m}`);
    if (s) s.style.display = m === newMode ? '' : 'none';
    if (l) l.style.display = m === newMode ? '' : 'none';
  });

  document.querySelectorAll('.mode-btn').forEach(b => {
    b.classList.toggle('mode-btn-active', b.dataset.mode === newMode);
  });

  state.cy.ready(() => {
    fitGraphToViewport();
    log(`Switched to ${MODE_NAMES[newMode] || newMode} simulation.`, 'info');
    updateButtonStates();
  });
}

bind('btn-mode-ad',     () => switchMode('ad'));
bind('btn-mode-entra',  () => switchMode('entra'));
bind('btn-mode-hybrid', () => switchMode('hybrid'));

// Fit graph to current canvas
bind('btn-fit-graph', () => fitGraphToViewport());

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
state.graphFitPadding = MODE_GRAPH_PADDING[state.mode] || 40;
initializeCytoscape(initialElements);
state.cy.ready(() => {
  fitGraphToViewport();
  log('AD Simulation Environment Initialized. Ready.', 'info');
  updateButtonStates();
});
