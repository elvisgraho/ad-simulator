import { initializeCytoscape, initialElements } from './graph.js';
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

// Wire all scenario buttons
Object.entries(SCENARIO_MAP).forEach(([id, scenario]) => {
  bind(id, () => startScenario(scenario));
});

// Control buttons
bind('btn-reset', () => resetSimulationState(true));
bind('btn-next-step', handleNextStep);
document.getElementById('chk-manual-mode')?.addEventListener('change', () => {});

// Init
initializeCytoscape(initialElements);
state.cy.ready(() => {
  log('AD Simulation Environment Initialized. Ready.', 'info');
  updateButtonStates();
});
