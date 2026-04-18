import { log } from './logger.js';
import { state, stepDelay } from './state.js';
import { initializeCytoscape, initialElements, entraInitialElements } from './graph.js';

const logContent       = document.getElementById('log-content');
const manualModeChk    = document.getElementById('chk-manual-mode');
const manualControlsDiv = document.getElementById('manual-step-controls');
const nextStepButton   = document.getElementById('btn-next-step');
const resetButton      = document.getElementById('btn-reset');
const scenarioButtons  = document.querySelectorAll('.scenario-buttons .btn');

function clearManualStepEdges() {
  if (state.cy && state.manualStepEdges.length > 0) {
    state.cy.batch(() => {
      state.manualStepEdges.forEach((id) => {
        const e = state.cy.getElementById(id);
        if (e.length > 0) state.cy.remove(e);
      });
    });
  }
  state.manualStepEdges = [];
}

export function resetSimulationState(clearLog = true) {
  clearTimeout(state.simulationTimeout);
  state.simulationTimeout = null;
  state.currentScenario = [];
  state.currentStep = -1;
  state.isRunning = false;
  clearManualStepEdges();

  if (clearLog) logContent.innerHTML = 'Simulation reset.\n';

  if (state.cy) {
    state.cy.remove('.temp-edge');
    state.cy.nodes().removeClass('highlighted compromised');
    state.cy.nodes().removeScratch('_sim_highlighted');
  } else {
    initializeCytoscape(state.mode === 'entra' ? entraInitialElements : initialElements);
  }
  updateButtonStates();
  if (clearLog) log('Select a scenario to start.', 'info');
}

function executeSingleStep(stepIndex) {
  if (!state.currentScenario || stepIndex < 0 || stepIndex >= state.currentScenario.length) return;
  const step = state.currentScenario[stepIndex];
  if (!(stepIndex === 0 && step.scenarioName)) log(step.logMessage, step.logType || 'info');
  if (typeof step.action === 'function') {
    try { step.action(); } catch (e) { console.error('Step action error:', e); log(`Step Error: ${e.message}`, 'fail'); }
  }
  updateButtonStates();
}

function executeStepsAutomatically() {
  if (!state.isRunning || state.isManualMode || state.currentStep >= state.currentScenario.length - 1) {
    if (state.isRunning && state.currentStep >= state.currentScenario.length - 1) resetSimulationState(false);
    clearTimeout(state.simulationTimeout);
    state.simulationTimeout = null;
    return;
  }
  state.currentStep++;
  const step = state.currentScenario[state.currentStep];
  if (!(state.currentStep === 0 && step.scenarioName)) log(step.logMessage, step.logType || 'info');
  if (typeof step.action === 'function') {
    try { step.action(); } catch (e) { console.error('Auto step error:', e); log(`Step Error: ${e.message}`, 'fail'); }
  }
  state.simulationTimeout = setTimeout(executeStepsAutomatically, step.delay || stepDelay);
}

export function startScenario(scenario) {
  if (state.isRunning) { log('Another simulation is running. Please Reset first.', 'fail'); return; }
  resetSimulationState(true);
  state.isRunning = true;
  state.isManualMode = manualModeChk.checked;

  setTimeout(() => {
    state.currentScenario = scenario;
    state.currentStep = -1;
    if (!state.currentScenario?.length) {
      log('Error: Selected scenario is empty.', 'fail');
      state.isRunning = false;
      updateButtonStates();
      return;
    }
    log(`--- Starting Scenario: ${state.currentScenario[0]?.scenarioName || 'Unnamed'} ---`, 'info');
    updateButtonStates();

    if (state.isManualMode) {
      manualControlsDiv.classList.add('active');
      handleNextStep();
    } else {
      manualControlsDiv.classList.remove('active');
      state.simulationTimeout = setTimeout(executeStepsAutomatically, (state.currentScenario[0]?.delay || stepDelay) / 2);
    }
  }, 100);
}

export function handleNextStep() {
  if (!state.isRunning || !state.isManualMode) return;
  if (state.currentStep >= state.currentScenario.length - 1) { resetSimulationState(false); return; }
  clearManualStepEdges();
  state.currentStep++;
  executeSingleStep(state.currentStep);
}

export function updateButtonStates() {
  const running = state.isRunning && state.currentScenario.length > 0;
  scenarioButtons.forEach((b) => (b.disabled = running));
  manualModeChk.disabled = running;
  resetButton.disabled = !running;

  if (running && state.isManualMode) {
    manualControlsDiv.classList.add('active');
    nextStepButton.disabled = false;
    nextStepButton.innerHTML = state.currentStep >= state.currentScenario.length - 1
      ? '<i class="fas fa-flag-checkered"></i> Finish'
      : '<i class="fas fa-forward-step"></i> Next Step';
  } else {
    manualControlsDiv.classList.remove('active');
    nextStepButton.disabled = true;
    nextStepButton.innerHTML = '<i class="fas fa-forward-step"></i> Next Step';
  }
}
