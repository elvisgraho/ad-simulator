document.addEventListener("DOMContentLoaded", function () {
  // --- DOM Element References ---
  const logContent = document.getElementById("log-content");
  const cyContainer = document.getElementById("cy");
  const manualModeCheckbox = document.getElementById("chk-manual-mode");
  const manualControlsDiv = document.getElementById("manual-step-controls");
  const nextStepButton = document.getElementById("btn-next-step");
  const resetButton = document.getElementById("btn-reset");
  const scenarioButtons = document.querySelectorAll(".scenario-buttons .btn");

  // --- State Variables ---
  let cy;
  let simulationTimeout = null;
  let isManualMode = false;
  let isRunning = false;
  const stepDelay = 3000;
  let currentScenario = [];
  let currentStep = -1;
  let manualStepEdges = [];

  // --- Logging Utility ---
  function log(message, type = "info") {
    const timestamp = new Date().toLocaleTimeString();
    let icon = "";
    let typeClass = `log-${type}`;
    switch (type) {
      case "kerberos":
        icon = '<i class="fas fa-key fa-fw me-1"></i>';
        break;
      case "ldap":
        icon = '<i class="fas fa-book fa-fw me-1"></i>';
        break;
      case "attack":
        icon = '<i class="fas fa-biohazard fa-fw me-1"></i>';
        break;
      case "success":
        icon = '<i class="fas fa-check-circle fa-fw me-1"></i>';
        break;
      case "fail":
        icon = '<i class="fas fa-times-circle fa-fw me-1"></i>';
        break;
      case "info":
        icon = '<i class="fas fa-info-circle fa-fw me-1"></i>';
        break;
      case "rpc":
        icon = '<i class="fas fa-network-wired fa-fw me-1"></i>';
        break;
      case "smb":
        icon = '<i class="fas fa-folder-open fa-fw me-1"></i>';
        break;
      case "dns":
        icon = '<i class="fas fa-search-location fa-fw me-1"></i>';
        break;
      case "http":
        icon = '<i class="fas fa-globe fa-fw me-1"></i>';
        break;
      case "drsuapi":
        icon = '<i class="fas fa-database fa-fw me-1"></i>';
        break;
      case "ntlm":
        icon = '<i class="fas fa-fingerprint fa-fw me-1"></i>';
        break;
      default:
        icon = '<i class="fas fa-angle-right fa-fw me-1"></i>';
        typeClass = "log-info";
    }
    const sanitizedMessage = message.replace(/</g, "<").replace(/>/g, ">");
    logContent.innerHTML += `<span class="${typeClass}">[${timestamp}] ${icon}${sanitizedMessage}\n</span>`;
    logContent.scrollTop = logContent.scrollHeight;
  }

  // --- Initial AD Objects (With initial positions for layout hint) ---
  const initialElements = [
    // Core Domain Infra
    {
      data: {
        id: "dc01",
        name: "DC01",
        type: "dc",
        fqdn: "dc01.corp.local",
        ip: "10.1.1.10",
      },
      classes: "cy-node cy-node-dc high-value",
      position: { x: 450, y: 100 },
    },
    {
      data: {
        id: "ca01",
        name: "CA01",
        type: "ca",
        fqdn: "ca01.corp.local",
        ip: "10.1.1.20",
      },
      classes: "cy-node cy-node-ca",
      position: { x: 600, y: 150 },
    },
    // Server OU
    {
      data: {
        id: "srv_web01",
        name: "SRV-WEB-01",
        type: "server",
        fqdn: "srv-web-01.corp.local",
        ip: "10.1.5.20",
        spns: ["HTTP/srv-web-01.corp.local"],
      },
      classes: "cy-node cy-node-server",
      position: { x: 750, y: 250 },
    },
    {
      data: {
        id: "srv_app01",
        name: "SRV-APP-01",
        type: "server",
        fqdn: "srv-app-01.corp.local",
        ip: "10.1.5.30",
        unconstrained_delegation: true,
      },
      classes: "cy-node cy-node-server delegation-unconstrained",
      position: { x: 750, y: 350 },
    },
    {
      data: {
        id: "srv_sql01",
        name: "SQL01",
        type: "server",
        fqdn: "sql01.corp.local",
        ip: "10.1.5.10",
      },
      classes: "cy-node cy-node-server",
      position: { x: 750, y: 450 },
    },
    {
      data: {
        id: "srv_files01",
        name: "FILES01",
        type: "server",
        fqdn: "files01.corp.local",
        ip: "10.1.5.40",
      },
      classes: "cy-node cy-node-server",
      position: { x: 750, y: 550 },
    },
    // Service Accounts
    {
      data: {
        id: "svc_sql01",
        name: "svc_sql01",
        type: "svc",
        sam: "CORP\\svc_sql01",
        spns: ["MSSQLSvc/sql01.corp.local:1433"],
        ip: "10.1.5.10",
        ntlm_hash: "SqlSvcHash1",
      },
      classes: "cy-node cy-node-svc",
      position: { x: 550, y: 500 },
    },
    {
      data: {
        id: "svc_nopreauth",
        name: "svc_nopreauth",
        type: "svc",
        sam: "CORP\\svc_nopreauth",
        no_preauth: true,
        ip: "10.1.5.11",
        ntlm_hash: "NoPreauthHash",
      },
      classes: "cy-node cy-node-svc",
      position: { x: 550, y: 600 },
    },
    // Workstation/User OU
    {
      data: {
        id: "host1",
        name: "WKSTN-01",
        type: "host",
        fqdn: "wkstn-01.corp.local",
        ip: "10.1.10.101",
      },
      classes: "cy-node cy-node-host",
      position: { x: 100, y: 450 },
    },
    {
      data: {
        id: "host2",
        name: "WKSTN-02",
        type: "host",
        fqdn: "wkstn-02.corp.local",
        ip: "10.1.10.102",
      },
      classes: "cy-node cy-node-host",
      position: { x: 350, y: 450 },
    },
    {
      data: {
        id: "user1",
        name: "Alice",
        type: "user",
        sam: "CORP\\Alice",
        ip: "10.1.10.50",
        ntlm_hash: "AliceHash",
      },
      classes: "cy-node cy-node-user",
      position: { x: 100, y: 550 },
    },
    {
      data: {
        id: "user2",
        name: "Bob",
        type: "user",
        sam: "CORP\\Bob",
        ip: "10.1.10.51",
        ntlm_hash: "BobHash",
      },
      classes: "cy-node cy-node-user",
      position: { x: 350, y: 550 },
    },
    {
      data: {
        id: "admin1",
        name: "DomainAdmin",
        type: "admin",
        sam: "CORP\\DomainAdmin",
        ip: "10.1.1.5",
        ntlm_hash: "DAHash",
      },
      classes: "cy-node cy-node-admin high-value",
      position: { x: 225, y: 100 },
    },
    // Attacker
    {
      data: {
        id: "attacker",
        name: "Attacker",
        type: "attacker",
        ip: "192.168.1.100",
      },
      classes: "cy-node cy-node-attacker",
      position: { x: 150, y: 250 },
    },
    // Hidden KRBTGT
    {
      data: {
        id: "krbtgt",
        name: "krbtgt",
        type: "svc",
        sam: "CORP\\krbtgt",
        ntlm_hash: "KRBTGT_HASH_SECRET",
      },
      classes: "cy-node cy-node-svc high-value",
      style: { display: "none" },
    },
  ];

  // --- Cytoscape Initialization ---
  function initializeCytoscape(elements) {
    if (cy) {
      cy.destroy();
    }
    cy = cytoscape({
      container: cyContainer,
      elements: JSON.parse(JSON.stringify(elements)),
      style: [
        // ** Base Node Style **
        {
          selector: "node",
          style: {
            width: "60px",
            height: "60px",
            "background-color": "#e0e0e0",
            "border-width": 2,
            "border-color": "#999",
            "text-valign": "bottom",
            "text-halign": "center",
            label: (ele) => {
              const name = ele.data("name") || ele.id();
              const detail = ele.data("fqdn") || ele.data("sam") || "";
              const type = ele.data("type");
              let icon = "";

              switch (type) {
                case "dc":
                  icon = "💾";
                  break;
                case "ca":
                  icon = "📜";
                  break;
                case "user":
                  icon = "👤";
                  break;
                case "admin":
                  icon = "👑";
                  break;
                case "svc":
                  icon = "⚙️";
                  break;
                case "host":
                  icon = "💻";
                  break;
                case "server":
                  icon = "🏢";
                  break;
                case "attacker":
                  icon = "💀";
                  break;
                default:
                  icon = "❓";
              }

              return `${icon}\n${detail}`;
            },
            "text-wrap": "wrap",
            "text-max-width": "80px",
            "text-margin-y": 20,
            "font-size": "24px",
            color: "#333",
            "text-outline-color": "#ffffff",
            "text-outline-width": 2,
            "line-height": 1.1,
            padding: "0px",
            "text-valign": "center",
            "text-halign": "center",
          },
        },

        // ** Node Type Specific Styles (Set Colors) **
        {
          selector: ".cy-node-dc",
          style: { "background-color": "#cce5ff", "border-color": "#0d6efd" },
        },
        {
          selector: ".cy-node-ca",
          style: { "background-color": "#fff3cd", "border-color": "#ffc107" },
        },
        {
          selector: ".cy-node-user",
          style: { "background-color": "#d1e7dd", "border-color": "#198754" },
        },
        {
          selector: ".cy-node-admin",
          style: { "background-color": "#d1e7dd", "border-color": "#b81f1f" },
        },
        {
          selector: ".cy-node-svc",
          style: { "background-color": "#e9ecef", "border-color": "#6c757d" },
        },
        {
          selector: ".cy-node-host",
          style: { "background-color": "#cff4fc", "border-color": "#0dcaf0" },
        },
        {
          selector: ".cy-node-server",
          style: { "background-color": "#cfe2ff", "border-color": "#6f42c1" },
        },
        {
          selector: ".cy-node-attacker",
          style: { "background-color": "#f8d7da", "border-color": "#dc3545" },
        },

        // ** Node State Styles **
        {
          selector: "node.highlighted",
          style: {
            "border-color": "#ffc107", // Yellow border
            "border-width": 4,
            shape: "ellipse",
            "background-color": "#fff3cd", // Light yellow background
          },
        },
        {
          selector: "node.compromised",
          style: {
            "background-color": "#f8d7da", // Light red background
            "border-color": "#dc3545", // Red border
            "border-width": 4,
            "border-style": "dashed",
            shape: "octagon", // Different shape to stand out
          },
        },
        {
          selector: ".delegation-unconstrained",
          style: {
            "border-style": "dotted",
            "border-width": 3,
            "border-color": "#6f42c1",
          },
        },
        {
          selector: ".delegation-constrained",
          style: {
            "border-style": "dotted",
            "border-width": 3,
            "border-color": "#0dcaf0",
          },
        },
        { selector: ".high-value", style: { shape: "star" } },

        // ** Edge styles **
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#adb5bd",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#adb5bd",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "18px",
            color: "#f8f9fa",
            "text-rotation": "autorotate",
            "text-background-color": "#343a40",
            "text-background-opacity": 0.8,
            "text-background-padding": "1px",
            "text-background-shape": "roundrectangle",
          },
        },
        {
          selector: ".kerberos-edge",
          style: {
            "line-color": "#4dabf7",
            "target-arrow-color": "#4dabf7",
            width: 2.5,
            "z-index": 10,
          },
        },
        {
          selector: ".ldap-edge",
          style: {
            "line-color": "#ffec99",
            "target-arrow-color": "#ffec99",
            width: 2.5,
            "line-style": "dashed",
            "z-index": 10,
          },
        },
        {
          selector: ".drsuapi-edge",
          style: {
            "line-color": "#ff8787",
            "target-arrow-color": "#ff8787",
            width: 3,
            "line-style": "dotted",
            "z-index": 11,
          },
        },
        {
          selector: ".rpc-edge",
          style: {
            "line-color": "#fcc2d7",
            "target-arrow-color": "#fcc2d7",
            width: 2,
            "line-style": "dotted",
            "z-index": 9,
          },
        },
        {
          selector: ".smb-edge",
          style: {
            "line-color": "#ffa94d",
            "target-arrow-color": "#ffa94d",
            width: 2.5,
            "line-style": "dashed",
            "z-index": 9,
          },
        },
        {
          selector: ".ntlm-edge",
          style: {
            "line-color": "#f783ac",
            "target-arrow-color": "#f783ac",
            width: 2.5,
            "line-style": "dashed",
            "z-index": 10,
          },
        },
        {
          selector: ".dns-edge",
          style: {
            "line-color": "#b197fc",
            "target-arrow-color": "#b197fc",
            width: 2,
            "line-style": "dotted",
            "z-index": 8,
          },
        },
        {
          selector: ".http-edge",
          style: {
            "line-color": "#63e6be",
            "target-arrow-color": "#63e6be",
            width: 2,
            "z-index": 8,
          },
        },
        {
          selector: ".attack-flow",
          style: {
            "line-color": "#e03131",
            "target-arrow-color": "#e03131",
            width: 3,
            "z-index": 12,
          },
        },
        { selector: ".temp-edge", style: { opacity: 0.9 } },
      ],
      layout: { name: "preset" }, // Use preset layout based on initial positions
    });

    // --- Event Handlers ---
    cy.on("mouseover", "node", (event) => event.target.addClass("highlighted"));
    cy.on("mouseout", "node", (event) => {
      if (
        !event.target.hasClass("compromised") &&
        !event.target.scratch("_sim_highlighted")
      ) {
        event.target.removeClass("highlighted");
      }
    });
    cy.nodes().grabify();
  } // --- End of initializeCytoscape ---

  // --- Simulation Logic ---

  function clearManualStepEdges() {
    if (cy && manualStepEdges.length > 0) {
      cy.batch(() => {
        manualStepEdges.forEach((edgeId) => {
          const edge = cy.getElementById(edgeId);
          if (edge.length > 0) {
            cy.remove(edge);
          }
        });
      });
    }
    manualStepEdges = [];
  }

  function resetSimulationState(clearLog = true) {
    clearTimeout(simulationTimeout);
    simulationTimeout = null;
    currentScenario = [];
    currentStep = -1;
    isRunning = false;
    clearManualStepEdges();

    if (clearLog) logContent.innerHTML = "Simulation reset.\n";

    if (cy) {
      cy.remove(".temp-edge");
      cy.nodes().removeClass("highlighted compromised");
      cy.nodes().removeScratch("_sim_highlighted");
    } else {
      initializeCytoscape(initialElements);
    }
    updateButtonStates();
    if (clearLog) log("Select a scenario to start.", "info");
  }

  function highlightElement(
    id,
    duration = stepDelay * 0.8,
    className = "highlighted"
  ) {
    const ele = cy.getElementById(id);
    if (ele?.length > 0) {
      ele.addClass(className);
      if (className === "highlighted") {
        ele.scratch("_sim_highlighted", true);
        setTimeout(() => {
          const currentEle = cy.getElementById(id);
          if (
            currentEle?.length > 0 &&
            currentEle.scratch("_sim_highlighted")
          ) {
            currentEle.removeClass(className);
            currentEle.removeScratch("_sim_highlighted");
          }
        }, duration);
      }
    } else {
      console.warn(`Highlight target not found: ${id}`);
      log(`Warn: Cannot highlight missing element ${id}`, "fail");
    }
  }

  function addTemporaryEdge(
    sourceId,
    targetId,
    protocol,
    label = "",
    duration = stepDelay * 0.9
  ) {
    let edgeClass = `temp-edge ${protocol.toLowerCase()}-edge`;
    const edgeId = `temp-${sourceId}-${targetId}-${Date.now()}-${Math.random()
      .toString(16)
      .substring(2)}`;
    const sourceNode = cy.getElementById(sourceId);
    const targetNode = cy.getElementById(targetId);

    if (!sourceNode?.length) {
      log(`Error: Source node ${sourceId} for edge not found.`, "fail");
      return null;
    }
    if (!targetNode?.length) {
      log(`Error: Target node ${targetId} for edge not found.`, "fail");
      return null;
    }

    try {
      const newEdge = cy.add({
        group: "edges",
        data: {
          id: edgeId,
          source: sourceId,
          target: targetId,
          label: label || protocol.toUpperCase(),
        },
        classes: edgeClass,
      });
      if (!isManualMode) {
        setTimeout(() => {
          try {
            const edgeToRemove = cy.getElementById(edgeId);
            if (edgeToRemove?.length > 0) {
              cy.remove(edgeToRemove);
            }
          } catch (e) {
            /* Ignore */
          }
        }, duration);
      } else {
        manualStepEdges.push(edgeId);
      }
      return newEdge;
    } catch (error) {
      console.error(
        `Error adding edge ${edgeId} from ${sourceId} to ${targetId}:`,
        error
      );
      log(
        `Error visualizing: ${sourceId} -> ${targetId} (${protocol})`,
        "fail"
      );
      return null;
    }
  }

  // --- Step Execution Functions ---
  function executeSingleStep(stepIndex) {
    if (
      !currentScenario ||
      stepIndex < 0 ||
      stepIndex >= currentScenario.length
    )
      return;
    const step = currentScenario[stepIndex];
    if (!(stepIndex === 0 && step.scenarioName)) {
      log(step.logMessage, step.logType || "info");
    }
    if (step.action && typeof step.action === "function") {
      try {
        step.action();
      } catch (e) {
        console.error("Error executing action for step", stepIndex, ":", e);
        log(`Step Error: ${e.message}`, "fail");
      }
    }
    updateButtonStates();
  }

  function executeStepsAutomatically() {
    if (
      !isRunning ||
      isManualMode ||
      currentStep >= currentScenario.length - 1
    ) {
      if (isRunning && currentStep >= currentScenario.length - 1) {
        resetSimulationState(false);
      }
      clearTimeout(simulationTimeout);
      simulationTimeout = null;
      return;
    }
    currentStep++;
    const step = currentScenario[currentStep];
    if (!(currentStep === 0 && step.scenarioName)) {
      log(step.logMessage, step.logType || "info");
    }
    if (step.action && typeof step.action === "function") {
      try {
        step.action();
      } catch (e) {
        console.error("Error executing auto action:", e);
        log(`Step Error: ${e.message}`, "fail");
      }
    }
    simulationTimeout = setTimeout(
      executeStepsAutomatically,
      step.delay || stepDelay
    );
  }

  function startScenario(scenario) {
    if (isRunning) {
      log("Another simulation is running. Please Reset first.", "fail");
      return;
    }
    resetSimulationState(true);
    isRunning = true;
    isManualMode = manualModeCheckbox.checked;

    setTimeout(() => {
      currentScenario = scenario;
      currentStep = -1;
      if (!currentScenario || currentScenario.length === 0) {
        log("Error: Selected scenario is empty.", "fail");
        isRunning = false;
        updateButtonStates();
        return;
      }
      const scenarioName =
        currentScenario[0]?.scenarioName || "Unnamed Scenario";
      log(`--- Starting Scenario: ${scenarioName} ---`, "info");
      updateButtonStates();

      if (isManualMode) {
        manualControlsDiv.classList.add("active");
        handleNextStep(); // Execute first step
      } else {
        manualControlsDiv.classList.remove("active");
        simulationTimeout = setTimeout(
          executeStepsAutomatically,
          (currentScenario[0]?.delay || stepDelay) / 2
        );
      }
    }, 100);
  }

  // --- Button Handlers ---
  function handleNextStep() {
    if (!isRunning || !isManualMode) return;
    if (currentStep >= currentScenario.length - 1) {
      resetSimulationState(false); // Finish
      return;
    }
    clearManualStepEdges();
    currentStep++;
    executeSingleStep(currentStep);
  }

  // --- UI State Manager ---
  function updateButtonStates() {
    const scenarioRunning = isRunning && currentScenario.length > 0;
    scenarioButtons.forEach((button) => (button.disabled = scenarioRunning));
    manualModeCheckbox.disabled = scenarioRunning;
    resetButton.disabled = !scenarioRunning;

    if (scenarioRunning && isManualMode) {
      manualControlsDiv.classList.add("active");
      nextStepButton.disabled = false;
      if (currentStep >= currentScenario.length - 1) {
        nextStepButton.innerHTML =
          '<i class="fas fa-flag-checkered"></i> Finish';
      } else {
        nextStepButton.innerHTML = '<i class="fas fa-forward-step"></i> Next';
      }
    } else {
      manualControlsDiv.classList.remove("active");
      nextStepButton.disabled = true;
      nextStepButton.innerHTML = '<i class="fas fa-forward-step"></i> Next';
    }
  }

  // --- Scenario Definitions (LDAP steps verified/added where necessary) ---
  const legitimateLogonScenario = [
    {
      scenarioName: "Standard User Kerberos Logon",
      logMessage: "User Alice (user1) initiates logon to WKSTN-01 (host1).",
      logType: "info",
      action: () => {
        highlightElement("user1");
        highlightElement("host1");
      },
    },
    {
      logMessage:
        "WKSTN-01 -> DC01: DNS SRV Query for _kerberos._tcp.corp.local (Find KDC).",
      logType: "dns",
      action: () => addTemporaryEdge("host1", "dc01", "DNS", "SRV Query"),
    },
    {
      logMessage: "DC01 -> WKSTN-01: DNS Response (KDC = dc01.corp.local).",
      logType: "dns",
      action: () => addTemporaryEdge("dc01", "host1", "DNS", "SRV Resp"),
    },
    {
      logMessage:
        "Alice (on host1) -> DC01: Kerberos AS-REQ (Requesting Ticket Granting Ticket - TGT). Includes timestamp encrypted with user's hash (pre-auth).",
      logType: "kerberos",
      action: () => addTemporaryEdge("host1", "dc01", "Kerberos", "AS-REQ"),
    },
    {
      logMessage:
        "DC01: Validates pre-authentication (decrypts timestamp), Creates TGT containing user's SID and group SIDs (PAC).",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Alice (on host1): Kerberos AS-REP (Sending TGT encrypted with user's hash, Session Key encrypted with user's hash).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "host1", "Kerberos", "AS-REP (TGT)"),
    },
    {
      logMessage:
        "Alice (on host1) -> DC01: Kerberos TGS-REQ (Using TGT, Requesting Service Ticket - ST for host/WKSTN-01).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("host1", "dc01", "Kerberos", "TGS-REQ (Host)"),
    },
    {
      logMessage:
        "DC01: Validates TGT & PAC signature, Finds SPN for host/WKSTN-01 (implicit), Generates Service Ticket (ST) including PAC.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Alice (on host1): Kerberos TGS-REP (Sending ST encrypted with WKSTN-01's machine account hash, Session Key encrypted with TGT Session Key).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "host1", "Kerberos", "TGS-REP (ST)"),
    },
    {
      logMessage:
        "Alice (on host1) -> WKSTN-01: Kerberos AP-REQ (Presenting ST & Authenticator encrypted with ST Session Key).",
      logType: "kerberos",
      // Note: Technically, this is LSASS on host1 presenting to itself (the host service).
      action: () => addTemporaryEdge("host1", "host1", "Kerberos", "AP-REQ"),
    },
    {
      logMessage:
        "WKSTN-01 (Host Service): Decrypts ST with its machine key, Validates Authenticator using ST Session Key, Extracts PAC for authorization info.",
      logType: "kerberos",
      action: () => highlightElement("host1"),
    },
    {
      // Note: PAC validation might involve RPC to DC, depending on config.
      // This LDAP search is often for additional user details/AuthZ context beyond PAC.
      logMessage:
        "WKSTN-01 -> DC01: LDAP Search (Optional: Using PAC info/user SID, Get Alice's full group memberships/details for AuthZ).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("host1", "dc01", "LDAP", "LDAP AuthZ Lookup"),
    },
    {
      logMessage:
        "DC01 -> WKSTN-01: LDAP Search Result (Alice's details/groups).",
      logType: "ldap",
      action: () => addTemporaryEdge("dc01", "host1", "LDAP", "LDAP Result"),
    },
    {
      // GPO processing happens after successful authentication
      logMessage:
        "WKSTN-01 -> DC01: SMB Access (Read GPOs from SYSVOL share using authenticated user context).",
      logType: "smb",
      action: () =>
        addTemporaryEdge("host1", "dc01", "SMB", "SYSVOL Read (GPO)"),
    },
    {
      logMessage:
        "Logon successful for Alice on WKSTN-01. Session established.",
      logType: "success",
      action: () => highlightElement("host1", stepDelay, "highlighted"),
    },
  ];

  const legitAdminGroupScenario = [
    {
      scenarioName: "Admin Adds User to Group via LDAP",
      logMessage:
        "Admin (admin1) uses ADUC (or similar tool) on their workstation to add Bob (user2) to 'AppUsers' group.",
      logType: "info",
      action: () => {
        highlightElement("admin1"); // Represents admin's action/context
        highlightElement("user2"); // Represents the target user
      },
    },
    {
      logMessage:
        "Admin Tool -> DC01: LDAP Bind Request (Authenticated as CORP\\Admin1, likely via Kerberos/Negotiate).",
      logType: "ldap",
      action: () => addTemporaryEdge("admin1", "dc01", "LDAP", "Bind"), // Edge from admin context
    },
    {
      logMessage:
        "DC01: Authenticates Admin (via Kerberos Ticket or NTLM). Verifies Bind.",
      logType: "ldap",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "Admin Tool -> DC01: LDAP Search (Find DN for user 'Bob', e.g., filter: '(sAMAccountName=user2)').",
      logType: "ldap",
      action: () => addTemporaryEdge("admin1", "dc01", "LDAP", "Search User"),
    },
    {
      logMessage:
        "DC01 -> Admin Tool: LDAP Search Result (Returns Bob's DistinguishedName - DN).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("dc01", "admin1", "LDAP", "Result User DN"),
    },
    {
      logMessage:
        "Admin Tool -> DC01: LDAP Search (Find DN for group 'AppUsers', e.g., filter: '(cn=AppUsers)').",
      logType: "ldap",
      action: () => addTemporaryEdge("admin1", "dc01", "LDAP", "Search Group"),
    },
    {
      logMessage:
        "DC01 -> Admin Tool: LDAP Search Result (Returns Group's DN).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("dc01", "admin1", "LDAP", "Result Group DN"),
    },
    {
      logMessage:
        "Admin Tool -> DC01: LDAP Modify Request (Operation: Add, Attribute: 'member', Value: Bob's DN) on the 'AppUsers' group object.",
      logType: "ldap",
      action: () => {
        highlightElement("dc01");
        highlightElement("user2"); // Target of the modification
        addTemporaryEdge("admin1", "dc01", "LDAP", "Modify Member");
      },
    },
    {
      logMessage:
        "DC01: Performs ACL check (Verifies Admin1 has 'WriteProperty - Member' rights on the group), Updates group membership attribute.",
      logType: "ldap",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 -> Admin Tool: LDAP Modify Response (Success).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("dc01", "admin1", "LDAP", "Modify Success"),
    },
    {
      logMessage: "Bob (user2) is now a member of the 'AppUsers' group.",
      logType: "success",
    },
  ];

  const legitGpoUpdateScenario = [
    {
      scenarioName: "Computer GPO Update Check",
      logMessage:
        "WKSTN-02 (host2) System process initiates background GPO update.",
      logType: "info",
      action: () => highlightElement("host2"),
    },
    {
      logMessage:
        "WKSTN-02 -> DC01: LDAP Search (using machine account context, Read Computer object's own attributes: DN, site, linked GPOs via gpLink attribute).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("host2", "dc01", "LDAP", "Get Computer/GPO Info"),
    },
    {
      logMessage:
        "DC01 -> WKSTN-02: LDAP Result (Computer DN, Site DN, list of linked GPO paths).",
      logType: "ldap",
      action: () => addTemporaryEdge("dc01", "host2", "LDAP", "Result"),
    },
    {
      logMessage:
        "WKSTN-02 -> DC01: LDAP Search (For each linked GPO path, read GPO attributes: versionNumber, gPCFileSysPath).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("host2", "dc01", "LDAP", "Read GPO Details"),
    },
    {
      logMessage:
        "DC01 -> WKSTN-02: LDAP Result (GPO versions and SYSVOL paths).",
      logType: "ldap",
      action: () => addTemporaryEdge("dc01", "host2", "LDAP", "Result"),
    },
    {
      logMessage:
        "WKSTN-02: Compares received GPO versions (from AD) with locally cached versions. Detects newer version required.",
      logType: "info",
      action: () => highlightElement("host2"),
    },
    {
      // Authentication likely uses machine account Kerberos ticket for DC's CIFS service
      logMessage:
        "WKSTN-02 -> DC01: SMB Access (Reads updated GPO files/scripts from SYSVOL path specified in gPCFileSysPath attribute).",
      logType: "smb",
      action: () =>
        addTemporaryEdge("host2", "dc01", "SMB", "SYSVOL Read (GPO)"),
    },
    {
      logMessage: "WKSTN-02 applies updated computer policies locally.",
      logType: "success",
      action: () => highlightElement("host2", stepDelay, "highlighted"),
    },
  ];

  const legitCertRequestScenario = [
    {
      scenarioName: "User Certificate Enrollment (AD CS)",
      logMessage:
        "Alice (user1) on WKSTN-01 initiates certificate request (manual via certlm.msc or autoenrollment) for 'User' template.",
      logType: "info",
      action: () => {
        highlightElement("user1");
        highlightElement("host1");
      },
    },
    {
      // Locating CAs published in AD
      logMessage:
        "WKSTN-01 -> DC01: LDAP Search (Find CAs: Query objects in CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,...).",
      logType: "ldap",
      action: () => addTemporaryEdge("host1", "dc01", "LDAP", "LDAP Find CA"),
    },
    {
      logMessage:
        "DC01 -> WKSTN-01: LDAP Result (List of available CAs, e.g., CA01).",
      logType: "ldap",
      action: () => addTemporaryEdge("dc01", "host1", "LDAP", "Result CA Info"),
    },
    {
      // Reading template details to build the request
      logMessage:
        "WKSTN-01 -> DC01: LDAP Search (Read 'User' Certificate Template object details: CN=User,CN=Certificate Templates,...).",
      logType: "ldap",
      action: () => addTemporaryEdge("host1", "dc01", "LDAP", "Read Template"),
    },
    {
      logMessage:
        "DC01 -> WKSTN-01: LDAP Result (Template details: flags, key usage, enrollment permissions, etc.).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("dc01", "host1", "LDAP", "Result Template Info"),
    },
    {
      // Communicating with the CA service (often RPC over SMB named pipes or HTTP if CES/CEP is used)
      logMessage:
        "WKSTN-01 -> CA01: RPC Request (ICertRequestD2::RequestCertificate using 'User' template info, authenticated as Alice).",
      logType: "rpc", // or HTTP
      action: () => addTemporaryEdge("host1", "ca01", "RPC", "Cert Request"),
    },
    {
      logMessage:
        "CA01: Receives request. Checks template ACLs (Does Alice have Enroll permission?). Builds certificate based on template & user attributes (UPN/SID from Auth).",
      logType: "info",
      action: () => {
        highlightElement("ca01");
        // CA may query DC for user details or group memberships if needed for template rules/issuance
        addTemporaryEdge("ca01", "dc01", "LDAP", "Check Perms/Attribs");
      },
    },
    {
      logMessage:
        "CA01 -> WKSTN-01: RPC Response (Issued Certificate or error/pending status).",
      logType: "rpc", // or HTTP
      action: () => addTemporaryEdge("ca01", "host1", "RPC", "Cert Issued"),
    },
    {
      logMessage:
        "Alice's certificate store on WKSTN-01 updated with the new certificate.",
      logType: "success",
      action: () => highlightElement("user1"),
    },
  ];

  const legitFileShareAccessScenario = [
    {
      scenarioName: "User Accesses SMB File Share",
      logMessage:
        "Bob (user2) on WKSTN-02 tries to access file share \\\\FILES01\\Share.",
      logType: "info",
      action: () => {
        highlightElement("user2");
        highlightElement("host2");
      },
    },
    {
      logMessage: "WKSTN-02 -> DC01: DNS A Query for files01.corp.local.",
      logType: "dns",
      action: () => addTemporaryEdge("host2", "dc01", "DNS", "A Query"),
    },
    {
      logMessage: "DC01 -> WKSTN-02: DNS Response (IP address for FILES01).",
      logType: "dns",
      action: () => addTemporaryEdge("dc01", "host2", "DNS", "A Resp"),
    },
    {
      // Get Kerberos Service Ticket for the file server's CIFS service
      logMessage:
        "Bob (on host2) -> DC01: Kerberos TGS-REQ (Using Bob's TGT, Requesting ST for SPN: cifs/files01.corp.local).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("host2", "dc01", "Kerberos", "TGS-REQ (CIFS)"),
    },
    {
      logMessage:
        "DC01: Validates TGT, Finds SPN via internal lookup, Issues ST for FILES01 encrypted with FILES01 machine account hash.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Bob (on host2): Kerberos TGS-REP (Sending ST and Session Key).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "host2", "Kerberos", "TGS-REP (ST)"),
    },
    {
      // Start SMB communication with the file server
      logMessage:
        "Bob (on host2) -> FILES01: SMB Negotiate Protocol Request (Determine SMB dialect).",
      logType: "smb",
      action: () =>
        addTemporaryEdge("host2", "srv_files01", "SMB", "Negotiate"),
    },
    {
      logMessage:
        "FILES01 -> Bob (on host2): SMB Negotiate Protocol Response (Agree on dialect, e.g., SMB 3.1.1).",
      logType: "smb",
      action: () =>
        addTemporaryEdge("srv_files01", "host2", "SMB", "Negotiate Resp"),
    },
    {
      // Authenticate the SMB session using the Kerberos Service Ticket
      logMessage:
        "Bob (on host2) -> FILES01: SMB Session Setup Request + Kerberos AP-REQ (Presenting ST for cifs/files01...).",
      logType: "smb", // Includes Kerberos payload
      action: () => {
        highlightElement("srv_files01");
        addTemporaryEdge("host2", "srv_files01", "SMB", "Session Setup");
        addTemporaryEdge("host2", "srv_files01", "Kerberos", "AP-REQ");
      },
    },
    {
      logMessage:
        "FILES01 (CIFS Service): Decrypts ST with its machine key, validates authenticator, checks PAC for AuthZ info (Bob's SIDs).",
      logType: "kerberos", // Server-side validation
      action: () => highlightElement("srv_files01"),
    },
    {
      logMessage:
        "FILES01 -> Bob (on host2): SMB Session Setup Response (Success, session established).",
      logType: "smb",
      action: () =>
        addTemporaryEdge("srv_files01", "host2", "SMB", "Session OK"),
    },
    {
      // Connect to the specific share requested
      logMessage:
        "Bob (on host2) -> FILES01: SMB Tree Connect Request (Path: \\\\FILES01\\Share).",
      logType: "smb",
      action: () =>
        addTemporaryEdge("host2", "srv_files01", "SMB", "Tree Connect"),
    },
    {
      logMessage:
        "FILES01: Checks Share-Level Permissions for 'Share' for Bob (using SIDs from PAC).",
      logType: "smb", // Authorization Check
      action: () => highlightElement("srv_files01"),
    },
    {
      logMessage:
        "FILES01 -> Bob (on host2): SMB Tree Connect Response (Success, share connected).",
      logType: "smb",
      action: () => addTemporaryEdge("srv_files01", "host2", "SMB", "Tree OK"),
    },
    {
      logMessage:
        "Bob can now perform file operations (Read/Write/etc.) based on NTFS permissions on the share.",
      logType: "success",
    },
  ];

  // == ATTACK SCENARIOS ==
  const attackPasswordSprayScenario = [
    {
      scenarioName: "Attack: Password Spray (Kerberos Pre-Auth)",
      logMessage:
        "Attacker Goal: Find valid credentials by trying one password against many accounts.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "[Optional Recon] Attacker -> DC01: LDAP Search (e.g., '(objectClass=user)') to get list of usernames.",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Enum Users"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ for User1 with Password 'Winter2024'. (No valid TGT expected initially).",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (Spray U1)"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos Error (KRB5KDC_ERR_PREAUTH_FAILED - Incorrect password).",
      logType: "kerberos",
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "Error"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ for User2 with Password 'Winter2024'.",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (Spray U2)"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos Error (KRB5KDC_ERR_PREAUTH_FAILED).",
      logType: "kerberos",
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "Error"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ for User3 (Alice - user1) with Password 'Winter2024'.",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (Spray U3)"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos AS-REP (Success! Password 'Winter2024' is valid for Alice). TGT Issued.",
      logType: "success",
      action: () => {
        highlightElement("user1", stepDelay, "compromised"); // Mark user as potentially compromised
        addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (Success!)");
      },
    },
    {
      logMessage:
        "IMPACT: Attacker identified valid credentials (user1:Winter2024). Can now authenticate as Alice, access resources she has access to, and perform further recon/attacks.",
      logType: "success",
    },
  ];

  const attackKerberoastingScenario = [
    {
      scenarioName: "Attack: Kerberoasting",
      logMessage:
        "Attacker Goal: Obtain crackable hash for a service account password.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker needs *any* valid domain user credentials (low privilege is sufficient).",
      logType: "info",
    },
    {
      logMessage:
        "Attacker (as UserX) -> DC01: LDAP Search (Filter: '(servicePrincipalName=*)', requesting SPN attribute). Find accounts with SPNs (potential service accounts).",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Find SPNs"),
    },
    {
      logMessage:
        "DC01 -> Attacker: LDAP Result (List of accounts and their SPNs, e.g., 'svc_sql01' has SPN 'MSSQLSvc/sql01.corp.local:1433').",
      logType: "ldap",
      action: () => addTemporaryEdge("dc01", "attacker", "LDAP", "SPN List"),
    },
    {
      logMessage:
        "Attacker (as UserX) -> DC01: Kerberos TGS-REQ (Requesting ST for a found SPN, e.g., 'MSSQLSvc/sql01...'). Uses UserX's TGT.",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ (Roast)"),
    },
    {
      logMessage:
        "DC01: Validates UserX's TGT. Finds the service account ('svc_sql01') linked to the SPN.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker (as UserX): Kerberos TGS-REP (Service Ticket ST). Crucially, the ticket is encrypted using the *service account's (svc_sql01)* NTLM hash.",
      logType: "kerberos",
      action: () => {
        highlightElement("svc_sql01"); // Target service account
        addTemporaryEdge(
          "dc01",
          "attacker",
          "Kerberos",
          "TGS-REP (Encrypted ST)"
        );
      },
    },
    {
      logMessage:
        "Attacker: Extracts the encrypted portion of the TGS-REP (the Service Ticket). No communication needed.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Performs OFFLINE cracking (e.g., using Hashcat, John the Ripper) against the extracted ST blob using a wordlist.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Successfully cracks the hash, revealing svc_sql01's password.",
      logType: "success",
      action: () => highlightElement("svc_sql01", stepDelay, "compromised"),
    },
    {
      logMessage:
        "IMPACT: Attacker knows the service account password. Can authenticate *as* svc_sql01, potentially access sensitive systems (like SQL server), run commands as the service, or use its privileges for lateral movement.",
      logType: "success",
    },
  ];

  const attackASREPRoastingScenario = [
    {
      scenarioName: "Attack: AS-REP Roasting",
      logMessage:
        "Attacker Goal: Obtain crackable hash for users with Kerberos pre-authentication disabled.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker needs network visibility to a KDC (DC) but NO domain credentials required.",
      logType: "info",
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Optional, if creds available: Filter: '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' - DONT_REQ_PREAUTH flag). Finds users without pre-auth required.",
      logType: "ldap", // Or attacker may guess usernames
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Find NoPreauth"),
    },
    {
      logMessage:
        "Attacker: Identifies/Guesses target username (e.g., 'svc_backup') known or suspected to have pre-auth disabled.",
      logType: "info",
      action: () => highlightElement("svc_backup"), // Example target user
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ for 'svc_backup'. Critically, the request does NOT include a pre-authentication timestamp.",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (NoPreAuth)"),
    },
    {
      logMessage:
        "DC01: Finds user 'svc_backup'. Checks userAccountControl flag. Sees DONT_REQ_PREAUTH is TRUE. Skips pre-auth validation.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos AS-REP (Sending TGT). Crucially, the AS-REP message contains a portion encrypted with the *user's (svc_backup)* NTLM hash.",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (Encrypted)"),
    },
    {
      logMessage:
        "Attacker: Extracts the encrypted portion of the AS-REP. No further communication needed.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Performs OFFLINE cracking (e.g., Hashcat mode 18200) against the extracted blob using a wordlist.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Successfully cracks the hash, revealing svc_backup's password.",
      logType: "success",
      action: () => highlightElement("svc_backup", stepDelay, "compromised"),
    },
    {
      logMessage:
        "IMPACT: Attacker knows the user's password without initially having any credentials. Can authenticate as that user, access resources, and perform further actions.",
      logType: "success",
    },
  ];
  const attackGoldenTicketScenario = [
    {
      scenarioName: "Attack: Golden Ticket Forgery & Use",
      logMessage:
        "Attacker Goal: Forge a Kerberos TGT to impersonate any user (e.g., Domain Admin) without needing their password.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has obtained the KRBTGT account's NTLM hash or AES key (e.g., via DCSync). Also needs Domain SID.",
      logType: "attack",
      action: () => {
        highlightElement("krbtgt", stepDelay, "compromised"); // Essential prerequisite
      },
    },
    {
      // Attacker may need Domain SID, easily obtainable via LDAP anonymously or with any user creds
      logMessage:
        "[Optional Recon] Attacker -> DC01: LDAP Search (Get Domain SID from RootDSE or Domain object).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Get Domain SID"),
    },
    {
      logMessage:
        "Attacker: Uses tool (Mimikatz, Rubeus) OFFLINE to craft a fake TGT. Specifies target username (e.g., 'Administrator'), UserID (e.g., 500), desired group SIDs (e.g., Domain Admins - 512), Domain SID, and encrypts/signs it using the stolen KRBTGT hash/key.",
      logType: "attack", // Offline action
      action: () => {
        highlightElement("attacker");
        highlightElement("admin1"); // Represents the impersonated DA
      },
    },
    {
      logMessage:
        "Attacker: Injects the forged Golden Ticket into their current logon session's memory.",
      logType: "attack", // Local action on attacker machine
      action: () => highlightElement("attacker"),
    },
    {
      // Now, use the forged TGT to access resources as the impersonated Admin
      logMessage:
        "Attacker (using forged DA TGT) -> DC01: Kerberos TGS-REQ (Requesting ST for LDAP/dc01... service).",
      logType: "attack", // Appears as DA to the DC
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ (Golden)"),
    },
    {
      logMessage:
        "DC01: Validates TGT (signed correctly with KRBTGT key - accepts it!). Issues ST for LDAP service as requested by 'Administrator'.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos TGS-REP (Sending ST for LDAP/dc01).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "TGS-REP (ST)"),
    },
    {
      logMessage:
        "Attacker (using ST) -> DC01: LDAP Operations (e.g., Add user to Domain Admins, Modify ACLs). Authenticated as Administrator.",
      logType: "attack", // Successful privileged action
      action: () => {
        highlightElement("dc01", stepDelay, "compromised");
        addTemporaryEdge("attacker", "dc01", "LDAP", "LDAP Modify (as DA)");
      },
    },
    {
      logMessage:
        "IMPACT: Attacker has achieved Domain Admin level access without knowing any DA password. Can impersonate *any* user by forging tickets. Provides long-term persistence as long as KRBTGT hash isn't changed *twice*.",
      logType: "success",
    },
  ];

  const attackSilverTicketScenario = [
    {
      scenarioName: "Attack: Silver Ticket",
      logMessage: "Attacker has compromised service account hash",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("srv_sql01");
      },
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Get service account's SID)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Get SID"),
    },
    {
      logMessage:
        "Attacker: Forges service ticket for MSSQLSvc/SRV-SQL-01.contoso.com",
      logType: "kerberos",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Sets ticket flags (forwardable, renewable, pre-authent)",
      logType: "kerberos",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker -> SRV-SQL-01: Kerberos AP-REQ (Present forged ticket)",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("attacker", "srv_sql01", "Kerberos", "AP-REQ"),
    },
    {
      logMessage: "SRV-SQL-01: Accepts forged ticket (no KDC validation)",
      logType: "kerberos",
      action: () => highlightElement("srv_sql01"),
    },
    {
      logMessage: "Attacker -> SRV-SQL-01: SQL Query (Enable xp_cmdshell)",
      logType: "sql",
      action: () =>
        addTemporaryEdge("attacker", "srv_sql01", "SQL", "Enable xp_cmdshell"),
    },
    {
      logMessage:
        "Attacker -> SRV-SQL-01: SQL Query (Execute command via xp_cmdshell)",
      logType: "sql",
      action: () =>
        addTemporaryEdge("attacker", "srv_sql01", "SQL", "Execute Command"),
    },
    {
      logMessage:
        "SILVER TICKET SUCCESSFUL: Attacker forged service ticket for SQL01. Can now access SQL01 as any user, execute commands with elevated privileges, and potentially run code via xp_cmdshell.",
      logType: "success",
    },
  ];

  const attackSharpHoundScenario = [
    {
      scenarioName: "Attack: BloodHound Enumeration (SharpHound)",
      logMessage:
        "Attacker Goal: Map Active Directory objects, relationships, ACLs, and sessions to find attack paths.",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        // Assumes attacker has compromised host2 and is running as user1
        highlightElement("host2", stepDelay, "compromised");
        highlightElement("user1");
      },
    },
    {
      logMessage:
        "Prerequisite: Attacker needs valid domain credentials (user1 in this case).",
      logType: "info",
    },
    {
      logMessage:
        "SharpHound (host2 as user1) -> DC01: LDAP Searches (Collecting Users, Groups, Computers, Trusts, OUs, GPOs). High volume of reads.",
      logType: "ldap",
      action: () => addTemporaryEdge("host2", "dc01", "LDAP", "Enum Objects"),
      delay: 500, // Simulate time for multiple queries
    },
    {
      logMessage:
        "SharpHound (host2 as user1) -> DC01: LDAP Searches (Collecting Group Memberships).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("host2", "dc01", "LDAP", "Enum Memberships"),
      delay: 500,
    },
    {
      logMessage:
        "SharpHound (host2 as user1) -> DC01: LDAP Searches (Collecting Object ACLs - Who can control what?). Very high volume.",
      logType: "ldap",
      action: () => addTemporaryEdge("host2", "dc01", "LDAP", "Enum ACLs"),
      delay: 1000,
    },
    {
      logMessage:
        "SharpHound (host2 as user1) -> DC01: LDAP Searches (Collecting SPNs for Kerberoasting targets).",
      logType: "ldap",
      action: () => addTemporaryEdge("host2", "dc01", "LDAP", "Enum SPNs"),
      delay: 300,
    },
    {
      logMessage:
        "SharpHound (host2 as user1) -> DC01: SAMR/RPC (Attempt to enumerate members of privileged local groups on DC, e.g., Domain Admins. Often restricted).",
      logType: "rpc",
      action: () => addTemporaryEdge("host2", "dc01", "RPC", "SAMR Enum (DC)"),
      delay: 800,
    },
    {
      logMessage:
        "SharpHound (host2 as user1) -> Domain Computers (e.g., WKSTN-01, SRV-WEB-01): SMB/RPC (NetSessionEnum, NetWkstaUserEnum - Find logged-on users).",
      logType: "smb", // Underlying protocols
      action: () => {
        addTemporaryEdge("host2", "host1", "SMB/RPC", "Session Enum");
        addTemporaryEdge("host2", "srv_web01", "SMB/RPC", "Session Enum");
        addTemporaryEdge("host2", "srv_app01", "SMB/RPC", "Session Enum");
        addTemporaryEdge("host2", "srv_sql01", "SMB/RPC", "Session Enum");
      },
      delay: 1500, // Simulate scanning multiple hosts
    },
    {
      logMessage:
        "SharpHound: Consolidates gathered data into JSON files for BloodHound GUI.",
      logType: "info",
      action: () => highlightElement("host2"),
    },
    {
      logMessage:
        "IMPACT: Attacker has a detailed map of the AD environment. Can visualize privilege escalation paths, identify misconfigurations (ACLs, delegation), find high-value targets, and locate logged-on privileged users.",
      logType: "success",
    },
  ];
  const attackPassTheTicketScenario = [
    {
      scenarioName: "Attack: Pass-the-Ticket (Kerberos)",
      logMessage:
        "Attacker Goal: Authenticate to a service using a stolen Kerberos ticket (TGT or ST).",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has extracted a valid Kerberos TGT for a user (e.g., Alice) from memory on a compromised machine (host1) using Mimikatz.",
      logType: "attack",
      action: () => {
        highlightElement("attacker", stepDelay, "compromised"); // Attacker needs initial access
        highlightElement("host1", stepDelay, "compromised"); // Source of ticket
        highlightElement("user1"); // Owner of stolen TGT
      },
    },
    {
      logMessage:
        "Attacker (from their machine, injecting Alice's TGT): -> DC01: Kerberos TGS-REQ (Using Alice's stolen TGT, Requesting ST for service HTTP/srv-web-01...).",
      logType: "attack", // Attacker initiates, but KDC sees it as Alice
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ (PtT)"),
    },
    {
      logMessage:
        "DC01: Validates the TGT (it's valid, signed by KRBTGT). Issues ST for the requested service (HTTP/srv-web-01). Sees request as coming from Alice.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos TGS-REP (Sending ST for HTTP/srv-web-01, usable by Alice).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "TGS-REP (ST)"),
    },
    {
      logMessage:
        "Attacker (injecting the received ST): -> SRV-WEB-01: Kerberos AP-REQ (Presenting the ST for HTTP/srv-web-01).",
      logType: "attack", // Attacker initiates, but service sees it as Alice
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "Kerberos", "AP-REQ (PtT)"),
    },
    {
      logMessage:
        "SRV-WEB-01: Decrypts ST (with its service key), validates authenticator. Sees the request is authenticated as 'Alice'. Grants access based on Alice's permissions.",
      logType: "kerberos", // Service validates
      action: () => highlightElement("srv_web01", stepDelay, "highlighted"),
    },
    {
      logMessage:
        "IMPACT: Attacker successfully authenticated to SRV-WEB-01 *as Alice* without knowing her password. Can access resources and perform actions as Alice on that service. Can repeat for any service Alice can access.",
      logType: "success",
    },
  ];
  const attackPassTheHashScenario = [
    {
      scenarioName: "Attack: Pass-the-Hash",
      logMessage: "Attacker has obtained user1's NTLM hash",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("user1");
      },
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Check user1's group memberships)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Check Groups"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: SMB Authentication (Using stolen NTLM hash)",
      logType: "smb",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "SMB", "Auth (NTLM)"),
    },
    {
      logMessage: "SRV-WEB-01: Authentication successful",
      logType: "success",
      action: () => highlightElement("srv_web01"),
    },
    {
      logMessage:
        "PASS-THE-HASH SUCCESSFUL: Attacker authenticated as user1. Can now authenticate as user1 to any service, access their resources, and potentially escalate privileges.",
      logType: "success",
    },
  ];
  const attackUnconstrainedDelegationScenario = [
    {
      scenarioName: "Attack: Unconstrained Delegation",
      logMessage:
        "Attacker compromises SRV-APP-01 (srv_app01), which has Unconstrained Delegation.",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("srv_app01", stepDelay, "compromised");
      },
    },
    {
      logMessage: "Legitimate Admin (admin1) logs onto SRV-APP-01 (e.g., RDP).",
      logType: "info",
      action: () => highlightElement("admin1"),
    },
    {
      logMessage:
        "Admin (on their machine) -> SRV-APP-01: Kerberos AP-REQ (Auth to srv_app01)",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("admin1", "srv_app01", "Kerberos", "AP-REQ (Admin)"),
    },
    {
      logMessage:
        "SRV-APP-01: Authenticates Admin. KDC sent Admin's TGT to SRV-APP-01 because of Unconstrained Delegation.",
      logType: "kerberos",
      action: () => highlightElement("srv_app01"),
    },
    {
      logMessage:
        "Attacker (on srv_app01): Uses Mimikatz/Rubeus to extract Admin's forwarded TGT from LSASS memory.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker (on srv_app01) -> DC01: Kerberos TGS-REQ (Using Admin's TGT, requesting ST for LDAP/dc01...)",
      logType: "attack",
      action: () =>
        addTemporaryEdge("srv_app01", "dc01", "Kerberos", "TGS-REQ (as Admin)"),
    },
    {
      logMessage: "DC01: Validates TGT (Admin's), issues ST for LDAP service.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker (on srv_app01): Kerberos TGS-REP (ST for LDAP/dc01)",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "srv_app01", "Kerberos", "TGS-REP (ST)"),
    },
    {
      logMessage:
        "Attacker (on srv_app01) -> DC01: LDAP Operations (Using ST - Authenticated as Admin!)",
      logType: "attack",
      action: () => {
        highlightElement("dc01", stepDelay, "compromised");
        addTemporaryEdge("srv_app01", "dc01", "LDAP", "LDAP Modify (as Admin)");
      },
    },
    {
      logMessage:
        "UNCONSTRAINED DELEGATION ABUSE: Attacker used compromised server to get Admin's TGT and impersonate them. Can now impersonate the Domain Admin, access all domain resources, and maintain persistence even if the admin changes their password.",
      logType: "success",
    },
  ];
  const attackRBCDScenario = [
    {
      scenarioName: "Attack: Resource-Based Constrained Delegation Abuse",
      logMessage:
        "Attacker Goal: Impersonate a user (e.g., Domain Admin) on a target machine (FILES01) by abusing delegation rights.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: Attacker has compromised an account (e.g., machine account 'host1$') that has permission to write to the 'msDS-AllowedToActOnBehalfOfOtherIdentity' attribute of the target computer object (FILES01).",
      logType: "attack",
      action: () => {
        highlightElement("host1", stepDelay, "compromised"); // Attacker controls this principal
        highlightElement("srv_files01"); // Target resource
      },
    },
    {
      logMessage:
        "Prerequisite 2: Attacker needs credentials for the controlled principal (host1$).",
      logType: "info",
    },
    {
      logMessage:
        "Attacker (as host1$) -> DC01: LDAP Modify (Write host1$'s SID to the 'msDS-AllowedToActOnBehalfOfOtherIdentity' attribute on the 'srv_files01' computer object).",
      logType: "attack", // The core configuration abuse
      action: () => {
        addTemporaryEdge("host1", "dc01", "LDAP", "LDAP Modify (Set RBCD)");
      },
    },
    {
      logMessage:
        "DC01: Validates ACL (host1$ has write permission). Updates attribute on srv_files01.",
      logType: "ldap",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "Attacker (using host1$ creds): -> DC01: Kerberos TGS-REQ (S4U2Self - Requesting a service ticket *to himself* for 'host1$' but specifying impersonation of 'DomainAdmin').",
      logType: "attack", // Getting a ticket to self, impersonating victim
      action: () =>
        addTemporaryEdge("host1", "dc01", "Kerberos", "TGS-REQ (S4U2Self)"),
    },
    {
      logMessage:
        "DC01: Issues a forwardable Service Ticket for 'host1$' (valid for host1$ to use) containing 'DomainAdmin' identity.",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "host1", "Kerberos", "TGS-REP (Self ST)"),
    },
    {
      logMessage:
        "Attacker (using host1$ creds): -> DC01: Kerberos TGS-REQ (S4U2Proxy - Uses the S4U2Self ticket, requests a ST for 'cifs/files01.corp.local' *as DomainAdmin*).",
      logType: "attack", // Requesting ticket to target service
      action: () => {
        addTemporaryEdge("host1", "dc01", "Kerberos", "TGS-REQ (S4U2Proxy)");
      },
    },
    {
      logMessage:
        "DC01: Validates request. Checks RBCD on target 'srv_files01': sees 'host1$' is allowed to delegate. Issues ST for 'cifs/files01' usable by 'host1$' but containing 'DomainAdmin' identity.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker (as host1$): Kerberos TGS-REP (ST for cifs/files01, usable *as DomainAdmin*).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "host1", "Kerberos", "TGS-REP (Proxy ST)"),
    },
    {
      logMessage:
        "Attacker (injects proxy ST): -> SRV-FILES01: SMB AP-REQ (Presents the proxy ST to access files).",
      logType: "attack", // Using the final ticket
      action: () => {
        highlightElement("srv_files01", stepDelay, "compromised"); // Access achieved
        addTemporaryEdge(
          "host1",
          "srv_files01",
          "SMB",
          "AP-REQ (as DA via RBCD)"
        );
      },
    },
    {
      logMessage:
        "SRV-FILES01: Validates ticket. Sees user is 'DomainAdmin'. Grants access with Domain Admin privileges.",
      logType: "smb",
    },
    {
      logMessage:
        "IMPACT: Attacker leveraged control of 'host1' and its write permission on 'srv_files01' to gain Domain Admin-level access specifically *to* srv_files01. Can potentially execute code (e.g., PsExec) or access sensitive data on srv_files01 as DA.",
      logType: "success",
    },
  ];

  const attackESC1Scenario = [
    {
      scenarioName: "Attack: AD CS ESC1 (Misconfigured Template ACL + SAN)",
      logMessage:
        "Attacker Goal: Obtain a certificate allowing authentication as a privileged user (e.g., Domain Admin) by abusing template permissions.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: Attacker controls a principal (e.g., compromised 'Bob' - user2) with 'Write' permissions on a Certificate Template object in AD.",
      logType: "attack",
      action: () => {
        highlightElement("user2", stepDelay, "compromised"); // Attacker's initial foothold
        highlightElement("ca01"); // Target CA infrastructure
      },
    },
    {
      logMessage:
        "Prerequisite 2: The target template does NOT have 'Manager Approval' required.",
      logType: "info",
    },
    {
      logMessage:
        "Prerequisite 3: The CA grants enrollment rights for this template to low-privileged users (or the attacker's user).",
      logType: "info",
    },
    {
      logMessage:
        "Attacker (as Bob) -> DC01: LDAP Modify Request (On the vulnerable template object, e.g., 'UserAutoenroll'): Set 'mspki-enrollment-flag' attribute to include the 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT' (0x1) flag.",
      logType: "attack", // The key modification enabling SAN abuse
      action: () =>
        addTemporaryEdge(
          "user2",
          "dc01",
          "LDAP",
          "Modify Template (Add ENROLLEE_SUPPLIES_SUBJECT)"
        ),
    },
    {
      logMessage:
        "DC01: Updates template object in AD configuration partition.",
      logType: "ldap",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "CA01: Periodically refreshes template cache from AD (This can introduce delay).",
      logType: "info",
      action: () => highlightElement("ca01"),
      delay: 2000, // Simulate cache refresh delay
    },
    {
      logMessage:
        "Attacker (as Bob) -> CA01: RPC/HTTP Request (Request certificate using the modified 'UserAutoenroll' template. Critically, *supply* a Subject Alternative Name (SAN) field specifying the UPN of a privileged user, e.g., 'DomainAdmin@corp.local').",
      logType: "attack", // Requesting cert, specifying DA identity in SAN
      action: () =>
        addTemporaryEdge(
          "user2",
          "ca01",
          "RPC/HTTP",
          "Cert Req (ESC1 - SAN=DA)"
        ),
    },
    {
      logMessage:
        "CA01: Checks enrollment permissions (Bob allowed). Sees ENROLLEE_SUPPLIES_SUBJECT flag is now set on template. Allows the supplied SAN. Issues certificate technically *for* Bob but containing the Domain Admin UPN in the SAN.",
      logType: "info", // CA follows the (now malicious) template rules
      action: () => highlightElement("ca01"),
    },
    {
      logMessage:
        "CA01 -> Attacker (as Bob): RPC/HTTP Response (Issued Certificate with DA UPN in SAN).",
      logType: "rpc", // or HTTP
      action: () =>
        addTemporaryEdge("ca01", "user2", "RPC/HTTP", "Cert Issued (DA SAN!)"),
    },
    {
      logMessage:
        "Attacker: Possesses a certificate that can be used for DA authentication.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ (Using PKINIT - Presenting the obtained certificate for pre-authentication).",
      logType: "attack", // Using the malicious cert for Kerberos auth
      action: () =>
        addTemporaryEdge(
          "attacker",
          "dc01",
          "Kerberos",
          "AS-REQ (PKINIT w/ DA Cert)"
        ),
    },
    {
      logMessage:
        "DC01: Validates certificate chain. Extracts UPN 'DomainAdmin@corp.local' from the SAN. Treats request as coming from DomainAdmin. Issues TGT for DomainAdmin.",
      logType: "kerberos", // DC accepts cert based on SAN
      action: () => {
        highlightElement("dc01");
        highlightElement("admin1", stepDelay, "compromised"); // Attacker now has DA TGT
      },
    },
    {
      logMessage: "DC01 -> Attacker: Kerberos AS-REP (TGT for DomainAdmin!).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (DA TGT!)"),
    },
    {
      logMessage:
        "IMPACT: Attacker exploited template ACLs to modify a template, allowing SAN specification during enrollment. Resulted in obtaining a certificate valid for Domain Admin authentication, leading to a DA TGT. Full domain compromise likely.",
      logType: "success",
    },
  ];

  const attackDCSyncScenario = [
    {
      scenarioName: "Attack: DCSync",
      logMessage:
        "Attacker Goal: Obtain password hashes (especially KRBTGT) by mimicking DC replication.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has compromised credentials with Domain Replication rights ('Replicating Directory Changes' & 'Replicating Directory Changes All'). E.g., Domain Admin (admin1) or specific delegate.",
      logType: "attack",
      action: () => {
        highlightElement("admin1", stepDelay, "compromised"); // Account with required rights
      },
    },
    {
      logMessage:
        "Attacker (using admin1 creds/ticket) -> DC01: RPC Bind Request (Targeting Directory Replication Service Remote Protocol - MS-DRSR).",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "Bind DRSR"),
    },
    {
      logMessage:
        "Attacker -> DC01: DRSR DRSUAPI GetNCChanges Request (Requesting replication updates for the Domain NC, specifically asking for secrets like password hashes).",
      logType: "attack", // Malicious use of replication protocol
      action: () =>
        addTemporaryEdge("attacker", "dc01", "DRSUAPI", "GetNCChanges"),
    },
    {
      logMessage:
        "DC01: Receives request. Verifies via ACL check that the requesting user (admin1) has the required DS-Replication-Get-Changes privileges.",
      logType: "info", // DC performs authorization check
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01: Accesses its local AD database (ntds.dit) to retrieve requested object data, including sensitive attributes like NTLM hashes and Kerberos keys.",
      logType: "info", // Internal DC action
      action: () =>
        addTemporaryEdge("dc01", "dc01", "DB Access", "Read Secrets"),
    },
    {
      logMessage:
        "DC01 -> Attacker: DRSR DRSUAPI GetNCChanges Response (Streams replication data containing requested objects and their secrets, including krbtgt hash, admin hashes, etc.).",
      logType: "attack", // Sensitive data exfiltration
      action: () => {
        highlightElement("krbtgt", stepDelay, "compromised"); // Key target obtained
        addTemporaryEdge("dc01", "attacker", "DRSUAPI", "Repl Resp (Secrets!)");
      },
    },
    {
      logMessage:
        "IMPACT: Attacker has obtained critical domain secrets, most importantly the KRBTGT account's hash. Can now forge Golden Tickets offline, granting arbitrary access as any user, achieving domain dominance and persistence.",
      logType: "success",
    },
  ];

  const attackSQLAccessScenario = [
    {
      scenarioName: "Attack: Access SQL Server (Post-Roast)",
      logMessage:
        "Attacker previously Kerberoasted svc_sql01 and cracked its hash/password.",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("svc_sql01", stepDelay, "compromised");
      },
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ (Requesting TGT for svc_sql01 using cracked creds)",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (svc_sql01)"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos AS-REP (Issuing TGT for svc_sql01)",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (TGT)"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos TGS-REQ (Using TGT, Requesting ST for MSSQLSvc/sql01...)",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ (SQL)"),
    },
    {
      logMessage: "DC01 -> Attacker: Kerberos TGS-REP (Issuing ST for SQL01)",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "TGS-REP (ST)"),
    },
    {
      logMessage:
        "Attacker -> SQL01 (srv_sql01): Kerberos AP-REQ (Presenting ST for SQL Service)",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "srv_sql01", "Kerberos", "AP-REQ (SQL)"),
    },
    {
      logMessage:
        "SQL01: Validates ticket. Attacker authenticated as svc_sql01.",
      logType: "kerberos",
      action: () => highlightElement("srv_sql01"),
    },
    {
      logMessage:
        "Attacker -> SQL01: Executes SQL commands (e.g., xp_cmdshell if enabled, sensitive data query)",
      logType: "attack",
      action: () => {
        highlightElement("srv_sql01", stepDelay, "compromised");
        addTemporaryEdge(
          "attacker",
          "srv_sql01",
          "HTTP",
          "SQL Query/Cmd"
        ); /* Using HTTP as placeholder for TDS protocol */
      },
    },
    {
      logMessage:
        "SQL ACCESS SUCCESSFUL: Attacker connects to SQL01 as service account. Can now execute SQL queries as svc_sql01, potentially run code via xp_cmdshell, and access sensitive database data.",
      logType: "success",
    },
  ];
  const attackRemoteExecScenario = [
    {
      scenarioName: "Attack: Remote Service Exec (PsExec-like)",
      logMessage:
        "Attacker has compromised creds (e.g., Alice's hash via PtH, or DA ticket)",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("user1");
      },
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: SMB Authentication (using stolen hash/ticket)",
      logType: "smb",
      action: () => {
        addTemporaryEdge("attacker", "srv_web01", "SMB", "Auth (SMB)");
        addTemporaryEdge("attacker", "srv_web01", "NTLM", "Auth (NTLM/Kerb)");
      },
    },
    {
      logMessage: "SRV-WEB-01: Authentication successful.",
      logType: "success",
      action: () => highlightElement("srv_web01"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: SMB Write Request (ADMIN$ share - copy malicious executable)",
      logType: "smb",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "SMB", "Write ADMIN$"),
    },
    {
      logMessage: "SRV-WEB-01: File written successfully.",
      logType: "smb",
      action: () => {},
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Connect to Service Control Manager - SCM) [UUID: 367ABB81-9844-35F1-AD32-98F038001003]",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "SCM Connect"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (SCM: CreateService - Win32_Own_Process, Auto_Start)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "CreateService"),
    },
    {
      logMessage:
        "SRV-WEB-01: Service 'UpdateService' created (SYSTEM privileges).",
      logType: "rpc",
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (SCM: StartService)",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "StartService"),
    },
    {
      logMessage:
        "SRV-WEB-01: Service started successfully (SYSTEM privileges).",
      logType: "attack",
      action: () => highlightElement("srv_web01", stepDelay, "compromised"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (SCM: DeleteService)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "DeleteService"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: SMB Delete Request (Remove malicious executable)",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "srv_web01", "SMB", "Delete"),
    },
    {
      logMessage:
        "REMOTE EXECUTION SUCCESSFUL: Attacker executed code on SRV-WEB-01 with SYSTEM privileges.",
      logType: "success",
    },
  ];

  const attackShadowCredentialsScenario = [
    {
      scenarioName: "Attack: Shadow Credentials",
      logMessage:
        "Attacker compromises a machine account (host1) with write access to target user (user1)",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("host1", stepDelay, "compromised");
      },
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Enumerate machine account permissions)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Search Permissions"),
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Check if target user has msDS-KeyCredentialLink attribute)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Check KeyCredential"),
    },
    {
      logMessage:
        "Attacker: Generates new certificate using PKINIT template (Key Usage: Digital Signature, Key Encipherment)",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Sets certificate validity period and subject alternative name",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Modify (Add KeyCredential to target user)",
      logType: "attack",
      action: () => {
        highlightElement("user1");
        addTemporaryEdge("attacker", "dc01", "LDAP", "Add KeyCredential");
      },
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Verify KeyCredential was added)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Verify KeyCredential"),
    },
    {
      logMessage:
        "Attacker -> DC01: PKINIT Authentication (Using new certificate)",
      logType: "kerberos",
      action: () => addTemporaryEdge("attacker", "dc01", "Kerberos", "PKINIT"),
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Modify (Remove KeyCredential after use)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Remove KeyCredential"),
    },
    {
      logMessage:
        "SHADOW CREDENTIALS SUCCESSFUL: Attacker gained access as target user with certificate-based authentication.",
      logType: "success",
    },
  ];

  const attackPrintNightmareScenario = [
    {
      scenarioName: "Attack: PrintNightmare",
      logMessage: "Attacker discovers vulnerable print server (srv_files01)",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("srv_files01");
      },
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Find print server's SPN and configuration)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Find Print Server"),
    },
    {
      logMessage:
        "Attacker -> SRV-FILES01: RPC Bind (Connect to Print System Remote Protocol)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_files01", "RPC", "Bind Print System"),
    },
    {
      logMessage:
        "Attacker -> SRV-FILES01: RPC Call (Add printer driver with malicious DLL path)",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "srv_files01", "RPC", "Add Driver"),
    },
    {
      logMessage:
        "Attacker -> SRV-FILES01: RPC Call (Point printer to malicious DLL)",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "srv_files01", "RPC", "Set Driver"),
    },
    {
      logMessage: "Attacker -> SRV-FILES01: RPC Call (Trigger driver load)",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "srv_files01", "RPC", "Load Driver"),
    },
    {
      logMessage: "SRV-FILES01: Loads malicious DLL with SYSTEM privileges",
      logType: "attack",
      action: () => highlightElement("srv_files01", stepDelay, "compromised"),
    },
    {
      logMessage:
        "PRINTNIGHTMARE SUCCESSFUL: Attacker gains SYSTEM privileges on print server. Can now execute arbitrary code with SYSTEM privileges, access all resources on the server, and maintain persistence.",
      logType: "success",
    },
  ];

  const attackNTLMRelayScenario = [
    {
      scenarioName: "Attack: NTLM Relay",
      logMessage: "Attacker targets DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Find servers with SMB signing disabled)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Find Targets"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Check target server's SPNs)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Check SPNs"),
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Check target server's delegation settings)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Check Delegation"),
    },
    {
      logMessage:
        "Attacker -> DC01: HTTP Request (Trigger NTLM authentication)",
      logType: "http",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "HTTP", "Trigger Auth"),
    },
    {
      logMessage: "DC01 -> Attacker: NTLM Type 1 Message (Challenge)",
      logType: "ntlm",
      action: () => addTemporaryEdge("dc01", "attacker", "NTLM", "Type 1"),
    },
    {
      logMessage: "Attacker -> DC01: NTLM Type 2 Message (Response)",
      logType: "ntlm",
      action: () => addTemporaryEdge("attacker", "dc01", "NTLM", "Type 2"),
    },
    {
      logMessage: "DC01 -> Attacker: NTLM Type 3 Message (Authentication)",
      logType: "ntlm",
      action: () => addTemporaryEdge("dc01", "attacker", "NTLM", "Type 3"),
    },
    {
      logMessage:
        "DC01: Validates NTLM authentication (Checks user credentials)",
      logType: "ntlm",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01: Verifies user permissions (Checks group memberships)",
      logType: "ntlm",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01: Validates SMB signing (Checks if signing is required)",
      logType: "smb",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Check for RBCD rights)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Check RBCD"),
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Modify (Set msDS-AllowedToActOnBehalfOfOtherIdentity if needed)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Set RBCD"),
    },
    {
      logMessage:
        "Attacker -> DC01: SMB Session Setup (Relay captured NTLM authentication)",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Relay Auth"),
    },
    {
      logMessage:
        "DC01: Validates NTLM authentication (Checks relayed credentials)",
      logType: "smb",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01: Verifies RBCD permissions (Checks delegation rights)",
      logType: "smb",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: SMB Tree Connect (Access ADMIN$ share)",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Tree Connect"),
    },
    {
      logMessage: "DC01: Validates share access (Checks share permissions)",
      logType: "smb",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: SMB Write (Copy malicious executable)",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Write File"),
    },
    {
      logMessage: "DC01: Validates file write permissions (Checks ACLs)",
      logType: "smb",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "Attacker -> DC01: RPC Call (Create service pointing to dropped executable)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "RPC", "Create Service"),
    },
    {
      logMessage:
        "DC01: Validates service creation rights (Checks service permissions)",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "NTLM RELAY SUCCESSFUL: Attacker executed code on DC. Can now execute arbitrary code on the domain controller, access all domain resources, and maintain persistence.",
      logType: "success",
    },
  ];

  const attackLLMNRPoisoningScenario = [
    {
      scenarioName: "Attack: LLMNR/NBT-NS Poisoning",
      logMessage: "Attacker sets up rogue LLMNR/NBT-NS responder",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "User (user1) -> Network: LLMNR Query (for non-existent share)",
      logType: "dns",
      action: () => highlightElement("user1"),
    },
    {
      logMessage: "Attacker -> User: LLMNR Response (spoofed IP)",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "user1", "DNS", "Spoofed Response"),
    },
    {
      logMessage: "User -> Attacker: SMB Session Setup (NTLM Type 1 Message)",
      logType: "smb",
      action: () => addTemporaryEdge("user1", "attacker", "SMB", "NTLM Type 1"),
    },
    {
      logMessage:
        "Attacker -> User: SMB Session Setup Response (NTLM Type 2 Challenge)",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "user1", "SMB", "NTLM Type 2"),
    },
    {
      logMessage:
        "User -> Attacker: SMB Session Setup (NTLM Type 3 Response with hash)",
      logType: "smb",
      action: () => addTemporaryEdge("user1", "attacker", "SMB", "NTLM Type 3"),
    },
    {
      logMessage: "Attacker -> User: SMB Tree Connect (Access share)",
      logType: "smb",
      action: () =>
        addTemporaryEdge("attacker", "user1", "SMB", "Tree Connect"),
    },
    {
      logMessage: "Attacker -> User: SMB Negotiate Protocol (SMB2)",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "user1", "SMB", "Negotiate"),
    },
    {
      logMessage:
        "LLMNR POISONING SUCCESSFUL: Attacker captured NTLM hash. Can now authenticate as the compromised user, access their resources, and potentially escalate privileges.",
      logType: "success",
    },
  ];

  const attackLDAPReconScenario = [
    {
      scenarioName: "Attack: LDAP Recon",
      logMessage: "Attacker performs LDAP reconnaissance",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Get domain naming context)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Get Naming Context"),
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Enumerate OUs and containers)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Enum OUs"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Find privileged groups)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Find Groups"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Find service accounts)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Find Services"),
    },
    {
      logMessage:
        "LDAP RECON COMPLETE: Attacker mapped AD structure. Can now identify high-value targets, misconfigurations, and potential attack paths for lateral movement.",
      logType: "success",
    },
  ];

  const attackDNSReconScenario = [
    {
      scenarioName: "Attack: DNS Recon",
      logMessage: "Attacker performs DNS reconnaissance",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage: "Attacker -> DC01: DNS Query (Get domain controllers)",
      logType: "dns",
      action: () => addTemporaryEdge("attacker", "dc01", "DNS", "Get DCs"),
    },
    {
      logMessage: "Attacker -> DC01: DNS Query (Get all domain records)",
      logType: "dns",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "DNS", "Zone Transfer"),
    },
    {
      logMessage: "Attacker -> DC01: DNS Query (Find SPN records)",
      logType: "dns",
      action: () => addTemporaryEdge("attacker", "dc01", "DNS", "Find SPNs"),
    },
    {
      logMessage:
        "DNS RECON COMPLETE: Attacker mapped network. Can now identify domain controllers, SPN records, and potential attack targets.",
      logType: "success",
    },
  ];

  const attackSMBShareEnumScenario = [
    {
      scenarioName: "Attack: SMB Share Enumeration",
      logMessage: "Attacker enumerates SMB shares",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage: "Attacker -> SRV-FILES01: SMB Session Setup",
      logType: "smb",
      action: () =>
        addTemporaryEdge("attacker", "srv_files01", "SMB", "Session Setup"),
    },
    {
      logMessage: "Attacker -> SRV-FILES01: SMB Tree Connect (List shares)",
      logType: "smb",
      action: () =>
        addTemporaryEdge("attacker", "srv_files01", "SMB", "List Shares"),
    },
    {
      logMessage:
        "Attacker -> SRV-FILES01: SMB File Access (Check permissions)",
      logType: "smb",
      action: () =>
        addTemporaryEdge("attacker", "srv_files01", "SMB", "Check Access"),
    },
    {
      logMessage:
        "SMB ENUM COMPLETE: Attacker found accessible shares. Can now access sensitive data, potentially execute code, and use this as a foothold for lateral movement.",
      logType: "success",
    },
  ];

  const attackScheduledTaskScenario = [
    {
      scenarioName: "Attack: Scheduled Task Abuse",
      logMessage: "Attacker has compromised user1's credentials",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("user1");
      },
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: SMB Authentication",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "srv_web01", "SMB", "Auth"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Connect to Task Scheduler service)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge(
          "attacker",
          "srv_web01",
          "RPC",
          "TaskScheduler Connect"
        ),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Create scheduled task with SYSTEM privileges)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Create Task"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Set task trigger - daily at 2 AM)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Set Trigger"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Set task action - execute malicious payload)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Set Action"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Set task security options - run as SYSTEM)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Set Security"),
    },
    {
      logMessage: "SRV-WEB-01: Task created successfully",
      logType: "success",
      action: () => highlightElement("srv_web01"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Trigger task immediately for testing)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Run Task"),
    },
    {
      logMessage:
        "SCHEDULED TASK SUCCESSFUL: Attacker can execute code. Can now run arbitrary code on the target system, maintain persistence, and potentially escalate privileges.",
      logType: "success",
    },
  ];

  const attackWMIAbuseScenario = [
    {
      scenarioName: "Attack: WMI Abuse",
      logMessage: "Attacker has compromised user1's credentials",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("user1");
      },
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (Connect to WMI)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "WMI Connect"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (Create WMI event filter)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Create Filter"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Create WMI event consumer)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Create Consumer"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (Bind filter to consumer)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Bind Filter"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Set consumer to execute malicious payload)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Set Payload"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: RPC Call (Trigger event to test persistence)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "RPC", "Trigger Event"),
    },
    {
      logMessage: "SRV-WEB-01: WMI persistence established",
      logType: "success",
      action: () => highlightElement("srv_web01"),
    },
    {
      logMessage:
        "WMI ABUSE SUCCESSFUL: Attacker has persistence. Can now execute arbitrary code on the target system, maintain persistence through WMI events, and potentially escalate privileges.",
      logType: "success",
    },
  ];

  const attackESC2Scenario = [
    // ESC2: Template grants Certificate Request Agent EKU, low-priv user has Enroll rights.
    // Note: Other ESC2 interpretations exist (e.g., Any Purpose EKU), but this is common & leads to ESC3.
    {
      scenarioName: "Attack: ESC2 (Enrollment Agent EKU Abuse - Prep for ESC3)",
      logMessage:
        "Attacker Goal: Obtain an 'Enrollment Agent' certificate via a misconfigured template.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: A certificate template (e.g., 'AgentTemplate') exists with the 'Certificate Request Agent' EKU (OID 1.3.6.1.4.1.311.20.2.1).",
      logType: "info",
    },
    {
      logMessage:
        "Prerequisite 2: Attacker's low-priv user (e.g., user2) has 'Enroll' permissions on 'AgentTemplate'.",
      logType: "info",
      action: () => highlightElement("user2"), // Assume attacker controls user2
    },
    {
      logMessage:
        "Prerequisite 3: The template does not require Manager Approval.",
      logType: "info",
    },
    {
      logMessage:
        "Attacker (as user2) -> DC01: LDAP Search (Find templates user2 can enroll in, identify 'AgentTemplate' with Enrollment Agent EKU).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge(
          "user2",
          "dc01",
          "LDAP",
          "Find Enrollable Agent Template"
        ),
    },
    {
      logMessage:
        "Attacker (as user2) -> CA01: RPC/HTTP Request (Request certificate using 'AgentTemplate'). Authenticates as user2.",
      logType: "rpc", // or HTTP
      action: () =>
        addTemporaryEdge("user2", "ca01", "RPC/HTTP", "Req Agent Cert"),
    },
    {
      logMessage:
        "CA01: Validates user2 has Enroll rights on 'AgentTemplate'. Issues certificate containing the 'Certificate Request Agent' EKU.",
      logType: "info",
      action: () => highlightElement("ca01"),
    },
    {
      logMessage:
        "CA01 -> Attacker (as user2): RPC/HTTP Response (Issued Enrollment Agent certificate).",
      logType: "rpc", // or HTTP
      action: () =>
        addTemporaryEdge("ca01", "user2", "RPC/HTTP", "Iss Agent Cert"),
    },
    {
      logMessage:
        "ESC2 SUCCESSFUL (Partial): Attacker now possesses an Enrollment Agent certificate. This enables the ESC3 attack.",
      logType: "success",
      action: () => highlightElement("attacker"), // Attacker holds the key cert
    },
  ];

  const attackESC3Scenario = [
    // ESC3: Abusing Enrollment Agent certificate to request certs on behalf of others.
    {
      scenarioName: "Attack: ESC3 (Enrollment Agent Impersonation)",
      logMessage:
        "Attacker Goal: Use an Enrollment Agent certificate to get a certificate for a privileged user (e.g., Domain Admin).",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: Attacker possesses a valid Enrollment Agent certificate (e.g., obtained via ESC2).",
      logType: "attack", // Acquired artifact
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 2: A target template exists (e.g., 'User') that allows enrollment AND whose defined EKUs enable authentication (e.g., Client Authentication).",
      logType: "info",
    },
    {
      logMessage:
        "Prerequisite 3: The CA is configured to allow Enrollment Agents.",
      logType: "info",
      action: () => highlightElement("ca01"),
    },
    {
      logMessage:
        "Attacker -> CA01: RPC/HTTP Request (Request certificate using 'User' template. Specify 'Request-On-Behalf-Of: CORP\\DomainAdmin'. Authenticate using the *Enrollment Agent certificate*).",
      logType: "attack", // The core ESC3 action
      action: () => {
        highlightElement("admin1"); // Target of impersonation
        addTemporaryEdge("attacker", "ca01", "RPC/HTTP", "Req OnBehalfOf DA");
      },
    },
    {
      logMessage:
        "CA01: Validates the Enrollment Agent certificate's EKU. Checks if agent is allowed. Sees request is for 'DomainAdmin'. Issues a 'User' certificate *as if* requested by 'DomainAdmin'.",
      logType: "info",
      action: () => highlightElement("ca01"),
    },
    {
      logMessage:
        "CA01 -> Attacker: RPC/HTTP Response (Issued certificate containing Domain Admin's identity).",
      logType: "rpc", // or HTTP
      action: () =>
        addTemporaryEdge("ca01", "attacker", "RPC/HTTP", "Iss DA Cert"),
    },
    {
      logMessage:
        "Attacker: Possesses certificate valid for Domain Admin authentication.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ (PKINIT using the DA certificate for pre-authentication).",
      logType: "attack",
      action: () =>
        addTemporaryEdge(
          "attacker",
          "dc01",
          "Kerberos",
          "AS-REQ (PKINIT w/ DA Cert)"
        ),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos AS-REP (Issues TGT for Domain Admin).",
      logType: "kerberos", // Successful auth as DA
      action: () => {
        highlightElement("admin1", stepDelay, "compromised"); // DA effectively compromised
        addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (DA TGT!)");
      },
    },
    {
      logMessage:
        "ESC3 SUCCESSFUL: Attacker used Enrollment Agent cert to impersonate DA, obtaining DA TGT. Full domain compromise likely.",
      logType: "success",
    },
  ];

  const attackESC4Scenario = [
    // ESC4: Attacker has Write rights over a Certificate Template object in AD.
    {
      scenarioName: "Attack: ESC4 (Template ACL Abuse)",
      logMessage:
        "Attacker Goal: Modify a certificate template's ACLs to grant themselves enrollment rights, then request a potentially privileged certificate.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker controls a principal (e.g., user2) with Write/FullControl ACL permissions on a Certificate Template object (e.g., 'AdminOnlyTemplate') in AD.",
      logType: "attack",
      action: () => {
        highlightElement("user2", stepDelay, "compromised"); // Attacker controls this user
      },
    },
    {
      logMessage:
        "Attacker (as user2) -> DC01: LDAP Search (Identify 'AdminOnlyTemplate' object CN=AdminOnlyTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration...).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("user2", "dc01", "LDAP", "Find Target Template"),
    },
    {
      logMessage:
        "Attacker (as user2) -> DC01: LDAP Modify Request (Modify the 'nTSecurityDescriptor' attribute of 'AdminOnlyTemplate' to add an ACE granting 'Enroll' rights to user2).",
      logType: "attack", // The core ESC4 action - modifying template security
      action: () =>
        addTemporaryEdge("user2", "dc01", "LDAP", "Modify Template ACL"),
    },
    {
      logMessage:
        "DC01: Updates the template object's ACL in the Configuration partition.",
      logType: "ldap",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "CA01: Periodically refreshes template cache from AD (This can introduce delay).",
      logType: "info",
      action: () => highlightElement("ca01"),
      delay: 2000, // Simulate cache refresh delay
    },
    {
      logMessage:
        "Attacker (as user2) -> CA01: RPC/HTTP Request (Request certificate using 'AdminOnlyTemplate'. Now permitted due to modified ACL).",
      logType: "rpc", // or HTTP
      action: () =>
        addTemporaryEdge("user2", "ca01", "RPC/HTTP", "Req Mod Template Cert"),
    },
    {
      logMessage:
        "CA01: Checks enrollment permissions (user2 now has Enroll rights due to ACL change). Issues certificate based on 'AdminOnlyTemplate' definition.",
      logType: "info",
      action: () => highlightElement("ca01"),
    },
    {
      logMessage:
        "CA01 -> Attacker (as user2): RPC/HTTP Response (Issued certificate. Privileges depend on 'AdminOnlyTemplate' definition).",
      logType: "rpc", // or HTTP
      action: () =>
        addTemporaryEdge("ca01", "user2", "RPC/HTTP", "Iss Mod Template Cert"),
    },
    {
      logMessage:
        "Attacker: Possesses a certificate potentially enabling privileged access.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    // Next step depends on what the template allows (e.g., DA auth, specific service auth)
    {
      logMessage:
        "ESC4 SUCCESSFUL: Attacker modified template ACLs to gain enrollment. Obtained certificate defined by template, potentially leading to privilege escalation.",
      logType: "success",
    },
  ];

  const attackESC6Scenario = [
    // ESC6: CA server configured with EDITF_ATTRIBUTESUBJECTALTNAME2 flag, allowing SAN specification regardless of template settings.
    {
      scenarioName: "Attack: ESC6 (CA Misconfiguration - SubjectAltName Flag)",
      logMessage:
        "Attacker Goal: Obtain a certificate authenticating as a privileged user by abusing CA's allowance of Subject Alternative Names (SAN).",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: The CA server (CA01) has the 'EDITF_ATTRIBUTESUBJECTALTNAME2' policy flag enabled.",
      logType: "info", // Critical CA misconfiguration
      action: () => highlightElement("ca01"),
    },
    {
      logMessage:
        "Prerequisite 2: Attacker controls a user (e.g., user2) with Enroll rights on *any* template allowing client authentication (e.g., default 'User' template).",
      logType: "info",
      action: () => highlightElement("user2"),
    },
    {
      logMessage:
        "Attacker (as user2) -> CA01: RPC/HTTP Request (Request certificate using 'User' template. Critically, *supply* a Subject Alternative Name (SAN) attribute specifying a privileged user, e.g., 'DomainAdmin@corp.local').",
      logType: "attack", // The core ESC6 action - supplying SAN
      action: () => {
        highlightElement("admin1"); // Target of impersonation
        addTemporaryEdge(
          "user2",
          "ca01",
          "RPC/HTTP",
          "Req Cert (ESC6 - SAN=DA)"
        );
      },
    },
    {
      logMessage:
        "CA01: Checks user2 has Enroll rights on 'User' template. Sees the CA-level 'EDITF_ATTRIBUTESUBJECTALTNAME2' flag is set. *Ignores* template settings regarding SAN and accepts the attacker-supplied SAN. Issues certificate.",
      logType: "info", // CA follows its own misconfigured flag
      action: () => highlightElement("ca01"),
    },
    {
      logMessage:
        "CA01 -> Attacker (as user2): RPC/HTTP Response (Issued certificate with Domain Admin UPN in SAN).",
      logType: "rpc", // or HTTP
      action: () =>
        addTemporaryEdge("ca01", "user2", "RPC/HTTP", "Iss DA SAN Cert"),
    },
    {
      logMessage:
        "Attacker: Possesses certificate valid for Domain Admin authentication.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ (PKINIT using the DA certificate).",
      logType: "attack",
      action: () =>
        addTemporaryEdge(
          "attacker",
          "dc01",
          "Kerberos",
          "AS-REQ (PKINIT w/ DA Cert)"
        ),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos AS-REP (Issues TGT for Domain Admin).",
      logType: "kerberos",
      action: () => {
        highlightElement("admin1", stepDelay, "compromised");
        addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (DA TGT!)");
      },
    },
    {
      logMessage:
        "ESC6 SUCCESSFUL: Attacker exploited CA flag misconfiguration to specify SAN, obtained DA certificate and TGT. Full domain compromise likely.",
      logType: "success",
    },
  ];

  const attackESC8Scenario = [
    // ESC8: Abusing NTLM Relay to the AD CS Web Enrollment pages.
    {
      scenarioName: "Attack: ESC8 (NTLM Relay to Web Enrollment)",
      logMessage:
        "Attacker Goal: Obtain a certificate for a victim (e.g., DC machine account) by relaying their NTLM authentication to the CA Web Enrollment page.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: CA01 has AD CS Web Enrollment role installed (certsrv).",
      logType: "info",
      action: () => highlightElement("ca01"),
    },
    {
      logMessage: "Prerequisite 2: Web Enrollment allows NTLM authentication.",
      logType: "info",
    },
    {
      logMessage:
        "Prerequisite 3: NTLM relay protections (SMB Signing, EPA) are not fully enforced between victim, attacker, and CA web server.",
      logType: "info",
    },
    {
      logMessage:
        "Prerequisite 4: Attacker can trigger NTLM authentication from a victim machine (e.g., DC01$) to the attacker machine.",
      logType: "info",
      action: () => highlightElement("dc01"), // Victim whose creds will be relayed
    },
    {
      logMessage:
        "Attacker Machine: Starts NTLM relay tool (e.g., ntlmrelayx) listening for connections and targeting CA01's /certsrv/.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker -> DC01: Trigger NTLM Auth (e.g., using PrinterBug, PetitPotam) coercing DC01 to authenticate to Attacker Machine.",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "MS-RPRN/EFSRPC", "Coerce Auth"),
    },
    {
      logMessage:
        "DC01 -> Attacker Machine: NTLM Authentication attempt (Type 1, Type 2, Type 3 negotiation initiated).",
      logType: "ntlm",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "NTLM", "Auth Attempt"),
    },
    {
      logMessage:
        "Attacker Machine (Relay) -> CA01 (/certsrv): Relays NTLM messages from DC01 to the Web Enrollment endpoint.",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "ca01", "HTTP/NTLM", "Relay Auth"),
    },
    {
      logMessage:
        "CA01 (/certsrv) <-> Attacker Machine (Relay): Completes NTLM authentication. Relay tool is now authenticated to /certsrv *as DC01$*.",
      logType: "http", // Underlying protocol for web enrollment
      action: () => highlightElement("ca01"),
    },
    {
      logMessage:
        "Attacker Machine (Relay) -> CA01 (/certsrv): HTTP POST (Submits certificate request via Web Enrollment interface, using the relayed DC01$ session. Requests template like 'Machine' or 'User').",
      logType: "attack",
      action: () =>
        addTemporaryEdge(
          "attacker",
          "ca01",
          "HTTP",
          "Submit Cert Req (as DC01$)"
        ),
    },
    {
      logMessage:
        "CA01 -> Attacker Machine (Relay): HTTP Response (Issues certificate *for DC01$*).",
      logType: "http",
      action: () =>
        addTemporaryEdge("ca01", "attacker", "HTTP", "Issue Cert (for DC01$)"),
    },
    {
      logMessage:
        "Attacker: Relay tool captures the issued certificate for DC01$.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "ESC8 SUCCESSFUL: Attacker relayed DC authentication to obtain a certificate for the DC machine account. Can potentially use this for Shadow Credentials (ESC10) or RBCD attacks.",
      logType: "success",
    },
  ];

  const attackSkeletonKeyScenario = [
    {
      scenarioName: "Attack: Skeleton Key",
      logMessage: "Attacker targets DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: RPC Bind (Connect to LSASS service)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "LSASS Bind"),
    },
    {
      logMessage:
        "Attacker -> DC01: RPC Call (Inject Skeleton Key DLL into LSASS)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "Inject DLL"),
    },
    {
      logMessage:
        "Attacker -> DC01: RPC Call (Hook password validation routine)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "RPC", "Hook Validation"),
    },
    {
      logMessage: "Attacker -> DC01: RPC Call (Set Skeleton Key password)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "Set Key"),
    },
    {
      logMessage: "Attacker -> DC01: RPC Bind (Connect to Netlogon service)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "RPC", "Netlogon Bind"),
    },
    {
      logMessage:
        "Attacker -> DC01: NetrLogonSamLogon (Test Skeleton Key authentication)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "Test Auth"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Bind (Using Skeleton Key password)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Bind"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Enumerate domain objects)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Enum Objects"),
    },
    {
      logMessage:
        "DSRM ABUSE SUCCESSFUL: Attacker has domain admin access. Can now authenticate as any user with the skeleton key password, access all domain resources, and maintain persistence.",
      logType: "success",
    },
  ];

  const attackPetitPotamScenario = [
    {
      scenarioName: "Attack: PetitPotam",
      logMessage: "Attacker targets DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: MS-EFSRPC Call (Trigger authentication)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "MS-EFSRPC"),
    },
    {
      logMessage: "DC01: Validates RPC call (Checks EFS service)",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 -> Attacker: NTLM Challenge",
      logType: "ntlm",
      action: () => addTemporaryEdge("dc01", "attacker", "NTLM", "Challenge"),
    },
    {
      logMessage: "Attacker -> DC01: NTLM Response",
      logType: "ntlm",
      action: () => addTemporaryEdge("attacker", "dc01", "NTLM", "Response"),
    },
    {
      logMessage: "DC01: Validates NTLM authentication",
      logType: "ntlm",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "PETITPOTAM SUCCESSFUL: Attacker triggered DC authentication. Can now capture DC credentials, potentially gain domain admin access, and maintain persistence.",
      logType: "success",
    },
  ];

  const attackZeroLogonScenario = [
    {
      scenarioName: "Attack: ZeroLogon",
      logMessage: "Attacker targets DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: NetrServerPasswordSet2 RPC Call",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "PasswordSet2"),
    },
    {
      logMessage: "DC01: Validates RPC call (Checks Netlogon service)",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01: Processes password reset (Vulnerable to ZeroLogon)",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "Attacker -> DC01: NetrServerPasswordSet2 (Set empty password)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "SetEmpty"),
    },
    {
      logMessage: "DC01: Updates DC password (Due to vulnerability)",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "ZEROLOGON SUCCESSFUL: Attacker reset DC password. Can now authenticate as the domain controller, access all domain resources, and maintain persistence.",
      logType: "success",
    },
  ];

  const attackMS14068Scenario = [
    {
      scenarioName: "Attack: MS14-068",
      logMessage: "Attacker targets DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: Kerberos AS-REQ (Request TGT)",
      logType: "kerberos",
      action: () => addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ"),
    },
    {
      logMessage: "DC01: Validates AS-REQ (Checks user credentials)",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: Kerberos TGS-REQ (Exploit PAC validation)",
      logType: "kerberos",
      action: () => addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ"),
    },
    {
      logMessage: "DC01: Processes TGS-REQ (Vulnerable to PAC bypass)",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos TGS-REP (With elevated privileges)",
      logType: "kerberos",
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "TGS-REP"),
    },
    {
      logMessage:
        "MS14-068 SUCCESSFUL: Attacker obtained Domain Admin privileges. Can now access all domain resources, create new users, and maintain persistence.",
      logType: "success",
    },
  ];

  const attackSAMRAbuseScenario = [
    {
      scenarioName: "Attack: SAMR Abuse",
      logMessage: "Attacker targets DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: SAMR Connect",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "SAMR Connect"),
    },
    {
      logMessage: "DC01: Validates SAMR connection",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: SAMR EnumUsers",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "EnumUsers"),
    },
    {
      logMessage: "DC01: Processes user enumeration",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: SAMR DumpHashes",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "DumpHashes"),
    },
    {
      logMessage: "DC01: Extracts password hashes",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "SAMR ABUSE SUCCESSFUL: Attacker dumped password hashes. Can now authenticate as any user whose hash was dumped, access their resources, and potentially escalate privileges.",
      logType: "success",
    },
  ];

  const attackNTDSExtractionScenario = [
    {
      scenarioName: "Attack: NTDS.dit Extraction",
      logMessage: "Attacker targets DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: SMB Authentication",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Auth"),
    },
    {
      logMessage: "Attacker -> DC01: Copy NTDS.dit",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Copy NTDS"),
    },
    {
      logMessage: "DC01: Processes file copy request",
      logType: "smb",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: Copy SYSTEM hive",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Copy SYSTEM"),
    },
    {
      logMessage: "DC01: Processes SYSTEM hive copy",
      logType: "smb",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "NTDS.dit EXTRACTION SUCCESSFUL: Attacker obtained AD database. Can now extract all user hashes, authenticate as any user, access all resources, and maintain persistence.",
      logType: "success",
    },
  ];

  const attackDSRMAbuseScenario = [
    {
      scenarioName: "Attack: DSRM Abuse",
      logMessage: "Attacker targets DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: RPC Bind (Connect to Netlogon service)",
      logType: "rpc",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "RPC", "Netlogon Bind"),
    },
    {
      logMessage:
        "Attacker -> DC01: NetrLogonSamLogon (Test DSRM authentication)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "Test Auth"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Bind (Using DSRM password)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Bind"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Enumerate domain objects)",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Enum Objects"),
    },
    {
      logMessage:
        "DSRM ABUSE SUCCESSFUL: Attacker has domain admin access. Can now access all domain resources as Domain Admin, create new users, and maintain persistence even if DSRM password is changed.",
      logType: "success",
    },
  ];

  // --- Event Listeners ---
  function addEventListenerSafe(elementId, callback) {
    const element = document.getElementById(elementId);
    if (element) {
      element.addEventListener("click", callback);
    }
  }

  // Add event listeners for all scenarios
  addEventListenerSafe("btn-legit-logon", () =>
    startScenario(legitimateLogonScenario)
  );
  addEventListenerSafe("btn-legit-admin-group", () =>
    startScenario(legitAdminGroupScenario)
  );
  addEventListenerSafe("btn-legit-gpo", () =>
    startScenario(legitGpoUpdateScenario)
  );
  addEventListenerSafe("btn-legit-cert", () =>
    startScenario(legitCertRequestScenario)
  );
  addEventListenerSafe("btn-legit-fileshare", () =>
    startScenario(legitFileShareAccessScenario)
  );
  addEventListenerSafe("btn-attack-spray", () =>
    startScenario(attackPasswordSprayScenario)
  );
  addEventListenerSafe("btn-attack-kerberoast", () =>
    startScenario(attackKerberoastingScenario)
  );
  addEventListenerSafe("btn-attack-asrep", () =>
    startScenario(attackASREPRoastingScenario)
  );
  addEventListenerSafe("btn-attack-sharphound", () =>
    startScenario(attackSharpHoundScenario)
  );
  addEventListenerSafe("btn-attack-ptt", () =>
    startScenario(attackPassTheTicketScenario)
  );
  addEventListenerSafe("btn-attack-pth", () =>
    startScenario(attackPassTheHashScenario)
  );
  addEventListenerSafe("btn-attack-uncon", () =>
    startScenario(attackUnconstrainedDelegationScenario)
  );
  addEventListenerSafe("btn-attack-rbcd", () =>
    startScenario(attackRBCDScenario)
  );
  addEventListenerSafe("btn-attack-esc1", () =>
    startScenario(attackESC1Scenario)
  );
  addEventListenerSafe("btn-attack-dcsync", () =>
    startScenario(attackDCSyncScenario)
  );
  addEventListenerSafe("btn-attack-sql", () =>
    startScenario(attackSQLAccessScenario)
  );
  addEventListenerSafe("btn-attack-golden", () =>
    startScenario(attackGoldenTicketScenario)
  );
  addEventListenerSafe("btn-attack-silver", () =>
    startScenario(attackSilverTicketScenario)
  );
  addEventListenerSafe("btn-attack-remote-exec", () =>
    startScenario(attackRemoteExecScenario)
  );
  addEventListenerSafe("btn-attack-shadow", () =>
    startScenario(attackShadowCredentialsScenario)
  );
  addEventListenerSafe("btn-attack-printnightmare", () =>
    startScenario(attackPrintNightmareScenario)
  );

  // Add event listeners for new scenarios
  const newAttackButtons = [
    "btn-attack-ntlm",
    "btn-attack-llmnr",
    "btn-attack-ldap",
    "btn-attack-dns",
    "btn-attack-smb",
    "btn-attack-scheduled",
    "btn-attack-wmi",
    "btn-attack-esc2",
    "btn-attack-esc3",
    "btn-attack-esc4",
    "btn-attack-esc6",
    "btn-attack-esc8",
    "btn-attack-skeleton",
    "btn-attack-dsr",
    "btn-attack-petitpotam",
    "btn-attack-zerologon",
    "btn-attack-ms14",
    "btn-attack-samr",
    "btn-attack-ntds",
  ];

  newAttackButtons.forEach((buttonId) => {
    addEventListenerSafe(buttonId, () => {
      const scenarioMap = {
        "btn-attack-ntlm": attackNTLMRelayScenario,
        "btn-attack-llmnr": attackLLMNRPoisoningScenario,
        "btn-attack-ldap": attackLDAPReconScenario,
        "btn-attack-dns": attackDNSReconScenario,
        "btn-attack-smb": attackSMBShareEnumScenario,
        "btn-attack-scheduled": attackScheduledTaskScenario,
        "btn-attack-wmi": attackWMIAbuseScenario,
        "btn-attack-esc2": attackESC2Scenario,
        "btn-attack-esc3": attackESC3Scenario,
        "btn-attack-esc4": attackESC4Scenario,
        "btn-attack-esc6": attackESC6Scenario,
        "btn-attack-esc8": attackESC8Scenario,
        "btn-attack-skeleton": attackSkeletonKeyScenario,
        "btn-attack-dsr": attackDSRMAbuseScenario,
        "btn-attack-petitpotam": attackPetitPotamScenario,
        "btn-attack-zerologon": attackZeroLogonScenario,
        "btn-attack-ms14": attackMS14068Scenario,
        "btn-attack-samr": attackSAMRAbuseScenario,
        "btn-attack-ntds": attackNTDSExtractionScenario,
      };

      if (scenarioMap[buttonId]) {
        startScenario(scenarioMap[buttonId]);
      } else {
        log(`Scenario ${buttonId} is not yet implemented`, "info");
      }
    });
  });

  addEventListenerSafe("btn-reset", () => resetSimulationState(true));
  addEventListenerSafe("btn-next-step", handleNextStep);
  addEventListenerSafe("chk-manual-mode", () => {}); // State checked on scenario start

  // --- Initial Execution ---
  initializeCytoscape(initialElements);
  cy.ready(() => {
    log("Expert AD Simulation Environment Initialized. Ready.", "info");
    updateButtonStates();
  });
}); // End DOMContentLoaded
