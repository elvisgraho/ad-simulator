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
  const stepDelay = 2200;
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
      position: { x: 550, y: 400 },
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
      position: { x: 200, y: 300 },
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
            "font-size": "18px",
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
        "Attacker Goal: Find valid credentials by trying one common password (e.g., 'admin12345') against many different accounts, avoiding lockouts.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "[Optional Recon] Attacker -> DC01: LDAP Search (e.g., '(objectClass=user)') to obtain a list of valid usernames.",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Enum Users"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ for User1 with guessed password 'admin12345'. (No valid TGT expected initially).",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (Spray U1)"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos Error (KRB5KDC_ERR_PREAUTH_FAILED - Incorrect password for User1).",
      logType: "kerberos", // Indicates username is valid, password is not
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "Error (Bad Pwd)"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ for User2 with guessed password 'Company123'.",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (Spray U2)"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos Error (KRB5KDC_ERR_PREAUTH_FAILED - Incorrect password for User2).",
      logType: "kerberos",
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "Error (Bad Pwd)"),
    },
    {
      // ... Attacker continues spraying the same password against other users ...
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ for User3 (user1) with guessed password 'Winter2024'.",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (Spray U3)"),
    },
    {
      logMessage:
        "DC01: Validates pre-authentication using user1's hash and the provided password ('Winter2024'). It matches!",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos AS-REP (Success! Password 'Winter2024' is valid for user1). TGT for user1 is issued.",
      logType: "success",
      action: () => {
        highlightElement("user1", stepDelay, "compromised"); // Mark user as compromised
        addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (Success!)");
      },
    },
    {
      logMessage:
        "IMPACT: Attacker identified valid credentials (user1:Winter2024) without triggering immediate lockouts. Can now authenticate as user1, access resources they have permissions for, and potentially perform further attacks (like Kerberoasting).",
      logType: "success",
    },
  ];

  const attackKerberoastingScenario = [
    {
      scenarioName: "Attack: Kerberoasting",
      logMessage:
        "Attacker Goal: Obtain the NTLM hash of a service account password by requesting a Service Ticket (ST) for it and cracking the ticket offline.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has compromised *any* valid domain user account credentials (low privilege is sufficient). Let's assume attacker controls 'userX'.",
      logType: "info",
      action: () => highlightElement("userX", stepDelay, "compromised"), // Represents any low-priv user
    },
    {
      logMessage:
        "Attacker (authenticated as userX) -> DC01: LDAP Search (Querying for accounts with Service Principal Names (SPNs) set, e.g., '(servicePrincipalName=*)', requesting the 'servicePrincipalName' attribute).",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Find SPNs"),
    },
    {
      logMessage:
        "DC01 -> Attacker: LDAP Search Result (Returns list of accounts and their associated SPNs. Example: 'svc_sql01' account has SPN 'MSSQLSvc/sql01.corp.local:1433').",
      logType: "ldap",
      action: () => addTemporaryEdge("dc01", "attacker", "LDAP", "SPN List"),
    },
    {
      logMessage:
        "Attacker (using userX's TGT) -> DC01: Kerberos TGS-REQ (Requesting a Service Ticket (ST/TGS) for a discovered SPN, e.g., 'MSSQLSvc/sql01...'). Any authenticated user can request STs for most services.",
      logType: "kerberos", // This is a legitimate Kerberos request from userX
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ (Roast SPN)"),
    },
    {
      logMessage:
        "DC01: Validates userX's TGT. Finds the service account ('svc_sql01') associated with the requested SPN.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker (as userX): Kerberos TGS-REP (Containing the Service Ticket). The crucial part is that the ticket itself is encrypted using the NTLM hash of the *service account* ('svc_sql01').",
      logType: "kerberos",
      action: () => {
        highlightElement("svc_sql01"); // Target service account whose hash is in the ticket
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
        "Attacker: Receives the TGS-REP and extracts the encrypted Service Ticket portion. No further interaction with the network is needed for cracking.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Performs OFFLINE password cracking (e.g., using Hashcat mode 13100 or John the Ripper) against the extracted encrypted ST blob, using password lists/rules.",
      logType: "attack", // Offline computation
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Successfully cracks the hash, revealing the plaintext password for the 'svc_sql01' service account.",
      logType: "success",
      action: () => highlightElement("svc_sql01", stepDelay, "compromised"),
    },
    {
      logMessage:
        "IMPACT: Attacker obtained the password for a potentially privileged service account ('svc_sql01'). This allows authentication *as* the service account, potentially granting access to sensitive systems (like the SQL server), execution of commands under the service's context, and lateral movement opportunities.",
      logType: "success",
    },
  ];

  const attackASREPRoastingScenario = [
    {
      scenarioName: "Attack: AS-REP Roasting",
      logMessage:
        "Attacker Goal: Obtain the NTLM hash of a user account that has Kerberos Pre-Authentication disabled, by requesting an AS-REP and cracking it offline.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker needs network visibility to a Domain Controller (KDC). NO initial domain credentials are required.",
      logType: "info",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Optional, if creds available or anonymous bind allowed: Filter: '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' to find users with 'DONT_REQ_PREAUTH' flag set). Attacker might also use pre-compiled lists or guess common usernames.",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Find NoPreauth Users"),
    },
    {
      logMessage:
        "Attacker: Identifies or guesses a target username (e.g., 'svc_backup') known or suspected to have pre-authentication disabled.",
      logType: "info",
      action: () => highlightElement("svc_backup"), // Example target user
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ for the target user ('svc_backup'). Critically, the request does NOT include any pre-authentication data (encrypted timestamp).",
      logType: "attack",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (NoPreAuth Data)"),
    },
    {
      logMessage:
        "DC01: Finds the user account 'svc_backup'. Checks its 'userAccountControl' attribute. Sees the DONT_REQ_PREAUTH flag is TRUE. Therefore, it skips the pre-authentication validation step.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos AS-REP (Sending the TGT response). Because pre-auth was skipped, this AS-REP contains a portion encrypted with the *target user's ('svc_backup')* NTLM hash.",
      logType: "kerberos", // DC sends encrypted ticket as user doesn't require pre-auth
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (Encrypted TGT Part)"),
    },
    {
      logMessage:
        "Attacker: Receives the AS-REP message and extracts the encrypted portion. No further communication needed for cracking.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Performs OFFLINE password cracking (e.g., Hashcat mode 18200) against the extracted encrypted blob using password lists/rules.",
      logType: "attack", // Offline computation
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Successfully cracks the hash, revealing the plaintext password for the 'svc_backup' user account.",
      logType: "success",
      action: () => highlightElement("svc_backup", stepDelay, "compromised"),
    },
    {
      logMessage:
        "IMPACT: Attacker obtained the password for a user ('svc_backup') without needing any prior credentials, solely by exploiting disabled pre-authentication. Allows authentication as this user, access to their resources, and potential further actions.",
      logType: "success",
    },
  ];

  const attackGoldenTicketScenario = [
    {
      scenarioName: "Attack: Golden Ticket Forgery & Use",
      logMessage:
        "Attacker Goal: Forge a Kerberos Ticket Granting Ticket (TGT) that impersonates any user (typically Domain Admin) and is accepted by any KDC in the domain.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: Attacker has obtained the NTLM hash or AES key(s) of the domain's KRBTGT account (e.g., via DCSync attack).",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("krbtgt", stepDelay, "compromised"); // Essential prerequisite
      },
    },
    {
      logMessage:
        "Prerequisite 2: Attacker knows the Domain SID.",
      logType: "info",
      // Attacker may need Domain SID, easily obtainable via LDAP anonymously or with any user creds
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "[Opt] Get Domain SID"),
    },
    {
      logMessage:
        "Attacker: Uses a tool (e.g., Mimikatz, Rubeus) OFFLINE on their machine to craft a fraudulent TGT. The attacker specifies: Target Username (e.g., 'Administrator'), UserID (e.g., 500), Group SIDs (e.g., Domain Admins - RID 512, Enterprise Admins - RID 519, etc.), the Domain SID, ticket lifetime, and crucially signs/encrypts the ticket using the stolen KRBTGT hash/key.",
      logType: "attack", // Offline action
      action: () => {
        highlightElement("attacker");
        highlightElement("admin1"); // Represents the impersonated DA specified in the ticket
      },
    },
    {
      logMessage:
        "Attacker: Injects the forged Golden Ticket into their current logon session's memory (e.g., using Mimikatz 'kerberos::ptt' or Rubeus 'ptt').",
      logType: "attack", // Local action on attacker machine to load the ticket
      action: () => highlightElement("attacker"),
    },
    {
      // Now, the attacker uses the forged TGT as if it were legitimate
      logMessage:
        "Attacker (session now contains forged DA TGT): -> DC01: Kerberos TGS-REQ (Requesting a Service Ticket for a target service, e.g., 'cifs/dc01.corp.local' or 'LDAP/dc01...'). The request uses the injected Golden Ticket.",
      logType: "attack", // Appears as the forged user (DA) to the DC
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ (w/ Golden TGT)"),
    },
    {
      logMessage:
        "DC01: Receives TGS-REQ. Validates the accompanying TGT. Since the TGT is correctly encrypted/signed with the *real* KRBTGT key (which the attacker stole), the DC accepts the TGT as valid! It doesn't need to check the user/groups inside against AD at this stage.",
      logType: "kerberos", // DC trusts the TGT because the KRBTGT key matches
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos TGS-REP (Issues the requested Service Ticket, e.g., for LDAP/dc01, granting access *as the user specified in the Golden Ticket* - e.g., 'Administrator').",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "TGS-REP (ST as DA)"),
    },
    {
      logMessage:
        "Attacker (using the obtained ST): -> DC01: Authenticated Operation (e.g., LDAP modify to add user to DA group, WMI/SMB exec on DC). The operation is authorized based on the identity/groups ('Administrator', 'Domain Admins') embedded in the ST derived from the Golden Ticket.",
      logType: "attack", // Successful privileged action
      action: () => {
        highlightElement("dc01", stepDelay, "compromised"); // DC compromised
        addTemporaryEdge("attacker", "dc01", "LDAP", "Privileged Op (as DA)");
      },
    },
    {
      logMessage:
        "IMPACT: Attacker has effectively become a Domain Admin (or any chosen user/groups) without needing a password. They can access any resource and perform any action allowed by the impersonated identity. This provides powerful, domain-wide persistence as long as the KRBTGT hash isn't changed *twice* (to invalidate old and new keys).",
      logType: "success",
    },
  ];

  const attackSilverTicketScenario = [
    {
      scenarioName: "Attack: Silver Ticket Forgery & Use",
      logMessage:
        "Attacker Goal: Forge a Kerberos Service Ticket (ST/TGS) for a *specific service* on a *specific host*, impersonating a user to access only that service.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has obtained the NTLM hash or AES key of the *service account* hosting the target service (e.g., the 'svc_sql01' account for 'MSSQLSvc/srv_sql01...'). This might come from Kerberoasting, memory dumping, etc.",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("svc_sql01", stepDelay, "compromised"); // Service account hash known
        highlightElement("srv_sql01"); // Target server hosting the service
      },
    },
    {
      logMessage:
        "Prerequisite 2: Attacker knows the Service Principal Name (SPN) of the target service (e.g., 'MSSQLSvc/srv_sql01.corp.local:1433') and the Domain SID.",
      logType: "info",
    },
    {
      logMessage:
        "Attacker: Uses a tool (e.g., Mimikatz, Kekeo, Rubeus) OFFLINE to craft a fraudulent Service Ticket (TGS/ST). The attacker specifies: Target Server FQDN (srv_sql01.corp.local), Target Service SPN (MSSQLSvc/...), User to impersonate (can be *any* user, e.g., 'Administrator' or even a non-existent user!), UserID/Group SIDs (if needed by the service), Domain SID, and signs/encrypts the ticket using the stolen *service account's* hash/key.",
      logType: "attack", // Offline action using service key
      action: () => {
        highlightElement("attacker");
        highlightElement("admin1"); // Represents the user being impersonated *within* the ticket
      },
    },
    {
      logMessage:
        "Attacker: Injects the forged Silver Ticket into their current logon session's memory OR prepares to present it directly.",
      logType: "attack", // Local action on attacker machine
      action: () => highlightElement("attacker"),
    },
    {
      // Attacker now directly contacts the TARGET SERVICE, bypassing the KDC for ST validation
      logMessage:
        "Attacker -> SRV-SQL-01 (Target Service Host): Kerberos AP-REQ (Presents the forged Silver Ticket directly to the SQL service). ***No TGS-REQ to the DC is needed***.",
      logType: "attack", // Direct communication with service using forged ST
      action: () =>
        addTemporaryEdge("attacker", "srv_sql01", "Kerberos", "AP-REQ (w/ Silver ST)"),
    },
    {
      logMessage:
        "SRV-SQL-01 (Service): Receives the AP-REQ containing the Silver Ticket. It decrypts the ticket using its *own* service account key (the one the attacker stole). Since the decryption works, the service trusts the ticket and the user identity/groups specified inside ('Administrator'). ***The service does NOT contact the KDC (DC) to validate the ST.***",
      logType: "kerberos", // Service validates using its own key
      action: () => highlightElement("srv_sql01", stepDelay, "highlighted"), // Service grants access
    },
    {
      logMessage:
        "Attacker -> SRV-SQL-01: Authenticated Service Request (e.g., SQL Query as 'Administrator' to enable xp_cmdshell). The service grants access based on the impersonated identity from the Silver Ticket.",
      logType: "sql", // Or other protocol depending on the service
      action: () =>
        addTemporaryEdge("attacker", "srv_sql01", "SQL", "Exec Cmd (as DA via Silver)"),
    },
    {
      logMessage:
        "SILVER TICKET SUCCESSFUL: Attacker gained access *specifically to the targeted service* (MSSQL on srv_sql01) as the chosen impersonated user ('Administrator'). Does not grant domain-wide access like a Golden Ticket. Less likely to be detected by DC logs but potentially detectable on the target server.",
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
        "Prerequisite: Attacker has extracted a valid Kerberos TGT for a user (e.g., user1) from memory on a compromised machine (host1) using Mimikatz.",
      logType: "attack",
      action: () => {
        highlightElement("attacker", stepDelay, "compromised"); // Attacker needs initial access
        highlightElement("host1", stepDelay, "compromised"); // Source of ticket
        highlightElement("user1"); // Owner of stolen TGT
      },
    },
    {
      logMessage:
        "Attacker (from their machine, injecting user1's TGT): -> DC01: Kerberos TGS-REQ (Using user1's stolen TGT, Requesting ST for service HTTP/srv-web-01...).",
      logType: "attack", // Attacker initiates, but KDC sees it as user1
      action: () =>
        addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ (PtT)"),
    },
    {
      logMessage:
        "DC01: Validates the TGT (it's valid, signed by KRBTGT). Issues ST for the requested service (HTTP/srv-web-01). Sees request as coming from user1.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker: Kerberos TGS-REP (Sending ST for HTTP/srv-web-01, usable by user1).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "TGS-REP (ST)"),
    },
    {
      logMessage:
        "Attacker (injecting the received ST): -> SRV-WEB-01: Kerberos AP-REQ (Presenting the ST for HTTP/srv-web-01).",
      logType: "attack", // Attacker initiates, but service sees it as user1
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "Kerberos", "AP-REQ (PtT)"),
    },
    {
      logMessage:
        "SRV-WEB-01: Decrypts ST (with its service key), validates authenticator. Sees the request is authenticated as 'user1'. Grants access based on user1's permissions.",
      logType: "kerberos", // Service validates
      action: () => highlightElement("srv_web01", stepDelay, "highlighted"),
    },
    {
      logMessage:
        "IMPACT: Attacker successfully authenticated to SRV-WEB-01 *as user1* without knowing their password. Can access resources and perform actions as user1 on that service. Can repeat for any service user1 can access.",
      logType: "success",
    },
  ];

  const attackPassTheHashScenario = [
    {
      scenarioName: "Attack: Pass-the-Hash",
      logMessage: "Attacker Goal: Authenticate to services using a stolen NTLM hash.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has obtained user1's NTLM hash (e.g., via Mimikatz on a compromised host).",
      logType: "attack",
      action: () => {
        highlightElement("attacker", stepDelay, "compromised");
        highlightElement("user1"); // Owner of the hash
      },
    },
    {
      logMessage:
        "Attacker -> DC01: LDAP Search (Optional Recon: Check user1's group memberships to identify targets/privileges).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Recon Groups"),
    },
    {
      logMessage:
        "Attacker -> SRV-WEB-01: SMB Authentication Request (Attempting NTLM authentication using user1's stolen NTLM hash).",
      logType: "smb", // Or other NTLM-supporting protocols like WMI/RPC
      action: () =>
        addTemporaryEdge("attacker", "srv_web01", "SMB", "Auth Req (PtH)"),
    },
    // Note: NTLM involves a challenge-response not fully detailed here for simplicity
    {
      logMessage:
        "SRV-WEB-01: Verifies the NTLM response (derived from the hash). Authentication successful.",
      logType: "success",
      action: () => highlightElement("srv_web01", stepDelay, "highlighted"),
    },
    {
      logMessage:
        "IMPACT: Attacker successfully authenticated to SRV-WEB-01 *as user1* without the password. Can potentially access resources or execute commands (e.g., via SMB/WMI) as user1. Can repeat for other services supporting NTLM.",
      logType: "success",
    },
  ];

  const attackUnconstrainedDelegationScenario = [
    {
      scenarioName: "Attack: Unconstrained Delegation Abuse",
      logMessage:
        "Attacker Goal: Steal a privileged user's TGT when they authenticate to a compromised server configured for Unconstrained Delegation.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker compromises SRV-APP-01 (srv_app01), which is configured for Kerberos Unconstrained Delegation.",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("srv_app01", stepDelay, "compromised");
      },
    },
    {
      logMessage: "Legitimate Admin (admin1) logs onto SRV-APP-01 (e.g., via RDP, WinRM).",
      logType: "info",
      action: () => highlightElement("admin1"),
    },
    {
      logMessage:
        "Admin's Machine -> SRV-APP-01: Kerberos AP-REQ (Authenticating admin1 to srv_app01).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("admin1", "srv_app01", "Kerberos", "AP-REQ (Admin)"),
    },
    {
      logMessage:
        "SRV-APP-01: Authenticates Admin. Crucially, the KDC sent Admin's *forwardable TGT* to SRV-APP-01 because it has Unconstrained Delegation enabled. The TGT is stored in LSASS memory.",
      logType: "kerberos",
      action: () => highlightElement("srv_app01"),
    },
    {
      logMessage:
        "Attacker (on the compromised srv_app01): Uses Mimikatz/Rubeus to extract Admin's forwarded TGT from LSASS memory.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker (on srv_app01, injecting Admin's TGT): -> DC01: Kerberos TGS-REQ (Using Admin's stolen TGT, requesting ST for a sensitive service, e.g., LDAP/dc01...).",
      logType: "attack",
      action: () =>
        addTemporaryEdge("srv_app01", "dc01", "Kerberos", "TGS-REQ (as Admin)"),
    },
    {
      logMessage: "DC01: Validates the TGT (it's Admin's), issues ST for the LDAP service.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker (on srv_app01): Kerberos TGS-REP (Sending ST for LDAP/dc01).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "srv_app01", "Kerberos", "TGS-REP (ST)"),
    },
    {
      logMessage:
        "Attacker (on srv_app01, using the obtained ST): -> DC01: LDAP Operations (e.g., modify group memberships, read sensitive data - Authenticated as Admin!).",
      logType: "attack",
      action: () => {
        highlightElement("dc01", stepDelay, "compromised"); // DC access achieved as Admin
        addTemporaryEdge("srv_app01", "dc01", "LDAP", "LDAP Modify (as Admin)");
      },
    },
    {
      logMessage:
        "IMPACT: Attacker leveraged the compromised Unconstrained Delegation server to capture a highly privileged user's TGT. Can now impersonate this user (potentially Domain Admin) across the domain, potentially leading to full domain compromise and persistence (TGT valid until expiry).",
      logType: "success",
    },
  ];

  const attackRBCDScenario = [
    {
      scenarioName: "Attack: Resource-Based Constrained Delegation Abuse",
      logMessage:
        "Attacker Goal: Impersonate a user (e.g., Domain Admin) on a specific target machine (SRV-FILES01) by abusing delegation rights configured via object attributes.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: Attacker has compromised a principal (e.g., user 'lowpriv' or computer 'host1$') that has permission to write to the 'msDS-AllowedToActOnBehalfOfOtherIdentity' attribute of the target computer object (SRV-FILES01). Let's assume attacker controls 'host1$'.",
      logType: "attack",
      action: () => {
        highlightElement("host1", stepDelay, "compromised"); // Attacker controls this principal
        highlightElement("srv_files01"); // Target resource
      },
    },
    {
      logMessage:
        "Prerequisite 2: Attacker needs credentials (e.g., hash or Kerberos ticket) for the controlled principal (host1$).",
      logType: "info",
    },
    {
      logMessage:
        "Attacker (using host1$'s credentials): -> DC01: LDAP Modify Request (Write host1$'s SID to the 'msDS-AllowedToActOnBehalfOfOtherIdentity' attribute on the 'srv_files01' computer object). This configures srv_files01 to trust host1$ for delegation.",
      logType: "attack", // The core configuration abuse
      action: () => {
        addTemporaryEdge("host1", "dc01", "LDAP", "LDAP Modify (Set RBCD)");
      },
    },
    {
      logMessage:
        "DC01: Validates ACL (confirms host1$ has write permission on the attribute for srv_files01). Updates the attribute.",
      logType: "ldap",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "Attacker (using host1$ creds): -> DC01: Kerberos TGS-REQ (S4U2Self - Requesting a service ticket *to host1$ itself*, specifying impersonation of the target victim, e.g., 'DomainAdmin').",
      logType: "attack", // Getting a ticket to self, impersonating victim
      action: () =>
        addTemporaryEdge("host1", "dc01", "Kerberos", "TGS-REQ (S4U2Self)"),
    },
    {
      logMessage:
        "DC01: Validates host1$ can request tickets. Issues a *forwardable* Service Ticket *for host1$* (valid for host1$ to use), containing 'DomainAdmin' identity information inside.",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "host1", "Kerberos", "TGS-REP (Self ST)"),
    },
    {
      logMessage:
        "Attacker (using host1$ creds and the S4U2Self ticket): -> DC01: Kerberos TGS-REQ (S4U2Proxy - Uses the S4U2Self ticket as evidence, requests a Service Ticket for the target service 'cifs/srv_files01.corp.local' *as DomainAdmin*).",
      logType: "attack", // Requesting ticket to target service
      action: () => {
        addTemporaryEdge("host1", "dc01", "Kerberos", "TGS-REQ (S4U2Proxy)");
      },
    },
    {
      logMessage:
        "DC01: Validates the S4U2Self ticket. Checks RBCD on target 'srv_files01': sees 'host1$' is listed in 'msDS-AllowedToActOnBehalfOfOtherIdentity'. Issues ST for 'cifs/srv_files01' usable by 'host1$' but containing 'DomainAdmin' identity.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker (as host1$): Kerberos TGS-REP (Sending the Service Ticket for cifs/srv_files01, usable *as DomainAdmin*).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "host1", "Kerberos", "TGS-REP (Proxy ST)"),
    },
    {
      logMessage:
        "Attacker (injects the S4U2Proxy ST): -> SRV-FILES01: SMB AP-REQ (Presents the proxy ST to access the file share).",
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
        "SRV-FILES01: Validates the ticket (decrypts with its key). Sees the user identity inside is 'DomainAdmin'. Grants access with Domain Admin privileges.",
      logType: "smb", // Or relevant protocol for the service
    },
    {
      logMessage:
        "IMPACT: Attacker leveraged control of 'host1$' and its write permission on 'srv_files01's delegation attribute to gain Domain Admin-level access specifically *to* srv_files01. Can potentially execute code (e.g., PsExec via SMB) or access sensitive data on srv_files01 as the impersonated DA.",
      logType: "success",
    },
  ];

  const attackESC1Scenario = [
    {
      scenarioName: "Attack: AD CS ESC1 (Template ACL + ENROLLEE_SUPPLIES_SUBJECT)",
      logMessage:
        "Attacker Goal: Obtain a certificate allowing authentication as a privileged user (e.g., Domain Admin) by abusing AD CS template permissions and configuration.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: Attacker controls a principal (e.g., compromised standard user 'CORP\\BOB') which has 'Write' permissions on a Certificate Template object in AD (e.g., 'UserTemplateVulnerable').",
      logType: "attack",
      action: () => {
        highlightElement("user2", stepDelay, "compromised"); // Attacker's initial foothold
        highlightElement("ca01"); // Target CA infrastructure
        highlightElement("dc01"); // AD interaction needed
      },
    },
    {
      logMessage:
        "Prerequisite 2: The target template ('UserTemplateVulnerable') does NOT require 'Manager Approval' for issuance.",
      logType: "info",
    },
    {
      logMessage:
        "Prerequisite 3: The CA grants enrollment rights for this template to low-privileged users (including the attacker's controlled principal 'CORP\\BOB').",
      logType: "info",
    },
    {
      logMessage:
        "Attacker (as user2) -> DC01: LDAP Modify Request (Targeting the 'UserTemplateVulnerable' template object): Sets the 'mspki-enrollment-flag' attribute to include the 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT' (0x1) flag. This allows the requester to specify a Subject Alternative Name (SAN).",
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
        "DC01: Validates ACL (user2 has Write permission). Updates the template object properties in the AD configuration partition.",
      logType: "ldap",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "CA01: Periodically polls AD and refreshes its template cache. (This introduces a potential delay before the change is active on the CA).",
      logType: "info",
      action: () => highlightElement("ca01"),
      delay: 2000, // Simulate cache refresh delay if desired
    },
    {
      logMessage:
        "Attacker (as user2) -> CA01: Certificate Enrollment Request (RPC/HTTP) (Requests a certificate using the now-modified 'UserTemplateVulnerable' template. Critically, *supplies* a Subject Alternative Name (SAN) field specifying the UPN of a privileged user, e.g., 'DomainAdmin@corp.local').",
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
        "CA01: Checks enrollment permissions (user2 allowed). Sees 'ENROLLEE_SUPPLIES_SUBJECT' flag is set on template in its cache. Allows the supplied SAN. Issues a certificate technically *for* user2 but containing the 'DomainAdmin@corp.local' UPN in the SAN.",
      logType: "info", // CA follows the (now malicious) template rules
      action: () => highlightElement("ca01"),
    },
    {
      logMessage:
        "CA01 -> Attacker (as user2): Certificate Response (RPC/HTTP) (Sends the issued certificate, containing the DA UPN in SAN, back to the requester).",
      logType: "rpc", // or HTTP
      action: () =>
        addTemporaryEdge("ca01", "user2", "RPC/HTTP", "Cert Issued (DA SAN!)"),
    },
    {
      logMessage:
        "Attacker: Now possesses a certificate that can be used for Domain Admin authentication.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker -> DC01: Kerberos AS-REQ (Using PKINIT extension - Presents the obtained certificate for pre-authentication instead of a password hash).",
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
        "DC01: Validates certificate chain/trust. Extracts the UPN 'DomainAdmin@corp.local' from the SAN. Treats the request as coming from the legitimate Domain Admin. Issues a TGT for the Domain Admin.",
      logType: "kerberos", // DC accepts cert based on SAN for authentication
      action: () => {
        highlightElement("dc01");
        highlightElement("admin1", stepDelay, "compromised"); // Assuming admin1 represents the DA account visually
      },
    },
    {
      logMessage: "DC01 -> Attacker: Kerberos AS-REP (Sending TGT for DomainAdmin!).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (DA TGT!)"),
    },
    {
      logMessage:
        "IMPACT: Attacker exploited weak template ACLs to modify a certificate template, enabling SAN specification during enrollment. This allowed obtaining a certificate valid for Domain Admin authentication via Kerberos PKINIT, leading to the acquisition of a DA TGT. Full domain compromise is highly likely.",
      logType: "success",
    },
  ];

  const attackDCSyncScenario = [
    {
      scenarioName: "Attack: DCSync",
      logMessage:
        "Attacker Goal: Obtain password hashes (especially KRBTGT hash) by abusing Domain Replication privileges to mimic Domain Controller replication.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has compromised credentials (or a Kerberos ticket) for an account possessing Domain Replication rights ('Replicating Directory Changes' & 'Replicating Directory Changes All'). E.g., a Domain Admin (admin1) or a specially delegated account.",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("admin1", stepDelay, "compromised"); // Account with required rights
      },
    },
    {
      logMessage:
        "Attacker (using admin1 credentials/ticket) -> DC01: RPC Bind Request (Connects to the Directory Replication Service Remote Protocol - MS-DRSR - endpoint on the target DC).",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "Bind DRSR"),
    },
    {
      logMessage:
        "Attacker -> DC01: DRSR Remote Procedure Call (e.g., using DRSUAPI GetNCChanges function): Requests replication updates for the Domain Naming Context, specifically asking for sensitive data including password hashes (by requesting specific attributes).",
      logType: "attack", // Malicious use of legitimate replication protocol
      action: () =>
        addTemporaryEdge("attacker", "dc01", "DRSUAPI", "GetNCChanges Request"),
    },
    {
      logMessage:
        "DC01: Receives the GetNCChanges request. Verifies via Access Control checks that the requesting user (authenticated as admin1) possesses the required privileges (DS-Replication-Get-Changes / DS-Replication-Get-Changes-All).",
      logType: "info", // DC performs standard authorization check
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01: If authorized, accesses its local Active Directory database (ntds.dit) to retrieve the requested object data, including sensitive attributes like NTLM hashes, Kerberos keys (past and present for krbtgt), etc.",
      logType: "info", // Internal DC action accessing sensitive store
      action: () =>
        addTemporaryEdge("dc01", "dc01", "DB Access", "Read Secrets from NTDS.dit"), // Self-loop indicating internal process
    },
    {
      logMessage:
        "DC01 -> Attacker: DRSR GetNCChanges Response (Streams the requested replication data back to the 'replicating DC' - which is actually the attacker. This data contains the objects and their requested attributes, including krbtgt hash, admin account hashes, etc.).",
      logType: "attack", // Sensitive data exfiltration via replication channel
      action: () => {
        highlightElement("krbtgt", stepDelay, "compromised"); // Key target obtained
        addTemporaryEdge("dc01", "attacker", "DRSUAPI", "GetNCChanges Resp (Secrets!)");
      },
    },
    {
      logMessage:
        "IMPACT: Attacker has obtained critical domain secrets remotely without needing code execution on the DC. Most importantly, the KRBTGT account's hash allows the attacker to forge Kerberos Golden Tickets offline, granting domain-wide administrative access as any user, achieving effective domain dominance and long-term persistence.",
      logType: "success",
    },
  ];

  // --- SQL Access (Post-Roast) ---
  const attackSQLAccessScenario = [
    {
      scenarioName: "Attack: SQL Access (Post-Roast)",
      logMessage: "Prerequisite: Attacker previously Kerberoasted SPN 'MSSQLSvc/sql01.domain.com' associated with 'svc_sql01' account and cracked its password/hash.",
      logType: "setup",
      action: () => {
        highlightElement("attacker");
        highlightElement("svc_sql01");
      },
    },
    {
      logMessage: "Attacker -> DC01: Kerberos AS-REQ (Request TGT for svc_sql01 using cracked creds)",
      logType: "kerberos",
      action: () => addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (svc_sql01)"),
    },
    {
      logMessage: "DC01 -> Attacker: Kerberos AS-REP (Issues TGT for svc_sql01)",
      logType: "kerberos",
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (TGT)"),
    },
    {
      logMessage: "Attacker -> DC01: Kerberos TGS-REQ (Using TGT, Request ST for SPN 'MSSQLSvc/sql01.domain.com')",
      logType: "kerberos",
      action: () => addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ (SQL SPN)"),
    },
    {
      logMessage: "DC01 -> Attacker: Kerberos TGS-REP (Issues Service Ticket for SQL Server)",
      logType: "kerberos",
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "TGS-REP (SQL ST)"),
    },
    {
      logMessage: "Attacker -> SQL Server (srv_sql01): TDS Login Request with Kerberos AP-REQ (Presenting ST)",
      logType: "tds", // Tabular Data Stream (SQL Protocol)
      action: () => addTemporaryEdge("attacker", "srv_sql01", "TDS/Kerberos", "Login (AP-REQ)"),
    },
    {
      logMessage: "SQL Server (srv_sql01): Validates Kerberos ticket, authenticates attacker as svc_sql01.",
      logType: "tds",
      action: () => highlightElement("srv_sql01"),
    },
    {
      logMessage: "Attacker -> SQL Server (srv_sql01): Executes SQL commands via TDS (e.g., SELECT @@version, xp_cmdshell 'whoami')",
      logType: "tds",
      action: () => addTemporaryEdge("attacker", "srv_sql01", "TDS", "SQL Query/Exec"),
    },
    {
      logMessage: "SQL Server (srv_sql01) -> Attacker: TDS Response (Query results / command output)",
      logType: "tds",
      action: () => addTemporaryEdge("srv_sql01", "attacker", "TDS", "SQL Result"),
    },
    {
      logMessage: "SQL ACCESS SUCCESSFUL: Attacker authenticated to SQL Server as the service account via Kerberos. Can now interact with the database, potentially execute OS commands (xp_cmdshell), and exfiltrate data.",
      logType: "success",
    },
  ]

  // --- Remote Service Exec (PsExec-like) ---
  const attackRemoteExecScenario = [
    {
      scenarioName: "Attack: Remote Service Exec (PsExec-like)",
      logMessage: "Prerequisite: Attacker has credentials (hash, password, ticket) for a user (e.g., 'AdminUser') with *Local Administrator* rights on the target (SRV-WEB-01).",
      logType: "setup",
      action: () => {
        highlightElement("attacker");
        highlightElement("admin1");
      },
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: SMB Negotiate & Session Setup (Authenticate as AdminUser using stolen creds)",
      logType: "smb", // This implicitly uses NTLM or Kerberos
      action: () => addTemporaryEdge("attacker", "srv_web01", "SMB", "Authenticate (Admin)"),
    },
    {
      logMessage: "SRV-WEB-01 -> Attacker: SMB Session Setup Success",
      logType: "smb",
      action: () => addTemporaryEdge("srv_web01", "attacker", "SMB", "Auth Success"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: SMB Write Request (Copy malicious 'payload.exe' to ADMIN$ or C$ share)",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "srv_web01", "SMB", "Write Payload (ADMIN$)"),
    },
    {
      logMessage: "SRV-WEB-01 -> Attacker: SMB Write Response Success",
      logType: "smb",
      action: () => addTemporaryEdge("srv_web01", "attacker", "SMB", "Write Success"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Bind (Connect to Service Control Manager pipe 'svcctl')",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "SCM Bind (svcctl)"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (OpenSCManagerW)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "SCM Open"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (CreateServiceW - pointing to 'C:\\Windows\\payload.exe', auto-start, own process)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "CreateService"),
    },
    {
      logMessage: "SRV-WEB-01 (SCM): Creates the malicious service ('EvilService').",
      logType: "internal",
      action: () => highlightElement("srv_web01"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (StartService 'EvilService')",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "StartService"),
    },
    {
      logMessage: "SRV-WEB-01: Service 'EvilService' starts, executing 'payload.exe' (typically as SYSTEM).",
      logType: "execution",
      action: () => highlightElement("srv_web01", stepDelay, "compromised"),
    },
    // --- Cleanup ---
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (DeleteService 'EvilService')",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "DeleteService"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: SMB Delete Request (Remove 'payload.exe' from ADMIN$/C$)",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "srv_web01", "SMB", "Delete Payload"),
    },
    {
      logMessage: "REMOTE EXECUTION SUCCESSFUL: Attacker uploaded and executed a payload on SRV-WEB-01, typically achieving SYSTEM-level code execution.",
      logType: "success",
    },
  ]

  // --- Shadow Credentials ---
  const attackShadowCredentialsScenario = [
    {
      scenarioName: "Attack: Shadow Credentials (Key Trust)",
      logMessage: "Prerequisite: Attacker controls account 'host1$' (e.g., compromised machine) which has write permissions (e.g., GenericWrite) over target account 'user1'.",
      logType: "setup",
      action: () => {
        highlightElement("attacker");
        highlightElement("host1", stepDelay, "compromised"); // Show host1 is controlled
      },
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Check effective rights of 'host1$' on 'user1')",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Check Rights (host1$ -> user1)"),
    },
    {
      logMessage: "Attacker (Offline): Generates a new public/private key pair and self-signed certificate.",
      logType: "offline_action",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Bind Request (Authenticate as 'host1$' using its credentials)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Bind (host1$)"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Modify Request (Add attacker's public key to 'user1's 'msDS-KeyCredentialLink' attribute, authenticated as 'host1$')",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Modify msDS-KeyCredentialLink (user1)"),
    },
    {
      logMessage: "DC01: Updates 'user1' object based on 'host1$'s permissions.",
      logType: "internal",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 -> Attacker: LDAP Modify Response (Success)",
      logType: "ldap",
      action: () => addTemporaryEdge("dc01", "attacker", "LDAP", "Modify Success"),
    },
    // --- Authentication using the shadow credential ---
    {
      logMessage: "Attacker -> DC01: Kerberos AS-REQ with PA-PK-AS-REQ (Authenticate as 'user1' using the newly added key/certificate - PKINIT)",
      logType: "kerberos",
      action: () => addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ PKINIT (user1)"),
    },
    {
      logMessage: "DC01: Validates certificate against 'user1's 'msDS-KeyCredentialLink'.",
      logType: "internal",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 -> Attacker: Kerberos AS-REP (Issues TGT for 'user1')",
      logType: "kerberos",
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (TGT for user1)"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Modify Request (Remove attacker's key from 'user1's 'msDS-KeyCredentialLink', authenticated as 'host1$')",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Remove KeyCredential"),
    },
    {
      logMessage: "SHADOW CREDENTIALS SUCCESSFUL: Attacker added a key credential to the target user via a compromised account with write permissions. Attacker can now authenticate as the target user using certificate-based Kerberos (PKINIT).",
      logType: "success",
    },
  ]


  // --- PrintNightmare ---
  const attackPrintNightmareScenario = [
    {
      scenarioName: "Attack: PrintNightmare",
      logMessage: "Prerequisite: Target (SRV-FILES01) runs Print Spooler service, is vulnerable (CVE-2021-1675/34527 - Point/Print or driver install restrictions not configured securely). Attacker has valid domain user credentials (can be low-priv 'user1').",
      logType: "setup",
      action: () => {
        highlightElement("attacker");
        highlightElement("srv_files01"); // Target Print Server
      },
    },
    {
      logMessage: "Attacker -> SRV-FILES01: RPC Bind (Connect to Print Spooler service pipe 'spoolss' - MS-RPRN protocol)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_files01", "RPC", "Bind Spoolss"),
    },
    {
      logMessage: "Attacker -> SRV-FILES01: RPC Call (RpcAddPrinterDriverEx - specifying a malicious driver path, e.g., \\\\attacker_ip\\share\\evil.dll)",
      logType: "rpc", // MS-RPRN
      action: () => addTemporaryEdge("attacker", "srv_files01", "RPC", "RpcAddPrinterDriverEx"),
    },
    {
      logMessage: "SRV-FILES01 (Print Spooler): Attempts to load the specified driver DLL (evil.dll) from attacker's path.",
      logType: "internal", // Service action
      action: () => highlightElement("srv_files01"),
    },
    {
      logMessage: "SRV-FILES01 -> Attacker's Machine: SMB Request (Fetch evil.dll)",
      logType: "smb", // Spooler fetches DLL
      action: () => addTemporaryEdge("srv_files01", "attacker", "SMB", "Fetch DLL"),
    },
    {
      logMessage: "SRV-FILES01 (Print Spooler): Loads 'evil.dll' into its process (running as SYSTEM).",
      logType: "execution",
      action: () => highlightElement("srv_files01", stepDelay, "compromised"),
    },
    {
      logMessage: "PRINTNIGHTMARE SUCCESSFUL: Attacker exploited vulnerability in Print Spooler service to achieve remote code execution as SYSTEM on SRV-FILES01 by forcing it to load a malicious DLL.",
      logType: "success",
    },
  ]


  // --- NTLM Relay (SMB -> LDAP example) ---
  const attackNTLMRelayScenario = [
    {
      scenarioName: "Attack: NTLM Relay (SMB -> LDAP example)",
      logMessage: "Prerequisite: Attacker can trigger authentication from a victim (e.g., 'host1$') to the attacker machine (via PrinterBug, LLMNR Poisoning, etc.). Target LDAP service (DC01) does not enforce LDAP signing/channel binding. Relay target (AD CS Web Enrollment) is vulnerable.",
      logType: "setup",
      action: () => {
        highlightElement("attacker");
        highlightElement("host1"); // Victim machine
        highlightElement("dc01"); // Target LDAP
        highlightElement("ca01");
      },
    },
    {
      logMessage: "Attacker triggers 'host1$' to authenticate to Attacker's machine (e.g., via PrinterBug forcing SMB auth)",
      logType: "trigger", // Conceptual trigger step
      action: () => addTemporaryEdge("attacker", "host1", "Trigger", "Coerce Auth"),
    },
    {
      logMessage: "Victim (host1$) -> Attacker: SMB Negotiate & Session Setup / NTLM Negotiate (Type 1)",
      logType: "ntlm", // Victim initiates auth TO attacker
      action: () => addTemporaryEdge("host1", "attacker", "NTLM", "Negotiate (Type 1)"),
    },
    // --- Relay START ---
    {
      logMessage: "Attacker -> Target LDAP (DC01): LDAP Bind Request (Forwarding NTLM Type 1 Info)",
      logType: "ntlm_relay",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP/NTLM", "Relay Type 1"),
    },
    {
      logMessage: "Target LDAP (DC01) -> Attacker: LDAP Bind Response / NTLM Challenge (Type 2)",
      logType: "ntlm_relay",
      action: () => addTemporaryEdge("dc01", "attacker", "LDAP/NTLM", "Relay Type 2 (Challenge)"),
    },
    {
      logMessage: "Attacker -> Victim (host1$): SMB Response / Forward NTLM Challenge (Type 2)",
      logType: "ntlm",
      action: () => addTemporaryEdge("attacker", "host1", "NTLM", "Challenge (Type 2)"),
    },
    {
      logMessage: "Victim (host1$) -> Attacker: SMB Session Setup / NTLM Authenticate (Type 3 - Response)",
      logType: "ntlm",
      action: () => addTemporaryEdge("host1", "attacker", "NTLM", "Authenticate (Type 3)"),
    },
    {
      logMessage: "Attacker -> Target LDAP (DC01): LDAP Bind Request / Forward NTLM Authenticate (Type 3)",
      logType: "ntlm_relay",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP/NTLM", "Relay Type 3"),
    },
    {
      logMessage: "Target LDAP (DC01): Authenticates relayed session (as 'host1$'). Grants LDAP access.",
      logType: "internal",
      action: () => highlightElement("dc01", stepDelay, "compromised_session"), // Show successful relay to LDAP
    },
    // --- Post-Relay Action (Example: AD CS Abuse) ---
    {
      logMessage: "Attacker (relayed as host1$) -> AD CS Server: HTTP Request (Request certificate via Web Enrollment)",
      logType: "http", // Assumes ADCS server element exists
      action: () => addTemporaryEdge("attacker", "adcs_server", "HTTP", "Cert Request (Relayed)"),
    },
    {
      logMessage: "AD CS Server: Issues certificate for 'host1$'.",
      logType: "internal",
      action: () => highlightElement("adcs_server"),
    },
    {
      logMessage: "AD CS Server -> Attacker: HTTP Response (Certificate Download)",
      logType: "http",
      action: () => addTemporaryEdge("adcs_server", "attacker", "HTTP", "Cert Download"),
    },
    {
      logMessage: "Attacker: Obtains certificate for 'host1$', can now authenticate as machine.",
      logType: "result",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage: "NTLM RELAY SUCCESSFUL: Attacker coerced authentication from a victim and relayed it to a target service (LDAP/AD CS). Attacker potentially gained a certificate for the victim machine account, enabling further impersonation/attacks.",
      logType: "success",
    },
  ]

  const attackLLMNRPoisoningScenario = [
    {
      scenarioName: "Attack: LLMNR/NBT-NS Poisoning & NTLM Relay/Capture",
      logMessage: "Attacker starts LLMNR/NBT-NS poisoner and NTLM Relay/Capture server (e.g., Responder)",
      logType: "setup",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage: "User (user1) attempts to access a non-existent or mistyped network resource (e.g., \\\\fileshar\\)",
      logType: "user_action",
      action: () => highlightElement("user1"),
    },
    {
      logMessage: "User (user1) -> Network: Broadcasts LLMNR/NBT-NS Query for 'fileshar'",
      logType: "llmnr_nbtns", // Combined type
      action: () => addTemporaryEdge("user1", "network", "LLMNR/NBT-NS", "Query"), // network is conceptual here
    },
    {
      logMessage: "Attacker -> User (user1): LLMNR/NBT-NS Spoofed Response ('fileshar' is at Attacker's IP)",
      logType: "llmnr_nbtns",
      action: () => addTemporaryEdge("attacker", "user1", "LLMNR/NBT-NS", "Spoofed Reply"),
    },
    {
      logMessage: "User (user1) -> Attacker: Attempts SMB connection based on spoofed response",
      logType: "smb",
      action: () => addTemporaryEdge("user1", "attacker", "SMB", "Connection Attempt"),
    },
    {
      logMessage: "User (user1) -> Attacker: Sends NTLM Authentication (Negotiate - Type 1)",
      logType: "ntlm",
      action: () => addTemporaryEdge("user1", "attacker", "NTLM", "Negotiate (Type 1)"),
    },
    {
      logMessage: "Attacker -> User (user1): Sends NTLM Challenge (Type 2)",
      logType: "ntlm",
      action: () => addTemporaryEdge("attacker", "user1", "NTLM", "Challenge (Type 2)"),
    },
    {
      logMessage: "User (user1) -> Attacker: Sends NTLM Response (Authenticate - Type 3 with NTLMv1/v2 Hash)",
      logType: "ntlm",
      action: () => addTemporaryEdge("user1", "attacker", "NTLM", "Response (Type 3)"),
    },
    {
      logMessage: "Attacker (Relay): Forwards NTLM credentials to target server (e.g., SRV-FILES01)",
      logType: "ntlm_relay",
      action: () => addTemporaryEdge("attacker", "srv_files01", "NTLM", "Relay Auth"), // Assuming srv_files01 exists
    },
    {
      logMessage: "Target Server (SRV-FILES01): Grants access based on relayed user1 credentials",
      logType: "result",
      action: () => highlightElement("srv_files01"), // Show compromised server
    },
    {
      logMessage:
        "LLMNR/NBT-NS POISONING SUCCESSFUL: Attacker intercepted authentication attempt. Captured NTLM hash for offline cracking OR relayed authentication to another service, potentially gaining access as user1.",
      logType: "success",
    },
  ];

  const attackLDAPReconScenario = [
    {
      scenarioName: "Attack: LDAP Reconnaissance",
      logMessage: "Attacker (authenticated user) targets Domain Controller (DC01) for LDAP recon",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: LDAP Bind Request (Authenticate to LDAP service)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Bind"),
    },
    {
      logMessage: "DC01 -> Attacker: LDAP Bind Success",
      logType: "ldap",
      action: () => addTemporaryEdge("dc01", "attacker", "LDAP", "Bind Success"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Query RootDSE for naming contexts)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Query RootDSE"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Enumerate Domain Users - e.g., '(objectCategory=person)')",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Enum Users"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Enumerate Domain Computers - e.g., '(objectCategory=computer)')",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Enum Computers"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Find Privileged Groups - e.g., '(adminCount=1)')",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Find Admins"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Find Service Principal Names - e.g., '(servicePrincipalName=*)')",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Find SPNs"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Search (Identify Group Memberships)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Group Members"),
    },
    {
      logMessage: "Attacker -> DC01: LDAP Unbind",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Unbind"),
    },
    {
      logMessage:
        "LDAP RECON COMPLETE: Attacker gathered extensive information about users, computers, groups, SPNs, and AD structure. This data is crucial for identifying targets and planning further attacks.",
      logType: "success",
    },
  ];

  const attackDNSReconScenario = [
    {
      scenarioName: "Attack: DNS Reconnaissance",
      logMessage: "Attacker targets the Domain DNS Server (often DC01)",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01"); // Assuming DC01 is the DNS server
      },
    },
    {
      logMessage: "Attacker -> DC01 (DNS): Query SRV Records for Domain Controllers (_ldap._tcp.dc._msdcs.<domain>)",
      logType: "dns",
      action: () => addTemporaryEdge("attacker", "dc01", "DNS", "SRV Query (DCs)"),
    },
    {
      logMessage: "Attacker -> DC01 (DNS): Query SRV Records for Global Catalog (_gc._tcp.<domain>)",
      logType: "dns",
      action: () => addTemporaryEdge("attacker", "dc01", "DNS", "SRV Query (GCs)"),
    },
    {
      logMessage: "Attacker -> DC01 (DNS): Query A Records for specific hosts (e.g., SRV-FILES01)",
      logType: "dns",
      action: () => addTemporaryEdge("attacker", "dc01", "DNS", "A Query (Host)"),
    },
    {
      logMessage: "Attacker -> DC01 (DNS): Attempt Zone Transfer (AXFR Request for <domain>)",
      logType: "dns",
      action: () => addTemporaryEdge("attacker", "dc01", "DNS", "AXFR Attempt"),
    },
    {
      logMessage: "DC01 (DNS) -> Attacker: Zone Transfer Response (Success or Failure - often restricted)",
      logType: "dns",
      action: () => addTemporaryEdge("dc01", "attacker", "DNS", "AXFR Response"),
    },
    {
      logMessage:
        "DNS RECON COMPLETE: Attacker identified key infrastructure servers (DCs, GCs) and potentially other hosts via DNS lookups. A successful Zone Transfer (if allowed) would provide a comprehensive list of domain DNS records.",
      logType: "success",
    },
  ];

  const attackSMBShareEnumScenario = [
    {
      scenarioName: "Attack: SMB Share Enumeration",
      logMessage: "Attacker (authenticated user) targets a server (SRV-FILES01) for share enumeration",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("srv_files01");
      },
    },
    {
      logMessage: "Attacker -> SRV-FILES01: SMB Negotiate Protocol Request",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "srv_files01", "SMB", "Negotiate"),
    },
    {
      logMessage: "Attacker -> SRV-FILES01: SMB Session Setup Request (Authenticate user)",
      logType: "smb", // Contains NTLM or Kerberos auth data
      action: () => addTemporaryEdge("attacker", "srv_files01", "SMB", "Session Setup"),
    },
    {
      logMessage: "SRV-FILES01 -> Attacker: SMB Session Setup Response (Success/Failure)",
      logType: "smb",
      action: () => addTemporaryEdge("srv_files01", "attacker", "SMB", "Session Response"),
    },
    {
      logMessage: "Attacker -> SRV-FILES01: RPC Call over SMB (Connect to srvsvc pipe for NetShareEnumAll)",
      logType: "rpc_smb", // RPC over named pipe
      action: () => addTemporaryEdge("attacker", "srv_files01", "RPC/SMB", "Connect srvsvc"),
    },
    {
      logMessage: "Attacker -> SRV-FILES01: RPC Call (NetShareEnumAll Request)",
      logType: "rpc_smb",
      action: () => addTemporaryEdge("attacker", "srv_files01", "RPC/SMB", "NetShareEnumAll"),
    },
    {
      logMessage: "SRV-FILES01 -> Attacker: RPC Response (List of shares and comments)",
      logType: "rpc_smb",
      action: () => addTemporaryEdge("srv_files01", "attacker", "RPC/SMB", "Share List"),
    },
    {
      logMessage: "Attacker -> SRV-FILES01: SMB Tree Connect Request (Access discovered share e.g., \\\\SRV-FILES01\\SHARE)",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "srv_files01", "SMB", "Tree Connect (Share)"),
    },
    {
      logMessage: "SRV-FILES01 -> Attacker: SMB Tree Connect Response (Access Granted/Denied)",
      logType: "smb",
      action: () => addTemporaryEdge("srv_files01", "attacker", "SMB", "Tree Connect Resp."),
    },
    {
      logMessage:
        "SMB SHARE ENUM COMPLETE: Attacker listed available SMB shares on the target server. May have identified shares with sensitive data or world-readable/writable permissions useful for lateral movement.",
      logType: "success",
    },
  ];

  const attackScheduledTaskScenario = [
    {
      scenarioName: "Attack: Remote Scheduled Task (Persistence/Lateral Movement)",
      logMessage: "Attacker (with user1 creds - requiring Admin on target) targets SRV-WEB-01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("srv_web01"); // Target server
      },
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: Authenticate (e.g., SMB/RPC) using user1 credentials",
      logType: "auth", // SMB/RPC auth happens implicitly or explicitly before RPC calls
      action: () => addTemporaryEdge("attacker", "srv_web01", "Auth", "User1 Login"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (Connect to Task Scheduler service - ATSVC pipe)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "TaskSched Connect"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (SchRpcRegisterTask - Define Task XML/Properties)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "Register Task"),
      // This single call usually includes action, trigger, security context (e.g., SYSTEM), etc.
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (Set Task Action - e.g., C:\\Windows\\Temp\\payload.exe)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "Set Action"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (Set Task Trigger - e.g., Logon)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "Set Trigger"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (Set Task Principal - e.g., Run as SYSTEM)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "Set Principal"),
    },
    {
      logMessage: "SRV-WEB-01: Task Scheduler Service creates the task as defined",
      logType: "internal",
      action: () => highlightElement("srv_web01"),
    },
    {
      logMessage: "SRV-WEB-01 -> Attacker: RPC Response (Task Creation Success)",
      logType: "rpc",
      action: () => addTemporaryEdge("srv_web01", "attacker", "RPC", "Task Created"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: RPC Call (SchRpcRun - Trigger task execution now)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "srv_web01", "RPC", "Run Task Now"),
    },
    {
      logMessage: "SRV-WEB-01: Task runs with specified privileges (e.g., SYSTEM), executes payload",
      logType: "execution",
      action: () => highlightElement("srv_web01"), // Payload runs on target
    },
    {
      logMessage:
        "REMOTE SCHEDULED TASK SUCCESSFUL: Attacker created a scheduled task on the target system for persistence or immediate code execution, often running as SYSTEM.",
      logType: "success",
    },
  ];

  const attackWMIAbuseScenario = [
    {
      scenarioName: "Attack: WMI Event Subscription (Persistence/Lateral Movement)",
      logMessage: "Attacker (with user1 creds - requiring Admin on target) targets SRV-WEB-01 via WMI",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("srv_web01");
      },
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: DCOM/RPC Connection (Connect to WMI Service - Port 135 + Dynamic)",
      logType: "dcom_rpc", // WMI uses DCOM over RPC
      action: () => addTemporaryEdge("attacker", "srv_web01", "DCOM/RPC", "WMI Connect"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: WMI Call (Authenticate using user1 credentials)",
      logType: "wmi",
      action: () => addTemporaryEdge("attacker", "srv_web01", "WMI", "Authenticate"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: WMI Call (Create __EventFilter instance - trigger condition)",
      logType: "wmi",
      action: () => addTemporaryEdge("attacker", "srv_web01", "WMI", "Create Filter"),
      // Example Filter: Trigger after 5 mins: SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: WMI Call (Create Event Consumer instance - action to take)",
      logType: "wmi",
      // Example Consumer: CommandLineEventConsumer to run payload.exe
      action: () => addTemporaryEdge("attacker", "srv_web01", "WMI", "Create Consumer (Payload)"),
    },
    {
      logMessage: "Attacker -> SRV-WEB-01: WMI Call (Create __FilterToConsumerBinding instance - link filter and consumer)",
      logType: "wmi",
      action: () => addTemporaryEdge("attacker", "srv_web01", "WMI", "Bind Filter/Consumer"),
    },
    {
      logMessage: "SRV-WEB-01: WMI service stores the event subscription components",
      logType: "internal",
      action: () => highlightElement("srv_web01"),
    },
    {
      logMessage: "SRV-WEB-01: WMI event filter condition met (e.g., system uptime reaches threshold)",
      logType: "wmi_event",
      action: () => highlightElement("srv_web01"), // Event occurs on target
    },
    {
      logMessage: "SRV-WEB-01: WMI executes the bound consumer action (runs payload.exe)",
      logType: "execution",
      action: () => highlightElement("srv_web01"), // Payload runs on target
    },
    {
      logMessage:
        "WMI EVENT SUBSCRIPTION SUCCESSFUL: Attacker established persistence via WMI. The malicious payload will execute whenever the defined event filter condition is met on the target system.",
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
      scenarioName: "Attack: Skeleton Key (Persistence)",
      logMessage: "Attacker (with DA privileges) targets DC01 LSASS process",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: Gain handle to LSASS process",
      logType: "os_action", // Or custom type
      action: () => highlightElement("dc01"), // Action occurs on DC
    },
    {
      logMessage: "Attacker -> DC01: Allocate memory within LSASS",
      logType: "os_action",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: Write Skeleton Key payload (DLL/shellcode) into LSASS memory",
      logType: "os_action",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: Execute payload within LSASS (e.g., CreateRemoteThread)",
      logType: "os_action", // This triggers the hooking and setting of the key
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 (LSASS): Skeleton Key payload hooks authentication function",
      logType: "internal", // Action within DC process
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 (LSASS): Skeleton Key payload sets master password",
      logType: "internal",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: Attempt Kerberos/NTLM Authentication (Any User, Skeleton Key Password)",
      logType: "kerberos/ntlm", // Can use either
      action: () => addTemporaryEdge("attacker", "dc01", "Auth", "Test Skeleton Key"),
    },
    {
      logMessage: "DC01 (LSASS): Hooked function bypasses normal check, validates Skeleton Key password",
      logType: "internal",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 -> Attacker: Authentication Success (using Skeleton Key)",
      logType: "kerberos/ntlm",
      action: () => addTemporaryEdge("dc01", "attacker", "Auth", "Success"),
    },
    // Post-Exploitation Example
    {
      logMessage: "Attacker -> DC01: Access resources using Skeleton Key (e.g., LDAP Bind)",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Bind (Skeleton Key)"),
    },
    {
      logMessage:
        "SKELETON KEY SUCCESSFUL: Attacker injected backdoor into LSASS. Can now authenticate as *any* domain user using the single Skeleton Key password, bypassing original credentials.",
      logType: "success",
    },
  ];

  const attackPetitPotamScenario = [
    {
      scenarioName: "Attack: PetitPotam (NTLM Relay Trigger)",
      logMessage: "Attacker prepares NTLM Relay listener targeting e.g., ADCS", // Added step
      logType: "setup",
      action: () => highlightElement("attacker"), // Optionally highlight relay target too
    },
    {
      scenarioName: "Attack: PetitPotam",
      logMessage: "Attacker targets DC01's EFS service",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: MS-EFSRPC EfsRpcOpenFileRaw (Trigger Auth to Attacker Machine)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "EfsRpcOpenFileRaw"),
    },
    {
      logMessage: "DC01: Processes EFS RPC call, attempts auth to Attacker's specified path",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 -> Attacker: NTLM Authentication Request (Negotiate)", // DC initiates auth TO attacker
      logType: "ntlm",
      action: () => addTemporaryEdge("dc01", "attacker", "NTLM", "Negotiate"),
    },
    {
      logMessage: "Attacker (Relay): Receives NTLM Negotiate from DC01",
      logType: "ntlm",
      action: () => highlightElement("attacker"),
    },
    // Relay part begins (Simplified - actual relay involves multiple back-and-forth)
    {
      logMessage: "Attacker (Relay) -> Target Service (e.g., ADCS): Relays NTLM Negotiate",
      logType: "ntlm",
      action: () => addTemporaryEdge("attacker", "ca01", "NTLM", "Relay Neg."), // Assuming ca01 node exists
    },
    {
      logMessage: "Target Service -> Attacker (Relay): NTLM Challenge",
      logType: "ntlm",
      action: () => addTemporaryEdge("ca01", "attacker", "NTLM", "Challenge"),
    },
    {
      logMessage: "Attacker (Relay) -> DC01: Forwards NTLM Challenge",
      logType: "ntlm",
      action: () => addTemporaryEdge("attacker", "dc01", "NTLM", "Challenge"),
    },
    {
      logMessage: "DC01 -> Attacker (Relay): NTLM Authenticate (Response)",
      logType: "ntlm",
      action: () => addTemporaryEdge("dc01", "attacker", "NTLM", "Authenticate"),
    },
    {
      logMessage: "Attacker (Relay) -> Target Service: Relays NTLM Authenticate",
      logType: "ntlm",
      action: () => addTemporaryEdge("attacker", "ca01", "NTLM", "Relay Auth."),
    },
    {
      logMessage: "Target Service: Grants access/issues certificate based on relayed DC01 credentials",
      logType: "result",
      action: () => highlightElement("ca01"), // Highlight the compromised service
    },
    {
      logMessage:
        "PETITPOTAM RELAY SUCCESSFUL: Attacker coerced DC authentication and relayed it. May have obtained DC certificate (via ADCS) or authenticated to another service as the DC, potentially leading to DA.",
      logType: "success",
    },
  ];

  const attackZeroLogonScenario = [
    {
      scenarioName: "Attack: ZeroLogon (CVE-2020-1472)",
      logMessage: "Attacker targets DC01 Netlogon service",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: Repeatedly send crafted NetrServerAuthenticate3 calls (Exploiting AES-CFB8 flaw)",
      logType: "rpc", // MS-NRPC
      action: () => addTemporaryEdge("attacker", "dc01", "MS-NRPC", "Auth Bypass Attempt"),
    },
    {
      logMessage: "DC01: Processes Netlogon calls, vulnerable validation allows bypass",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    // Assuming bypass succeeded after several attempts...
    {
      logMessage: "Attacker -> DC01: NetrServerPasswordSet2 RPC Call (Set DC password to empty string)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "MS-NRPC", "SetEmptyPassword"),
    },
    {
      logMessage: "DC01: Successfully resets its machine account password to empty (vulnerability exploited)",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    // Post-Exploitation
    {
      logMessage: "Attacker -> DC01: Authenticate as DC$ using empty password (e.g., via SMB, RPC)",
      logType: "auth", // Could be NTLM or Kerberos depending on tool
      action: () => addTemporaryEdge("attacker", "dc01", "Auth", "DC$ Login (Empty Pass)"),
    },
    {
      logMessage: "Attacker -> DC01: Perform DCSync (Dump all domain hashes using DC$ privileges)",
      logType: "drsuapi", // Directory Replication Service Remote Protocol
      action: () => addTemporaryEdge("attacker", "dc01", "DRSUAPI", "DCSync"),
    },
    {
      logMessage: "Attacker: Obtains NTLM hashes (e.g., krbtgt, Domain Admins)",
      logType: "result",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage: "Attacker -> DC01: Restore original DC$ password hash (using dumped hash)", // CRITICAL step to avoid breaking domain
      logType: "rpc", // Likely requires authenticated session as DC$
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "Restore Password"),
    },
    {
      logMessage:
        "ZEROLOGON SUCCESSFUL: Attacker reset DC password, authenticated as DC, dumped domain hashes (DCSync), and restored password. Effectively achieved Domain Admin.",
      logType: "success",
    },
  ];

  const attackMS14068Scenario = [
    {
      scenarioName: "Attack: MS14-068 (Kerberos PAC Vulnerability)",
      logMessage: "Attacker (with low-priv user creds) targets KDC on DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: Kerberos AS-REQ (Request TGT for low-priv user)",
      logType: "kerberos",
      action: () => addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ"),
    },
    {
      logMessage: "DC01: Validates user credentials",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 -> Attacker: Kerberos AS-REP (Issue TGT for low-priv user)", // Added step
      logType: "kerberos",
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (TGT)"),
    },
    {
      logMessage: "Attacker: Crafts TGS-REQ with a forged PAC (Privilege Attribute Certificate)", // Clarified
      logType: "kerberos",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage: "Attacker -> DC01: Kerberos TGS-REQ (Request Service Ticket, includes forged PAC signed with user key)",
      logType: "kerberos",
      action: () => addTemporaryEdge("attacker", "dc01", "Kerberos", "TGS-REQ (Forged PAC)"),
    },
    {
      logMessage: "DC01 (KDC): Processes TGS-REQ, FAILS to properly validate PAC signature (MS14-068 vulnerability)", // Clarified
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 (KDC) -> Attacker: Kerberos TGS-REP (Issues Service Ticket based on FORGED PAC privileges)",
      logType: "kerberos",
      action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "TGS-REP (Elevated)"),
    },
    // Post-Exploitation Example
    {
      logMessage: "Attacker: Uses the elevated Service Ticket to access a target service (e.g., CIFS on DC01)", // Added usage step
      logType: "kerberos", // Or SMB/CIFS etc. depending on service
      action: () => addTemporaryEdge("attacker", "dc01", "Kerberos/SMB", "Access with Forged Ticket"),
    },
    {
      logMessage:
        "MS14-068 SUCCESSFUL: Attacker exploited KDC validation flaw to obtain Kerberos tickets with elevated (likely Domain Admin) privileges using only low-privilege user credentials.",
      logType: "success",
    },
  ];

  const attackSAMRAbuseScenario = [
    {
      scenarioName: "Attack: SAMR Abuse (Enumeration)",
      logMessage: "Attacker (authenticated user) targets DC01 SAMR service",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    // Assumes prior SMB/RPC authentication succeeded
    {
      logMessage: "Attacker -> DC01: RPC Bind (Connect to SAMR pipe)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "RPC", "SAMR Bind"),
    },
    {
      logMessage: "Attacker -> DC01: SAMR Call (e.g., SamrConnect, SamrOpenDomain)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "SAMR", "Connect/OpenDomain"),
    },
    {
      logMessage: "DC01: Validates SAMR connection request",
      logType: "rpc",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: SAMR Call (SamrEnumerateUsersInDomain)",
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "SAMR", "EnumUsers"),
    },
    {
      logMessage: "DC01: Processes request, returns list of domain user RIDs/names",
      logType: "rpc",
      action: () => addTemporaryEdge("dc01", "attacker", "SAMR", "User List"),
    },
    {
      logMessage: "Attacker -> DC01: SAMR Call (SamrEnumerateGroupsInDomain)", // Example: Enum Groups
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "SAMR", "EnumGroups"),
    },
    {
      logMessage: "DC01: Processes request, returns list of domain group RIDs/names",
      logType: "rpc",
      action: () => addTemporaryEdge("dc01", "attacker", "SAMR", "Group List"),
    },
    {
      logMessage: "Attacker -> DC01: SAMR Call (SamrCloseHandle)", // Disconnect
      logType: "rpc",
      action: () => addTemporaryEdge("attacker", "dc01", "SAMR", "Close"),
    },
    {
      logMessage:
        "SAMR ABUSE SUCCESSFUL: Attacker successfully enumerated domain objects (users, groups) via SAMR protocol. Provides valuable reconnaissance information for further attacks.",
      logType: "success",
    },
  ];

  const attackNTDSExtractionScenario = [
    {
      scenarioName: "Attack: NTDS.dit Extraction (via VSS)",
      logMessage: "Attacker (DA/Backup privs) targets DC01",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    // Assumes attacker has remote command execution (e.g., WinRM, PsExec) or SMB access
    {
      logMessage: "Attacker -> DC01: Execute command to Create Volume Shadow Copy",
      logType: "os_action", // e.g., vssadmin create shadow /for=C:
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01: Creates Shadow Copy of the system volume",
      logType: "os_action",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker -> DC01: Copy NTDS.dit from Shadow Copy path (via SMB/CMD)",
      logType: "smb/os_action",
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Copy NTDS.dit"),
    },
    {
      logMessage: "Attacker -> DC01: Copy SYSTEM hive from Shadow Copy path (via SMB/CMD)",
      logType: "smb/os_action",
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Copy SYSTEM"),
    },
    {
      logMessage: "Attacker -> DC01: Execute command to Delete Volume Shadow Copy", // Cleanup
      logType: "os_action",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "Attacker (Offline): Use SYSTEM hive to decrypt hashes within NTDS.dit", // Offline step
      logType: "offline_action",
      action: () => highlightElement("attacker"), // Action on attacker machine
    },
    {
      logMessage:
        "NTDS.dit EXTRACTION SUCCESSFUL: Attacker obtained copy of AD database (NTDS.dit) and SYSTEM hive. Can now extract all domain password hashes offline for cracking or pass-the-hash.",
      logType: "success",
    },
  ];

  const attackDSRMAbuseScenario = [
    {
      scenarioName: "Attack: DSRM Abuse (Persistence Logon)",
      logMessage: "Attacker targets DC01 (previously configured for DSRM network logon)",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("dc01");
      },
    },
    {
      logMessage: "Attacker -> DC01: NTLM Authentication Request (User: .\\Administrator, Pass: DSRM_Password)",
      logType: "ntlm", // Target e.g., WinRM or SMB service
      action: () => addTemporaryEdge("attacker", "dc01", "NTLM", "DSRM Auth Req"),
    },
    {
      logMessage: "DC01: Validates credentials against local SAM DSRM account (Allowed due to DsrmAdminLogonBehavior=2)",
      logType: "ntlm",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage: "DC01 -> Attacker: NTLM Authentication Success",
      logType: "ntlm",
      action: () => addTemporaryEdge("dc01", "attacker", "NTLM", "DSRM Auth Success"),
    },
    {
      logMessage: "Attacker -> DC01: Establish Remote Session (e.g., WinRM, PsExec using DSRM creds)",
      logType: "winrm/smb",
      action: () => addTemporaryEdge("attacker", "dc01", "Session", "Remote Access (DSRM)"),
    },
    {
      logMessage: "Attacker (via remote session): Execute commands with local Administrator privileges on DC01",
      logType: "os_action",
      action: () => highlightElement("dc01"), // Running commands on DC
    },
    {
      logMessage: "Attacker: Can now perform DA-level actions (e.g., DCSync, modify domain)",
      logType: "result",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "DSRM ABUSE (PERSISTENCE) SUCCESSFUL: Attacker regained privileged access to the DC using the DSRM account via network logon, bypassing standard domain authentication.",
      logType: "success",
    },
  ];

  const attackGPOAbuseScenario = [
    {
      scenarioName: "Attack: Malicious GPO Modification",
      logMessage:
        "Attacker Goal: Achieve code execution or persistence on multiple machines by modifying a Group Policy Object.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has compromised credentials with permissions to edit a specific GPO (e.g., member of 'Group Policy Creator Owners' or direct ACL). Assume compromised 'gpo_editor' user.",
      logType: "attack",
      action: () => {
        highlightElement("gpo_editor", stepDelay, "compromised");
        highlightElement("dc01"); // GPOs are stored/managed via DC
      },
    },
    {
      logMessage:
        "Attacker (as gpo_editor) -> DC01: SMB Connection (Accessing SYSVOL share where GPO files are stored, e.g., \\\\dc01\\SYSVOL\\...).",
      logType: "smb",
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Connect SYSVOL"),
    },
    {
      logMessage:
        "Attacker (as gpo_editor) -> DC01: Modify GPO Files (e.g., Adds malicious startup script, scheduled task XML, or modifies registry settings within the GPO files on SYSVOL).",
      logType: "attack", // Modifying policy files
      action: () => addTemporaryEdge("attacker", "dc01", "SMB", "Modify GPO Files"),
    },
    {
      logMessage:
        "Attacker (as gpo_editor) -> DC01: LDAP Modify (Updates GPO version number in AD object to trigger client refresh).",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Update GPO Version"),
    },
    {
      logMessage:
        "Victim Machine (host1 - linked to GPO): Periodically checks for GPO updates.",
      logType: "info",
      action: () => highlightElement("host1"),
    },
    {
      logMessage:
        "Victim Machine (host1) -> DC01: SMB/LDAP Request (Detects GPO version change, fetches updated policy files from SYSVOL/AD).",
      logType: "smb", // Or LDAP depending on setting type
      action: () => addTemporaryEdge("host1", "dc01", "SMB/LDAP", "Fetch GPO Update"),
    },
    {
      logMessage:
        "Victim Machine (host1): Applies the malicious GPO settings (e.g., runs the attacker's script at next startup/logon, creates malicious scheduled task).",
      logType: "system", // Local action triggered by GPO
      action: () => highlightElement("host1", stepDelay, "compromised"), // Host executes attacker's payload
    },
    {
      logMessage:
        "IMPACT: Attacker leveraged GPO edit rights to gain code execution or persistence on potentially many machines linked to the GPO, often with SYSTEM privileges.",
      logType: "success",
    },
  ];


  const attackKCDAbuseScenario = [
    {
      scenarioName: "Attack: Constrained Delegation (KCD) Abuse",
      logMessage:
        "Attacker Goal: Impersonate a user on a backend service (Service B) by compromising a frontend service (Service A) configured for KCD.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite 1: Attacker compromises Server A (srv_app01), which runs a service configured for Kerberos Constrained Delegation (KCD) to Service B (e.g., cifs/srv_files01). Service A's account ('svc_app01') has 'msDS-AllowedToDelegateTo' set for Service B.",
      logType: "attack",
      action: () => {
        highlightElement("attacker");
        highlightElement("srv_app01", stepDelay, "compromised"); // Frontend service compromised
        highlightElement("svc_app01"); // Account running frontend service
        highlightElement("srv_files01"); // Backend service target
      },
    },
    {
      logMessage:
        "Prerequisite 2: Service A ('svc_app01') must be configured for 'Use any authentication protocol' (Transition). If not, a user must authenticate to Service A with Kerberos first.",
      logType: "info",
    },
    {
      logMessage:
        "Attacker (on srv_app01, controlling svc_app01): Needs to trigger S4U process. Can either wait for a legitimate user (e.g., 'user1') to authenticate to Service A, OR force authentication (e.g., using RBCD against Service A, or other means). Assume attacker forces 'user1' authentication.",
      logType: "attack", // Attacker manipulates the service
      action: () => {
        highlightElement("user1"); // The user to be impersonated
      },
    },
    {
      logMessage:
        "Attacker (as svc_app01 on srv_app01) -> DC01: Kerberos TGS-REQ (S4U2Self - Requesting ST *to itself* for 'svc_app01', specifying impersonation of 'user1'). This step is needed if protocol transition is enabled.",
      logType: "attack", // Service gets ticket to self as user
      action: () =>
        addTemporaryEdge("srv_app01", "dc01", "Kerberos", "TGS-REQ (S4U2Self as user1)"),
    },
    {
      logMessage:
        "DC01 -> Attacker (as svc_app01): Kerberos TGS-REP (Issues forwardable ST for 'svc_app01' containing 'user1' identity).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "srv_app01", "Kerberos", "TGS-REP (Self ST as user1)"),
    },
    {
      logMessage:
        "Attacker (as svc_app01 on srv_app01) -> DC01: Kerberos TGS-REQ (S4U2Proxy - Uses the S4U2Self ticket [or user's original TGT if no transition], requests ST for the target service 'cifs/srv_files01' *as user1*).",
      logType: "attack", // Service uses delegation rights
      action: () =>
        addTemporaryEdge("srv_app01", "dc01", "Kerberos", "TGS-REQ (S4U2Proxy to files01)"),
    },
    {
      logMessage:
        "DC01: Validates request. Checks KCD config: confirms 'svc_app01' is allowed to delegate to 'cifs/srv_files01'. Issues ST for 'cifs/srv_files01' usable by 'svc_app01' containing 'user1' identity.",
      logType: "kerberos",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker (as svc_app01): Kerberos TGS-REP (Sending ST for cifs/srv_files01, valid *as user1*).",
      logType: "kerberos",
      action: () =>
        addTemporaryEdge("dc01", "srv_app01", "Kerberos", "TGS-REP (Proxy ST as user1)"),
    },
    {
      logMessage:
        "Attacker (on srv_app01, injects proxy ST): -> SRV-FILES01: Service Request (e.g., SMB AP-REQ to access files, presenting the proxy ST).",
      logType: "attack", // Accessing backend service
      action: () => {
        highlightElement("srv_files01", stepDelay, "highlighted"); // Access achieved on backend
        addTemporaryEdge("srv_app01", "srv_files01", "SMB", "AP-REQ (as user1 via KCD)");
      },
    },
    {
      logMessage:
        "SRV-FILES01: Validates ticket. Sees user is 'user1'. Grants access based on user1's permissions.",
      logType: "smb",
    },
    {
      logMessage:
        "IMPACT: Attacker compromised a frontend service (A) and abused its Kerberos Constrained Delegation rights to access a backend service (B) while impersonating another user ('user1').",
      logType: "success",
    },
  ];


  const attackLAPSAbuseScenario = [
    {
      scenarioName: "Attack: LAPS Password Retrieval & Abuse",
      logMessage:
        "Attacker Goal: Retrieve a target computer's Local Administrator password managed by LAPS via LDAP.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has compromised credentials (e.g., 'helpdesk_user') that have been granted READ access to the 'ms-Mcs-AdmPwd' attribute on target computer objects in AD.",
      logType: "attack",
      action: () => {
        highlightElement("helpdesk_user", stepDelay, "compromised");
        highlightElement("dc01");
        highlightElement("host1"); // Target computer whose LAPS pwd we want
      },
    },
    {
      logMessage:
        "Attacker (as helpdesk_user) -> DC01: LDAP Search Request (Querying the computer object 'host1' and specifically requesting the 'ms-Mcs-AdmPwd' attribute).",
      logType: "ldap",
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Query LAPS Pwd (host1)"),
    },
    {
      logMessage:
        "DC01: Receives query. Performs ACL check: confirms 'helpdesk_user' has read permission for 'ms-Mcs-AdmPwd' on 'host1' object.",
      logType: "ldap",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 -> Attacker: LDAP Search Result (Returns the value of 'ms-Mcs-AdmPwd' for host1 - the current Local Admin password).",
      logType: "ldap", // Sensitive data disclosure
      action: () => {
        addTemporaryEdge("dc01", "attacker", "LDAP", "LAPS Pwd Response");
        // Note: No specific element for the password itself, attacker now knows it.
      }
    },
    {
      logMessage:
        "Attacker: Now possesses the Local Administrator password for 'host1'.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker -> Host1: Remote Logon Attempt (e.g., SMB, WinRM, RDP) using '.\Administrator' and the retrieved LAPS password.",
      logType: "attack", // Using the obtained credential
      action: () =>
        addTemporaryEdge("attacker", "host1", "SMB/WinRM", "Logon (LAPS Pwd)"),
    },
    {
      logMessage:
        "Host1: Authenticates the attacker as the local Administrator.",
      logType: "success",
      action: () => highlightElement("host1", stepDelay, "compromised"), // Host compromised
    },
    {
      logMessage:
        "IMPACT: Attacker leveraged legitimate (but perhaps excessive) read permissions to retrieve a local administrator password via LDAP, enabling direct administrative access to the target machine for lateral movement.",
      logType: "success",
    },
  ];


  const attackGMSAAbuseScenario = [
    {
      scenarioName: "Attack: gMSA Password Retrieval & Use",
      logMessage:
        "Attacker Goal: Retrieve the password hash for a Group Managed Service Account (gMSA) and use it.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has compromised credentials (e.g., 'priv_user') with privileges to read gMSA password data (Requires specific AD rights, often Domain Admin equivalent or delegated).",
      logType: "attack",
      action: () => {
        highlightElement("priv_user", stepDelay, "compromised");
        highlightElement("dc01");
        highlightElement("gmsa_sql"); // Example gMSA account
      },
    },
    {
      logMessage:
        "Attacker (as priv_user) -> DC01: LDAP Search (Querying the gMSA object 'gmsa_sql', requesting the 'msDS-ManagedPassword' attribute blob).",
      logType: "ldap",
      action: () => addTemporaryEdge("attacker", "dc01", "LDAP", "Query gMSA Pwd Blob"),
    },
    {
      logMessage:
        "DC01: Validates permissions. Returns the encrypted 'msDS-ManagedPassword' blob if authorized.",
      logType: "ldap",
      action: () => addTemporaryEdge("dc01", "attacker", "LDAP", "gMSA Blob Response"),
    },
    {
      logMessage:
        "Attacker: Uses tools (e.g., DSInternals, gMSADumper) OFFLINE with the necessary privileges/context to decrypt the blob and extract the NT hash for the current gMSA password.",
      logType: "attack", // Offline processing
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Attacker: Now possesses the NTLM hash for the 'gmsa_sql' account.",
      logType: "attack",
      action: () => highlightElement("gmsa_sql", stepDelay, "compromised"),
    },
    {
      logMessage:
        "Attacker -> Target Service Host (e.g., srv_sql01): Pass-the-Hash (Uses the extracted gMSA hash to authenticate via NTLM to services running as gmsa_sql).",
      logType: "attack", // Using the hash for lateral movement
      action: () => {
        highlightElement("srv_sql01"); // Host running the gMSA service
        addTemporaryEdge("attacker", "srv_sql01", "SMB/RPC", "PtH (gMSA Hash)");
      }
    },
    {
      logMessage:
        "Target Service Host (srv_sql01): Authenticates the attacker as the 'gmsa_sql' account.",
      logType: "success",
      action: () => highlightElement("srv_sql01", stepDelay, "compromised"),
    },
    {
      logMessage:
        "IMPACT: Attacker with high privileges read gMSA password data from AD, extracted the hash offline, and used it via Pass-the-Hash to compromise systems or services running under that gMSA.",
      logType: "success",
    },
  ];


  const attackAdminSDHolderScenario = [
    {
      scenarioName: "Attack: AdminSDHolder Backdoor",
      logMessage:
        "Attacker Goal: Gain persistent privileged access by adding an attacker-controlled principal to the ACL of the AdminSDHolder object.",
      logType: "attack",
      action: () => highlightElement("attacker"),
    },
    {
      logMessage:
        "Prerequisite: Attacker has compromised credentials with rights to modify the ACL of the AdminSDHolder object (CN=AdminSDHolder,CN=System,DC=corp,DC=local). Typically requires Domain Admin or equivalent.",
      logType: "attack",
      action: () => {
        highlightElement("admin1", stepDelay, "compromised"); // Assume attacker has DA creds
        highlightElement("dc01");
        highlightElement("user2"); // A user the attacker controls/created
      },
    },
    {
      logMessage:
        "Attacker (as admin1) -> DC01: LDAP Modify Request (Targets the AdminSDHolder object. Adds an Access Control Entry (ACE) granting the 'CORP\\BOB' Full Control permissions).",
      logType: "attack", // Modifying the template ACL
      action: () =>
        addTemporaryEdge("attacker", "dc01", "LDAP", "Modify AdminSDHolder ACL"),
    },
    {
      logMessage:
        "DC01: Updates the ACL on the AdminSDHolder object in the System container.",
      logType: "ldap",
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 (SDProp Process): Periodically (default: 60 mins), the Security Descriptor Propagator process runs on the DC holding the PDC Emulator FSMO role.",
      logType: "info", // System process
      action: () => highlightElement("dc01"),
      delay: 2000, // Simulate delay before SDProp runs
    },
    {
      logMessage:
        "DC01 (SDProp Process): Compares ACLs of protected users/groups (e.g., Domain Admins, Enterprise Admins, Administrators, etc.) against the AdminSDHolder template ACL. Finds differences.",
      logType: "info", // Internal DC check
      action: () => highlightElement("dc01"),
    },
    {
      logMessage:
        "DC01 (SDProp Process) -> DC01: LDAP Modify (Overwrites the ACLs of protected objects like the 'Domain Admins' group with the ACL from AdminSDHolder, including the attacker's ACE). Inheritance is disabled.",
      logType: "system", // Automatic ACL propagation by the system
      action: () => {
        highlightElement("domain_admins_group", stepDelay, "highlighted"); // ACL overwritten
        // Attacker's controlled user now implicitly has rights ON the DA group
      }
    },
    {
      logMessage:
        "Attacker (as user2): Now has permissions defined by the AdminSDHolder ACL (e.g., Full Control) over all protected groups/users, such as 'Domain Admins'.",
      logType: "attack",
      action: () => highlightElement("user2", stepDelay, "privileged"), // User gained privs
    },
    {
      logMessage:
        "Attacker (as user2) -> DC01: LDAP Modify (Uses newly gained permissions, e.g., adds itself to the 'Domain Admins' group).",
      logType: "attack", // Exploiting the propagated permissions
      action: () =>
        addTemporaryEdge("user2", "dc01", "LDAP", "Add Self to DA Group"),
    },
    {
      logMessage:
        "IMPACT: Attacker modified the AdminSDHolder template ACL. The SDProp process automatically propagated this malicious permission to all protected groups/users, granting the attacker's account persistent privileged access that resists manual ACL changes on the protected objects themselves.",
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
    "btn-attack-gpo",
    "btn-attack-kcd",
    "btn-attack-laps",
    "btn-attack-gmsa",
    "btn-attack-adminsd",
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
        "btn-attack-gpo": attackGPOAbuseScenario,
        "btn-attack-kcd": attackKCDAbuseScenario,
        "btn-attack-laps": attackLAPSAbuseScenario,
        "btn-attack-gmsa": attackGMSAAbuseScenario,
        "btn-attack-adminsd": attackAdminSDHolderScenario,
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
  addEventListenerSafe("chk-manual-mode", () => { }); // State checked on scenario start

  // --- Initial Execution ---
  initializeCytoscape(initialElements);
  cy.ready(() => {
    log("Expert AD Simulation Environment Initialized. Ready.", "info");
    updateButtonStates();
  });
}); // End DOMContentLoaded
