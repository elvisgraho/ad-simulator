import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';


export const attackPassTheTicketScenario = [
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

export const attackPassTheHashScenario = [
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

export const attackRemoteExecScenario = [
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

export const attackScheduledTaskScenario = [
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

export const attackWMIAbuseScenario = [
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
