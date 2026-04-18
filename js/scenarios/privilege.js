import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';


export const attackLAPSAbuseScenario = [
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

export const attackGMSAAbuseScenario = [
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

export const attackUnconstrainedDelegationScenario = [
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

export const attackKCDAbuseScenario = [
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

export const attackRBCDScenario = [
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

export const attackGPOAbuseScenario = [
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

export const attackMS14068Scenario = [
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

export const attackShadowCredentialsScenario = [
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
