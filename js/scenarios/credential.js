import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';


export const attackPasswordSprayScenario = [
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
      "Attacker -> DC01: Kerberos AS-REQ for Bob (user2) with spray password 'Winter2024'. (No valid TGT expected initially).",
    logType: "attack",
    action: () =>
      addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (Spray U1)"),
  },
  {
    logMessage:
      "DC01 -> Attacker: Kerberos Error (KRB5KDC_ERR_PREAUTH_FAILED - Incorrect password for Bob).",
    logType: "kerberos",
    action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "Error (Bad Pwd)"),
  },
  {
    logMessage:
      "Attacker -> DC01: Kerberos AS-REQ for DomainAdmin (admin1) with same spray password 'Winter2024'.",
    logType: "attack",
    action: () =>
      addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (Spray U2)"),
  },
  {
    logMessage:
      "DC01 -> Attacker: Kerberos Error (KRB5KDC_ERR_PREAUTH_FAILED - Incorrect password for DomainAdmin).",
    logType: "kerberos",
    action: () => addTemporaryEdge("dc01", "attacker", "Kerberos", "Error (Bad Pwd)"),
  },
  {
    logMessage:
      "Attacker -> DC01: Kerberos AS-REQ for Alice (user1) with same spray password 'Winter2024'.",
    logType: "attack",
    action: () =>
      addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (Spray U3)"),
  },
  {
    logMessage:
      "DC01: Validates pre-authentication using Alice's hash and the provided password ('Winter2024'). It matches!",
    logType: "kerberos",
    action: () => highlightElement("dc01"),
  },
  {
    logMessage:
      "DC01 -> Attacker: Kerberos AS-REP (Success! Password 'Winter2024' is valid for Alice/user1). TGT for user1 is issued.",
    logType: "success",
    action: () => {
      highlightElement("user1", stepDelay, "compromised");
      addTemporaryEdge("dc01", "attacker", "Kerberos", "AS-REP (Success!)");
    },
  },
  {
    logMessage:
      "IMPACT: Attacker identified valid credentials (Alice:Winter2024) by spraying one password across many accounts, staying below per-account lockout thresholds. Can now authenticate as user1 and perform further attacks (e.g., Kerberoasting).",
    logType: "success",
  },
];

export const attackKerberoastingScenario = [
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
    action: () => highlightElement("user2", stepDelay, "compromised"), // Bob represents any low-priv user
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

export const attackASREPRoastingScenario = [
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
    action: () => highlightElement("svc_nopreauth"), // Target user with pre-auth disabled
  },
  {
    logMessage:
      "Attacker -> DC01: Kerberos AS-REQ for the target user ('svc_nopreauth'). Critically, the request does NOT include any pre-authentication data (encrypted timestamp).",
    logType: "attack",
    action: () =>
      addTemporaryEdge("attacker", "dc01", "Kerberos", "AS-REQ (NoPreAuth Data)"),
  },
  {
    logMessage:
      "DC01: Finds the user account 'svc_nopreauth'. Checks its 'userAccountControl' attribute. Sees the DONT_REQ_PREAUTH flag is TRUE. Therefore, it skips the pre-authentication validation step.",
    logType: "kerberos",
    action: () => highlightElement("dc01"),
  },
  {
    logMessage:
      "DC01 -> Attacker: Kerberos AS-REP (Sending the TGT response). Because pre-auth was skipped, this AS-REP contains a portion encrypted with the *target user's ('svc_nopreauth')* NTLM hash.",
    logType: "kerberos",
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
    logType: "attack",
    action: () => highlightElement("attacker"),
  },
  {
    logMessage:
      "Attacker: Successfully cracks the hash, revealing the plaintext password for the 'svc_nopreauth' user account.",
    logType: "success",
    action: () => highlightElement("svc_nopreauth", stepDelay, "compromised"),
  },
  {
    logMessage:
      "IMPACT: Attacker obtained the password for a user ('svc_nopreauth') without needing any prior credentials, solely by exploiting disabled pre-authentication. Allows authentication as this user, access to their resources, and potential further actions.",
    logType: "success",
  },
];

export const attackNTLMRelayScenario = [
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
    logMessage: "Attacker (relayed as host1$) -> CA01 (/certsrv): HTTP Request (Request certificate via AD CS Web Enrollment)",
    logType: "http",
    action: () => addTemporaryEdge("attacker", "ca01", "HTTP", "Cert Request (Relayed)"),
  },
  {
    logMessage: "CA01: Issues certificate for 'host1$'.",
    logType: "internal",
    action: () => highlightElement("ca01"),
  },
  {
    logMessage: "CA01 -> Attacker: HTTP Response (Certificate Download)",
    logType: "http",
    action: () => addTemporaryEdge("ca01", "attacker", "HTTP", "Cert Download"),
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

export const attackLLMNRPoisoningScenario = [
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
    logMessage: "User (user1) -> Network: Broadcasts LLMNR/NBT-NS Query for 'fileshar' (multicast/broadcast - no direct target node)",
    logType: "llmnr_nbtns",
    action: () => highlightElement("user1"),
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

export const attackPetitPotamScenario = [
  {
    scenarioName: "Attack: PetitPotam (NTLM Relay Trigger)",
    logMessage: "Attacker prepares NTLM Relay listener targeting e.g., ADCS", // Added step
    logType: "setup",
    action: () => highlightElement("attacker"), // Optionally highlight relay target too
  },
  {
    logMessage: "Attacker targets DC01's EFS service (MS-EFSRPC) to coerce NTLM authentication",
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
