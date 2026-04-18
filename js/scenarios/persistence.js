import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';


export const attackDCSyncScenario = [
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

export const attackSQLAccessScenario = [
  {
    scenarioName: "Attack: SQL Access (Post-Roast)",
    logMessage: "Prerequisite: Attacker previously Kerberoasted SPN 'MSSQLSvc/sql01.corp.local:1433' associated with 'svc_sql01' account and cracked its password/hash.",
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
    logMessage: "Attacker -> DC01: Kerberos TGS-REQ (Using TGT, Request ST for SPN 'MSSQLSvc/sql01.corp.local:1433')",
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

export const attackNTDSExtractionScenario = [
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

export const attackGoldenTicketScenario = [
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

export const attackSilverTicketScenario = [
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

export const attackSkeletonKeyScenario = [
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

export const attackDSRMAbuseScenario = [
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

export const attackAdminSDHolderScenario = [
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
      highlightElement("admin1", stepDelay, "highlighted"); // Protected objects (DA group, etc.) get ACL overwritten
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
