import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';


export const legitimateLogonScenario = [
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

export const legitAdminGroupScenario = [
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

export const legitGpoUpdateScenario = [
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

export const legitCertRequestScenario = [
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

export const legitFileShareAccessScenario = [
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
