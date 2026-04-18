import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';


export const attackESC1Scenario = [
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

export const attackESC2Scenario = [
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

export const attackESC3Scenario = [
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

export const attackESC4Scenario = [
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

export const attackESC6Scenario = [
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

export const attackESC8Scenario = [
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
