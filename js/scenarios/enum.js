import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';


export const attackSharpHoundScenario = [
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

export const attackLDAPReconScenario = [
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

export const attackDNSReconScenario = [
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

export const attackSMBShareEnumScenario = [
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

export const attackSAMRAbuseScenario = [
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
