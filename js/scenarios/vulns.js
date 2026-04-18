import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';


export const attackZeroLogonScenario = [
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

export const attackPrintNightmareScenario = [
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
