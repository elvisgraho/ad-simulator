import { highlightElement, addTemporaryEdge } from '../graph.js';

// ── 1. AAD Connect Delta Sync Cycle ──────────────────────────────────────────
export const hybridDeltaSyncScenario = [
  {
    scenarioName: "Hybrid: AAD Connect Delta Sync Cycle",
    logMessage: "AADConnect (hb_aadconnect) scheduler triggers delta sync. Default interval: 30 min. Sync cycle types: Delta (incremental, uSNChanged watermark) vs Full (forced re-read of all objects). Running: Delta.",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "AADConnect → DC01: LDAP SearchRequest (RFC 4511) with DirSync Control (OID 1.2.840.113556.1.4.841). Filter: (|(objectClass=user)(objectClass=group)(objectClass=computer)). Attribute: uSNChanged > <watermark>. Scope: subtree.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_dc01", "ldap", "DirSync LDAP Poll"),
  },
  {
    logMessage: "DC01 → AADConnect: DirSync response — 14 changed objects (3 user attrib updates, 1 group membership delta, 10 computer accounts). Returns new watermark cookie for next cycle.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_dc01", "hb_aadconnect", "ldap", "Delta objects"),
  },
  {
    logMessage: "AADConnect Import Stage: Changed objects written to Connector Space (CS). CS is a staging area — raw on-prem AD schema representation. Pending import state flagged for each object.",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "AADConnect Synchronization Stage: Metaverse (MV) join rules evaluated. Attribute flow rules applied (scoping filters, transformation rules, outbound sync rules). alice@corp.com: displayName, mail, proxyAddresses, userPrincipalName pushed to MV.",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "AADConnect Export Stage: Connector Space export objects built for Entra ID connector. MSOL_<id> account authenticates to Entra provisioning endpoint using OAuth2 client_credentials (service principal).",
    logType: "sync",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_entra", "sync", "OAuth2 client_cred"),
  },
  {
    logMessage: "AADConnect → Entra ID: HTTPS POST https://adminwebservice.microsoftonline.com/provisioningservice.svc (SOAP/WCF). Body contains ObjectDelta entries: [UpsertObject, ModifyObject]. TLS 1.2, cert-pinned.",
    logType: "sync",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_entra", "sync", "Object delta push"),
  },
  {
    logMessage: "Entra ID: Processes 14 object deltas. Reconciles with existing shadow objects in tenant (identified by ImmutableID = Base64(objectGUID from on-prem)). 3 user attributes updated, 1 group member added.",
    logType: "info",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "Entra ID → AADConnect: 200 OK — sync confirmation. Export statistics: Success=14, Errors=0. New anchor values returned for any newly provisioned objects.",
    logType: "success",
    action: () => { highlightElement("hb_entra"); highlightElement("hb_aadconnect"); },
  },
  {
    logMessage: "AADConnect: Updates watermark. Logs sync stats to Event Log (Application, source: Directory Synchronization). Next delta sync scheduled in 30 minutes.",
    logType: "success",
    action: () => highlightElement("hb_aadconnect"),
  },
];

// ── 2. Password Hash Sync (PHS) — Full Low-Level Detail ──────────────────────
export const hybridPHSScenario = [
  {
    scenarioName: "Hybrid: Password Hash Sync (PHS) — Full Cryptographic Chain",
    logMessage: "Alice changes her on-prem password at WKSTN-HYB. Event triggers on DC01 — password change propagated via Kerberos change key (KERB-CHANGE-PASSWORD) or SAMR set. PHS agent monitors for password changes.",
    logType: "info",
    action: () => { highlightElement("hb_user1"); highlightElement("hb_dev1"); },
  },
  {
    logMessage: "DC01: Stores new password as NT hash. NT hash derivation: NT_hash = MD4(UTF-16LE(password)). 16-byte digest. Example: MD4(UTF-16LE('Corp@2026!')) → [binary 16 bytes]. NTLM v1 auth uses this raw hash.",
    logType: "kerberos",
    action: () => highlightElement("hb_dc01"),
  },
  {
    logMessage: "AADConnect PHS agent: Registered via DS-Replication-Get-Changes-In-Filtered-Set ACE on MSOL_ account. Agent calls DRS GetNCChanges (DRSUAPI, MS-DRSR §4.1.10) targeting cn=Schema,cn=Configuration — specifically requesting password attribute replication (OID 1.2.840.113556.1.4.221 = unicodePwd).",
    logType: "rpc",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_dc01", "rpc", "DRS GetNCChanges"),
  },
  {
    logMessage: "DC01 → AADConnect: Replication response includes password blob. The blob contains: supplementalCredentials (AES keys, DES keys, WDigest, LM hash if enabled) + NT hash. Transmitted encrypted over DRSUAPI RPC session key.",
    logType: "rpc",
    action: () => addTemporaryEdge("hb_dc01", "hb_aadconnect", "rpc", "Password blob"),
  },
  {
    logMessage: "AADConnect PHS agent — Hash Transform Step 1: Extract NT hash from DRSUAPI blob. Salt construction: PerObjectSalt = UserObjectSID string (e.g., 'S-1-5-21-...-1104'). Apply PBKDF2-HMAC-SHA256(NT_hash, PerObjectSalt, iterations=1, dkLen=32).",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "AADConnect PHS agent — Hash Transform Step 2: Generate random 10-byte salt (cryptographically random). Apply PBKDF2-HMAC-SHA256(result_step1, random_salt, iterations=1000, dkLen=32). Output: 32-byte salted hash value.",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "AADConnect PHS agent — Hash Transform Step 3: Construct final payload = [version:4B][reserved:4B][random_salt:10B][hash_value:32B] = 50-byte blob. The original NT hash is NOT included in the payload. On-prem credential material never leaves the organization.",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "AADConnect → Entra ID: HTTPS POST /provisioningservice.svc with PasswordSyncMessage payload. Encrypted via TLS 1.3. Entra ID stores the 50-byte hash blob indexed by ImmutableID (objectGUID). Overwrites prior blob.",
    logType: "sync",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_entra", "sync", "PasswordSyncMsg"),
  },
  {
    logMessage: "Entra ID: Confirms hash receipt. On next cloud sign-in by alice@corp.com: Entra extracts stored blob, re-applies PBKDF2-HMAC-SHA256(MD4(UTF-16LE(submitted_pwd)), PerObjectSalt, iter=1000) and compares output to stored 32-byte value.",
    logType: "info",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "PHS enables cloud auth without on-prem infrastructure dependency. Trade-off: Entra holds a derived password hash — compromise of Entra store + knowledge of salt structure is theoretically sufficient to brute-force offline.",
    logType: "success",
    action: () => { highlightElement("hb_entra"); highlightElement("hb_aadconnect"); },
  },
];

// ── 3. Pass-Through Authentication (PTA) ─────────────────────────────────────
export const hybridPTAScenario = [
  {
    scenarioName: "Hybrid: Pass-Through Authentication (PTA) Flow",
    logMessage: "Alice at WKSTN-HYB submits credentials to Entra ID sign-in page: POST https://login.microsoftonline.com/corp.onmicrosoft.com/login (UPN: alice@corp.com, password: [cleartext over TLS]). Entra ID detects corp.com domain is PTA-enabled (not PHS, not federated).",
    logType: "oidc",
    action: () => { highlightElement("hb_user1"); highlightElement("hb_dev1"); },
  },
  {
    logMessage: "Entra ID: Resolves corp.com to PTA authentication method. Locates PTA agents registered for this tenant. Selects active agent (round-robin with health check). PTA agents are outbound-only — no inbound firewall ports needed.",
    logType: "info",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "Entra ID: Encrypts credential payload using the PTA agent's RSA-2048 public key (registered at provisioning, stored in Entra). Payload: {UPN, password, correlationId, requestId}. Encryption: RSA-OAEP-SHA1 (PKCS#1 OAEP).",
    logType: "oidc",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "Entra ID → Azure Service Bus: Publishes encrypted auth request to tenant-specific Service Bus relay namespace. Message TTL: 90 seconds. Queue type: PTA authentication channel (authenticated with Entra service token).",
    logType: "http",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "AADConnect PTA Agent (on hb_aadconnect, running as SYSTEM): Long-polls Azure Service Bus outbound HTTPS connection (port 443). Receives encrypted auth request from queue.",
    logType: "http",
    action: () => { addTemporaryEdge("hb_aadconnect", "hb_entra", "http", "SvcBus long-poll"); highlightElement("hb_aadconnect"); },
  },
  {
    logMessage: "PTA Agent: Decrypts payload using RSA-2048 private key (stored in Windows Certificate Store, non-exportable: CNG key, CAPI2). Decrypted: {UPN='alice@corp.com', password='[cleartext]', correlationId='...'}.",
    logType: "info",
    action: () => highlightElement("hb_aadconnect"),
  },
  {
    logMessage: "PTA Agent → DC01: LDAP simple bind validation: ldap_bind(dc01.corp.local:389, userDN='cn=Alice,ou=Users,dc=corp,dc=local', password='[cleartext]', auth=LDAP_AUTH_SIMPLE). Alternatively: LogonUserW() API call for Kerberos pre-auth.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_dc01", "ldap", "LDAP bind (PTA)"),
  },
  {
    logMessage: "DC01: Validates credentials. Checks: password hash match ✓, account not disabled ✓, not locked out ✓, logon hours ✓, workstation restrictions ✓. Returns LDAP_SUCCESS (0x00).",
    logType: "ldap",
    action: () => highlightElement("hb_dc01"),
  },
  {
    logMessage: "PTA Agent → Azure Service Bus: Posts encrypted result {success: true, errorCode: null, correlationId} back to Entra response queue. Encrypted with session key, signed with agent key.",
    logType: "http",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_entra", "http", "Auth result"),
  },
  {
    logMessage: "Entra ID: Receives success result (correlation ID matched). Evaluates Conditional Access policies (device compliance, sign-in risk, MFA requirements). All satisfied — issues access_token + id_token + refresh_token for Alice.",
    logType: "success",
    action: () => { highlightElement("hb_entra"); highlightElement("hb_user1"); },
  },
];

// ── 4. Password Writeback (SSPR) ──────────────────────────────────────────────
export const hybridPasswordWritebackScenario = [
  {
    scenarioName: "Hybrid: Password Writeback — SSPR to On-Premises",
    logMessage: "Alice triggers Self-Service Password Reset at https://aka.ms/sspr. Entra ID checks: SSPR enabled for user ✓, Writeback enabled ✓, on-prem account is synced ✓ (onPremisesSyncEnabled=true).",
    logType: "oidc",
    action: () => { highlightElement("hb_user1"); highlightElement("hb_entra"); },
  },
  {
    logMessage: "Entra ID: Identity verification gate. Alice must satisfy configured SSPR methods (e.g., MFA authenticator app + security questions). Number of required gates: 2.",
    logType: "oidc",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "Alice satisfies MFA (Authenticator app TOTP) + alternate email OTP. Entra ID: Identity verified. Now evaluates new password against cloud complexity policy (length, character classes, banned password list).",
    logType: "info",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "Entra ID: Validates new password against Microsoft's leaked-credential (banned password) list. Password accepted. Initiates writeback flow to on-prem.",
    logType: "info",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "Entra ID → Azure Service Bus: Publishes PasswordResetRequest message to AADConnect writeback channel. Payload encrypted (AES-256, per-request key). Message: {ImmutableID, newPasswordHash, requestId, timestamp}.",
    logType: "sync",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "AADConnect Password Writeback Agent (outbound polling): Receives PasswordResetRequest from Service Bus. Validates HMAC signature on message (prevents tampering). Decrypts payload.",
    logType: "sync",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_entra", "sync", "SvcBus poll"),
  },
  {
    logMessage: "AADConnect → DC01: LDAP modify request — unicodePwd attribute change. Distinguished Name: 'cn=Alice,ou=Users,dc=corp,dc=local'. Operation: LDAP_MOD_REPLACE. Value: UTF-16LE(new_password) wrapped in double-quotes, per MS-ADTS §3.1.1.3.1.3.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_aadconnect", "hb_dc01", "ldap", "unicodePwd modify"),
  },
  {
    logMessage: "DC01 (PDC Emulator): Validates: password complexity ✓, minimum password age ✓, password history (last 24) ✓. Applies password change. Replicates to all DCs in domain via USN-based AD replication (urgent replication to other DCs within 15s).",
    logType: "ldap",
    action: () => highlightElement("hb_dc01"),
  },
  {
    logMessage: "DC01 → AADConnect: LDAP_SUCCESS (0x00). AADConnect writes success result to Service Bus response channel.",
    logType: "ldap",
    action: () => addTemporaryEdge("hb_dc01", "hb_aadconnect", "ldap", "LDAP success"),
  },
  {
    logMessage: "Entra ID: Receives writeback success confirmation. Updates pwdLastSet timestamp in cloud directory. Invalidates existing refresh tokens (forceChangePassword semantics if enabled). Alice receives success confirmation — on-prem password updated.",
    logType: "success",
    action: () => { highlightElement("hb_entra"); highlightElement("hb_user1"); },
  },
];

// ── 5. Seamless SSO (AZUREADSSOACC$ Kerberos) ─────────────────────────────────
export const hybridSeamlessSSOScenario = [
  {
    scenarioName: "Hybrid: Seamless SSO via AZUREADSSOACC$ Kerberos Ticket",
    logMessage: "Alice at WKSTN-HYB (domain-joined, on corp network) navigates to office.com in browser. Browser reaches https://login.microsoftonline.com — Entra performs Home Realm Discovery (HRD): corp.com → Seamless SSO enabled.",
    logType: "oidc",
    action: () => { highlightElement("hb_user1"); highlightElement("hb_dev1"); },
  },
  {
    logMessage: "Entra ID → Browser: Returns JavaScript that triggers Kerberos negotiation. Specifically targets: GET https://autologon.microsoftazuread-sso.com/corp.onmicrosoft.com/winauth/sso?client-request-id=<guid>&sso_nonce=<nonce>&pullStatus=0.",
    logType: "http",
    action: () => addTemporaryEdge("hb_dev1", "hb_entra", "http", "GET /winauth/sso"),
  },
  {
    logMessage: "autologon.microsoftazuread-sso.com: Returns HTTP 401 Unauthorized with header: WWW-Authenticate: Negotiate. Browser passes challenge to Windows SSPI (Security Support Provider Interface).",
    logType: "http",
    action: () => addTemporaryEdge("hb_entra", "hb_dev1", "http", "401 Negotiate"),
  },
  {
    logMessage: "WKSTN-HYB Windows SSPI: Checks TGT cache — Alice has a valid TGT from morning logon. Requests Service Ticket for SPN: HTTP/autologon.microsoftazuread-sso.com (backed by AZUREADSSOACC$ computer account in AD).",
    logType: "kerberos",
    action: () => highlightElement("hb_dev1"),
  },
  {
    logMessage: "WKSTN-HYB → DC01: AS-REQ / TGS-REQ. KDC: Looks up AZUREADSSOACC$ — computer account created by AADConnect Seamless SSO setup. KDC encrypts TGS with AZUREADSSOACC$ account's AES-256 long-term key (synced to Entra).",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_dev1", "hb_dc01", "kerberos", "TGS-REQ AZUREADSSOACC$"),
  },
  {
    logMessage: "DC01 → WKSTN-HYB: TGS-REP. Kerberos Service Ticket for HTTP/autologon.microsoftazuread-sso.com. Ticket body encrypted with AZUREADSSOACC$ AES-256 key. PAC contains: Alice's SID, group membership, UPN (alice@corp.com).",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_dc01", "hb_dev1", "kerberos", "TGS-REP"),
  },
  {
    logMessage: "WKSTN-HYB → Entra ID: GET /winauth/sso with Authorization: Negotiate <base64-encoded Kerberos AP-REQ>. The AP-REQ wraps the Kerberos service ticket (encrypted by AZUREADSSOACC$ key) + authenticator (client timestamp, subkey).",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_dev1", "hb_entra", "kerberos", "Kerberos AP-REQ"),
  },
  {
    logMessage: "Entra ID: Decrypts the Kerberos service ticket using AZUREADSSOACC$ account's AES-256 key (synchronized by AADConnect from on-prem). Validates: ticket not expired ✓, authenticator freshness (replay window 5 min) ✓.",
    logType: "kerberos",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "Entra ID: Extracts UPN from Kerberos PAC (alice@corp.com). Maps to Entra user object via ImmutableID / UPN match. Validates nonce from original sso_nonce parameter (CSRF protection).",
    logType: "info",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "Entra ID: Kerberos auth validated. No password prompt issued. Issues PRT (Primary Refresh Token) for device + access_token + id_token. Alice silently authenticated to M365 services without entering credentials.",
    logType: "success",
    action: () => { highlightElement("hb_entra"); highlightElement("hb_user1"); addTemporaryEdge("hb_entra", "hb_m365", "oidc", "Access granted"); },
  },
];

// ── 6. Cloud Kerberos Trust (WHfB → Entra Partial TGT → On-Prem TGT) ─────────
export const hybridCloudKerberosTrustScenario = [
  {
    scenarioName: "Hybrid: Cloud Kerberos Trust — WHfB to On-Premises Kerberos",
    logMessage: "Alice at WKSTN-HYB (Hybrid AAD Joined, WHfB enrolled, Cloud Kerberos Trust configured). Device is NOT on corp network — no DC line of sight. Alice wants to access \\\\dc01\\SYSVOL (on-prem resource). Cloud Kerberos Trust provides the path.",
    logType: "info",
    action: () => { highlightElement("hb_user1"); highlightElement("hb_dev1"); },
  },
  {
    logMessage: "WKSTN-HYB: No on-prem TGT cached (device off-network at provisioning time). Cloud Kerberos Trust enabled — Windows checks for krbtgt_AzureAD$ account in AD (created by AADConnect Entra Kerberos feature). Requests partial TGT from Entra ID.",
    logType: "tpm",
    action: () => highlightElement("hb_dev1"),
  },
  {
    logMessage: "Alice authenticates with WHfB gesture (PIN/fingerprint). TPM 2.0 unseals WHfB private key. Device constructs signed JWT assertion: {sub: deviceId, upn: alice@corp.com, iat, exp, nonce}. JWT signed with WHfB private key (TPM-bound, never extracted).",
    logType: "tpm",
    action: () => highlightElement("hb_dev1"),
  },
  {
    logMessage: "WKSTN-HYB → Entra ID: POST https://login.microsoftonline.com/<tenantId>/oauth2/v2.0/token. Body: grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer, assertion=<WHfB-JWT>, scope=https://kerberos.microsoftonline.com/.default. Requests Cloud Kerberos ticket.",
    logType: "oidc",
    action: () => addTemporaryEdge("hb_dev1", "hb_entra", "oidc", "WHfB TGT request"),
  },
  {
    logMessage: "Entra ID: Validates WHfB JWT assertion (signature vs registered TPM public key, device compliance, user state). Issues Cloud Kerberos Ticket (partial TGT): Kerberos TGT structure encrypted with Entra Kerberos Server Key (AES-256, tied to krbtgt_AzureAD$ account in AD).",
    logType: "oidc",
    action: () => highlightElement("hb_entra"),
  },
  {
    logMessage: "Entra ID → WKSTN-HYB: Cloud TGT (partial Kerberos TGT, RODC-style). Ticket realm: corp.local. Client: alice@corp.com. Session key: AES-256. Encoded in KERB_CLOUD_KERBEROS_DEBUG blob returned in token response.",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_entra", "hb_dev1", "kerberos", "Cloud TGT issued"),
  },
  {
    logMessage: "WKSTN-HYB → DC01: AS-REQ with PADATA = KERB-KEY-LIST-REQ containing the Cloud TGT. DC01 must have Network connectivity (VPN or on-net). DC identifies this as a referral from Entra Kerberos trust.",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_dev1", "hb_dc01", "kerberos", "AS-REQ Cloud TGT"),
  },
  {
    logMessage: "DC01: Decrypts Cloud TGT using krbtgt_AzureAD$ account key (read-only DC style). Validates PAC: alice@corp.com SID, group memberships. Generates full on-prem TGT (encrypted with regular krbtgt AES-256 key). Returns AS-REP.",
    logType: "kerberos",
    action: () => highlightElement("hb_dc01"),
  },
  {
    logMessage: "DC01 → WKSTN-HYB: Full Kerberos TGT (corp.local realm, 10h validity). WKSTN-HYB now requests TGS for cifs/dc01.corp.local (SYSVOL access). Standard TGS-REQ / TGS-REP exchange.",
    logType: "kerberos",
    action: () => addTemporaryEdge("hb_dc01", "hb_dev1", "kerberos", "Full on-prem TGT"),
  },
  {
    logMessage: "Alice accesses \\\\dc01\\SYSVOL via Kerberos service ticket. Full Kerberos chain established without NTLM, without user entering password. WHfB (phishing-resistant) → Cloud TGT → On-Prem TGT: complete hybrid Kerberos chain.",
    logType: "success",
    action: () => { highlightElement("hb_dev1"); highlightElement("hb_dc01"); highlightElement("hb_user1"); },
  },
];
