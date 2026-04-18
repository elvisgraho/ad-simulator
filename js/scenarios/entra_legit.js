import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';

// ── 1. Interactive Sign-in (OAuth2 PKCE Auth Code + MFA) ─────────────────────
export const entraInteractiveSignInScenario = [
  {
    scenarioName: "Entra ID Interactive Sign-in (OAuth2 PKCE + MFA)",
    logMessage: "Alice (ent_user1) opens M365 from LAPTOP-02 (ent_dev2) — Entra-registered device, no WHfB enrolled.",
    logType: "info",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_dev2"); },
  },
  {
    logMessage: "LAPTOP-02 → Entra ID: GET /oauth2/v2.0/authorize?client_id=...&scope=openid+Mail.Read&response_type=code&code_challenge=<SHA-256>&code_challenge_method=S256&state&nonce",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_dev2", "ent_tenant", "oidc", "GET /authorize"),
  },
  {
    logMessage: "Entra ID: No existing session cookie found for this device/user. Renders interactive login page (HTML). No PRT available on unmanaged device.",
    logType: "oidc",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Alice → Entra ID: POST /login (UPN: alice@corp.onmicrosoft.com + password). Transmitted over TLS 1.3. Entra ID validates credential hash against directory store.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_dev2", "ent_tenant", "oidc", "POST /login"),
  },
  {
    logMessage: "Entra ID: Credentials valid. Sign-in risk ML evaluation: Low. User requires MFA per policy — dispatches push notification to Microsoft Authenticator app (number matching enabled).",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Alice approves Authenticator push (displays matching number '42'). Entra ID: MFA claim satisfied (amr: [pwd, mfa]).",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_dev2", "ent_tenant", "oidc", "MFA approved"),
  },
  {
    logMessage: "Entra ID → LAPTOP-02: HTTP 302 redirect to redirect_uri with authorization code (10-min TTL, single-use, bound to code_challenge).",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev2", "oidc", "auth_code"),
  },
  {
    logMessage: "LAPTOP-02 → Entra ID: POST /oauth2/v2.0/token (grant_type=authorization_code, code, code_verifier — proves original PKCE initiator, client_id, redirect_uri).",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_dev2", "ent_tenant", "oidc", "POST /token"),
  },
  {
    logMessage: "Entra ID: Validates auth code. Verifies SHA-256(code_verifier) == stored code_challenge (PKCE — prevents authorization code interception). Builds JWT claims.",
    logType: "oidc",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID → LAPTOP-02: 200 OK { access_token (JWT, 1h), id_token (OIDC), refresh_token (14d, sliding), token_type: Bearer, scope }.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev2", "oidc", "tokens issued"),
  },
  {
    logMessage: "LAPTOP-02 → MS Graph: GET https://graph.microsoft.com/v1.0/me/messages (Authorization: Bearer <access_token>). JWT claims: upn, tid, scp=Mail.Read, amr=[pwd,mfa], iat, exp. Signed with Entra RS256 key.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_dev2", "ent_m365", "msgraph", "GET /me/messages"),
  },
  {
    logMessage: "M365: Validates token signature against Entra ID JWKS endpoint. Claims verified (audience, issuer, expiry, scopes). Access granted to Alice's mailbox.",
    logType: "success",
    action: () => { highlightElement("ent_m365"); highlightElement("ent_user1"); },
  },
];

// ── 2. Windows Hello for Business Sign-in (TPM-backed) ───────────────────────
export const entraWHfBSignInScenario = [
  {
    scenarioName: "Windows Hello for Business Sign-in (TPM 2.0-backed)",
    logMessage: "Alice at LAPTOP-01 (ent_dev1, Entra-joined + WHfB enrolled). Device wakes — WHfB credential provider prompts for gesture.",
    logType: "info",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_dev1"); },
  },
  {
    logMessage: "TPM 2.0 (LAPTOP-01): Alice enters PIN. Windows verifies PIN value against TPM-sealed blob (PCR policy binding). TPM 2.0 unseals the WHfB private key — key material NEVER leaves the TPM boundary.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Cloud AP Plugin (LAPTOP-01): Contacts Entra ID to get a nonce for the signed assertion (prevents replay attacks).",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "GET /nonce"),
  },
  {
    logMessage: "Entra ID → LAPTOP-01: Returns encrypted nonce (server-generated entropy, short TTL, single-use).",
    logType: "prt",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "prt", "nonce"),
  },
  {
    logMessage: "Cloud AP Plugin: Constructs PRT renewal JWT. { alg: RS256, kid: <WHfB_key_id> } / { sub: alice@corp, did: <device_id>, nonce, nbf, exp }. TPM signs JWT with WHfB private key — RS256 signature computed fully inside TPM hardware.",
    logType: "tpm",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "tpm", "Sign(WHfB key)"),
  },
  {
    logMessage: "LAPTOP-01 → Entra ID: POST /oauth2/v2.0/token (grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer, assertion=<TPM-signed JWT>, client_info, request_nonce).",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "PRT renew req"),
  },
  {
    logMessage: "Entra ID: Resolves device_id → retrieves device object. Fetches Alice's registered WHfB public key (stored during WHfB provisioning). Validates RS256 JWT signature — proves key resides in TPM on this enrolled device.",
    logType: "prt",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID: Evaluates Conditional Access. Sign-in risk: None (device-bound credential, no password). Device: Entra-joined, Intune-compliant ✓. All CA controls satisfied without MFA prompt (WHfB is MFA by design: PIN = something you know, TPM = something you have).",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID → LAPTOP-01: Issues PRT (opaque token, 14-day TTL, device+user bound) + session key encrypted with device transport key (also stored in TPM). PRT cannot be extracted — tied to this hardware.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "prt", "PRT issued"),
  },
  {
    logMessage: "Cloud AP Plugin: Stores PRT in LSASS protected memory. TPM decrypts session key via transport key. PRT is device-locked — cannot be used from another machine even if LSASS memory is dumped.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "WHfB sign-in complete. Alice is authenticated. All subsequent cloud app access will use PRT for silent SSO — no repeated credential prompts.",
    logType: "success",
    action: () => { highlightElement("ent_dev1"); highlightElement("ent_user1"); },
  },
];

// ── 3. PRT Silent SSO via WAM ─────────────────────────────────────────────────
export const entraPRTSSOScenario = [
  {
    scenarioName: "PRT Silent SSO — Token Acquisition via WAM",
    logMessage: "Alice opens Microsoft Teams on LAPTOP-01 (ent_dev1). WAM (Web Account Manager) broker intercepts the token request from Teams.",
    logType: "info",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_dev1"); },
  },
  {
    logMessage: "Teams → WAM (broker): AcquireTokenSilent(scope=https://api.spaces.skype.com/.default). WAM checks its in-memory PRT cache — valid PRT found for alice@corp, 11 days remaining.",
    logType: "prt",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "WAM: Requests a fresh nonce from Entra ID to sign the PRT token request (replay prevention — nonce is time-bound and single-use).",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "GET /nonce"),
  },
  {
    logMessage: "Entra ID → LAPTOP-01: Encrypted nonce returned.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "prt", "nonce"),
  },
  {
    logMessage: "TPM 2.0 (LAPTOP-01): WAM asks Cloud AP Plugin to sign the PRT request. TPM decrypts the session key (bound to TPM device transport key during PRT issuance), uses session key to sign HMAC over nonce + request params. Proves device possession without re-entering credentials.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "LAPTOP-01 → Entra ID: POST /oauth2/v2.0/token (grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer, assertion=<PRT cookie signed with session key>, request_nonce, scope=Teams+openid+profile).",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "SSO token req"),
  },
  {
    logMessage: "Entra ID: Validates PRT (checks expiry, device binding, session key signature over nonce). Re-evaluates CA policies — all controls satisfied. PRT satisfies MFA requirement (amr=ngcmfa from original WHfB sign-in).",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID → LAPTOP-01: 200 OK { access_token (JWT, 1h, scp=Teams), token_type: Bearer } + refreshed PRT cookie (sliding 14-day window renewal). JWT amr claim includes 'ngcmfa' (Next Gen Credentials MFA).",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "oidc", "access_token"),
  },
  {
    logMessage: "Teams → M365 Graph API: GET /v1.0/me/joinedTeams (Authorization: Bearer <access_token>). Graph validates token against Entra JWKS and returns Teams membership data.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_dev1", "ent_m365", "msgraph", "GET /me/joinedTeams"),
  },
  {
    logMessage: "Teams renders workspace. No credential prompt shown — fully transparent SSO. Total time from app launch to data: ~200ms. PRT lifecycle extended.",
    logType: "success",
    action: () => { highlightElement("ent_m365"); highlightElement("ent_user1"); },
  },
];

// ── 4. Conditional Access — Compliant Device Enforcement ─────────────────────
export const entraConditionalAccessScenario = [
  {
    scenarioName: "Conditional Access — Compliant Device Enforcement",
    logMessage: "Bob (ent_user2) on LAPTOP-02 (ent_dev2 — Entra-registered only, NOT Intune-managed, no WHfB) attempts to access SharePoint Online.",
    logType: "info",
    action: () => { highlightElement("ent_user2"); highlightElement("ent_dev2"); },
  },
  {
    logMessage: "LAPTOP-02 → Entra ID: GET /oauth2/v2.0/authorize (scope=https://corp.sharepoint.com/.default, response_type=code, PKCE). No PRT available — no WHfB, no Entra join.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_dev2", "ent_tenant", "oidc", "GET /authorize"),
  },
  {
    logMessage: "Bob → Entra ID: POST /login (UPN + password). MFA triggered — Authenticator push. Bob approves.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_dev2", "ent_tenant", "oidc", "Auth + MFA"),
  },
  {
    logMessage: "Entra ID → Conditional Access Engine: Evaluating policies for (Bob, LAPTOP-02, SharePoint Online, corp network, sign-in risk: Low).",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "CA Policy 'Require compliant device — SharePoint': User in scope ✓ | App: SharePoint ✓ | Platform: Windows ✓ | Device compliance (Intune): UNKNOWN (device not enrolled) ✗ | Hybrid AAD join: NOT joined ✗. Required control NOT met.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "CA Engine: Compliant device grant control failed. Checking session policy fallback: 'App-enforced restrictions' (via Defender for Cloud Apps). Applies session-level access controls rather than full block.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID: Token issued. access_token lacks deviceid claim (unmanaged device). Sets x-ms-cpim-slice for app-enforced session controls. Refresh token TTL capped at 1h (short session for unmanaged device).",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev2", "oidc", "token (restricted)"),
  },
  {
    logMessage: "LAPTOP-02 → SharePoint: GET https://corp.sharepoint.com (Bearer token). SharePoint detects missing device compliance claim → enforces app-enforced CA via MCAS proxy.",
    logType: "http",
    action: () => addTemporaryEdge("ent_dev2", "ent_m365", "http", "restricted session"),
  },
  {
    logMessage: "SharePoint grants read-only browser access. Download blocked, OneDrive sync disabled, copy to unmanaged apps blocked. Bob can view documents but cannot exfiltrate data via this device.",
    logType: "success",
    action: () => { highlightElement("ent_m365"); highlightElement("ent_user2"); },
  },
];

// ── 5. Managed Identity — Key Vault Secret Retrieval ─────────────────────────
export const entraManagedIdentityScenario = [
  {
    scenarioName: "Managed Identity — Key Vault Secret Retrieval",
    logMessage: "Azure-hosted App (ent_svc) starts and requires a DB connection string from Key Vault (ent_kv). App uses system-assigned Managed Identity (ent_mi) — no credentials in code or config.",
    logType: "info",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_mi"); },
  },
  {
    logMessage: "App → Azure IMDS: GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net (Header: Metadata: true). IMDS is a link-local endpoint at the hypervisor — not reachable from outside the VM.",
    logType: "imds",
    action: () => addTemporaryEdge("ent_svc", "ent_mi", "imds", "MI token req"),
  },
  {
    logMessage: "Azure IMDS: Identifies system-assigned Managed Identity bound to this compute resource. Resolves the associated service principal object in Entra ID. Initiates internal token acquisition on behalf of the workload.",
    logType: "imds",
    action: () => highlightElement("ent_mi"),
  },
  {
    logMessage: "IMDS → Entra ID: client_credentials token request using MI's certificate credential (managed by Azure platform, never exposed to app). audience=https://vault.azure.net.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_mi", "ent_tenant", "oidc", "MI cred flow"),
  },
  {
    logMessage: "Entra ID: Validates MI service principal. Checks Azure Resource Manager — MI assigned to this resource ✓. Issues access_token (JWT, 1h, aud=https://vault.azure.net) signed with Entra RS256 key.",
    logType: "oidc",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID → IMDS → App: { access_token: 'eyJ0eX...', token_type: Bearer, expires_in: 3599, expires_on: <unix_ts> }. App never sees the MI certificate — only the resulting token.",
    logType: "imds",
    action: () => addTemporaryEdge("ent_mi", "ent_svc", "imds", "token returned"),
  },
  {
    logMessage: "App → Key Vault: GET https://corp-kv.vault.azure.net/secrets/db-connstr?api-version=7.4 (Authorization: Bearer <MI_access_token>). Azure RBAC data-plane call — audience: vault.azure.net, enforced via Azure RBAC (not Entra app permissions).",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_svc", "ent_kv", "azurerm", "GET /secrets/db-connstr"),
  },
  {
    logMessage: "Key Vault: Validates JWT signature (public key from Entra JWKS). Checks claims: aud=vault.azure.net ✓ | iss=login.microsoftonline.com ✓ | exp ✓. Evaluates Azure RBAC: MI service principal has 'Key Vault Secrets User' role ✓.",
    logType: "info",
    action: () => highlightElement("ent_kv"),
  },
  {
    logMessage: "Key Vault → App: 200 OK { value: '<db_connection_string>', id: '...secrets/db-connstr/abc123', attributes: { enabled, created, updated, exp } }. Secret delivered. No credentials stored in environment variables or app config.",
    logType: "success",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_kv"); },
  },
];

// ── 6. PIM Just-in-Time Admin Role Activation ────────────────────────────────
export const entraPIMActivationScenario = [
  {
    scenarioName: "PIM Just-in-Time Role Activation (Global Admin)",
    logMessage: "EntraAdmin (ent_admin) needs to perform privileged Entra directory operations. Has zero standing admin privileges — only a PIM-eligible assignment for Global Administrator.",
    logType: "info",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "EntraAdmin → Entra ID PIM API: GET /privilegedAccess/aadRoles/resources/{tenantId}/roleAssignments?$filter=type eq 'Eligible' and subject/id eq '{adminObjectId}'. Lists eligible roles.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_admin", "ent_tenant", "oidc", "GET eligible roles"),
  },
  {
    logMessage: "Entra PIM: Returns eligible role assignment — GlobalAdministrator (roleDefinitionId: 62e90394-...). Activation policy: Max duration 4h | Justification required: Yes | MFA required: Yes | Approval required: No.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "EntraAdmin → Entra PIM: POST /privilegedAccess/aadRoles/roleAssignmentRequests { roleDefinitionId: GlobalAdmin, type: UserAdd, assignmentState: Active, justification: 'Emergency patch deployment — INC-7741', scheduleInfo: { duration: PT2H } }.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_admin", "ent_tenant", "oidc", "activation req"),
  },
  {
    logMessage: "Entra PIM: Activation requires MFA step-up (current session token lacks recent MFA claim). Triggers Authenticator push challenge to EntraAdmin.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_admin", "ent_tenant", "oidc", "MFA step-up"),
  },
  {
    logMessage: "EntraAdmin approves MFA push. Entra ID issues step-up token with refreshed 'mfa' amr claim (max age validated). PIM proceeds with activation.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra PIM: Creates time-bound active assignment — GlobalAdministrator, valid for 2h from now. Writes to Entra ID Audit Log: { actor: EntraAdmin, operation: Add member to role, target: GlobalAdministrator, timestamp, justification }.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID → EntraAdmin: 201 Created. Role active. On next token request, access_token will contain 'wids' claim with GlobalAdministrator role GUID (62e90394-69f5-4237-9190-012177145e10).",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_admin", "oidc", "role active (2h)"),
  },
  {
    logMessage: "EntraAdmin → Entra ID: PATCH /users/{targetId} with elevated token. Entra ID validates 'wids' claim — GlobalAdmin role present ✓. Privileged directory write operation authorized and executed.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_admin", "ent_tenant", "oidc", "privileged op"),
  },
  {
    logMessage: "Operation complete. PIM role auto-deactivates in 2h. Full audit trail preserved: activation request, justification, MFA event, all privileged operations — visible in Entra Sign-in Logs and Audit Logs.",
    logType: "success",
    action: () => { highlightElement("ent_admin"); highlightElement("ent_tenant"); },
  },
];

// ── 7. TPM 2.0 Key Attestation & WHfB Provisioning ───────────────────────────
export const entraTpmAttestationScenario = [
  {
    scenarioName: "TPM 2.0 Key Attestation — WHfB Provisioning",
    logMessage: "LAPTOP-01 (ent_dev1) has just completed Entra ID join. WHfB provisioning is triggered post-join for Alice. LAPTOP-01 has TPM 2.0 (firmware TPM via UEFI). Goal: generate and register a hardware-bound WHfB signing key with Entra ID.",
    logType: "info",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_dev1"); },
  },
  {
    logMessage: "Windows Provisioning: TPM2_CreatePrimary (Storage Root Key, SRK, hierarchy=Owner). TPM2_Create (WHfB auth key under SRK — RSA-2048, key attributes: fixedTPM=1 (non-exportable), fixedParent=1, sign=1, userWithAuth=1, policy=PCR[7]+AuthValue). Private key material generated inside TPM, never exposed.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "TPM 2.0: TPM2_Certify — Attestation Identity Key (AIK, derived under Endorsement Key hierarchy) signs a TPM2B_ATTEST structure containing the WHfB key's name (hash of public area). This cryptographically proves the WHfB key was created inside this specific TPM hardware.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Windows: Queries TPM for EK certificate (manufacturer-issued cert, embedded in TPM NVRAM, signed by Infineon/STMicro/Nuvoton CA). EK identifies the specific TPM hardware globally. AIK cert chain built: EK → Privacy CA → AIK.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "LAPTOP-01 → Entra ID: POST /devices/{deviceId}/registeredKeys { attestationStatement: 'TPM20', keyType: 'RSA2048', usage: 'NGC', aikCert: <AIK chain PEM>, creationData: <TPM2B_CREATION_DATA (PCR digest, clock, firmware version)>, certifyInfo: <TPM2B_ATTEST>, certifyInfoSignature: <AIK-signed ECDSA-256 quote over certifyInfo> }.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "tpm", "WHfB key reg + attestation"),
  },
  {
    logMessage: "Entra ID → Microsoft Azure Attestation (MAA): Validates attestation chain. EK certificate verifies against TPM manufacturer trusted CA root ✓. AIK signature over TPM2B_ATTEST valid ✓. creationData.objectAttributes confirms fixedTPM=1, sign=1, sensitiveDataOrigin=1 ✓. PCR[7] digest: Secure Boot enforcement active ✓.",
    logType: "tpm",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID: Attestation verified. Device health report: TPM present, hardware-backed key, Secure Boot enforced. Stores WHfB RSA-2048 public key on Alice's user object (keyCredential attribute). Sets keyStrength=NORMAL, attestationLevel=attested.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID → LAPTOP-01: 201 Created { activationBlob: <encrypted activation nonce, wrapped with WHfB public key> }. Only the TPM private key can decrypt this — confirms the key was never exported (round-trip proof of possession).",
    logType: "prt",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "tpm", "key registered"),
  },
  {
    logMessage: "TPM2_RSA_Decrypt (WHfB private key) → activationBlob decrypted. Proof-of-possession confirmed. WHfB provisioning complete. attestationLevel=attested grants access to CA policies requiring hardware-bound credentials. LAPTOP-01 now satisfies 'Require compliant TPM 2.0 device' Conditional Access rules.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "WHfB enrollment complete. All future sign-ins use this TPM-bound key (see 'WHfB Sign-in' scenario). Hardware attestation differentiates this device from software-credential-only devices — enables stricter CA policy grants for sensitive resources.",
    logType: "success",
    action: () => { highlightElement("ent_dev1"); highlightElement("ent_user1"); },
  },
];

// ── 8. macOS Platform SSO — Secure Enclave-backed ────────────────────────────
export const entraMacOSSSOScenario = [
  {
    scenarioName: "macOS Platform SSO — Secure Enclave-backed Sign-in",
    logMessage: "LAPTOP-01 (ent_dev1, treated as macOS 14 Sonoma, Intune-enrolled). Microsoft Enterprise SSO Plugin (PSSOe / com.microsoft.CompanyPortalMac.ssoextension) deployed via Intune MDM profile. Secure Enclave device key registered with Entra ID during enrollment. Alice uses Touch ID at macOS login.",
    logType: "info",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_dev1"); },
  },
  {
    logMessage: "macOS Secure Enclave Processor (SEP): Touch ID biometric evaluated entirely within SEP silicon — fingerprint template never accessible to Application Processor or OS kernel. SEP returns local auth success → unseals Platform SSO private key (EC P-256, generated in SEP, non-exportable). Equivalent to TPM 2.0 on Windows.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Platform SSO Extension (PSSOe): Detects no valid Entra PRT in macOS Keychain (SEP-protected ACL entry). Initiates device assertion flow using SEP-bound device identity key (provisioned at Intune enrollment via MDM SCEP + Apple CryptoTokenKit).",
    logType: "prt",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "PSSOe: Constructs device assertion JWT { alg: ES256, kid: <SEP_device_key_id> } / { sub: alice@corp.onmicrosoft.com, device_id: <entraDeviceId>, iss: <client_id>, iat, exp, nonce }. SEP performs ECDSA-P256 signing — key material never leaves Secure Enclave boundary.",
    logType: "tpm",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "tpm", "SEP Sign(device key)"),
  },
  {
    logMessage: "PSSOe → Entra ID: POST /oauth2/v2.0/token { grant_type=urn:ietf:params:oauth:grant-type:device-sso, device_assertion=<SEP-signed JWT>, client_id, scope=openid+profile+offline_access }.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "Platform SSO req"),
  },
  {
    logMessage: "Entra ID: Resolves device_id → fetches Entra device object (macOS, Intune-compliant: FileVault=enabled, Gatekeeper=enforced, min OS=14 ✓). Retrieves registered SEP public key (EC P-256, enrolled via Intune SCEP). Validates ES256 assertion signature ✓.",
    logType: "prt",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID: CA policy evaluation. Sign-in risk: None (device-bound hardware key, no password transmitted). Device compliance (Intune): macOS compliant ✓. Hybrid join / Entra join check: device registered ✓. Authentication strength: hardware-backed SSO — satisfies MFA requirement (SEP = 'something you have', Touch ID = 'something you are').",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID → PSSOe: Issues PRT (opaque, 14-day TTL, device+user bound) + session key encrypted with device SEP public key (EC P-256 ECDH key wrap). Only the SEP-bound device private key can unwrap the session key.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "prt", "PRT + session key"),
  },
  {
    logMessage: "PSSOe stores PRT in macOS Keychain item protected by SEP ACL (kSecAttrAccessControl: biometryAny + devicePasscode). Unlike Windows LSASS, the Keychain SEP ACL blocks access from unauthorized processes even with root privileges or kernel extension bypass.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Alice opens Microsoft Teams on Mac. PSSOe intercepts token acquisition (via macOS Network Extension + ASWebAuthenticationSession SSO extension hook). Uses SEP to HMAC-sign PRT cookie with session key (decrypted by SEP). Sends signed PRT cookie to Entra ID.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "SSO token req"),
  },
  {
    logMessage: "Entra ID: Validates PRT + session key HMAC. Issues scoped access_token (1h, scp=Teams). amr claim: ['hwsso'] — hardware SSO via Platform SSO. No password prompt, no Authenticator push — fully silent authentication.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "oidc", "access_token (hwsso)"),
  },
  {
    logMessage: "LAPTOP-01 → M365: GET /api/teams (Bearer <access_token>). M365 validates JWT amr=hwsso — hardware-backed session, satisfies Conditional Access grant controls for sensitive resources. Teams workspace rendered. macOS Platform SSO provides equivalent security posture to WHfB on Windows.",
    logType: "success",
    action: () => { highlightElement("ent_m365"); highlightElement("ent_user1"); },
  },
];

// ── 9. Daily PRT Rotation via WHfB Biometric Re-auth ─────────────────────────
export const entraPRTRotationScenario = [
  {
    scenarioName: "Daily PRT Rotation — WHfB Biometric Re-authentication",
    logMessage: "Alice opens LAPTOP-01 (ent_dev1) Monday morning. Device was locked overnight. Cloud AP Plugin detects existing PRT in LSASS (3 days old, 11 days remaining). Interactive biometric gesture at wake → triggers PRT rotation: resets 14-day sliding window, rotates session key.",
    logType: "info",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_dev1"); },
  },
  {
    logMessage: "Windows Hello credential provider: fingerprint gesture received. TPM 2.0 PCR[7] policy evaluated (Secure Boot PCR values match enrollment state ✓). TPM unseals WHfB private key (RSA-2048) — key handle created inside TPM; private key never exposed to OS.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Cloud AP Plugin → Entra ID: GET nonce (short-lived, cryptographically random, single-use — replay prevention for the upcoming rotation request).",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "GET nonce"),
  },
  {
    logMessage: "Entra ID → LAPTOP-01: Encrypted nonce blob returned (nonce encrypted such that only the current session key holder can incorporate it into the signed request).",
    logType: "prt",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "prt", "nonce blob"),
  },
  {
    logMessage: "Cloud AP Plugin: Two TPM operations in sequence. (1) HMAC-SHA256(current_session_key, nonce + request_params) — proves possession of existing valid PRT without transmitting it in cleartext. (2) RSA-2048 sign { kid: <WHfB_key_id>, sub: alice@corp, did: <device_id>, nonce, iat, exp } with WHfB private key — proves hardware binding.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "LAPTOP-01 → Entra ID: POST /oauth2/v2.0/token { grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer, assertion=<WHfB-signed JWT>, request=<HMAC-signed PRT cookie>, refresh_token=<current PRT reference>, scope=openid+profile }.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_dev1", "ent_tenant", "prt", "PRT rotation req"),
  },
  {
    logMessage: "Entra ID validates in order. (1) PRT lookup: retrieves current PRT by reference, verifies session key HMAC over nonce ✓ — proves caller holds the session key, not just a stolen PRT blob. (2) WHfB assertion: fetches registered public key from device object, validates RSA-2048 signature ✓. Both checks must pass.",
    logType: "prt",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID: CA re-evaluation for this rotation event — sign-in risk: None, device compliant ✓, interactive hardware re-auth → amr=ngcmfa. Current PRT is IMMEDIATELY INVALIDATED server-side (one-time-use rotation — replay-safe even if the rotation request was intercepted in transit).",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID → LAPTOP-01: 200 OK { new_prt: <opaque, 14-day TTL reset from now>, new_session_key: <RSA-OAEP encrypted with WHfB public key>, token_type: Bearer }. Old session key is now invalid server-side.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_tenant", "ent_dev1", "prt", "new PRT + session key"),
  },
  {
    logMessage: "TPM2_RSA_Decrypt (WHfB private key, OAEP): Unwraps new session key from ciphertext. New session key lives only in TPM and LSASS protected memory — never in plaintext on disk or accessible to userspace. Old PRT cookie and session key zeroed from LSASS.",
    logType: "tpm",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "PRT rotation complete. Validity window reset to 14 days from now. All subsequent app SSO (Teams, SharePoint, Outlook via WAM) uses new PRT + new session key. Stolen PRT from this morning's LSASS dump is now a dead token — single-use rotation is the primary defense against pass-the-PRT attacks.",
    logType: "success",
    action: () => { highlightElement("ent_dev1"); highlightElement("ent_user1"); },
  },
];
