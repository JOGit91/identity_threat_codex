/* ── M365 Hardening Control Data ────────────────────────────
   Shared across hardening matrix, control profiles, and plan builder.

   Coverage scale: 0 = none, 1 = partial, 2 = high, 3 = critical
   Complexity:     1 = low,  2 = medium,  3 = high
   Cost:           "free" | "included" | "upgrade" | "third-party"
─────────────────────────────────────────────────────────── */

const ATTACKS = [
  {
    id: "session-token-theft",
    name: "Session Token Theft",
    short: "Token Theft",
    url: "attacks/session-token-theft.html",
  },
  {
    id: "ms-teams-impersonation",
    name: "MS Teams Impersonation",
    short: "Teams Impersonation",
    url: "attacks/ms-teams-impersonation.html",
  },
];

const CONTROLS = [

  // ── Identity & Authentication ─────────────────────────────

  {
    id: "fido2",
    name: "Phishing-Resistant MFA (FIDO2 / Windows Hello for Business)",
    category: "Identity & Authentication",
    priority: "P1",
    complexity: 3,
    complexityLabel: "High",
    complexityNote: "Requires hardware procurement, Intune device management, helpdesk preparation, user training, and a phased rollout. Budget several weeks to months for a full deployment.",
    cost: "included",
    costLabel: "Included + Hardware Cost",
    licenseNote: "FIDO2 configuration is included in all Entra ID / M365 plans. Windows Hello for Business requires Intune (included in M365 Business Premium, E3, E5). Hardware FIDO2 keys cost ~$25–$50 per user.",
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 2,
    },
    why: {
      "session-token-theft":    "FIDO2 credentials are origin-bound — an AiTM proxy cannot capture or relay them. The only MFA type that prevents token theft at the authentication layer.",
      "ms-teams-impersonation": "If a victim clicks a phishing link from Teams, FIDO2 prevents compromise because the phishing domain won't match the registered origin.",
    },
    overview: [
      "Phishing-Resistant MFA replaces traditional password + one-time code (OTP) authentication with cryptographic proof that is permanently bound to a specific website origin. When a user registers a FIDO2 security key or Windows Hello for Business credential, the private key is stored on the device and mathematically linked to the exact domain they registered it against. An AiTM (Adversary-in-the-Middle) phishing proxy is fundamentally incapable of relaying these credentials because the domain the victim is actually connecting to won't match.",
      "This is categorically different from app-based authenticators (Microsoft Authenticator, Google Authenticator) or SMS codes, which generate one-time passwords that an AiTM proxy can capture and replay in real time. FIDO2 and Windows Hello for Business are the only MFA methods that stop AiTM phishing by cryptographic design — not by policy or user behavior.",
    ],
    m365Config: {
      where: "Entra ID admin center → Security → Authentication methods → FIDO2 Security Key / Windows Hello for Business",
      license: "Entra ID Free (FIDO2 config) · Intune required for WHfB (M365 Business Premium, E3, E5)",
      steps: [
        "Audit current MFA method usage in Entra ID → Security → Authentication methods → Activity report",
        "Identify pilot group — start with IT staff and privileged admin accounts",
        "Procure FIDO2 hardware keys (YubiKey, etc.) or verify that Windows devices are eligible for Windows Hello for Business",
        "Enable FIDO2 Security Key authentication method in Entra ID → Security → Authentication methods",
        "Pilot enrollment with IT group — verify registration flow and test helpdesk reset procedures",
        "Create a Conditional Access policy requiring phishing-resistant MFA for all privileged roles",
        "Prepare user communication and training materials explaining the new login flow",
        "Deploy Intune configuration profile to enforce Windows Hello for Business on managed Windows devices",
        "Phase out SMS and voice MFA for enrolled users once phishing-resistant methods are registered",
        "Expand rollout in monthly cohorts until all users are covered; enforce via Conditional Access",
      ],
    },
    thirdParty: [
      { name: "Yubico (YubiKey)", note: "Industry-standard FIDO2 hardware keys. Available in USB-A, USB-C, NFC variants. Series 5 recommended for enterprise." },
      { name: "Google Titan Security Key", note: "FIDO2/FIDO U2F compatible. USB-C and NFC options available." },
      { name: "HID Global", note: "Enterprise-focused FIDO2 keys with additional smart card capabilities." },
      { name: "Feitian Technologies", note: "Wide range of FIDO2 keys at lower price points; suitable for large deployments." },
    ],
    implementationPlan: [
      "Phase 0 (Week 1): Run authentication method usage report; identify any users without MFA and prioritize them first",
      "Phase 1 (Weeks 2–3): Pilot with IT team — procure keys, enroll, test break-glass procedures",
      "Phase 2 (Week 4): Draft Conditional Access policy for privileged roles in report-only mode; validate with pilot",
      "Phase 3 (Months 2–3): Procure keys for all users; deploy Intune WHfB policy to managed Windows fleet",
      "Phase 4 (Month 3+): Phased user rollout by department; run training before each cohort goes live",
      "Phase 5 (Month 4+): Enable Conditional Access enforcement; begin removing legacy MFA methods for enrolled users",
    ],
  },

  {
    id: "number-matching",
    name: "Number Matching & Additional Context for MFA Push",
    category: "Identity & Authentication",
    priority: "P2",
    complexity: 1,
    complexityLabel: "Low",
    complexityNote: "A single configuration toggle in the Entra admin center. Takes under 30 minutes to enable. No user disruption — only changes what the MFA approval notification looks like.",
    cost: "free",
    costLabel: "Free",
    licenseNote: "Included in all Entra ID / M365 plans. No additional licensing required.",
    coverage: {
      "session-token-theft":    1,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Reduces push bombing effectiveness in AiTM-adjacent campaigns. Doesn't stop token theft once a session exists, but limits MFA fatigue abuse.",
      "ms-teams-impersonation": "Directly stops MFA push bombing — victims must enter a matching code rather than blindly approving. Additional context (app name + location) makes attacker-triggered pushes obvious.",
    },
    overview: [
      "Number Matching requires users approving a Microsoft Authenticator MFA push to type a two-digit number shown on the sign-in screen into the Authenticator app. This one change eliminates 'push bombing' — where attackers who have a victim's credentials trigger repeated MFA notifications hoping the victim approves one out of annoyance or confusion.",
      "Additional Context shows the name of the application requesting authentication and the geographic location of the sign-in attempt inside the Authenticator notification. A victim receiving a push for 'Microsoft Exchange Online' from 'Eastern Europe' when they haven't touched their laptop is immediately suspicious — and far less likely to approve.",
    ],
    m365Config: {
      where: "Entra ID admin center → Security → Authentication methods → Microsoft Authenticator → Configure",
      license: "Free — included in all Entra ID and M365 plans",
      steps: [
        "Sign in to Entra ID admin center (entra.microsoft.com)",
        "Navigate to Security → Authentication methods → Microsoft Authenticator",
        "Click Configure to open the feature settings",
        "Set 'Require number matching' to Enabled",
        "Set 'Show additional context in notifications' to Enabled",
        "Save the configuration",
        "Send a brief user communication explaining that MFA approvals will now require entering a two-digit code",
        "Monitor Authenticator help desk tickets for the first week; update your MFA guidance documentation",
      ],
    },
    thirdParty: [],
    implementationPlan: [
      "Day 1: Enable number matching and additional context in Entra admin center (30 minutes)",
      "Day 1: Draft user communication explaining what to expect at next login",
      "Day 2: Send communication to all users",
      "Week 1: Monitor helpdesk tickets; update self-service MFA guidance if needed",
    ],
  },

  {
    id: "restrict-mfa-reg",
    name: "Restrict MFA Method Registration (Require Compliant Device)",
    category: "Identity & Authentication",
    priority: "P2",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Requires creating a Conditional Access policy and testing carefully to avoid locking out users who need to register MFA legitimately. Plan for a report-only period before enforcement.",
    cost: "included",
    costLabel: "Included (P1 License)",
    licenseNote: "Requires Entra ID P1 (included in M365 Business Premium, E3, E5, or as standalone add-on).",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Prevents an attacker who has stolen a session token from registering a new MFA method to maintain persistent access through a password reset.",
      "ms-teams-impersonation": "Limits persistence options after account takeover via Teams-based phishing — attacker cannot add their own authenticator.",
    },
    overview: [
      "By default, any user can register a new MFA method from any device or location. This is a critical gap: an attacker who gains access to an account can register their own authenticator app or phone number, giving them persistent MFA-authenticated access even after the legitimate user resets their password.",
      "This control restricts MFA method registration to scenarios that meet specific requirements — such as occurring from a compliant, Intune-managed device, or from a trusted network location. Any attempt to add or modify MFA methods from an untrusted context is blocked, making post-compromise persistence via MFA registration significantly harder.",
    ],
    m365Config: {
      where: "Entra ID admin center → Protection → Conditional Access → New policy → Action: Register security information",
      license: "Entra ID P1 (M365 Business Premium, E3, E5)",
      steps: [
        "Navigate to Entra ID → Security → Named Locations and define your trusted office/VPN IP ranges",
        "In Conditional Access → create a new policy named 'Restrict MFA registration'",
        "Target: All users (with break-glass admin account excluded)",
        "Action: User Actions → Register security information",
        "Conditions: Require that the device be compliant OR the location be a named trusted location",
        "Grant: Block access (for all other scenarios)",
        "Enable in Report-only mode for 2 weeks",
        "Review sign-in logs for 'Register security information' events that would have been blocked",
        "Address any legitimate registration scenarios that need to be excluded",
        "Switch to Enabled enforcement",
      ],
    },
    thirdParty: [],
    implementationPlan: [
      "Week 1: Define Named Locations (office IPs, VPN) in Entra ID",
      "Week 1: Create and enable Conditional Access policy in Report-only mode",
      "Weeks 1–2: Monitor sign-in logs for would-be blocked registrations; address edge cases",
      "Week 3: Switch to Enabled; communicate to IT helpdesk how to assist users who need to register from home",
    ],
  },

  {
    id: "block-legacy-auth",
    name: "Block Legacy Authentication Protocols",
    category: "Identity & Authentication",
    priority: "P3",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Quick to configure but requires an audit of legacy auth usage first to avoid disrupting users or service accounts. The audit step is non-negotiable before enabling the block.",
    cost: "included",
    costLabel: "Included (P1 License)",
    licenseNote: "Requires Entra ID P1 for Conditional Access (included in M365 Business Premium, E3, E5). Microsoft provides a built-in CA policy template.",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 0,
    },
    why: {
      "session-token-theft":    "Legacy protocols (IMAP, POP3, SMTP AUTH, basic auth) bypass Conditional Access and MFA entirely — they cannot enforce MFA and tokens acquired through these protocols can be used independently of session cookie theft.",
      "ms-teams-impersonation": "Not directly relevant to Teams-based attack chains.",
    },
    overview: [
      "Legacy authentication protocols — IMAP, POP3, SMTP AUTH, and Exchange ActiveSync with Basic Authentication — were designed before MFA existed. They authenticate with a username and password alone, and cannot present an MFA claim. More critically, they completely bypass Conditional Access policies. Any user or service account that can authenticate via a legacy protocol is effectively unprotected by your modern auth stack.",
      "Blocking legacy authentication is one of the most commonly cited quick-win security controls in M365. Microsoft deprecated Basic Authentication for Exchange Online and has been enforcing the block in waves since 2022. However, many tenants still have residual legacy auth usage from older email clients, shared mailboxes accessed via IMAP scripts, or line-of-business apps using SMTP AUTH. The audit step is critical before blocking.",
    ],
    m365Config: {
      where: "Entra ID admin center → Protection → Conditional Access → Policies → + New policy from template → Block legacy authentication",
      license: "Entra ID P1 (M365 Business Premium, E3, E5)",
      steps: [
        "In Azure AD / Entra Sign-In Logs, filter 'Client App' to show legacy auth methods (IMAP, POP3, SMTP, Basic Auth)",
        "Export the last 30 days of legacy auth sign-ins to identify any active users or service accounts",
        "For each legacy auth user, work with them to migrate to a modern auth client (Outlook, web browser)",
        "For service accounts or scripts using SMTP AUTH, migrate to OAuth 2.0 or use a dedicated SMTP relay",
        "In Conditional Access → Policies → use the 'Block legacy authentication' template policy",
        "Enable the policy in Report-only mode for 2 weeks",
        "Monitor for any blocked legacy auth attempts that haven't been migrated yet",
        "After all legacy auth users are migrated, switch to Enabled",
      ],
    },
    thirdParty: [],
    implementationPlan: [
      "Week 1: Pull legacy auth usage report from Sign-In Logs; catalog all affected users and apps",
      "Weeks 1–2: Work with affected users and service accounts to migrate to modern auth",
      "Week 2: Enable Conditional Access block policy in Report-only",
      "Week 3: Validate no remaining legacy auth in sign-in logs",
      "Week 3: Switch to Enabled",
    ],
  },

  // ── Conditional Access ────────────────────────────────────

  {
    id: "token-protection",
    name: "Conditional Access Token Protection (Token Binding)",
    category: "Conditional Access",
    priority: "P1",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Requires Entra ID P2 licensing and Conditional Access policy creation. Some older or third-party apps may not support token binding, requiring a compatibility testing period.",
    cost: "upgrade",
    costLabel: "Requires Entra ID P2 / M365 E5",
    licenseNote: "Requires Entra ID P2 or M365 E5 / E5 Security. Token Protection is generally available for Exchange Online, SharePoint Online, and Teams.",
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Directly stops token replay — binds access tokens to the specific device and session where they were issued. A stolen token replayed from an attacker's device will be rejected by Entra ID.",
      "ms-teams-impersonation": "Provides post-compromise protection if account takeover occurs following a Teams phishing attack.",
    },
    overview: [
      "Token Protection (also called Token Binding) is a Conditional Access Session control that cryptographically binds an access token to the specific device and Entra-registered session where it was issued. When the token is presented from any other device or session, Entra ID detects the mismatch and rejects the authentication — even if the token itself is otherwise valid and unexpired.",
      "This is a direct countermeasure for pass-the-cookie and AiTM token replay attacks. Where traditional session tokens are bearer tokens (usable by anyone who holds them), Token Protection makes tokens device-bound. An attacker who successfully steals a cookie via an AiTM proxy or infostealer malware cannot use it from their own machine.",
    ],
    m365Config: {
      where: "Entra ID admin center → Protection → Conditional Access → New policy → Session → Require token protection for sign-in sessions",
      license: "Entra ID P2 (M365 E5, M365 E5 Security, or Entra ID P2 standalone add-on)",
      steps: [
        "Verify Entra ID P2 licensing is assigned to target users",
        "In Conditional Access → create a new policy targeting Exchange Online, SharePoint Online, and Microsoft Teams",
        "Under Session controls → enable 'Require token protection for sign-in sessions'",
        "Enable in Report-only mode",
        "Monitor for Token Protection failure events (sign-ins where binding fails) — these indicate clients that don't support token binding",
        "Investigate non-compliant clients and move users to supported clients (modern Outlook, browser-based apps)",
        "After 2–4 weeks with no unexpected failures, switch to Enabled",
        "Expand to additional cloud apps over time",
      ],
    },
    thirdParty: [],
    implementationPlan: [
      "Week 1: Verify P2 licensing; create Conditional Access policy in Report-only",
      "Weeks 2–4: Monitor for token binding failures; remediate incompatible clients",
      "Week 4: Switch to Enabled for Exchange Online, SharePoint, Teams",
      "Month 2+: Expand to additional cloud apps",
    ],
  },

  {
    id: "cae",
    name: "Continuous Access Evaluation (CAE)",
    category: "Conditional Access",
    priority: "P1",
    complexity: 1,
    complexityLabel: "Low",
    complexityNote: "CAE is enabled by default in most M365 tenants. This is primarily a verification task — confirm it is on and optionally enable Strict Location Enforcement.",
    cost: "free",
    costLabel: "Free",
    licenseNote: "Included in all Entra ID and M365 plans. No additional licensing required.",
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Revokes stolen tokens in near-real-time (within minutes) when a password reset, account disable, or policy violation occurs — dramatically reducing the window a stolen token is useful.",
      "ms-teams-impersonation": "Limits the time window after gaining access via a Teams phishing chain before the session can be revoked.",
    },
    overview: [
      "Without Continuous Access Evaluation, access tokens remain valid until they naturally expire — which can be 60–90 minutes for access tokens and up to 90 days for refresh tokens. If an account is compromised, security teams must race to revoke sessions before an attacker uses the time window. CAE changes this by establishing a persistent channel between M365 services and Entra ID that allows near-real-time token revocation.",
      "When a critical event occurs — password change, account disabled, MFA changed, or a Conditional Access policy change — Entra ID signals CAE-capable applications to re-evaluate the user's authorization immediately. The user's access is revoked within minutes rather than hours. CAE is already on by default for most tenants; the primary action is to verify it's enabled and not inadvertently disabled.",
    ],
    m365Config: {
      where: "Entra ID admin center → Security → Continuous Access Evaluation",
      license: "Free — included in all Entra ID plans",
      steps: [
        "Sign in to Entra ID admin center → Security → Continuous Access Evaluation",
        "Verify the feature is enabled (it is on by default for most tenants)",
        "Review which applications are listed as 'CAE capable' — Exchange Online, SharePoint, Teams, and the Entra ID service are supported",
        "Optionally enable 'Strict Location Enforcement' if you use Named Location Conditional Access policies — this ensures location-based policies are enforced in near-real-time",
        "Test CAE by revoking a test user's sessions in Entra ID (All Users → select user → Revoke sessions) and verify access is lost within a few minutes",
      ],
    },
    thirdParty: [],
    implementationPlan: [
      "Day 1: Verify CAE is enabled in Entra ID admin center (15 minutes)",
      "Day 1: Test revocation with a test account",
      "Day 2: Enable Strict Location Enforcement if using Named Location CA policies",
      "Ongoing: Include session revocation in incident response procedures",
    ],
  },

  {
    id: "signin-risk-ca",
    name: "Sign-in Risk Conditional Access Policies",
    category: "Conditional Access",
    priority: "P1",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Requires Entra ID P2 licensing and careful policy creation to avoid false-positive lockouts. A report-only period with monitoring is essential before enforcement.",
    cost: "upgrade",
    costLabel: "Requires Entra ID P2 / M365 E5",
    licenseNote: "Requires Entra ID P2 or M365 E5 / E5 Security. Entra ID Protection (which generates risk signals) is also P2.",
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 2,
    },
    why: {
      "session-token-theft":    "Blocks or requires step-up authentication when Entra ID Protection detects Anomalous Token, Impossible Travel, or High sign-in risk — the primary real-time enforcement layer for detected token theft.",
      "ms-teams-impersonation": "Catches and blocks high-risk sign-ins that follow a successful Teams phishing chain where credentials were harvested.",
    },
    overview: [
      "Sign-in Risk Conditional Access policies use the risk signals generated by Entra ID Protection to make real-time access decisions. When a user's sign-in is flagged as Medium or High risk — due to anomalous token properties, impossible travel, anonymous IP usage, or other signals — the CA policy can require step-up MFA, force a password change, or block access entirely.",
      "This is the enforcement mechanism that translates Entra ID Protection's detections into actual protective action. Without a risk-based CA policy, detections are informational only. With it, detected token theft and credential compromise automatically trigger friction or block the attacker before they can do damage.",
    ],
    m365Config: {
      where: "Entra ID admin center → Protection → Conditional Access → New policy → Conditions → Sign-in risk",
      license: "Entra ID P2 (M365 E5, M365 E5 Security, or standalone add-on)",
      steps: [
        "Confirm Entra ID P2 licenses are assigned to all users in scope",
        "Review current risk detections in Entra ID → Security → Identity Protection to understand your baseline",
        "Create a Conditional Access policy: Sign-in risk = High → Block access (for most orgs) or require phishing-resistant MFA",
        "Create a second policy: Sign-in risk = Medium → Require MFA",
        "Enable both policies in Report-only mode",
        "Review flagged sign-ins over 2–4 weeks; identify and exclude any legitimate false positive patterns",
        "Switch High-risk policy to Enabled; monitor for 1 week",
        "Switch Medium-risk policy to Enabled",
      ],
    },
    thirdParty: [
      { name: "Microsoft Sentinel", note: "Ingest Entra ID Protection risk events for advanced hunting and correlation beyond what CA policies can do." },
    ],
    implementationPlan: [
      "Week 1: Verify P2 licensing; review current Identity Protection detections",
      "Week 1: Create both risk-based CA policies in Report-only mode",
      "Weeks 2–4: Monitor and tune; document false positive exclusion patterns",
      "Week 4: Enable High-risk block policy",
      "Week 5: Enable Medium-risk MFA policy",
      "Ongoing: Review risk detections weekly; dismiss false positives",
    ],
  },

  {
    id: "compliant-device",
    name: "Require Compliant / Hybrid-Joined Device for Sensitive Apps",
    category: "Conditional Access",
    priority: "P3",
    complexity: 3,
    complexityLabel: "High",
    complexityNote: "Requires Microsoft Intune MDM deployment, device compliance policies, device enrollment across the fleet, and Conditional Access policy creation. This is a multi-month initiative for most organizations.",
    cost: "included",
    costLabel: "Included (Intune Required)",
    licenseNote: "Microsoft Intune is included in M365 Business Premium, E3, and E5. If you only have M365 E1/F1, Intune requires a separate add-on.",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Stolen tokens replayed from an unmanaged attacker device fail — the CA policy rejects authentication unless the device is enrolled and compliant.",
      "ms-teams-impersonation": "Limits post-compromise lateral movement by requiring managed, compliant devices for access to sensitive applications.",
    },
    overview: [
      "Requiring a compliant or Hybrid Azure AD-joined device as a condition for accessing M365 applications means that even a valid username, password, and MFA cannot gain access from an unknown or unmanaged device. This is powerful because most attackers attempting to replay stolen tokens or use harvested credentials will be operating from their own machines — which will never pass a device compliance check.",
      "Implementing this control requires that your organization have Microsoft Intune deployed and all user devices enrolled. Device compliance policies define minimum standards (disk encryption, OS patch level, PIN requirements) that a device must meet before access is granted. This is one of the most impactful long-term controls but also one of the heaviest to implement.",
    ],
    m365Config: {
      where: "Intune admin center → Devices → Compliance policies + Entra ID Conditional Access → Require device to be marked as compliant",
      license: "Microsoft Intune (included in M365 Business Premium, E3, E5)",
      steps: [
        "Confirm Microsoft Intune licensing and set up Intune tenant if not already configured",
        "Define device compliance policies in Intune (Devices → Compliance policies) for Windows, macOS, iOS, Android",
        "Set compliance requirements: BitLocker encryption, OS version minimums, antivirus active, screen lock",
        "Enroll a pilot group of devices in Intune MDM",
        "Verify compliance policy is applying correctly and devices are showing as compliant",
        "Create Conditional Access policy requiring device compliance for Exchange Online and SharePoint",
        "Enable in Report-only mode; expand device enrollment to all users over 4–8 weeks",
        "Address BYOD scenarios using Mobile Application Management (MAM without enrollment) for personal devices",
        "Once >95% device enrollment is achieved, switch CA policy to Enabled",
      ],
    },
    thirdParty: [
      { name: "Jamf (macOS/iOS)", note: "Best-in-class MDM for Apple devices. Integrates with Intune for conditional access compliance." },
      { name: "VMware Workspace ONE", note: "Cross-platform MDM/EMM with Entra ID integration for compliance-based CA." },
      { name: "Ivanti", note: "Enterprise UEM platform supporting Windows, macOS, iOS, Android with Entra ID integration." },
    ],
    implementationPlan: [
      "Month 1: Set up Intune, define compliance policies, enroll IT team devices as pilot",
      "Month 2: Create Report-only CA policy; begin broad device enrollment rollout",
      "Months 2–3: Enroll all Windows devices; address Mac, iOS, Android with platform-specific profiles",
      "Month 3: Address BYOD with MAM policies",
      "Month 4: Switch CA policy to Enabled once enrollment reaches target coverage",
      "Ongoing: Maintain compliance policies as OS versions change; monitor non-compliant device alerts",
    ],
  },

  {
    id: "token-lifetime",
    name: "Reduce Token Lifetimes / Enforce Sign-in Frequency",
    category: "Conditional Access",
    priority: "P2",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Conditional Access policy creation with UX tradeoffs to consider. Reducing sign-in frequency increases authentication prompts for users — target sensitive apps first, not all apps.",
    cost: "included",
    costLabel: "Included (P1 License)",
    licenseNote: "Sign-in frequency control requires Entra ID P1 (M365 Business Premium, E3, E5).",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 0,
    },
    why: {
      "session-token-theft":    "Shorter token lifetimes reduce the window a stolen token is useful. Disabling persistent browser sessions also limits cookie theft viability — the cookie expires when the browser closes.",
      "ms-teams-impersonation": "Not directly relevant to Teams-based initial access chains.",
    },
    overview: [
      "By default, Microsoft 365 access tokens are valid for 60–90 minutes and refresh tokens for up to 90 days. 'Persistent browser session' cookies can also keep users signed in across browser restarts. If a token or cookie is stolen, the attacker has the full remaining lifetime of that token to operate. This control reduces that window.",
      "Sign-in Frequency in Conditional Access sets a maximum age for sessions before re-authentication is required. Applied to sensitive apps like Exchange Online or financial SharePoint sites, it limits how long a stolen session is useful without triggering a new authentication event the attacker can't complete. Disabling persistent browser sessions means closing the browser invalidates the session cookie.",
    ],
    m365Config: {
      where: "Entra ID admin center → Protection → Conditional Access → Session controls → Sign-in frequency",
      license: "Entra ID P1 (M365 Business Premium, E3, E5)",
      steps: [
        "Identify high-sensitivity apps (Exchange Online, Finance SharePoint sites, Azure Portal)",
        "In Conditional Access → create a new policy scoped to those high-sensitivity apps",
        "Under Session controls → Sign-in frequency: set to 4–8 hours (balance security vs. user friction)",
        "Under Session controls → Persistent browser session: set to 'Never persistent' for privileged users and admin portals",
        "Enable in Report-only mode for 1–2 weeks",
        "Review for user authentication failure patterns or excessive re-authentication complaints",
        "Tune the frequency value based on feedback; switch to Enabled",
        "Consider a separate, stricter policy for privileged admin accounts (1–4 hour frequency)",
      ],
    },
    thirdParty: [],
    implementationPlan: [
      "Week 1: Define which apps get shorter session lifetimes; create CA policy in Report-only",
      "Weeks 1–2: Gather user impact data; tune frequency value",
      "Week 2: Enable for privileged accounts first (strictest settings)",
      "Week 3: Enable for all users on the targeted sensitive apps",
    ],
  },

  // ── Entra ID Protection ───────────────────────────────────

  {
    id: "eid-protection",
    name: "Entra ID Protection (Anomalous Token Detection)",
    category: "Entra ID Protection",
    priority: "P1",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Requires P2 licensing and policy configuration. Initial alert volume can be high until tuned. Plan for a 2–4 week period of alert triage before enforcement.",
    cost: "upgrade",
    costLabel: "Requires Entra ID P2 / M365 E5",
    licenseNote: "Requires Entra ID P2 or M365 E5 / E5 Security. Anomalous Token detection specifically is a P2 feature.",
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 2,
    },
    why: {
      "session-token-theft":    "Anomalous Token is the highest-fidelity real-time signal for token theft — detecting tokens used from unusual locations, devices, or with anomalous claims.",
      "ms-teams-impersonation": "Detects anomalous sign-in patterns following a successful Teams phishing chain — unusual location, device, or token properties post-credential theft.",
    },
    overview: [
      "Entra ID Protection uses machine learning to analyze every sign-in across the Microsoft identity platform and generate risk signals when anomalies are detected. The 'Anomalous Token' risk event specifically detects when an access or refresh token is being used in ways that suggest it was stolen — such as being replayed from a different IP, country, or device than where it was originally issued.",
      "Entra ID Protection's value is that it combines detection AND enforcement. The risk detections it generates can directly drive Conditional Access policies — so a detected high-risk sign-in triggers an MFA challenge or block in real time, without requiring manual analyst intervention. This is the closest M365 comes to automated response to active token theft.",
    ],
    m365Config: {
      where: "Entra ID admin center → Security → Identity Protection (also requires Conditional Access policies to enforce)",
      license: "Entra ID P2 (M365 E5, M365 E5 Security, or Entra P2 standalone)",
      steps: [
        "Confirm Entra ID P2 licenses are assigned (or M365 E5 / E5 Security)",
        "Navigate to Entra ID → Security → Identity Protection → Risky sign-ins to review current detections",
        "Navigate to Risky users to review any accounts currently flagged",
        "Configure User Risk Policy: set High risk → require password change",
        "Configure Sign-in Risk Policy: set High risk → require MFA (or block)",
        "Set Medium risk → require MFA",
        "Alternatively, configure these via Conditional Access policies (recommended for more granular control)",
        "Connect to Microsoft Sentinel by enabling the Entra ID diagnostic settings to stream risk events",
        "Review and dismiss false positives weekly for the first month",
      ],
    },
    thirdParty: [
      { name: "Microsoft Sentinel", note: "Ingest AADUserRiskEvents and SigninLogs for advanced correlation and custom detection rules beyond what Identity Protection provides natively." },
      { name: "CrowdStrike Falcon Identity Protection", note: "Identity threat detection platform with AD and Entra ID integration; provides risk signals complementary to Entra ID Protection." },
      { name: "SentinelOne Singularity Identity", note: "Identity security platform with real-time Entra ID risk detection and deception capabilities." },
    ],
    implementationPlan: [
      "Week 1: Confirm P2 licensing; review current baseline of Identity Protection detections",
      "Week 1: Configure risk policies (User Risk + Sign-in Risk) in report/informational mode initially",
      "Weeks 2–3: Triage existing detections; dismiss false positives; note patterns",
      "Week 3: Enable User Risk Policy enforcement (password change on high risk)",
      "Week 4: Enable Sign-in Risk CA policies (high risk → block; medium → MFA)",
      "Ongoing: Weekly false positive triage; integrate with Sentinel for hunting",
    ],
  },

  // ── Microsoft Teams Hardening ─────────────────────────────

  {
    id: "restrict-external-teams",
    name: "Restrict External Teams Access (Allowlist Only)",
    category: "Microsoft Teams Hardening",
    priority: "P1",
    complexity: 1,
    complexityLabel: "Low",
    complexityNote: "A single setting change in the Teams Admin Center. The only planning required is identifying legitimate external partner domains before switching from 'allow all' to 'allowlist only'.",
    cost: "free",
    costLabel: "Free",
    licenseNote: "No additional licensing required. Available in all Microsoft 365 plans with Microsoft Teams.",
    coverage: {
      "session-token-theft":    0,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Not related to token theft attack chain.",
      "ms-teams-impersonation": "Single highest-impact control — prevents any external M365 tenant from cold-contacting your users. Eliminates the primary delivery vector for external Teams impersonation campaigns.",
    },
    overview: [
      "By default, Microsoft 365 tenants allow users from any other M365 tenant to send Teams messages to your users. An attacker needs only a free Microsoft 365 trial account to appear in someone's Teams chat as 'Microsoft Support' or 'IT Help Desk.' The '(External)' label is the only indicator — and most users don't treat it as a red flag.",
      "Switching from 'allow all external domains' to 'allowlist only' means only the specific organizations you explicitly trust can initiate Teams conversations with your users. This is a one-setting change with immediate effect. The planning work is identifying your legitimate external collaboration partners beforehand so their domains are in the allowlist when you make the change.",
    ],
    m365Config: {
      where: "Microsoft Teams Admin Center → Users → External access",
      license: "Free — available in all M365 plans",
      steps: [
        "Before making changes, survey department heads to identify external organizations your users legitimately collaborate with via Teams",
        "Sign in to Microsoft Teams Admin Center (admin.teams.microsoft.com)",
        "Navigate to Users → External access",
        "Under 'Teams and Skype for Business users in external organizations' → change to 'Allow only specific external domains'",
        "Add all identified legitimate partner domains to the allowlist",
        "For 'Teams accounts not managed by an organization' (consumer Teams) → set to Blocked unless needed",
        "Save changes (takes effect within ~30 minutes)",
        "Communicate to users that external Teams messages from unknown organizations will now be blocked",
        "Establish a process for users to request new external domain additions",
      ],
    },
    thirdParty: [],
    implementationPlan: [
      "Day 1: Survey department heads for external Teams collaboration partners (email/form)",
      "Day 2–3: Collect responses; compile allowlist of partner domains",
      "Day 3: Make the setting change in Teams Admin Center; add allowlisted domains",
      "Day 3: Communicate change to all users",
      "Ongoing: Quarterly review of the allowlist; add/remove domains as partnerships change",
    ],
  },

  {
    id: "safe-links-teams",
    name: "Safe Links for Microsoft Teams (MDO P1)",
    category: "Microsoft Teams Hardening",
    priority: "P1",
    complexity: 1,
    complexityLabel: "Low",
    complexityNote: "Enabling Safe Links for Teams is a policy configuration change that takes under an hour. Requires MDO P1 licensing, which is included in most business M365 plans.",
    cost: "included",
    costLabel: "Included (MDO P1)",
    licenseNote: "Requires Microsoft Defender for Office 365 Plan 1 — included in M365 Business Premium, E3, E5. Not included in M365 Business Basic/Standard or E1.",
    coverage: {
      "session-token-theft":    0,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Not related to token theft attack chain.",
      "ms-teams-impersonation": "Inspects and blocks malicious URLs sent in Teams messages before the victim can click them — addresses the link-based phishing delivery vector that email security gateways miss entirely.",
    },
    overview: [
      "Safe Links is Microsoft Defender for Office 365's URL inspection capability. By default it applies to email, but it can be extended to Microsoft Teams. When a user clicks a link in a Teams message, Safe Links rewrites the URL through Microsoft's inspection proxy, detonates it in a sandbox if needed, and blocks access if the destination is known malicious or suspicious.",
      "This control is particularly valuable for Teams because Teams messages completely bypass email security gateways (no DMARC, DKIM, SPF, no email filtering at all). A malicious link delivered in a Teams chat has zero email-layer inspection by default. Safe Links for Teams provides the equivalent of that email gateway protection directly in the Teams message flow.",
    ],
    m365Config: {
      where: "Microsoft Defender Portal → Email & Collaboration → Policies & rules → Threat Policies → Safe Links",
      license: "Microsoft Defender for Office 365 Plan 1 (M365 Business Premium, E3, E5)",
      steps: [
        "Confirm Microsoft Defender for Office 365 Plan 1 licensing is active for your tenant",
        "Navigate to Microsoft Defender Portal (security.microsoft.com)",
        "Go to Email & Collaboration → Policies & rules → Threat Policies → Safe Links",
        "Edit your existing Safe Links policy (or create a new one)",
        "Under 'Teams' settings → enable 'On: Safe Links checks a list of known, malicious links when users click links in Microsoft Teams'",
        "Set 'Do not track user clicks' to Off (ensure click telemetry is captured for hunting)",
        "Ensure the policy applies to all users (or your target group)",
        "Save and verify the policy shows as Active",
        "Test by sharing a known test URL (e.g., testphishing.com) in Teams and verifying the block page appears",
      ],
    },
    thirdParty: [
      { name: "Mimecast", note: "URL protection that extends to Teams via API integration. Suitable if you already use Mimecast for email." },
      { name: "Proofpoint", note: "URL Defense for Teams available as part of the Proofpoint collaboration security suite." },
    ],
    implementationPlan: [
      "Day 1: Verify MDO P1 licensing",
      "Day 1: Enable Safe Links for Teams in the Defender portal (30 minutes)",
      "Day 2: Test with a safe phishing test URL",
      "Ongoing: Review Safe Links click reports in the Defender portal monthly",
    ],
  },

  {
    id: "block-guest-files",
    name: "Block File Sharing from External/Guest Users in Teams",
    category: "Microsoft Teams Hardening",
    priority: "P2",
    complexity: 1,
    complexityLabel: "Low",
    complexityNote: "A setting change in the Teams Admin Center. Review legitimate guest collaboration use cases before disabling — communicate changes to any teams that actively work with external guests.",
    cost: "free",
    costLabel: "Free",
    licenseNote: "No additional licensing required. Available in all M365 plans with Teams.",
    coverage: {
      "session-token-theft":    0,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Not related to token theft attack chain.",
      "ms-teams-impersonation": "Closes the malware delivery vector used by Storm-0324 and similar actors who distribute malicious executables and scripts (.exe, .vbs, .lnk) via Teams file shares from external-tenant accounts.",
    },
    overview: [
      "Microsoft Teams allows guest and external users to share files in chats and channels by default. Storm-0324, documented in Microsoft's September 2023 threat intelligence report, industrialized this vector — creating hundreds of external M365 tenant accounts to deliver DarkGate and Qakbot malware via Teams file attachments at scale. The files bypass email security gateways entirely.",
      "Disabling file sharing from external and guest users eliminates this delivery method. Legitimate external collaboration can still happen via other means (SharePoint links shared via email, uploaded by internal users, etc.). The tradeoff is that guests can no longer directly drag-and-drop files into Teams chats — a convenience loss that most organizations will find acceptable given the risk.",
    ],
    m365Config: {
      where: "Microsoft Teams Admin Center → Users → Guest access + SharePoint Admin Center → Policies → Sharing",
      license: "Free — available in all M365 plans",
      steps: [
        "In Teams Admin Center → Users → Guest access",
        "Under 'Files' section → disable 'Share files'",
        "Also disable 'Send files' if present in your admin center version",
        "Navigate to SharePoint Admin Center → Policies → Sharing",
        "Review external sharing settings and align with your security posture (consider 'New and existing guests' or 'Only people in your organization')",
        "Communicate the change to any teams that actively collaborate with external guests via Teams file sharing",
        "Provide alternative: internal users can still share SharePoint links; only guest-initiated file uploads are blocked",
      ],
    },
    thirdParty: [],
    implementationPlan: [
      "Day 1: Survey teams that use guest file sharing; document use cases",
      "Day 2: Make setting change in Teams Admin Center",
      "Day 2: Communicate to affected teams with alternative workflows",
      "Ongoing: Monitor for business requests to restore; evaluate exceptions on a case-by-case basis",
    ],
  },

  {
    id: "remove-quickassist",
    name: "Remove / Restrict Microsoft QuickAssist",
    category: "Microsoft Teams Hardening",
    priority: "P1",
    complexity: 1,
    complexityLabel: "Low",
    complexityNote: "An Intune policy or Group Policy Object deployment. If QuickAssist is not a tool your IT helpdesk uses, this is a straightforward removal with minimal user impact.",
    cost: "free",
    costLabel: "Free",
    licenseNote: "Intune is required for managed deployment (included in M365 Business Premium, E3, E5). Can also be done via Group Policy with no licensing cost.",
    coverage: {
      "session-token-theft":    0,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Not related to token theft attack chain.",
      "ms-teams-impersonation": "Directly blocks a documented attack chain — Black Basta affiliates and Scattered Spider call victims via Teams impersonating IT helpdesk, then request a QuickAssist session to deploy persistent backdoors.",
    },
    overview: [
      "Microsoft QuickAssist is a built-in Windows tool that provides screen sharing and remote control for IT support purposes. It requires no administrative privileges to install or accept connections, making it trivially easy for a social engineer to get a victim to hand over control of their device. Unlike enterprise remote access tools, QuickAssist has minimal logging and no integration with security monitoring platforms.",
      "Black Basta ransomware affiliates specifically documented Microsoft QuickAssist abuse in their 2024 attack campaigns — initiating contact via Teams, impersonating IT helpdesk, and walking victims through accepting a QuickAssist session while live on a Teams call. If your IT helpdesk does not use QuickAssist as a legitimate tool (most enterprises use dedicated RMM tools instead), removing it eliminates this attack surface entirely.",
    ],
    m365Config: {
      where: "Intune admin center → Devices → Configuration profiles (or Group Policy Management Console)",
      license: "Intune for MDM deployment (M365 Business Premium, E3, E5); or Group Policy (free)",
      steps: [
        "Confirm with your IT helpdesk whether QuickAssist is used as a legitimate support tool",
        "If QuickAssist is not in use, proceed with removal",
        "Option A — Intune: Create a PowerShell script to remove the QuickAssist provisioned package: Get-AppxPackage -Name 'MicrosoftCorporationII.QuickAssist' | Remove-AppxPackage",
        "Option A — Intune: Deploy the script to all devices via Intune → Devices → Scripts and remediations",
        "Option B — GPO: Create a GPO to remove the QuickAssist app package and apply to all workstation OUs",
        "Option C — Defender: Create a Defender for Endpoint Application Control policy blocking QuickAssist.exe",
        "Communicate to employees that QuickAssist has been removed; provide the approved alternative remote support tool and how IT will contact them",
        "Train employees: 'IT will never initiate a QuickAssist session unsolicited via Teams'",
      ],
    },
    thirdParty: [],
    implementationPlan: [
      "Day 1: Confirm IT helpdesk doesn't use QuickAssist; document approved remote support tool",
      "Day 2: Create and test Intune or GPO removal script on pilot machines",
      "Day 3: Deploy to all managed endpoints",
      "Day 3: Communicate to all employees; update IT support documentation",
      "Ongoing: Add 'QuickAssist removal' to new device build checklist",
    ],
  },

  {
    id: "restrict-teams-apps",
    name: "Restrict App Permissions in Teams (Allowlist Apps)",
    category: "Microsoft Teams Hardening",
    priority: "P3",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Requires an inventory of currently installed apps, business impact assessment, and policy configuration. Communication to users is important since they may lose access to apps they use regularly.",
    cost: "free",
    costLabel: "Free (MDCA Optional)",
    licenseNote: "Teams app governance is free. Microsoft Defender for Cloud Apps App Governance add-on provides OAuth app visibility and is included in M365 E5 Security.",
    coverage: {
      "session-token-theft":    1,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Malicious OAuth apps consented via Teams can provide persistent token-based access that survives password resets.",
      "ms-teams-impersonation": "Prevents attackers from installing malicious Teams apps used as a foothold or data exfiltration channel.",
    },
    overview: [
      "Microsoft Teams allows users to install third-party and custom apps that can request OAuth consent to access M365 data. A malicious Teams app can be used to establish persistent access to a user's mailbox, files, and Teams data — independent of the user's session token — simply by getting the user to consent to its permissions. This is a form of OAuth app abuse.",
      "Restricting which apps can be installed to a curated allowlist (Microsoft apps + vetted third-party apps) significantly reduces the OAuth app attack surface. The Microsoft Defender for Cloud Apps App Governance add-on provides visibility into all OAuth apps consented in your tenant and can alert on apps with excessive permissions or suspicious consent patterns.",
    ],
    m365Config: {
      where: "Microsoft Teams Admin Center → Teams apps → Manage apps + App permission policies",
      license: "Free for basic Teams app governance; MDCA (M365 E5 Security) for App Governance add-on",
      steps: [
        "In Teams Admin Center → Teams apps → Manage apps: review all currently installed and available apps",
        "Export the app inventory; categorize apps as 'Microsoft,' 'vetted third-party,' or 'unknown/unreviewed'",
        "In App permission policies → create a custom policy allowing only Microsoft apps and your vetted list",
        "Assign this policy to all users as the default policy",
        "Communicate changes to users; provide a process to request new app approvals",
        "Optionally enable Microsoft Defender for Cloud Apps App Governance (MDCA → App governance) for OAuth visibility",
        "Set up App Governance alerts for apps requesting high-privilege permissions",
      ],
    },
    thirdParty: [
      { name: "Microsoft Defender for Cloud Apps (App Governance)", note: "Native Microsoft add-on providing full OAuth app inventory, risk scoring, and policy enforcement for apps consented in your M365 tenant." },
    ],
    implementationPlan: [
      "Week 1: Inventory all installed Teams apps; survey teams for which apps they rely on",
      "Week 1: Categorize apps; build the approved allowlist",
      "Week 2: Create permission policy; enable in test group first",
      "Week 2: Communicate coming changes to all users",
      "Week 3: Apply policy to all users",
      "Ongoing: Process app approval requests; review App Governance alerts monthly",
    ],
  },

  // ── Detection & Response ──────────────────────────────────

  {
    id: "inbox-rule-alerts",
    name: "Alert on Suspicious Inbox Rules (New-InboxRule)",
    category: "Detection & Response",
    priority: "P2",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Requires audit logging to be enabled and a SIEM or Defender alert rule to be created. Microsoft Sentinel has a built-in template that makes this straightforward. Tuning false positives takes 1–2 weeks.",
    cost: "included",
    costLabel: "Included (Sentinel or Defender)",
    licenseNote: "M365 Unified Audit Log is free. Microsoft Sentinel requires a Log Analytics workspace (pay-as-you-go or commitment tier). Defender for Office 365 Plan 2 has built-in alerts.",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 2,
    },
    why: {
      "session-token-theft":    "Creating forwarding/deletion inbox rules is the first post-compromise action after token theft. Alerting on this catches intrusions early before BEC fraud can occur.",
      "ms-teams-impersonation": "Same post-compromise action follows account takeover via Teams phishing — rapid detection dramatically limits the blast radius.",
    },
    overview: [
      "In virtually every documented M365 account compromise, one of the first actions an attacker takes is creating an inbox rule to hide evidence — forwarding copies of email to an external address, deleting security alert emails, or moving messages to an obscure folder. This activity is logged in the M365 Unified Audit Log as a 'New-InboxRule' or 'Set-InboxRule' operation.",
      "Alerting on inbox rules with suspicious parameters (DeleteMessage, ForwardTo, RedirectTo) is extremely high value — it catches post-compromise activity within minutes of it happening, long before the attacker completes their objective. Microsoft Sentinel ships with a built-in analytics rule template for this exact detection. Defender for Office 365 Plan 2 also includes a default alert for suspicious inbox manipulation.",
    ],
    m365Config: {
      where: "Microsoft Sentinel → Analytics → Rule templates / or Microsoft Defender Portal → Alerts",
      license: "Audit logging is free. Sentinel requires Log Analytics workspace; Defender for Office 365 P2 for built-in alerts.",
      steps: [
        "Verify M365 audit logging is enabled: Microsoft Purview Compliance Portal → Audit → verify 'Auditing is on'",
        "If using Microsoft Sentinel: Navigate to Sentinel → Analytics → Rule templates",
        "Search for 'Suspicious inbox manipulation rule' or 'Mail redirect via ExO transport rule'",
        "Enable the template analytics rule (configure severity as High, alert grouping as desired)",
        "Set up notification: connect to Logic App, email, or Teams for alert delivery",
        "Test: create a test inbox rule with 'ForwardTo' on a test account; verify the alert fires within 5 minutes",
        "Tune: review first 2 weeks of alerts; add exclusions for any IT-managed rules (e.g., auto-forward for shared mailboxes)",
        "Alternatively: in Defender Portal → investigate pre-built 'Suspicious inbox manipulation' alert policy",
      ],
    },
    thirdParty: [
      { name: "Microsoft Sentinel", note: "Recommended SIEM — built-in analytics rule templates for M365 inbox rule abuse require minimal configuration." },
      { name: "Splunk (Microsoft 365 Add-on)", note: "Ingest M365 Unified Audit Log into Splunk; build correlation rule on New-InboxRule with DeleteMessage/ForwardTo parameters." },
      { name: "Elastic SIEM", note: "M365 integration available via Filebeat or built-in integration. Detection rule available in Elastic's prebuilt rule set." },
    ],
    implementationPlan: [
      "Day 1: Verify M365 audit logging is enabled",
      "Day 1: Deploy Sentinel analytics rule (or Defender alert policy) for inbox rule abuse",
      "Day 2: Test with a canary inbox rule on a test account",
      "Weeks 1–2: Tune false positives from legitimate IT-managed rules",
      "Week 2: Integrate alert into incident response workflow and ticketing system",
    ],
  },

  {
    id: "mdca-policies",
    name: "Defender for Cloud Apps Activity Policies",
    category: "Detection & Response",
    priority: "P2",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Requires MDCA licensing, app connector setup, and policy configuration. Initial alert volume requires tuning. Most organizations can be operational within 1–2 weeks.",
    cost: "upgrade",
    costLabel: "Requires MDCA License / M365 E5",
    licenseNote: "Microsoft Defender for Cloud Apps is included in M365 E5, M365 E5 Security, and EMS E5. Also available as a standalone license (~$3.50/user/month).",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "MDCA detects mass download activity, impossible travel, and anomalous session patterns that indicate an active token theft intrusion in progress.",
      "ms-teams-impersonation": "Provides the richest Teams-specific telemetry available — detects external tenants messaging multiple users, suspicious guest file shares, and unusual Teams activity patterns not visible elsewhere.",
    },
    overview: [
      "Microsoft Defender for Cloud Apps (MDCA) is a Cloud Access Security Broker (CASB) that provides deep visibility into activity across Microsoft 365 and connected third-party SaaS applications. For M365 defenders, it offers something unavailable in native Entra ID or Exchange logs: behavioral analytics and rich activity policies at the application event level — including Teams-specific events like external messaging patterns, guest file shares, and mass download detection.",
      "MDCA's activity policies allow you to define threshold-based rules — such as 'alert when an external tenant sends Teams messages to more than 3 internal users in an hour' — that would be complex to build in a SIEM but are native policy templates in the MDCA console. It also provides App Governance for OAuth app oversight and can integrate with Microsoft Sentinel for centralized alerting.",
    ],
    m365Config: {
      where: "Microsoft Defender Portal → Cloud Apps → App connectors + Policies → Activity policies",
      license: "Microsoft Defender for Cloud Apps (M365 E5, E5 Security, EMS E5, or standalone)",
      steps: [
        "Confirm MDCA licensing is active in your tenant",
        "In Microsoft Defender Portal → Cloud Apps → App connectors → Connect Microsoft 365",
        "Follow the wizard to authorize MDCA to ingest M365 activity data",
        "Wait 24–48 hours for initial data population",
        "Navigate to Cloud Apps → Policies → Activity policies → Create policy",
        "Build policy: 'External Teams user sends messages to multiple internal users' (see Detection queries in Teams Impersonation attack profile)",
        "Build policy: 'Guest file upload with high-risk extension in Teams'",
        "Set alert severity (High) and notification method (email, Teams webhook)",
        "Review alerts for the first 2 weeks; tune thresholds to reduce false positives",
        "Connect MDCA alerts to Microsoft Sentinel via the MDCA data connector",
      ],
    },
    thirdParty: [
      { name: "Netskope", note: "Leading CASB alternative to MDCA with strong M365 integration and advanced behavioral analytics." },
      { name: "Palo Alto Prisma Access", note: "CASB + SASE platform with M365 integration. Strong for organizations with multi-cloud environments." },
      { name: "Zscaler Internet Access", note: "Cloud security platform with CASB capabilities for M365 including DLP and threat protection." },
    ],
    implementationPlan: [
      "Week 1: Confirm licensing; connect M365 to MDCA via App connectors",
      "Week 1: Wait for initial data population; review baseline activity",
      "Week 2: Create Teams-focused activity policies (external messaging volume, guest file shares)",
      "Week 2: Create anomalous download policies (mass download from SharePoint/OneDrive)",
      "Weeks 2–4: Tune alert thresholds based on your organization's normal activity patterns",
      "Week 4: Connect MDCA to Sentinel for centralized alerting",
      "Ongoing: Monthly policy review; add new policies as new attack patterns emerge",
    ],
  },

  // ── Human Layer ───────────────────────────────────────────

  {
    id: "awareness-training",
    name: "Security Awareness Training (Teams & MFA-Specific)",
    category: "Human Layer",
    priority: "P1",
    complexity: 2,
    complexityLabel: "Medium",
    complexityNote: "Requires selecting and configuring a training platform, creating/selecting content, running simulations, and tracking completion. M365 includes basic Attack Simulation Training with E5 or Defender for Office 365 P2.",
    cost: "included",
    costLabel: "Included (MDO P2) or Third-Party",
    licenseNote: "Microsoft Attack Simulation Training requires Defender for Office 365 Plan 2 (M365 E5, or Defender for Office 365 P2 add-on). Basic awareness training can be done with free content and no license.",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Users who recognize AiTM phishing patterns (identical-looking login pages, unexpected redirects, urgency cues) are less likely to complete credential submission.",
      "ms-teams-impersonation": "Primary defense against vishing and social engineering. Trained employees know: IT will never call via Teams to ask for MFA approval; urgency from an unknown sender is a red flag.",
    },
    overview: [
      "Security awareness training is frequently undervalued as a technical control — but for social engineering attacks like Teams impersonation and vishing, it is often the first and last line of defense. No technical control prevents an employee from willingly approving an MFA push or installing a remote access tool when an articulate, confident attacker on a Teams call says 'I'm from IT and this is urgent.' Training shapes the behavioral response to exactly these scenarios.",
      "Effective training for M365-specific threats needs to be specific: not generic phishing slides, but scenarios that reflect how Scattered Spider and Black Basta actually operate. 'You will receive a Teams message from someone claiming to be IT. The message will seem urgent. Here is exactly what to do.' Microsoft's Attack Simulation Training platform allows you to send simulated Teams and email phishing campaigns to measure and improve your organization's actual response rate.",
    ],
    m365Config: {
      where: "Microsoft Defender Portal → Email & Collaboration → Attack simulation training",
      license: "Microsoft Defender for Office 365 Plan 2 (M365 E5 or Defender for Office 365 P2 add-on)",
      steps: [
        "Confirm Defender for Office 365 P2 licensing (or select a third-party training platform)",
        "In Microsoft Defender Portal → Email & Collaboration → Attack simulation training",
        "Create a simulation campaign using a Teams-themed or credential phishing template",
        "Create a second simulation for MFA push manipulation awareness",
        "Assign a mandatory training module to all users: include Teams social engineering and MFA push bombing content",
        "Run initial simulation; measure click rate, credential submission rate, and report rate",
        "Assign targeted training to users who failed the simulation",
        "Schedule quarterly recurring simulations",
        "Track completion metrics; escalate non-completions to managers",
      ],
    },
    thirdParty: [
      { name: "KnowBe4", note: "Leading security awareness training platform. Extensive Teams and MFA-specific phishing simulation templates. Integrates with M365 for automated training assignment." },
      { name: "Proofpoint Security Awareness Training", note: "Sophisticated simulation platform with threat-intelligence-driven content. Strong for organizations already using Proofpoint email security." },
      { name: "Cofense", note: "Phishing simulation and response platform with strong focus on measurable behavior change." },
      { name: "Infosec IQ", note: "Full-featured awareness training platform with good M365 integration and a large content library." },
    ],
    implementationPlan: [
      "Week 1: Select training platform; confirm licensing or procurement",
      "Week 2: Configure platform; select or create Teams-specific and MFA-specific training modules",
      "Week 2: Launch first simulated phishing campaign (email or Teams-themed)",
      "Week 3: Review simulation results; assign remedial training to users who clicked or submitted credentials",
      "Week 4: Deploy mandatory awareness training to all users",
      "Month 2+: Track completion; run follow-up simulation to measure improvement",
      "Ongoing: Quarterly simulations; annual curriculum refresh to reflect current threat actor TTPs",
    ],
  },

];

// ── Derived helpers ────────────────────────────────────────

function totalScore(control) {
  return ATTACKS.reduce((sum, a) => sum + (control.coverage[a.id] || 0), 0);
}

const MAX_SCORE = ATTACKS.length * 3;

const SORTED_CONTROLS = [...CONTROLS].sort((a, b) => totalScore(b) - totalScore(a));
