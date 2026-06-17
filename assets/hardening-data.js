/* ── M365 Hardening Control Data ────────────────────────────
   Shared across all hardening matrix layout demos.

   Coverage scale per attack:
     3 = Critical  — directly prevents or fully disrupts the attack
     2 = High      — significantly impairs the attack path
     1 = Partial   — reduces effectiveness or limits follow-on
     0 = None      — no meaningful protection against this attack

   To add a new attack: add to ATTACKS and add coverage scores
   for that attack id in every control's `coverage` object.
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
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 2,
    },
    why: {
      "session-token-theft":    "FIDO2 credentials are origin-bound — an AiTM proxy cannot capture or relay them. The only MFA type that prevents token theft at the authentication layer.",
      "ms-teams-impersonation": "If a victim clicks a phishing link from Teams, FIDO2 prevents compromise because the phishing domain won't match the registered origin.",
    },
  },
  {
    id: "number-matching",
    name: "Number Matching & Additional Context for MFA Push",
    category: "Identity & Authentication",
    priority: "P2",
    coverage: {
      "session-token-theft":    1,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Reduces push bombing in related campaigns. Doesn't stop token theft once a session exists, but limits MFA fatigue abuse.",
      "ms-teams-impersonation": "Directly stops MFA push bombing — victims must enter a matching code. Also shows the requesting app and location, making social engineering obvious.",
    },
  },
  {
    id: "restrict-mfa-reg",
    name: "Restrict MFA Method Registration (Require Compliant Device)",
    category: "Identity & Authentication",
    priority: "P2",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Prevents attackers who steal a token from registering new authenticators to survive a password reset.",
      "ms-teams-impersonation": "Limits persistence after account takeover via Teams-based phishing.",
    },
  },
  {
    id: "block-legacy-auth",
    name: "Block Legacy Authentication Protocols",
    category: "Identity & Authentication",
    priority: "P3",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 0,
    },
    why: {
      "session-token-theft":    "Legacy protocols (IMAP, SMTP AUTH) bypass Conditional Access and MFA, enabling credential access that supplements token theft campaigns.",
      "ms-teams-impersonation": "Not directly relevant to Teams-based attack chains.",
    },
  },

  // ── Conditional Access ────────────────────────────────────
  {
    id: "token-protection",
    name: "Conditional Access Token Protection (Token Binding)",
    category: "Conditional Access",
    priority: "P1",
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Directly stops token replay — binds access tokens to the originating device so a stolen token fails when replayed from an attacker's machine.",
      "ms-teams-impersonation": "Provides post-compromise protection if account takeover occurs following a Teams phishing attack.",
    },
  },
  {
    id: "cae",
    name: "Continuous Access Evaluation (CAE)",
    category: "Conditional Access",
    priority: "P1",
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Revokes stolen tokens in near-real-time on password reset or policy violation — dramatically reducing the window a stolen token is useful.",
      "ms-teams-impersonation": "Limits the time window after gaining access via a Teams phishing chain.",
    },
  },
  {
    id: "signin-risk-ca",
    name: "Sign-in Risk Conditional Access Policies",
    category: "Conditional Access",
    priority: "P1",
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 2,
    },
    why: {
      "session-token-theft":    "Blocks or requires step-up when Entra ID Protection detects Anomalous Token, Impossible Travel, or High risk — the primary enforcement layer for detected token theft.",
      "ms-teams-impersonation": "Catches and blocks high-risk sign-ins that follow a successful Teams phishing chain.",
    },
  },
  {
    id: "compliant-device",
    name: "Require Compliant / Hybrid-Joined Device for Sensitive Apps",
    category: "Conditional Access",
    priority: "P3",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Makes token replay from unmanaged attacker devices fail — stolen tokens can't authenticate to apps requiring device compliance.",
      "ms-teams-impersonation": "Limits post-compromise lateral movement by requiring managed devices for sensitive apps.",
    },
  },
  {
    id: "token-lifetime",
    name: "Reduce Token Lifetimes / Enforce Sign-in Frequency",
    category: "Conditional Access",
    priority: "P2",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 0,
    },
    why: {
      "session-token-theft":    "Shorter token lifetimes reduce the window a stolen token is useful. Disabling persistent browser sessions also limits cookie theft viability.",
      "ms-teams-impersonation": "Not directly relevant to Teams-based initial access chains.",
    },
  },

  // ── Entra ID Protection ───────────────────────────────────
  {
    id: "eid-protection",
    name: "Entra ID Protection (Anomalous Token Detection)",
    category: "Entra ID Protection",
    priority: "P1",
    coverage: {
      "session-token-theft":    3,
      "ms-teams-impersonation": 2,
    },
    why: {
      "session-token-theft":    "The Anomalous Token risk event is the highest-fidelity real-time signal for token theft. Requires P2 but provides detection unavailable elsewhere.",
      "ms-teams-impersonation": "Detects anomalous sign-in patterns that follow a successful Teams phishing chain — unusual location, device, or token properties.",
    },
  },

  // ── Microsoft Teams Hardening ─────────────────────────────
  {
    id: "restrict-external-teams",
    name: "Restrict External Teams Access (Allowlist Only)",
    category: "Microsoft Teams Hardening",
    priority: "P1",
    coverage: {
      "session-token-theft":    0,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Not related to token theft attack chain.",
      "ms-teams-impersonation": "Single highest-impact control: prevents any external M365 tenant from cold-contacting your users. Eliminates the primary delivery vector for external Teams impersonation.",
    },
  },
  {
    id: "safe-links-teams",
    name: "Safe Links for Microsoft Teams (MDO P1)",
    category: "Microsoft Teams Hardening",
    priority: "P1",
    coverage: {
      "session-token-theft":    0,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Not related to token theft attack chain.",
      "ms-teams-impersonation": "Inspects and blocks malicious URLs sent in Teams messages before the victim can click them. Bypasses the gap in email gateway coverage.",
    },
  },
  {
    id: "block-guest-files",
    name: "Block File Sharing from External/Guest Users in Teams",
    category: "Microsoft Teams Hardening",
    priority: "P2",
    coverage: {
      "session-token-theft":    0,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Not related to token theft attack chain.",
      "ms-teams-impersonation": "Closes the malware delivery vector used by Storm-0324 and similar actors who distribute malicious files via Teams file shares.",
    },
  },
  {
    id: "remove-quickassist",
    name: "Remove / Restrict Microsoft QuickAssist",
    category: "Microsoft Teams Hardening",
    priority: "P1",
    coverage: {
      "session-token-theft":    0,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Not related to token theft attack chain.",
      "ms-teams-impersonation": "Directly blocks a documented attack chain — Black Basta and Scattered Spider use QuickAssist during Teams vishing calls to gain remote device access.",
    },
  },
  {
    id: "restrict-teams-apps",
    name: "Restrict App Permissions in Teams (Allowlist Apps)",
    category: "Microsoft Teams Hardening",
    priority: "P3",
    coverage: {
      "session-token-theft":    1,
      "ms-teams-impersonation": 1,
    },
    why: {
      "session-token-theft":    "Malicious OAuth apps consented via Teams can provide persistent token-based access that survives password resets.",
      "ms-teams-impersonation": "Prevents attackers from installing malicious Teams apps as a foothold or exfiltration channel.",
    },
  },

  // ── Detection & Response ──────────────────────────────────
  {
    id: "inbox-rule-alerts",
    name: "Alert on Suspicious Inbox Rules (New-InboxRule)",
    category: "Detection & Response",
    priority: "P2",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 2,
    },
    why: {
      "session-token-theft":    "Creating forwarding/deletion inbox rules is the first post-compromise action after token theft. Early alerting limits damage before BEC fraud occurs.",
      "ms-teams-impersonation": "Also the first post-compromise action after account takeover via Teams phishing — rapid detection limits blast radius.",
    },
  },
  {
    id: "mdca-policies",
    name: "Defender for Cloud Apps Activity Policies",
    category: "Detection & Response",
    priority: "P2",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "MDCA detects mass download activity, impossible travel, and anomalous session patterns indicating active token theft intrusion.",
      "ms-teams-impersonation": "Richest Teams-specific telemetry — detects external tenants messaging multiple users, guest file shares, and unusual Teams activity patterns.",
    },
  },

  // ── Human Layer ───────────────────────────────────────────
  {
    id: "awareness-training",
    name: "Security Awareness Training (Teams & MFA-Specific)",
    category: "Human Layer",
    priority: "P1",
    coverage: {
      "session-token-theft":    2,
      "ms-teams-impersonation": 3,
    },
    why: {
      "session-token-theft":    "Users who recognize AiTM phishing patterns are less likely to complete the credential submission that enables token theft.",
      "ms-teams-impersonation": "Primary defense against vishing and social engineering. Train employees: IT never calls via Teams to ask for MFA approval; urgency is a red flag.",
    },
  },
];

// ── Derived helpers (used by all layouts) ─────────────────

function totalScore(control) {
  return ATTACKS.reduce((sum, a) => sum + (control.coverage[a.id] || 0), 0);
}

const MAX_SCORE = ATTACKS.length * 3;

const SORTED_CONTROLS = [...CONTROLS].sort((a, b) => totalScore(b) - totalScore(a));
