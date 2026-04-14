---
layout: default
title: WDAC Overview
nav_order: 1.5
---

# Windows Defender Application Control (WDAC) Overview
{: .fs-8 }

A comprehensive overview of what WDAC is, how it works, and how it fits into an enterprise endpoint security strategy.
{: .fs-5 .fw-300 }

---

## What is WDAC?

**Windows Defender Application Control (WDAC)** is a security feature built into Windows 10 and Windows 11 that controls which applications and drivers are allowed to run on a device. It operates on a **default-deny model** — only explicitly trusted code is permitted to execute, and everything else is blocked.

WDAC is part of Microsoft's **App Control for Business** (formerly known as Windows Defender Application Control) and is a core component of a **zero-trust endpoint strategy**.

{: .note }
> WDAC replaces and supersedes the older **Software Restriction Policies (SRP)** and **AppLocker** features. Microsoft recommends WDAC as the primary application control solution for Windows.

---

## Why Use WDAC?

| Challenge | How WDAC Helps |
|:---|:---|
| **Ransomware & malware execution** | Only trusted binaries can run — unknown malware is blocked by default |
| **Living Off the Land (LOTL) attacks** | Deny policies block abuse of built-in tools like `mshta.exe`, `certutil.exe`, etc. |
| **Unsigned or untrusted software** | Only signed, approved applications pass the policy checks |
| **Vulnerable drivers** | Deny driver policies block known exploitable kernel drivers |
| **Shadow IT** | Users cannot install or run unapproved software |
| **Compliance requirements** | Provides auditable, policy-driven application control |

---

## How WDAC Works

WDAC policies are evaluated by the **Windows kernel** at load time. When an application, DLL, script, or driver attempts to execute, Windows checks it against the active WDAC policies before allowing it to run.

```
┌──────────────────────────────────────────────────┐
│                 Application Launches              │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│          Is it blocked by a Deny Policy?          │
│       (Deny Driver / Deny User Mode Block)        │
└───────┬──────────────────────────────┬───────────┘
        │ YES                          │ NO
        ▼                              ▼
┌───────────────┐    ┌─────────────────────────────┐
│   BLOCKED     │    │  Is it allowed by a Base or  │
│  (Event 3077) │    │     Supplemental Policy?      │
└───────────────┘    └───────┬─────────────┬───────┘
                             │ YES         │ NO
                             ▼             ▼
                   ┌──────────────┐ ┌──────────────┐
                   │   ALLOWED    │ │   BLOCKED    │
                   │              │ │  (Event 3077)│
                   └──────────────┘ └──────────────┘
```

{: .important }
> **Deny always wins.** If a binary matches both an allow rule and a deny rule, the deny rule takes precedence.

---

## Policy Types Explained

### Base Policies

A **base policy** defines the core trust boundary for a device. It determines the fundamental set of applications and publishers that are trusted. Common starting points include:

- **Allow Microsoft** — Trusts all Microsoft-signed binaries
- **Default Windows** — Trusts only the binaries that ship with Windows
- **Allow Store Apps** — Additionally trusts applications from the Microsoft Store

Every device must have at least one base policy. Base policies can be deployed in **Audit Mode** (logs but doesn't block) or **Enforced Mode** (actively blocks untrusted code).

### Supplemental Policies

**Supplemental policies** extend a base policy by adding allow rules for specific applications. Each supplemental policy is linked to exactly one base policy via its **Base Policy ID**.

Use supplemental policies to:
- Allow line-of-business (LOB) applications
- Permit third-party software (e.g., Chrome, Citrix, SAP)
- Add rules discovered from Code Integrity event logs

{: .note }
> Supplemental policies can only **add** allow rules — they cannot add deny rules or override deny policies.

### Deny Policies

**Deny policies** explicitly block specific binaries, even if they would otherwise be allowed by a base or supplemental policy. Microsoft provides two recommended block lists:

| Deny Policy | What It Blocks |
|:---|:---|
| **Microsoft Recommended Driver Block List** | Known vulnerable kernel drivers that could be exploited for privilege escalation |
| **Microsoft Recommended User Mode Block List** | Known abusable user-mode binaries (LOLBINs) such as `mshta.exe`, `certutil.exe`, `InstallUtil.exe` |

These lists are maintained by Microsoft and updated regularly. See [Microsoft Recommended Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol) for the latest versions.

---

## Audit Mode vs Enforced Mode

| | Audit Mode | Enforced Mode |
|:---|:---|:---|
| **Behaviour** | Logs violations but allows execution | Blocks violations and logs them |
| **Event ID** | 3076 (Information) | 3077 (Error) |
| **Use case** | Testing new policies, capturing required rules | Production enforcement |
| **Risk** | No security enforcement — all code runs | Misconfigured policies can break applications |

**Recommended workflow:**

1. Deploy policies in **Audit Mode** first
2. Monitor **Event ID 3076** in Code Integrity logs to identify what would be blocked
3. Create supplemental policies to allow legitimate applications
4. Once no unexpected 3076 events are seen, switch to **Enforced Mode**
5. Continue monitoring **Event ID 3077** for any blocks in production

---

## Policy Evaluation Order

When multiple policies are present on a device, WDAC evaluates them in the following order:

1. **Deny policies are evaluated first** — if any deny policy matches, the binary is blocked regardless of allow rules
2. **Base policies are evaluated next** — the binary must be allowed by at least one active base policy
3. **Supplemental policies extend scope** — supplemental allow rules are applied to their associated base policy

```
┌────────────────────────────┐
│     Deny Driver Policy     │──── Block if matched
├────────────────────────────┤
│  Deny User Mode Policy     │──── Block if matched
├────────────────────────────┤
│      Base Allow Policy     │──── Allow if matched
│  ┌──────────────────────┐  │
│  │  Supplemental: Chrome │  │──── Extends base allow
│  ├──────────────────────┤  │
│  │  Supplemental: Citrix │  │──── Extends base allow
│  └──────────────────────┘  │
└────────────────────────────┘
```

---

## Rule Levels (How Files Are Identified)

WDAC policies identify trusted files using different **rule levels**, which vary in specificity and maintenance overhead:

| Rule Level | What It Matches | Best For |
|:---|:---|:---|
| **Hash** | Exact file hash | Unsigned files; maximum specificity |
| **FileName** | Internal file name attribute | Files that keep the same name across versions |
| **FilePublisher** | Publisher + file name + minimum version | Most LOB apps — allows updates automatically |
| **Publisher** | Certificate publisher only | When you trust everything from a publisher |
| **WHQLFilePublisher** | WHQL-certified publisher + file + version | Kernel drivers |
| **PCACertificate** | Intermediate certificate authority | Broad trust across a CA's signed binaries |

{: .note-title }
> Recommendation
>
> Use **FilePublisher** for most applications. It provides a good balance between security (specific to the file and publisher) and maintenance (automatically allows updates from the same publisher for the same file).

---

## Key Event IDs

| Event ID | Source | Meaning |
|:---|:---|:---|
| **3076** | Code Integrity | Audit event — binary *would have been* blocked |
| **3077** | Code Integrity | Enforcement event — binary *was blocked* |
| **3089** | Code Integrity | Signing information for the audited/blocked file (publisher, hash) |
| **3099** | Code Integrity | Policy load/refresh events |

Event logs are located at:

```
Event Viewer → Application and Services Logs → Microsoft → Windows → Code Integrity → Operational
```

---

## Deployment via Microsoft Intune

WDAC policies are deployed to managed devices through **Microsoft Intune** using the **App Control for Business** profile:

1. **Author** the policy using AppControl Manager (XML format)
2. **Upload** the XML policy to Intune via **Endpoint Security → App Control for Business**
3. **Assign** the policy to device groups
4. Devices receive the policy on next **Intune sync** and apply it after **reboot**

{: .important }
> When updating a policy, the **version number** in the XML must be higher than the currently deployed version. If it is the same or lower, Intune will report an error and the device will reject the update.

---

## Common Terminology

| Term | Definition |
|:---|:---|
| **WDAC** | Windows Defender Application Control |
| **App Control for Business** | Microsoft's current branding for WDAC |
| **CIPolicy** | Code Integrity Policy — the technical name for a WDAC policy |
| **CITool** | `citool.exe` — built-in command-line tool for managing WDAC policies on a device |
| **LOLBIN** | Living Off the Land Binary — a legitimate system tool commonly abused by attackers |
| **Supplemental Policy** | An add-on policy that extends a base policy with additional allow rules |
| **Base Policy** | The foundational policy that defines the core trust boundary |
| **Friendly Name** | The human-readable policy name shown by `citool.exe --list-policies` |

---

## Next Steps

For deeper background on specific topics:

- [WDAC vs AV & EDR](wdac-vs-av-edr.md) — How WDAC complements antivirus and endpoint detection
- [Trust Models Deep Dive](trust-models.md) — Managed Installer, ISG, self-signing, and choosing the right model
- [Common Pitfalls & Lifecycle](common-pitfalls-lifecycle.md) — Avoiding hash sprawl, phased rollout, and continuous governance

Ready to start managing WDAC policies? See the operational guides:

- [Change Policy Settings](change-policy-settings.md) — Switch between Enforced and Audit mode
- [Create a Supplemental Policy](create-supplemental-policy.md) — Allow a new application
- [Troubleshoot Deny Policy Blocks](troubleshoot-deny-policies.md) — Debug blocks from deny policies
