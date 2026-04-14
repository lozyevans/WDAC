---
layout: default
title: Home
nav_order: 1
---

# WDAC Troubleshooting Guide
{: .fs-9 }

A step-by-step guide to managing and troubleshooting Windows Defender Application Control (WDAC) policies using AppControl Manager and Microsoft Intune.
{: .fs-6 .fw-300 }

---

## Overview

For a comprehensive introduction to WDAC — how it works, policy types, rule levels, event IDs, and deployment — see the **[WDAC Overview]({% link wdac-overview.md %})** page.

For deeper background, see:

- **[WDAC vs AV & EDR]({% link wdac-vs-av-edr.md %})** — How WDAC complements antivirus and endpoint detection
- **[Trust Models Deep Dive]({% link trust-models.md %})** — Managed Installer, ISG, self-signing, and choosing the right model
- **[Common Pitfalls & Lifecycle]({% link common-pitfalls-lifecycle.md %})** — Avoiding hash sprawl, phased rollout, and continuous governance

A commonly recommended way to use Windows Defender Application Control (WDAC) in an enterprise environment is to adopt a **default-deny, explicit allow-list model**, where only known and trusted code is permitted to run, and everything else is blocked by default.

In practice, this starts with a well-scoped **base policy** (for example, "Default Windows" or "Allow Microsoft") that defines the core trust boundary, and then uses **supplemental policies** to add explicit allow rules for individual line-of-business applications as they are validated, rather than expanding the base policy over time.

This keeps the core policy stable and easier to audit while allowing controlled growth of the application set.

Alongside this, Microsoft recommends using **explicit deny policies**, particularly for high-risk areas such as kernel drivers and user-mode tooling, to block known vulnerable, abused, or unwanted components even if they are otherwise signed or would be implicitly allowed by another policy.

### Policy Architecture

| Policy Type | Purpose |
|:---|:---|
| **Base Allow Policy** | Defines the core trust boundary (e.g., "Allow Microsoft") |
| **Supplemental Policies** | Adds allow rules for specific LOB applications (each linked to exactly one base policy via its Base Policy ID) |
| **Deny Driver Policy** | Blocks known vulnerable or abused kernel drivers |
| **Deny User Mode Policy** | Blocks known vulnerable or abused user-mode binaries |

{: .important }
> Deny policies always take precedence over allow policies. If a binary is allowed by a supplemental policy but blocked by a deny policy, the deny will win.

---

## Guides

| Guide | Description |
|:---|:---|
| [Change Policy Settings]({% link change-policy-settings.md %}) | Switch a WDAC policy between Enforced and Audit modes |
| [Create a Supplemental Policy]({% link create-supplemental-policy.md %}) | Generate a new supplemental allow policy for an application |
| [Update a Supplemental Policy from Event Logs]({% link update-supplemental-from-logs.md %}) | Add missing rules to an existing supplemental policy |
| [Update Policy Name & Details]({% link update-policy-name.md %}) | Edit the Friendly Name, version, and description of a policy |
| [Validate Policies on a Device]({% link validate-policy.md %}) | Confirm policies have applied correctly using CITool |
| [Troubleshoot Stuck Policies]({% link troubleshoot-stuck-policies.md %}) | Resolve policies that fail to update via Intune |
| [Troubleshoot Deny Policy Blocks]({% link troubleshoot-deny-policies.md %}) | Identify and resolve blocks caused by deny policies |

---

## Prerequisites

- **AppControl Manager** — Download from the [Microsoft Store](https://apps.microsoft.com/detail/9png1mfhwkr2) or [GitHub](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager). Requires elevation (Run as Administrator).
- **WDAC base policies in XML format** — Downloaded from your organisation's policy repository or Intune.
- **Microsoft Intune access** — For deploying policies to devices.
- **Elevated PowerShell** — Required for `citool.exe` commands.

## Tools Reference

| Tool | Purpose |
|:---|:---|
| `citool.exe --list-policies` | List all WDAC policies on the device |
| `citool.exe --remove-policy <ID>` | Remove a specific WDAC policy by its Policy ID |
| Event Viewer → Code Integrity → Operational | View WDAC audit (3076) and block (3077) events |
| AppControl Manager | GUI tool for creating, editing, and validating WDAC policies |

---

## Policy Naming Convention

Use a consistent naming convention for all WDAC policies. The Friendly Name is displayed by `citool.exe --list-policies` and is the primary way to identify policies on a device.

**Recommended format:**

```
<Org>-<Platform>-<OS>-WDAC-<Type>-<Action>-<AppName>-<Date>
```

| Segment | Description | Example Values |
|:---|:---|:---|
| `<Org>` | Organisation / business unit | `EUD`, `CORP`, `SEC` |
| `<Platform>` | Device platform or config profile | `CPC`, `PHY`, `VDI` |
| `<OS>` | Operating system context | `Windows` |
| `WDAC` | Fixed identifier | `WDAC` |
| `<Type>` | Policy type | `Base`, `Supplemental`, `DenyDriver`, `DenyUser` |
| `<Action>` | Allow or Deny | `Allow`, `Deny` |
| `<AppName>` | Application name (supplemental only) | `Chrome`, `Citrix`, `SAP` |
| `<Date>` | Date of last update (YYYY-MM-DD) | `2026-04-13` |

**Examples:**

- `EUD-CPC-Windows-WDAC-Base-Allow-2026-04-13`
- `EUD-CPC-Windows-WDAC-Supplemental-Allow-Chrome-2026-04-13`
- `EUD-CPC-Windows-WDAC-DenyUser-Block-2026-04-13`
