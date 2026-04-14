---
layout: default
title: Trust Models Deep Dive
nav_order: 1.8
---

# Trust Models Deep Dive
{: .fs-8 }

WDAC supports multiple trust models beyond basic publisher and hash rules. Understanding when to use each model is critical for balancing security, scalability, and operational overhead.
{: .fs-5 .fw-300 }

---

## Trust Model Overview

| Trust Model | How Trust Is Established | Best For |
|:---|:---|:---|
| **Publisher Rules** | Certificate-based — trusts a signed vendor | Most LOB apps with good signing practices |
| **Hash Rules** | Exact binary match | Unsigned or static binaries only |
| **Path Rules** | File location on disk | Limited use — high risk if path is writable |
| **Managed Installer** | Inherited from approved deployment tooling | Intune-deployed applications at scale |
| **Intelligent Security Graph (ISG)** | Microsoft cloud reputation | Dynamic trust for known-good binaries |
| **Self-Signing** | Enterprise PKI certificate | Full control, but high operational overhead |

---

## Publisher Rules

Publisher rules trust code based on the **signing certificate** of the software vendor. They are the preferred rule type for most applications because they:

- **Survive application updates** — new versions signed by the same publisher are automatically trusted
- **Reduce policy churn** — no need to update rules for every patch or minor release
- **Provide accountability** — trust is tied to a specific, verifiable identity

WDAC offers several levels of publisher-based trust:

| Rule Level | What It Matches | Specificity |
|:---|:---|:---|
| **Publisher** | Certificate publisher only | Broad — trusts everything from that publisher |
| **FilePublisher** | Publisher + file name + minimum version | **Recommended** — specific to the file, allows updates |
| **WHQLFilePublisher** | WHQL-certified publisher + file + version | For kernel drivers |

{: .note-title }
> Recommendation
>
> Use **FilePublisher** as the default for most applications. It provides a good balance between security (specific to the file and publisher) and maintenance (automatically allows updates from the same publisher for the same file).

{: .warning }
> Not all vendors follow good signing practices. Some applications ship with unsigned components, inconsistent publishers, or certificates that change between versions. Always validate signing behaviour during the audit phase.

---

## Hash Rules

Hash rules trust a **specific binary** by its exact cryptographic hash. They provide maximum specificity but are the most operationally expensive rule type.

**When to use:**
- The binary is **unsigned** and cannot be trusted via publisher rules
- The binary is **static** and rarely changes (e.g., a legacy internal tool)
- You need a temporary allow rule while investigating a proper publisher-based solution

**When to avoid:**
- The application updates frequently — every update changes the hash and breaks the rule
- You are managing many applications — hash-based policies become unmanageable at scale

{: .warning }
> Over-use of hash rules is the primary cause of **hash sprawl** — fragile, bloated policies that require constant updates and are a leading cause of WDAC deployment fatigue.

---

## Path Rules

Path rules trust any code that runs from a **specific file system location**. They are the simplest rule type but carry significant security risk.

**When they might be acceptable:**
- The path is in a **protected, administrator-only location** (e.g., `C:\Program Files\`)
- Combined with other controls that prevent users from writing to that path

**When to avoid:**
- The path is **user-writable** (e.g., `C:\Users\`, `%TEMP%`, `%APPDATA%`)
- The path can be **indirectly controlled** by users via symlinks, junctions, or application behaviour

{: .important }
> Path rules are the most dangerous rule type if misused. An attacker who can place a binary in a trusted path bypasses WDAC entirely. Use with extreme caution and only for protected locations.

---

## Managed Installer

Managed Installer is a trust model that allows WDAC to **inherit trust from an approved software deployment mechanism**. When enabled, any application deployed through a designated managed installer (such as Microsoft Intune) is automatically trusted without needing explicit publisher or hash rules.

### How It Works

1. A management tool (e.g., Intune) is registered as a **Managed Installer** in the WDAC policy
2. When the installer deploys an application, Windows tags the installed files with a trust attribute
3. WDAC recognises the trust attribute and allows execution without requiring a specific rule for each binary

### Benefits

- **Scales with your deployment pipeline** — new applications deployed via Intune are automatically trusted
- **Reduces policy maintenance** — no need to create supplemental policies for every Intune-deployed app
- **Works regardless of signing** — even unsigned applications are trusted if deployed through the managed installer

### Considerations

- Trust is **only established at install time** — if files are modified after deployment, the trust attribute may not apply
- Requires the deployment tool to be properly registered as a managed installer
- Provides **broad trust** — any application deployed through the installer is trusted, so your deployment pipeline becomes a trust boundary

{: .note }
> Managed Installer is a key enabler for enterprise-scale WDAC. It allows trust to be inherited from approved deployment mechanisms rather than defined binary-by-binary.

---

## Intelligent Security Graph (ISG)

The Intelligent Security Graph allows WDAC to dynamically permit binaries that Microsoft classifies as **known-good** using cloud-based reputation intelligence.

### How It Works

When ISG is enabled in a WDAC policy:

1. WDAC checks the ISG **only for binaries not explicitly allowed or denied by policy**
2. If the binary has a **"known good" reputation** → execution is allowed
3. If the binary is **unknown or known bad** → execution is blocked

### Benefits

- Provides a **safety net** for applications that are well-known but not yet covered by explicit policy rules
- Reduces the initial policy gap during early WDAC deployment
- Leverages Microsoft's cloud-scale threat intelligence

### Considerations

- ISG requires **internet connectivity** to query Microsoft's reputation service
- Reputation can change — a binary classified as "known good" today may not be tomorrow
- ISG is a **fallback**, not a primary trust model — explicit policy rules always take precedence
- Provides less **deterministic control** than publisher or hash rules

---

## Self-Signing (Enterprise PKI)

Organisations can choose to **self-sign applications** using their own enterprise-controlled Public Key Infrastructure (PKI). This provides full execution control by tying trust to internally managed certificates.

### How It Works

1. The organisation signs applications (or wraps them) with an **enterprise code-signing certificate**
2. A WDAC publisher rule trusts the enterprise certificate
3. Only applications signed with that certificate — or other explicitly trusted publishers — are allowed to run

### Benefits

- **Full control** over what is trusted — no dependency on third-party vendor signing
- Works for **internal tools**, custom scripts, and unsigned third-party applications
- Enables a **self-contained trust model** that does not rely on external reputation services

### Considerations

- Introduces **significant operational overhead**: certificate lifecycle management, signing infrastructure, and signing governance
- If the signing certificate is compromised, all code signed with it becomes a risk
- Requires **strong certificate protection** — HSMs, restricted access, audit trails
- Every application must be signed (or re-signed) before deployment

{: .warning }
> Self-signing provides full flexibility and control but requires mature PKI governance. Weak certificate protection, poor lifecycle management, or lax signing governance can undermine the entire trust model.

---

## Choosing the Right Model

Most enterprise deployments use a **combination** of trust models rather than relying on a single approach:

```
┌──────────────────────────────────────────────────────────┐
│                  Typical Enterprise Mix                   │
├──────────────────────────────────────────────────────────┤
│  FilePublisher rules     → Major LOB apps (SAP, Citrix) │
│  Managed Installer       → Intune-deployed apps          │
│  Hash rules              → Unsigned legacy tools (few)   │
│  ISG                     → Safety net during rollout     │
│  Deny rules              → LOLBins, vulnerable drivers   │
└──────────────────────────────────────────────────────────┘
```

| Scenario | Recommended Model |
|:---|:---|
| Well-signed LOB application | FilePublisher |
| Intune-deployed application at scale | Managed Installer |
| Unsigned internal script or legacy tool | Hash (with plan to sign or replace) |
| Early deployment phase, broad coverage needed | ISG as fallback |
| Custom internal tooling, full control required | Self-Signing (if PKI is mature) |
| Known-dangerous binaries (LOLBins, vulnerable drivers) | Explicit Deny rules |
