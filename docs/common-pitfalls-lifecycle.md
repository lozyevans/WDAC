---
layout: default
title: Common Pitfalls & Lifecycle
nav_order: 1.7
---

# Common Pitfalls & Lifecycle Best Practices
{: .fs-8 }

WDAC deployments succeed or fail based on process and governance, not tooling. This page covers the most common pitfalls and the lifecycle practices that avoid them.
{: .fs-5 .fw-300 }

---

## Common Pitfalls

WDAC pitfalls typically arise when enforcement decisions are made without sufficient understanding of real-world execution behaviour, combined with policy designs that treat application control as a static configuration rather than a governed, evolving security capability.

### Hash Sprawl

Over-reliance on hash-based rules creates fragile policies that break with every application update. Each patch, hotfix, or minor version change produces new hashes, requiring constant policy updates.

{: .warning }
> Hash sprawl and rushed enforcement are the fastest ways to create operational resistance and undermine confidence in WDAC.

### No Baselining (Enforcing Without Audit Data)

Moving to enforced mode without sufficient audit data is the single most common cause of WDAC deployment failure. Without representative telemetry from real user behaviour, policies will inevitably block legitimate applications.

### Static Design

Treating WDAC as a one-time configuration exercise rather than a living, governed control. Applications change, platforms update, and new software is onboarded — policies must evolve with them.

### Hidden Dependencies

Applications frequently rely on updaters, plugins, helper processes, and child executables that are invisible until WDAC blocks them. These are often undocumented and only discovered during audit analysis.

{: .note }
> Discovering hidden dependencies is expected, not a failure. There are always more than you think. Some may be blocked intentionally by design through deny rules (e.g., User Mode CI deny rules blocking LOLBins invoked by applications).

### Platform Breakage

Blocking OS components or critical application dependencies due to insufficient testing. This is often caused by starting with an overly restrictive base policy or enforcing before audit data is fully analysed.

---

## The WDAC Lifecycle

Successful WDAC deployments treat policy management as a **continuous lifecycle** rather than a project with a completion date.

### 1. Baseline — Audit Mode First

Deploy policies in **Audit Mode** and collect execution telemetry from real user environments over a meaningful period. Lab or pilot data alone is not sufficient — audit data should represent actual user behaviour across time.

- Monitor **Event ID 3076** in Code Integrity logs
- Identify all executables, DLLs, scripts, and drivers that run in production
- Capture signing information for each binary

### 2. Design — Prefer Scalable Rule Types

Choose rule types that minimise ongoing maintenance:

| Approach | Maintenance | Recommendation |
|:---|:---|:---|
| **Publisher / FilePublisher rules** | Low — survives updates automatically | **Preferred for most applications** |
| **Managed Installer** | Low — inherits trust from deployment tooling | **Preferred for Intune-deployed apps** |
| **Hash rules** | High — breaks on every update | Use only for unsigned, static binaries |
| **Path rules** | Variable — risky if paths are user-writable | Use with caution |

### 3. Iterate — Supplemental Policies Per Application

Use **supplemental policies** for all application allow-listing rather than modifying the base policy. This provides:

- **Separation of concerns** — base trust is stable, application trust is iterative
- **Reduced blast radius** — a bad supplemental policy only affects one application
- **Easier auditing** — each policy maps to a specific business application
- **Independent lifecycle** — application policies can be updated without touching the core trust boundary

### 4. Roll Out — Phased Deployment

Deploy using a **phased or ringed rollout** model:

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Ring 0     │──▶│   Ring 1     │──▶│   Ring 2     │──▶│   Ring 3     │
│  IT / Pilot  │   │ Early Adopt  │   │  Majority    │   │  Remaining   │
│  (Audit)     │   │  (Audit)     │   │  (Enforce)   │   │  (Enforce)   │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
```

- Start with IT or pilot devices in audit mode
- Expand to early adopters, still in audit mode
- Promote to enforced mode only after no unexpected 3076 events are observed
- Roll enforcement progressively to wider device groups

### 5. Maintain — Continuous Governance

WDAC is not "deploy and forget":

- **New applications** require new supplemental policies before deployment
- **Application updates** may introduce new unsigned binaries or changed publishers
- **Deny lists** (driver and user mode) should be updated as Microsoft publishes new versions
- **Policy drift** should be monitored — ensure deployed policies match intended state
- **Event monitoring** should continue post-enforcement to catch unexpected blocks (Event ID 3077)

---

## Anti-Patterns to Avoid

| Do Not | Why |
|:---|:---|
| Modify the base policy for individual applications | Breaks separation of concerns and makes auditing impossible |
| Accumulate hash rules | Creates unmaintainable policies that break on every update |
| Enforce without audit validation | Guarantees user-impacting blocks and erodes confidence |
| Skip phased rollout | A single misconfigured policy can disrupt the entire estate |
| Treat WDAC as a one-time project | Applications and threats change — policies must evolve |

---

## Summary

> WDAC exposes gaps in application governance, and those gaps are often mistaken for platform issues. Deployments fail when enforcement is prioritised over understanding actual execution behaviour.
{: .highlight }

Operational success with WDAC depends more on **process and governance** than on tooling. Audit data, publisher-based rules, supplemental policy separation, and phased rollout are the foundations of a sustainable deployment.
