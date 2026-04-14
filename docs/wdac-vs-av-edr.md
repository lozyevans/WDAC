---
layout: default
title: WDAC vs AV & EDR
nav_order: 1.6
---

# WDAC vs Antivirus & EDR
{: .fs-8 }

Understanding how WDAC complements — rather than replaces — antivirus and endpoint detection and response.
{: .fs-5 .fw-300 }

---

## Different Questions, Different Layers

WDAC and AV/EDR solve fundamentally different problems at different stages of the attack lifecycle:

| | WDAC | AV / EDR |
|:---|:---|:---|
| **Core question** | *Is this code allowed to run at all?* | *Is this running code doing something bad?* |
| **When it acts** | Before execution — at load time | During or after execution — at runtime |
| **Decision model** | Deterministic — explicit allow/deny policy rules | Probabilistic — signatures, heuristics, behavioural analysis |
| **Operates at** | Kernel level (Windows Code Integrity) | User mode / kernel hooks |
| **Scope** | Executables, DLLs, scripts, installers, drivers | Running processes, memory, network activity |

{: .important }
> WDAC does not try to decide whether code is malicious — it only decides whether it is **allowed**. AV/EDR decides whether *running* code is behaving maliciously. They are complementary controls.

---

## Where WDAC Excels

WDAC is specifically effective against attack techniques that evade traditional detection:

### Preventing Initial Compromise

Because WDAC blocks execution *before runtime*, unknown malware, staged payloads, and attacker-controlled tooling never get the chance to run — regardless of whether they appear legitimate to detection engines.

### Breaking Living Off the Land (LOTL) Attacks

Modern attacks increasingly avoid dropping obviously malicious binaries. Instead, they abuse trusted built-in tools — known as **Living Off the Land Binaries (LOLBins)** — that are intentionally difficult for AV/EDR to classify as malicious because they are legitimate Microsoft-signed components.

Common LOLBins include:

| Binary | Attacker Use |
|:---|:---|
| `powershell.exe` | Script execution, payload download |
| `cmd.exe` | Command execution and chaining |
| `mshta.exe` | Execute scripts via HTML/HTA |
| `rundll32.exe` | Execute exported DLL functions |
| `wmic.exe` | System interrogation and remote execution |
| `certutil.exe` | File download, encoding/decoding |

{: .note }
> LOLBins are not malware — they are signed Microsoft tools. AV/EDR typically detects *malicious behaviour*, not mere execution. WDAC can explicitly restrict how, where, and when LOLBins are allowed to run, making it particularly effective at breaking file-less and low-noise attacks.

### Reducing Post-Execution Detection Burden

WDAC does not reduce the *need* for EDR — it reduces the *number of situations where EDR must engage*. By preventing untrusted code from executing in the first place, WDAC eliminates an entire class of events that would otherwise require investigation and response.

---

## How They Work Together

```
┌──────────────────────────────────────────────────────────┐
│                    Attack Lifecycle                       │
├──────────────┬───────────────────────────────────────────┤
│  WDAC        │  Prevents execution of:                   │
│  (Pre-exec)  │  • Unknown/unapproved binaries            │
│              │  • Staged payloads                         │
│              │  • Abused LOLBins (via deny rules)         │
│              │  • Unsigned or untrusted code              │
├──────────────┼───────────────────────────────────────────┤
│  AV          │  Scans and blocks:                        │
│  (On-access) │  • Known malware signatures               │
│              │  • Suspicious file patterns                │
├──────────────┼───────────────────────────────────────────┤
│  EDR         │  Detects and responds to:                 │
│  (Runtime)   │  • Anomalous process behaviour            │
│              │  • Lateral movement                        │
│              │  • Memory-based attacks                    │
│              │  • Post-compromise activity                │
└──────────────┴───────────────────────────────────────────┘
```

In a well-designed endpoint strategy, WDAC acts as a **preventative layer** that narrows the attack surface before AV and EDR even need to engage. The result is:

- Fewer alerts to triage
- Reduced reliance on detection accuracy
- Stronger protection against zero-day and unknown threats
- A meaningful reduction in the blast radius of any compromise

---

## Key Takeaways

- **WDAC prevents execution; AV/EDR detects behaviour** — they solve different problems
- **WDAC is deterministic** — policy decisions are explicit and auditable, not based on classification confidence
- **LOLBin abuse is a primary threat** that AV/EDR struggles with but WDAC handles well
- **Most WDAC pain stories are policy stories, not technology stories** — when implemented with discipline, WDAC becomes a quiet but powerful control that materially reduces risk
