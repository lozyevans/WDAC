---
layout: default
title: Manage Citrix VDA with Managed Installer
nav_order: 4.5
---

# Manage Citrix VDA Under WDAC Enforcement
{: .fs-8 }

Citrix VDA is one of the hardest applications to manage under WDAC because of how it updates itself. This page covers why supplemental publisher rules and path rules are not enough on their own, and how to use the **Managed Installer** trust model to let Citrix VDA — and its updates — run without constant policy churn.
{: .fs-5 .fw-300 }

---

## The Problem

When the Citrix VDA agent is updated from Citrix Cloud (or from the Citrix on-premises management plane), the update process:

- Downloads a new VDA package
- Extracts a large number of DLLs and executables into **temporary paths** under the user profile or `%TEMP%`
- Executes those binaries to perform the installation
- Restarts services and registers new binaries on disk

WDAC sees these as **new, untrusted code** because:

| Rule Type | Why It Fails for Citrix VDA |
|:---|:---|
| **Hash rules** | The hash of every Citrix binary changes on every update — generating hash sprawl and breaking enforcement on every upgrade. |
| **Path rules** | The update extracts code into **user-writable temporary paths** (`%TEMP%`, `%LOCALAPPDATA%`). Allowing those paths would give any user a trivial WDAC bypass. |
| **Publisher (FilePublisher) rules** | These work *while the binaries are signed by Citrix and the file name doesn't change*. But Citrix updates frequently introduce new binary names, new internal product strings, and (occasionally) re-signed certificates — each of which requires a new supplemental rule. |

The net result is that **every Citrix VDA update produces a new wave of WDAC audit (3076) or block (3077) events**, and operations teams are forced to re-generate a supplemental policy from event logs every time. For most teams this overhead is unsustainable.

{: .important }
> Supplemental policies for Citrix are still useful as a **safety net** — they let the currently installed binaries run if Managed Installer tagging is ever inconsistent — but they cannot solve the update problem on their own.

---

## The Solution: Managed Installer

WDAC's [Managed Installer]({% link trust-models.md %}#managed-installer) trust model lets you designate a specific signed process (defined in **AppLocker**) as a trusted source of new binaries. When that process writes a file to disk, Windows tags the file with the `$KERNEL.SMARTLOCKER.ORIGINCLAIM` extended attribute. WDAC's **Option 13 (Enabled:Managed Installer)** then trusts any tagged file at execution time — regardless of signing.

Applied to Citrix VDA:

- The Citrix VDA service binaries are declared as Managed Installers in an AppLocker `ManagedInstaller` rule collection
- Anything those services write to disk during an update — including the DLLs in temporary paths — inherits MI trust
- The next VDA upgrade runs without producing fresh 3076/3077 events

This shifts the trust decision from "what is this binary?" to "**who installed it?**", which is exactly the kind of trust boundary an enterprise software supply chain already enforces.

{: .warning-title }
> Security Trade-off
>
> Managed Installer is a heuristic, not a cryptographic guarantee. Anything a designated MI process writes is trusted, including any child process it launches. The Citrix VDA service runs as **SYSTEM**, so designating it as an MI effectively says: *"I trust anything Citrix services choose to install."* In a managed enterprise where Citrix is sourced from Citrix Cloud or a vendor MSI, this is acceptable. In an environment where Citrix binaries can be replaced or side-loaded by an attacker with admin rights, it is not. See [Trust Models — Managed Installer]({% link trust-models.md %}#managed-installer).

---

## Prerequisites

| Requirement | Details |
|:---|:---|
| **Windows 10 1903+** or **Windows 11** | Multiple-policy WDAC and Managed Installer support |
| **AppLocker service (`AppIDSvc`)** | Must be **Automatic** and **Running** on every target device |
| **AppLocker filter driver (`applockerfltr`)** | Must be loaded (default on Win10+; verify with `fltmc filters`) |
| **WDAC base policy with Option 13** | `Enabled:Managed Installer` must be set on every base policy that should honour MI tags |
| **`appidtel.exe start -mionly`** | Must be run once to wire up MI telemetry (use `-mionly` if you are not using ISG / Option 14) |
| **Intune (or ConfigMgr) for deployment** | The AppLocker MI rule and the detect/remediate scripts are deployed via Intune Remediations |

{: .note }
> **WDAC IME version floor.** The Microsoft Recommended User Mode Block List blocks `Microsoft.Management.Services.IntuneWindowsAgent.exe` at `MinimumFileVersion 1.46.204.0` (which in WDAC block-list semantics blocks **that version and below**). Explicit deny beats MI trust, so devices stuck on an old IME cannot act as an MI even with the rule in place. Let Intune auto-update IME above the floor before relying on MI tagging.

---

## Configuration Options

There are two layers, and most production environments need both:

### Option A — Intune Native Managed Installer (IME only)

The **Endpoint Security → App Control for Business → Managed installer** policy in the Intune admin centre designates the **Intune Management Extension (IME)** as a managed installer. This is the supported configuration for Intune-deployed Win32 apps and should be enabled first.

It does **not** cover Citrix VDA, Configuration Manager, or any other deployment tooling — those need a separate AppLocker policy.

See Microsoft's guide: [Manage approved apps with App Control for Business and Managed Installers in Intune](https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/manage-app-control).

### Option B — Custom AppLocker Policy (Citrix VDA, ConfigMgr, third-party tooling)

For anything Intune's built-in policy doesn't cover, you author a custom AppLocker XML that adds a `ManagedInstaller` rule collection alongside the dummy `Exe` / `Dll` collections required to enable services enforcement.

The example policy below trusts:

- **Citrix VDA** — any binary signed by `O=CITRIX SYSTEMS, INC.`
- **Intune Management Extension** — defensive duplicate of the native Intune MI rule (harmless when both are present)
- **Configuration Manager** — `CCMEXEC.EXE` and `CCMSETUP.EXE`

```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Benign DENY DLL Rule"
                  Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" />
      </Conditions>
    </FilePathRule>
    <RuleCollectionExtensions>
      <ThresholdExtensions>
        <Services EnforcementMode="Enabled" />
      </ThresholdExtensions>
      <RedstoneExtensions>
        <SystemApps Allow="Enabled" />
      </RedstoneExtensions>
    </RuleCollectionExtensions>
  </RuleCollection>

  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Benign DENY EXE Rule"
                  Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" />
      </Conditions>
    </FilePathRule>
    <RuleCollectionExtensions>
      <ThresholdExtensions>
        <Services EnforcementMode="Enabled" />
      </ThresholdExtensions>
      <RedstoneExtensions>
        <SystemApps Allow="Enabled" />
      </RedstoneExtensions>
    </RuleCollectionExtensions>
  </RuleCollection>

  <RuleCollection Type="ManagedInstaller" EnforcementMode="AuditOnly">
    <FilePublisherRule Id="6b4b54fa-002a-478d-a8a0-17089e24a061"
                      Name="Managed Installer - Citrix"
                      Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition
          PublisherName="O=CITRIX SYSTEMS, INC., L=FORT LAUDERDALE, S=FLORIDA, C=US"
          ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="3cf97403-1b4a-4492-8e70-98436cf78983"
                      Name="Managed Installer - Intune Management Extension"
                      Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition
          PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
          ProductName="*" BinaryName="MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="6ead5a35-5bac-4fe4-a0a4-be8885012f87"
                      Name="CCM - CCMEXEC.EXE, 5.0.0.0+, Microsoft signed"
                      Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition
          PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
          ProductName="*" BinaryName="CCMEXEC.EXE">
          <BinaryVersionRange LowSection="5.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="8e23170d-e0b7-4711-b6d0-d208c960f30e"
                      Name="CCM - CCMSETUP.EXE, 5.0.0.0+, Microsoft signed"
                      Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition
          PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
          ProductName="*" BinaryName="CCMSETUP.EXE">
          <BinaryVersionRange LowSection="5.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
```

Notes on the XML:

- The `ManagedInstaller` rule collection uses `EnforcementMode="AuditOnly"`. This is the safer choice — AppLocker emits Event ID **8003 (Warning)** for unmatched executables instead of **8004 (Error)** under `Enabled` mode. The MI tagging behaviour is identical either way.
- The benign `Deny` rules in the `Exe` and `Dll` collections are there to make the rule collections non-empty so `<Services EnforcementMode="Enabled" />` and `<SystemApps Allow="Enabled" />` actually take effect. They target a non-existent file path and never block anything real.
- The Citrix rule uses `BinaryName="*"` which makes **every Citrix-signed binary** a managed installer. On end-user endpoints, consider narrowing this to specific service or updater binaries to avoid user-launched Citrix apps acting as installers. On dedicated VDA hosts the broad rule is usually acceptable.

---

## Deployment Pattern (Detect + Remediate)

The most reliable way to deploy and self-heal a custom AppLocker MI policy is via **Intune Remediations** (formerly Proactive Remediations) — the same mechanism Microsoft uses internally to deploy the IME managed installer policy.

A working pair of detect and remediate scripts is maintained in a separate workspace:

```
C:\VSCode-Projects\AppLocker-ManagedInstaller\
├─ Detect-CustomManagedInstaller.ps1
├─ Remediate-CustomManagedInstaller.ps1
├─ ManagedInstallerCSPText.txt        (reference AppLocker XML)
└─ OMA-URI Text for MI.txt            (alternative OMA-URI deployment)
```

### What the detect script checks

1. `Get-AppLockerPolicy -Effective -Xml` contains a `ManagedInstaller` rule collection
2. That collection has publisher rules for **IME**, **Citrix**, **CCMEXEC.EXE**, and **CCMSETUP.EXE**
3. The `Exe` and `Dll` collections are present with `<Services EnforcementMode="Enabled" />`
4. **AppIDSvc** is `Automatic` and `Running`
5. (Informational only) IME is above the WDAC block-list floor

Exit `0` = compliant; exit `1` = remediation required.

### What the remediate script does

1. Sets **AppIDSvc** to `Automatic` (via `sc.exe config AppIDSvc start= auto` — `Set-Service` can fail with Access Denied because of the protected description ACL) and starts the service
2. Runs `appidtel.exe start -mionly` to initialise the Managed Installer subsystem
3. Writes the AppLocker policy XML to `%TEMP%` and runs `Set-AppLockerPolicy -XmlPolicy <path> -Merge` — **`-Merge` is critical**; without it you overwrite any existing AppLocker policy (including Intune's IME MI rules)
4. **Restarts `AppIDSvc`** so AppLocker re-reads the merged policy from disk — without this, `Get-AppLockerPolicy -Effective` can return the pre-merge view and the post-remediation compliance check produces false "rule not found" failures
5. Re-runs the compliance check and exits accordingly

{: .warning-title }
> Always merge — never replace
>
> `Set-AppLockerPolicy -XmlPolicy ... -Merge` is the only safe deployment method on devices that may already have:
>
> - Intune's IME Managed Installer policy (deployed via the native Intune "Managed installer" policy)
> - Configuration Manager's built-in MI policy
> - Any pre-existing AppLocker `Script` collection deployed via the AppLocker CSP
>
> Omit `-Merge` and you silently delete those policies. This is the same overwrite trap covered in [Common Pitfalls — Trusting Tool Merges Without a Backup]({% link common-pitfalls-lifecycle.md %}#trusting-tool-merges-without-a-backup).

---

## Caveats and Operational Behaviour

Read these before relying on Managed Installer in production:

| Caveat | What it means in practice |
|:---|:---|
| **Rules can be declared before the binary exists.** AppLocker rules are declarations. Nothing is tagged until a matching binary actually runs. | Safe to deploy the AppLocker MI policy in advance of Citrix being installed. |
| **Tagging only starts on NEW process launches.** Already-running processes are not retroactively treated as MIs. | After first deploying the policy, **restart the Citrix services** (or reboot) to start MI tracking. |
| **Files written BEFORE the rule was active are not tagged.** Only files written by an MI-tracked process AFTER policy activation get the `$KERNEL.SMARTLOCKER.ORIGINCLAIM` EA. | Pre-existing Citrix binaries must be covered by a supplemental WDAC policy (or re-installed) — MI tagging will only apply to future updates. |
| **WDAC explicit Deny beats MI trust.** A file blocked by a deny rule is blocked even if it carries the MI tag. | Confirm none of your deny policies (driver block list, user-mode block list) target the binaries you expect Citrix to install. |
| **Kernel drivers are NOT authorized by MI.** MI applies to user-mode files only. | Any Citrix VDA kernel driver must still be allowed by an explicit WDAC rule. |
| **`AuditOnly` enforcement still produces noisy AppLocker events.** Event ID 8003 (Warning) is emitted for every executable that doesn't match an explicit allow rule. | Filter on `PolicyName = MANAGEDINSTALLER` in the event XML to identify and suppress these. In Defender for Endpoint Advanced Hunting, look for `AppControlExecutableAudited` in `DeviceEvents`. |
| **ConfigMgr also needs the client to register.** The AppLocker rule alone is not enough for ConfigMgr to act as an MI. The CM client must be installed (or upgraded) with `ccmsetup.exe /MANAGEDINSTALLER=TRUE` **or** one of the MEMCM inbox App Control policies must be deployed. | The Citrix and IME rules need no equivalent switch — they self-register once AppIDSvc is running and the policy is loaded. |

---

## Validation

### 1. Verify the effective AppLocker policy

```powershell
Get-AppLockerPolicy -Effective -Xml | Out-File AppLockerPolicy.xml
notepad AppLockerPolicy.xml
```

Confirm the `ManagedInstaller` rule collection is present and contains the expected publisher rules.

### 2. Verify the AppLocker filter driver is loaded

```powershell
fltmc filters
```

Look for `applockerfltr` in the output. If it's not listed or shows `0 instances`, AppLocker (and therefore MI tagging) is inert.

### 3. Verify AppIDSvc is running

```powershell
Get-Service AppIDSvc
```

Status must be `Running`. If it's stopped, MI tracking does nothing regardless of policy.

### 4. Verify a file has been tagged after a Citrix update

After Citrix services have written a new binary, check its extended attributes:

```powershell
fsutil file queryea "C:\Program Files\Citrix\<path-to-newly-installed-binary>.exe"
```

If you see `$KERNEL.SMARTLOCKER.ORIGINCLAIM`, the Managed Installer is working — the file is tagged and WDAC will allow it under Option 13.

### 5. Confirm WDAC Option 13 is enabled

In each base policy XML, confirm:

```xml
<Rule>
  <Option>Enabled:Managed Installer</Option>
</Rule>
```

Or in PowerShell on a policy file:

```powershell
Set-RuleOption -FilePath <PolicyXml> -Option 13
```

(Run only if not already set — this writes to the XML.)

---

## Where Managed Installer Fits With Other WDAC Policies

| Layer | Purpose | Coverage |
|:---|:---|:---|
| **Base allow policy (Option 13 enabled)** | Defines core trust boundary; tells WDAC to honour MI tags | Whole device |
| **Supplemental policy — Allow Citrix** | Trusts the Citrix binaries already on disk (publisher / hash) | Pre-MI inventory; safety net |
| **AppLocker Managed Installer policy** | Tags new files written by Citrix services so updates are trusted | Future Citrix updates; ConfigMgr deployments; IME-deployed apps |
| **Deny policies (driver + user-mode)** | Block known-bad or vulnerable binaries | Always wins, including against MI-tagged files |

MI does not replace your supplemental policy — it complements it. Keep the supplemental policy in place so that Citrix binaries already installed before MI was deployed continue to run.

---

## References

- [Manage approved apps for Windows devices with App Control for Business policy and Managed Installers in Intune](https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/manage-app-control)
- [Allow apps deployed with an App Control managed installer](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/configure-authorized-apps-deployed-with-a-managed-installer)
- [AppControl for Business — Managed Installers Part 3: How ConfigMgr and Intune Actually Implement It and defining your own](https://www.appcontrol.ai/post/appcontrol-for-business-managed-installers-part-3-how-configmgr-and-intune-actually-implement-it)
- [Trust Models Deep Dive — Managed Installer]({% link trust-models.md %}#managed-installer)
- [Common Pitfalls & Lifecycle]({% link common-pitfalls-lifecycle.md %})
