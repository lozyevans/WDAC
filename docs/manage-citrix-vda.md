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

#### How to get the Citrix publisher string for the rule

The `PublisherName` in the Citrix rule (`O=CITRIX SYSTEMS, INC., L=FORT LAUDERDALE, S=FLORIDA, C=US`) is the **subject** of the Authenticode signing certificate on a Citrix binary. The VDA installer (`VDAWorkstationSetup_2511.exe`) is a self-extracting bundle, so the signed binary you want is *inside* it. The certificate was extracted as follows:

1. **Open the installer as an archive.** Using [7-Zip](https://www.7-zip.org/), right-click `VDAWorkstationSetup_2511.exe` → **7-Zip → Open archive**. This exposes the embedded payload without running the installer.
2. **Extract a signed Citrix component.** From inside the archive, extract `CitrixUpgradeAgent_x64.msi` (any consistently Citrix-signed binary works; the upgrade agent is a reliable choice because it's present in every VDA build and signed by the same certificate).
3. **Read the certificate subject.** Right-click the extracted file → **Properties → Digital Signatures → Citrix Systems, Inc. → Details → View Certificate → Details → Subject**, or run PowerShell against the extracted file:

   ```powershell
   (Get-AuthenticodeSignature ".\CitrixUpgradeAgent_x64.msi").SignerCertificate | Format-List Subject, Issuer, Thumbprint
   ```

4. **Map the subject to the AppLocker `PublisherName`.** AppLocker expects the certificate subject in canonical comma-separated form. The `Subject` field — for example `CN=Citrix Systems, Inc., O=CITRIX SYSTEMS, INC., L=Fort Lauderdale, S=Florida, C=US` — maps directly to the `O=...`, `L=...`, `S=...`, `C=...` segments used in the rule.

{: .note }
> The fastest way to get a correctly formatted `FilePublisherCondition` is to point the **AppLocker rule wizard** (or `New-AppLockerPolicy`) at the extracted, signed binary — it reads the certificate and emits the exact `PublisherName`, `ProductName`, and `BinaryName` values for you, which you can then widen to `ProductName="*" BinaryName="*"`.

{: .warning }
> Always verify the signature is valid (`Status = Valid`) and sourced from a binary you downloaded directly from Citrix. Building a Managed Installer rule from an unverified or tampered binary would trust the wrong publisher. Re-check the subject after any Citrix certificate rollover.

---

## Deployment Pattern (Detect + Remediate)

The most reliable way to deploy and self-heal a custom AppLocker MI policy is via **Intune Remediations** (formerly Proactive Remediations) — the same mechanism Microsoft uses internally to deploy the IME managed installer policy.

A working pair of detect and remediate scripts is provided below. Download them directly or copy them from the [Appendix](#appendix-deployment-scripts):

- [Detect-CustomManagedInstaller.ps1]({{ site.baseurl }}/scripts/Detect-CustomManagedInstaller.ps1) — detection script
- [Remediate-CustomManagedInstaller.ps1]({{ site.baseurl }}/scripts/Remediate-CustomManagedInstaller.ps1) — remediation script

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

---

## Appendix: Deployment Scripts
{: #appendix-deployment-scripts }

The full detection and remediation scripts used in the [Deployment Pattern](#deployment-pattern-detect--remediate) section are reproduced below for review. You can also download them directly:

- [Download Detect-CustomManagedInstaller.ps1]({{ site.baseurl }}/scripts/Detect-CustomManagedInstaller.ps1)
- [Download Remediate-CustomManagedInstaller.ps1]({{ site.baseurl }}/scripts/Remediate-CustomManagedInstaller.ps1)

{: .note }
> The publisher strings, the WDAC IME version floor (`1.46.204.0`), and the environment-specific notes in the script headers reflect one reference tenant. Review and adapt the publisher names, binary names, and version ranges to match your own signing certificates and tooling before deploying.

### Detect-CustomManagedInstaller.ps1

```powershell
<#
.SYNOPSIS
    Intune Remediation detection script - reports compliance with the custom
    AppLocker Managed Installer policy (IME + Citrix + Configuration Manager).

.DESCRIPTION
    Reads the effective AppLocker policy and verifies the required
    ManagedInstaller publisher rules are present, plus services enforcement
    is Enabled on the EXE and DLL rule collections. Exits 0 when compliant,
    1 when remediation is required.

.NOTES
    Managed Installer behavior caveats (apply to ALL publishers below):

    * Rules can be present without the binary being installed.
      AppLocker rules are declarations; nothing is tagged until a matching
      binary actually runs. Deploying ahead of the app is safe.

    * Tagging only starts on NEW process launches after the rule is active.
      Processes already running before the policy applied are NOT retroactively
      treated as managed installers. A service restart or reboot is required
      to start tagging for already-running publishers.

    * Files written BEFORE the rule applied are NOT tagged.
      Only files written by an MI-tracked process AFTER policy activation
      receive the $KERNEL.SMARTLOCKER.ORIGINCLAIM EA used by App Control
      Option 13 (Enabled:Managed Installer).

    Publisher-specific caveats:

    * Intune Management Extension (IME):
      Microsoft's native 'Managed installer' policy under Intune > Endpoint
      security > App Control for Business is the supported configuration for
      IME. This script's IME rule is a defensive duplicate and is harmless
      when the native policy is already in place.

    * Configuration Manager (CCMEXEC.EXE / CCMSETUP.EXE):
      The AppLocker rule alone is not enough for ConfigMgr to act as an MI.
      The CM client must also be installed (or upgraded) with the switch
        ccmsetup.exe /MANAGEDINSTALLER=TRUE
      OR one of the MEMCM inbox App Control policies must be deployed to the
      device. Without that, the binary will run but CM will not register
      itself with the MI subsystem.

    * Citrix:
      No equivalent installer switch is needed. The AppLocker rule itself is
      the registration, provided AppIDSvc is running and the AppLocker
      filter driver (applockerfltr) is loaded. Pre-installed Citrix is fine,
      but currently-running Citrix processes won't be MI-tracked until they
      restart (reboot recommended after first policy deployment).
      The Citrix rule uses BinaryName="*" which makes EVERY Citrix-signed
      binary an MI. On end-user endpoints, consider narrowing to specific
      service/updater binaries to avoid user-launched Citrix apps acting as
      installers.

    Prerequisites on the device:
      * AppIDSvc service: Automatic + Started (validated by this script).
      * AppLocker filter driver (applockerfltr) loaded (default on Win10+).
      * For end-to-end trust: WDAC / App Control policy with Option 13
        (Enabled:Managed Installer) deployed.

    Environment-specific notes (HSBC Silver tenant / MSA1865, verified
    from the tenant settings report dated 2026-03-25):

    * WDAC Option 13 (Enabled:Managed Installer) is ALREADY enabled on all
      four base App Control policies in this tenant (NoScriptCLM, Driver
      Block Rules audit + enforced, User Mode Block Rules Allow_Citrix).
      No additional WDAC change is required for MI trust to take effect.

    * A WDAC supplemental policy "Allow-Citrix" already trusts Citrix
      binaries directly (CertPublisher + per-file hash). Our MI rule is
      COMPLEMENTARY: the supplemental allows Citrix binaries to execute;
      the MI rule additionally lets files Citrix writes inherit MI trust.

    * The existing AppLocker CSP profile (MDM_Silver-Win-DCP-Windows-
      AppLocker-CLMOnly) deploys ONLY a Script rule collection at
      Grouping="Native". This script writes Dll / Exe / ManagedInstaller
      collections to the LOCAL AppLocker store. The two stores are
      separate; AppLocker evaluates the union, so no conflict.

    * The previous custom OMA-URI MI profile and the
      WDAC-AppTagging-Device-CSP profile have been REMOVED from the
      tenant. AppId tagging is a different feature from AppLocker MI; it
      was causing unintended WDAC blocks. This script's approach (the
      standard AppLocker ManagedInstaller collection + WDAC Option 13) is
      the supported, lower-risk path.

    * IMPORTANT - WDAC IME version floor:
      The Microsoft Recommended User Mode Block List in use contains:
        <Deny FriendlyName="IntuneWindowsAgent.exe"
              FileName="Microsoft.Management.Services.IntuneWindowsAgent.exe"
              MinimumFileVersion="1.46.204.0" />
      In WDAC block-list semantics, this blocks IME versions <= 1.46.204.0.
      Explicit deny beats MI trust, so devices with IME at or below this
      version cannot act as an MI even with the rule present. This script
      logs an informational warning if it detects an IME below the floor;
      it does NOT mark the device non-compliant for it (IME auto-updates
      via Intune and Remediation cannot fix the binary version).

    * HVCI / VBS is enforced on this device baseline. This does not
      affect AppLocker MI operation.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Primary log location (preferred). If this is unavailable for any reason
# (ACL, file locked by another instance, missing parent path), we silently
# fall back to $env:TEMP and record that fact in the active log path.
$PrimaryLogRoot = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\CustomManagedInstaller'
$PrimaryLogFile = Join-Path -Path $PrimaryLogRoot -ChildPath 'Detect-CustomManagedInstaller.log'
$FallbackLogRoot = Join-Path -Path $env:TEMP -ChildPath 'CustomManagedInstaller'
$FallbackLogFile = Join-Path -Path $FallbackLogRoot -ChildPath 'Detect-CustomManagedInstaller.log'

# Script-scoped runtime state, populated by Initialize-Log. $script:LogFile
# is what Write-Log writes to; $script:LogInitError captures any reason the
# primary path was rejected so we can log it on the very first line.
$script:LogFile = $PrimaryLogFile
$script:LogInitError = $null

$MaxLogSizeBytes = 5MB
$MaxLogRollFiles = 5

function Initialize-Log {
    <#
        Bulletproof log initializer.
        - Never throws. Any failure to prepare a path is swallowed and the
          next candidate is tried.
        - Tries primary path first, then $env:TEMP fallback.
        - Returns the path that ultimately succeeded (or $null if neither
          succeeded, in which case Write-Log will only emit to stdout).
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CandidatePaths,
        [Parameter(Mandatory = $true)]
        [int64]$MaxBytes,
        [Parameter(Mandatory = $true)]
        [int]$MaxRollFiles
    )

    foreach ($Path in $CandidatePaths) {
        try {
            $folder = Split-Path -Path $Path -Parent
            if (-not (Test-Path -LiteralPath $folder)) {
                New-Item -Path $folder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            # Roll if oversized. Use SilentlyContinue here because a locked
            # log from a concurrent run should not abort the script; we'll
            # just append instead.
            if (Test-Path -LiteralPath $Path) {
                $size = (Get-Item -LiteralPath $Path -ErrorAction Stop).Length
                if ($size -ge $MaxBytes) {
                    for ($i = $MaxRollFiles - 1; $i -ge 1; $i--) {
                        $older = "{0}.{1}" -f $Path, $i
                        $newer = "{0}.{1}" -f $Path, ($i + 1)
                        if (Test-Path -LiteralPath $older) {
                            if ($i -eq ($MaxRollFiles - 1)) {
                                Remove-Item -LiteralPath $older -Force -ErrorAction SilentlyContinue
                            }
                            else {
                                Move-Item -LiteralPath $older -Destination $newer -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                    Move-Item -LiteralPath $Path -Destination ("{0}.1" -f $Path) -Force -ErrorAction SilentlyContinue
                }
            }

            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -ItemType File -Force -ErrorAction Stop | Out-Null
            }

            # Final proof-of-write probe: a zero-byte append must succeed
            # before we commit to this path as the live log.
            [System.IO.File]::AppendAllText($Path, [string]::Empty)
            return $Path
        }
        catch {
            $script:LogInitError = ("Log path '{0}' rejected: {1}" -f $Path, $_.Exception.Message)
            continue
        }
    }

    return $null
}

function Write-Log {
    <#
        Tee-style writer. Always emits to stdout (so Intune captures it in
        the per-device remediation output panel, first ~2KB) and ALSO appends
        to the active log file if one was successfully initialized. File
        write failures are swallowed so a transient file lock cannot crash
        the script and lose information.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message

    # Always emit to stdout - Intune surfaces this in the remediation portal.
    Write-Output $line

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -ErrorAction Stop
        }
        catch {
            # As a last-ditch fallback, try the alternate path. Never throw.
            try {
                Add-Content -LiteralPath $FallbackLogFile -Value $line -ErrorAction Stop
            }
            catch {
                # Give up on file logging for this line; stdout already has it.
            }
        }
    }
}

function Get-AppIdServiceState {
    # AppIDSvc is the Application Identity service. Without it Running +
    # Automatic, AppLocker (and therefore MI tagging) does nothing, regardless
    # of how perfect the policy XML is. Detect script must surface this so
    # the remediation script can correct it on the next pass.
    [OutputType([hashtable])]
    param()

    $state = @{
        ServiceFound = $false
        StartupType  = $null
        Status       = $null
    }

    try {
        $svc = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
        $state.ServiceFound = $true
        $state.Status = [string]$svc.Status
        $state.StartupType = [string]$svc.StartType
    }
    catch {
        # Service not present (e.g. SKU without AppLocker). Leave defaults.
    }

    return $state
}

function Get-IntuneAgentVersionInfo {
    # Informational only - the Microsoft Recommended User Mode Block List in
    # use on this tenant denies Microsoft.Management.Services.IntuneWindowsAgent.exe
    # at MinimumFileVersion 1.46.204.0. In WDAC blocklist semantics, that
    # blocks versions <= 1.46.204.0. Explicit deny beats MI trust, so if a
    # device is running an IME at or below that floor it CANNOT act as an MI.
    # We log this as a warning but do NOT mark the device non-compliant -
    # the script cannot fix the IME version; that comes from Intune updates.
    [OutputType([hashtable])]
    param()

    $info = @{
        AgentFound       = $false
        AgentPath        = $null
        AgentVersion     = $null
        WdacBlockFloor   = [version]'1.46.204.0'
        IsAtOrBelowFloor = $false
    }

    $candidates = @()
    if ($env:ProgramFiles) {
        $candidates += (Join-Path -Path $env:ProgramFiles -ChildPath 'Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe')
    }
    if (${env:ProgramFiles(x86)}) {
        $candidates += (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe')
    }

    foreach ($path in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -Path $path)) {
            $info.AgentFound = $true
            $info.AgentPath = $path
            try {
                $fvi = (Get-Item -Path $path).VersionInfo
                # FileVersionRaw is a [version]; fall back to FileVersion string parse.
                $ver = $null
                if ($fvi.PSObject.Properties.Match('FileVersionRaw').Count -gt 0 -and $fvi.FileVersionRaw) {
                    $ver = [version]$fvi.FileVersionRaw
                }
                elseif (-not [string]::IsNullOrWhiteSpace($fvi.FileVersion)) {
                    $ver = [version]($fvi.FileVersion -replace '[^\d\.].*$', '')
                }
                if ($ver) {
                    $info.AgentVersion = $ver
                    $info.IsAtOrBelowFloor = ($ver -le $info.WdacBlockFloor)
                }
            }
            catch {
                # Unable to read version info; leave AgentVersion null.
            }
            break
        }
    }

    return $info
}

function Get-ManagedInstallerCompliance {
    [OutputType([hashtable])]
    param()

    $result = @{
        IsCompliant = $false
        Reasons     = New-Object System.Collections.Generic.List[string]
    }

    # ---- 1. AppLocker effective policy (CSP store + local store merged) ----
    try {
        [xml]$xml = Get-AppLockerPolicy -Effective -Xml
    }
    catch {
        $result.Reasons.Add("Failed to read effective AppLocker policy: $($_.Exception.Message)")
        return $result
    }

    $ruleCollections = @($xml.AppLockerPolicy.RuleCollection)

    # ---- 2. ManagedInstaller publisher rules ----
    # In this tenant the existing CSP-deployed AppLocker policy contains only
    # a Script collection (Grouping="Native"). The ManagedInstaller collection
    # therefore lives in the LOCAL store, written by the remediation script.
    $managedInstallerCollection = $ruleCollections | Where-Object { $_.Type -eq 'ManagedInstaller' } | Select-Object -First 1
    if (-not $managedInstallerCollection) {
        $result.Reasons.Add('ManagedInstaller rule collection not found in effective AppLocker policy.')
    }
    else {
        $publisherConditions = @($managedInstallerCollection.FilePublisherRule.Conditions.FilePublisherCondition)

        $hasImeRule = $false
        $hasCitrixRule = $false
        $hasCcmExecRule = $false
        $hasCcmSetupRule = $false

        foreach ($condition in $publisherConditions) {
            if (-not $condition) {
                continue
            }

            # IME - Microsoft.Management.Services.IntuneWindowsAgent.exe
            if ($condition.PublisherName -like '*MICROSOFT CORPORATION*' -and $condition.BinaryName -ieq 'MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE') {
                $hasImeRule = $true
            }

            # Citrix - any Citrix-signed binary (BinaryName="*" in our rule)
            if ($condition.PublisherName -like '*CITRIX SYSTEMS*') {
                $hasCitrixRule = $true
            }

            # ConfigMgr CCMEXEC.EXE
            if ($condition.PublisherName -like '*MICROSOFT CORPORATION*' -and $condition.BinaryName -ieq 'CCMEXEC.EXE') {
                $hasCcmExecRule = $true
            }

            # ConfigMgr CCMSETUP.EXE
            if ($condition.PublisherName -like '*MICROSOFT CORPORATION*' -and $condition.BinaryName -ieq 'CCMSETUP.EXE') {
                $hasCcmSetupRule = $true
            }
        }

        if (-not $hasImeRule) {
            $result.Reasons.Add('Intune Management Extension ManagedInstaller rule not found.')
        }

        if (-not $hasCitrixRule) {
            $result.Reasons.Add('Citrix ManagedInstaller rule not found.')
        }

        if (-not $hasCcmExecRule) {
            $result.Reasons.Add('Configuration Manager CCMEXEC.EXE ManagedInstaller rule not found.')
        }

        if (-not $hasCcmSetupRule) {
            $result.Reasons.Add('Configuration Manager CCMSETUP.EXE ManagedInstaller rule not found.')
        }
    }

    # ---- 3. EXE / DLL collections must exist with Services enforcement ----
    # MI tracking requires *some* rule in Exe + Dll collections and the
    # Services sub-element set to Enabled. The benign deny + SystemApps Allow
    # pattern in the remediation XML satisfies both without restricting apps.
    $exeCollection = $ruleCollections | Where-Object { $_.Type -eq 'Exe' } | Select-Object -First 1
    $dllCollection = $ruleCollections | Where-Object { $_.Type -eq 'Dll' } | Select-Object -First 1

    if (-not $exeCollection) {
        $result.Reasons.Add('EXE rule collection not found in effective AppLocker policy.')
    }
    else {
        $exeServicesMode = $exeCollection.RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode
        if ($exeServicesMode -ne 'Enabled') {
            $result.Reasons.Add("EXE services enforcement is '$exeServicesMode' instead of 'Enabled'.")
        }
    }

    if (-not $dllCollection) {
        $result.Reasons.Add('DLL rule collection not found in effective AppLocker policy.')
    }
    else {
        $dllServicesMode = $dllCollection.RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode
        if ($dllServicesMode -ne 'Enabled') {
            $result.Reasons.Add("DLL services enforcement is '$dllServicesMode' instead of 'Enabled'.")
        }
    }

    # ---- 4. AppIDSvc state - rules are useless without the service ----
    $svcState = Get-AppIdServiceState
    if (-not $svcState.ServiceFound) {
        $result.Reasons.Add('AppIDSvc (Application Identity) service not found on device. AppLocker requires this service.')
    }
    else {
        if ($svcState.StartupType -ne 'Automatic') {
            $result.Reasons.Add("AppIDSvc startup type is '$($svcState.StartupType)' instead of 'Automatic'.")
        }
        if ($svcState.Status -ne 'Running') {
            $result.Reasons.Add("AppIDSvc status is '$($svcState.Status)' instead of 'Running'.")
        }
    }

    $result.IsCompliant = ($result.Reasons.Count -eq 0)
    return $result
}

# ============================================================================
# ENTRY POINT
# Wrapped in a top-level try/catch so that even a logging or environment
# failure produces some signal (stdout) to Intune. exit codes:
#   0 = compliant, no remediation needed
#   1 = non-compliant OR unrecoverable error (Intune will run remediation)
# ============================================================================
try {
    $script:LogFile = Initialize-Log -CandidatePaths @($PrimaryLogFile, $FallbackLogFile) -MaxBytes $MaxLogSizeBytes -MaxRollFiles $MaxLogRollFiles

    if ($script:LogInitError) {
        Write-Log -Level 'WARN' -Message $script:LogInitError
    }
    if ($script:LogFile) {
        Write-Log -Level 'INFO' -Message ("Active log file: {0}" -f $script:LogFile)
    }
    else {
        Write-Output ("[{0}] [WARN] Unable to open any log file. Continuing with stdout-only logging." -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'))
    }

    Write-Log -Level 'INFO' -Message 'Starting custom managed installer detection run.'
    Write-Log -Level 'INFO' -Message ("Log rollover settings: MaxLogSizeBytes={0}; MaxLogRollFiles={1}" -f $MaxLogSizeBytes, $MaxLogRollFiles)
    Write-Log -Level 'INFO' -Message ("PowerShell {0} | PID {1} | User {2} | 64-bit process: {3}" -f $PSVersionTable.PSVersion, $PID, [System.Security.Principal.WindowsIdentity]::GetCurrent().Name, [Environment]::Is64BitProcess)

    # See header NOTES. Logged but never causes the detection to fail.
    $imeInfo = Get-IntuneAgentVersionInfo
    if ($imeInfo.AgentFound) {
        Write-Log -Level 'INFO' -Message ("IME found at {0}; version {1}; WDAC block floor {2}." -f $imeInfo.AgentPath, $imeInfo.AgentVersion, $imeInfo.WdacBlockFloor)
        if ($imeInfo.IsAtOrBelowFloor) {
            Write-Log -Level 'WARN' -Message ("IME version {0} is at or below the WDAC Microsoft Recommended User Mode Block List floor ({1}). WDAC explicit Deny will block IME, preventing it from acting as a Managed Installer until IME is updated above the floor." -f $imeInfo.AgentVersion, $imeInfo.WdacBlockFloor)
        }
    }
    else {
        Write-Log -Level 'INFO' -Message 'IME binary not found in standard install paths. Skipping IME version vs WDAC floor check.'
    }

    $compliance = Get-ManagedInstallerCompliance

    if ($compliance.IsCompliant) {
        Write-Log -Level 'INFO' -Message 'Device is compliant. Intune, Citrix, and Configuration Manager managed installer requirements are present.'
        exit 0
    }

    foreach ($reason in $compliance.Reasons) {
        Write-Log -Level 'WARN' -Message $reason
    }

    Write-Log -Level 'WARN' -Message 'Device is NOT compliant. Remediation required.'
    exit 1
}
catch {
    # Master safety net: never let an unhandled exception swallow the reason.
    $errMsg = ("Detection failed (unhandled): {0} | At: {1}" -f $_.Exception.Message, $_.InvocationInfo.PositionMessage)
    try { Write-Log -Level 'ERROR' -Message $errMsg } catch { Write-Output $errMsg }
    exit 1
}
```

### Remediate-CustomManagedInstaller.ps1

```powershell
<#
.SYNOPSIS
    Intune Remediation script - ensures the custom AppLocker Managed Installer
    policy is present (merged, not replaced) so that IME, Citrix, and
    Configuration Manager binaries are trusted as managed installers.

.DESCRIPTION
    Merges a ManagedInstaller RuleCollection plus AuditOnly EXE/DLL collections
    with services enforcement enabled, then re-checks compliance.

.NOTES
    Managed Installer behavior caveats (apply to ALL publishers below):

    * Rules can be present without the binary being installed.
      AppLocker rules are declarations; nothing is tagged until a matching
      binary actually runs. Deploying ahead of the app is safe.

    * Tagging only starts on NEW process launches after the rule is active.
      Processes already running before the policy applied are NOT retroactively
      treated as managed installers. A service restart or reboot is required
      to start tagging for already-running publishers.

    * Files written BEFORE the rule applied are NOT tagged.
      Only files written by an MI-tracked process AFTER policy activation
      receive the $KERNEL.SMARTLOCKER.ORIGINCLAIM EA used by App Control
      Option 13 (Enabled:Managed Installer).

    Publisher-specific caveats:

    * Intune Management Extension (IME):
      Microsoft's native 'Managed installer' policy under Intune > Endpoint
      security > App Control for Business is the supported configuration for
      IME. This script's IME rule is a defensive duplicate and is harmless
      when the native policy is already in place.

    * Configuration Manager (CCMEXEC.EXE / CCMSETUP.EXE):
      The AppLocker rule alone is not enough for ConfigMgr to act as an MI.
      The CM client must also be installed (or upgraded) with the switch
        ccmsetup.exe /MANAGEDINSTALLER=TRUE
      OR one of the MEMCM inbox App Control policies must be deployed to the
      device. Without that, the binary will run but CM will not register
      itself with the MI subsystem.

    * Citrix:
      No equivalent installer switch is needed. The AppLocker rule itself is
      the registration, provided AppIDSvc is running and the AppLocker
      filter driver (applockerfltr) is loaded. Pre-installed Citrix is fine,
      but currently-running Citrix processes won't be MI-tracked until they
      restart (reboot recommended after first policy deployment).
      The Citrix rule uses BinaryName="*" which makes EVERY Citrix-signed
      binary an MI. On end-user endpoints, consider narrowing to specific
      service/updater binaries to avoid user-launched Citrix apps acting as
      installers.

    Prerequisites on the device:
      * AppIDSvc service: Automatic + Started (handled by this script).
      * AppLocker filter driver (applockerfltr) loaded (default on Win10+).
      * Managed Installer subsystem initialized via appidtel.exe start -mionly
        (handled by this script). The -mionly switch is used because trust is
        granted via WDAC Option 13 (Managed Installer) only; Option 14 / ISG
        is not in use in this environment.
      * For end-to-end trust: WDAC / App Control policy with Option 13
        (Enabled:Managed Installer) deployed.

    Environment-specific notes (HSBC Silver tenant / MSA1865, verified
    from the tenant settings report dated 2026-03-25):

    * WDAC Option 13 (Enabled:Managed Installer) is ALREADY enabled on all
      four base App Control policies in this tenant (NoScriptCLM, Driver
      Block Rules audit + enforced, User Mode Block Rules Allow_Citrix).
      No additional WDAC change is required for MI trust to take effect.

    * The Allow_Citrix WDAC base policy disables Option 19 (Dynamic Code
      Security) intentionally for Citrix VDA compatibility, and removes
      InstallUtil.exe from the deny list to permit Citrix autoupdate. Both
      are deliberate, pre-existing decisions; this script does not touch
      WDAC and therefore does not affect them.

    * A WDAC supplemental policy "Allow-Citrix" already trusts Citrix
      binaries directly (CertPublisher + per-file hash). Our MI rule is
      COMPLEMENTARY: the supplemental allows Citrix binaries to execute;
      the MI rule additionally lets files Citrix writes inherit MI trust.
      Keep both in place.

    * The existing AppLocker CSP profile (MDM_Silver-Win-DCP-Windows-
      AppLocker-CLMOnly) deploys ONLY a Script rule collection at
      Grouping="Native". Set-AppLockerPolicy -Merge in this script writes
      Dll / Exe / ManagedInstaller collections to the LOCAL AppLocker
      store. The two stores are separate; AppLocker evaluates the union,
      so there is no conflict with the existing CSP-deployed Script rules.

    * The previous custom OMA-URI MI profile and the
      WDAC-AppTagging-Device-CSP profile have been REMOVED from the
      tenant. AppId tagging is a different feature from AppLocker MI; it
      was causing unintended WDAC blocks. This script's approach is the
      supported, lower-risk replacement.

    * IMPORTANT - WDAC IME version floor:
      The Microsoft Recommended User Mode Block List in use contains a
      Deny rule on Microsoft.Management.Services.IntuneWindowsAgent.exe
      at MinimumFileVersion 1.46.204.0. In WDAC blocklist semantics, this
      blocks versions <= 1.46.204.0. Explicit deny beats MI trust, so a
      device with IME at or below that floor will not be able to act as
      an MI even after this script runs successfully. This is acceptable
      and matches Microsoft's recommended secure baseline; IME above the
      floor (delivered via normal Intune auto-update) will work.

    * HVCI / VBS is enforced on this device baseline. This does not
      affect AppLocker MI operation.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$LogRoot = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\CustomManagedInstaller'
$PrimaryLogFile = Join-Path -Path $LogRoot -ChildPath 'Remediate-CustomManagedInstaller.log'
$FallbackLogRoot = Join-Path -Path $env:TEMP -ChildPath 'CustomManagedInstaller'
$FallbackLogFile = Join-Path -Path $FallbackLogRoot -ChildPath 'Remediate-CustomManagedInstaller.log'

# Script-scoped runtime state, populated by Initialize-Log. $script:LogFile
# is what Write-Log writes to; $script:LogInitError captures any reason the
# primary path was rejected so we can log it on the very first line.
$script:LogFile = $PrimaryLogFile
$script:LogInitError = $null

$MaxLogSizeBytes = 5MB
$MaxLogRollFiles = 5

function Initialize-Log {
    <#
        Bulletproof log initializer.
        - Never throws. Any failure to prepare a path is swallowed and the
          next candidate is tried.
        - Tries primary path first, then $env:TEMP fallback.
        - Returns the path that ultimately succeeded (or $null if neither
          succeeded, in which case Write-Log will only emit to stdout).
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CandidatePaths,
        [Parameter(Mandatory = $true)]
        [int64]$MaxBytes,
        [Parameter(Mandatory = $true)]
        [int]$MaxRollFiles
    )

    foreach ($Path in $CandidatePaths) {
        try {
            $folder = Split-Path -Path $Path -Parent
            if (-not (Test-Path -LiteralPath $folder)) {
                New-Item -Path $folder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            if (Test-Path -LiteralPath $Path) {
                $size = (Get-Item -LiteralPath $Path -ErrorAction Stop).Length
                if ($size -ge $MaxBytes) {
                    for ($i = $MaxRollFiles - 1; $i -ge 1; $i--) {
                        $older = "{0}.{1}" -f $Path, $i
                        $newer = "{0}.{1}" -f $Path, ($i + 1)
                        if (Test-Path -LiteralPath $older) {
                            if ($i -eq ($MaxRollFiles - 1)) {
                                Remove-Item -LiteralPath $older -Force -ErrorAction SilentlyContinue
                            }
                            else {
                                Move-Item -LiteralPath $older -Destination $newer -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                    Move-Item -LiteralPath $Path -Destination ("{0}.1" -f $Path) -Force -ErrorAction SilentlyContinue
                }
            }

            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -ItemType File -Force -ErrorAction Stop | Out-Null
            }

            # Final proof-of-write probe: a zero-byte append must succeed
            # before we commit to this path as the live log.
            [System.IO.File]::AppendAllText($Path, [string]::Empty)
            return $Path
        }
        catch {
            $script:LogInitError = ("Log path '{0}' rejected: {1}" -f $Path, $_.Exception.Message)
            continue
        }
    }

    return $null
}

function Write-Log {
    <#
        Tee-style writer. Always emits to stdout (so Intune captures it in
        the per-device remediation output panel, first ~2KB) and ALSO appends
        to the active log file if one was successfully initialized. File
        write failures are swallowed so a transient file lock cannot crash
        the script and lose information.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message

    # Always emit to stdout - Intune surfaces this in the remediation portal.
    Write-Output $line

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -ErrorAction Stop
        }
        catch {
            try {
                Add-Content -LiteralPath $FallbackLogFile -Value $line -ErrorAction Stop
            }
            catch {
                # Give up on file logging for this line; stdout already has it.
            }
        }
    }
}

function Get-ManagedInstallerCompliance {
    [OutputType([hashtable])]
    param()

    $result = @{
        IsCompliant = $false
        Reasons     = New-Object System.Collections.Generic.List[string]
    }

    try {
        [xml]$xml = Get-AppLockerPolicy -Effective -Xml
    }
    catch {
        $result.Reasons.Add("Failed to read effective AppLocker policy: $($_.Exception.Message)")
        return $result
    }

    $ruleCollections = @($xml.AppLockerPolicy.RuleCollection)

    $managedInstallerCollection = $ruleCollections | Where-Object { $_.Type -eq 'ManagedInstaller' } | Select-Object -First 1
    if (-not $managedInstallerCollection) {
        $result.Reasons.Add('ManagedInstaller rule collection not found in effective AppLocker policy.')
    }
    else {
        $publisherConditions = @($managedInstallerCollection.FilePublisherRule.Conditions.FilePublisherCondition)

        $hasImeRule = $false
        $hasCitrixRule = $false
        $hasCcmExecRule = $false
        $hasCcmSetupRule = $false

        foreach ($condition in $publisherConditions) {
            if (-not $condition) {
                continue
            }

            if ($condition.PublisherName -like '*MICROSOFT CORPORATION*' -and $condition.BinaryName -ieq 'MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE') {
                $hasImeRule = $true
            }

            if ($condition.PublisherName -like '*CITRIX SYSTEMS*') {
                $hasCitrixRule = $true
            }

            if ($condition.PublisherName -like '*MICROSOFT CORPORATION*' -and $condition.BinaryName -ieq 'CCMEXEC.EXE') {
                $hasCcmExecRule = $true
            }

            if ($condition.PublisherName -like '*MICROSOFT CORPORATION*' -and $condition.BinaryName -ieq 'CCMSETUP.EXE') {
                $hasCcmSetupRule = $true
            }
        }

        if (-not $hasImeRule) {
            $result.Reasons.Add('Intune Management Extension ManagedInstaller rule not found.')
        }

        if (-not $hasCitrixRule) {
            $result.Reasons.Add('Citrix ManagedInstaller rule not found.')
        }

        if (-not $hasCcmExecRule) {
            $result.Reasons.Add('Configuration Manager CCMEXEC.EXE ManagedInstaller rule not found.')
        }

        if (-not $hasCcmSetupRule) {
            $result.Reasons.Add('Configuration Manager CCMSETUP.EXE ManagedInstaller rule not found.')
        }
    }

    $exeCollection = $ruleCollections | Where-Object { $_.Type -eq 'Exe' } | Select-Object -First 1
    $dllCollection = $ruleCollections | Where-Object { $_.Type -eq 'Dll' } | Select-Object -First 1

    if (-not $exeCollection) {
        $result.Reasons.Add('EXE rule collection not found in effective AppLocker policy.')
    }
    else {
        $exeServicesMode = $exeCollection.RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode
        if ($exeServicesMode -ne 'Enabled') {
            $result.Reasons.Add("EXE services enforcement is '$exeServicesMode' instead of 'Enabled'.")
        }
    }

    if (-not $dllCollection) {
        $result.Reasons.Add('DLL rule collection not found in effective AppLocker policy.')
    }
    else {
        $dllServicesMode = $dllCollection.RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode
        if ($dllServicesMode -ne 'Enabled') {
            $result.Reasons.Add("DLL services enforcement is '$dllServicesMode' instead of 'Enabled'.")
        }
    }

    $result.IsCompliant = ($result.Reasons.Count -eq 0)
    return $result
}

function Get-RemediationPolicyXml {
    [OutputType([string])]
    param()

    return @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Benign DENY DLL Rule" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
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
    <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Benign DENY EXE Rule" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
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
    <FilePublisherRule Id="6b4b54fa-002a-478d-a8a0-17089e24a061" Name="Managed Installer - Citrix" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=CITRIX SYSTEMS, INC., L=FORT LAUDERDALE, S=FLORIDA, C=US" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="3cf97403-1b4a-4492-8e70-98436cf78983" Name="Managed Installer - Intune Management Extension" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="6ead5a35-5bac-4fe4-a0a4-be8885012f87" Name="CCM - CCMEXEC.EXE, 5.0.0.0+, Microsoft signed" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="CCMEXEC.EXE">
          <BinaryVersionRange LowSection="5.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="8e23170d-e0b7-4711-b6d0-d208c960f30e" Name="CCM - CCMSETUP.EXE, 5.0.0.0+, Microsoft signed" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="CCMSETUP.EXE">
          <BinaryVersionRange LowSection="5.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
'@
}

# ============================================================================
# ENTRY POINT
# Wrapped in a top-level try/catch so logging/environment failures still
# produce a captured signal via stdout. Intune surfaces the first ~2 KB of
# stdout under the per-device remediation status.
# exit codes:
#   0 = compliant (no change OR remediation succeeded)
#   1 = remediation attempted but device still not compliant, OR unhandled
#       exception (Intune marks the run failed)
# ============================================================================
try {
    $script:LogFile = Initialize-Log -CandidatePaths @($PrimaryLogFile, $FallbackLogFile) -MaxBytes $MaxLogSizeBytes -MaxRollFiles $MaxLogRollFiles

    if ($script:LogInitError) {
        Write-Log -Level 'WARN' -Message $script:LogInitError
    }
    if ($script:LogFile) {
        Write-Log -Level 'INFO' -Message ("Active log file: {0}" -f $script:LogFile)
    }
    else {
        Write-Output ("[{0}] [WARN] Unable to open any log file. Continuing with stdout-only logging." -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'))
    }

    Write-Log -Level 'INFO' -Message 'Starting custom managed installer remediation run.'
    Write-Log -Level 'INFO' -Message ("Log rollover settings: MaxLogSizeBytes={0}; MaxLogRollFiles={1}" -f $MaxLogSizeBytes, $MaxLogRollFiles)
    Write-Log -Level 'INFO' -Message ("PowerShell {0} | PID {1} | User {2} | 64-bit process: {3}" -f $PSVersionTable.PSVersion, $PID, [System.Security.Principal.WindowsIdentity]::GetCurrent().Name, [Environment]::Is64BitProcess)

    $before = Get-ManagedInstallerCompliance
    if ($before.IsCompliant) {
        Write-Log -Level 'INFO' -Message 'Device is already compliant. No remediation needed.'
        exit 0
    }

    foreach ($reason in $before.Reasons) {
        Write-Log -Level 'WARN' -Message ("Pre-remediation gap: {0}" -f $reason)
    }

    Write-Log -Level 'INFO' -Message 'Ensuring AppIDSvc is enabled and running.'
    # AppIDSvc (Application Identity) ships Manual by default. AppLocker - and
    # therefore MI tagging - cannot operate unless this service is Automatic
    # and Running. We log each step explicitly rather than silently swallowing
    # errors, because a failure here means the policy will be inert.
    #
    # Why sc.exe first instead of Set-Service:
    # PowerShell's Set-Service writes multiple service properties under the
    # hood (start type, display name, description). On AppIDSvc the
    # description has a protected ACL and the write throws Access Denied
    # even when the start-type change itself succeeds. sc.exe config only
    # changes the start type and is the Microsoft-documented way to do it.
    $scExe = Join-Path -Path $env:SystemRoot -ChildPath 'System32\sc.exe'
    $startTypeSet = $false

    if (Test-Path -LiteralPath $scExe) {
        try {
            # NOTE: 'start=' MUST have a trailing space before the value (sc.exe quirk).
            $scOutput = & $scExe config AppIDSvc start= auto 2>&1
            $scExit = $LASTEXITCODE
            Write-Log -Level 'INFO' -Message ("sc.exe config AppIDSvc start= auto exit code: {0}; output: {1}" -f $scExit, ($scOutput -join ' | '))
            if ($scExit -eq 0) { $startTypeSet = $true }
        }
        catch {
            Write-Log -Level 'WARN' -Message ("sc.exe config AppIDSvc start= auto threw: {0}" -f $_.Exception.Message)
        }
    }

    # Fallback to Set-Service only if sc.exe failed. Set-Service is more
    # likely to error here but is included for completeness.
    if (-not $startTypeSet) {
        try {
            Set-Service -Name 'AppIDSvc' -StartupType Automatic -ErrorAction Stop
            Write-Log -Level 'INFO' -Message 'AppIDSvc startup type set to Automatic via Set-Service fallback.'
            $startTypeSet = $true
        }
        catch {
            Write-Log -Level 'WARN' -Message ("Set-Service fallback also failed: {0}" -f $_.Exception.Message)
        }
    }

    # Verify the final startup type. Even if both setters reported failure,
    # one may have partially applied.
    try {
        $svcCheck = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
        Write-Log -Level 'INFO' -Message ("AppIDSvc post-change StartType: {0}; Status: {1}" -f $svcCheck.StartType, $svcCheck.Status)
    }
    catch {
        Write-Log -Level 'WARN' -Message ("Unable to query AppIDSvc state: {0}" -f $_.Exception.Message)
    }

    try {
        $svcBefore = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
        if ($svcBefore.Status -ne 'Running') {
            Start-Service -Name 'AppIDSvc' -ErrorAction Stop
            Write-Log -Level 'INFO' -Message 'AppIDSvc started.'
        }
        else {
            Write-Log -Level 'INFO' -Message 'AppIDSvc was already running.'
        }
    }
    catch {
        Write-Log -Level 'WARN' -Message ("Failed to start AppIDSvc: {0}" -f $_.Exception.Message)
    }

    # Initialize the AppLocker Managed Installer subsystem (loads applockerfltr,
    # wires up MI telemetry). '-mionly' opts out of ISG because the environment
    # trusts MI via WDAC Option 13 only (Option 14 / ISG is not in use).
    $appidtel = Join-Path -Path $env:SystemRoot -ChildPath 'System32\appidtel.exe'
    if (Test-Path -Path $appidtel) {
        Write-Log -Level 'INFO' -Message ('Running appidtel.exe start -mionly to activate Managed Installer tracking.')
        try {
            $appidtelOutput = & $appidtel start -mionly 2>&1
            $appidtelExit = $LASTEXITCODE
            if ($appidtelOutput) {
                Write-Log -Level 'INFO' -Message ('appidtel output: {0}' -f ($appidtelOutput -join ' | '))
            }
            Write-Log -Level 'INFO' -Message ('appidtel.exe exit code: {0}' -f $appidtelExit)
        }
        catch {
            Write-Log -Level 'WARN' -Message ('appidtel.exe invocation failed: {0}' -f $_.Exception.Message)
        }
    }
    else {
        Write-Log -Level 'WARN' -Message ('appidtel.exe not found at {0}. Managed Installer subsystem may not initialize.' -f $appidtel)
    }

    # Write temp policy file. Each step wrapped so we get a specific error
    # message rather than a generic "Remediation failed" from the master catch.
    $policyXml = Get-RemediationPolicyXml
    $tempPolicyPath = Join-Path -Path $env:TEMP -ChildPath 'CustomManagedInstallerPolicy.xml'
    try {
        Set-Content -LiteralPath $tempPolicyPath -Value $policyXml -Encoding UTF8 -ErrorAction Stop
        Write-Log -Level 'INFO' -Message ("Wrote merge-source policy to {0} ({1} bytes)." -f $tempPolicyPath, (Get-Item -LiteralPath $tempPolicyPath).Length)
    }
    catch {
        Write-Log -Level 'ERROR' -Message ("Failed to write merge-source policy file '{0}': {1}" -f $tempPolicyPath, $_.Exception.Message)
        throw
    }

    Write-Log -Level 'INFO' -Message ("Merging AppLocker policy from {0}" -f $tempPolicyPath)
    try {
        Set-AppLockerPolicy -XmlPolicy $tempPolicyPath -Merge -ErrorAction Stop
        Write-Log -Level 'INFO' -Message 'Set-AppLockerPolicy -Merge completed.'
    }
    catch {
        Write-Log -Level 'ERROR' -Message ("Set-AppLockerPolicy -Merge failed: {0}" -f $_.Exception.Message)
        throw
    }

    # ---- Force AppLocker to re-evaluate the merged policy --------------------
    # Set-AppLockerPolicy writes the new rules to the local store but the
    # running AppIDSvc instance keeps an in-memory snapshot of the effective
    # policy. Without a restart, Get-AppLockerPolicy -Effective can return the
    # pre-merge view, producing false "rule not found" results on the
    # post-remediation compliance check.
    try {
        Write-Log -Level 'INFO' -Message 'Restarting AppIDSvc to force AppLocker to load the merged policy.'
        Restart-Service -Name 'AppIDSvc' -Force -ErrorAction Stop
        Write-Log -Level 'INFO' -Message 'AppIDSvc restarted.'
    }
    catch {
        Write-Log -Level 'WARN' -Message ("Failed to restart AppIDSvc post-merge: {0}" -f $_.Exception.Message)
    }

    # Brief grace period for the service to rebuild its in-memory policy view.
    Start-Sleep -Seconds 3

    # ---- Diagnostic: dump what is now in the LOCAL ManagedInstaller store ---
    # We read -Local (not -Effective) so we can see exactly what our merge
    # wrote, independent of any CSP-deployed rules. If the LOCAL view doesn't
    # contain our rules, the merge silently dropped them. If the LOCAL view
    # does contain them but -Effective doesn't, AppLocker has a caching or
    # store-precedence issue worth investigating.
    try {
        $localXml = [xml](Get-AppLockerPolicy -Local -Xml)
        $localMi = @($localXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'ManagedInstaller' } | Select-Object -First 1)
        if ($localMi -and $localMi[0]) {
            $localPub = @($localMi[0].FilePublisherRule.Conditions.FilePublisherCondition)
            Write-Log -Level 'INFO' -Message ("[Diag] LOCAL store ManagedInstaller rule count: {0}" -f $localPub.Count)
            foreach ($p in $localPub) {
                if ($p) {
                    Write-Log -Level 'INFO' -Message ("[Diag] LOCAL MI rule: PublisherName='{0}' BinaryName='{1}'" -f $p.PublisherName, $p.BinaryName)
                }
            }
        }
        else {
            Write-Log -Level 'WARN' -Message '[Diag] LOCAL store has no ManagedInstaller RuleCollection after merge.'
        }
    }
    catch {
        Write-Log -Level 'WARN' -Message ("[Diag] Failed to read LOCAL AppLocker policy: {0}" -f $_.Exception.Message)
    }

    # ---- Diagnostic: same dump from EFFECTIVE view (CSP + Local merged) -----
    try {
        $effXml = [xml](Get-AppLockerPolicy -Effective -Xml)
        $effMi = @($effXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'ManagedInstaller' } | Select-Object -First 1)
        if ($effMi -and $effMi[0]) {
            $effPub = @($effMi[0].FilePublisherRule.Conditions.FilePublisherCondition)
            Write-Log -Level 'INFO' -Message ("[Diag] EFFECTIVE ManagedInstaller rule count: {0}" -f $effPub.Count)
            foreach ($p in $effPub) {
                if ($p) {
                    Write-Log -Level 'INFO' -Message ("[Diag] EFFECTIVE MI rule: PublisherName='{0}' BinaryName='{1}'" -f $p.PublisherName, $p.BinaryName)
                }
            }
        }
        else {
            Write-Log -Level 'WARN' -Message '[Diag] EFFECTIVE policy has no ManagedInstaller RuleCollection after merge.'
        }
    }
    catch {
        Write-Log -Level 'WARN' -Message ("[Diag] Failed to read EFFECTIVE AppLocker policy: {0}" -f $_.Exception.Message)
    }

    $after = Get-ManagedInstallerCompliance
    if ($after.IsCompliant) {
        Write-Log -Level 'INFO' -Message 'Remediation successful. Device is now compliant.'
        exit 0
    }

    foreach ($reason in $after.Reasons) {
        Write-Log -Level 'ERROR' -Message ("Post-remediation gap: {0}" -f $reason)
    }

    Write-Log -Level 'ERROR' -Message 'Remediation attempted but compliance requirements are still not fully met.'
    exit 1
}
catch {
    # Master safety net: never let an unhandled exception swallow the reason.
    $errMsg = ("Remediation failed (unhandled): {0} | At: {1}" -f $_.Exception.Message, $_.InvocationInfo.PositionMessage)
    try { Write-Log -Level 'ERROR' -Message $errMsg } catch { Write-Output $errMsg }
    exit 1
}
```
