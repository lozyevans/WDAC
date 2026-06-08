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

    Environment-specific notes (verify against your own tenant's App
    Control / AppLocker configuration before deploying):

    * WDAC Option 13 (Enabled:Managed Installer) is assumed to be ALREADY
      enabled on the base App Control policies in the environment. When
      that is the case, no additional WDAC change is required for MI trust
      to take effect.

    * If a WDAC supplemental policy already trusts Citrix binaries directly
      (CertPublisher + per-file hash), the MI rule is COMPLEMENTARY: the
      supplemental allows Citrix binaries to execute; the MI rule
      additionally lets files Citrix writes inherit MI trust.

    * If an existing AppLocker CSP profile deploys ONLY a Script rule
      collection at Grouping="Native", this script writes Dll / Exe /
      ManagedInstaller collections to the LOCAL AppLocker store. The two
      stores are separate; AppLocker evaluates the union, so there is no
      conflict.

    * Any previous custom OMA-URI MI profile and AppId tagging device CSP
      profile should be REMOVED. AppId tagging is a different feature from
      AppLocker MI; it
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
    # use in the environment denies Microsoft.Management.Services.IntuneWindowsAgent.exe
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
    # Where the existing CSP-deployed AppLocker policy contains only
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
