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
