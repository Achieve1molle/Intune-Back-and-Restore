<#!
.SYNOPSIS
    Intune Backup + Single-File Restore (Option A).
    Provides a WPF UI and CLI to back up Microsoft Intune configuration and to restore exactly one configuration JSON at a time.
    Backups can be timestamped with optional retention; restores always POST (never PATCH) and ensure unique names.

.DESCRIPTION
    This script supports three modes via -Mode: UI, Backup, and Restore.
      • UI: Launches the WPF interface (auto-relaunches in STA if needed) with actions to run backups, perform single-file restores,
        test the app connection, save/load config (no secrets), open output/log folders, and create a nightly Scheduled Task.
      • Backup: Connects to Microsoft Graph (app-only) and exports key Intune artifacts to JSON (e.g., device configurations—
        excluding WUfB from that set, settings catalog via beta, compliance policies, scripts, assignment filters, enrollment configs,
        Autopilot profiles, app protection policies, Windows Update rings/profiles, and more). Optional timestamp folder and retention.
      • Restore (Option A): Takes exactly one .json file and issues a POST to the appropriate Graph collection. It strips read-only
        properties, optionally appends a timestamp, fetches existing objects to guarantee uniqueness by name, and commits only when
        -ForceRestore is present; otherwise it performs a dry run (plan only).

.NOTES
 Author  : Michael Molle
 Date    : 2025-10-30
    • Logging:
        - Backup logs:  "<OutputPath>\Intune-OptionA-Backup-YYYYMMDD-HHMMSS.log"
          (If -UseTimestampFolder, logs live under the timestamped subfolder.)
        - Restore logs: same folder as the input JSON.
    • Scheduled Task automation:
        - The UI’s “Create Nightly Task” stores your client secret using DPAPI at:
              C:\ProgramData\IntuneBR\secret.bin
          and registers a daily 2:00 AM task that runs Backup with your current UI settings.
        - At runtime, the engine loads the secret via -SecretPath (no secret on disk in plain text, no secret in configs).
    • Profiles & endpoints:
        - Uses Microsoft Graph v1.0 by default; -AutoBeta/-UseBeta selects beta for entities that require it.
    • Safety & idempotency:
        - Restore mode never overwrites in place; it POSTs a new object and guarantees name uniqueness.
    • Support:
        - Run the companion Pre-Install-Prerequisites.ps1 once per host before first use.
        - Use the UI “Test App Connection” to validate Tenant/App/Secret prior to backup/restore.

.SCRIPT REQUIREMENTS
    • PowerShell 7.x (Core) – recommended
      (Windows PowerShell 5.1 is supported; UI still works as the script auto-handles STA relaunch.)
    • .NET Windows Desktop Runtime 8+ (x64) – required for WPF UI mode.
    • Microsoft.Graph PowerShell SDK modules.
        Install via:
            Install-Module Microsoft.Graph -Scope CurrentUser
    • Execution Policy: must allow this script to run.
        Recommended for ad-hoc runs:
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    • If the script was downloaded from the internet, unblock it:
            Unblock-File -Path .\Intune-BackupRestore.ps1
    • Optional: ScheduledTasks module (for creating the recurring task from the UI).
        On most client OSes it’s present by default; on Windows Server, install if needed:
            Install-WindowsFeature RSAT-ScheduledTasks
    • Azure AD App Registration with Graph app-only permissions:
        - Backup requires read permissions (e.g., DeviceManagementConfiguration.Read.All, etc.).
        - Restore requires write permissions (e.g., DeviceManagementConfiguration.ReadWrite.All, etc.).
    • Admin rights are required to register a scheduled task and to write to the target output path.
    • Network egress to https://graph.microsoft.com.

    Companion Script:
      A helper script named “Pre-Install-Prerequisites.ps1” is included in the same GitHub repo. Run it once per host to
      pre-install/validate all prerequisites before launching this script:
          pwsh -NoProfile -ExecutionPolicy Bypass -File .\Pre-Install-Prerequisites.ps1
.COMMAND LINE EXAMPLES
    # Launch the UI
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\Intune-BackupRestore.ps1 -Mode UI

    # Backup (CLI) with timestamp folder, keep last 10, enable AutoBeta and diagnostics
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\Intune-BackupRestore.ps1 `
        -Mode Backup `
        -AuthMode App `
        -TenantId "<your-tenant-guid>" `
        -AppId "<your-app-id>" `
        -ClientSecretPlain "<your-client-secret>" `
        -OutputPath "C:\Staging\Backup" `
        -UseTimestampFolder `
        -RetentionCount 10 `
        -AutoBeta `
        -Diag

    # Backup including managed devices (slower)
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\Intune-BackupRestore.ps1 `
        -Mode Backup -AuthMode App -TenantId "<tenant>" -AppId "<appId>" -ClientSecretPlain "<secret>" `
        -OutputPath "C:\Staging\Backup" -UseTimestampFolder -RetentionCount 7 -IncludeManagedDevices

    # Restore (dry run; plan only, no changes) of a single JSON file
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\Intune-BackupRestore.ps1 `
        -Mode Restore `
        -AuthMode App `
        -TenantId "<tenant>" `
        -AppId "<appId>" `
        -ClientSecretPlain "<secret>" `
        -InputPath "C:\Staging\Backup\deviceConfigurations\My Policy.json"

    # Restore (commit), append timestamp to name to ensure uniqueness
    pwsh -NoProfile -ExecutionPolicy Bypass -File .\Intune-BackupRestore.ps1 `
        -Mode Restore `
        -AuthMode App `
        -TenantId "<tenant>" `
        -AppId "<appId>" `
        -ClientSecretPlain "<secret>" `
        -InputPath "C:\Backups\configurationPolicies\My Settings Catalog.json" `
        -ForceRestore `
        -AppendTimestamp

    # (Task Scheduler) If creating manually, your Action can invoke:
    #   Program:  pwsh.exe
    #   Arguments:
    #     -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Path\Intune-BackupRestore.ps1"
    #       -Mode Backup -AuthMode App -TenantId "<tenant>" -AppId "<appId>" -OutputPath "C:\Staging\Backup"
    #       -UseTimestampFolder -RetentionCount 10 -AutoBeta -Diag -SecretPath "C:\ProgramData\IntuneBR\secret.bin"
    #
    # Note: Use the UI’s “Create Nightly Task” button to (a) DPAPI-encrypt and save your client secret to
    #       C:\ProgramData\IntuneBR\secret.bin and (b) register a 2:00 AM daily task with the proper arguments.

.CHANGELOG
    2025-10-30 (v1.1.x)
      • Sign-first & relaunch-in-same-window behavior for consistent signature trust.
      • Prerequisite checks are detect-only; installs are handled by the companion Pre-Install-Prerequisites.ps1.
      • UI polish: aligned action rows, dedicated Cancel on Restore, “Open logs” link; logo removed.
      • Single-file restore (Option A) always uses POST and ensures unique names (timestamp/suffix strategy).
      • Added/confirmed exports: settings catalog (beta), device configs (excluding WUfB from that set),
        compliance policies, scripts (device & health), assignment filters, terms & enrollment configs,
        Autopilot profiles, app protection policies, Windows Update rings/feature/quality updates, endpoint security intents.
#>
[CmdletBinding()]
param(
    [ValidateSet('UI','Backup','Restore')][string]$Mode = 'UI',
    [ValidateSet('App')][string]$AuthMode = 'App',

    # Shared auth
    [string]$TenantId,
    [string]$AppId,
    [string]$ClientSecretPlain,

    # Backup
    [string]$OutputPath = 'C:\Staging\Backup',
    [switch]$UseTimestampFolder,
    [int]$RetentionCount = 10,
    [switch]$IncludeManagedDevices,

    # Restore (Option A: single JSON file only)
    [string]$InputPath,
    [switch]$ForceRestore,      # unchecked Dry run => not present; checked (Commit) => present
    [switch]$AppendTimestamp,   # default ON via UI

    # Graph / diagnostics
    [switch]$UseBeta,
    [switch]$AutoBeta,
    [switch]$Diag,

    # DPAPI secret fallback (engine/scheduled task only; never written to config)
    [string]$SecretPath,

    # --- INTERNAL one-run sentinel to avoid self-sign relaunch loops ---
    [switch]$__Child
)

# ------------------------------ Globals ------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:BuildVersion = 'v337k2m_optionA_1.1.7b_signFirst_childSentinel_uiPolish_silentUI'
$script:LogPath=$null; $script:LogFolder=$null; $script:RunTs=$null

# =================== Self-sign FIRST (skipped in child) ===================
function Ensure-CodeSigning {
    [OutputType([bool])]  # returns $false if already signed; otherwise relaunches and exits the parent
    param([Parameter(Mandatory)][string]$ScriptPath)

    # If this is the child of the signing relaunch, DO NOT sign again.
    if ($__Child.IsPresent) { return $false }

    # If already validly signed, do nothing
    try { $sig = Get-AuthenticodeSignature -FilePath $ScriptPath -ErrorAction SilentlyContinue } catch { $sig = $null }
    if ($sig -and $sig.Status -eq 'Valid') { return $false }

    Write-Host "[SIGN] Generating self-signed code signing certificate..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=IntuneBR Self-Signed" -CertStoreLocation Cert:\CurrentUser\My

    # Trust for current user
    try { Copy-Item -Path $cert.PSPath -Destination 'Cert:\CurrentUser\TrustedPublisher' -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Copy-Item -Path $cert.PSPath -Destination 'Cert:\CurrentUser\Root'             -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Sign this script
    Set-AuthenticodeSignature -FilePath $ScriptPath -Certificate $cert | Out-Null

    # Locate pwsh (fallback to Windows PowerShell)
    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
    if (-not $pwsh) { $pwsh = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" }

    # Rebuild ONLY the script's arguments (no function-only params; do not echo ClientSecretPlain)
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass')
    if ($Mode -eq 'UI') { $argList += '-STA' }
    $argList += @('-File',("`"$ScriptPath`""))

    function AddArg([string]$name, $value, [switch]$IsSwitch) {
        if ($IsSwitch) {
            if (($value -is [switch] -and $value.IsPresent) -or ($value -is [bool] -and $value)) { $script:__args += "-$name" }
            return
        }
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            $script:__args += "-$name"; $script:__args += ("`"$value`"")
        }
    }

    $script:__args = $argList  # working list for AddArg

    # Mirror param(...) — OMIT ClientSecretPlain on purpose
    AddArg 'Mode'                  $Mode
    AddArg 'AuthMode'              $AuthMode
    AddArg 'TenantId'              $TenantId
    AddArg 'AppId'                 $AppId
    AddArg 'OutputPath'            $OutputPath
    AddArg 'UseTimestampFolder'    $UseTimestampFolder    -IsSwitch
    AddArg 'RetentionCount'        $RetentionCount
    AddArg 'IncludeManagedDevices' $IncludeManagedDevices -IsSwitch
    AddArg 'InputPath'             $InputPath
    AddArg 'ForceRestore'          $ForceRestore          -IsSwitch
    AddArg 'AppendTimestamp'       $AppendTimestamp       -IsSwitch
    AddArg 'UseBeta'               $UseBeta               -IsSwitch
    AddArg 'AutoBeta'              $AutoBeta              -IsSwitch
    AddArg 'Diag'                  $Diag                  -IsSwitch
    AddArg 'SecretPath'            $SecretPath

    # One-run child sentinel so the child skips signing entirely
    $script:__args += '-__Child'

    $argList = $script:__args
    Remove-Variable -Name __args -Scope Script -ErrorAction SilentlyContinue

    # Relaunch in the SAME window and WAIT; exit with child's code
    $proc = Start-Process -FilePath $pwsh `
                          -ArgumentList ($argList -join ' ') `
                          -WorkingDirectory (Get-Location).Path `
                          -NoNewWindow `
                          -PassThru

    # Suppress the message in UI mode (still wait silently for a clean exit)
    if ($Mode -ne 'UI') {
        Write-Host "[SIGN] Relaunched as PID $($proc.Id). Waiting for child to complete..."
    }

    $proc.WaitForExit()
    exit $proc.ExitCode
}

# --- Sign first; if we signed, the parent will exit (child continues). ---
$null = Ensure-CodeSigning -ScriptPath $PSCommandPath
# (If already signed, or we are the child, we return and continue.)

# =================== Detect-only Prereqs (no install here) ===================
function Assert-Prereqs {
    param([ValidateSet('UI','Backup','Restore')] [string]$Mode = 'UI')

    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    # 1) Microsoft.Graph SDK present?
    $graphOk = $false
    try { $null = Get-Command Connect-MgGraph -ErrorAction Stop; $graphOk = $true } catch {}

    # 2) .NET Windows Desktop Runtime 8+ for WPF UI?
    $desktopOk = $true
    if ($Mode -eq 'UI') {
        $desktopOk = $false
        try {
            $out = & dotnet --list-runtimes 2>$null
            foreach ($ln in ($out -split "`n")) {
                if ($ln -match 'Microsoft\.WindowsDesktop\.App\s+([0-9]+)\.') {
                    if ([int]$Matches[1] -ge 8) { $desktopOk = $true; break }
                }
            }
        } catch {}
    }

    # 3) ScheduledTasks module (needed for Create Nightly Task button).
    $schedOk = $true
    try { Import-Module ScheduledTasks -ErrorAction Stop | Out-Null } catch { $schedOk = $false }

    if (-not $graphOk -or -not $desktopOk -or -not $schedOk) {
        $msgs = @()
        if (-not $graphOk)  { $msgs += " - Microsoft.Graph PowerShell SDK is missing" }
        if (-not $desktopOk){ $msgs += " - .NET Windows Desktop Runtime 8+ (x64) is missing (UI only)" }
        if (-not $schedOk)  { $msgs += " - ScheduledTasks module unavailable (needed for 'Create Nightly Task')" }

        $hint = @(
            "Run the Pre-Install Prerequisites script first (once per host), e.g.:",
            "  pwsh -NoProfile -ExecutionPolicy Bypass -File .\Pre-Install-Prerequisites.ps1",
            "",
            "Then re-run this script."
        ) -join [Environment]::NewLine
        throw ("Prerequisites not satisfied:" + [Environment]::NewLine +
               ($msgs -join [Environment]::NewLine) + [Environment]::NewLine +
               [Environment]::NewLine + $hint)
    }
}

# Run prereq checks AFTER signing (so the child process enforces them)
Assert-Prereqs -Mode $Mode

# ====================== Logging + DPAPI ======================
function New-Log([string]$stage){
    $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $script:RunTs = $ts
    if ($stage -eq 'Backup' -and $UseTimestampFolder) { $script:LogFolder = Join-Path $OutputPath $script:RunTs }
    elseif ($stage -eq 'Restore' -and $InputPath)     { $script:LogFolder = Split-Path -Parent $InputPath }
    else                                             { $script:LogFolder = $OutputPath }
    if (-not (Test-Path -LiteralPath $script:LogFolder)) { New-Item -ItemType Directory -Path $script:LogFolder -Force | Out-Null }
    $script:LogPath = Join-Path $script:LogFolder ("Intune-OptionA-" + $stage + '-' + $ts + '.log')
    Add-Content -Path $script:LogPath -Value ("[{0}] [INFO] LAUNCH {1} (UseBeta={2}, AutoBeta={3}, Diag={4})" -f ((Get-Date).ToString('s'),$stage,[bool]$UseBeta,[bool]$AutoBeta,[bool]$Diag))
    Add-Content -Path $script:LogPath -Value ("[{0}] [INFO] BuildVersion: {1}" -f ((Get-Date).ToString('s'),$script:BuildVersion))
}
function Log([string]$level,[string]$message){ try { Add-Content -Path $script:LogPath -Value ("[{0}] [{1}] {2}" -f ((Get-Date).ToString('s'), $level.ToUpperInvariant(), $message)) } catch {} }
function Signal-UI([string]$state,[string]$exit){ try { $script:UiState=$state; $script:UiExit=$exit } catch {} }

# DPAPI helpers (engine/scheduled task only)
Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Security.Cryptography
function Get-EntropyBytes([string]$TenantId,[string]$AppId){ [Text.Encoding]::UTF8.GetBytes(("IntuneBR`n" + $TenantId + "`n" + $AppId)) }
function Save-DpapiSecret {
    param([Parameter(Mandatory)][string]$Secret,[Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$TenantId,[Parameter(Mandatory)][string]$AppId)
    $dir = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $bytes = [Text.Encoding]::UTF8.GetBytes($Secret)
    $entropy = Get-EntropyBytes -TenantId $TenantId -AppId $AppId
    $prot = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes($Path, $prot)
}
function Read-DpapiSecret{
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$TenantId,[Parameter(Mandatory)][string]$AppId)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Secret file not found: $Path" }
    $protected = [IO.File]::ReadAllBytes($Path)
    $entropy = Get-EntropyBytes -TenantId $TenantId -AppId $AppId
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($protected, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Text.Encoding]::UTF8.GetString($bytes)
}

# ====================== Graph helpers ======================
$script:GraphProfile='v1.0'
function Ensure-GraphProfile{
    $wantBeta=($UseBeta -or $AutoBeta); $profile= if($wantBeta){'beta'}else{'v1.0'}
    if(Get-Command Select-MgProfile -ErrorAction SilentlyContinue){ try { Select-MgProfile -Name $profile } catch {} }
    $script:GraphProfile=$profile
    Log 'INFO' ("Graph profile: " + $script:GraphProfile)
}
function Log-GraphVersions{
    try{
        (Get-Module Microsoft.Graph* -ListAvailable |
            Group-Object Name |
            ForEach-Object { $_.Group | Sort-Object Version -Descending | Select-Object -First 1 }) |
        ForEach-Object { Log 'INFO' ("Module {0} v{1}" -f $_.Name,$_.Version) }
    }catch{}
}

# ---- Robust APP-ONLY AUTH (resilient across SDK param sets) ----
function Connect-GraphApp([string]$TenantId,[string]$AppId,[string]$ClientSecretPlain){
    if(-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)){
        throw 'Microsoft.Graph module is required. Install-Module Microsoft.Graph -Scope CurrentUser'
    }
    if([string]::IsNullOrWhiteSpace($ClientSecretPlain)){
        throw "Client secret is empty. Provide ClientSecretPlain or configure SecretPath."
    }

    $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
    $hasClientSecret = $cmd.Parameters.ContainsKey('ClientSecret')
    $hasClientSecretCredential = $cmd.Parameters.ContainsKey('ClientSecretCredential')
    Log 'INFO' ("AUTH: ParamSets => -ClientSecret={0}, -ClientSecretCredential={1}" -f $hasClientSecret,$hasClientSecretCredential)

    if ($hasClientSecret) {
        Log 'INFO' 'AUTH: Using ClientId/ClientSecret path'
        Connect-MgGraph -TenantId $TenantId -ClientId $AppId -ClientSecret $ClientSecretPlain -NoWelcome -ErrorAction Stop | Out-Null
    }
    elseif ($hasClientSecretCredential) {
        try { $ptype = $cmd.Parameters['ClientSecretCredential'].ParameterType.FullName } catch { $ptype = '' }
        if ($ptype -eq 'System.Management.Automation.PSCredential' -or [string]::IsNullOrEmpty($ptype)) {
            $sec = ConvertTo-SecureString -String $ClientSecretPlain -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential($AppId,$sec)
            Log 'INFO' 'AUTH: Using ClientSecretCredential (PSCredential) fallback'
            Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome -ErrorAction Stop | Out-Null
        }
        else {
            try {
                $aicred = [Azure.Identity.ClientSecretCredential]::new($TenantId,$AppId,$ClientSecretPlain)
                Log 'INFO' 'AUTH: Using ClientSecretCredential (Azure.Identity) fallback'
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $aicred -NoWelcome -ErrorAction Stop | Out-Null
            } catch {
                throw 'Azure.Identity not available for ClientSecretCredential path. Install Microsoft.Graph.Authentication >= 2.x'
            }
        }
    }
    else {
        throw 'No supported Client Secret parameter set was found in Connect-MgGraph.'
    }
    Log 'INFO' ("Connected to Graph. Tenant=" + $TenantId + "; Profile=" + $script:GraphProfile)
}

function Invoke-GraphJson {
    param([Parameter(Mandatory)][string]$Uri,[ValidateSet('v1.0','beta')][string]$Profile=$script:GraphProfile,[int]$PageSize=100)
    $base= if($Profile -eq 'beta'){ 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }
    $url = $base + $Uri + '?$top=' + $PageSize
    $all=@()
    do{
        $respObj = $null
        try{
            $hr = Invoke-MgGraphRequest -Method GET -Uri $url -OutputType HttpResponseMessage -ErrorAction Stop
            $json = $hr.Content.ReadAsStringAsync().Result
            $respObj = $json | ConvertFrom-Json -ErrorAction Stop
        } catch {
            try{
                $ps = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop
                $json = $ps | ConvertTo-Json -Depth 20 -Compress
                $respObj = $json | ConvertFrom-Json -ErrorAction Stop
            } catch {
                Log 'ERROR' ("GET failed: " + $_.Exception.Message); break
            }
        }
        $items=@()
        if($respObj -and $respObj.PSObject -and $respObj.PSObject.Properties['value']){ $items = $respObj.value }
        elseif($respObj -is [System.Array]){ $items = $respObj } else { $items = @($respObj) }
        if($items -ne $null){ $all += $items }
        $url = if ($respObj.PSObject -and $respObj.PSObject.Properties['@odata.nextLink']) { $respObj.'@odata.nextLink' } else { $null }
    } while($url)
    return $all
}

# ====================== Backup helpers ======================
function Ensure-Dir([string]$path){ if(-not (Test-Path $path)){ New-Item -ItemType Directory -Path $path -Force | Out-Null } }
function Extract-Items([object]$obj){ if($null -eq $obj){ return @() }; if($obj.PSObject -and $obj.PSObject.Properties['value']){ return @($obj.value) }; if($obj -is [System.Array]){ return @($obj) }; if($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])){ return @($obj) }; return @($obj) }
function SafeCount([object]$x){ try{ return ((Extract-Items $x) | Measure-Object).Count } catch { return 0 } }
function Write-JsonFile([object]$obj,[string]$path){ try{ $json = ConvertTo-Json -InputObject $obj -Depth 20 -Compress -ErrorAction Stop } catch { $json = ConvertTo-Json -InputObject ([string]$obj) -Depth 3 -Compress }; $utf8 = New-Object System.Text.UTF8Encoding($false); [System.IO.File]::WriteAllText($path, $json, $utf8) }
function Read-JsonFile([string]$path){ [IO.File]::ReadAllText($path,[Text.UTF8Encoding]::new($false)) | ConvertFrom-Json -ErrorAction Stop }
function Save-Items([object[]]$items,[string]$dir){
    $items = Extract-Items $items
    foreach($it in $items){
        $o = $it
        if($o -is [string]){ try{ $o = $o | ConvertFrom-Json -ErrorAction Stop }catch{} }
        $disp=$null; try{ $disp=$o.displayName }catch{}; if([string]::IsNullOrWhiteSpace($disp)){ try{ $disp=$o.name }catch{} }
        $id=$null; try{ $id=$o.id }catch{}; if([string]::IsNullOrWhiteSpace($id)){ $id = ([guid]::NewGuid().ToString('N')).Substring(0,8) }
        $safeName = if ([string]::IsNullOrWhiteSpace($disp)) { $id } else { $disp }
        $safe = $safeName -replace '[\\/:*"<>\n\r]', '_'
        $path = Join-Path $dir ($safe + '.json')
        Write-JsonFile -obj $o -path $path
    }
}
function Export-Entity([string]$name,[string]$uri,[string]$dir,[string]$profile='v1.0'){
    Log 'INFO' ("[STAGE] Fetching " + $name)
    $d = Invoke-GraphJson -Uri $uri -Profile $profile
    Ensure-Dir $dir
    Save-Items @($d) $dir
    Write-JsonFile -obj $d -path (Join-Path $dir 'index.json')
    Log 'INFO' ("[STAGE] Completed " + $name + (" (count={0})" -f (SafeCount $d)))
}
# Keep Update Rings out of deviceConfigurations
function Export-DeviceConfigurationsClean([string]$dir) {
    Log 'INFO' "[STAGE] Fetching deviceConfigurations (excluding Windows Update rings)"
    $d = Invoke-GraphJson -Uri '/deviceManagement/deviceConfigurations' -Profile 'v1.0'
    $d = @($d) | Where-Object { $_.'@odata.type' -notlike '*windowsUpdateForBusinessConfiguration*' }
    Ensure-Dir $dir
    Save-Items @($d) $dir
    Write-JsonFile -obj $d -path (Join-Path $dir 'index.json')
    Log 'INFO' ("[STAGE] Completed deviceConfigurations (count={0})" -f (($d | Measure-Object).Count))
}
function Run-Backup{
    param([string]$TenantId,[string]$AppId,[string]$ClientSecretPlain,[string]$OutputPath,[int]$RetentionCount)
    New-Log 'Backup'
    Ensure-GraphProfile
    Log-GraphVersions

    if([string]::IsNullOrWhiteSpace($ClientSecretPlain) -and -not [string]::IsNullOrWhiteSpace($SecretPath)){
        try { $ClientSecretPlain = Read-DpapiSecret -Path $SecretPath -TenantId $TenantId -AppId $AppId; Log 'INFO' 'Client secret loaded from DPAPI.' }
        catch { Log 'ERROR' ("DPAPI read failed: " + $_.Exception.Message); throw }
    }

    Connect-GraphApp -TenantId $TenantId -AppId $AppId -ClientSecretPlain $ClientSecretPlain

    $root = $OutputPath
    if ($UseTimestampFolder) { $root = Join-Path $OutputPath $script:RunTs; Ensure-Dir $root }

    # Device configurations (cleaned)
    Export-DeviceConfigurationsClean (Join-Path $root 'deviceConfigurations')

    # Settings Catalog & others (beta)
    Export-Entity 'configurationPolicies (beta)' '/deviceManagement/configurationPolicies' (Join-Path $root 'configurationPolicies') 'beta'

    # Compliance policies
    Export-Entity 'deviceCompliancePolicies' '/deviceManagement/deviceCompliancePolicies' (Join-Path $root 'deviceCompliancePolicies') 'v1.0'

    # Scripts
    Export-Entity 'deviceManagementScripts (beta)' '/deviceManagement/deviceManagementScripts' (Join-Path $root 'deviceManagementScripts') 'beta'
    Export-Entity 'deviceHealthScripts (beta)' '/deviceManagement/deviceHealthScripts' (Join-Path $root 'deviceHealthScripts') 'beta'

    # Assignment Filters, Terms, Enrollment configs, Autopilot
    Export-Entity 'assignmentFilters (beta)' '/deviceManagement/assignmentFilters' (Join-Path $root 'assignmentFilters') 'beta'
    Export-Entity 'termsAndConditions' '/deviceManagement/termsAndConditions' (Join-Path $root 'termsAndConditions') 'v1.0'
    Export-Entity 'deviceEnrollmentConfigurations' '/deviceManagement/deviceEnrollmentConfigurations' (Join-Path $root 'deviceEnrollmentConfigurations') 'v1.0'
    Export-Entity 'autopilotProfiles' '/deviceManagement/windowsAutopilotDeploymentProfiles' (Join-Path $root 'windowsAutopilotDeploymentProfiles') 'v1.0'

    # ---- Re-added collections for parity ----
    Export-Entity 'mobileApps' '/deviceAppManagement/mobileApps' (Join-Path $root 'mobileApps') 'v1.0'
    Export-Entity 'windowsUpdateRings' '/deviceManagement/windowsUpdateRings' (Join-Path $root 'windowsUpdateRings') 'v1.0'
    Export-Entity 'windowsFeatureUpdates' '/deviceManagement/windowsFeatureUpdateProfiles' (Join-Path $root 'windowsFeatureUpdates') 'v1.0'
    Export-Entity 'windowsQualityUpdates' '/deviceManagement/windowsQualityUpdateProfiles' (Join-Path $root 'windowsQualityUpdates') 'v1.0'
    Export-Entity 'appProtectionPolicies' '/deviceAppManagement/managedAppPolicies' (Join-Path $root 'appProtectionPolicies') 'v1.0'
    Export-Entity 'endpointSecurity (intents)' '/deviceManagement/intents' (Join-Path $root 'endpointSecurity') 'beta'
    Export-Entity 'securityBaselines (templates)' '/deviceManagement/templates' (Join-Path $root 'securityBaselines') 'beta'

    if ($IncludeManagedDevices) {
        Export-Entity 'managedDevices' '/deviceManagement/managedDevices' (Join-Path $root 'managedDevices') 'v1.0'
    }

    Log 'INFO' ("[STAGE] Backup complete. Output: " + $root)
    try {
        if ($UseTimestampFolder -and $RetentionCount -gt 0) {
            $tsDirs = Get-ChildItem -Path $OutputPath -Directory |
                Where-Object { $_.Name -match '^\d{8}[-_]\d{6}$' } |
                Sort-Object Name -Descending
            $keep = [Math]::Max($RetentionCount,1)
            $toRemove = $tsDirs | Select-Object -Skip $keep
            foreach($d in $toRemove){ try{ Remove-Item -Path $d.FullName -Recurse -Force } catch { Log 'WARN' ("Retention delete failed: " + $_.Exception.Message) } }
        }
    } catch { Log 'WARN' ("Retention step failed: " + $_.Exception.Message) }
    Signal-UI 'Complete' '0'
}

# ====================== Restore (single JSON) ======================
function Normalize-ForCreate([hashtable]$obj){
    foreach($k in @('id','createdDateTime','lastModifiedDateTime','version','roleScopeTagIds','supportsScopeTags')){
        if($obj.ContainsKey($k)){ $obj.Remove($k) | Out-Null }
    }
    return $obj
}
function Add-RestoreSuffix([hashtable]$h) {
    $suffix = (Get-Date).ToString('yyyyMMdd-HHmmss')
    if ($h.ContainsKey('displayName') -and -not [string]::IsNullOrWhiteSpace($h['displayName'])) {
        $h['displayName'] = ("{0} ({1})" -f $h['displayName'], $suffix)
    } elseif ($h.ContainsKey('name') -and -not [string]::IsNullOrWhiteSpace($h['name'])) {
        $h['name'] = ("{0} ({1})" -f $h['name'], $suffix)
    }
    return $h
}
function Ensure-UniqueByName([hashtable]$h,[object[]]$existing){
    $prop = if ($h.ContainsKey('displayName')) { 'displayName' } elseif ($h.ContainsKey('name')) { 'name' } else { $null }
    if (-not $prop) { return $h }
    $value = [string]$h[$prop]
    if ([string]::IsNullOrWhiteSpace($value)) { return $h }

    $names = @($existing | ForEach-Object {
        if ($_.PSObject.Properties['displayName']) { $_.displayName }
        elseif ($_.PSObject.Properties['name'])     { $_.name }
    }) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($names -notcontains $value) { return $h }

    $i=2
    while($true){
        $candidate = ("{0} - {1:yyyyMMdd-HHmmss}-{2:D2}" -f $value, (Get-Date), $i)
        if ($names -notcontains $candidate) { $h[$prop]=$candidate; break }
        $i++
    }
    return $h
}
function Resolve-TargetUri([string]$odataType){
    $t = [string]$odataType
    if (-not $t) { $t = '' }
    $t = $t.ToLowerInvariant()
    if ($t -like '*windowsupdateforbusinessconfiguration*') { return '/deviceManagement/deviceConfigurations' }
    if ($t -like '*deviceconfiguration*')                   { return '/deviceManagement/deviceConfigurations' }
    if ($t -like '*devicecompliancepolicy*')                { return '/deviceManagement/deviceCompliancePolicies' }
    if ($t -like '*devicemanagementscript*')                { return '/deviceManagement/deviceManagementScripts' }
    if ($t -like '*devicehealthscript*')                    { return '/deviceManagement/deviceHealthScripts' }
    if ($t -like '*assignmentfilter*')                      { return '/deviceManagement/assignmentFilters' }
    if ($t -like '*termsandconditions*')                    { return '/deviceManagement/termsAndConditions' }
    if ($t -like '*deviceenrollmentconfiguration*')         { return '/deviceManagement/deviceEnrollmentConfigurations' }
    if ($t -like '*windowsautopilotdeploymentprofile*')     { return '/deviceManagement/windowsAutopilotDeploymentProfiles' }
    if ($t -like '*managedappprotection*' -or $t -like '*windowsinformationprotection*') { return '/deviceAppManagement/managedAppPolicies' }
    return '/deviceManagement/deviceConfigurations'
}
function Run-Restore{
    param([string]$TenantId,[string]$AppId,[string]$ClientSecretPlain,[string]$InputPath,[switch]$ForceRestore,[switch]$AppendTimestamp)
    if (-not (Test-Path -LiteralPath $InputPath)) { throw "InputPath not found: $InputPath" }
    if ((Split-Path -Leaf $InputPath) -notmatch '\.json$') { throw "InputPath must point to a single .json file." }

    New-Log 'Restore'
    Ensure-GraphProfile
    Log-GraphVersions

    try {
        if([string]::IsNullOrWhiteSpace($ClientSecretPlain) -and -not [string]::IsNullOrWhiteSpace($SecretPath)){
            try { $ClientSecretPlain = Read-DpapiSecret -Path $SecretPath -TenantId $TenantId -AppId $AppId; Log 'INFO' 'Client secret loaded from DPAPI (restore).' }
            catch { Log 'ERROR' ("DPAPI read failed: " + $_.Exception.Message); throw }
        }

        Connect-GraphApp -TenantId $TenantId -AppId $AppId -ClientSecretPlain $ClientSecretPlain

        $obj = Get-Content -Path $InputPath -Raw | ConvertFrom-Json -ErrorAction Stop
        $h = @{}; $obj.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value }
        $norm = Normalize-ForCreate $h

        $odataType = ''
        if ($obj.PSObject.Properties['@odata.type']) { $odataType = [string]$obj.'@odata.type' }
        $targetUri = Resolve-TargetUri $odataType
        if ($AppendTimestamp) { $norm = Add-RestoreSuffix $norm }

        $existing = Invoke-GraphJson -Uri $targetUri -Profile $script:GraphProfile
        $norm = Ensure-UniqueByName $norm $existing

        $base = if ($script:GraphProfile -eq 'beta') { 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }

        if ($ForceRestore) {
            $body = (ConvertTo-Json -InputObject $norm -Depth 20 -Compress)
            $hr = Invoke-MgGraphRequest -Method POST -Uri ($base + $targetUri) -Body $body -ContentType 'application/json' -OutputType HttpResponseMessage -ErrorAction Stop
            [void]$hr.StatusCode
            Log 'INFO' "[STAGE] Single-file restore committed (POST)."
        } else {
            Log 'INFO' ("DRY-RUN would POST to {0}" -f $targetUri)
        }

        Signal-UI 'Complete' '0'
    }
    finally { try { Signal-UI 'Complete' '0' } catch {} }
}

# ====================== UI ======================
if($Mode -eq 'UI'){
    # Relaunch with -STA if needed
    try { $ap = [Threading.Thread]::CurrentThread.ApartmentState } catch { $ap = 'MTA' }
    if ($ap -ne 'STA') {
        $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
        if (-not $pwsh) { $pwsh = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" }
        $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',"`"$PSCommandPath`"",' -Mode','UI')
        foreach($kv in $PSBoundParameters.GetEnumerator()){
            $name=$kv.Key; $value=$kv.Value
            if ($name -eq 'Mode') { continue }
            if ($null -eq $value -or $name -in @('ClientSecretPlain')) { continue }
            if ($value -is [switch]) { if ($value.IsPresent) { $argList += "-$name" } }
            else { $argList += "-$name"; $argList += ("`"$value`"") }
        }
        $proc = Start-Process -FilePath $pwsh -ArgumentList ($argList -join ' ') -PassThru -NoNewWindow
        Write-Host "[UI] Relaunched in STA as PID $($proc.Id). Exiting non-STA instance..."
        exit 0
    }

    Add-Type -AssemblyName PresentationFramework,PresentationCore

    # ---- Window XAML (logo removed; aligned action rows; links; title restored) ----
    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
 xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
 Title="Achieve One-Leadership to Adapt-Expertise to Achieve"
 Height="600" Width="1020" WindowStartupLocation="CenterScreen">
 <Grid Margin="12">
  <Grid.RowDefinitions>
   <RowDefinition Height="Auto"/>
   <RowDefinition Height="*"/>
  </Grid.RowDefinitions>

  <Border x:Name="HeaderBorder" Grid.Row="0" Background="#FFFFFFFF" BorderBrush="#DDDDDD" BorderThickness="1" CornerRadius="4" Padding="8" Margin="0,0,0,8">
    <TextBlock x:Name="AppTitleBlock" Text="Intune Backup and Restore" TextAlignment="Center" HorizontalAlignment="Center" FontSize="13" Foreground="#333333"/>
  </Border>

  <TabControl x:Name="MainTabs" Grid.Row="1" Margin="0,0,0,0">

    <!-- BACKUP TAB -->
    <TabItem Header="Backup">
      <Grid Margin="10">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,8">
          <TextBlock Width="140" VerticalAlignment="Center">TenantId:</TextBlock>
          <TextBox x:Name="TenantBox" MinWidth="520"/>
        </StackPanel>

        <StackPanel Orientation="Horizontal" Grid.Row="1" Margin="0,0,0,8">
          <TextBlock Width="140" VerticalAlignment="Center">AppId:</TextBlock>
          <TextBox x:Name="AppIdBox" MinWidth="520"/>
        </StackPanel>

        <StackPanel Orientation="Horizontal" Grid.Row="2" Margin="0,0,0,8">
          <TextBlock Width="140" VerticalAlignment="Center">Client Secret:</TextBlock>
          <PasswordBox x:Name="SecretBox" MinWidth="520"/>
        </StackPanel>

        <StackPanel Orientation="Horizontal" Grid.Row="3" Margin="0,0,0,8">
          <TextBlock Width="140" VerticalAlignment="Center">Output Path:</TextBlock>
          <TextBox x:Name="OutputBox" MinWidth="520" Text="C:\Staging\Backup"/>
        </StackPanel>

        <StackPanel Orientation="Horizontal" Grid.Row="4" Margin="0,0,0,8">
          <CheckBox x:Name="TimestampChk" IsChecked="True">Use timestamp folder</CheckBox>
          <TextBlock Margin="20,0,6,0" VerticalAlignment="Center">Keep last:</TextBlock>
          <TextBox x:Name="RetentionBox" Width="60" Text="10"/>
          <CheckBox x:Name="AutoBetaChk" Margin="20,0,0,0" IsChecked="True">AutoBeta</CheckBox>
          <CheckBox x:Name="DiagChk" Margin="20,0,0,0">Diagnostics</CheckBox>
        </StackPanel>

        <StackPanel Orientation="Horizontal" Grid.Row="5" Margin="0,0,0,8">
          <CheckBox x:Name="IncludeManagedChk" Margin="0,0,0,0" IsChecked="False">Include managed devices (slow)</CheckBox>
        </StackPanel>

        <!-- Backup actions row (left-to-right) -->
        <StackPanel Orientation="Horizontal" Grid.Row="5" Margin="0,36,0,0">
          <Button x:Name="BackupBtn" Width="160" Height="34">Run Backup</Button>
          <Button x:Name="CancelBtn" Width="120" Height="34" Margin="6,0,0,0" IsEnabled="False">Cancel</Button>
          <Button x:Name="SaveCfgBtn" Width="120" Height="34" Margin="10,0,0,0">Save Config</Button>
          <Button x:Name="LoadCfgBtn" Width="120" Height="34" Margin="6,0,0,0">Load Config</Button>
          <Button x:Name="CreateTaskBtn" Width="160" Height="34" Margin="6,0,0,0">Create Nightly Task</Button>
          <Button x:Name="TestConnBtn" Width="160" Height="34" Margin="6,0,0,0">Test App Connection</Button>
        </StackPanel>

        <StackPanel Grid.Row="6" Orientation="Vertical">
          <TextBlock x:Name="StatusText" Margin="0,4,0,6" Foreground="#333333"/>
          <StackPanel Orientation="Horizontal">
            <TextBlock x:Name="OutputLink" Foreground="#0063b1" TextDecorations="Underline" Cursor="Hand" Visibility="Collapsed">Open backup folder</TextBlock>
          </StackPanel>
        </StackPanel>

      </Grid>
    </TabItem>

    <!-- RESTORE TAB -->
    <TabItem Header="Restore (single JSON)">
      <Grid Margin="10">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/> <!-- 0 Tenant -->
          <RowDefinition Height="Auto"/> <!-- 1 AppId -->
          <RowDefinition Height="Auto"/> <!-- 2 Secret -->
          <RowDefinition Height="Auto"/> <!-- 3 File row -->
          <RowDefinition Height="Auto"/> <!-- 4 Options -->
          <RowDefinition Height="Auto"/> <!-- 5 Actions row -->
          <RowDefinition Height="Auto"/> <!-- 6 Status + link -->
          <RowDefinition Height="*"/>   <!-- filler -->
        </Grid.RowDefinitions>

        <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,8">
          <TextBlock Width="140" VerticalAlignment="Center">TenantId:</TextBlock>
          <TextBox x:Name="RTenantBox" MinWidth="520"/>
        </StackPanel>

        <StackPanel Orientation="Horizontal" Grid.Row="1" Margin="0,0,0,8">
          <TextBlock Width="140" VerticalAlignment="Center">AppId:</TextBlock>
          <TextBox x:Name="RAppIdBox" MinWidth="520"/>
        </StackPanel>

        <StackPanel Orientation="Horizontal" Grid.Row="2" Margin="0,0,0,8">
          <TextBlock Width="140" VerticalAlignment="Center">Client Secret:</TextBlock>
          <PasswordBox x:Name="RSecretBox" MinWidth="520"/>
        </StackPanel>

        <Grid Grid.Row="3">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Width="140" VerticalAlignment="Center">JSON file:</TextBlock>
          <TextBox x:Name="InputBox" Grid.Column="1" MinWidth="520" IsReadOnly="True"/>
          <Button x:Name="BrowseBtn" Grid.Column="2" Width="120" Height="28" Margin="8,0,0,0">Browse…</Button>
        </Grid>

        <StackPanel Orientation="Horizontal" Grid.Row="4" Margin="0,8,0,0">
          <CheckBox x:Name="DryRunChk" IsChecked="True">Dry run (plan only, no changes)</CheckBox>
          <CheckBox x:Name="AppendTimestampChk" Margin="20,0,0,0" IsChecked="True">Append date/time to names</CheckBox>
        </StackPanel>

        <!-- Restore actions row (left-to-right like Backup) -->
        <StackPanel Orientation="Horizontal" Grid.Row="5" Margin="0,8,0,0">
          <Button x:Name="RestoreBtn" Width="160" Height="34">Run Restore</Button>
          <Button x:Name="RCancelBtn" Width="120" Height="34" Margin="6,0,0,0" IsEnabled="False">Cancel</Button>
          <Button x:Name="RSaveCfgBtn" Width="120" Height="28" Margin="10,0,0,0">Save Config</Button>
          <Button x:Name="RLoadCfgBtn" Width="120" Height="28" Margin="6,0,0,0">Load Config</Button>
        </StackPanel>

        <StackPanel Orientation="Horizontal" Grid.Row="6" Margin="0,8,0,0">
          <TextBlock x:Name="RStatusText" Margin="0,8,10,0" Foreground="#333333"/>
          <TextBlock x:Name="ROpenLogsLink" Foreground="#0063b1" TextDecorations="Underline" Cursor="Hand" Visibility="Collapsed">Open logs folder</TextBlock>
        </StackPanel>

      </Grid>
    </TabItem>

  </TabControl>
 </Grid>
</Window>
"@

    # XAML load
    try {
        $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
        $win = [Windows.Markup.XamlReader]::Load($reader)
    } catch {
        Write-Host "[UI] XAML load failed: $($_.Exception.Message)"
        if ($Diag) { try { if($script:LogPath){ Add-Content -Path $script:LogPath -Value "[UI] XAML error: $($_.Exception)" } } catch {} }
        throw
    }

    # Controls
    $TenantBox=$win.FindName('TenantBox'); $AppIdBox=$win.FindName('AppIdBox'); $SecretBox=$win.FindName('SecretBox')
    $OutputBox=$win.FindName('OutputBox'); $TimestampChk=$win.FindName('TimestampChk'); $AutoBetaChk=$win.FindName('AutoBetaChk'); $DiagChk=$win.FindName('DiagChk')
    $RetentionBox=$win.FindName('RetentionBox'); $BackupBtn=$win.FindName('BackupBtn'); $StatusText=$win.FindName('StatusText')
    $SaveCfgBtn=$win.FindName('SaveCfgBtn'); $LoadCfgBtn=$win.FindName('LoadCfgBtn'); $CreateTaskBtn=$win.FindName('CreateTaskBtn'); $TestConnBtn=$win.FindName('TestConnBtn')
    $IncludeManagedChk=$win.FindName('IncludeManagedChk'); $CancelBtn=$win.FindName('CancelBtn')
    $RTenantBox=$win.FindName('RTenantBox'); $RAppIdBox=$win.FindName('RAppIdBox'); $RSecretBox=$win.FindName('RSecretBox')
    $InputBox=$win.FindName('InputBox'); $DryRunChk=$win.FindName('DryRunChk'); $AppendTimestampChk=$win.FindName('AppendTimestampChk')
    $RestoreBtn=$win.FindName('RestoreBtn'); $RStatusText=$win.FindName('RStatusText'); $BrowseBtn=$win.FindName('BrowseBtn')
    $RSaveCfgBtn=$win.FindName('RSaveCfgBtn'); $RLoadCfgBtn=$win.FindName('RLoadCfgBtn'); $RCancelBtn=$win.FindName('RCancelBtn')
    $OutputLink=$win.FindName('OutputLink'); $ROpenLogsLink=$win.FindName('ROpenLogsLink')

    function QuoteArg([string]$s){ '"' + ($s -replace '"','\"') + '"' }

    # ====== UI State helpers (disable/enable controls during runs) ======
    function Set-UiRunningState([ValidateSet('Backup','Restore')]$Context, [bool]$Running) {
        if ($Context -eq 'Backup') {
            $TenantBox.IsEnabled = -not $Running
            $AppIdBox.IsEnabled = -not $Running
            $SecretBox.IsEnabled = -not $Running
            $OutputBox.IsEnabled = -not $Running
            $TimestampChk.IsEnabled = -not $Running
            $RetentionBox.IsEnabled = -not $Running
            $AutoBetaChk.IsEnabled = -not $Running
            $DiagChk.IsEnabled = -not $Running
            $IncludeManagedChk.IsEnabled = -not $Running
            $BackupBtn.IsEnabled = -not $Running
            $SaveCfgBtn.IsEnabled = -not $Running
            $LoadCfgBtn.IsEnabled = -not $Running
            $CreateTaskBtn.IsEnabled = -not $Running
            $TestConnBtn.IsEnabled = -not $Running
            $CancelBtn.IsEnabled = $Running
        } else {
            $RTenantBox.IsEnabled = -not $Running
            $RAppIdBox.IsEnabled = -not $Running
            $RSecretBox.IsEnabled = -not $Running
            $InputBox.IsEnabled = -not $Running
            $BrowseBtn.IsEnabled = -not $Running
            $DryRunChk.IsEnabled = -not $Running
            $AppendTimestampChk.IsEnabled = -not $Running
            $RestoreBtn.IsEnabled = -not $Running
            $RSaveCfgBtn.IsEnabled = -not $Running
            $RLoadCfgBtn.IsEnabled = -not $Running
            $RCancelBtn.IsEnabled = $Running
        }
    }

    $script:CurrentProc = $null
    function Monitor-Process([ValidateSet('Backup','Restore')]$Context){
        if (-not $script:CurrentProc) { return }
        [System.Threading.Tasks.Task]::Run({
            try { $script:CurrentProc.WaitForExit() } catch {}
            $ExecutionContext.SessionState.PSVariable.Set('ui_done_action',
                [Action]{
                    try {
                        Set-UiRunningState $Context $false
                        if ($Context -eq 'Backup') { $StatusText.Text = 'Completed.'; $CancelBtn.IsEnabled = $false }
                        else { $RStatusText.Text = 'Completed.'; $RCancelBtn.IsEnabled = $false }
                    } catch {}
                })
            $win.Dispatcher.Invoke($ui_done_action)
        }) | Out-Null
    }

    # ---- Config helpers (NO secrets in/out) ----
    function Get-UiConfig {
        $keep=10; [void][int]::TryParse($RetentionBox.Text,[ref]$keep)
        return [ordered]@{
            Version = $script:BuildVersion
            TenantId = $TenantBox.Text
            AppId = $AppIdBox.Text
            OutputPath = $OutputBox.Text
            UseTimestampFolder = [bool]$TimestampChk.IsChecked
            RetentionCount = $keep
            AutoBeta = [bool]$AutoBetaChk.IsChecked
            Diagnostics = [bool]$DiagChk.IsChecked
            IncludeManagedDevices = [bool]$IncludeManagedChk.IsChecked
            RestoreTenantId = $RTenantBox.Text
            RestoreAppId = $RAppIdBox.Text
        }
    }
    function Read-JsonFile([string]$path){ [IO.File]::ReadAllText($path,[Text.UTF8Encoding]::new($false)) | ConvertFrom-Json -ErrorAction Stop }
    function To-Hashtable([object]$obj){ if($obj -is [hashtable]){return $obj}; $ht=@{}; foreach($p in $obj.PSObject.Properties){ $ht[$p.Name]=$p.Value }; $ht }
    function Set-UiConfig([object]$cfg){
        $cfg = To-Hashtable $cfg
        if($cfg.ContainsKey('TenantId')){$TenantBox.Text = [string]$cfg.TenantId}
        if($cfg.ContainsKey('AppId')){$AppIdBox.Text = [string]$cfg.AppId}
        if($cfg.ContainsKey('OutputPath')){$OutputBox.Text = [string]$cfg.OutputPath}
        if($cfg.ContainsKey('UseTimestampFolder')){$TimestampChk.IsChecked = [bool]$cfg.UseTimestampFolder}
        if($cfg.ContainsKey('RetentionCount')){$RetentionBox.Text = [string]$cfg.RetentionCount}
        if($cfg.ContainsKey('AutoBeta')){$AutoBetaChk.IsChecked = [bool]$cfg.AutoBeta}
        if($cfg.ContainsKey('Diagnostics')){$DiagChk.IsChecked = [bool]$cfg.Diagnostics}
        if($cfg.ContainsKey('IncludeManagedDevices')){$IncludeManagedChk.IsChecked = [bool]$cfg.IncludeManagedDevices}
        if($cfg.ContainsKey('RestoreTenantId')){$RTenantBox.Text = [string]$cfg.RestoreTenantId}
        if($cfg.ContainsKey('RestoreAppId')){$RAppIdBox.Text = [string]$cfg.RestoreAppId}
    }

    # ---- Engine launcher ----
    function Start-Engine([ValidateSet('Backup','Restore')][string]$mode,[hashtable]$payload){
        $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
        if(-not $pwsh){ $pwsh = "$env:WINDIR\System32\WindowsPowerShell`v1.0\powershell.exe" }
        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', (QuoteArg ((Resolve-Path $PSCommandPath).ProviderPath)), '-Mode', $mode, '-AuthMode','App')
        # IMPORTANT: emit ForceRestore/AppendTimestamp as true switches
        foreach($k in $payload.Keys){
            $v = [string]$payload[$k]
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            if ($v -eq 'True' -and $k -in @('ForceRestore','AppendTimestamp')) { $args += ('-' + $k); continue }
            $args += @('-' + $k, (QuoteArg ([string]$v)))
        }
        if($AutoBetaChk.IsChecked){ $args += '-AutoBeta' }
        if($mode -eq 'Backup' -and $TimestampChk.IsChecked){ $args += '-UseTimestampFolder' }
        if($DiagChk.IsChecked){ $args += '-Diag' }
        if($mode -eq 'Backup' -and $IncludeManagedChk.IsChecked){ $args += '-IncludeManagedDevices' }
        if($script:SecretPath){ $args += @('-SecretPath',(QuoteArg $script:SecretPath)) }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $pwsh; $psi.Arguments = ($args -join ' ')
        $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        $script:CurrentProc = $p

        # Toggle UI state & start monitor
        if($mode -eq 'Backup'){
            Set-UiRunningState 'Backup' $true
            Monitor-Process 'Backup'
        } else {
            Set-UiRunningState 'Restore' $true
            Monitor-Process 'Restore'
        }
    }

    # ---- Links: open folders ----
    $OutputLink.Add_MouseLeftButtonUp({ if($OutputLink.Tag){ Start-Process explorer.exe $OutputLink.Tag } })
    $ROpenLogsLink.Add_MouseLeftButtonUp({ if($ROpenLogsLink.Tag){ Start-Process explorer.exe $ROpenLogsLink.Tag } })

    # ---- Backup buttons ----
    $BackupBtn.Add_Click({
        $keep=10; [void][int]::TryParse($RetentionBox.Text,[ref]$keep)
        $payload=@{ TenantId=$TenantBox.Text; AppId=$AppIdBox.Text; ClientSecretPlain=($SecretBox.Password); OutputPath=$OutputBox.Text; RetentionCount=$keep }
        if([string]::IsNullOrWhiteSpace($payload['TenantId']) -or
           [string]::IsNullOrWhiteSpace($payload['AppId']) -or
           [string]::IsNullOrWhiteSpace($payload['ClientSecretPlain'])){
            $StatusText.Text = 'Please fill TenantId, AppId, and Client Secret.'
            return
        }

        try {
            if(-not [string]::IsNullOrWhiteSpace($OutputBox.Text)){
                if(-not (Test-Path -LiteralPath $OutputBox.Text)){
                    New-Item -ItemType Directory -Path $OutputBox.Text -Force | Out-Null
                }
                $OutputLink.Visibility='Visible'
                $OutputLink.Tag=$OutputBox.Text
                $OutputLink.Text='Open backup folder'
            }
        } catch {}

        Start-Engine 'Backup' $payload
        try { $StatusText.Text = 'Backup started. Monitor the backup folder (link below) for status.' } catch {}
    })

    $CancelBtn.Add_Click({
        try {
            if ($script:CurrentProc -and -not $script:CurrentProc.HasExited) {
                Stop-Process -Id $script:CurrentProc.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        try { $StatusText.Text = 'Cancelled.' } catch {}
        Set-UiRunningState 'Backup' $false
    })

    $SaveCfgBtn.Add_Click({
        try {
            $cfg = Get-UiConfig
            $dlg = New-Object Microsoft.Win32.SaveFileDialog
            $dlg.Filter = "Config (*.json)|*.json"
            $dlg.FileName = "IntuneBR.config.json"
            if ($dlg.ShowDialog() -ne $true) { return }
            $json = ConvertTo-Json -InputObject $cfg -Depth 10 -Compress
            Set-Content -Path $dlg.FileName -Value $json -Encoding UTF8
            $StatusText.Text = "Config saved: $($dlg.FileName)"
        } catch { $StatusText.Text = "Save Config failed: $($_.Exception.Message)" }
    })

    $LoadCfgBtn.Add_Click({
        try {
            $ofd = New-Object Microsoft.Win32.OpenFileDialog
            $ofd.Filter = "Config (*.json)|*.json"
            if ($ofd.ShowDialog() -ne $true) { return }
            $cfg = Read-JsonFile -path $ofd.FileName
            Set-UiConfig -cfg $cfg
            $StatusText.Text = "Config loaded: $($ofd.FileName)"
        } catch { $StatusText.Text = "Load Config failed: $($_.Exception.Message)" }
    })

    # Create Nightly Task (stores secret via DPAPI if needed)
    $CreateTaskBtn.Add_Click({
        try {
            if([string]::IsNullOrWhiteSpace($TenantBox.Text) -or [string]::IsNullOrWhiteSpace($AppIdBox.Text) -or [string]::IsNullOrWhiteSpace($SecretBox.Password) -or [string]::IsNullOrWhiteSpace($OutputBox.Text)){
                $StatusText.Text = "Please fill TenantId, AppId, Client Secret, and Output Path."
                return
            }
            $defaultSecretPath = Join-Path $env:ProgramData "IntuneBR\secret.bin"
            if(-not (Test-Path (Split-Path -Parent $defaultSecretPath))){ New-Item -ItemType Directory -Path (Split-Path -Parent $defaultSecretPath) -Force | Out-Null }
            Save-DpapiSecret -Secret $SecretBox.Password -Path $defaultSecretPath -TenantId $TenantBox.Text -AppId $AppIdBox.Text
            $script:SecretPath = $defaultSecretPath

            $scriptPath = (Resolve-Path $PSCommandPath).ProviderPath
            $args = @('-NoProfile','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File',"`"$scriptPath`"",' -Mode','Backup',
                      ' -TenantId',"`"$($TenantBox.Text)`"",' -AppId',"`"$($AppIdBox.Text)`"",' -OutputPath',"`"$($OutputBox.Text)`"",' -RetentionCount',"$([int]$RetentionBox.Text)")
            if($TimestampChk.IsChecked){ $args += ' -UseTimestampFolder' }
            if($AutoBetaChk.IsChecked){ $args += ' -AutoBeta' }
            if($DiagChk.IsChecked){ $args += ' -Diag' }
            if($IncludeManagedChk.IsChecked){ $args += ' -IncludeManagedDevices' }
            if($script:SecretPath){ $args += @(' -SecretPath',"`"$script:SecretPath`"") }

            $action = New-ScheduledTaskAction -Execute (Get-Command pwsh).Source -Argument ($args -join '')
            $trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            $taskName = "IntuneBR Nightly Backup"
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Intune Backup nightly" -Force | Out-Null
            $StatusText.Text = "Scheduled task created: $taskName (2:00 AM daily)"
        } catch { $StatusText.Text = "Create Task failed: $($_.Exception.Message)" }
    })

    # Test App Connection
    $TestConnBtn.Add_Click({
        try {
            if([string]::IsNullOrWhiteSpace($TenantBox.Text) -or [string]::IsNullOrWhiteSpace($AppIdBox.Text)){
                $StatusText.Text = "Enter TenantId and AppId (and secret)."; return
            }
            $secret = $SecretBox.Password
            if([string]::IsNullOrWhiteSpace($secret) -and $script:SecretPath){
                try { $secret = Read-DpapiSecret -Path $script:SecretPath -TenantId $TenantBox.Text -AppId $AppIdBox.Text } catch {}
            }
            if([string]::IsNullOrWhiteSpace($secret)){ $StatusText.Text = "Client Secret is required."; return }
            Ensure-GraphProfile
            Connect-GraphApp -TenantId $TenantBox.Text -AppId $AppIdBox.Text -ClientSecretPlain $secret
            $StatusText.Text = "Connection OK."
        } catch { $StatusText.Text = "Connection failed: $($_.Exception.Message)" }
    })

    # ---- Restore buttons ----
    $RSaveCfgBtn.Add_Click({
        try {
            $cfg = Get-UiConfig
            $dlg = New-Object Microsoft.Win32.SaveFileDialog
            $dlg.Filter = "Config (*.json)|*.json"
            $dlg.FileName = "IntuneBR.config.json"
            if ($dlg.ShowDialog() -ne $true) { return }
            $json = ConvertTo-Json -InputObject $cfg -Depth 10 -Compress
            Set-Content -Path $dlg.FileName -Value $json -Encoding UTF8
            $RStatusText.Text = "Config saved: $($dlg.FileName)"
        } catch { $RStatusText.Text = "Save Config failed: $($_.Exception.Message)" }
    })
    $RLoadCfgBtn.Add_Click({
        try {
            $ofd = New-Object Microsoft.Win32.OpenFileDialog
            $ofd.Filter = "Config (*.json)|*.json"
            if ($ofd.ShowDialog() -ne $true) { return }
            $cfg = Read-JsonFile -path $ofd.FileName
            Set-UiConfig -cfg $cfg
            $RStatusText.Text = "Config loaded: $($ofd.FileName)"
        } catch { $RStatusText.Text = "Load Config failed: $($_.Exception.Message)" }
    })
    $BrowseBtn.Add_Click({
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = "JSON (*.json)|*.json"
        $dlg.Multiselect = $false
        if ($dlg.ShowDialog() -eq $true) {
            $InputBox.Text = $dlg.FileName
            # Pre-populate Restore "Open logs" link (restore logs live next to the JSON by design)
            try { $ROpenLogsLink.Tag = Split-Path -Parent $dlg.FileName; $ROpenLogsLink.Visibility='Visible' } catch {}
            $RStatusText.Text = "Selected: $($dlg.FileName)"
        }
    })
    $RestoreBtn.Add_Click({
        $payload=@{ TenantId=$RTenantBox.Text; AppId=$RAppIdBox.Text; ClientSecretPlain=($RSecretBox.Password); InputPath=$InputBox.Text }
        if(-not $DryRunChk.IsChecked){ $payload['ForceRestore']='True' }
        if($AppendTimestampChk.IsChecked){ $payload['AppendTimestamp']='True' }
        if([string]::IsNullOrWhiteSpace($payload['TenantId']) -or [string]::IsNullOrWhiteSpace($payload['AppId']) -or [string]::IsNullOrWhiteSpace($payload['ClientSecretPlain']) -or [string]::IsNullOrWhiteSpace($payload['InputPath'])){
            $RStatusText.Text = 'Please fill TenantId, AppId, Client Secret, and select a JSON file.'; return
        }
        try { if ($InputBox.Text) { $ROpenLogsLink.Tag = Split-Path -Parent $InputBox.Text; $ROpenLogsLink.Visibility='Visible' } } catch {}
        Start-Engine 'Restore' $payload
        $RStatusText.Text = 'Restore started…'
    })
    $RCancelBtn.Add_Click({
        try {
            if ($script:CurrentProc -and -not $script:CurrentProc.HasExited) {
                Stop-Process -Id $script:CurrentProc.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        try { $RStatusText.Text = 'Cancelled.' } catch {}
        Set-UiRunningState 'Restore' $false
    })

    [void]$win.ShowDialog()
    return
}

# ====================== Mode Switch ======================
try{
    switch($Mode){
        'Backup' { Run-Backup -TenantId $TenantId -AppId $AppId -ClientSecretPlain $ClientSecretPlain -OutputPath $OutputPath -RetentionCount $RetentionCount }
        'Restore'{ Run-Restore -TenantId $TenantId -AppId $AppId -ClientSecretPlain $ClientSecretPlain -InputPath $InputPath -ForceRestore:$ForceRestore -AppendTimestamp:$AppendTimestamp }
        'UI'     { } # UI already launched
    }
}
catch{
    try{ Log 'ERROR' ("Unhandled: " + $_.Exception.Message) }catch{}
    throw
}
``