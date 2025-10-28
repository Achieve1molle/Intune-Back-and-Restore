<#! 
.SYNOPSIS
    Intune Backup and Restore Automation Script with Automated Task Scheduler. Powered by Achieve one

.DESCRIPTION
    This script provides automated backup and restore capabilities for Microsoft Intune configurations using Microsoft Graph API.
    It supports both UI-based and command-line modes, with secure credential handling via DPAPI and scheduled task creation.

    Key capabilities include:
    - Backup of Intune entities such as device configurations, compliance policies, scripts, apps, and more.
    - Restore functionality with optional dry-run mode.
    - Secure storage of secrets using DPAPI (LocalMachine scope).
    - UI interface for ease of use.
    - Scheduled nightly backup task creation.
    - OAuth2 client credentials flow validation.
    - Support for Microsoft Graph v1.0 and beta profiles.
    - Automatic retention management of backup folders.

.SCRIPT REQUIREMENTS
    - PowerShell 7.x (Core)
    - Windows Desktop Runtime (for WPF UI support)
    - Microsoft.Graph PowerShell SDK modules
        Install via: Install-Module Microsoft.Graph -Scope CurrentUser
    - Execution Policy: Must allow script execution
        Recommended: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    - Unblock the script if downloaded from the internet:
        Unblock-File -Path .\Intune-BackupRestore.ps1
    - Optional: ScheduledTasks module (for task creation)
        Install via: Install-WindowsFeature RSAT-ScheduledTasks (if not present)

.COMMAND LINE EXAMPLES
    # Run backup with timestamp folder and retention
    pwsh -File .\Intune-BackupRestore.v3.3.7k2m.ps1 -Mode Backup -AuthMode App -TenantId "<tenant>" -AppId "<appid>" -ClientSecretPlain "<secret>" -OutputPath "C:\Staging\Backup" -UseTimestampFolder -RetentionCount 10

    # Run restore with dry-run
    pwsh -File .\Intune-BackupRestore.v3.3.7k2m.ps1 -Mode Restore -AuthMode App -TenantId "<tenant>" -AppId "<appid>" -ClientSecretPlain "<secret>" -InputPath "C:\Staging\Backup\latest"

    # Run restore with object creation
    pwsh -File .\Intune-BackupRestore.v3.3.7k2m.ps1 -Mode Restore -AuthMode App -TenantId "<tenant>" -AppId "<appid>" -ClientSecretPlain "<secret>" -InputPath "C:\Staging\Backup\latest" -ForceRestore

    # Launch UI
    pwsh -File .\Intune-BackupRestore.v3.3.7k2m.ps1 -Mode UI

.CHANGELOG
    Beta 1.0.1
    - UI completion and status fixes
    - Scheduled task creation with DPAPI secret storage
    - OAuth2 client credentials validation
    - Graph profile selection and fallback
    - Improved logging and error handling

.NOTES
    Script Version : Beta
    Author         : Michael Molle
    Last Updated   : 2025-10-27
#>
[CmdletBinding()]
param(
  [ValidateSet('UI','Backup','Restore')][string]$Mode = 'UI',
  [ValidateSet('App')][string]$AuthMode = 'App',
  [string]$TenantId,
  [string]$AppId,
  [string]$ClientSecretPlain,
  [string]$OutputPath = 'C:\Staging\Backup',
  [switch]$UseTimestampFolder,
  [int]$RetentionCount = 10,
  [string]$InputPath,
  [switch]$ForceRestore,
  [switch]$UseBeta,
  [switch]$AutoBeta,
  [string]$UiStatePath,
  [string]$UiExitPath,
  [switch]$Diag,
  # DPAPI runtime fallback
  [string]$SecretPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:BuildVersion = 'v3.3.7k2m_patched'
$script:LogPath=$null; $script:LogFolder=$null; $script:RunTs=$null
if (-not (Test-Path variable:script:RunningTimers)) { $script:RunningTimers = New-Object System.Collections.ArrayList }

function New-Log([string]$stage){
  $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
  $script:RunTs = $ts
  if ($stage -eq 'Backup' -and $UseTimestampFolder) { $script:LogFolder = Join-Path $OutputPath $script:RunTs }
  elseif ($stage -eq 'Restore' -and $InputPath) { $script:LogFolder = $InputPath }
  else { $script:LogFolder = $OutputPath }
  if (-not (Test-Path -LiteralPath $script:LogFolder)) { New-Item -ItemType Directory -Path $script:LogFolder -Force | Out-Null }
  $script:LogPath = Join-Path $script:LogFolder ("Intune-v337k2m-" + $stage + '-' + $ts + '.log')
  Add-Content -Path $script:LogPath -Value ("[{0}] [INFO] LAUNCH {1} (UseBeta={2}, AutoBeta={3}, Diag={4})" -f ((Get-Date).ToString('s'),$stage,[bool]$UseBeta,[bool]$AutoBeta,[bool]$Diag))

  # --- PATCH: tell the UI the real output folder for this run (so it can read state/exit directly) ---
  try {
    if ($UiStatePath) {
      $uiSideBandDir = Split-Path -Path $UiStatePath -Parent
      if (-not [string]::IsNullOrWhiteSpace($uiSideBandDir)) {
        $uiOutDirHint  = Join-Path $uiSideBandDir 'outdir.txt'
        Set-Content -Path $uiOutDirHint -Value $script:LogFolder -Encoding UTF8 -ErrorAction SilentlyContinue
      }
    }
  } catch { }
}

function Log([string]$level,[string]$message){ Add-Content -Path $script:LogPath -Value ("[{0}] [{1}] {2}" -f ((Get-Date).ToString('s'), $level.ToUpperInvariant(), $message)) }
function Ensure-PathParent([string]$p){ try{ $dir = Split-Path -Path $p -Parent; if($dir -and -not (Test-Path -LiteralPath $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null } }catch{ try{ Log 'WARN' ("Ensure-PathParent failed for " + $p + ": " + $_.Exception.Message) }catch{} } }
function Signal-UI([string]$state,[string]$exitCode){ try{ if($UiStatePath){ Ensure-PathParent $UiStatePath; Set-Content -Path $UiStatePath -Value $state -Encoding UTF8 -ErrorAction Stop }; if($UiExitPath -and $exitCode){ Ensure-PathParent $UiExitPath; Set-Content -Path $UiExitPath -Value $exitCode -Encoding UTF8 -ErrorAction Stop } }catch{ try{ Log 'WARN' ("Signal-UI write failed: " + $_.Exception.Message) }catch{} } }

# ====================== DPAPI Helpers ======================
Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Security.Cryptography
function Get-EntropyBytes([string]$TenantId,[string]$AppId){ [Text.Encoding]::UTF8.GetBytes(("IntuneBR`nk2m`n" + $TenantId + "`n" + $AppId)) }
function Save-DpapiSecret{
  param([Parameter(Mandatory)][string]$Secret,[Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$TenantId,[Parameter(Mandatory)][string]$AppId)
  $dir = Split-Path -Path $Path -Parent
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $bytes = [Text.Encoding]::UTF8.GetBytes($Secret)
  $entropy = Get-EntropyBytes -TenantId $TenantId -AppId $AppId
  $prot = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
  [IO.File]::WriteAllBytes($Path, $prot)
  try {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $iflag = [System.Security.AccessControl.InheritanceFlags]::None
    $pflag = [System.Security.AccessControl.PropagationFlags]::None
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl
    $read = [System.Security.AccessControl.FileSystemRights]::Read
    $acl.SetOwner( (New-Object System.Security.Principal.NTAccount('BUILTIN','Administrators')) )
    $acl.AddAccessRule( (New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM',$full,$iflag,$pflag,'Allow')) )
    $acl.AddAccessRule( (New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators',$full,$iflag,$pflag,'Allow')) )
    $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if (-not [string]::IsNullOrWhiteSpace($who)) { $acl.AddAccessRule( (New-Object System.Security.AccessControl.FileSystemAccessRule($who,$read,$iflag,$pflag,'Allow')) ) }
    Set-Acl -Path $Path -AclObject $acl
  } catch { try{ Log 'WARN' ("Set-Acl failed for secret file: " + $_.Exception.Message) }catch{} }
}
function Read-DpapiSecret{
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$TenantId,[Parameter(Mandatory)][string]$AppId)
  if (-not (Test-Path -LiteralPath $Path)) { throw "Secret file not found: $Path" }
  $protected = [IO.File]::ReadAllBytes($Path)
  $entropy = Get-EntropyBytes -TenantId $TenantId -AppId $AppId
  $bytes = [Security.Cryptography.ProtectedData]::Unprotect($protected, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
  return [Text.Encoding]::UTF8.GetString($bytes)
}
# ==========================================================
$script:GraphProfile='v1.0'
function Ensure-GraphProfile{
  $wantBeta=($UseBeta -or $AutoBeta); $profile= if($wantBeta){'beta'}else{'v1.0'}
  if(Get-Command Select-MgProfile -ErrorAction SilentlyContinue){ try{ Select-MgProfile -Name $profile; $script:GraphProfile=$profile; Log 'INFO' ("Graph profile selected: " + $script:GraphProfile) } catch{ $script:GraphProfile=$profile; Log 'WARN' ("Select-MgProfile failed; URLs fallback: " + $_.Exception.Message) } }
  else { $script:GraphProfile=$profile; Log 'WARN' 'Select-MgProfile not found. Using explicit base URLs.' }
}
function Log-GraphVersions{ try{ $mods= Get-Module Microsoft.Graph* -ListAvailable | Sort-Object Name,Version -Descending; $top = $mods | Group-Object Name | ForEach-Object { $_.Group | Select-Object -First 1 }; foreach($m in $top){ Log 'INFO' ("Module: {0} v{1}" -f $m.Name,$m.Version) } }catch{} }
function Connect-GraphApp([string]$TenantId,[string]$AppId,[string]$ClientSecretPlain){
  if(-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)){ throw 'Microsoft.Graph module is required. Install-Module Microsoft.Graph -Scope CurrentUser' }
  $sec = ConvertTo-SecureString -String $ClientSecretPlain -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($AppId,$sec)
  Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome -ErrorAction Stop | Out-Null
  Log 'INFO' ("Connected. Tenant=" + $TenantId + "; Profile=" + $script:GraphProfile)
}
function ConvertTo-PSJson([object]$obj){
  if($null -eq $obj){ return $null }
  $propCount=0; try{ $propCount = ($obj.PSObject.Properties | Measure-Object).Count }catch{ $propCount=0 }
  if($obj -is [psobject] -and $propCount -gt 0){ return $obj }
  $t = $obj.GetType().FullName
  if($t -like '*JsonElement*'){ try{ return ($obj.ToString() | ConvertFrom-Json -ErrorAction Stop) }catch{} }
  if($obj.PSObject -and $obj.PSObject.Properties['Content']){ $c=$obj.Content; if($c -is [string]){ try{ return ($c | ConvertFrom-Json -ErrorAction Stop) }catch{} } }
  if($obj -is [string]){ $s=$obj.Trim(); if($s.StartsWith('{') -or $s.StartsWith('[')){ try{ return ($s | ConvertFrom-Json -ErrorAction Stop) }catch{} } }
  return $obj
}
function Invoke-GraphJson{
  param([Parameter(Mandatory)][string]$Uri,[ValidateSet('v1.0','beta')][string]$Profile=$script:GraphProfile,[int]$PageSize=100)
  function Get-NextLink([object]$o){
    try{
      if($null -eq $o){ return $null }
      if($o -is [System.Collections.IDictionary]){
        if($o.Contains('@odata.nextLink')){ return $o['@odata.nextLink'] }
        if($o.ContainsKey('@odata.nextLink')){ return $o['@odata.nextLink'] }
        return $null
      }
      if($o.PSObject -and $o.PSObject.Properties['@odata.nextLink']){ return $o.'@odata.nextLink' }
    } catch { }
    return $null
  }
  $base= if($Profile -eq 'beta'){ 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }
  $url = $base + $Uri + '?$top=' + $PageSize
  $all=@()
  do{
    $respObj = $null
    try{
      $hr = Invoke-MgGraphRequest -Method GET -Uri $url -OutputType HttpResponseMessage -ErrorAction Stop; $json = $hr.Content.ReadAsStringAsync().Result; $respObj = $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
      try{ $ps = Invoke-MgGraphRequest -Method GET -Uri $url -ErrorAction Stop; $json = $ps | ConvertTo-Json -Depth 20 -Compress; $respObj = $json | ConvertFrom-Json -ErrorAction Stop }
      catch { Log 'ERROR' ("Invoke-GraphJson failed for " + $url + " : " + $_.Exception.Message); break }
    }
    $items=@()
    if($respObj -and $respObj.PSObject -and $respObj.PSObject.Properties['value']){ $items = $respObj.value }
    elseif($respObj -is [System.Array]){ $items = $respObj } else { $items = @($respObj) }
    if($items -ne $null){ $all += $items }
    $url = Get-NextLink $respObj
  } while($url)
  return $all
}
function Ensure-Dir([string]$path){ if(-not (Test-Path $path)){ New-Item -ItemType Directory -Path $path -Force | Out-Null } }
function Get-SafeName([string]$display,[string]$fallbackId){ if([string]::IsNullOrWhiteSpace($display)){ $display=$fallbackId }; $safe = ($display -replace '[\\\/:*?"<>\n\r]', '_').Trim().TrimEnd('.'); if([string]::IsNullOrWhiteSpace($safe)){ $safe=$fallbackId }; return $safe }
function Get-UniqueName([string]$base,[string]$id,[string]$dir){ if($base.Length -gt 120){ $base=$base.Substring(0,116) + '_' + $id.Substring(0,4) }; $name=$base; if(Test-Path (Join-Path $dir ($name + '.json'))){ $suffix='_' + $id.Substring(0,6); $name = if($base.Length -le (120 - $suffix.Length)){ $base + $suffix } else { $base.Substring(0,120 - $suffix.Length) + $suffix } }; return $name }
function Write-JsonFile([object]$obj,[string]$path){ try{ $json = ConvertTo-Json -InputObject $obj -Depth 20 -Compress -ErrorAction Stop } catch { $json = ConvertTo-Json -InputObject ([string]$obj) -Depth 3 -Compress }; $utf8 = New-Object System.Text.UTF8Encoding($false); [System.IO.File]::WriteAllText($path, $json, $utf8) }
function Extract-Items([object]$obj){ if($null -eq $obj){ return @() }; if($obj.PSObject -and $obj.PSObject.Properties['value']){ return @($obj.value) }; if($obj -is [System.Array]){ return @($obj) }; if($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])){ return @($obj) }; return @($obj) }
function SafeCount([object]$x){ try{ return ((Extract-Items $x) | Measure-Object).Count } catch { return 0 } }
function Save-Items([object[]]$items,[string]$dir){
  $items = Extract-Items $items; $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach($it in $items){
    $o = $it
    if($o -is [string]){ $tmp = ConvertTo-PSJson $o; if($tmp){ $o = $tmp } }
    $disp=$null; try{ $disp=$o.displayName }catch{}; if([string]::IsNullOrWhiteSpace($disp)){ try{ $disp=$o.name }catch{} }
    $id=$null; try{ $id=$o.id }catch{}; if([string]::IsNullOrWhiteSpace($id)){ $id = ([guid]::NewGuid().ToString('N')).Substring(0,8) }
    $base = Get-SafeName $disp $id; if($base.Length -gt 120){ $base = $base.Substring(0,116) + '_' + $id.Substring(0,4) }
    $name=$base; if($seen.Contains($name) -or (Test-Path (Join-Path $dir ($name + '.json')))){ $suffix='_' + $id.Substring(0,6); $name = if($base.Length -le (120 - $suffix.Length)){ $base + $suffix } else { $base.Substring(0,120 - $suffix.Length) + $suffix } }
    $seen.Add($name) | Out-Null; $path = Join-Path $dir ($name + '.json'); Write-JsonFile -obj $o -path $path
  }
}
function Save-ChildCollection([object[]]$items,[string]$parent,[string]$childName){ $childDir = Join-Path $parent $childName; Ensure-Dir $childDir; Save-Items @($items) $childDir; Write-JsonFile -obj $items -path (Join-Path $childDir 'index.json') }
function Get-SafeObjectDir([object]$it,[string]$dir){ if($it -is [string]){ $tmp = ConvertTo-PSJson $it; if($tmp){ $it=$tmp } }; $disp=$null; try{ $disp=$it.displayName }catch{}; if([string]::IsNullOrWhiteSpace($disp)){ try{ $disp=$it.name }catch{} }; $id=$null; try{ $id=$it.id }catch{}; if([string]::IsNullOrWhiteSpace($id)){ $id=([guid]::NewGuid().ToString('N')).Substring(0,8) }; $safe = Get-SafeName $disp $id; $safe = Get-UniqueName $safe $id $dir; $objDir = Join-Path $dir $safe; Ensure-Dir $objDir; return $objDir }
$script:FirstFailureSignaled=$false
function Export-Entity([string]$name,[scriptblock]$action){
  Log 'INFO' ("[STAGE] Fetching " + $name)
  try{ & $action; Log 'INFO' ("[STAGE] Completed " + $name); $script:SuccessCount++ }
  catch { Log 'ERROR' ("Export failed for $($name): " + $_.Exception.Message); $script:ErrorCount++; if(-not $script:FirstFailureSignaled){ try{ if($UiStatePath){ Set-Content -Path $UiStatePath -Value 'ErrorDetected' -Encoding UTF8 } }catch{ Log 'WARN' ("ErrorDetected write failed: " + $_.Exception.Message) }; $script:FirstFailureSignaled=$true } }
}
function Apply-UiEnvFallback { if ([string]::IsNullOrWhiteSpace($UiStatePath)) { $UiStatePath = $env:INTUNE_UI_STATE }; if ([string]::IsNullOrWhiteSpace($UiExitPath)) { $UiExitPath = $env:INTUNE_UI_EXIT }; Log 'INFO' ("UI side-band paths: UiStatePath='" + ($UiStatePath ?? '') + "', UiExitPath='" + ($UiExitPath ?? '') + "'") }

function Run-Backup{
  param([string]$TenantId,[string]$AppId,[string]$ClientSecretPlain,[string]$OutputPath,[int]$RetentionCount)
  New-Log 'Backup'; Ensure-GraphProfile; Log-GraphVersions; Apply-UiEnvFallback; Signal-UI 'Starting' $null
  # DPAPI fallback if secret not provided
  if ([string]::IsNullOrWhiteSpace($ClientSecretPlain) -and -not [string]::IsNullOrWhiteSpace($SecretPath)) {
    try { $ClientSecretPlain = Read-DpapiSecret -Path $SecretPath -TenantId $TenantId -AppId $AppId; Log 'INFO' 'Client secret loaded from DPAPI secret store.' }
    catch { Log 'ERROR' ("Failed to read DPAPI secret: " + $_.Exception.Message); throw }
  }
  $resolvedOut=$OutputPath; if($UseTimestampFolder){ $resolvedOut = Join-Path $OutputPath $script:RunTs; if(-not (Test-Path $resolvedOut)){ New-Item -ItemType Directory -Path $resolvedOut -Force | Out-Null } }
  try{
    Connect-GraphApp -TenantId $TenantId -AppId $AppId -ClientSecretPlain $ClientSecretPlain
    $entities = @('deviceConfigurations','configurationPolicies','deviceCompliancePolicies','deviceManagementScripts','deviceHealthScripts','assignmentFilters','termsAndConditions','deviceEnrollmentConfigurations','windowsAutopilotDeploymentProfiles','managedDevices','endpointSecurity','securityBaselines','enrollmentProfiles','mobileApps','windowsUpdateRings','windowsFeatureUpdates','windowsQualityUpdates','appProtectionPolicies')
    $script:SuccessCount=0; $script:ErrorCount=0
    $handlers = @{}

    # ======= entity handlers (unchanged) =======
    $handlers['deviceConfigurations'] = { param($dir)
      Export-Entity 'deviceConfigurations' { $d = Invoke-GraphJson -Uri '/deviceManagement/deviceConfigurations'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("deviceConfigurations: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['configurationPolicies'] = { param($dir)
      Export-Entity 'configurationPolicies' { $d = Invoke-GraphJson -Uri '/deviceManagement/configurationPolicies' -Profile 'beta'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("configurationPolicies: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['deviceCompliancePolicies'] = { param($dir)
      Export-Entity 'deviceCompliancePolicies' { $d = Invoke-GraphJson -Uri '/deviceManagement/deviceCompliancePolicies'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("deviceCompliancePolicies: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['deviceManagementScripts'] = { param($dir)
      Export-Entity 'deviceManagementScripts' { $d = Invoke-GraphJson -Uri '/deviceManagement/deviceManagementScripts' -Profile 'beta'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("deviceManagementScripts: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['deviceHealthScripts'] = { param($dir)
      Export-Entity 'deviceHealthScripts' { $d = Invoke-GraphJson -Uri '/deviceManagement/deviceHealthScripts' -Profile 'beta'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("deviceHealthScripts: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['assignmentFilters'] = { param($dir)
      Export-Entity 'assignmentFilters' { $d = Invoke-GraphJson -Uri '/deviceManagement/assignmentFilters' -Profile 'beta'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("assignmentFilters: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['termsAndConditions'] = { param($dir)
      Export-Entity 'termsAndConditions' { $d = Invoke-GraphJson -Uri '/deviceManagement/termsAndConditions'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("termsAndConditions: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['deviceEnrollmentConfigurations'] = { param($dir)
      Export-Entity 'deviceEnrollmentConfigurations' { $d = Invoke-GraphJson -Uri '/deviceManagement/deviceEnrollmentConfigurations'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("deviceEnrollmentConfigurations: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['windowsAutopilotDeploymentProfiles'] = { param($dir)
      Export-Entity 'windowsAutopilotDeploymentProfiles' { $d = Invoke-GraphJson -Uri '/deviceManagement/windowsAutopilotDeploymentProfiles'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("windowsAutopilotDeploymentProfiles: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['managedDevices'] = { param($dir)
      Export-Entity 'managedDevices' { $d = Invoke-GraphJson -Uri '/deviceManagement/managedDevices' -PageSize 50; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("managedDevices: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['endpointSecurity'] = { param($dir)
      Export-Entity 'endpointSecurity' { $d = Invoke-GraphJson -Uri '/deviceManagement/intents' -Profile 'beta'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("endpointSecurity(intents): wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['securityBaselines'] = { param($dir)
      Export-Entity 'securityBaselines' { $d = Invoke-GraphJson -Uri '/deviceManagement/templates' -Profile 'beta'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("securityBaselines(templates): wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['enrollmentProfiles'] = { param($dir)
      Export-Entity 'enrollmentProfiles' { 
        $all=@()
        $dep = Invoke-GraphJson -Uri '/deviceManagement/depOnboardingSettings' -Profile 'beta'; 
        $depItems=Extract-Items $dep; 
        if(($depItems | Measure-Object).Count -gt 0){
          $depRoot=Join-Path $dir 'depOnboardingSettings'; Ensure-Dir $depRoot;
          foreach($d in $depItems){
            if(-not $d -or -not $d.id){ continue }
            $depDir= Get-SafeObjectDir $d $depRoot;
            Write-JsonFile -obj $d -path (Join-Path $depDir 'depOnboardingSetting.json');
            $profilesDir= Join-Path $depDir 'profiles'; Ensure-Dir $profilesDir;
            $eps = Invoke-GraphJson -Uri "/deviceManagement/depOnboardingSettings/$($d.id)/enrollmentProfiles" -Profile 'beta';
            Save-Items @($eps) $profilesDir; Write-JsonFile -obj $eps -path (Join-Path $profilesDir 'index.json');
            foreach($defName in @('defaultIosEnrollmentProfile','defaultMacOsEnrollmentProfile','defaultTvOsEnrollmentProfile','defaultVisionOsEnrollmentProfile')){
              try{ $def = Invoke-GraphJson -Uri "/deviceManagement/depOnboardingSettings/$($d.id)/$defName" -Profile 'beta'; if($def){ Write-JsonFile -obj $def -path (Join-Path $depDir ($defName + '.json')) } }
              catch{ Log 'WARN' ("Default profile $defName not returned for DEP token ${($d.id)}: " + $_.Exception.Message) }
            }
          }
        }
        $all += $depItems
        foreach($tuple in @(@{name='appleUserInitiated';uri='/deviceManagement/appleUserInitiatedEnrollmentProfiles'},@{name='androidDeviceOwner';uri='/deviceManagement/androidDeviceOwnerEnrollmentProfiles'},@{name='androidForWork';uri='/deviceManagement/androidForWorkEnrollmentProfiles'})){
          try{
            $list = Invoke-GraphJson -Uri $tuple.uri -Profile 'beta'; $listItems=Extract-Items $list;
            if(( $listItems | Measure-Object).Count -gt 0){
              $sub = Join-Path $dir $tuple.name; Ensure-Dir $sub;
              Save-Items @($listItems) $sub; Write-JsonFile -obj $listItems -path (Join-Path $sub 'index.json'); $all += $listItems
            }
          } catch{ Log 'WARN' ("$($tuple.name): " + $_.Exception.Message) }
        }
        Log 'INFO' ("enrollmentProfiles: wrote subtrees for {0} families" -f ((@($all) | Measure-Object).Count)); 
        Write-JsonFile -obj $all -path (Join-Path $dir 'index.json') 
      }
    }
    $handlers['mobileApps'] = { param($dir)
      Export-Entity 'mobileApps' { $d = Invoke-GraphJson -Uri '/deviceAppManagement/mobileApps'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("mobileApps: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json') }
    }
    $handlers['windowsUpdateRings'] = { param($dir)
      Export-Entity 'windowsUpdateRings' { $all = Invoke-GraphJson -Uri '/deviceManagement/deviceConfigurations'; $rings = @($all | Where-Object { $_ -and $_.PSObject.Properties['@odata.type'] -and $_.'@odata.type' -like '*windowsUpdateForBusinessConfiguration*' }); Save-Items $rings $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("windowsUpdateRings: wrote {0} object files (filtered from {1})" -f $written,(SafeCount $rings)); Write-JsonFile -obj $rings -path (Join-Path $dir 'index.json'); if($written -gt 0){ foreach($r in $rings){ if(-not $r -or -not $r.id){ continue } try{ $rDir= Get-SafeObjectDir $r $dir; Write-JsonFile -obj $r -path (Join-Path $rDir 'windowsUpdateForBusinessConfiguration.json'); $a=Invoke-GraphJson -Uri "/deviceManagement/deviceConfigurations/$($r.id)/assignments"; Save-ChildCollection @($a) $rDir 'assignments' }catch{ Log 'WARN' ("Update ring assignments for ${($r.id)}: " + $_.Exception.Message) } } } }
    }
    $handlers['windowsFeatureUpdates'] = { param($dir)
      Export-Entity 'windowsFeatureUpdates' { $d = Invoke-GraphJson -Uri '/deviceManagement/windowsFeatureUpdateProfiles' -Profile 'beta'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("windowsFeatureUpdates: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json'); if($written -gt 0){ foreach($it in $items){ $obj= if($it -is [string]){ ConvertTo-PSJson $it } else { $it }; if(-not $obj -or -not $obj.id){ continue } try{ $objDir= Get-SafeObjectDir $obj $dir; Write-JsonFile -obj $obj -path (Join-Path $objDir 'windowsFeatureUpdateProfile.json'); $assign=Invoke-GraphJson -Uri "/deviceManagement/windowsFeatureUpdateProfiles/$($obj.id)/assignments" -Profile 'beta'; Save-ChildCollection @($assign) $objDir 'assignments' }catch{ Log 'WARN' ("Feature update profile assignments for ${($obj.id)}: " + $_.Exception.Message) } } } }
    }
    $handlers['windowsQualityUpdates'] = { param($dir)
      Export-Entity 'windowsQualityUpdates' { $d = Invoke-GraphJson -Uri '/deviceManagement/windowsQualityUpdateProfiles' -Profile 'beta'; $items=Extract-Items $d; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("windowsQualityUpdates: wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $d -path (Join-Path $dir 'index.json'); if($written -gt 0){ foreach($it in $items){ $obj= if($it -is [string]){ ConvertTo-PSJson $it } else { $it }; if(-not $obj -or -not $obj.id){ continue } try{ $objDir= Get-SafeObjectDir $obj $dir; Write-JsonFile -obj $obj -path (Join-Path $objDir 'windowsQualityUpdateProfile.json'); $assign=Invoke-GraphJson -Uri "/deviceManagement/windowsQualityUpdateProfiles/$($obj.id)/assignments" -Profile 'beta'; Save-ChildCollection @($assign) $objDir 'assignments' }catch{ Log 'WARN' ("Quality update profile assignments for ${($obj.id)}: " + $_.Exception.Message) } } } }
    }
    $handlers['appProtectionPolicies'] = { param($dir)
      Export-Entity 'appProtectionPolicies' { $root=Invoke-GraphJson -Uri '/deviceAppManagement/managedAppPolicies'; $items=Extract-Items $root; Save-Items @($items) $dir; $written=(Get-ChildItem $dir -Filter '*.json' -File | Where-Object {$_.Name -ne 'index.json'} | Measure-Object).Count; Log 'INFO' ("appProtectionPolicies(all): wrote {0} object files (received {1})" -f $written,(SafeCount $items)); Write-JsonFile -obj $root -path (Join-Path $dir 'index.json'); $families=@(@{name='androidManagedAppProtections';uri='/deviceAppManagement/androidManagedAppProtections'},@{name='iosManagedAppProtections';uri='/deviceAppManagement/iosManagedAppProtections'},@{name='windowsInformationProtectionPolicies';uri='/deviceAppManagement/windowsInformationProtectionPolicies'},@{name='mdmWindowsInformationProtectionPolicies';uri='/deviceAppManagement/mdmWindowsInformationProtectionPolicies'}); foreach($fam in $families){ try{ $setDir= Join-Path $dir $fam.name; Ensure-Dir $setDir; $list=Invoke-GraphJson -Uri $fam.uri; $famItems=Extract-Items $list; Save-Items @($famItems) $setDir; Write-JsonFile -obj $famItems -path (Join-Path $setDir 'index.json'); foreach($p in $famItems){ $obj= if($p -is [string]){ ConvertTo-PSJson $p } else { $p }; if(-not $obj -or -not $obj.id){ continue } try{ $objDir= Get-SafeObjectDir $obj $setDir; Write-JsonFile -obj $obj -path (Join-Path $objDir ($fam.name + '.json')); $assign=Invoke-GraphJson -Uri ($fam.uri + "/$($obj.id)/assignments"); Save-ChildCollection @($assign) $objDir 'assignments' }catch{ Log 'WARN' ("App protection assignments for ${($obj.id)}: " + $_.Exception.Message) } } }catch{ Log 'WARN' ("$($fam.name): " + $_.Exception.Message) } } }
    }

    # ==========================================
    foreach($e in $entities){ $dir = Join-Path $resolvedOut $e; Ensure-Dir $dir; if($handlers.ContainsKey($e)){ & $handlers[$e] $dir } else { Export-Entity $e { throw [System.NotSupportedException]::new('Unsupported entity name') } } }

    if($script:SuccessCount -eq 0){ Log 'ERROR' 'No entities exported successfully.'; Set-Content -Path (Join-Path $script:LogFolder 'state.txt') -Value 'Failed'; Set-Content -Path (Join-Path $script:LogFolder 'exit.code') -Value '1'; Signal-UI 'Failed' '1'; return }
    Log 'INFO' ("[STAGE] Backup complete. Output: " + $resolvedOut)
    Set-Content -Path (Join-Path $script:LogFolder 'state.txt') -Value 'Complete'
    Set-Content -Path (Join-Path $script:LogFolder 'exit.code') -Value '0'
    Signal-UI 'Complete' '0'

    try{
      if($UseTimestampFolder -and $RetentionCount -gt 0){
        $tsDirs = Get-ChildItem -Path $OutputPath -Directory |
          Where-Object { $_.Name -match '^\d{8}[-_]\d{6}$' } |
          Sort-Object Name -Descending
        $keep=[Math]::Max($RetentionCount,1); $toRemove = $tsDirs | Select-Object -Skip $keep
        $have = ($tsDirs | Measure-Object).Count; $rem = ($toRemove | Measure-Object).Count
        if($rem -gt 0){ foreach($d in $toRemove){ try{ Log 'INFO' ("Retention: deleting " + $d.FullName); Remove-Item -Recurse -Force -Path $d.FullName }catch{ Log 'WARN' ("Retention delete failed: " + $_.Exception.Message) } } }
        else { Log 'INFO' ("Retention: nothing to delete (have {0}, keeping {1})" -f $have, $keep) }
      }
    }catch{ Log 'WARN' ("Retention step failed: " + $_.Exception.Message) }
  }
  finally {
    try{
      $finalState = if($script:SuccessCount -gt 0 -and $script:ErrorCount -eq 0){'Complete'} else {'Failed'}
      $finalExit  = if($script:SuccessCount -gt 0 -and $script:ErrorCount -eq 0){'0'} else {'1'}
      if($UiStatePath){ Ensure-PathParent $UiStatePath; Set-Content -Path $UiStatePath -Value $finalState -Encoding UTF8 -ErrorAction Stop }
      if($UiExitPath){ Ensure-PathParent $UiExitPath; Set-Content -Path $UiExitPath -Value $finalExit -Encoding UTF8 -ErrorAction Stop }
      Signal-UI $finalState $finalExit
    }catch{ Log 'WARN' ("Final Signal-UI failed: " + $_.Exception.Message) }
  }
}

function Read-JsonIfExists([string]$path){ if(Test-Path $path){ try{ return Get-Content -Path $path -Raw | ConvertFrom-Json -ErrorAction Stop }catch{ Log 'ERROR' ("Failed to parse JSON: " + $path + ": " + $_.Exception.Message) } } return $null }
function Normalize-ForCreate([hashtable]$obj){ foreach($k in @('id','createdDateTime','lastModifiedDateTime','version','roleScopeTagIds','supportsScopeTags')){ if($obj.ContainsKey($k)){ $obj.Remove($k) | Out-Null } } return $obj }

function Run-Restore{
  param([string]$TenantId,[string]$AppId,[string]$ClientSecretPlain,[string]$InputPath,[switch]$ForceRestore)
  if(-not (Test-Path -LiteralPath $InputPath)){ throw "InputPath not found: $InputPath" }
  New-Log 'Restore'; Ensure-GraphProfile; Log-GraphVersions; Apply-UiEnvFallback; Signal-UI 'Starting' $null
  try{
    if ([string]::IsNullOrWhiteSpace($ClientSecretPlain) -and -not [string]::IsNullOrWhiteSpace($SecretPath)) {
      try { $ClientSecretPlain = Read-DpapiSecret -Path $SecretPath -TenantId $TenantId -AppId $AppId; Log 'INFO' 'Client secret loaded from DPAPI (restore).' } catch { Log 'ERROR' ("DPAPI read failed: " + $_.Exception.Message); throw }
    }
    Connect-GraphApp -TenantId $TenantId -AppId $AppId -ClientSecretPlain $ClientSecretPlain
    $entities=@(
      @{name='deviceConfigurations';uri='/deviceManagement/deviceConfigurations';file='deviceConfigurations\index.json'},
      @{name='configurationPolicies';uri='/deviceManagement/configurationPolicies';file='configurationPolicies\index.json'},
      @{name='deviceCompliancePolicies';uri='/deviceManagement/deviceCompliancePolicies';file='deviceCompliancePolicies\index.json'},
      @{name='deviceManagementScripts';uri='/deviceManagement/deviceManagementScripts';file='deviceManagementScripts\index.json'},
      @{name='deviceHealthScripts';uri='/deviceManagement/deviceHealthScripts';file='deviceHealthScripts\index.json'},
      @{name='assignmentFilters';uri='/deviceManagement/assignmentFilters';file='assignmentFilters\index.json'},
      @{name='termsAndConditions';uri='/deviceManagement/termsAndConditions';file='termsAndConditions\index.json'},
      @{name='deviceEnrollmentConfigurations';uri='/deviceManagement/deviceEnrollmentConfigurations';file='deviceEnrollmentConfigurations\index.json'},
      @{name='windowsAutopilotDeploymentProfiles';uri='/deviceManagement/windowsAutopilotDeploymentProfiles';file='windowsAutopilotDeploymentProfiles\index.json'}
    )
    foreach($e in $entities){
      $name=$e.name; $path= Join-Path $InputPath $e.file
      Log 'INFO' ("[STAGE] Restoring " + $name)
      $data= Read-JsonIfExists $path
      if(-not $data){ Log 'WARN' ("No data file for " + $name + ": " + $path); continue }
      $items= Extract-Items $data; $count=0
      foreach($it in $items){
        try{
          $obj=$it; if($obj -is [string]){ $tmp= ConvertTo-PSJson $obj; if($tmp){ $obj=$tmp } }
          $h=@{}; $obj.psobject.Properties | ForEach-Object { $h[$_.Name]=$_.Value }
          $norm = Normalize-ForCreate $h
          if($ForceRestore){
            $base= if($script:GraphProfile -eq 'beta'){ 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }
            $hr = Invoke-MgGraphRequest -Method POST -Uri ($base + $e.uri) -Body (ConvertTo-Json -InputObject $norm -Depth 20 -Compress) -ContentType 'application/json' -OutputType HttpResponseMessage -ErrorAction Stop; [void]$hr.StatusCode; $count++
          } else { Log 'INFO' ("DRY-RUN would POST to " + $e.uri) }
        } catch { Log 'ERROR' ("Restore failed for $($name): " + $_.Exception.Message) }
      }
      if($ForceRestore){ Log 'INFO' ("[STAGE] Restored " + $name + ": " + $count + " objects") } else { Log 'INFO' ("[STAGE] Dry-run completed for " + $name) }
    }
    Log 'INFO' '[STAGE] Restore complete.'
    Set-Content -Path (Join-Path $script:LogFolder 'state.txt') -Value 'Complete'
    Set-Content -Path (Join-Path $script:LogFolder 'exit.code') -Value '0'
    Signal-UI 'Complete' '0'
  } finally {
    try{
      $finalState='Complete'; $finalExit='0'
      if($UiStatePath){ Ensure-PathParent $UiStatePath; Set-Content -Path $UiStatePath -Value $finalState -Encoding UTF8 -ErrorAction Stop }
      if($UiExitPath){ Ensure-PathParent $UiExitPath; Set-Content -Path $UiExitPath -Value $finalExit -Encoding UTF8 -ErrorAction Stop }
      Signal-UI $finalState $finalExit
    }catch{ Log 'WARN' ("Final Restore Signal-UI failed: " + $_.Exception.Message) }
  }
}

if($Mode -eq 'UI'){
  Add-Type -AssemblyName PresentationFramework,PresentationCore
  $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
 xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
 xmlns:sys="clr-namespace:System;assembly=mscorlib"
 Title="Achieve One-Leadership to Adapt-Expertise to Achieve"
 Height="600" Width="980" WindowStartupLocation="CenterScreen">
 <Grid Margin="12">
  <Grid.RowDefinitions>
   <RowDefinition Height="Auto"/>
   <RowDefinition Height="*"/>
   <RowDefinition Height="Auto"/>
  </Grid.RowDefinitions>
  <Border x:Name="HeaderBorder" Grid.Row="0" Background="#FFFFFFFF" BorderBrush="#DDDDDD" BorderThickness="1" CornerRadius="4" Padding="8" Margin="0,0,0,8">
   <TextBlock x:Name="AppTitleBlock" Text="Intune Backup and Restore" TextAlignment="Center" HorizontalAlignment="Center" FontSize="13" Foreground="#333333"/>
  </Border>
  <TabControl x:Name="MainTabs" Grid.Row="1" Margin="0,0,0,10">
   <TabItem Header="Backup">
    <Grid Margin="10">
     <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
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
      <TextBlock Margin="20,0,6,0" VerticalAlignment="Center">Keep last (retention):</TextBlock>
      <TextBox x:Name="RetentionBox" Width="60" Text="10"/>
      <CheckBox x:Name="AutoBetaChk" Margin="20,0,0,0" IsChecked="True">AutoBeta</CheckBox>
      <CheckBox x:Name="DiagChk" Margin="20,0,0,0">Diagnostics</CheckBox>
     </StackPanel>
     <StackPanel Orientation="Horizontal" Grid.Row="5" Margin="0,0,0,8">
      <Button x:Name="BackupBtn" Width="160" Height="34">Run Backup</Button>
      <Button x:Name="SaveCfgBtn" Width="120" Height="34" Margin="10,0,0,0">Save Config</Button>
      <Button x:Name="LoadCfgBtn" Width="120" Height="34" Margin="6,0,0,0">Load Config</Button>
      <Button x:Name="CreateTaskBtn" Width="160" Height="34" Margin="6,0,0,0">Create Nightly Task</Button>
      <Button x:Name="TestConnBtn" Width="160" Height="34" Margin="6,0,0,0">Test App Connection</Button>
     </StackPanel>
     <StackPanel Grid.Row="6" Orientation="Vertical">
      <TextBlock x:Name="StatusText" Margin="0,4,0,6" Foreground="#333333"/>
      <StackPanel Orientation="Horizontal">
       <TextBlock x:Name="OutputLink" Foreground="#0063b1" TextDecorations="Underline" Cursor="Hand" Visibility="Collapsed">Open output folder</TextBlock>
      </StackPanel>
     </StackPanel>
    </Grid>
   </TabItem>
   <TabItem Header="Restore (advanced)">
    <Grid Margin="10">
     <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/><RowDefinition Height="*"/>
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
     <StackPanel Orientation="Horizontal" Grid.Row="3" Margin="0,0,0,8">
      <TextBlock Width="140" VerticalAlignment="Center">Input Path:</TextBlock>
      <TextBox x:Name="InputBox" MinWidth="520" Text="C:\Staging\Backup\latest"/>
     </StackPanel>
     <StackPanel Orientation="Horizontal" Grid.Row="4" Margin="0,10,0,0">
      <CheckBox x:Name="ForceRestoreChk">I understand this will create new objects (disables dry-run)</CheckBox>
     </StackPanel>
     <StackPanel Orientation="Vertical" Grid.Row="4" Margin="0,48,0,0">
      <TextBlock x:Name="RStatusText" Margin="0,12,0,0" Foreground="#333333"/>
     </StackPanel>
    </Grid>
   </TabItem>
  </TabControl>
  <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right"/>
 </Grid>
</Window>
"@
  $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
  $win = [Windows.Markup.XamlReader]::Load($reader)
  # Controls
  $TenantBox=$win.FindName('TenantBox'); $AppIdBox=$win.FindName('AppIdBox'); $SecretBox=$win.FindName('SecretBox')
  $OutputBox=$win.FindName('OutputBox'); $TimestampChk=$win.FindName('TimestampChk'); $AutoBetaChk=$win.FindName('AutoBetaChk'); $DiagChk=$win.FindName('DiagChk')
  $RetentionBox=$win.FindName('RetentionBox'); $BackupBtn=$win.FindName('BackupBtn'); $StatusText=$win.FindName('StatusText'); $OutputLink=$win.FindName('OutputLink')
  $SaveCfgBtn=$win.FindName('SaveCfgBtn'); $LoadCfgBtn=$win.FindName('LoadCfgBtn'); $CreateTaskBtn=$win.FindName('CreateTaskBtn'); $TestConnBtn=$win.FindName('TestConnBtn')
  $RTenantBox=$win.FindName('RTenantBox'); $RAppIdBox=$win.FindName('RAppIdBox'); $RSecretBox=$win.FindName('RSecretBox')
  $InputBox=$win.FindName('InputBox'); $ForceRestoreChk=$win.FindName('ForceRestoreChk'); $RStatusText=$win.FindName('RStatusText')
  function QuoteArg([string]$s){ '"' + ($s -replace '"','\"') + '"' }
  # UI text helper via window Dispatcher
  function Set-UiText([string]$m,[string]$s,[string]$e){
    try{ $null = $win.Dispatcher.Invoke([Action]{ 
      if($m -eq 'Backup'){
        if($s -match 'Complete' -or $e -eq '0'){ $StatusText.Text='Completed successfully.' }
        elseif($s -match 'Failed' -or $e -eq '1'){ $StatusText.Text='Finished with errors.' }
        elseif($s -match 'Starting'){ $StatusText.Text='Backing up…' }
        else { $StatusText.Text='Backing up…' }
      } else {
        if($s -match 'Complete' -or $e -eq '0'){ $RStatusText.Text='Completed successfully.' }
        elseif($s -match 'Failed' -or $e -eq '1'){ $RStatusText.Text='Finished with errors.' }
        elseif($s -match 'Starting'){ $RStatusText.Text='Restoring…' }
        else { $RStatusText.Text='Restoring…' }
      }
    }) }catch{}
  }
  function Start-Engine([string]$mode,[hashtable]$payload){
    $rid = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0,8))
    $work = Join-Path $env:TEMP ("IntuneBR_" + $rid); New-Item -ItemType Directory -Path $work -Force | Out-Null
    $outRoot = $OutputBox.Text
    $sp = Join-Path $work 'state.txt'; $ep = Join-Path $work 'exit.code'
    Set-Content -Path $sp -Value 'Starting' -Encoding UTF8

    # --- PATCH locals for live output folder tracking ---
    $outDirHint = Join-Path $work 'outdir.txt'    # will be written by engine (New-Log)
    $runOutDir  = $null                           # once we know it, read state/exit here
    $tsRegex    = '^\d{8}[-_]\d{6}$'

    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
    if(-not $pwsh){ $pwsh = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" }
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', (QuoteArg ((Resolve-Path $PSCommandPath).ProviderPath)), '-Mode', $mode, '-AuthMode','App')
    foreach($k in $payload.Keys){ $args += @('-' + $k, (QuoteArg ([string]$payload[$k]))) }
    if($AutoBetaChk.IsChecked){ $args += '-AutoBeta' }
    if($TimestampChk.IsChecked -and $mode -eq 'Backup'){ $args += '-UseTimestampFolder' }
    if($DiagChk.IsChecked){ $args += '-Diag' }
    $args += @('-UiStatePath', (QuoteArg $sp), '-UiExitPath', (QuoteArg $ep))
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $pwsh
    $psi.Arguments = ($args -join ' ')
    $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true
    $psi.Environment['INTUNE_UI_STATE'] = $sp
    $psi.Environment['INTUNE_UI_EXIT']  = $ep
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $p.EnableRaisingEvents = $true
    [void]$p.Start()

    $start = Get-Date
    $timeout = [TimeSpan]::FromMinutes(12)

    # Background task: read final state after process exits; improved timestamp regex
    $task = [System.Threading.Tasks.Task]::Run([System.Action]{
      try{
        $p.WaitForExit()
        $state = if(Test-Path $sp){ Get-Content -Path $sp -Raw -ErrorAction SilentlyContinue } else { '' }
        $exit  = if(Test-Path $ep){ Get-Content -Path $ep -Raw -ErrorAction SilentlyContinue } else { '' }
        if([string]::IsNullOrWhiteSpace($exit)){ try{ $exit = [string]$p.ExitCode }catch{ $exit = '' } }
        if([string]::IsNullOrWhiteSpace($exit)){
          try{
            $root = $outRoot
            if([string]::IsNullOrWhiteSpace($root) -eq $false -and (Test-Path -LiteralPath $root)){
              $latest = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match $tsRegex } |
                        Sort-Object Name -Descending |
                        Select-Object -First 1
              if($latest){
                $ofExit = Join-Path $latest.FullName 'exit.code'
                if(Test-Path $ofExit){ $exit = (Get-Content -Path $ofExit -Raw -ErrorAction SilentlyContinue).Trim() }
                if([string]::IsNullOrWhiteSpace($state)){
                  $ofState = Join-Path $latest.FullName 'state.txt'
                  if(Test-Path $ofState){ $state = (Get-Content -Path $ofState -Raw -ErrorAction SilentlyContinue).Trim() }
                }
              }
            }
          }catch{}
        }
        if([string]::IsNullOrWhiteSpace($state)){
          if($exit -eq '0'){ $state='Complete' }
          elseif($exit -eq '1'){ $state='Failed' }
          elseif($exit -ne ''){ $state = ([int]$exit -eq 0) ? 'Complete' : 'Failed' }
          else { $state='Failed' }
        }
        Set-UiText $mode $state $exit
      }catch{}
    })
    [void]$script:RunningTimers.Add($task)

    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $work; $watcher.Filter='*.*'
    $watcher.NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'
    $watcher.IncludeSubdirectories=$false
    $fsAction = { param($mode,$sp,$ep) try{ Start-Sleep -Milliseconds 60; $state = if(Test-Path $sp){ Get-Content -Path $sp -Raw -ErrorAction SilentlyContinue } else { '' }; $exit = if(Test-Path $ep){ Get-Content -Path $ep -Raw -ErrorAction SilentlyContinue } else { '' }; Set-UiText $mode $state $exit }catch{} }.GetNewClosure()
    $createdReg = Register-ObjectEvent -InputObject $watcher -EventName Created -Action { & $fsAction $mode $sp $ep }
    $changedReg = Register-ObjectEvent -InputObject $watcher -EventName Changed -Action { & $fsAction $mode $sp $ep }
    $watcher.EnableRaisingEvents = $true
    [void]$script:RunningTimers.Add($watcher); [void]$script:RunningTimers.Add($createdReg); [void]$script:RunningTimers.Add($changedReg)

    $exitReg = Register-ObjectEvent -InputObject $p -EventName Exited -Action {
      try{
        $state = if(Test-Path $sp){ Get-Content -Path $sp -Raw -ErrorAction SilentlyContinue } else { '' }
        $exit  = if(Test-Path $ep){ Get-Content -Path $ep -Raw -ErrorAction SilentlyContinue } else { '' }
        if ([string]::IsNullOrWhiteSpace($state) -and [string]::IsNullOrWhiteSpace($exit)) {
          $procExit = 1; try{ $procExit = $Event.Sender.ExitCode }catch{}
          $state = ($procExit -eq 0) ? 'Complete' : 'Failed'
          $exit  = ($procExit -eq 0) ? '0' : '1'
        }
        Set-UiText $mode $state $exit
      }catch{}
    }
    [void]$script:RunningTimers.Add($exitReg)

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(500)
    [void]$script:RunningTimers.Add($timer)
    $timer.add_Tick({
      try{
        # 1) Learn real dated out dir from hint, once
        if (-not $runOutDir -and (Test-Path -LiteralPath $outDirHint)) {
          $hint = Get-Content -Path $outDirHint -Raw -ErrorAction SilentlyContinue
          if (-not [string]::IsNullOrWhiteSpace($hint) -and (Test-Path -LiteralPath $hint)) {
            $runOutDir = $hint.Trim()
          }
        }

        # 2) Gather state/exit with priority: side-band -> runOutDir -> latest under output root
        $state = if(Test-Path $sp){ Get-Content -Path $sp -Raw -ErrorAction SilentlyContinue } else { '' }
        $exit  = if(Test-Path $ep){ Get-Content -Path $ep -Raw -ErrorAction SilentlyContinue } else { '' }

        if ([string]::IsNullOrWhiteSpace($exit) -or [string]::IsNullOrWhiteSpace($state)) {
          if ($runOutDir -and (Test-Path -LiteralPath $runOutDir)) {
            $ofState = Join-Path $runOutDir 'state.txt'
            $ofExit  = Join-Path $runOutDir 'exit.code'
            if ([string]::IsNullOrWhiteSpace($state) -and (Test-Path $ofState)) {
              $state = (Get-Content -Path $ofState -Raw -ErrorAction SilentlyContinue).Trim()
            }
            if ([string]::IsNullOrWhiteSpace($exit) -and (Test-Path $ofExit)) {
              $exit = (Get-Content -Path $ofExit -Raw -ErrorAction SilentlyContinue).Trim()
            }
          }
        }

        if ([string]::IsNullOrWhiteSpace($exit) -or [string]::IsNullOrWhiteSpace($state)) {
          if (-not [string]::IsNullOrWhiteSpace($outRoot) -and (Test-Path -LiteralPath $outRoot)) {
            $latest = Get-ChildItem -Path $outRoot -Directory -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -match $tsRegex } |
                      Sort-Object Name -Descending |
                      Select-Object -First 1
            if ($latest) {
              $ofState = Join-Path $latest.FullName 'state.txt'
              $ofExit  = Join-Path $latest.FullName 'exit.code'
              if ([string]::IsNullOrWhiteSpace($state) -and (Test-Path $ofState)) {
                $state = (Get-Content -Path $ofState -Raw -ErrorAction SilentlyContinue).Trim()
              }
              if ([string]::IsNullOrWhiteSpace($exit) -and (Test-Path $ofExit)) {
                $exit = (Get-Content -Path $ofExit -Raw -ErrorAction SilentlyContinue).Trim()
              }
            }
          }
        }

        # 3) Same liveness logic, but now powered by real folder status
        $elapsed = (Get-Date) - $start
        $procAlive=$true; try{ $null = Get-Process -Id $p.Id -ErrorAction Stop }catch{ $procAlive=$false }

        $setDone=$false
        if($state -match 'Complete' -or $exit -eq '0'){ $StatusText.Text='Completed successfully.'; $setDone=$true }
        elseif($state -match 'Failed' -or $exit -eq '1'){ $StatusText.Text='Finished with errors.'; $setDone=$true }
        elseif(-not $procAlive){ $StatusText.Text= if($p.ExitCode -eq 0){'Completed successfully.'}else{'Finished with errors.'}; $setDone=$true }
        elseif($elapsed -ge $timeout){ $StatusText.Text='Finished with errors (timeout).'; $setDone=$true; try{ if(Test-Path $ep){ Set-Content -Path $ep -Value '1' } }catch{} }
        else {
          if($state -match 'ErrorDetected'){ $StatusText.Text='Errors detected (still running)…' }
          elseif($state -match 'Starting' -or [string]::IsNullOrWhiteSpace($StatusText.Text)){ $StatusText.Text='Backing up…' }
        }

        if($setDone){ $timer.Stop() }
      }catch{}
    })
    $timer.Start() | Out-Null
  }

  # --- Buttons ---
  # Run Backup
  $BackupBtn.Add_Click({
    $StatusText.Text='Starting backup…'
    $keep=10; [void][int]::TryParse($RetentionBox.Text,[ref]$keep)
    $payload=@{ TenantId=$TenantBox.Text; AppId=$AppIdBox.Text; ClientSecretPlain=($SecretBox.Password); OutputPath=$OutputBox.Text; RetentionCount=$keep }
    if([string]::IsNullOrWhiteSpace($payload['TenantId']) -or [string]::IsNullOrWhiteSpace($payload['AppId']) -or [string]::IsNullOrWhiteSpace($payload['ClientSecretPlain'])){ $StatusText.Text='Please fill TenantId, AppId, and Client Secret.'; return }
    Start-Engine 'Backup' $payload
    $OutputLink.Visibility='Visible'; $OutputLink.Tag=$OutputBox.Text
  })
  $OutputLink.Add_MouseLeftButtonUp({ if($OutputLink.Tag){ Start-Process explorer.exe $OutputLink.Tag } })

  # Save/Load Config
  function Save-Config{
    $cfg=[ordered]@{ TenantId=$TenantBox.Text; AppId=$AppIdBox.Text; ClientSecretPlain=""; OutputPath=$OutputBox.Text; UseTimestampFolder=[bool]$TimestampChk.IsChecked; AutoBeta=[bool]$AutoBetaChk.IsChecked; RetentionCount=$RetentionBox.Text; Version=$script:BuildVersion }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog; $dlg.Filter = "JSON (*.json)|*.json"; $dlg.FileName = "IntuneBR-config.json"
    if($dlg.ShowDialog() -eq $true){ (ConvertTo-Json -InputObject $cfg -Depth 10 -Compress) | Set-Content -Path $dlg.FileName -Encoding UTF8; $StatusText.Text = "Config saved to $($dlg.FileName)" }
  }
  function Load-Config{
    $dlg = New-Object Microsoft.Win32.OpenFileDialog; $dlg.Filter = "JSON (*.json)|*.json"; $dlg.Multiselect=$false
    if($dlg.ShowDialog() -eq $true){
      try{ $cfg = Get-Content -Path $dlg.FileName -Raw | ConvertFrom-Json -ErrorAction Stop; if($cfg.TenantId){ $TenantBox.Text=$cfg.TenantId }; if($cfg.AppId){ $AppIdBox.Text=$cfg.AppId }; if($cfg.OutputPath){ $OutputBox.Text=$cfg.OutputPath }; if($cfg.UseTimestampFolder -ne $null){ $TimestampChk.IsChecked=[bool]$cfg.UseTimestampFolder }; if($cfg.AutoBeta -ne $null){ $AutoBetaChk.IsChecked=[bool]$cfg.AutoBeta }; if($cfg.RetentionCount){ $RetentionBox.Text=[string]$cfg.RetentionCount }; $StatusText.Text = "Config loaded from $($dlg.FileName). (Client Secret not loaded.)" } catch { $StatusText.Text = "Failed to load config: $($_.Exception.Message)" }
    } else {
      try{ $cfgPath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'IntuneBR-config.json'; if(Test-Path $cfgPath){ $cfg = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -ErrorAction Stop; if($cfg.TenantId){ $TenantBox.Text=$cfg.TenantId }; if($cfg.AppId){ $AppIdBox.Text=$cfg.AppId }; if($cfg.OutputPath){ $OutputBox.Text=$cfg.OutputPath }; if($cfg.UseTimestampFolder -ne $null){ $TimestampChk.IsChecked=[bool]$cfg.UseTimestampFolder }; if($cfg.AutoBeta -ne $null){ $AutoBetaChk.IsChecked=[bool]$cfg.AutoBeta }; if($cfg.RetentionCount){ $RetentionBox.Text=[string]$cfg.RetentionCount }; $StatusText.Text = "Config loaded from Documents\IntuneBR-config.json (secret not loaded)." } else { $StatusText.Text='No config selected and none found in Documents.' } } catch { $StatusText.Text = "Failed to load fallback config: $($_.Exception.Message)" }
    }
  }
  $SaveCfgBtn.Add_Click({ Save-Config })
  $LoadCfgBtn.Add_Click({ Load-Config })

  # Create Nightly Task (DPAPI)
  function New-IntuneNightlyTask {
    param([string]$ScriptPath)
    try {
      if ([string]::IsNullOrWhiteSpace($ScriptPath)) { try { $ScriptPath = (Resolve-Path $PSCommandPath).ProviderPath } catch { $ScriptPath = $null } }
      if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)){
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'PowerShell scripts (*.ps1)|*.ps1|All files (*.*)|*.*'
        $dlg.Title = 'Select the Intune Backup/Restore script (.ps1) to schedule'
        $dlg.Multiselect = $false
        if ($dlg.ShowDialog() -ne $true) { $StatusText.Text='No script selected.'; return }
        $ScriptPath = $dlg.FileName
      }
      $tenant = $TenantBox.Text
      $appid  = $AppIdBox.Text
      $secret = $SecretBox.Password
      $outPath = $OutputBox.Text
      $keep = 10; [void][int]::TryParse($RetentionBox.Text,[ref]$keep)
      if ([string]::IsNullOrWhiteSpace($tenant) -or [string]::IsNullOrWhiteSpace($appid) -or [string]::IsNullOrWhiteSpace($secret) -or [string]::IsNullOrWhiteSpace($outPath)) { $StatusText.Text = 'Please fill TenantId, AppId, Client Secret, and Output Path before creating the task.'; return }
      $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
      if (-not $pwsh) { $pwsh = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" }
      $safeTenant = ($tenant -replace '[^A-Za-z0-9_\-]','_')
      $safeApp    = ($appid  -replace '[^A-Za-z0-9_\-]','_')
      $secretDir = Join-Path $env:ProgramData 'IntuneBR\secrets'
      $secretPath = Join-Path $secretDir ($safeTenant + '__' + $safeApp + '.dpapi')
      Save-DpapiSecret -Secret $secret -Path $secretPath -TenantId $tenant -AppId $appid
      function QuoteArg([string]$s){ '"' + ($s -replace '"','\"') + '"' }
      $argList = @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File', (QuoteArg $ScriptPath),
        '-Mode','Backup','-AuthMode','App',
        '-TenantId', (QuoteArg $tenant),
        '-AppId',    (QuoteArg $appid),
        '-OutputPath',(QuoteArg $outPath),
        '-RetentionCount', ([string]$keep),
        '-SecretPath', (QuoteArg $secretPath)
      )
      if ($TimestampChk.IsChecked) { $argList += '-UseTimestampFolder' }
      if ($AutoBetaChk.IsChecked)  { $argList += '-AutoBeta' }
      if ($DiagChk.IsChecked)      { $argList += '-Diag' }
      $arguments = ($argList -join ' ')
      try{ Import-Module ScheduledTasks -ErrorAction SilentlyContinue }catch{}
      $action = New-ScheduledTaskAction -Execute $pwsh -Argument $arguments
      $trigger = New-ScheduledTaskTrigger -Daily -At 00:00
      $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances Parallel
      $taskName = 'Intune Nightly Backups'
      try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop } catch {}
      try {
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
          -Description 'Nightly Intune backups (DPAPI secret).' -ErrorAction Stop | Out-Null
        $StatusText.Text = "Scheduled task '$taskName' created under SYSTEM to run nightly at 12:00 AM."
      } catch {
        try {
          Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
            -Description 'Nightly Intune backups (DPAPI secret).' -ErrorAction Stop | Out-Null
          $StatusText.Text = "Scheduled task '$taskName' created under current user to run nightly at 12:00 AM."
        } catch {
          $StatusText.Text = "Failed to create scheduled task: $($_.Exception.Message)"
          return
        }
      }
      $StatusText.Text += " Secret stored at $secretPath (DPAPI LocalMachine; ACL: SYSTEM/Admins/you)."
    } catch { $StatusText.Text = "Create task failed: $($_.Exception.Message)" }
  }
  $CreateTaskBtn.Add_Click({ New-IntuneNightlyTask })

  # --- Test App Connection ---
  function Test-EntraAppConnection {
    try {
      $tenant = $TenantBox.Text
      $appid  = $AppIdBox.Text
      $secret = $SecretBox.Password
      if ([string]::IsNullOrWhiteSpace($tenant) -or [string]::IsNullOrWhiteSpace($appid) -or [string]::IsNullOrWhiteSpace($secret)) {
        $StatusText.Text = 'Enter TenantId, AppId, and Client Secret first.'
        return
      }
      $StatusText.Text = 'Testing app connection…'
      $tokenUrl = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
      $body = @{
        client_id     = $appid
        client_secret = $secret
        scope         = 'https://graph.microsoft.com/.default'
        grant_type    = 'client_credentials'
      }
      $resp = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
      $issued = Get-Date
      $exp = $issued.AddSeconds([int]$resp.expires_in)
      $StatusText.Text = "Connection OK. Token issued: $($issued.ToString('s')); expires: $($exp.ToString('s'))"
    }
    catch {
      $msg = $_.Exception.Message
      try {
        if ($_.Exception.Response) {
          $sr = New-Object IO.StreamReader ($_.Exception.Response.GetResponseStream())
          $json = $sr.ReadToEnd() | ConvertFrom-Json -ErrorAction SilentlyContinue
          if ($json.error -or $json.error_description) { $msg = "$($json.error): $($json.error_description)" }
        }
      } catch {}
      $StatusText.Text = "Connection failed: $msg"
    }
  }
  $TestConnBtn.Add_Click({ Test-EntraAppConnection })

  # Restore Button on Restore tab
  $tabs = $win.FindName('MainTabs')
  $restoreTab = $tabs.Items | Where-Object { $_.Header -eq 'Restore (advanced)' }
  $grid = $restoreTab.Content
  $RestoreBtn = New-Object System.Windows.Controls.Button
  $RestoreBtn.Content='Run Restore'; $RestoreBtn.Width=160; $RestoreBtn.Height=34
  [System.Windows.Controls.Grid]::SetRow($RestoreBtn,3); $RestoreBtn.Margin='0,48,0,0'
  [void]$grid.Children.Add($RestoreBtn)
  $RestoreBtn.Add_Click({
    $RStatusText.Text='Starting restore…'
    $payload=@{ TenantId=$RTenantBox.Text; AppId=$RAppIdBox.Text; ClientSecretPlain=($RSecretBox.Password); InputPath=$InputBox.Text }
    if($ForceRestoreChk.IsChecked){ $payload['ForceRestore']='True' }
    if([string]::IsNullOrWhiteSpace($payload['TenantId']) -or [string]::IsNullOrWhiteSpace($payload['AppId']) -or [string]::IsNullOrWhiteSpace($payload['ClientSecretPlain']) -or [string]::IsNullOrWhiteSpace($payload['InputPath'])){ $RStatusText.Text='Please fill TenantId, AppId, Client Secret, and Input Path.'; return }
    Start-Engine 'Restore' $payload
  })
  [void]$win.ShowDialog()
  return
}

try{
  switch($Mode){
    'Backup' { Run-Backup -TenantId $TenantId -AppId $AppId -ClientSecretPlain $ClientSecretPlain -OutputPath $OutputPath -RetentionCount $RetentionCount }
    'Restore' { Run-Restore -TenantId $TenantId -AppId $AppId -ClientSecretPlain $ClientSecretPlain -InputPath $InputPath -ForceRestore:$ForceRestore }
    'UI' { } # UI launched above
  }
}
catch{
  try{ Log 'ERROR' ("Unhandled: " + $_.Exception.Message) }catch{}
  try{ Set-Content -Path (Join-Path $script:LogFolder 'state.txt') -Value 'Failed'; Set-Content -Path (Join-Path $script:LogFolder 'exit.code') -Value '1'; Signal-UI 'Failed' '1' }catch{}
  throw
}
