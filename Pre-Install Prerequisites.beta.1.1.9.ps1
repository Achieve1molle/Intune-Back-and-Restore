<#
.SYNOPSIS
 Installs prerequisites for the Intune Backup/Restore script (no winget).

.DESCRIPTION
 - Sets Execution Policy (LocalMachine & CurrentUser) to RemoteSigned
 - Prefers PSResourceGet for PSGallery registration & trust (fallback to PowerShellGet)
 - Optional reachability probe with resilient timeouts
 - Ensures NuGet provider ONLY if PowerShellGet fallback is used
 - Installs Microsoft.Graph (latest) via PSResourceGet first; falls back to Install-Module
 - Ensures .NET Desktop Runtime (x64) via local EXE or dotnet-install.ps1 (accepts .NET 8 or 9)
 - Ensures RSAT ScheduledTasks (Server feature / Client FoD)
 - Prints verification summary

.PARAMETER DesktopRuntimeInstaller
 Optional path to a local Desktop Runtime EXE (e.g., windowsdesktop-runtime-8.0.21-win-x64.exe).

.PARAMETER DotNetChannel
 Channel for dotnet-install (default 8.0). Example: 8.0 | 9.0 | LTS.

.PARAMETER DotNetVersion
 Optional exact Desktop Runtime version for dotnet-install (e.g., 8.0.21).

.PARAMETER ProxyUrl
 Optional HTTP/HTTPS proxy URL (e.g., http://proxy:8080). Sets DefaultWebProxy + HTTP(S)_PROXY.

.PARAMETER ProxyUseDefaultCredentials
 Use current user’s credentials for the proxy.

.PARAMETER SkipRSAT
 Skips RSAT ScheduledTasks ensure step.

.NOTES
 Script Version : Beta 1.1.9
 Author        : Michael Molle
 Last Updated  : 2025-10-28

.NOTES
 Run as Administrator in PowerShell 7 (pwsh).

#>

[CmdletBinding()]
param(
  [string]$DesktopRuntimeInstaller,
  [string]$DotNetChannel = '8.0',
  [string]$DotNetVersion,
  [string]$ProxyUrl,
  [switch]$ProxyUseDefaultCredentials,
  [switch]$SkipRSAT
)

# ---------------- Helpers ----------------
function Have-Command {
  param([string]$Name)
  return (Get-Command $Name -ErrorAction SilentlyContinue) -ne $null
}

function Ensure-Tls12 {
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
}

function Set-SessionProxy {
  param([string]$Url,[switch]$UseDefaultCreds)
  try {
    if ([string]::IsNullOrWhiteSpace($Url)) { return }
    $proxy = New-Object System.Net.WebProxy($Url, $true)
    if ($UseDefaultCreds) { $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials }
    [System.Net.WebRequest]::DefaultWebProxy = $proxy
    $env:HTTPS_PROXY = $Url
    $env:HTTP_PROXY  = $Url
    Write-Host "Using proxy: $Url (DefaultCredentials=$($UseDefaultCreds.IsPresent))"
  } catch {
    Write-Warning "Failed to configure proxy: $($_.Exception.Message)"
  }
}

function Try-Set-ExecutionPolicy {
  param(
    [Parameter(Mandatory)]
    [ValidateSet('RemoteSigned','AllSigned','Unrestricted','Bypass','Restricted')]
    [string]$Policy
  )
  Write-Host "Setting ExecutionPolicy (LocalMachine) -> $Policy"
  try   { Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy $Policy -Force -ErrorAction Stop }
  catch { Write-Warning "LocalMachine scope failed: $($_.Exception.Message)" }

  Write-Host "Setting ExecutionPolicy (CurrentUser) -> $Policy"
  try   { Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy $Policy -Force -ErrorAction Stop }
  catch { Write-Warning "CurrentUser scope failed: $($_.Exception.Message)" }
}

# -------- Prefer PSResourceGet for PSGallery; fallback to PowerShellGet --------
function Ensure-PSGallery-Trusted {
  [CmdletBinding()]
  param([int]$WebTimeoutSec = 45)

  $psrg = Have-Command 'Install-PSResource'
  if ($psrg) {
    try {
      $repo = $null
      try { $repo = Get-PSResourceRepository -Name PSGallery -ErrorAction SilentlyContinue } catch {}
      if (-not $repo) {
        Write-Host "Registering PSGallery via PSResourceGet..."
        Register-PSResourceRepository -PSGallery -Trusted -ErrorAction SilentlyContinue | Out-Null
      } elseif (-not $repo.Trusted) {
        Write-Host "Marking existing PSGallery repo as Trusted (PSResourceGet)..."
        Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction SilentlyContinue
      } else {
        Write-Host "PSGallery already registered and trusted (PSResourceGet)."
      }
    } catch {
      Write-Warning "PSResourceGet repository step hit an issue: $($_.Exception.Message)"
    }

    try {
      Write-Verbose "PSGallery probe via web request..."
      $null = Invoke-WebRequest -Uri 'https://www.powershellgallery.com/api/v2' -UseBasicParsing -TimeoutSec $WebTimeoutSec -ErrorAction Stop
      Write-Host "PSGallery reachable."
    } catch {
      Write-Warning "PSGallery probe failed or timed out: $($_.Exception.Message)"
      Write-Host "If you're behind a proxy, re-run with -ProxyUrl and -ProxyUseDefaultCredentials."
    }
  }
  else {
    try {
      $repo = $null
      try { $repo = Get-PSRepository -ErrorAction SilentlyContinue | Where-Object Name -eq 'PSGallery' } catch {}
      if (-not $repo) {
        if ((Get-Command Register-PSRepository -ErrorAction SilentlyContinue).Parameters.ContainsKey('Default')) {
          Write-Host "Restoring PSGallery with Register-PSRepository -Default..."
          Register-PSRepository -Default -ErrorAction SilentlyContinue
        } else {
          Write-Host "Registering PSGallery with explicit URLs (PowerShellGet)..."
          Register-PSRepository -Name 'PSGallery' `
            -SourceLocation 'https://www.powershellgallery.com/api/v2' `
            -ScriptSourceLocation 'https://www.powershellgallery.com/api/v2' `
            -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }
      } elseif ($repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
      } else {
        Write-Host "PSGallery already registered and trusted (PowerShellGet)."
      }
    } catch {
      Write-Warning "PowerShellGet repository step hit an issue: $($_.Exception.Message)"
    }

    try {
      Write-Verbose "PSGallery probe via web request..."
      $null = Invoke-WebRequest -Uri 'https://www.powershellgallery.com/api/v2' -UseBasicParsing -TimeoutSec $WebTimeoutSec -ErrorAction Stop
      Write-Host "PSGallery reachable."
    } catch {
      Write-Warning "PSGallery probe failed or timed out: $($_.Exception.Message)"
      Write-Host "If you're behind a proxy, re-run with -ProxyUrl and -ProxyUseDefaultCredentials."
    }
  }
}

# Only needed if we fall back to PowerShellGet
function Ensure-NuGet-Provider {
  Write-Host "Ensuring NuGet provider (PowerShellGet fallback path only)..."
  try {
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
      Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
    } else {
      Write-Host "NuGet provider already available."
    }
  } catch {
    Write-Warning "NuGet provider install failed: $($_.Exception.Message)"
  }
}

# -------- Prefer PSResourceGet to install Microsoft.Graph; fallback to Install-Module --------
function Ensure-GraphSDK {
  Write-Host "`n=== Ensure Microsoft.Graph PowerShell SDK ==="
  try {
    if (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) {
      Write-Host "Microsoft.Graph already available."
      return $true
    }
    $psrg = Have-Command 'Install-PSResource'
    if ($psrg) {
      Write-Host "Installing Microsoft.Graph via PSResourceGet..."
      try {
        $repo = $null
        try { $repo = Get-PSResourceRepository -Name PSGallery -ErrorAction SilentlyContinue } catch {}
        if (-not $repo) {
          Register-PSResourceRepository -PSGallery -Trusted -ErrorAction SilentlyContinue | Out-Null
        } elseif (-not $repo.Trusted) {
          Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction SilentlyContinue
        }
        Install-PSResource -Name Microsoft.Graph -Scope CurrentUser -TrustRepository -ErrorAction Stop
        return (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) -ne $null
      } catch {
        Write-Warning "Install-PSResource failed: $($_.Exception.Message)"
      }
    }

    Write-Host "Falling back to Install-Module (PowerShellGet)..."
    Ensure-NuGet-Provider
    try {
      $repo = $null
      try { $repo = Get-PSRepository -ErrorAction SilentlyContinue | Where-Object Name -eq 'PSGallery' } catch {}
      if (-not $repo) {
        if ((Get-Command Register-PSRepository -ErrorAction SilentlyContinue).Parameters.ContainsKey('Default')) {
          Register-PSRepository -Default -ErrorAction SilentlyContinue
        } else {
          Register-PSRepository -Name 'PSGallery' `
            -SourceLocation 'https://www.powershellgallery.com/api/v2' `
            -ScriptSourceLocation 'https://www.powershellgallery.com/api/v2' `
            -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }
      } elseif ($repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
      }
      Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
      return (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) -ne $null
    } catch {
      Write-Warning "Install-Module failed: $($_.Exception.Message)"
      return $false
    }
  } catch {
    Write-Warning "Failed to install Microsoft.Graph: $($_.Exception.Message)"
    return $false
  }
}

# -------- Desktop Runtime detection (CLI + Registry + FS) --------
function Get-InstalledWindowsDesktopRuntime {
  [CmdletBinding()]
  param([ValidateSet('x64','x86')] [string]$Arch = 'x64')

  $found = @()

  # 1) Try known hosts explicitly
  $candidates = @('dotnet')
  $x64Host = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
  $x86Host = Join-Path ${env:ProgramFiles(x86)} 'dotnet\dotnet.exe'
  if (Test-Path $x64Host) { $candidates += $x64Host }
  if (Test-Path $x86Host) { $candidates += $x86Host }

  foreach ($candidate in $candidates | Select-Object -Unique) {
    try {
      $out = & $candidate --list-runtimes 2>$null
      foreach ($line in $out) {
        $m = [regex]::Match($line, '^(?<name>Microsoft\.WindowsDesktop\.App)\s+(?<ver>[\d\.]+)\s+\[(?<path>[^\]]+)\]')
        if ($m.Success) {
          $isX64Path = $m.Groups['path'].Value -like "$($env:ProgramFiles)\*"
          $isX86Path = $m.Groups['path'].Value -like "$(${env:ProgramFiles(x86)})\*"
          if ( ($Arch -eq 'x64' -and $isX64Path) -or ($Arch -eq 'x86' -and $isX86Path) ) {
            $found += [pscustomobject]@{
              Version = $m.Groups['ver'].Value
              Path    = $m.Groups['path'].Value
              Source  = 'dotnet'
            }
          }
        }
      }
    } catch {}
  }

  # 2) Registry
  $regPath = if ($Arch -eq 'x64') {
    'HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App'
  } else {
    'HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x86\sharedfx\Microsoft.WindowsDesktop.App'
  }
  if (Test-Path $regPath) {
    Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
      $found += [pscustomobject]@{
        Version = $_.PSChildName
        Path    = $null
        Source  = 'registry'
      }
    }
  }

  # 3) File system
  $fsPath = if ($Arch -eq 'x64') {
    Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.WindowsDesktop.App'
  } else {
    Join-Path ${env:ProgramFiles(x86)} 'dotnet\shared\Microsoft.WindowsDesktop.App'
  }
  if (Test-Path $fsPath) {
    Get-ChildItem $fsPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $found += [pscustomobject]@{
        Version = $_.Name
        Path    = $_.FullName
        Source  = 'fs'
      }
    }
  }

  $found | Sort-Object { [version]$_.Version } -Descending | Select-Object -Unique
}

# -------- Install Desktop Runtime (in-process dotnet-install + fixed path + robust verification) --------
function Install-DesktopRuntime {
  [CmdletBinding()]
  param(
    [string]$DesktopRuntimeInstaller,
    [string]$DotNetChannel = '8.0',
    [string]$DotNetVersion,
    [string]$ProxyUrl,
    [switch]$ProxyUseDefaultCredentials
  )

  Write-Host "`n=== Ensure .NET Desktop Runtime (x64) for WPF UI ==="

  # Accept either .NET 8.x or 9.x unless a specific version is requested
  $installed = Get-InstalledWindowsDesktopRuntime -Arch x64
  $hasNeeded = if ($DotNetVersion) {
    $installed | Where-Object { $_.Version -eq $DotNetVersion }
  } else {
    $installed | Where-Object { $_.Version -match '^(8|9)\.' }
  }

  if ($hasNeeded) {
    Write-Host ("WindowsDesktop runtime already present: {0}" -f (($hasNeeded | Select-Object -Expand Version) -join ', '))
    return $true
  }

  # 1) Try local EXE if provided
  if ($DesktopRuntimeInstaller) {
    if (-not (Test-Path -LiteralPath $DesktopRuntimeInstaller)) {
      Write-Warning "Desktop Runtime EXE not found at: $DesktopRuntimeInstaller"
    } else {
      Write-Host "Installing Desktop Runtime from EXE: $DesktopRuntimeInstaller"
      try {
        $p = Start-Process -FilePath $DesktopRuntimeInstaller -ArgumentList '/install /quiet /norestart' -PassThru -Wait -ErrorAction Stop
        if ($p.ExitCode -ne 0) { Write-Warning "Installer exit code: $($p.ExitCode)" }
      } catch {
        Write-Warning "Desktop Runtime EXE failed: $($_.Exception.Message)"
      }
    }
    # Re-check
    $installed = Get-InstalledWindowsDesktopRuntime -Arch x64
    if ($DotNetVersion) { $installed = $installed | Where-Object { $_.Version -eq $DotNetVersion } }
    else { $installed = $installed | Where-Object { $_.Version -match '^(8|9)\.' } }
    if ($installed) { Write-Host "WindowsDesktop runtime installed: $($installed[0].Version)"; return $true }
    Write-Warning "Desktop Runtime not detected after EXE install attempt."
  }

  # 2) Fallback: dotnet-install.ps1 in current process (so PATH is updated here)
  $tmp = Join-Path $env:TEMP ("dotnet-install-" + [guid]::NewGuid().ToString("N") + ".ps1")
  $installDir = Join-Path $env:ProgramFiles 'dotnet'

  try {
    Write-Host "Downloading Microsoft's dotnet-install.ps1 ..."
    Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $tmp -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop

    $args = @(
      '-Runtime','windowsdesktop',
      '-Architecture','x64',
      '-InstallDir', $installDir,
      '-Channel', $DotNetChannel
    )
    if ($DotNetVersion) { $args += @('-Version', $DotNetVersion) }
    if ($ProxyUrl) {
      $args += @('-ProxyAddress', $ProxyUrl)
      if ($ProxyUseDefaultCredentials) { $args += '-ProxyUseDefaultCredentials' }
    }

    Write-Host "Installing Desktop Runtime via dotnet-install.ps1 ($($args -join ' ')) ..."
    & $tmp @args  # run in current session

    # Ensure current session can find it
    if (-not ($env:PATH -split ';' | Where-Object { $_ -ieq $installDir })) { $env:PATH = "$installDir;$env:PATH" }
    if (-not $env:DOTNET_ROOT) { $env:DOTNET_ROOT = $installDir }
  }
  catch {
    Write-Warning "dotnet-install.ps1 download/run failed: $($_.Exception.Message)"
  }
  finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }

  # Final verification
  $installed = Get-InstalledWindowsDesktopRuntime -Arch x64
  if ($DotNetVersion) { $installed = $installed | Where-Object { $_.Version -eq $DotNetVersion } }
  else { $installed = $installed | Where-Object { $_.Version -match '^(8|9)\.' } }
  if ($installed) {
    Write-Host "WindowsDesktop runtime installed successfully: $($installed[0].Version)"
    return $true
  }

  Write-Warning "Desktop Runtime still not detected. Manual download (Desktop Runtime x64): https://dotnet.microsoft.com/en-us/download/dotnet"
  return $false
}

function Ensure-RSAT-ScheduledTasks {
  Write-Host "`n=== Ensure RSAT: ScheduledTasks module ==="
  try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $isServer = $os.ProductType -in 2,3
    $imported = $false
    if ($isServer) {
      try {
        if (Get-Module -ListAvailable -Name ServerManager) { Import-Module ServerManager -ErrorAction SilentlyContinue }
        $feat = Get-WindowsFeature -Name RSAT-ScheduledTasks -ErrorAction SilentlyContinue
        if (-not $feat -or -not $feat.Installed) {
          Write-Host "Installing Windows Feature: RSAT-ScheduledTasks"
          Install-WindowsFeature RSAT-ScheduledTasks -Restart:$false | Out-Null
        } else {
          Write-Host "RSAT-ScheduledTasks already installed."
        }
      } catch {
        Write-Warning "Server feature step hit an issue: $($_.Exception.Message)"
      }
    } else {
      try {
        $capName = 'Rsat.TaskScheduler.Tools~~~~0.0.1.0'
        $cap = Get-WindowsCapability -Online -Name $capName -ErrorAction SilentlyContinue
        if ($cap -and $cap.State -ne 'Installed') {
          Write-Host "Adding Windows capability: $capName"
          Add-WindowsCapability -Online -Name $capName -ErrorAction SilentlyContinue | Out-Null
        } elseif (-not $cap) {
          Write-Host "RSAT Task Scheduler capability not advertised on this edition; module may already be present."
        } else {
          Write-Host "RSAT Task Scheduler capability already installed."
        }
      } catch {
        Write-Warning "Client capability step hit an issue: $($_.Exception.Message)"
      }
    }

    try { Import-Module ScheduledTasks -Force -ErrorAction Stop; $imported = $true } catch { $imported = $false }
    if ($imported) { Write-Host "ScheduledTasks module is available and importable."; return $true }
    else { Write-Warning "ScheduledTasks module is not importable. Fallback to 'schtasks.exe' remains possible."; return $false }
  } catch {
    Write-Warning "RSAT ensure step skipped due to: $($_.Exception.Message)"
    return $false
  }
}

function Verify-Summary {
  Write-Host "`n=== Verification summary ==="
  try {
    $execLM = (Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue)
    $execCU = (Get-ExecutionPolicy -Scope CurrentUser  -ErrorAction SilentlyContinue)
    $graph  = (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) -ne $null
    $desktopX64 = Get-InstalledWindowsDesktopRuntime -Arch x64 | Select-Object -Expand Version -ErrorAction SilentlyContinue
    $pw7    = Have-Command 'pwsh'
    $scht   = $false; try { Import-Module ScheduledTasks -ErrorAction Stop; $scht = $true } catch {}

    Write-Host ("PowerShell 7 present           : {0}" -f ($pw7 ? 'Yes' : 'No'))
    Write-Host ("ExecutionPolicy (LocalMachine) : {0}" -f ($execLM ?? '<unknown>'))
    Write-Host ("ExecutionPolicy (CurrentUser)  : {0}" -f ($execCU ?? '<unknown>'))
    Write-Host ("Microsoft.Graph available      : {0}" -f ($graph ? 'Yes' : 'No'))
    Write-Host ("WindowsDesktop (x64) versions  : {0}" -f ($(if ($desktopX64) { ($desktopX64 -join ', ') } else { 'None' })))
    Write-Host ("ScheduledTasks module present  : {0}" -f ($scht ? 'Yes' : 'No'))

    if ($pw7 -and $graph -and $desktopX64 -and $scht -and ($execLM -eq 'RemoteSigned' -or $execCU -eq 'RemoteSigned')) {
      Write-Host "`nAll core prerequisites look good. You can run the Intune UI with:"
      Write-Host ' pwsh -File .\Intune-BackupRestore.ps1 -Mode UI' -ForegroundColor Cyan
    } else {
      Write-Warning "One or more prerequisites may still be missing. Review the summary above."
      Write-Host  "If Desktop Runtime is missing, install the x64 Desktop Runtime manually:"
      Write-Host  " https://dotnet.microsoft.com/en-us/download/dotnet"
    }
  } catch {
    Write-Warning "Verification step hit an error: $($_.Exception.Message)"
  }
}

# ---------------- Main ----------------
# Admin check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Please run this script in an elevated PowerShell session (Run as Administrator)."
}

Ensure-Tls12
Set-SessionProxy -Url $ProxyUrl -UseDefaultCreds:$ProxyUseDefaultCredentials

Write-Host "=== 1) Set Execution Policy to RemoteSigned (persistent) ==="
Try-Set-ExecutionPolicy -Policy RemoteSigned

Write-Host "`n=== 2) Trust PSGallery & Ensure NuGet (fallback only) ==="
Ensure-PSGallery-Trusted -Verbose
if (-not (Have-Command 'Install-PSResource')) { Ensure-NuGet-Provider }

Write-Host "`n=== 3) Install Microsoft.Graph ==="
Ensure-GraphSDK | Out-Null

Write-Host "`n=== 4) Install .NET Desktop Runtime (x64) ==="
Install-DesktopRuntime -DesktopRuntimeInstaller $DesktopRuntimeInstaller -DotNetChannel $DotNetChannel -DotNetVersion $DotNetVersion -ProxyUrl $ProxyUrl -ProxyUseDefaultCredentials:$ProxyUseDefaultCredentials | Out-Null

if (-not $SkipRSAT) {
  Write-Host "`n=== 5) Ensure RSAT ScheduledTasks ==="
  Ensure-RSAT-ScheduledTasks | Out-Null
} else {
  Write-Host "`n[Skip] RSAT ScheduledTasks ensure (user requested)."
}

Verify-Summary
Write-Host "`n=== Install complete. If Desktop Runtime remains missing, install it manually, then rerun your script. ==="