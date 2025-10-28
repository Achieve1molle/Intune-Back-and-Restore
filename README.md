
# Intune Backup & Restore Script

This PowerShell script provides a comprehensive solution for backing up and restoring Microsoft Intune configurations. It supports both command-line and graphical user interface (WPF) modes, making it accessible for both automation and interactive use.

## Features
    - Backup of Intune entities such as device configurations, compliance policies, scripts, apps, and more.
    - Restore functionality with optional dry-run mode.
    - Secure storage of secrets using DPAPI (LocalMachine scope).
    - UI interface for ease of use.
    - Scheduled nightly backup task creation.
    - OAuth2 client credentials flow validation.
    - Support for Microsoft Graph v1.0 and beta profiles.
    - Automatic retention management of backup folders.

## Prerequisites
 -Entra Permissions for Application Creation
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

## Usage
### Command-Line
    # Run backup with timestamp folder and retention
    pwsh -File .\Intune-BackupRestore.v3.3.7k2m.ps1 -Mode Backup -AuthMode App -TenantId "<tenant>" -AppId "<appid>" -ClientSecretPlain "<secret>" -OutputPath "C:\Staging\Backup" -UseTimestampFolder -RetentionCount 10

    # Run restore with dry-run
    pwsh -File .\Intune-BackupRestore.v3.3.7k2m.ps1 -Mode Restore -AuthMode App -TenantId "<tenant>" -AppId "<appid>" -ClientSecretPlain "<secret>" -InputPath "C:\Staging\Backup\latest"

    # Run restore with object creation
    pwsh -File .\Intune-BackupRestore.v3.3.7k2m.ps1 -Mode Restore -AuthMode App -TenantId "<tenant>" -AppId "<appid>" -ClientSecretPlain "<secret>" -InputPath "C:\Staging\Backup\latest" -ForceRestore

    # Launch UI
    pwsh -File .\Intune-BackupRestore.v3.3.7k2m.ps1 -Mode UI

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author
Michael Molle
