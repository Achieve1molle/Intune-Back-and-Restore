
# Intune Backup & Restore Script

This PowerShell script provides a comprehensive solution for backing up and restoring Microsoft Intune configurations. It supports both command-line and graphical user interface (WPF) modes, making it accessible for both automation and interactive use.

## Features
- Backup Intune configuration items via Microsoft Graph API
- Restore backed-up configurations
- WPF UI for interactive usage
- Console wizard fallback for non-UI environments
- Supports multiple authentication modes: Browser, Device Code, App (Client Credentials)
- Timestamped backup folders with retention policy
- Verbose logging and heartbeat monitoring

## Prerequisites
- PowerShell 7 or later
- Microsoft.Graph PowerShell SDK
- Appropriate permissions in Azure AD for accessing Intune resources

## Usage
### Command-Line
```powershell
pwsh -File Intune-BackupRestore.AllInOne.v2.fixed3l_r3e4p.ps1 -Mode Backup -TenantId "<tenant-id>" -AuthMode Browser
```

### UI Mode
```powershell
pwsh -File Intune-BackupRestore.AllInOne.v2.fixed3l_r3e4p.ps1 -Mode UI
```

## Parameters
- `Mode`: UI, Backup, Restore, Wizard (default: UI)
- `AuthMode`: Browser, DeviceCode, App (default: Browser)
- `TenantId`: Azure AD tenant ID
- `AppId`: Application (Client) ID for App authentication
- `ClientSecretPlain`: Client secret for App authentication
- `CertThumbprint`, `CertPath`, `CertPasswordPlain`: Certificate-based authentication options
- `UseBeta`, `AutoBeta`, `AutoUpdateGraph`: Graph API profile options
- `OutputPath`, `InputPath`: Paths for backup and restore
- `Include`: Specific Intune collections to include
- `RetentionCount`: Number of backups to retain

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author
Michael Molle
