# AD Import Script

This PowerShell script monitors a shared directory and email inbox for new CSV or XML files, parses and sanitizes the data, and imports users and computers into Active Directory.

## Features
- Monitors a shared directory for new files
- Fetches emails with specific subjects and processes attachments
- Parses both CSV and XML files
- Sanitizes and validates input data
- Imports users and computers into Active Directory
- Logs operations and sends notifications on errors

## Configuration
Update the `$config` section in the script to match your environment settings. I've assumed usage of Azure Key Vault, Microsoft Graph API, and Exchange Web Services

```powershell
$config = @{
    EWSPath         = "C:\\Program Files\\Microsoft\\Exchange\\Web Services\\2.2\\Microsoft.Exchange.WebServices.dll"
    SavePath        = "Y:\\ADImports\\"
    UsersPath       = "Y:\\ADImports\\Users\\"
    ComputersPath   = "Y:\\ADImports\\Computers\\"
    LogsPath        = "Y:\\ADImports\\Logs\\"
    ArchivePath     = "Y:\\ADImports\\Archive\\"
    ProcessedPath   = "Y:\\ADImports\\Processed\\"
    Mailbox         = "importdata@companyname.com"
    Credentials     = Get-Credential
    LogPath         = "Y:\\ADImports\\Logs\\import.log"
    KeyVaultName    = "YourKeyVaultName"
    SecretName      = "ADImportPassword"
}
