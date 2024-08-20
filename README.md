
# Unified AD Import and Provisioning Scripts

This repository contains two PowerShell scripts designed to automate the process of user and device management in an enterprise environment. The scripts handle tasks such as importing users and devices into Active Directory (AD), provisioning users in Azure AD, assigning Microsoft 365 licenses, enrolling devices in Intune, applying compliance policies, and managing Microsoft Defender configurations.

## Script 1: AD Import Script (`AD-Import-1.ps1`)

### Overview

The **AD Import Script** monitors a shared directory and an email inbox for new CSV or XML files, parses and sanitizes the data, and imports users and computers into an on-premises Active Directory. This script is useful for environments where Active Directory is still the primary user and computer management solution.

### Features

- **Monitors a shared directory** for new files to process.
- **Fetches emails** from a specified inbox and processes attachments containing user or computer data.
- **Parses both CSV and XML files**, sanitizes and validates the input data to ensure it's safe and correct.
- **Imports users and computers** into Active Directory based on the sanitized data.
- **Logs all operations** and sends notifications in case of errors.

### Configuration

Update the `$config` section in the script to match your environment settings. The script uses Azure Key Vault for secure password management, Microsoft Graph API for email fetching, and Exchange Web Services (EWS) for mailbox access.

```powershell
$config = @{
    EWSPath         = "C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll"
    SavePath        = "Y:\ADImports\"
    UsersPath       = "Y:\ADImports\Users\"
    ComputersPath   = "Y:\ADImports\Computers\"
    LogsPath        = "Y:\ADImports\Logs\"
    ArchivePath     = "Y:\ADImports\Archive\"
    ProcessedPath   = "Y:\ADImports\Processed\"
    Mailbox         = "importdata@companyname.com"
    Credentials     = Get-Credential
    LogPath         = "Y:\ADImports\Logs\import.log"
    KeyVaultName    = "YourKeyVaultName"
    SecretName      = "ADImportPassword"
}
```

### Usage

1. **Configuration**: Modify the configuration section in the script to specify your paths, mailbox settings, and key vault details.
2. **Monitoring**: The script will monitor the specified directory and mailbox for new CSV or XML files.
3. **Processing**: Upon detecting a new file, the script will parse, sanitize, and validate the data before importing users and computers into AD.
4. **Logging**: All actions are logged, and notifications are sent in case of any issues.

## Script 2: Unified User and Device Provisioning Script (`AD-Import-2.ps1`)

### Overview

The **Unified User and Device Provisioning Script** is designed to manage modern cloud environments using Azure AD, Microsoft 365, Intune, and Microsoft Defender. It automates the provisioning of users, assigns necessary licenses, enrolls devices in Intune, assigns Autopilot profiles, and applies compliance and security policies.

### Features

- **User Creation**: Automatically creates users in Azure AD with unique, secure passwords.
- **License Assignment**: Assigns Microsoft 365, Azure AD Premium, Enterprise Mobility + Security, and Microsoft Defender licenses.
- **Device Enrollment**: Enrolls devices into Intune and applies compliance and configuration policies.
- **Autopilot Configuration**: Assigns Autopilot deployment profiles to newly enrolled devices.
- **Microsoft Defender**: Applies Microsoft Defender policies for endpoint security.
- **Secure Password Handling**: Generates and securely sends unique passwords to users or administrators.
- **Logging and Notifications**: Logs all operations and sends notifications in case of errors.

### Configuration

Update the `$config` section in the script to match your environment settings. The script integrates with Azure Key Vault for secure password management, Microsoft Graph API for user and device management, and an SMTP server for securely communicating passwords.

```powershell
$config = @{
    SavePath        = "Y:\ADImports\"
    UsersPath       = "Y:\ADImports\Users\"
    LogsPath        = "Y:\ADImports\Logs\"
    ArchivePath     = "Y:\ADImports\Archive\"
    ProcessedPath   = "Y:\ADImports\Processed\"
    Mailbox         = "importdata@companyname.com"
    LogPath         = "Y:\ADImports\Logs\import.log"
    KeyVaultName    = "YourKeyVaultName"
    SecretName      = "ADImportPassword"
    TenantId        = "YourTenantId"
    ClientId        = "YourClientId"
    ClientSecret    = (Get-AzKeyVaultSecret -VaultName $config.KeyVaultName -Name $config.SecretName).SecretValueText
    SmtpServer      = "smtp.yourdomain.com"
    AdminEmail      = "admin@yourdomain.com"
}
```

### Usage

1. **Configuration**: Update the configuration section to specify paths, Azure AD tenant information, SMTP server details, and other settings.
2. **Monitoring**: The script continuously monitors the specified shared directory for new CSV or XML files.
3. **Provisioning**: Upon detecting a new file, the script processes the data, creates users in Azure AD, assigns licenses, enrolls devices in Intune, assigns Autopilot profiles, and applies necessary security policies.
4. **Secure Password Distribution**: The script generates secure passwords for new users and sends them via email to the user’s alternate email or an administrator.
5. **Logging**: All operations are logged, and notifications are sent if any errors occur.

## Differences Between the Scripts

1. **Target Environment**:
   - **AD-Import-1.ps1** is focused on traditional on-premises Active Directory environments.
   - **AD-Import-2.ps1** is designed for modern cloud environments using Azure AD, Microsoft 365, Intune, and Microsoft Defender.

2. **User Management**:
   - **AD-Import-1.ps1** imports users and computers into an on-premises Active Directory.
   - **AD-Import-2.ps1** creates users in Azure AD and assigns cloud-based licenses and security policies.

3. **Device Management**:
   - **AD-Import-1.ps1** primarily focuses on user and computer objects within AD.
   - **AD-Import-2.ps1** includes device enrollment in Intune, configuration profile assignment, and Autopilot profile assignment.

4. **Security and Compliance**:
   - **AD-Import-1.ps1** includes input sanitization and validation but is focused on AD security.
   - **AD-Import-2.ps1** includes comprehensive security measures like Microsoft Defender integration, compliance policies, and secure password management.

5. **Technology Stack**:
   - **AD-Import-1.ps1** relies on Active Directory, Azure Key Vault, and EWS/Graph API for email integration.
   - **AD-Import-2.ps1** utilizes Azure AD, Microsoft Graph API, Intune, and Microsoft Defender for cloud-based management.
