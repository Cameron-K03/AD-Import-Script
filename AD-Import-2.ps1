[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("Graph")]
    [string]$InputMethod = "Graph"
)

# Import required modules
Import-Module Az.Accounts
Import-Module Microsoft.Graph
Import-Module Microsoft.Graph.Intune

# Configuration settings
$config = @{
    SavePath        = "Y:\\ADImports\\"
    UsersPath       = "Y:\\ADImports\\Users\\"
    LogsPath        = "Y:\\ADImports\\Logs\\"
    ArchivePath     = "Y:\\ADImports\\Archive\\"
    ProcessedPath   = "Y:\\ADImports\\Processed\\"
    Mailbox         = "importdata@companyname.com"
    LogPath         = "Y:\\ADImports\\Logs\\import.log"
    KeyVaultName    = "YourKeyVaultName"
    SecretName      = "ADImportPassword"
    TenantId        = "YourTenantId"
    ClientId        = "YourClientId"
    ClientSecret    = (Get-AzKeyVaultSecret -VaultName $config.KeyVaultName -Name $config.SecretName).SecretValueText
    SmtpServer      = "smtp.yourdomain.com"
    AdminEmail      = "admin@yourdomain.com"  # Where to send the passwords for secure communication
}

# Ensure directories exist
$paths = @($config.SavePath, $config.UsersPath, $config.LogsPath, $config.ArchivePath, $config.ProcessedPath)
foreach ($path in $paths) {
    if (-not (Test-Path -Path $path)) {
        New-Item -ItemType Directory -Path $path
    }
}

# Logging 
function Log-Message {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$type] $message"
    Add-Content -Path $config.LogPath -Value $logMessage
}

# Authenticate with Microsoft Graph
function Connect-Graph {
    $scope = "https://graph.microsoft.com/.default"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $config.ClientId
        client_secret = $config.ClientSecret
        scope         = $scope
    }
    $authResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$($config.TenantId)/oauth2/v2.0/token" -Method Post -Body $body
    $authHeader = @{
        Authorization = "Bearer $($authResponse.access_token)"
    }
    return $authHeader
}

# Generate a secure password
function Generate-SecurePassword {
    Add-Type -AssemblyName "System.Web"
    $password = [System.Web.Security.Membership]::GeneratePassword(16, 4)
    return $password
}

# Send password via email
function Send-PasswordEmail {
    param (
        [string]$userEmail,
        [string]$password
    )

    $smtpFrom = $config.AdminEmail
    $smtpTo = $userEmail
    $subject = "Your New Account Password"
    $body = "Hello,`n`nYour new account has been created. Here is your initial password:`n`nPassword: $password`n`nPlease change this password as soon as possible after logging in."

    $message = New-Object System.Net.Mail.MailMessage $smtpFrom, $smtpTo, $subject, $body
    $smtp = New-Object Net.Mail.SmtpClient($config.SmtpServer)
    $smtp.Send($message)

    Log-Message "Password sent securely to $smtpTo."
}

# Create new user in Azure AD and assign Microsoft 365 licenses
function Create-AzureADUser {
    param (
        [PSCustomObject]$entry
    )

    $authHeader = Connect-Graph

    # Generate a secure password for the user
    $userPassword = Generate-SecurePassword

    $userBody = @{
        accountEnabled = $true
        displayName    = "$($entry.FirstName) $($entry.LastName)"
        mailNickname   = $entry.Username
        userPrincipalName = "$($entry.Username)@yourdomain.com"
        passwordProfile = @{
            forceChangePasswordNextSignIn = $true
            password = $userPassword
        }
        givenName = $entry.FirstName
        surname   = $entry.LastName
        department = $entry.Department
        jobTitle   = $entry.Title
        officeLocation = "HQ"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Headers $authHeader -Method Post -Body $userBody -ContentType "application/json"

    if ($response) {
        Log-Message "User $($entry.Username) created successfully in Azure AD."

        # Assign licenses
        Assign-License -userId $response.id -authHeader $authHeader

        # Assign to groups
        Assign-UserToGroup -userId $response.id -authHeader $authHeader

        # Enroll in Intune and Assign Policies
        Enroll-DeviceIntune -userId $response.id -authHeader $authHeader

        # Assign Autopilot Profile
        Assign-AutopilotProfile -deviceId $response.id -authHeader $authHeader

        # Send the password securely to the admin or the user's alternate email
        Send-PasswordEmail -userEmail $entry.AlternateEmail -password $userPassword

    } else {
        Log-Message "Failed to create user $($entry.Username)" "ERROR"
    }
}

# Assign Multiple Microsoft 365 and Other Licenses
function Assign-License {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $licensesToAssign = @(
        "your-365-sku-id",  # Microsoft 365 License
        "your-ad-premium-sku-id",  # Azure AD Premium
        "your-ems-sku-id",  # Enterprise Mobility + Security
        "your-defender-sku-id"  # Microsoft Defender
    )

    $licenseBody = @{
        addLicenses = @()
        removeLicenses = @()
    }

    foreach ($skuId in $licensesToAssign) {
        $licenseBody.addLicenses += @{
            skuId = $skuId
        }
    }

    $licenseBodyJson = $licenseBody | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$userId/assignLicense" -Headers $authHeader -Method Post -Body $licenseBodyJson -ContentType "application/json"

    if ($response) {
        Log-Message "Licenses assigned to user $userId."
    } else {
        Log-Message "Failed to assign licenses to user $userId" "ERROR"
    }
}

# Assign User to Groups
function Assign-UserToGroup {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $groupIds = @("group-id-1", "group-id-2")

    foreach ($groupId in $groupIds) {
        $groupBody = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$groupId"
        } | ConvertTo-Json

        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members/$userId/$ref" -Headers $authHeader -Method Post -Body $groupBody -ContentType "application/json"

        Log-Message "User $userId added to group $groupId."
    }
}

# Enroll Device in Intune and Assign Policies
function Enroll-DeviceIntune {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    # Example device enrollment (this would be more detailed in a real implementation)
    $deviceBody = @{
        userPrincipalName = "$userId@yourdomain.com"
        deviceType = "Windows"
        groupTag = "IntuneEnrollment"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$userId" -Headers $authHeader -Method Post -Body $deviceBody -ContentType "application/json"

    if ($response) {
        Log-Message "Device enrolled for user $userId in Intune."

        # Assign Compliance Policy
        Assign-CompliancePolicy -userId $userId -authHeader $authHeader

        # Assign Configuration Profile
        Assign-ConfigProfile -userId $userId -authHeader $authHeader

        # Assign Defender Policies
        Assign-DefenderPolicies -userId $userId -authHeader $authHeader

    } else {
        Log-Message "Failed to enroll device for user $userId in Intune" "ERROR"
    }
}

# Assign Compliance Policy in Intune
function Assign-CompliancePolicy {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $policyId = "compliance-policy-id"  # Replace with your actual policy ID
    $policyBody = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$policyId"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$userId/deviceCompliancePolicyStates" -Headers $authHeader -Method Post -Body $policyBody -ContentType "application/json"

    if ($response) {
        Log-Message "Compliance policy assigned to user $userId."
    } else {
        Log-Message "Failed to assign compliance policy to user $userId" "ERROR"
    }
}

# Assign Configuration Profile in Intune
function Assign-ConfigProfile {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $profileId = "config-profile-id"  # Replace with your actual profile ID
    $profileBody = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurationProfiles/$profileId"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$userId/deviceConfigurationStates" -Headers $authHeader -Method Post -Body $profileBody -ContentType "application/json"

    if ($response) {
        Log-Message "Configuration profile assigned to user $userId."
    } else {
        Log-Message "Failed to assign configuration profile to user $userId" "ERROR"
    }
}

# Assign Microsoft Defender Policies
function Assign-DefenderPolicies {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $defenderPolicyId = "defender-policy-id"  # Replace with your actual Defender policy ID
    $defenderPolicyBody = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$defenderPolicyId"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$userId/deviceCompliancePolicyStates" -Headers $authHeader -Method Post -Body $defenderPolicyBody -ContentType "application/json"

    if ($response) {
        Log-Message "Microsoft Defender policy assigned to user $userId."
    } else {
        Log-Message "Failed to assign Microsoft Defender policy to user $userId" "ERROR"
    }
}

# Assign Autopilot Profile to Device
function Assign-AutopilotProfile {
    param (
        [string]$deviceId,
        [hashtable]$authHeader
    )

    $profileId = "autopilot-profile-id"  # Replace with your actual profile ID
    $assignmentBody = @{
        "groupTag"  = "Standard Users"
        "assignedProfile" = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeploymentProfiles/$profileId"
        }
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$deviceId/assignProfile" -Headers $authHeader -Method Post -Body $assignmentBody -ContentType "application/json"

    if ($response) {
        Log-Message "Autopilot profile $profileId assigned to device $deviceId."
    } else {
        Log-Message "Failed to assign Autopilot profile $profileId to device $deviceId" "ERROR"
    }
}

# Process File (CSV or XML)
function Process-File {
    param (
        [string]$filePath
    )

    try {
        $entries = if ($filePath -match "\.xml$") {
            Parse-XML -xmlPath $filePath
        } elseif ($filePath -match "\.csv$") {
            Parse-CSV -csvPath $filePath
        } else {
            Log-Message "Unsupported file format: $filePath" "ERROR"
            throw "Unsupported file format: $filePath"
        }

        foreach ($entry in $entries) {
            Create-AzureADUser -entry $entry
        }
    } catch {
        Log-Message "Error processing file {$filePath}: $_" "ERROR"
    }
}

# Monitor for Files
function Monitor-ShareDrive {
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $config.SavePath
    $watcher.Filter = "*.*"
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true

    $onCreated = Register-ObjectEvent $watcher Created -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Log-Message "New file detected: $filePath"
        Process-File -filePath $filePath
    }

    while ($true) {
        Start-Sleep -Seconds 10
    }

    Unregister-Event -SourceIdentifier $onCreated.Id
}

# Start Process based on InputMethod
switch ($InputMethod) {
    "Graph" {
        Monitor-ShareDrive
    }
}
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("Graph")]
    [string]$InputMethod = "Graph"
)

# Import required modules
Import-Module Az.Accounts
Import-Module Microsoft.Graph
Import-Module Microsoft.Graph.Intune

# Configuration settings
$config = @{
    SavePath        = "Y:\\ADImports\\"
    UsersPath       = "Y:\\ADImports\\Users\\"
    LogsPath        = "Y:\\ADImports\\Logs\\"
    ArchivePath     = "Y:\\ADImports\\Archive\\"
    ProcessedPath   = "Y:\\ADImports\\Processed\\"
    Mailbox         = "importdata@companyname.com"
    LogPath         = "Y:\\ADImports\\Logs\\import.log"
    KeyVaultName    = "YourKeyVaultName"
    SecretName      = "ADImportPassword"
    TenantId        = "YourTenantId"
    ClientId        = "YourClientId"
    ClientSecret    = (Get-AzKeyVaultSecret -VaultName $config.KeyVaultName -Name $config.SecretName).SecretValueText
    SmtpServer      = "smtp.yourdomain.com"
    AdminEmail      = "admin@yourdomain.com"  # Where to send the passwords for secure communication
}

# Ensure directories exist
$paths = @($config.SavePath, $config.UsersPath, $config.LogsPath, $config.ArchivePath, $config.ProcessedPath)
foreach ($path in $paths) {
    if (-not (Test-Path -Path $path)) {
        New-Item -ItemType Directory -Path $path
    }
}

# Logging 
function Log-Message {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$type] $message"
    Add-Content -Path $config.LogPath -Value $logMessage
}

# Authenticate with Microsoft Graph
function Connect-Graph {
    $scope = "https://graph.microsoft.com/.default"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $config.ClientId
        client_secret = $config.ClientSecret
        scope         = $scope
    }
    $authResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$($config.TenantId)/oauth2/v2.0/token" -Method Post -Body $body
    $authHeader = @{
        Authorization = "Bearer $($authResponse.access_token)"
    }
    return $authHeader
}

# Generate a secure password
function Generate-SecurePassword {
    Add-Type -AssemblyName "System.Web"
    $password = [System.Web.Security.Membership]::GeneratePassword(16, 4)
    return $password
}

# Send password via email
function Send-PasswordEmail {
    param (
        [string]$userEmail,
        [string]$password
    )

    $smtpFrom = $config.AdminEmail
    $smtpTo = $userEmail
    $subject = "Your New Account Password"
    $body = "Hello,`n`nYour new account has been created. Here is your initial password:`n`nPassword: $password`n`nPlease change this password as soon as possible after logging in."

    $message = New-Object System.Net.Mail.MailMessage $smtpFrom, $smtpTo, $subject, $body
    $smtp = New-Object Net.Mail.SmtpClient($config.SmtpServer)
    $smtp.Send($message)

    Log-Message "Password sent securely to $smtpTo."
}

# Create new user in Azure AD and assign Microsoft 365 licenses
function Create-AzureADUser {
    param (
        [PSCustomObject]$entry
    )

    $authHeader = Connect-Graph

    # Generate a secure password for the user
    $userPassword = Generate-SecurePassword

    $userBody = @{
        accountEnabled = $true
        displayName    = "$($entry.FirstName) $($entry.LastName)"
        mailNickname   = $entry.Username
        userPrincipalName = "$($entry.Username)@yourdomain.com"
        passwordProfile = @{
            forceChangePasswordNextSignIn = $true
            password = $userPassword
        }
        givenName = $entry.FirstName
        surname   = $entry.LastName
        department = $entry.Department
        jobTitle   = $entry.Title
        officeLocation = "HQ"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Headers $authHeader -Method Post -Body $userBody -ContentType "application/json"

    if ($response) {
        Log-Message "User $($entry.Username) created successfully in Azure AD."

        # Assign licenses
        Assign-License -userId $response.id -authHeader $authHeader

        # Assign to groups
        Assign-UserToGroup -userId $response.id -authHeader $authHeader

        # Enroll in Intune and Assign Policies
        Enroll-DeviceIntune -userId $response.id -authHeader $authHeader

        # Assign Autopilot Profile
        Assign-AutopilotProfile -deviceId $response.id -authHeader $authHeader

        # Send the password securely to the admin or the user's alternate email
        Send-PasswordEmail -userEmail $entry.AlternateEmail -password $userPassword

    } else {
        Log-Message "Failed to create user $($entry.Username)" "ERROR"
    }
}

# Assign Multiple Microsoft 365 and Other Licenses
function Assign-License {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $licensesToAssign = @(
        "your-365-sku-id",  # Microsoft 365 License
        "your-ad-premium-sku-id",  # Azure AD Premium
        "your-ems-sku-id",  # Enterprise Mobility + Security
        "your-defender-sku-id"  # Microsoft Defender
    )

    $licenseBody = @{
        addLicenses = @()
        removeLicenses = @()
    }

    foreach ($skuId in $licensesToAssign) {
        $licenseBody.addLicenses += @{
            skuId = $skuId
        }
    }

    $licenseBodyJson = $licenseBody | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$userId/assignLicense" -Headers $authHeader -Method Post -Body $licenseBodyJson -ContentType "application/json"

    if ($response) {
        Log-Message "Licenses assigned to user $userId."
    } else {
        Log-Message "Failed to assign licenses to user $userId" "ERROR"
    }
}

# Assign User to Groups
function Assign-UserToGroup {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $groupIds = @("group-id-1", "group-id-2")

    foreach ($groupId in $groupIds) {
        $groupBody = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$groupId"
        } | ConvertTo-Json

        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members/$userId/$ref" -Headers $authHeader -Method Post -Body $groupBody -ContentType "application/json"

        Log-Message "User $userId added to group $groupId."
    }
}

# Enroll Device in Intune and Assign Policies
function Enroll-DeviceIntune {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    # Example device enrollment (this would be more detailed in a real implementation)
    $deviceBody = @{
        userPrincipalName = "$userId@yourdomain.com"
        deviceType = "Windows"
        groupTag = "IntuneEnrollment"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$userId" -Headers $authHeader -Method Post -Body $deviceBody -ContentType "application/json"

    if ($response) {
        Log-Message "Device enrolled for user $userId in Intune."

        # Assign Compliance Policy
        Assign-CompliancePolicy -userId $userId -authHeader $authHeader

        # Assign Configuration Profile
        Assign-ConfigProfile -userId $userId -authHeader $authHeader

        # Assign Defender Policies
        Assign-DefenderPolicies -userId $userId -authHeader $authHeader

    } else {
        Log-Message "Failed to enroll device for user $userId in Intune" "ERROR"
    }
}

# Assign Compliance Policy in Intune
function Assign-CompliancePolicy {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $policyId = "compliance-policy-id"  # Replace with your actual policy ID
    $policyBody = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$policyId"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$userId/deviceCompliancePolicyStates" -Headers $authHeader -Method Post -Body $policyBody -ContentType "application/json"

    if ($response) {
        Log-Message "Compliance policy assigned to user $userId."
    } else {
        Log-Message "Failed to assign compliance policy to user $userId" "ERROR"
    }
}

# Assign Configuration Profile in Intune
function Assign-ConfigProfile {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $profileId = "config-profile-id"  # Replace with your actual profile ID
    $profileBody = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurationProfiles/$profileId"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$userId/deviceConfigurationStates" -Headers $authHeader -Method Post -Body $profileBody -ContentType "application/json"

    if ($response) {
        Log-Message "Configuration profile assigned to user $userId."
    } else {
        Log-Message "Failed to assign configuration profile to user $userId" "ERROR"
    }
}

# Assign Microsoft Defender Policies
function Assign-DefenderPolicies {
    param (
        [string]$userId,
        [hashtable]$authHeader
    )

    $defenderPolicyId = "defender-policy-id"  # Replace with your actual Defender policy ID
    $defenderPolicyBody = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$defenderPolicyId"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$userId/deviceCompliancePolicyStates" -Headers $authHeader -Method Post -Body $defenderPolicyBody -ContentType "application/json"

    if ($response) {
        Log-Message "Microsoft Defender policy assigned to user $userId."
    } else {
        Log-Message "Failed to assign Microsoft Defender policy to user $userId" "ERROR"
    }
}

# Assign Autopilot Profile to Device
function Assign-AutopilotProfile {
    param (
        [string]$deviceId,
        [hashtable]$authHeader
    )

    $profileId = "autopilot-profile-id"  # Replace with your actual profile ID
    $assignmentBody = @{
        "groupTag"  = "Standard Users"
        "assignedProfile" = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeploymentProfiles/$profileId"
        }
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$deviceId/assignProfile" -Headers $authHeader -Method Post -Body $assignmentBody -ContentType "application/json"

    if ($response) {
        Log-Message "Autopilot profile $profileId assigned to device $deviceId."
    } else {
        Log-Message "Failed to assign Autopilot profile $profileId to device $deviceId" "ERROR"
    }
}

# Process File (CSV or XML)
function Process-File {
    param (
        [string]$filePath
    )

    try {
        $entries = if ($filePath -match "\.xml$") {
            Parse-XML -xmlPath $filePath
        } elseif ($filePath -match "\.csv$") {
            Parse-CSV -csvPath $filePath
        } else {
            Log-Message "Unsupported file format: $filePath" "ERROR"
            throw "Unsupported file format: $filePath"
        }

        foreach ($entry in $entries) {
            Create-AzureADUser -entry $entry
        }
    } catch {
        Log-Message "Error processing file {$filePath}: $_" "ERROR"
    }
}

# Monitor for Files
function Monitor-ShareDrive {
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $config.SavePath
    $watcher.Filter = "*.*"
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true

    $onCreated = Register-ObjectEvent $watcher Created -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Log-Message "New file detected: $filePath"
        Process-File -filePath $filePath
    }

    while ($true) {
        Start-Sleep -Seconds 10
    }

    Unregister-Event -SourceIdentifier $onCreated.Id
}

# Start Process based on InputMethod
switch ($InputMethod) {
    "Graph" {
        Monitor-ShareDrive
    }
}
