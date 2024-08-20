[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("ShareDrive", "EWS", "Graph")]
    [string]$InputMethod = "ShareDrive"
)

# Import required modules
Import-Module ActiveDirectory
Import-Module Az.KeyVault
Import-Module Microsoft.Graph

# Configuration settings
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

# Ensure directories exist
$paths = @($config.SavePath, $config.UsersPath, $config.ComputersPath, $config.LogsPath, $config.ArchivePath, $config.ProcessedPath)
foreach ($path in $paths) {
    if (-not (Test-Path -Path $path)) {
        New-Item -ItemType Directory -Path $path
    }
}


# Retrieve AD password from vault
$adPassword = (Get-AzKeyVaultSecret -VaultName $config.KeyVaultName -Name $config.SecretName).SecretValueText

# Ensure directories exist
$paths = @($config.SavePath, $config.UsersPath, $config.ComputersPath, $config.LogsPath, $config.ArchivePath)
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

# Notifications
function Send-Notification {
    param (
        [string]$subject,
        [string]$body
    )

    $smtpFrom = "noreply@companyname.com"
    $smtpTo = $config.NotificationEmail

    $message = New-Object System.Net.Mail.MailMessage $smtpFrom, $smtpTo, $subject, $body
    $smtp = New-Object Net.Mail.SmtpClient($config.SMTPServer)
    $smtp.Send($message)
}

# Monitor Share Drive Y: for XML or CSV Files
function Monitor-ShareDrive {
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $config.SavePath
    $watcher.Filter = "*.*"
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true

    # Event Handlers 
    $onCreated = Register-ObjectEvent $watcher Created -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Log-Message "New file detected: $filePath"
        try {
            Process-File -filePath $filePath
            # Move the file to the processed directory for organization
            $fileName = [System.IO.Path]::GetFileName($filePath)
            $processedFilePath = Join-Path -Path $config.ProcessedPath -ChildPath $fileName
            Move-Item -Path $filePath -Destination $processedFilePath
            Log-Message "File processed and moved to: $processedFilePath"
        } catch {
            Log-Message "Error processing file: $filePath - $_" "ERROR"
        }
    }

    # Keep the script running
    while ($true) {
        Start-Sleep -Seconds 10
    }

    # Cleanup event handlers
    Unregister-Event -SourceIdentifier $onCreated.Id
}



# EWS Fetching
function Get-EWSMails {
    Add-Type -Path $config.EWSPath

    $service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService
    $service.Credentials = $config.Credentials
    $service.AutodiscoverUrl($config.Mailbox, { $true })

    $inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($service, [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox)
    $view = New-Object Microsoft.Exchange.WebServices.Data.ItemView(10)
    $findResults = $inbox.FindItems($view)

    foreach ($item in $findResults.Items) {
        if ($item.Subject -ceq "imporT pleasE Custom Passphrase Here" -and $item.Attachments.Count -gt 0) {
            foreach ($attachment in $item.Attachments) {
                if ($attachment -is [Microsoft.Exchange.WebServices.Data.FileAttachment]) {
                    $filePath = Join-Path -Path $config.SavePath -ChildPath $attachment.Name
                    $attachment.Load($filePath)
                    Log-Message "Saved attachment: $($attachment.Name)"
                    Process-File -filePath $filePath
                }
            }
        }
    }
}

# Graph Fetching
function Get-GraphMails {
    Connect-MgGraph -Scopes "Mail.ReadWrite"

    # Fetch mails that exactly match the subject and have an attachment. 
    $mails = Get-MgUserMessage -UserId $config.Mailbox -Filter "subject eq 'imporT pleasE Custom Passphrase Here'" -Select "subject,attachments"

    foreach ($mail in $mails) {
        # Perform case-sensitive check
        if ($mail.Subject -ceq "imporT pleasE Custom Passphrase Here") {
            foreach ($attachment in $mail.Attachments) {
                if ($attachment.ODataType -eq "#microsoft.graph.fileAttachment") {
                    $fileContent = [System.Convert]::FromBase64String($attachment.ContentBytes)
                    $fileName = Join-Path -Path $config.SavePath -ChildPath $attachment.Name
                    [System.IO.File]::WriteAllBytes($fileName, $fileContent)
                    Log-Message "Saved attachment: $($attachment.Name)"
                    Process-File -filePath $fileName
                }
            }
        }
    }

    Disconnect-MgGraph
}

# Parse XML securely
function Parse-XML {
    param (
        [string]$xmlPath
    )

    try {
        # Configure XML Reader Settings for security against XXE, XML bomb attacks, and to sanitize fields.
        $xmlSettings = New-Object System.Xml.XmlReaderSettings
        $xmlSettings.DtdProcessing = "Prohibit"
        $xmlSettings.XmlResolver = $null

        # Load XML securely
        $xmlReader = [System.Xml.XmlReader]::Create($xmlPath, $xmlSettings)
        [xml]$xmlData = New-Object XML
        $xmlData.Load($xmlReader)

        $entries = @()

        foreach ($entry in $xmlData.Entries.Entry) {
            $entries += [PSCustomObject]@{
                Type        = $entry.Type.ToLower()
                FirstName   = [System.Web.HttpUtility]::HtmlEncode($entry.FirstName)
                LastName    = [System.Web.HttpUtility]::HtmlEncode($entry.LastName)
                Username    = [System.Web.HttpUtility]::HtmlEncode($entry.Username)
                Email       = [System.Web.HttpUtility]::HtmlEncode($entry.Email)
                Department  = [System.Web.HttpUtility]::HtmlEncode($entry.Department)
                Title       = [System.Web.HttpUtility]::HtmlEncode($entry.Title)
                PhoneNumber = [System.Web.HttpUtility]::HtmlEncode($entry.PhoneNumber)
                ComputerName = [System.Web.HttpUtility]::HtmlEncode($entry.ComputerName)
                Description = [System.Web.HttpUtility]::HtmlEncode($entry.Description)
            }
        }

        return $entries
    } catch {
        Log-Message "Error parsing XML: $_" "ERROR"
        throw $_
    }
}

# Parse CSV securely
function Parse-CSV {
    param (
        [string]$csvPath
    )

    try {
        $csvData = Import-Csv -Path $csvPath

        # Check for missing or extra headers
        $requiredHeaders = @('Type', 'FirstName', 'LastName', 'Username', 'Email', 'Department', 'Title', 'PhoneNumber', 'ComputerName', 'Description')
        $csvHeaders = $csvData[0].PSObject.Properties.Name
        $missingHeaders = $requiredHeaders | Where-Object { $_ -notin $csvHeaders }
        $extraHeaders = $csvHeaders | Where-Object { $_ -notin $requiredHeaders }

        if ($missingHeaders.Count -gt 0) {
            $errorMessage = "CSV is missing required headers: " + ($missingHeaders -join ", ")
            Log-Message $errorMessage "ERROR"
            throw $errorMessage
        }

        if ($extraHeaders.Count -gt 0) {
            $warningMessage = "CSV contains extra headers: " + ($extraHeaders -join ", ")
            Log-Message $warningMessage "WARNING"
        }

        $entries = @()

        foreach ($entry in $csvData) {
            # Sanitize and guard against injection attacks
            $sanitizedEntry = [PSCustomObject]@{
                Type        = $entry.Type.ToLower()
                FirstName   = $entry.FirstName -replace '^(=|\+|\-|\@)', "'$1"
                LastName    = $entry.LastName -replace '^(=|\+|\-|\@)', "'$1"
                Username    = $entry.Username -replace '^(=|\+|\-|\@)', "'$1"
                Email       = $entry.Email -replace '^(=|\+|\-|\@)', "'$1"
                Department  = $entry.Department -replace '^(=|\+|\-|\@)', "'$1"
                Title       = $entry.Title -replace '^(=|\+|\-|\@)', "'$1"
                PhoneNumber = $entry.PhoneNumber -replace '^(=|\+|\-|\@)', "'$1"
                ComputerName = $entry.ComputerName -replace '^(=|\+|\-|\@)', "'$1"
                Description = $entry.Description -replace '^(=|\+|\-|\@)', "'$1"
            }
            $entries += $sanitizedEntry
        }

        return $entries
    } catch {
        Log-Message "Error parsing CSV: $_" "ERROR"
        throw $_
    }
}

# Sanitize and Validate Inputs
function Sanitize-Input {
    param (
        [PSCustomObject]$entry
    )

    try {
        $errors = @()

        if (-not $entry.FirstName) { $errors += "FirstName is missing" }
        if (-not $entry.LastName) { $errors += "LastName is missing" }
        if (-not $entry.Username) { $errors += "Username is missing" }
        if (-not $entry.Email) { $errors += "Email is missing" }
        if (-not ([regex]::IsMatch($entry.Email, '^[^\@\s]+@[^\@\s]+\.[^\@\s]+$'))) { $errors += "Invalid Email format" }

        if ($entry.Type -eq 'user') {
            if (-not $entry.Department) { $errors += "Department is missing" }
            if (-not $entry.Title) { $errors += "Title is missing" }
            if (-not $entry.PhoneNumber) { $errors += "PhoneNumber is missing" }
        } elseif ($entry.Type -eq 'computer') {
            if (-not $entry.ComputerName) { $errors += "ComputerName is missing" }
        } else {
            $errors += "Type must be either 'user' or 'computer'"
        }

        if ($errors.Count -gt 0) {
            $errorMessage = "Errors in entry: " + ($errors -join "; ")
            Log-Message $errorMessage "ERROR"
            throw $errorMessage
        }

        $entry.FirstName   = $entry.FirstName.ToLower()
        $entry.LastName    = $entry.LastName.ToLower()
        $entry.Username    = $entry.Username.ToLower()
        $entry.Email       = $entry.Email.ToLower()
        $entry.Department  = $entry.Department.ToLower()
        $entry.Title       = $entry.Title.ToLower()
        $entry.PhoneNumber = $entry.PhoneNumber.ToLower()
        $entry.ComputerName = $entry.ComputerName.ToLower()
        $entry.Description = $entry.Description.ToLower()

        return $entry
    } catch {
        Log-Message "Error sanitizing input: $_" "ERROR"
        throw $_
    }
}

# Process into Active Directory
function Process-ADEntry {
    param (
        [PSCustomObject]$entry
    )

    try {
        $securePassword = ConvertTo-SecureString $adPassword -AsPlainText -Force

        if ($entry.Type -eq 'user') {
            New-ADUser `
                -Name "$($entry.FirstName) $($entry.LastName)" `
                -GivenName $entry.FirstName `
                -Surname $entry.LastName `
                -SamAccountName $entry.Username `
                -UserPrincipalName "$($entry.Username)@yourdomain.com" `
                -Path "OU=Users,DC=yourdomain,DC=com" `
                -AccountPassword $securePassword `
                -Enabled $true `
                -EmailAddress $entry.Email `
                -Title $entry.Title `
                -Department $entry.Department `
                -OfficePhone $entry.PhoneNumber `
                -Description $entry.Description

            Add-ADGroupMember -Identity "Staff" -Members $entry.Username

            Log-Message "User $($entry.Username) created successfully."
        } elseif ($entry.Type -eq 'computer') {
            New-ADComputer `
                -Name $entry.ComputerName `
                -Path "OU=Computers,DC=yourdomain,DC=com" `
                -Description $entry.Description

            Log-Message "Computer $($entry.ComputerName) created successfully."
        }
    } catch {
        Log-Message "Failed to create $($entry.Type) $($entry.Username): $_" "ERROR"
        Send-Notification -subject "AD Import Error" -body "Failed to create $($entry.Type) $($entry.Username): $_"
    }
}

# Process File
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
            $sanitizedEntry = Sanitize-Input -entry $entry
            Process-ADEntry -entry $sanitizedEntry
        }
    } catch {
        Log-Message "Error processing file $filePath: $_" "ERROR"
        Send-Notification -subject "AD Import Error" -body "Error processing file $filePath: $_"
    }
}

# Determine the input method
switch ($InputMethod) {
    "ShareDrive" {
        Monitor-ShareDrive
    }
    "EWS" {
        Get-EWSMails
    }
    "Graph" {
        Get-GraphMails
    }
}
