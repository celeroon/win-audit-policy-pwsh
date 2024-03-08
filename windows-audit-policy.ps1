function Get-ValidInput {
    param (
        [string]$prompt
    )

    while ($true) {
        $response = (Read-Host $prompt).ToLower()

        if ($response -eq 'yes' -or $response -eq 'no' -or $response -eq 'x') {
            return $response
        } else {
            Write-Host "Invalid input. Please enter 'yes', 'no', or 'x' to exit."
        }
    }
}

# Ask the user if NPS role is installed
Write-Host "Configuring Network Policy Server audit policy:"
$npsInstalled = Get-ValidInput "Is NPS role installed? (yes/no/x)"

if ($npsInstalled -eq 'x') {
    Write-Host "Exiting the script."
    exit
}

# Ask the user if ADCS is installed
Write-Host "Configuring Certification Services audit policy:"
$adcsInstalled = Get-ValidInput "Is ADCS installed? (yes/no/x)"

if ($adcsInstalled -eq 'x') {
    Write-Host "Exiting the script."
    exit
}

# Ask the user if AzMan is installed
Write-Host "Configuring Application Generated and Application Group Management audit policies:"
$azManInstalled = Get-ValidInput "Is AzMan installed? (yes/no/x)"

if ($azManInstalled -eq 'x') {
    Write-Host "Exiting the script."
    exit
}

# Define custom audit policy settings
$auditPolicies = @(
    @{ Subcategory="Security System Extension"; Success="enable"; Failure=$null },
    @{ Subcategory="System Integrity"; Success="enable"; Failure=$null },
    @{ Subcategory="IPsec Driver"; Success="enable"; Failure="enable" },
    @{ Subcategory="Other System Events"; Success="enable"; Failure="enable" },
    @{ Subcategory="Security State Change"; Success="enable"; Failure=$null },
    @{ Subcategory="Logon"; Success="enable"; Failure="enable" },
    @{ Subcategory="Logoff"; Success="enable"; Failure=$null },
    @{ Subcategory="Account Lockout"; Success=$null; Failure="enable" },
    @{ Subcategory="IPsec Main Mode"; Success="disable"; Failure="disable" },
    @{ Subcategory="IPsec Quick Mode"; Success="disable"; Failure="disable" },
    @{ Subcategory="IPsec Extended Mode"; Success="disable"; Failure="disable" },
    @{ Subcategory="Special Logon"; Success="enable"; Failure=$null },
    @{ Subcategory="Other Logon/Logoff Events"; Success="enable"; Failure="enable" },
    @{ Subcategory="User / Device Claims"; Success="enable"; Failure=$null },
    @{ Subcategory="Group Membership"; Success="enable"; Failure=$null },
    @{ Subcategory="File System"; Success="enable"; Failure="enable" },
    @{ Subcategory="Registry"; Success="enable"; Failure="enable" },
    @{ Subcategory="Kernel Object"; Success="disable"; Failure="disable" },
    @{ Subcategory="SAM"; Success="enable"; Failure="enable" },
    @{ Subcategory="Handle Manipulation"; Success="enable"; Failure="enable" },
    @{ Subcategory="File Share"; Success="enable"; Failure="enable" },
    @{ Subcategory="Filtering Platform Packet Drop"; Success="disable"; Failure="disable" },
    @{ Subcategory="Filtering Platform Connection"; Success="disable"; Failure="enable" },
    @{ Subcategory="Other Object Access Events"; Success="enable"; Failure="enable" },
    @{ Subcategory="Detailed File Share"; Success="enable"; Failure="enable" },
    @{ Subcategory="Removable Storage"; Success="enable"; Failure="enable" },
    @{ Subcategory="Central Policy Staging"; Success="enable"; Failure=$null },
    @{ Subcategory="Non Sensitive Privilege Use"; Success="enable"; Failure="enable" },
    @{ Subcategory="Other Privilege Use Events"; Success="disable"; Failure="disable" },
    @{ Subcategory="Sensitive Privilege Use"; Success="enable"; Failure="enable" },
    @{ Subcategory="Process Creation"; Success="enable"; Failure=$null },
    @{ Subcategory="Process Termination"; Success="enable"; Failure=$null },
    @{ Subcategory="DPAPI Activity"; Success="enable"; Failure="enable" },
    @{ Subcategory="RPC Events"; Success="disable"; Failure="disable" },
    @{ Subcategory="Plug and Play Events"; Success="enable"; Failure=$null },
    @{ Subcategory="Token Right Adjusted Events"; Success="enable"; Failure=$null },
    @{ Subcategory="Audit Policy Change"; Success="enable"; Failure=$null },
    @{ Subcategory="Authentication Policy Change"; Success="enable"; Failure=$null },
    @{ Subcategory="Authorization Policy Change"; Success="enable"; Failure=$null },
    @{ Subcategory="MPSSVC Rule-Level Policy Change"; Success="enable"; Failure="enable" },
    @{ Subcategory="Filtering Platform Policy Change"; Success="disable"; Failure="disable" },
    @{ Subcategory="Other Policy Change Events"; Success="enable"; Failure="enable" },
    @{ Subcategory="Computer Account Management"; Success="enable"; Failure=$null },
    @{ Subcategory="Security Group Management"; Success="enable"; Failure=$null },
    @{ Subcategory="Distribution Group Management"; Success="enable"; Failure=$null },
    @{ Subcategory="Other Account Management Events"; Success="enable"; Failure=$null },
    @{ Subcategory="User Account Management"; Success="enable"; Failure="enable" },
    @{ Subcategory="Directory Service Access"; Success="enable"; Failure="enable" },
    @{ Subcategory="Directory Service Changes"; Success="enable"; Failure=$null },
    @{ Subcategory="Directory Service Replication"; Success="disable"; Failure="disable" },
    @{ Subcategory="Detailed Directory Service Replication"; Success="disable"; Failure="disable" },
    @{ Subcategory="Kerberos Service Ticket Operations"; Success="enable"; Failure="enable" },
    @{ Subcategory="Other Account Logon Events"; Success="disable"; Failure="disable" },
    @{ Subcategory="Kerberos Authentication Service"; Success="enable"; Failure="enable" },
    @{ Subcategory="Credential Validation"; Success=$null; Failure="enable" },

    # Define NPS audit policy
    @{
        Subcategory = "Network Policy Server"
        Success     = if ($npsInstalled -eq 'yes') { "enable" } else { "disable" }
        Failure     = if ($npsInstalled -eq 'yes') { "enable" } else { "disable" }
    },

    # Define ADCS audit policy
    @{
        Subcategory = "Certification Services"
        Success     = if ($adcsInstalled -eq 'yes') { "enable" } else { "disable" }
        Failure     = if ($adcsInstalled -eq 'yes') { "enable" } else { "disable" }
    },

    # Define AzMan audit policies
    @{
        Subcategory = "Application Generated"
        Success     = if ($azManInstalled -eq 'yes') { "enable" } else { "disable" }
        Failure     = "disable"
    },
    @{
        Subcategory = "Application Group Management"
        Success     = if ($azManInstalled -eq 'yes') { "enable" } else { "disable" }
        Failure     = "disable"
    }
)

# Apply each audit policy setting
foreach ($policy in $auditPolicies) {
    Write-Host "Configuring audit policy for subcategory: $($policy.Subcategory)"
    $cmd = "AuditPol /set /subcategory:`"$($policy.Subcategory)`""
    if ($policy.Success) { $cmd += " /success:$($policy.Success)" }
    if ($policy.Failure) { $cmd += " /failure:$($policy.Failure)" }

    # Execute the command
    Invoke-Expression $cmd
}

Write-Host "Audit policy settings have been applied"
