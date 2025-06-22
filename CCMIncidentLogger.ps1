############
# Parameters for use
############
$CCMUsername = "" # Your CCM username
$CCMPassword = "" # Your CCM password
$CCMServer = "localhost:8443" # Your CCM Server - Server:port can be used, e.g. localhost:8443
# $HeaderAuthKey = @{"authorization"="Basic YOURBASICENCODEDCREDS"} # Or set a header auth key directly:
$ITMSIntegrationProduct = "JIRA" # Your integration tool
$ScriptPath = "C:\Program Files\Tripwire\Configuration Compliance Manager\CCMIncidentLogger" # Path where this script resides
$Mode = "Run"
############
# Functions
############
function Set-IgnoreSSL{
     <#
    .SYNOPSIS
    Disables SSL validation for subsequent PowerShell queries and sets TLS 1.2
    .DESCRIPTION
    Disables SSL validation for subsequent PowerShell queries - this shouldn't be used unless you can add the certificate to a trust store
    .EXAMPLE
    Set-IgnoreSSL
    #>
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    $TLS12Protocol = [System.Net.SecurityProtocolType] 'Ssl3 , Tls12'
}
Set-IgnoreSSL
function ConvertTo-Base64($string) {
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes($string);
    $encoded = [System.Convert]::ToBase64String($bytes);
    return $encoded;
}
function Set-CCMScanHeaders{
    param($Username,$Password,$Server)
    $b64 = ConvertTo-Base64 "$($Username):$($Password)"
    $headers = @{};
    $headers.Add("Referer", "https://$CCMServer")
    $headers.Add("X-Requested-With","XMLHttpRequest")
    $headers.Add("Authorization","Basic $b64")
    Set-Variable -name "HeaderAuthKey" -Value $headers -Scope Global
}
function Get-CCMAssetByIP{
     <#
    .SYNOPSIS
    Gets a CCM asset by it's IP address
    .DESCRIPTION
    Gets a CCM asset by it's IP address
    .EXAMPLE
    Get-CCMAssetByIP -AssetIPAddress "192.168.1.10" -CCMUsername "admin" -CCMPassword "MyPassword" -CCMServer "localhost:8443"
    Returns a CCM Asset with the IP 192.168.1.10
    #>
    param([parameter(mandatory)]$AssetIPAddress,[parameter(mandatory)]$CCMUsername,[parameter(mandatory)]$CCMPassword,[parameter(mandatory)]$CCMServer)
    Set-CCMScanHeaders -Username $CCMUsername -Password $CCMPassword -Server $CCMServer
    try{
        Invoke-RestMethod -Method get -ContentType "application/json" -Uri "https://$ccmserver/api/v1/asset?search=AssetInformation.%22IP%20Address%22%20%3D%3D%20%22$AssetIPAddress%22" -Headers $headers
        }
    catch{
        Write-Error "Failed to find asset $AssetIPAddress"
    }
}
function Get-CCMAssetByID{
     <#
    .SYNOPSIS
    Gets a CCM asset by its CCM ID 
    .DESCRIPTION
    Gets a CCM asset by its CCM ID
    .EXAMPLE
    Get-CCMAssetByIP -AssetID "1" -CCMUsername "admin" -CCMPassword "MyPassword" -CCMServer "localhost:8443"
    Returns a CCM Asset with the ID of 1
    #>
    param([parameter(mandatory)]$AssetID,[parameter(mandatory)]$CCMUsername,[parameter(mandatory)]$CCMPassword,[parameter(mandatory)]$CCMServer)
    Set-CCMScanHeaders -Username $CCMUsername -Password $CCMPassword -Server $CCMServer
    try{
        Invoke-RestMethod -Method get -ContentType "application/json" -Uri "https://$ccmserver/api/v1/asset/$AssetID" -Headers $headers
        }
    catch{
        Write-Error "Failed to find asset $AssetID"
    }
}
function Add-CCMAssetLicense{
     <#
    .SYNOPSIS
    Adds a CCM asset license
    .DESCRIPTION
    Adds a CCM asset license
    .EXAMPLE
    Add-CCMAssetLicense -AssetID 10 -CCMUsername "admin" -CCMPassword "MyPassword" -CCMServer "localhost:8443"
    Returns a CCM Asset with the IP 192.168.1.10
    #>
    param($AssetID,$CCMUsername,$CCMPassword,$CCMServer)
    Set-CCMScanHeaders -Username $CCMUsername -Password $CCMPassword -Server $CCMServer
    $payload = @{licensed=$true} | ConvertTo-Json
    Write-host $payload
    try{
        Invoke-WebRequest -Method "PATCH" -ContentType "application/json" -Uri "https://$ccmserver/api/v1/asset/$AssetID" -Headers $headers -Body $payload
        }
    Catch
        {Write-Error "Failed to license asset"}
}
function Add-CCMNetworkProfilePingSweepScanTask{
    <#
  .SYNOPSIS
    Add a scan task to a CCM Network Profile
  .DESCRIPTION
    Add a scan task to a CCM Network Profile
  .EXAMPLE
     Add-CCMProfileScanTask -ProfileName "Test" -ScanTaskName "My Scan Task Name Test"
  .NOTES
    N/A
#>
    Param([Parameter(Mandatory=$true)]$ProfileName,[Parameter(Mandatory=$true)]$ScanTaskName)
    $Profile = Get-CCMNetworkProfileByName -ProfileName $ProfileName
    $ProfileID = $Profile.id
    $payload = @{"name"= "$ScanTaskName"; "enabled"=$true; "type"= "PingSweep"; "parent"= @{"href"= "/api/v1/assetgroup/1";}} | ConvertTo-Json
    Write-host $Payload
    try{
        $r = Invoke-RestMethod -UseBasicParsing -Uri "https://$CCMServer/api/v1/networkprofile/$profileid/scantasks" -Headers $HeaderAuthKey -Method Post -ContentType text/json -body $payload
        return $r
        }
    catch{
      $Error[0]
        Write-Error "Failed to add scan profile"
    }
}
function Get-CCMScanTaskByID{
    <#
  .SYNOPSIS
    Get Scan Task by CCM Scan Task by ID
  .DESCRIPTION
    Get Scan Task by CCM Scan Task by ID
  .EXAMPLE
     Get-CCMScanTaskByID -ID "169"
  .NOTES
    N/A
#>
    Param([Parameter(Mandatory=$true)]$ID)
    try{
        $r = Invoke-RestMethod -UseBasicParsing -Uri "https://$CCMServer/api/v1/scantask/$ID" -Headers $HeaderAuthKey -Method Get -ContentType text/json
        return $r
        }
    catch{
        Write-Error "Failed to get network"
    }
}
function Get-CCMScanTasks{
    <#
  .SYNOPSIS
    Get all Scan Tasks in CCM
  .DESCRIPTION
    Get all Scan Tasks in CCM
  .EXAMPLE
     Get-CCMScanTasks
  .NOTES
    N/A
#>
    try{
        $r = Invoke-RestMethod -UseBasicParsing -Uri "https://$CCMServer/api/v1/scantask" -Headers $HeaderAuthKey -Method Get -ContentType text/json
        return $r
        }
    catch{
        Write-Error "Failed to get scan tasks"
    }
}
function Get-CCMScanTaskConfigByID{
    <#
  .SYNOPSIS
    Get Scan Task by CCM Scan Task Configuration Options by ID
  .DESCRIPTION
    Get Scan Task by CCM Scan Task Configuration Options by ID
  .EXAMPLE
     Get-CCMScanTaskConfigByID -ID "169"
  .NOTES
    N/A
#>
    Param([Parameter(Mandatory=$true)]$ID)
    try{
        $r = Invoke-RestMethod -UseBasicParsing -Uri "https://$CCMServer/api/v1/scantask/$ID/configuration" -Headers $HeaderAuthKey -Method Get -ContentType text/json
        return $r
        }
    catch{
        Write-Error "Failed to get network"
    }
}
function Get-CCMScanTaskTECompliancePolicyConfigByID{
    <#
  .SYNOPSIS
    Get Scan Task by CCM Scan Task TE Configuration Policy Settings by ID
  .DESCRIPTION
    Get Scan Task by CCM Scan Task TE Configuration Policy Settings by ID
  .EXAMPLE
     Get-CCMScanTaskTECompliancePolicyConfigByID -ID "169"
  .NOTES
    N/A
#>
    Param([Parameter(Mandatory=$true)]$ID)
    try{
        $r = Invoke-RestMethod -UseBasicParsing -Uri "https://$CCMServer/api/v1/scantask/$ID/tepolicies" -Headers $HeaderAuthKey -Method Get -ContentType text/json
        return $r
        }
    catch{
        Write-Error "Failed to get network"
    }
}
function Get-CCMCompliancePolicies{
    <#
  .SYNOPSIS
    Get all Compliance Policies in CCM
  .DESCRIPTION
    Get all Compliance Policies in CCM
  .EXAMPLE
     Get-CCMCompliancePolicies
  .NOTES
    N/A
#>
    try{
        $r = Invoke-RestMethod -UseBasicParsing -Uri "https://$CCMServer/api/v1/scantask" -Headers $HeaderAuthKey -Method Get -ContentType text/json
        return $r
        }
    catch{
        Write-Error "Failed to get scan tasks"
    }
}
function Get-CCMChanges{
    <#
  .SYNOPSIS
    Get all Compliance Changes in CCM
  .DESCRIPTION
    Get all Compliance Changes in CCM
  .EXAMPLE
     Get-CCMChanges
  .NOTES
    N/A
#>
    try{
        $r = Invoke-RestMethod -UseBasicParsing -Uri "https://$CCMServer/api/v1/change" -Headers $HeaderAuthKey -Method Get -ContentType text/json
        return $r
        }
    catch{
        Write-Error "Failed to get changes"
    }
}
function Get-CCMChangesinLast24Hours{
    <#
  .SYNOPSIS
    Get all Compliance Changes in CCM in the alst 24 hours
  .DESCRIPTION
    Get all Compliance Changes in CCM
  .EXAMPLE
     Get-CCMChangesinLast24Hours
  .NOTES
    N/A
#>
    try{
        $EndTime = (Get-Date).AddHours(-24).ToString("yyyy-MM-ddTHH:mm:ss.ff")
        Write-Debug "Getting changes in last 24 hours, i.e after $EndTime)"
        $r = Invoke-RestMethod -UseBasicParsing -Uri "https://$CCMServer/api/v1/change&startTime=$EndTime" -Headers $HeaderAuthKey -Method Get -ContentType text/json
        return $r
        }
    catch{
        Write-Error "Failed to get changes"
    }
}
function CCMITSMINTEGRATIONWORKFLOW{
     <#
    .SYNOPSIS
    Sets up or runs the CCM ITSM INTEGRATION WORKFLOW 
    .DESCRIPTION
    Sets up or runs the CCM ITSM INTEGRATION WORKFLOW 
    .EXAMPLE
    CCMITSMINTEGRATIONWORKFLOW -mode "setup" -CCMUsername $CCMUsername -CCMPassword $CCMPassword -CCMServer $CCMServer -ITMSIntegrationProduct "JIRA"
    Sets a scheduled task to run this script
    .EXAMPLE
    CCMITSMINTEGRATIONWORKFLOW -Mode "Run" -CCMUsername $CCMUsername -CCMPassword $CCMPassword -CCMServer $CCMServer -ITMSIntegrationProduct "JIRA"
    Runs the integration
    .EXAMPLE
    CCMITSMINTEGRATIONWORKFLOW -Mode "Run" -ITMSIntegrationProduct "JIRA"
    Runs the integration - nb credentials must be set in the script which is obviously not desirable - consider using a key vault to manage credential usage
    #>
    param($Mode,$CCMUsername,$CCMPassword,$CCMServer,$ITMSIntegrationProduct)
if($Mode -eq "Setup")
    {
    # Create a scheduled task to excecute the workflow
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfweek ("Monday","Tuesday","Wednesday","Thursday","Friday") -At 10AM
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -WindowStyle Hidden -File "$ScriptPath"'
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $CCMScheduledTask = @{
        TaskName = 'Run CCM ITSM Integration Workflow'
        Trigger = $trigger
        Action = $action
        Settings = $settings
        Principal = $principal
        TaskPath = '\Tripwire\'
        }
    Register-ScheduledTask @CCMScheduledTask
    }
elseif($Mode -eq "Run" -or $null)
    {
    Set-CCMScanHeaders -Username $CCMUsername -Password $CCMPassword -Server $CCMServer
    # Enumerate changes - you can further filter your incidents based on parameters here - typically we just filter by time range...
    $CCMChanges = Get-CCMChangesinLast24Hours 
    # but you could filter by criticality for example:
    # $CCMChanges = Get-CCMChangesinLast24Hours  | where-object{$_.criticality -eq "High"}
    # or by category:
    # $CCMChanges = Get-CCMChangesinLast24Hours  | where-object{$_.category -eq "Compliance Policies"}
    # or by desription:
    # $CCMChanges = Get-CCMChangesinLast24Hours  | where-object{$_.description -like "Policy Test changed"}
    $CCMChanges | ForEach-Object
        {
        # Raise a ITSM case
        Write-Information "Logging a case for $_"
        # Optionally, gather additional asset details for incident raising
        if($GetAssetDetails){
            $Asset = Get-CCMAssetByID -AssetID $_.asset.id
            if($Asset.Count -ne 1){$Asset = $Null}
            }
        else
            {$Asset = $null}
        switch($ITMSIntegrationProduct) {
            "JIRA"{New-IncidentJIRA -IncidentParams $_ -AssetParams $Asset}
            "REMEDY"{New-IncidentREMEDY -IncidentParams $_ -AssetParams $Asset}
            "SNOW"{New-IncidentSNOW -IncidentParams $_ -AssetParams $Asset}
            }
        }
    }
}
############
# Execution
############
CCMITSMINTEGRATIONWORKFLOW -Mode $Mode -CCMUsername $CCMUsername -CCMPassword $CCMPassword -CCMServer $CCMServer -ITMSIntegrationProduct $ITMSIntegrationProduct
