<#PSScriptInfo

.VERSION 0.3.3
.GUID 9c1fcbcd-fe13-4810-bf91-f204ec903193
.AUTHOR Nick Benton
.COMPANYNAME odds+endpoints
.COPYRIGHT GPL
.TAGS Graph Intune Windows
.LICENSEURI https://github.com/ennnbeee/Win11Accelerator/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/Win11Accelerator
.ICONURI
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v0.1 - Initial release
v0.2 - Allows creation of Dynamic Groups
v0.2.1 - Function improvements and bug fixes
v0.2.2 - Changed logic if groups are to be created
v0.2.3 - Improved function performance, and updated device dynamic groups
v0.2.4 - Updated attribute assignment logic and module check logic
v0.3  - Updated to create a Feature Update profile and assign the low risk group
v0.3.1 - Bug fixes for group creation and assignment, and improved error handling
v0.3.2 - Bug fixes for attribute assignment and whatIf mode
v0.3.4 - User interface improvements, and improved error handling

.PRIVATEDATA
#>

<#
.SYNOPSIS
Allows for a phased and controlled distribution of Windows 11 Feature Updates following the run and capture of Update Readiness data, tagging devices in Entra ID with their update readiness risk score for use with Dynamic Security Groups.

.DESCRIPTION
The Invoke-Windows11Accelerator script allows for the controlled roll out of Windows 11 Feature Updates based on device readiness risk assessments data.

.PARAMETER featureUpdateBuild
Select the Windows 11 Feature Update version you wish to deploy
Choice of 22H2, 23H2, 24H2.
Default is 24H2, so the script will target Windows 11 24H2 Feature Update.

.PARAMETER extensionAttribute
Configure the device extensionAttribute to be used for tagging Entra ID objects with their Feature Update Readiness Assessment risk score.
Choice of 1 to 15

.PARAMETER target
Select the whether you want to target the deployment to groups of users or groups of devices.
Choice of Users or Devices.
Default is Devices, so the script will target devices.

.PARAMETER createGroups
Select whether the dynamic groups should be created as part of the script run.
Default is false, so the script will not create the groups.

.PARAMETER groupPrefix
The prefix to be used for the dynamic group names and Feature Update profile name.
Default is 'Win11Acc-'

.PARAMETER whatIf
Select whether you want to run the script in whatIf mode, with this switch it will not tag devices or users with their risk state.
Default is false, so the script will run in production mode.

.PARAMETER firstRun
Run the script without with warning prompts, used for continued running of the script.
Default is true, so the script will run with warning prompts.

.PARAMETER tenantId
Provide the Id of the tenant to connect to.

.PARAMETER appId
Provide the Id of the Entra App registration to be used for authentication.

.PARAMETER appSecret
Provide the App secret to allow for authentication to graph

.EXAMPLE
PS> .\Win11Accelerator.ps1 -featureUpdateBuild 23H2 -target device -extensionAttribute 15 -whatIf -createGroups

.EXAMPLE
PS> .\Win11Accelerator.ps1 -featureUpdateBuild 24H2 -target device -extensionAttribute 10 -firstRun

.NOTES
Version:        0.3.3
Author:         Nick Benton
WWW:            oddsandendpoints.co.uk
Creation Date:  25/06/2025
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]

param(

    [Parameter(Position = 0, Mandatory = $true, HelpMessage = 'Select the Windows 11 Feature Update version you wish to deploy')]
    [ValidateSet('22H2', '23H2', '24H2')]
    [String]$featureUpdateBuild = '24H2',

    [Parameter(Position = 1, Mandatory = $true, HelpMessage = 'Select the whether you want to target the deployment to groups of users or groups of devices.')]
    [ValidateSet('user', 'device')]
    [String]$target = 'device',

    [Parameter(Position = 2, Mandatory = $true, HelpMessage = 'Configure the device extensionAttribute to be used for tagging Entra ID objects with their Feature Update Readiness Assessment risk score.')]
    [ValidateRange(1, 15)]
    [int]$extensionAttribute,

    [Parameter(Position = 3, Mandatory = $false, HelpMessage = 'Select whether the dynamic groups should be created as part of the script run')]
    [Boolean]$createGroups = $false,

    [Parameter(Position = 4, Mandatory = $false, HelpMessage = 'The prefix to be used for the dynamic group names and Feature Update profile name')]
    [String]$groupPrefix = 'Win11Acc-',

    [Parameter(Position = 7, Mandatory = $false, HelpMessage = 'Run the script with or without with warning prompts, used for continued running of the script.')]
    [Boolean]$firstRun = $true,

    [Parameter(Position = 8, Mandatory = $false, HelpMessage = 'Select the scope tag to be used for the report')]
    [String]$scopeTag = 'default',

    [Parameter(Mandatory = $false, HelpMessage = 'Provide the Id of the Entra ID tenant to connect to')]
    [ValidateLength(36, 36)]
    [String]$tenantId,

    [Parameter(Mandatory = $false, HelpMessage = 'Provide the Id of the Entra App registration to be used for authentication')]
    [ValidateLength(36, 36)]
    [String]$appId,

    [Parameter(Mandatory = $false, HelpMessage = 'Provide the App secret to allow for authentication to graph')]
    [ValidateNotNullOrEmpty()]
    [String]$appSecret,

    [Parameter(Mandatory = $false, HelpMessage = 'Run the script in whatIf mode, with this switch it will not tag devices or users with their risk state.')]
    [Boolean]$whatIf = $false

)

#region Functions
Function Connect-ToGraph {
    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.

.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.

.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.

.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.

.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

.PARAMETER Scopes
Specifies the user scopes for interactive authentication.

.EXAMPLE
Connect-ToGraph -tenantId $tenantId -appId $app -appSecret $secret

-#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$tenantId,
        [Parameter(Mandatory = $false)] [string]$appId,
        [Parameter(Mandatory = $false)] [string]$appSecret,
        [Parameter(Mandatory = $false)] [string[]]$scopes
    )

    Process {
        #Import-Module Microsoft.Graph.Authentication
        $version = (Get-Module microsoft.graph.authentication | Select-Object -ExpandProperty Version).major

        if ($AppId -ne '') {
            $body = @{
                grant_type    = 'client_credentials';
                client_id     = $appId;
                client_secret = $appSecret;
                scope         = 'https://graph.microsoft.com/.default';
            }

            $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body
            $accessToken = $response.access_token

            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
                $accessTokenFinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
                $accessTokenFinal = $accessToken
            }
            $graph = Connect-MgGraph -AccessToken $accessTokenFinal
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        }
        else {
            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -Scopes $scopes -TenantId $tenantId
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}
Function Test-JSONData() {

    param (
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $TestJSON | Out-Null
        $validJson = $true
    }
    catch {
        $validJson = $false
        $_.Exception
    }
    if (!$validJson) {
        Write-Host "Provided JSON isn't in valid JSON format" -f Red
        break
    }

}
Function New-ReportFeatureUpdateReadiness() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]

    param
    (
        [parameter(Mandatory = $true)]
        $featureUpdate,

        [Parameter()]
        $scopeTagId
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/reports/exportJobs'

    $JSON = @"
    {
        "reportName": "MEMUpgradeReadinessDevice",
        "filter": "(TargetOS eq '$featureUpdate') and (DeviceScopesTag eq '$scopeTagId')",
        "select": [
            "DeviceName",
            "DeviceManufacturer",
            "DeviceModel",
            "OSVersion",
            "ReadinessStatus",
            "SystemRequirements",
            "AppIssuesCount",
            "DriverIssuesCount",
            "AppOtherIssuesCount",
            "DeviceId",
            "AadDeviceId",
            "Ownership"
        ],
        "format": "csv"
    }
"@


    if ($PSCmdlet.ShouldProcess('Creating new Feature Update Report')) {
        try {
            Test-JSONData -Json $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
        }
        catch {
            Write-Error $_.Exception.Message
            break
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'Feature Update report would have been created'
    }
    else {
        Write-Output 'Feature Update report was not created'
    }
}
Function Get-ReportFeatureUpdateReadiness() {

    [cmdletbinding()]

    param (

        [parameter(Mandatory = $true)]
        $Id

    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/reports/exportJobs('$Id')"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        if ($id) {
            Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
        }
        elseif ($JSON) {
            $tempFile = [System.IO.Path]::GetTempFileName()
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json' -OutputFilePath $tempFile
            Get-Content -Raw $tempFile | ConvertFrom-Json
            Remove-Item $tempFile
        }

    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function Add-ObjectAttribute() {

    [cmdletbinding()]

    param
    (

        [parameter(Mandatory = $true)]
        [ValidateSet('User', 'Device')]
        $object,

        [parameter(Mandatory = $true)]
        $JSON,

        [parameter(Mandatory = $true)]
        $Id
    )

    $graphApiVersion = 'Beta'
    if ($object -eq 'User') {
        $Resource = "users/$Id"
    }
    else {
        $Resource = "devices/$Id"
    }

    try {
        Test-JSONData -Json $JSON
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Patch -Body $JSON -ContentType 'application/json'
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function Get-EntraIDObject() {

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param
    (

        [parameter(Mandatory = $false)]
        [switch]$user,

        [parameter(Mandatory = $false, ParameterSetName = 'devices')]
        [switch]$device,

        [parameter(Mandatory = $true, ParameterSetName = 'devices')]
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS')]
        [string]$os

    )

    $graphApiVersion = 'beta'
    if ($user) {
        $Resource = "users?`$filter=userType eq 'member' and accountEnabled eq true"
    }
    elseif ($device) {
        switch ($os) {
            'iOS' {
                $Resource = "devices?`$filter=operatingSystem eq 'iOS' and isManaged eq true"
            }
            'Android' {
                $Resource = "devices?`$filter=operatingSystem eq 'Android'and isManaged eq true"
            }
            'macOS' {
                $Resource = "devices?`$filter=operatingSystem eq 'macOS'and isManaged eq true"
            }
            'Windows' {
                $Resource = "devices?`$filter=operatingSystem eq 'Windows'and isManaged eq true"
            }
        }
    }
    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $graphResults = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject

        $results = @()
        $results += $graphResults.value

        $pages = $graphResults.'@odata.nextLink'
        while ($null -ne $pages) {

            $additional = Invoke-MgGraphRequest -Uri $pages -Method Get -OutputType PSObject

            if ($pages) {
                $pages = $additional.'@odata.nextLink'
            }
            $results += $additional.value
        }

        $results
    }
    catch {
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}
Function Get-ManagedDevice() {

    [cmdletbinding()]
    param
    (

    )

    $graphApiVersion = 'beta'
    $Resource = "deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $graphResults = Invoke-MgGraphRequest -Uri $uri -Method Get

        $results = @()
        $results += $graphResults.value

        $pages = $graphResults.'@odata.nextLink'
        while ($null -ne $pages) {

            $additional = Invoke-MgGraphRequest -Uri $pages -Method Get

            if ($pages) {
                $pages = $additional.'@odata.nextLink'
            }
            $results += $additional.value
        }
        $results
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function Get-ScopeTag() {

    [cmdletbinding()]
    param
    (

    )

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/roleScopeTags'

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function Get-MDMGroup() {

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $false)]
        [string]$groupName
    )

    $graphApiVersion = 'beta'
    $Resource = 'groups'

    try {
        if ($groupName) {
            $searchTerm = 'search="displayName:' + $groupName + '"'
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?$searchTerm"
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        }

        $graphResults = Invoke-MgGraphRequest -Uri $uri -Method Get -Headers @{ConsistencyLevel = 'eventual' } -OutputType PSObject

        $results = @()
        $results += $graphResults.value

        $pages = $graphResults.'@odata.nextLink'
        while ($null -ne $pages) {

            $additional = Invoke-MgGraphRequest -Uri $pages -Method Get -Headers @{ConsistencyLevel = 'eventual' } -OutputType PSObject

            if ($pages) {
                $pages = $additional.'@odata.nextLink'
            }
            $results += $additional.value
        }

        $results

    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function New-MDMGroup() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]

    param
    (
        [Parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'beta'
    $Resource = 'groups'

    if ($PSCmdlet.ShouldProcess('Creating new Entra ID security group')) {
        try {
            Test-Json -Json $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
        }
        catch {
            Write-Error $_.Exception.Message
            break
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'FEntra ID security group would have been created'
    }
    else {
        Write-Output 'Entra ID security group was not created'
    }
}
Function New-FeatureUpdateProfile() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]

    param
    (
        [parameter(Mandatory = $true)]
        $name,

        [parameter(Mandatory = $true)]
        [ValidateSet('22H2', '23H2', '24H2')]
        $featureUpdateBuild,

        [parameter(Mandatory = $false)]
        [datetime]$startDate,

        [parameter(Mandatory = $false)]
        [datetime]$endDate,

        [parameter(Mandatory = $false)]
        [int]$groupInterval = 7,

        [Parameter(Mandatory = $false)]
        $scopeTagId = '00000'
    )

    if ($startDate -and $startDate -lt (Get-Date)) {
        Write-Host 'Start Dates cannot be in the past' -ForegroundColor Yellow
        break
    }
    if ($endDate -and $endDate -lt (Get-Date)) {
        Write-Host 'End Dates cannot be in the past' -ForegroundColor Yellow
        break
    }

    if (!$startDate) {
        $startDate = (Get-Date).AddDays($groupInterval)
    }
    $startDateFormat = (Get-Date $startDate -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')

    if (!$endDate) {
        $endDate = '2025-10-01T00:00:00.000Z'
    }

    $endDateFormat = (Get-Date $endDate -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')

    $featureUpdateVersion = switch ($featureUpdateBuild) {
        '22H2' { 'Windows 11, version 22H2' } # Windows 11 22H2 (Nickel)
        '23H2' { 'Windows 11, version 23H2' } # Windows 11 23H2 (Nickel)
        '24H2' { 'Windows 11, version 24H2' } # Windows 11 24H2 (Germanium)
    }

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/windowsFeatureUpdateProfiles'

    $JSON = @"
    {
        "displayName": "$name",
        "description": "",
        "featureUpdateVersion": "$featureUpdateVersion",
        "roleScopeTagIds": [
            "$scopeTagId"
        ],
        "installFeatureUpdatesOptional": false,
        "installLatestWindows10OnWindows11IneligibleDevice": false,
        "rolloutSettings": {
            "offerStartDateTimeInUTC": "$startDateFormat",
            "offerEndDateTimeInUTC": "$endDateFormat",
            "offerIntervalInDays": $groupInterval
        }
    }
"@
    if ($PSCmdlet.ShouldProcess('Creating new Feature Update Profile')) {
        try {
            Test-JSONData -Json $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
        }
        catch {
            Write-Error $_.Exception.Message
            break
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'Feature Update profile would have been created'
    }
    else {
        Write-Output 'Feature Update profile was not created'
    }
}
Function Get-FeatureUpdateProfile() {

    [CmdletBinding()]

    param
    (
        [parameter(Mandatory = $false)]
        $Id
    )

    $graphApiVersion = 'Beta'
    if ($id) {
        $Resource = "deviceManagement/windowsFeatureUpdateProfiles('$Id')"
    }
    else {
        $Resource = 'deviceManagement/windowsFeatureUpdateProfiles'
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject).value
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }

}
Function New-FeatureUpdateAssignment() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]

    param
    (
        [parameter(Mandatory = $true)]
        $featureUpdateProfileId,

        [parameter(Mandatory = $true)]
        $groupId
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/windowsFeatureUpdateProfiles/$featureUpdateProfileId/assign"

    $JSON = @"
{
    "assignments": [
        {
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "$groupId"
            }
        }
    ]
}
"@

    if ($PSCmdlet.ShouldProcess('Creating new Feature Update Profile assignment')) {
        try {
            Test-JSONData -Json $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
        }
        catch {
            Write-Error $_.Exception.Message
            break
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'Feature Update profile assignment would have been created'
    }
    else {
        Write-Output 'Feature Update profile assignment was not created'
    }
}
#endregion Functions

#region testing
<#
$scopeTag = 'default'
$featureUpdateBuild = '24H2'
$extensionAttribute = 11
$whatIf = $false
$firstRun = $false
$target = 'device'
$createGroups = $false
$deployFeatureUpdate = $false
#>
#endregion testing

#region intro
Write-Host '
 ________ __         ____   ____   _______                   __                    __
|  |  |  |__|.-----.|_   | |_   | |   _   |.----.----.-----.|  |.-----.----.---.-.|  |_.-----.----.
|  |  |  |  ||     | _|  |_ _|  |_|       ||  __|  __|  -__||  ||  -__|   _|  _  ||   _|  _  |   _|
|________|__||__|__||______|______|___|___||____|____|_____||__||_____|__| |___._||____|_____|__|
' -ForegroundColor blue

Write-Host "Allows for the tagging of Windows devices with their Windows 11 $featureUpdate Feature Update risk score, to allow for a controlled update to Windows 11." -ForegroundColor Green
Write-Host 'Nick Benton - oddsandendpoints.co.uk' -NoNewline;
Write-Host ' | Version' -NoNewline; Write-Host ' 0.3.3 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2025-06-25' -ForegroundColor Magenta
Write-Host ''
Write-Host 'If you have any feedback, please open an issue at https://github.com/ennnbeee/W11Accelerator/issues' -ForegroundColor Cyan
Write-Host ''
#endregion intro

#region variables
$ProgressPreference = 'SilentlyContinue';
$rndWait = Get-Random -Minimum 1 -Maximum 3

$requiredScopes = @('Device.ReadWrite.All', 'DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All')
if ($createGroups -eq $true) {
    $requiredScopes += @('Group.ReadWrite.All')
}
if ($scopeTag -ne 'default') {
    $requiredScopes += @('DeviceManagementRBAC.Read.All')
}
if ($target -eq 'users') {
    $requiredScopes += @('User.ReadWrite.All')
}
[String[]]$scopes = $requiredScopes -join ', '

$extensionAttributeValue = 'extensionAttribute' + $extensionAttribute

$featureUpdate = Switch ($featureUpdateBuild) {
    '22H2' { 'NI22H2' } # Windows 11 22H2 (Nickel)
    '23H2' { 'NI23H2' } # Windows 11 23H2 (Nickel)
    '24H2' { 'GE24H2' } # Windows 11 24H2 (Germanium)
}

$userRule = "(user.accountEnabled -eq True) and (user.assignedPlans -any (assignedPlan.servicePlanId -eq `\`"c1ec4a95-1f05-45b3-a911-aa3fa01094f5`\`" -and assignedPlan.capabilityStatus -eq `\`"Enabled`\`")) and "
$deviceRule = "(device.deviceManagementAppId -ne null) and (device.deviceOwnership -eq `\`"Company`\`") and (device.deviceOSType -eq `\`"Windows`\`") and "

$targetCase = (Get-Culture).TextInfo.ToTitleCase($target)

$riskGroupArray = @()
$riskGroupArray += [PSCustomObject]@{ displayName = $groupPrefix + $targetCase + '-W11-' + $featureUpdateBuild + '-LowRisk'; rule = "($target.$extensionAttributeValue -eq `\`"W11-$featureUpdateBuild-LowRisk`\`")"; description = 'Low Risk Windows 11 Feature Update Readiness group' }
$riskGroupArray += [PSCustomObject]@{ displayName = $groupPrefix + $targetCase + '-W11-' + $featureUpdateBuild + '-MediumRisk'; rule = "($target.$extensionAttributeValue -eq `\`"W11-$featureUpdateBuild-MediumRisk`\`")"; description = 'Medium Risk Windows 11 Feature Update Readiness group' }
$riskGroupArray += [PSCustomObject]@{ displayName = $groupPrefix + $targetCase + '-W11-' + $featureUpdateBuild + '-HighRisk'; rule = "($target.$extensionAttributeValue -eq `\`"W11-$featureUpdateBuild-HighRisk`\`")"; description = 'High Risk Windows 11 Feature Update Readiness group' }
$riskGroupArray += [PSCustomObject]@{ displayName = $groupPrefix + $targetCase + '-W11-' + $featureUpdateBuild + '-Unknown'; rule = "($target.$extensionAttributeValue -eq `\`"W11-$featureUpdateBuild-Unknown`\`")"; description = 'Unknown Risk Windows 11 Feature Update Readiness group' }
$riskGroupArray += [PSCustomObject]@{ displayName = $groupPrefix + $targetCase + '-W11-' + $featureUpdateBuild + '-NotReady'; rule = "($target.$extensionAttributeValue -eq `\`"W11-$featureUpdateBuild-NotReady`\`")"; description = 'Not Ready Windows 11 Feature Update Readiness group' }

$groupsArray = @()
foreach ($riskGroup in $riskGroupArray) {
    if ($target -eq 'user') {
        $groupsArray += [PSCustomObject]@{ displayName = $riskGroup.displayName; rule = $userRule + $riskGroup.rule; description = $riskGroup.description }
    }
    else {
        $groupsArray += [PSCustomObject]@{ displayName = $riskGroup.displayName; rule = $deviceRule + $riskGroup.rule; description = $riskGroup.description }
    }
}

$groupsDisplayArray = @()
foreach ($groupArray in $groupsArray) {
    $groupsDisplayArray += [PSCustomObject]@{ displayName = $groupArray.displayName; rule = $groupArray.rule.replace('\', '') }
}

#endregion variables

#region module check
if (!$IsMacOS -and !$IsLinux) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $elevatedStatus = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$modules = @('Microsoft.Graph.Authentication')
foreach ($module in $modules) {
    Write-Host "Checking for $module PowerShell module..." -ForegroundColor Cyan
    Write-Host ''
    If (!(Get-Module -Name $module -ListAvailable)) {
        if ($elevatedStatus -eq $true) {
            Write-Host "PowerShell Module $module not found, installing for all users." -ForegroundColor Yellow
            Write-Host ''
            Install-Module -Name $module -AllowClobber
        }

        else {
            Write-Host "PowerShell Module $module not found, installing for current user." -ForegroundColor Yellow
            Write-Host ''
            Install-Module -Name $module -Scope CurrentUser -AllowClobber
        }

    }
    Write-Host "PowerShell Module $module found." -ForegroundColor Green
    Write-Host ''
    Import-Module -Name $module -Force
}
#endregion module check

#region app auth
try {
    if (!$tenantId) {
        Write-Host 'Connecting using interactive authentication' -ForegroundColor Yellow
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    }
    else {
        if ((!$appId -and !$appSecret) -or ($appId -and !$appSecret) -or (!$appId -and $appSecret)) {
            Write-Host 'Missing App Details, connecting using user authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -Scopes $scopes -ErrorAction Stop
        }
        else {
            Write-Host 'Connecting using App authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -appId $appId -appSecret $appSecret -ErrorAction Stop
        }
    }
    $context = Get-MgContext
    Write-Host ''
    Write-Host "Successfully connected to Microsoft Graph tenant with ID $($context.TenantId)." -ForegroundColor Green
}
catch {
    Write-Error $_.Exception.Message
    Exit
}
#endregion app auth

#region scopes
$currentScopes = $context.Scopes
# Validate required permissions
$missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
if ($missingScopes.Count -gt 0) {
    Write-Host 'WARNING: The following scope permissions are missing:' -ForegroundColor Red
    $missingScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ''
    Write-Host 'Please ensure these permissions are granted to the app registration for full functionality.' -ForegroundColor Yellow
    exit
}
Write-Host ''
Write-Host 'All required scope permissions are present.' -ForegroundColor Green
#endregion scopes

#region scope tags
if ($scopeTag -ne 'default') {
    Get-ScopeTag | ForEach-Object {
        if ($_.displayName -eq $scopeTag) {
            $scopeTagId = '{0:d5}' -f [int]$_.id
            $scopeTagId | Out-Null
        }
    }
    if ($null -eq $scopeTagId) {
        Write-Host "Unable to find Scope Tag $scopeTag" -ForegroundColor Red
        Break
    }
}
else {
    $scopeTagId = '00000'
}

#endregion scope tags

#region Start
Write-Host
Start-Sleep -Seconds $rndWait
if ($whatIf -eq $true) {
    Write-Host "Starting the 'Win11Accelerator' Script in whatIf mode" -ForegroundColor yellow
}
else {
    Write-Host "Starting the 'Win11Accelerator' Script in production mode" -ForegroundColor Red
}
Write-Host
Write-Host 'The script will carry out the following:' -ForegroundColor Green
Write-Host ''
Write-Host '    - Capture all Windows Device or User objects from Entra ID.' -ForegroundColor White
Write-Host "    - Start a Windows 11 $featureUpdateBuild Feature Update Readiness report." -ForegroundColor White
Write-Host "    - Capture and process the outcome of the Windows 11 $featureUpdateBuild Feature Update Readiness report." -ForegroundColor White
if ($target -eq 'user') {
    Write-Host "    - Assign a risk based flag to the Primary User object using Extension Attribute $extensionAttributeValue" -ForegroundColor White
}
else {
    Write-Host "    - Assign a risk based flag to the Device object using Extension Attribute $extensionAttributeValue" -ForegroundColor White
}
Write-Host ''
Write-Host 'The script can be run multiple times, as the Extension Attributes are overwritten (if  changed) with each run.' -ForegroundColor Yellow
Write-Host ''
if ($createGroups -eq $true) {
    Write-Host 'The script will create the Dynamic Groups in Entra ID for each of the risk levels, if they do not already exist' -ForegroundColor Green
    Write-Host ''
}
if ($firstRun -eq $true) {
    Write-Host ''
    Write-Warning 'Please review the above and confirm you are happy to continue.' -WarningAction Inquire
}
#endregion Start

#region pre-flight
Write-Host
if ($target -eq 'user') {
    Write-Host 'Getting user objects and associated IDs from Entra ID...' -ForegroundColor Cyan
    $entraUsers = Get-EntraIDObject -user
    Write-Host "Found $($entraUsers.Count) user objects and associated IDs from Entra ID." -ForegroundColor Green
    if ($entraUsers.Count -eq 0) {
        Write-Host 'Found no Users in Entra.' -ForegroundColor Red
        Break
    }
    #optimising the entra user data
    $optEntraUsers = @{}
    foreach ($itemEntraUser in $entraUsers) {
        $optEntraUsers[$itemEntraUser.id] = $itemEntraUser
    }
    Write-Host
    Write-Host 'Getting Windows device objects and associated IDs from Microsoft Intune...' -ForegroundColor Cyan
    $intuneDevices = Get-ManagedDevice
    Write-Host "Found $($intuneDevices.Count) Windows device objects and associated IDs from Microsoft Intune." -ForegroundColor Green
    Write-Host
    if ($intuneDevices.Count -eq 0) {
        Write-Host 'Found no Windows devices in Intune.' -ForegroundColor Red
        Break
    }
    #optimising the intune device data
    $optIntuneDevices = @{}
    foreach ($itemIntuneDevice in $intuneDevices) {
        $optIntuneDevices[$itemIntuneDevice.azureADDeviceId] = $itemIntuneDevice
    }
}
Write-Host 'Getting Windows device objects and associated IDs from Entra ID...' -ForegroundColor Cyan
$entraDevices = Get-EntraIDObject -device -os Windows
Write-Host "Found $($entraDevices.Count) Windows devices and associated IDs from Entra ID." -ForegroundColor Green
if ($entraDevices.Count -eq 0) {
    Write-Host 'Found no Windows devices in Entra.' -ForegroundColor Red
    Break
}
#optimising the entra device data
$optEntraDevices = @{}
foreach ($itemEntraDevice in $entraDevices) {
    $optEntraDevices[$itemEntraDevice.deviceid] = $itemEntraDevice
}
Write-Host
Write-Host "Checking for existing data in attribute $extensionAttributeValue in Entra ID..." -ForegroundColor Cyan
$attributeErrors = 0
$safeAttributes = @("W11-$featureUpdateBuild-LowRisk", "W11-$featureUpdateBuild-MediumRisk", "W11-$featureUpdateBuild-HighRisk", "W11-$featureUpdateBuild-NotReady", "W11-$featureUpdateBuild-Unknown")

$entraObjects = switch ($target) {
    'user' { $entraUsers }
    'device' { $entraDevices }
}

$extAttribute = switch ($target) {
    'user' { 'onPremisesExtensionAttributes' }
    'device' { 'extensionAttributes' }
}

foreach ($entraObject in $entraObjects) {

    $attribute = ($entraObject.$extAttribute | ConvertTo-Json | ConvertFrom-Json).$extensionAttributeValue
    if ($attribute -notin $safeAttributes) {
        if ($null -ne $attribute) {
            Write-Host "$($entraObject.displayName) already has a value of '$attribute' configured in $extensionAttributeValue" -ForegroundColor Yellow
            $attributeErrors = $attributeErrors + 1
        }
    }
}
if ($attributeErrors -gt 0) {
    Write-Host
    Write-Host "Please review the objects reporting as having existing data in the selected attribute $extensionAttributeValue." -ForegroundColor Red
    Write-Warning "If you are happy to overwrite $extensionAttributeValue please continue, otherwise stop the script." -WarningAction Inquire
}
Write-Host "No issues found using the selected attribute $extensionAttributeValue for risk assignment." -ForegroundColor Green
Write-Host
#endregion pre-flight

#region Group Creation
Write-Host ''
if ($firstRun -eq $true) {
    if ($createGroups -eq $false) {
        Write-Host "The following $($groupsArray.Count) group(s) should be created manually:" -ForegroundColor Yellow
    }
    else {
        Write-Host "The following $($groupsArray.Count) group(s) will be created:" -ForegroundColor Yellow
    }
    Write-Host ''
    $groupsDisplayArray | Select-Object -Property displayName, rule | Format-Table -AutoSize -Wrap
}

if ($createGroups -eq $true) {
    if ($firstRun -eq $true) {
        Write-Host ''
        Write-Warning -Message "You are about to create $($groupsArray.Count) new group(s) in Microsoft Entra ID. Please confirm you want to continue." -WarningAction Inquire
        Write-Host ''
    }

    foreach ($group in $groupsArray) {
        $groupName = $($group.displayName)
        if ($groupName.length -gt 120) {
            #shrinking group name to less than 120 characters
            $groupName = $groupName[0..120] -join ''
        }

        if (!(Get-MDMGroup -groupName $groupName)) {
            Write-Host ''
            Write-Host "Creating Group $groupName with rule $($group.rule)" -ForegroundColor Cyan
            $groupJSON = @"
    {
        "description": "$($group.description)",
        "displayName": "$groupName",
        "groupTypes": [
            "DynamicMembership"
        ],
        "mailEnabled": false,
        "mailNickname": "$groupName",
        "securityEnabled": true,
        "membershipRule": "$($group.rule)",
        "membershipRuleProcessingState": "On"
    }
"@
            if ($whatIf -eq $true) {
                Write-Host 'WhatIf mode enabled, no changes will be made.' -ForegroundColor Magenta
                continue
            }
            else {
                New-MDMGroup -JSON $groupJSON | Out-Null
            }
            Write-Host "Group $($group.displayName) created successfully." -ForegroundColor Green
        }
        else {
            Write-Host "Group $($group.displayName) already exists, skipping creation." -ForegroundColor Yellow
            continue
        }
    }
    Write-Host 'Successfully created new group(s) in Microsoft Entra ID.' -ForegroundColor Green
    Write-Host ''
}

#endregion Group Creation

#region Feature Update Readiness
Write-Host "Starting the Feature Update Readiness Report for Windows 11 $featureUpdateBuild with scope tag $scopeTag..." -ForegroundColor Magenta
Write-Host

$featureUpdateReport = New-ReportFeatureUpdateReadiness -featureUpdate $featureUpdate -scopeTagId $scopeTagId
Write-Host 'Waiting for the Feature Update report to finish processing...' -ForegroundColor Cyan
While ((Get-ReportFeatureUpdateReadiness -Id $featureUpdateReport.id).status -ne 'completed') {
    Start-Sleep -Seconds $rndWait
}

Write-Host "Windows 11 $featureUpdateBuild feature update readiness completed processing." -ForegroundColor Green
Write-Host
Write-Host "Getting Windows 11 $featureUpdateBuild feature update readiness Report data..." -ForegroundColor Magenta
Write-Host
$featureUpdateReadinessURL = (Get-ReportFeatureUpdateReadiness -Id $featureUpdateReport.id).url

$urlHeader = @{Accept = '*/*'; 'accept-encoding' = 'gzip, deflate, br, zstd' }
Add-Type -AssemblyName System.IO.Compression
$featureUpdateReadinessStream = Invoke-WebRequest -Uri $featureUpdateReadinessURL -Method Get -Headers $urlHeader -UseBasicParsing -ErrorAction Stop
$featureUpdateReadinessZip = [System.IO.Compression.ZipArchive]::new([System.IO.MemoryStream]::new($featureUpdateReadinessStream.Content))
$featureUpdateReadinessDevices = [System.IO.StreamReader]::new($featureUpdateReadinessZip.GetEntry($featureUpdateReadinessZip.Entries[0]).open()).ReadToEnd() | ConvertFrom-Csv

if ($($featureUpdateReadinessDevices.Count) -eq 0) {
    Write-Warning 'No Feature Update Readiness report details were found, please review the pre-requisites ' -WarningAction Inquire

}

Write-Host "Found Feature Update Report Details for $($featureUpdateReadinessDevices.Count) devices." -ForegroundColor Green
Write-Host
Write-Host "Processing Windows 11 $featureUpdateBuild feature update readiness Report data for $($featureUpdateReadinessDevices.Count) devices..." -ForegroundColor Magenta

$reportArray = @()
foreach ($featureUpdateReadinessDevice in $featureUpdateReadinessDevices) {

    $riskState = switch ($featureUpdateReadinessDevice.ReadinessStatus) {
        '0' { "W11-$featureUpdateBuild-LowRisk" }
        '1' { "W11-$featureUpdateBuild-MediumRisk" }
        '2' { "W11-$featureUpdateBuild-HighRisk" }
        '3' { "W11-$featureUpdateBuild-NotReady" }
        '5' { "W11-$featureUpdateBuild-Unknown" }
    }

    if ($target -eq 'user') {

        if ($null -ne $featureUpdateReadinessDevice.AadDeviceId) {
            $userObject = $optIntuneDevices[$featureUpdateReadinessDevice.AadDeviceId]

            if ($null -ne $userObject.userId) {
                $userEntraObject = $optEntraUsers[$userObject.userId]
            }
            else {
                $userEntraObject = $null
            }
        }
        else {
            $userObject = $null
            $userEntraObject = $null
        }

        $reportArray += [PSCustomObject]@{
            'AadDeviceId'              = $featureUpdateReadinessDevice.AadDeviceId
            'AppIssuesCount'           = $featureUpdateReadinessDevice.AppIssuesCount
            'AppOtherIssuesCount'      = $featureUpdateReadinessDevice.AppOtherIssuesCount
            'DeviceId'                 = $featureUpdateReadinessDevice.DeviceId
            'DeviceManufacturer'       = $featureUpdateReadinessDevice.DeviceManufacturer
            'DeviceModel'              = $featureUpdateReadinessDevice.DeviceModel
            'DeviceName'               = $featureUpdateReadinessDevice.DeviceName
            'DriverIssuesCount'        = $featureUpdateReadinessDevice.DriverIssuesCount
            'OSVersion'                = $featureUpdateReadinessDevice.OSVersion
            'Ownership'                = $featureUpdateReadinessDevice.Ownership
            'ReadinessStatus'          = $featureUpdateReadinessDevice.ReadinessStatus
            'SystemRequirements'       = $featureUpdateReadinessDevice.SystemRequirements
            'RiskState'                = $riskState
            'userObjectID'             = $userObject.userId
            'userPrincipalName'        = $userObject.userPrincipalName
            "$extensionAttributeValue" = $userEntraObject.onPremisesExtensionAttributes.$extensionAttributeValue
        }

    }
    else {

        if ($null -ne $featureUpdateReadinessDevice.AadDeviceId) {
            $deviceObject = $optEntraDevices[$featureUpdateReadinessDevice.AadDeviceId]
        }
        else {
            $deviceObject = $null
        }

        $reportArray += [PSCustomObject]@{
            'AadDeviceId'              = $featureUpdateReadinessDevice.AadDeviceId
            'AppIssuesCount'           = $featureUpdateReadinessDevice.AppIssuesCount
            'AppOtherIssuesCount'      = $featureUpdateReadinessDevice.AppOtherIssuesCount
            'DeviceId'                 = $featureUpdateReadinessDevice.DeviceId
            'DeviceManufacturer'       = $featureUpdateReadinessDevice.DeviceManufacturer
            'DeviceModel'              = $featureUpdateReadinessDevice.DeviceModel
            'DeviceName'               = $featureUpdateReadinessDevice.DeviceName
            'DriverIssuesCount'        = $featureUpdateReadinessDevice.DriverIssuesCount
            'OSVersion'                = $featureUpdateReadinessDevice.OSVersion
            'Ownership'                = $featureUpdateReadinessDevice.Ownership
            'ReadinessStatus'          = $featureUpdateReadinessDevice.ReadinessStatus
            'SystemRequirements'       = $featureUpdateReadinessDevice.SystemRequirements
            'RiskState'                = $riskState
            'deviceObjectID'           = $deviceObject.id
            "$extensionAttributeValue" = $deviceObject.extensionAttributes.$extensionAttributeValue
        }
    }
}
$reportArray = $reportArray | Sort-Object -Property ReadinessStatus

Write-Host "Processed Windows 11 $featureUpdateBuild feature update readiness data for $($featureUpdateReadinessDevices.Count) devices." -ForegroundColor Green
Write-Host
#endregion Feature Update Readiness

#region Attributes
Write-Host "Starting the assignment of risk based extension attributes to $extensionAttributeValue" -ForegroundColor Magenta
Write-Host ''
if ($firstRun -eq $true) {
    Write-Warning 'Please confirm you are happy to continue.' -WarningAction Inquire
}
Write-Host "Assigning the Risk attributes to $extensionAttributeValue..." -ForegroundColor cyan
Write-Host ''
if ($target -eq 'user') {
    # Removes devices with no primary user
    $userReportArray = $reportArray | Where-Object { $_.userPrincipalName -ne $null -and $_.userPrincipalName -ne '' } | Group-Object userPrincipalName

    foreach ( $user in $userReportArray ) {

        $userObject = $user.Group
        # All user devices at Windows 11
        if (($userObject.ReadinessStatus | Measure-Object -Sum).Sum / $user.count -eq 4) {
            # Only need one device object as they're all Windows 11
            $userObject = $user.Group | Select-Object -First 1

            if (($userObject.$extensionAttributeValue -eq $userObject.RiskState) -and ($null -ne $userObject.$extensionAttributeValue)) {
                $riskColour = 'cyan'
                Write-Host "$($userObject.userPrincipalName) risk tag hasn't changed for Windows 11 $featureUpdateBuild" -ForegroundColor White
            }
            elseif (($null -eq $userObject.$extensionAttributeValue) -and ($($userObject.ReadinessStatus) -eq 4)) {
                Write-Host "$($userObject.userPrincipalName) device already updated to Windows 11 $featureUpdateBuild" -ForegroundColor Cyan
            }
            else {
                $riskColour = 'Cyan'
                $JSON = @"
                    {
                        "$extAttribute": {
                            "$extensionAttributeValue": "$($userObject.RiskState)"
                        }
                    }
"@
            }

        }
        else {
            # Gets readiness state where not updated to Windows 11, selects highest risk number
            $highestRisk = ($userObject | Where-Object { $_.ReadinessStatus -ne 4 } | Measure-Object -Property ReadinessStatus -Maximum).Maximum
            $userObject = ($userObject | Where-Object { $_.ReadinessStatus -eq $highestRisk } | Select-Object -First 1)

            if ($userObject.$extensionAttributeValue -eq $userObject.RiskState -and ($null -ne $userObject.$extensionAttributeValue)) {
                $riskColour = 'cyan'
                Write-Host "$($userObject.userPrincipalName) risk tag hasn't changed for Windows 11 $featureUpdateBuild" -ForegroundColor White
            }
            elseif (($null -eq $userObject.$extensionAttributeValue) -and ($($userObject.ReadinessStatus) -eq 4)) {
                Write-Host "$($userObject.userPrincipalName) device already updated to Windows 11 $featureUpdateBuild" -ForegroundColor Cyan
            }
            else {
                $riskColour = switch ($($userObject.ReadinessStatus)) {
                    '0' { 'Green' }
                    '1' { 'Yellow' }
                    '2' { 'Red' }
                    '3' { 'Blue' }
                    '4' { 'Cyan' }
                    '5' { 'Magenta' }
                }
                $JSON = @"
                    {
                        "$extAttribute": {
                            "$extensionAttributeValue": "$($userObject.RiskState)"
                        }
                    }
"@
            }
        }

        If ($whatIf -eq $false) {
            Start-Sleep -Seconds $rndWait
            if (!([string]::IsNullOrEmpty($userObject.userObjectID))) {
                Add-ObjectAttribute -object User -Id $($userObject.userObjectID) -JSON $JSON
            }
            else {
                Write-Host "$($userObject.userObjectID) risk tag could not be assigned for Windows 11 $featureUpdateBuild" -ForegroundColor DarkRed
            }
        }
        if ($($user.Group.ReadinessStatus) -eq 4) {
            Write-Host "$($userObject.userPrincipalName) $extensionAttributeValue risk tag removed as already updated to Windows 11 $featureUpdateBuild" -ForegroundColor $riskColour
        }
        else {
            Write-Host "$($userObject.userPrincipalName) assigned risk tag $($userObject.RiskState) to $extensionAttributeValue for Windows 11 $featureUpdateBuild" -ForegroundColor $riskColour
        }
    }

}
else {
    Foreach ($device in $reportArray) {

        $riskColour = switch ($($device.ReadinessStatus)) {
            '0' { 'Green' }
            '1' { 'Yellow' }
            '2' { 'Red' }
            '3' { 'Blue' }
            '4' { 'Cyan' }
            '5' { 'Magenta' }
        }

        if (($device.$extensionAttributeValue -eq $device.RiskState) -and ($null -ne $device.$extensionAttributeValue)) {
            Write-Host "$($device.DeviceName) risk tag hasn't changed for Windows 11 $featureUpdateBuild" -ForegroundColor White
        }
        elseif (($null -eq $device.$extensionAttributeValue) -and ($($device.ReadinessStatus) -eq 4)) {
            Write-Host "$($device.DeviceName) already updated to Windows 11 $featureUpdateBuild" -ForegroundColor $riskColour
        }
        else {
            $JSON = @"
            {
                "$extAttribute": {
                    "$extensionAttributeValue": "$($device.RiskState)"
                }
            }
"@

            # Sleep to stop throttling issues
            If ($whatIf -eq $false) {
                Start-Sleep -Seconds $rndWait
                if (!([string]::IsNullOrEmpty($device.deviceObjectID))) {
                    Add-ObjectAttribute -object Device -Id $device.deviceObjectID -JSON $JSON
                    Write-Host "$($device.DeviceName) assigned risk tag $($device.RiskState) to $extensionAttributeValue for Windows 11 $featureUpdateBuild" -ForegroundColor $riskColour
                }
                else {
                    Write-Host "$($device.DeviceName) risk tag could not be assigned for Windows 11 $featureUpdateBuild as deviceID is missing" -ForegroundColor DarkRed
                }

            }
            if ($($device.ReadinessStatus) -eq 4) {
                Write-Host "$($device.DeviceName) risk tag removed as now updated Windows 11 $featureUpdateBuild" -ForegroundColor $riskColour
            }
            else {
                if ($whatIf -eq $true) {
                    Write-Host "$($device.DeviceName) assigned risk tag $($device.RiskState) to $extensionAttributeValue for Windows 11 $featureUpdateBuild" -ForegroundColor $riskColour
                }
            }
        }
    }
}
Write-Host ''
Write-Host "Completed the assignment of risk based extension attributes to $extensionAttributeValue" -ForegroundColor Green
Write-Host ''
#endregion Attributes