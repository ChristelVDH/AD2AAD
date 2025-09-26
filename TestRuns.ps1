[CmdletBinding()]
# https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.codeanalysis.suppressmessageattribute?view=net-8.0
#[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidDefaultValueSwitchParameter", "")]
param(
    [switch]$ConnectGraph,
    [switch]$SingleGroupTest,
    [switch]$TestCompareGroups,
    [switch]$GetEntraUsers
)
#import necessary connection parameters
$ConnectParams = Import-PowerShellDataFile -Path "$PSScriptRoot\ConnectParams.psd1"
Import-Module -Name "$PSScriptRoot\AD2AAD.psd1" -Force -ErrorAction Stop
$Logfolder = Join-Path -Path $PSScriptRoot -ChildPath logs
$TranscriptFile = Join-Path -Path $Logfolder -ChildPath "Ad2Aad_$(Get-Date -Format "MM-dd-yyyy_HHumm-ss").log"
Start-Transcript -Path $TranscriptFile

if ($ConnectGraph -or $TestCompareGroups -or $GetEntraUsers -or $SingleGroupTest) {
    New-GraphToken @ConnectParams -InitializeMGConnection -ErrorAction Stop
}
else { Write-Warning "Need to use New-GraphToken to run any online test"; exit 1 }

if ($SingleGroupTest) {
    [string]$ADgroup = Read-Host -Prompt "Enter the name of the AD group to sync (no wildcards!!!)"
    $TestUser = "Test.User"
    Add-ADGroupMember -Identity $ADgroup -Members $TestUser
    $CommonParams = @{
        #Objects2ExcludeGroup = "ExcludeFromAD2AADSync"
        AzureGroupPrefix = "TstINT"
        CreateEmptyGroup = $true
        RunAsJob         = $false
        OutLog           = $false
        Verbose          = $true
        Verbosity        = 0
    }
    $Script:Output += Sync-ADGroups2AAD @ConnectParams @CommonParams -Group2Sync $ADgroup -Objects2Sync All -DestinationGroupType All
}

if ($TestCompareGroups) {
    $SyncedOUs = @(
        "OU=Groups,OU=HeadQuarters,DC=company,DC=be",
        "OU=Groups,OU=BranchOfficeWX,DC=company,DC=be",
        "OU=Groups,OU=BranchOfficeYZ,DC=company,DC=be"
    )
    $ADGroups = @()
    $AdProps = @('Name', 'Description')
    foreach ($OU in $SyncedOUs) { $ADGroups += Get-ADGroup -Filter * -SearchBase $OU -SearchScope OneLevel -Properties $AdProps }
    [string]$AzureGroupPrefix = "INT-"
    $Filter = "startsWith(DisplayName, '$($AzureGroupPrefix)')"
    $Props = "Id,CreatedDateTime,DisplayName,Description"
    $AADGroups = Get-MgGroup -ConsistencyLevel eventual -Count GroupCount -Filter $Filter -Property $Props -OrderBy DisplayName -All
    $script:output += Confirm-GroupSync -AzureGroups $AADGroups -ADGroups $ADGroups -GroupPrefix $AzureGroupPrefix -UpdateDescriptionFromAD #-RemoveAzureOnlyGroups
}

if ($GetEntraUsers) {
    $MGUserParams = @{
        All      = $true
        Filter   = "OnPremisesSyncEnabled eq true and UserType eq 'Member'"
        Property = "Id,displayName,userPrincipalName"
    }
    #$script:AADUsers = Get-MgUser @MGUserParams
    $script:AADUsers = Initialize-GraphUri -Resource 'users' @MGUserParams -Consistency
    Write-Verbose -Message "Found $($script:AADUsers.Count) users in Entra ID with OnPremisesSyncEnabled set to true"
}

if ($Script:Output.Count -gt 0) { 
    $Now = Get-Date -Format "MM-dd-yyyy_HHumm"
    $OutputLog = Join-Path -Path $Logfolder -ChildPath "AD2AAD_SyncReport_$($Now).log"
    $Script:Output | Out-File -FilePath $OutputLog -Force 
}
Stop-Transcript
