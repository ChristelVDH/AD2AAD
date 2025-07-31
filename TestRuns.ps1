[CmdletBinding()]
# https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.codeanalysis.suppressmessageattribute?view=net-8.0
#[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidDefaultValueSwitchParameter", "")]
#new way of connecting to Graph:
param(
    [switch]$ConnectGraph,
    [switch]$SingleGroupTest,
    [switch]$TestCompareGroups
)

$ConnectParams = Import-PowerShellDataFile -Path "$PSScriptRoot\ConnectParams.psd1"
#$nl = [System.Environment]::NewLine
$Logfolder = Join-Path -Path $PSScriptRoot -ChildPath logs
Import-Module "$PSScriptRoot\AD2AAD.psd1" -Force -ErrorAction Stop
$TranscriptFile = Join-Path -Path $Logfolder -ChildPath "AD2AAD_$(Get-Date -Format "MM-dd-yyyy_HHumm-ss").log"
Start-Transcript -Path $TranscriptFile

if ($ConnectGraph -or $TestCompareGroups -or $CheckDuplicates -or $GetEntraUsers -or $SingleGroupTest) {
    New-GraphToken @ConnectParams -InitializeMGConnection -ErrorAction Stop
}
else { Write-Warning "Need to use New-GraphToken to run any online test"; exit 1 }

if ($SingleGroupTest) {
    [string]$ADgroup = Read-Host -Prompt "Enter the name of the AD group to sync (no wildcards!!!)"
    $TestUser = "Test.User"
    Add-ADGroupMember -Identity $ADgroup -Members $TestUser
    $CommonParams = @{
        #Objects2ExcludeGroup = "ExcludeFromAD2AADSync"
        AzureGroupPrefix = "INT-"
        CreateEmptyGroup = $true
        RunAsJob         = $false
        OutLog           = $false
        Verbose          = $true
    }
    $Script:Output += Sync-ADGroups2AAD @ConnectParams @CommonParams -Group2Sync $ADgroup -Objects2Sync All -DestinationGroupType All
}

if ($TestCompareGroups) {
    [string]$AzureGroupPrefix = "INT-"
    $OU = "OU=Groups,OU=HeadQuarters,DC=company,DC=be"
    #cache group membership for later use
    $ADGroups = Get-ADGroup -Filter * -SearchBase $OU -SearchScope OneLevel
    $AADGroups = Get-MgGroup -ConsistencyLevel eventual -Count GroupCount -Filter "startsWith(DisplayName, '$($AzureGroupPrefix)')" -OrderBy DisplayName -All
    $script:output += Confirm-GroupSync -AzureGroups $AADGroups -ADGroups $ADGroups -GroupPrefix $AzureGroupPrefix
}

if ($Script:Output.Count -gt 0) { 
    $Now = Get-Date -Format "MM-dd-yyyy_HHumm"
    $OutputLog = Join-Path -Path $Logfolder -ChildPath "AD2AAD_SyncReport_$($Now).log"
    $Script:Output | Out-File -FilePath $OutputLog -Force 
}
Stop-Transcript
