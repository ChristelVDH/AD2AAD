@{
    # Script module or binary module file associated with this manifest
    RootModule        = 'AD2AAD.psm1'
    NestedModules     = @()
    ModuleVersion     = '1.0.2'
    GUID              = 'b7e7e7e7-7e7e-7e7e-7e7e-b7e7e7e7e7e7'
    Author            = 'Christel Van der Herten'
    CompanyName       = 'KICTS'
    Description       = 'AD2AAD PowerShell module for Azure AD group sync and management.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop')
    FunctionsToExport = @(
        'Assert-InteractiveShell',
        'Assert-GroupName',
        'Confirm-AzureGroup',
        'Confirm-GroupSync',
        'Expand-RESTObject',
        'Get-AzureGroupMembers',
        'Get-CorporateDevices',
        'Get-GraphQueryResults',
        'Get-MDMDeviceInfo',
        'Get-MGConnection',
        'Initialize-GraphUri',
        'New-GraphToken',
        'Resolve-AzureGroup',
        'Resolve-Duplicates',
        'Resolve-GraphRequestError',
        'Select-GraphRoot',
        'Sync-ADGroups2AAD',
        'Update-AzureGroupMembership',
        'Write-LogEntry',
        'Write-LogEntries'
    )
    VariablesToExport = @()
    AliasesToExport   = @()
}
