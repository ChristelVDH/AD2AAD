@{
    # Script module or binary module file associated with this manifest
    RootModule        = 'AD2AAD.psm1'
    NestedModules     = @()
    ModuleVersion     = '1.0.0'
    GUID              = '5269e99f-0a2d-4048-9fc7-e9af12d8ab68'
    Author            = 'Christel Van der Herten'
    CompanyName       = 'KICTS'
    Description       = 'AD2AAD PowerShell module for Azure AD group sync and management.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Assert-InteractiveShell',
        'Assert-GroupName',
        'Confirm-AzureGroup',
        'Confirm-GroupSync',
        'Expand-RESTObject',
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
