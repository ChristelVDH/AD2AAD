# AQFIM PowerShell Module

## Overview
AQFIM is a PowerShell module for synchronizing on-premises (nested) Active Directory (AD) groups and their members (users/devices) with Azure AD (Entra) groups. It automates group CRUD operations, membership management, compliance checks, and logging using the Microsoft Graph API.

The exported functions can be used separately for their intended purpose. Make sure to retrieve a Graph Token and connect to MG Graph!

## Exported Functions
| Function | Description |
|----------|-------------|
| Assert-InteractiveShell | Checks if running in an interactive shell. |
| Select-GraphRoot | Sets the Microsoft Graph API environment (Production/Beta). |
| New-GraphToken | Acquires a Microsoft Graph access token using app registration or certificate. |
| Get-MGConnection | Connects to Microsoft Graph using an access token and validates required scopes. |
| Initialize-GraphUri | Constructs Microsoft Graph API URIs for various resources and queries. |
| Expand-RESTObject | Expands additional properties in REST API objects for easier access. |
| Get-AzureGroupMembers | Retrieves members of Azure AD groups using Microsoft Graph API. |
| Assert-GroupName | Validates AD group name against naming conventions. |
| Resolve-AzureGroup | Finds Azure groups by name/prefix, removes duplicates if needed. |
| Confirm-AzureGroup | Confirms or creates Azure AD group. |
| Confirm-GroupSync | Compares Azure groups to AD groups, removes Azure-only groups if not present in AD. |
| Get-GraphQueryResults | Executes Graph API queries and handles paging for large result sets. |
| Resolve-GraphRequestError | Handles and logs errors from Microsoft Graph API requests. |
| Write-LogEntry | Writes a single log entry with severity levels. |
| Write-LogEntries | Outputs or saves all log entries to file, with verbosity filtering. |
| Get-CorporateDevices | Retrieves all managed Windows devices from Azure AD/Intune. |
| Get-MDMDeviceInfo | Retrieves device objects for a user or device from Azure AD/Intune. |
| Update-AzureGroupMembership | Mirrors AD group membership to Azure AD group. |
| Sync-ADGroups2AAD | Main entry point: syncs AD groups to Azure AD. |
| Resolve-Duplicates | Utility for duplicate handling. |

## Module Flow Description
1. **Sync-ADGroups2AAD**: 
	Is the main entry point of this module. 
	It validates input parameters, sets up logging, connects to Graph, retrieves AD/Azure objects, processes each group and member, and calls `Update-AzureGroupMembership`.
2. **Update-AzureGroupMembership**: 
	Confirms/creates Azure group, compares membership, adds/removes members, logs actions.
3. **Confirm-AzureGroup**: 
	Checks for group existence, creates if missing, resolves duplicates.
4. **Resolve-AzureGroup**: 
	Finds groups by name/prefix, removes duplicates if needed.
5. **Assert-GroupName**: 
	Validates group naming conventions.
6. **Get-MDMDeviceInfo**: 
	Retrieves device/user info from Azure AD/Intune.
7. **Get-CorporateDevices**: 
	Retrieves all managed Windows devices.
8. **Get-AzureGroupMembers**: 
	Gets members of Azure AD groups.
9. **Select-GraphRoot**: 
	Sets Graph API environment.
10. **Initialize-GraphUri**: 
	Builds Graph API URIs for queries.
11. **Get-MGConnection**: 
	Connects to Graph, validates scopes.
12. **New-GraphToken**: 
	Acquires access token for Graph API.
13. **Confirm-GroupSync**: 
	Compares Azure/AD groups, removes Azure-only groups.
14. **Expand-RESTObject**: 
	Expands REST API object properties.
15. **Get-GraphQueryResults**: 
	Executes Graph API queries, handles paging.
16. **Resolve-GraphRequestError**: 
	Handles/logs Graph API errors.
17. **Write-LogEntry**: 
	Writes a log entry with severity.
18. **Write-LogEntries**: 
	Outputs or saves all log entries.
19. **Resolve-Duplicates**: 
	Utility for duplicate handling in group management.

## Example Usage
```powershell
# Sync all AD groups in an OU to Azure AD
Sync-ADGroups2AAD -TenantID '<tenant-id>' -AppRegistrationID '<app-id>' -AppSecret '<secret>' -OU2Sync 'OU=Groups,DC=domain,DC=com' -Objects2Sync 'Users' -DestinationGroupType 'UserGroup' -OutLog
```

## Requirements
- Windows PowerShell 5.1 or later
- Microsoft Graph PowerShell SDK
- Appropriate permissions in Azure AD and on-prem AD

## Author & License
Author: Christel Van der Herten
License: MIT

---
For detailed parameter info and advanced scenarios, see inline help in each function or the source code.
