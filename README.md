# Execution Flow of AD2AAD Module

The following is the execution flow for this module, starting from the `Sync-ADGroups2AAD` function:

1. **Sync-ADGroups2AAD** (= default entry point)
   - Validates and processes input parameters.
   - Sets up script variables, logging, and connects to Microsoft Graph.
   - Retrieves AD groups and Azure AD (Entra) objects (users, devices, groups).
   - For each AD group:
     - Validates group name with `Assert-GroupName`.
     - Retrieves group members (users/devices).
     - Builds lists of users/devices to mirror
     - Calls `Update-AzureGroupMembership` for each Azure group (UserGroup/DeviceGroup).

2. **Update-AzureGroupMembership**
   - Confirms or creates the Azure group with `Confirm-AzureGroup`.
   - Retrieves current Azure group members.
   - Compares AD and Azure group membership.
   - Adds/removes members in Azure group using Microsoft Graph API.
   - Logs actions and errors.

3. **Confirm-AzureGroup**
   - Checks if the Azure group exists in cached list.
   - If not, creates the group via Microsoft Graph API.
   - Calls `Resolve-AzureGroup` to ensure the correct group is found and returned.

4. **Resolve-AzureGroup**
   - Retrieves Azure groups by name or prefix.
   - Checks for duplicate groups (it happens!) and removes them if needed.

5. **Assert-GroupName**
   - Checks AD group name for naming convention compliance.
   - Logs or throws errors/warnings as needed.

6. **Get-MDMDeviceInfo**
   - Retrieves owner(s) and registree(s) for an Intune device

7. **Confirm-GroupSync** (optional, if ConfirmGroups is set)
   - Compares Azure groups to AD groups.
   - Removes Azure-only groups if not present in AD.

8. **Resolve-GraphRequestError**
   - Handles and logs errors from Microsoft Graph API requests.

9. **Write-LogEntry / -LogEntries**
   - Gathers (single) output and shows it to the console depending on selected -Verbosity param
   - Writes (all) output to pipeline or file (-OutLog) in the `My Documents` folder (by default)

10. **New-GraphToken / Get-MGConnection**
   - helper functions for establishing a Graph connection for sake of Graph cmdlets
   - returns a Token (Header) to use with Graph REST calls

**Supporting Functions**:
- `Assert-InteractiveShell`, `Expand-RESTObject`, `Get-GraphHeader`, `Get-GraphQueryResults` are utility functions used as needed for data handling, logging, and error management.

This flow ensures (nested) AD group membership is mirrored to a (flat) Entra group, with error handling, logging, and compliance checks throughout.
