# Pester tests for AD2AAD.psm1 module functions
$ModulePath = "$PSScriptRoot\..\AD2AAD.psm1"
Import-Module $ModulePath -Force

Describe 'AD2AAD Module Functions' {
    Context 'Assert-InteractiveShell' {
        It 'Should return a boolean value' {
            $result = Assert-InteractiveShell
            $result | Should -BeOfType 'System.Boolean'
        }
    }

    Context 'New-GraphToken' {
        It 'Should throw error for invalid TenantID' {
            { New-GraphToken -TenantID 'NoSuchTenantID' } | Should -Throw
        }
    }

    Context 'Get-MGConnection' {
        It 'Should throw if missing required scopes' {
            $fakeConn = @{ access_token = 'fake' }
            { Get-MGConnection -GraphConnection $fakeConn -RequiredScopes @('Fake.Scope') } | Should -Throw
        }
    }

    Context 'Expand-RESTObject' {
        It 'Should return input object if no AdditionalProperties' {
            $obj = [PSCustomObject]@{ Name = 'Test' }
            $result = Expand-RESTObject -InputObject $obj
            $result | Should -Be $obj
        }
    }

    Context 'Get-MDMDevices' {
        It 'Should return empty for unknown user' {
            $result = Get-MDMDevices -UPN 'unknown@domain.com'
            $result | Should -BeNullOrEmpty
        }
        It 'Should return empty for unknown device' {
            $result = Get-MDMDevices -DeviceID 'cb835a3e-4287-4b94-e8ee-a3281df0012d'
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'Assert-GroupName' {
        It 'Should return $true for valid group name' {
            $result = Assert-GroupName -GroupName 'INT-ValidGroupName-D' -Prefix 'INT-'
            $result | Should -Be $true
        }
        It 'Should return $false for invalid group name with Enforce' {
            $result = Assert-GroupName -GroupName 'Invalid Name' -Enforce
            $result | Should -Be $false
        }
    }

    Context 'Update-AzureGroupMembership' {
        It 'Should not throw for empty input' {
            { Update-AzureGroupMembership -AzureGroupName 'INT-TestGroup-U' -Users @() -Devices @() } | Should -Not -Throw
        }
    }

    Context 'Confirm-AzureGroup' {
        It 'Should not throw for non-existing group' {
            { Confirm-AzureGroup -Name 'NonExistingGroup' } | Should -Not -Throw
        }
    }

    Context 'Resolve-AzureGroup' {
        It 'Should not throw for valid name' {
            { Resolve-AzureGroup -Name 'INT-TestGroup-U' } | Should -Not -Throw
        }
    }

    Context 'Confirm-GroupSync' {
        It 'Should not throw for empty input' {
            { Confirm-GroupSync -AzureGroups @() -ADGroups @() } | Should -Not -Throw
        }
    }

    Context 'Get-GraphQueryResults' {
        It 'Should throw for invalid URI' {
            { Get-GraphQueryResults -uri 'http://invalid' -GraphHeader @{} } | Should -Throw
        }
    }

    Context 'Resolve-GraphRequestError' {
        It 'Should return string for fake response' {
            $fakeResponse = [PSCustomObject]@{ StatusCode = @{ value__ = 404 }; StatusDescription = 'Not Found'; GetResponseStream = { $null } }
            $result = Resolve-GraphRequestError -Response $fakeResponse -GraphUri 'http://invalid'
            $result | Should -BeOfType 'System.String'
        }
    }

    Context 'Write-Log' {
        It 'Should not throw for default call' {
            { Write-LogEntries } | Should -Not -Throw
        }
    }
}

    # Additional tests for uncovered functions
    Describe 'Additional AD2AAD Module Functions' {
        Context 'Select-GraphRoot' {
            It 'Should set GraphRoot to Production' {
                Select-GraphRoot -GraphEnvironment 'Production'
                $script:GraphRoot | Should -Be 'https://graph.microsoft.com/v1.0'
            }
            It 'Should set GraphRoot to Beta' {
                Select-GraphRoot -GraphEnvironment 'Beta'
                $script:GraphRoot | Should -Be 'https://graph.microsoft.com/beta'
            }
        }

        Context 'Initialize-GraphUri' {
            It 'Should not throw for default call' {
                { Initialize-GraphUri -Resource users } | Should -Not -Throw
            }
        }

        Context 'Get-AzureGroupMembers' {
            It 'Should not throw for non-existing group' {
                { Get-AzureGroupMembers -GroupName 'NonExistingGroup' } | Should -Not -Throw
            }
        }

        Context 'Get-CorporateDevices' {
            It 'Should not throw for unknown user' {
                { Get-CorporateDevices -UPN 'unknown@domain.com' } | Should -Not -Throw
            }
        }

        Context 'Write-LogEntry' {
            It 'Should not throw for default call' {
                { Write-LogEntry -Value 'Test log entry' } | Should -Not -Throw
            }
        }

        Context 'Sync-ADGroups2AAD' {
            It 'Should not throw for empty input' {
                { Sync-ADGroups2AAD -ADGroups @() -AADGroups @() } | Should -Not -Throw
            }
        }
    }
