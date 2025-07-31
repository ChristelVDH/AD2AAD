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
            { New-GraphToken -TenantID 'invalid' } | Should -Throw
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
        It 'Should return empty for unknown user/device' {
            $result = Get-MDMDevices -UPN 'unknown@domain.com'
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'Assert-GroupName' {
        It 'Should return $true for valid group name' {
            $result = Assert-GroupName -GroupName 'INT-ValidGroupName-D' -Prefix 'INT-'
            $result | Should -Be $true
        }
        It 'Should return $false for invalid group name with Enforce' {
            $result = Assert-GroupName -GroupName 'EXO-InvalidGroupName' -Enforce
            $result | Should -Be $false
        }
    }

    Context 'Update-AzureGroupMembership' {
        It 'Should not throw for empty input' {
            { Update-AzureGroupMembership -AzureGroupName 'TestGroup' -Users @() -Devices @() } | Should -Not -Throw
        }
    }

    Context 'Confirm-AzureGroup' {
        It 'Should not throw for non-existing group' {
            { Confirm-AzureGroup -Name 'NonExistingGroup' } | Should -Not -Throw
        }
    }

    Context 'Resolve-AzureGroup' {
        It 'Should not throw for valid name' {
            { Resolve-AzureGroup -Name 'TestGroup' } | Should -Not -Throw
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
