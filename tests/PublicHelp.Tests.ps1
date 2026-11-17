BeforeAll {
    $script:modulePath = Join-Path $PSScriptRoot '..\M365DomainAuthentication.psm1'
    $script:entryPath = Join-Path $PSScriptRoot '..\Set-M365DomainAuthentication.ps1'
    Import-Module $script:modulePath -Force
    $script:surfaces = @(
        @{ Name = 'Invoke-M365DomainAuthentication'; OutputType = 'PSCustomObject' },
        @{ Name = $script:entryPath; OutputType = 'String' }
    )
}

Describe 'Public command help' {
    It 'documents both public surfaces without running setup or contacting services' {
        Mock Read-Host { throw 'Help must not prompt for credentials' }
        Mock Invoke-RestMethod { throw 'Help must not send HTTP requests' }
        Mock Resolve-DnsName { throw 'Help must not query DNS' }
        Mock Read-Host { throw 'Help must not prompt for credentials' } -ModuleName M365DomainAuthentication
        Mock Invoke-RestMethod { throw 'Help must not send HTTP requests' } -ModuleName M365DomainAuthentication
        Mock Resolve-DnsName { throw 'Help must not query DNS' } -ModuleName M365DomainAuthentication

        foreach ($surface in $script:surfaces) {
            $help = Get-Help $surface.Name -Full
            $help.Synopsis | Should -Match 'Previews or applies'
            ($help.Description.Text -join ' ').Length | Should -BeGreaterThan 300
            @($help.Examples.Example).Count | Should -BeGreaterOrEqual 5
            ($help.InputTypes.InputType.Type.Name -join ' ') | Should -Match 'None'
            ($help.ReturnValues.ReturnValue.Type.Name -join ' ') | Should -Match $surface.OutputType
            @($help.relatedLinks.navigationLink).Count | Should -BeGreaterOrEqual 3

            $command = Get-Command $surface.Name
            $ast = $command.ScriptBlock.Ast
            if ($ast -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $ast = $ast.Body }
            $explicitParameters = @($ast.ParamBlock.Parameters |
                ForEach-Object { $_.Name.VariablePath.UserPath })
            $explicitParameters.Count | Should -Be 9
            foreach ($parameter in $explicitParameters) {
                $parameterHelp = Get-Help $surface.Name -Parameter $parameter
                ($parameterHelp.Description.Text -join ' ').Length | Should -BeGreaterThan 35 -Because "$($surface.Name) must explain $parameter"
            }
            $exampleHelp = Get-Help $surface.Name -Examples
            @($exampleHelp.Examples.Example).Count | Should -BeGreaterOrEqual 5
            $exampleText = $help.Examples.Example | Out-String -Width 240
            foreach ($pattern in 'AsSecureString', '-Apply', '-WhatIf', '-ReplaceConflictingRecords', '-DnsZone', '\.Health') {
                $exampleText | Should -Match $pattern
            }
        }

        Should -Invoke Read-Host -Times 0
        Should -Invoke Invoke-RestMethod -Times 0
        Should -Invoke Resolve-DnsName -Times 0
        Should -Invoke Read-Host -Times 0 -ModuleName M365DomainAuthentication
        Should -Invoke Invoke-RestMethod -Times 0 -ModuleName M365DomainAuthentication
        Should -Invoke Resolve-DnsName -Times 0 -ModuleName M365DomainAuthentication
    }

    It 'explains mandatory safety gates, boundaries, and recoverable states on both surfaces' {
        foreach ($surface in $script:surfaces) {
            $text = Get-Help $surface.Name -Full | Out-String -Width 240
            foreach ($pattern in @(
                'read-only', 'dmarc-rua@', 'dmarc-ruf@', 'immediately before',
                'authoritative', 'public resolvers', 'public keys', 'p=none',
                'SPF', 'MFA', 'domains\.domain:read', 'domains\.dns:update',
                'manual resolution', 'no automatic rollback', 'dns-before\.json',
                'result\.json', 'Pending', 'Partial', 'Conflict', 'NotVerifiable',
                '1\.1\.1\.1', '8\.8\.8\.8', '600', 'RUF', 'sensitive', 'dkim=pass', 'dmarc=pass'
            )) {
                $text | Should -Match $pattern -Because "$($surface.Name) must describe $pattern"
            }
        }
    }

    It 'distinguishes entry-script exit codes from module object results' {
        $scriptHelp = Get-Help $script:entryPath -Full | Out-String -Width 240
        $scriptHelp | Should -Match '0 = Preview or Completed'
        $scriptHelp | Should -Match '2 = Conflict or Pending'
        $scriptHelp | Should -Match '1 = Failed or Partial'
        $scriptHelp | Should -Match 'do not dot-source'
        $moduleHelp = Get-Help Invoke-M365DomainAuthentication -Full | Out-String -Width 240
        $moduleHelp | Should -Match 'does not set script process exit codes'
    }
}
