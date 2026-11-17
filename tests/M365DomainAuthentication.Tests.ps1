BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\M365DomainAuthentication.psm1') -Force
}

BeforeAll {
    & (Get-Module M365DomainAuthentication) {
        function script:Get-AcceptedDomain { param($ErrorAction) }
        function script:Get-DkimSigningConfig { param($ErrorAction) }
        function script:New-DkimSigningConfig { param($DomainName, $Enabled, $ErrorAction) }
        function script:Set-DkimSigningConfig { param($Identity, $Enabled, $ErrorAction) }
        function script:New-Mailbox { param([switch]$Shared, $Name, $Alias, $DisplayName, $PrimarySmtpAddress, $ErrorAction) }
        function script:Get-EXORecipient { param($Filter, [switch]$IncludeSoftDeletedRecipients, $Properties, $ResultSize, $ErrorAction) }
        function script:Get-EXOMailbox { param($Filter, $Properties, $ResultSize, $ErrorAction) }
        function script:Connect-ExchangeOnline { param($UserPrincipalName, $AppId, $CertificateThumbprint, $Organization, $ShowBanner, $ErrorAction) }
        function script:Get-ConnectionInformation { param($ErrorAction) }
        function script:Disconnect-ExchangeOnline { param($ConnectionId, $Confirm, [switch]$WhatIf, $ErrorAction) }

        function script:New-TestContext {
            [pscustomobject]@{
                Domain = 'example.com'; Zone = 'example.com'; ZonePath = '/zones/example.com'; Token = 'test-token'
                Replace = $false; Addresses = @('dmarc-rua@example.com', 'dmarc-ruf@example.com')
                AcceptedDomains = @('example.com'); Resolvers = @('1.1.1.1', '8.8.8.8')
                Authorities = @('ns1.domaincontrol.com', 'ns2.domaincontrol.com'); OriginalRecords = @()
                Health = [Collections.Generic.List[object]]::new(); Actions = [Collections.Generic.List[object]]::new()
                Changes = [Collections.Generic.List[object]]::new(); Conflicts = [Collections.Generic.List[string]]::new()
                Warnings = [Collections.Generic.List[string]]::new()
            }
        }
        function script:New-TestRecord {
            param($Name, $Type, $Data, $Id = ([guid]::NewGuid().ToString()))
            [pscustomobject]@{ name = $Name; type = $Type; data = $Data; ttl = 600; recordId = $Id }
        }
        function script:New-TestMailbox {
            param($Address, $Type = 'SharedMailbox')
            [pscustomobject]@{
                Identity = $Address; ExternalDirectoryObjectId = "id-$Address"; RecipientTypeDetails = $Type
                EmailAddresses = @("SMTP:$Address"); WhenSoftDeleted = $null
            }
        }
        $rsa = [Security.Cryptography.RSA]::Create(1024)
        try { $script:testKey = 'v=DKIM1; k=rsa; p=' + [Convert]::ToBase64String($rsa.ExportSubjectPublicKeyInfo()) }
        finally { $rsa.Dispose() }
    }
}

Describe 'Domain, policy, and key validation' {
    InModuleScope M365DomainAuthentication {
        It 'normalizes domain case and a trailing dot' {
            ConvertTo-DomainName 'Example.COM.' | Should -BeExactly 'example.com'
        }
        It 'rejects unsafe domain input <Value>' -TestCases @(
            @{ Value = 'https://example.com' }, @{ Value = 'example.com/zone' },
            @{ Value = '-bad.example.com' }, @{ Value = 'localhost' }, @{ Value = 'example..com' }
        ) {
            param($Value)
            { ConvertTo-DomainName $Value } | Should -Throw
        }
        It 'maps mail subdomains relative to their DNS zone' {
            $ctx = New-TestContext
            $ctx.Domain = 'mail.example.com'
            Get-RelativeName $ctx 'selector1._domainkey' | Should -Be 'selector1._domainkey.mail'
        }
        It 'parses strict DMARC policy without dropping unrelated tags' {
            $tags = Get-DmarcTags 'v=DMARC1; p=reject; sp=quarantine; adkim=s; rua=mailto:a@example.com; xcustom=keep'
            $tags.p | Should -Be 'reject'
            $tags.xcustom | Should -Be 'keep'
            @(Get-ReportAddresses $tags)[0] | Should -Be 'a@example.com'
        }
        It 'rejects malformed or duplicate DMARC tags <Policy>' -TestCases @(
            @{ Policy = 'v=DMARC1; p=invalid' }, @{ Policy = 'p=none; v=DMARC1' },
            @{ Policy = 'v=DMARC1; p=none; p=reject' }, @{ Policy = 'v=DMARC1; p=none; pct=101' },
            @{ Policy = 'v=DMARC1; p=none; aspf=bad' }
        ) {
            param($Policy)
            { Get-DmarcTags $Policy } | Should -Throw
        }
        It 'joins quoted provider TXT chunks' {
            ConvertFrom-ProviderTxt '"v=DMARC1; " "p=none"' | Should -BeExactly 'v=DMARC1; p=none'
        }
        It 'accepts a usable DKIM key and rejects missing, revoked, or malformed keys' {
            Test-DkimPublicKey $script:testKey | Should -BeTrue
            Test-DkimPublicKey 'v=DKIM1; p=' | Should -BeFalse
            Test-DkimPublicKey 'v=DKIM1; p=not-base64' | Should -BeFalse
            Test-DkimPublicKey 'v=DKIM1; k=ed25519; p=YWJj' | Should -BeFalse
            Test-DkimPublicKey ($script:testKey -replace 'DKIM1', 'invalid') | Should -BeFalse
            Test-DkimPublicKey ($script:testKey + '; p=') | Should -BeFalse
        }
    }
}

Describe 'Record planning preserves unrelated state' {
    InModuleScope M365DomainAuthentication {
        BeforeEach {
            $script:ctx = New-TestContext
            Mock Get-RecipientState { [pscustomobject]@{ State = 'Ready'; Identity = 'mailbox'; Address = $Address } }
            $script:dkim = [pscustomobject]@{
                Selector1CNAME = 'selector1-example-com._domainkey.tenant.r-v1.dkim.mail.microsoft'
                Selector2CNAME = 'selector2-example-com._domainkey.tenant.onmicrosoft.com'
            }
        }
        It 'uses both current and legacy Microsoft target values unchanged' {
            $plans = @(Get-RecordPlan $ctx @() $dkim)
            $plans[1].Data | Should -Be $dkim.Selector1CNAME
            $plans[2].Data | Should -Be $dkim.Selector2CNAME
            $plans[0].Data | Should -Be 'v=DMARC1; p=none; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com'
        }
        It 'preserves strict policies by default and reports differing reporting tags' {
            $original = 'v=DMARC1; p=reject; sp=reject; adkim=s; rua=mailto:old@example.com'
            $plan = Get-DmarcPlan $ctx @((New-TestRecord '_dmarc' TXT $original))
            $plan.Data | Should -BeExactly $original
            $ctx.Conflicts.Count | Should -BeGreaterThan 0
        }
        It 'changes only reporting tags when replacement is requested' {
            $ctx.Replace = $true
            $original = 'v=DMARC1; p=reject; sp=quarantine; adkim=s; xcustom=keep; rua=mailto:old@example.com'
            $plan = Get-DmarcPlan $ctx @((New-TestRecord '_dmarc' TXT $original))
            $tags = Get-DmarcTags $plan.Data
            $tags.p | Should -Be 'reject'
            $tags.sp | Should -Be 'quarantine'
            $tags.adkim | Should -Be 's'
            $tags.xcustom | Should -Be 'keep'
            $tags.rua | Should -Be 'mailto:dmarc-rua@example.com'
            $tags.ruf | Should -Be 'mailto:dmarc-ruf@example.com'
        }
        It 'does not replace unrelated TXT records at the DMARC owner' {
            $plan = Get-DmarcPlan $ctx @((New-TestRecord '_dmarc' TXT 'unrelated-verification=123'))
            $plan.Existing.Count | Should -Be 0
        }
        It 'requires manual resolution of multiple policies even with override rather than downgrading' {
            $ctx.Replace = $true
            $null = Get-DmarcPlan $ctx @(
                (New-TestRecord '_dmarc' TXT 'v=DMARC1; p=reject'),
                (New-TestRecord '_dmarc' TXT 'v=DMARC1; p=quarantine')
            )
            $ctx.Conflicts -join ' ' | Should -Match 'manual resolution'
        }
        It 'treats equivalent hostname case and trailing dots as already correct' {
            $plans = @(Get-RecordPlan $ctx @((New-TestRecord 'selector1._domainkey' CNAME ($dkim.Selector1CNAME.ToUpperInvariant() + '.'))) $dkim)
            $plans[1].Action | Should -Be 'Keep'
        }
        It 'reports incompatible records at selector names' {
            $null = Get-RecordPlan $ctx @((New-TestRecord 'selector1._domainkey' TXT 'other-key')) $dkim
            $ctx.Conflicts.Count | Should -BeGreaterThan 0
        }
        It 'marks existing external destinations unverifiable rather than creating them' {
            $null = Get-DmarcPlan $ctx @((New-TestRecord '_dmarc' TXT 'v=DMARC1; p=reject; rua=mailto:reports@external.test'))
            @($ctx.Health | Where-Object Status -EQ NotVerifiable).Count | Should -Be 1
            Should -Invoke Get-RecipientState -Times 0
        }
    }
}

Describe 'Recipient existence and provisioning' {
    InModuleScope M365DomainAuthentication {
        BeforeEach {
            $script:ctx = New-TestContext
            $script:mailbox = New-TestMailbox 'dmarc-rua@example.com'
            Mock Get-EXORecipient { $script:mailbox }
            Mock Get-EXOMailbox { $script:mailbox }
        }
        It 'accepts a pre-existing shared mailbox including alias ownership' {
            $mailbox.EmailAddresses = @('SMTP:primary@example.com', 'smtp:dmarc-rua@example.com')
            (Get-RecipientState 'dmarc-rua@example.com').State | Should -Be 'Ready'
        }
        It 'reuses user mailboxes without conversion' {
            $mailbox.RecipientTypeDetails = 'UserMailbox'
            (Get-RecipientState 'dmarc-rua@example.com').State | Should -Be 'Ready'
        }
        It 'rejects incompatible recipient types <Type>' -TestCases @(
            @{ Type = 'MailContact' }, @{ Type = 'MailUser' }, @{ Type = 'MailUniversalDistributionGroup' }
        ) {
            param($Type)
            $mailbox.RecipientTypeDetails = $Type
            (Get-RecipientState 'dmarc-rua@example.com').State | Should -Be 'Conflict'
        }
        It 'rejects soft-deleted address ownership' {
            $mailbox.WhenSoftDeleted = [datetime]::UtcNow
            (Get-RecipientState 'dmarc-rua@example.com').State | Should -Be 'Conflict'
        }
        It 'does not treat a recipient lookup error as absence' {
            Mock Get-EXORecipient { throw 'Access denied' }
            { Get-RecipientState 'dmarc-rua@example.com' } | Should -Throw '*Access denied*'
        }
        It 'blocks DMARC publication for an external destination' {
            { Assert-ReportAddresses $ctx 'v=DMARC1; p=none; rua=mailto:a@external.test; ruf=mailto:dmarc-ruf@example.com' } | Should -Throw '*external*'
        }
        It 'independently checks both report addresses' {
            Mock Get-RecipientState {
                if ($Address -like 'dmarc-ruf*') { [pscustomobject]@{ State = 'Missing' } }
                else { [pscustomobject]@{ State = 'Ready' } }
            }
            { Assert-ReportAddresses $ctx 'v=DMARC1; p=none; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com' } | Should -Throw '*DMARC write blocked*'
            Should -Invoke Get-RecipientState -Times 2
        }
        It 'requires provisioning readback even after successful creates' {
            Mock Get-RecipientState { [pscustomobject]@{ State = 'Missing'; Address = $Address } }
            Mock New-Mailbox { [pscustomobject]@{ Identity = $PrimarySmtpAddress } }
            Mock Start-Sleep {}
            Ensure-ReportingMailboxes $ctx 0 1 | Should -BeFalse
            Should -Invoke New-Mailbox -Times 2 -ParameterFilter { $Shared }
            Should -Invoke Get-RecipientState -Times 4
            Should -Invoke Start-Sleep -Times 0
        }
        It 'reconciles an ambiguous mailbox creation without creating a duplicate' {
            $script:recipientReads = @{}
            Mock Get-RecipientState {
                if (-not $script:recipientReads.ContainsKey($Address)) {
                    $script:recipientReads[$Address] = 0
                    return [pscustomobject]@{ State = 'Missing'; Address = $Address }
                }
                return [pscustomobject]@{ State = 'Ready'; Address = $Address; Identity = $Address }
            }
            Mock New-Mailbox { throw 'Response lost' }
            Ensure-ReportingMailboxes $ctx 0 1 | Should -BeTrue
            Should -Invoke New-Mailbox -Times 2
            @($ctx.Changes | Where-Object Action -EQ MailboxObservedAfterUncertainCreate).Count | Should -Be 2
        }
    }
}

Describe 'GoDaddy transport and concurrency' {
    InModuleScope M365DomainAuthentication {
        BeforeEach { $script:ctx = New-TestContext }
        It 'retrieves every page without trusting arbitrary next-link origins' {
            Mock Invoke-GoDaddy {
                if ($Path -match 'page=1&') { return @{ items = @((New-TestRecord a TXT one)); totalPages = 2 } }
                return @{ items = @((New-TestRecord b TXT two)); totalPages = 2 }
            }
            @(Get-ZoneRecords $ctx).Count | Should -Be 2
            Should -Invoke Invoke-GoDaddy -Times 2
        }
        It 'rejects malformed responses instead of assuming no records' {
            Mock Invoke-GoDaddy { @{ error = 'unexpected' } }
            { Get-ZoneRecords $ctx } | Should -Throw '*pagination response*'
        }
        It 'redacts transport errors and never retries a write blindly' {
            Mock Invoke-RestMethod { throw "network failure test-token" }
            { Invoke-GoDaddy $ctx POST '/zones/example.com/dns-records' @{ data = 'test' } } | Should -Throw '*HTTP 0*'
            try { Invoke-GoDaddy $ctx POST '/zones/example.com/dns-records' @{ data = 'test' } } catch { $_.Exception.Message | Should -Not -Match 'test-token' }
            Should -Invoke Invoke-RestMethod -Times 2
        }
        It 'bounds safe read retries on a rate limit and honors Retry-After' {
            Mock Start-Sleep {}
            Mock Invoke-RestMethod {
                $exception = [Exception]::new('rate limited')
                $exception | Add-Member NoteProperty Response ([pscustomobject]@{
                    StatusCode = 429
                    Headers = [pscustomobject]@{ RetryAfter = [pscustomobject]@{ Delta = [timespan]::FromSeconds(5) } }
                })
                throw $exception
            }
            { Invoke-GoDaddy $ctx GET '/zones/example.com/dns-records' } | Should -Throw '*Rate limit*'
            Should -Invoke Invoke-RestMethod -Times 3
            Should -Invoke Start-Sleep -Times 2 -ParameterFilter { $Seconds -eq 5 }
        }
        It 'detects a concurrent same-owner change before any write' {
            $old = New-TestRecord 'selector1._domainkey' CNAME old fixed
            $ctx.OriginalRecords = @($old)
            $plan = [pscustomobject]@{ Name = $old.name; Type = 'CNAME'; Data = 'new.example.com'; Existing = @($old); Action = 'Replace' }
            Mock Get-ZoneRecords { New-TestRecord 'selector1._domainkey' CNAME changed fixed }
            Mock Invoke-GoDaddy {}
            { Set-PlannedRecord $ctx $plan } | Should -Throw '*Concurrent DNS change*'
            Should -Invoke Invoke-GoDaddy -Times 0
        }
        It 'blocks DMARC writes if the immediate address check fails' {
            $ctx.OriginalRecords = @()
            $plan = [pscustomobject]@{ Name = '_dmarc'; Type = 'TXT'; Data = 'v=DMARC1; p=none'; Existing = @(); Action = 'Create' }
            Mock Get-ZoneRecords { @() }
            Mock Invoke-GoDaddy {}
            { Set-PlannedRecord $ctx $plan } | Should -Throw '*Both RUA and RUF*'
            Should -Invoke Invoke-GoDaddy -Times 0
        }
        It 'replaces a managed DMARC record while preserving unrelated TXT' {
            $old = New-TestRecord '_dmarc' TXT 'v=DMARC1; p=reject; rua=mailto:old@example.com' policy
            $unrelated = New-TestRecord '_dmarc' TXT 'verification=preserve' unrelated
            $ctx.OriginalRecords = @($old, $unrelated)
            $script:providerRecords = @($old, $unrelated)
            $plan = [pscustomobject]@{
                Name = '_dmarc'; Type = 'TXT'; Data = 'v=DMARC1; p=reject; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com'
                Existing = @($old); Action = 'Replace'
            }
            Mock Get-ZoneRecords { $script:providerRecords }
            Mock Get-RecipientState { [pscustomobject]@{ State = 'Ready'; Identity = $Address } }
            Mock Invoke-GoDaddy {
                if ($Method -ne 'PUT' -or $Path -notlike '*/policy') { throw 'Unexpected replacement operation' }
                $script:providerRecords[0].data = $Body.data
            }
            Set-PlannedRecord $ctx $plan
            $script:providerRecords[1].data | Should -Be 'verification=preserve'
            Should -Invoke Invoke-GoDaddy -Times 1 -ParameterFilter { $Method -eq 'PUT' -and $Path -like '*/policy' }
        }
        It 'removes conflicting selector records before creating the requested CNAME' {
            $old = New-TestRecord 'selector1._domainkey' TXT other-key conflicting
            $ctx.OriginalRecords = @($old)
            $script:providerRecords = @($old)
            $script:methods = [Collections.Generic.List[string]]::new()
            $plan = [pscustomobject]@{ Name = 'selector1._domainkey'; Type = 'CNAME'; Data = 'target.example.com'; Existing = @($old); Action = 'Replace' }
            Mock Get-ZoneRecords { $script:providerRecords }
            Mock Invoke-GoDaddy {
                $script:methods.Add($Method)
                if ($Method -eq 'DELETE') { $script:providerRecords = @(); return }
                if ($Method -eq 'POST') {
                    $record = New-TestRecord $Body.name $Body.type $Body.data created
                    $script:providerRecords = @($record)
                    return $record
                }
                throw 'Unexpected operation'
            }
            Set-PlannedRecord $ctx $plan
            $script:methods -join ',' | Should -Be 'DELETE,POST'
            $script:providerRecords[0].type | Should -Be 'CNAME'
        }
        It 'reconciles an ambiguous POST by readback instead of replaying it' {
            $ctx.OriginalRecords = @()
            $script:reads = 0
            $plan = [pscustomobject]@{ Name = 'selector1._domainkey'; Type = 'CNAME'; Data = 'target.example.com'; Existing = @(); Action = 'Create' }
            Mock Get-ZoneRecords {
                $script:reads++
                if ($script:reads -gt 1) { New-TestRecord 'selector1._domainkey' CNAME 'target.example.com' }
            }
            Mock Invoke-GoDaddy { throw 'response lost' }
            Set-PlannedRecord $ctx $plan
            Should -Invoke Invoke-GoDaddy -Times 1 -ParameterFilter { $Method -eq 'POST' }
            $ctx.Changes[0].Action | Should -Be 'DnsObservedAfterUncertainCreate'
        }
    }
}

Describe 'Mandatory publication health gates' {
    InModuleScope M365DomainAuthentication {
        BeforeEach {
            $script:ctx = New-TestContext
            $script:plans = @(
                [pscustomobject]@{ Name = 'selector1._domainkey'; Type = 'CNAME'; Data = 's1._domainkey.tenant.onmicrosoft.com' },
                [pscustomobject]@{ Name = 'selector2._domainkey'; Type = 'CNAME'; Data = 's2._domainkey.tenant.onmicrosoft.com' },
                [pscustomobject]@{ Name = '_dmarc'; Type = 'TXT'; Data = 'v=DMARC1; p=none; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com' }
            )
            $script:brokenName = ''
            $script:brokenSource = ''
            $script:failureMode = ''
            Mock Get-DnsAnswer {
                $plan = @($script:plans | Where-Object { "$($_.Name).example.com" -eq $Name })[0]
                if ($Name -like '*tenant.onmicrosoft.com') {
                    $data = if ($script:failureMode -eq 'BadKey') { 'v=DKIM1; p=' } else { $script:testKey }
                    return [pscustomobject]@{ Name = $Name; Type = 'TXT'; Strings = @($data) }
                }
                if ($Name -eq $script:brokenName -and (-not $script:brokenSource -or $Server -eq $script:brokenSource)) {
                    switch ($script:failureMode) {
                        'Error' { throw 'SERVFAIL or timeout' }
                        'Absent' { return }
                        'Stale' { return [pscustomobject]@{ Name = $Name; Type = 'CNAME'; NameHost = 'stale.example.com' } }
                        'MultipleDmarc' {
                            [pscustomobject]@{ Name = $Name; Type = 'TXT'; Strings = @($plan.Data) }
                            [pscustomobject]@{ Name = $Name; Type = 'TXT'; Strings = @('v=DMARC1; p=reject') }
                            return
                        }
                    }
                }
                if ($Type -eq 'CNAME') { return [pscustomobject]@{ Name = $Name; Type = 'CNAME'; NameHost = ($plan.Data.ToUpperInvariant() + '.') } }
                return [pscustomobject]@{ Name = $Name; Type = 'TXT'; Strings = @($plan.Data.Substring(0, 5), $plan.Data.Substring(5)) }
            }
            Mock Get-DkimConfig { [pscustomobject]@{ Enabled = $false; Status = 'CnameMissing' } }
            Mock Set-DkimSigningConfig {}
            Mock Start-Sleep {}
        }
        It 'requires matching authoritative, recursive, and key observations' {
            Test-PublicDns $ctx $plans | Should -BeTrue
            @($ctx.Health | Where-Object Status -NE Pass).Count | Should -Be 0
            Should -Invoke Get-DnsAnswer -Times 16
        }
        It 'blocks enablement for <Mode> at <Owner> from <Source>' -TestCases @(
            @{ Mode = 'Absent'; Owner = 'selector1._domainkey.example.com'; Source = '' },
            @{ Mode = 'Absent'; Owner = 'selector2._domainkey.example.com'; Source = '' },
            @{ Mode = 'Absent'; Owner = '_dmarc.example.com'; Source = '' },
            @{ Mode = 'Stale'; Owner = 'selector1._domainkey.example.com'; Source = 'ns2.domaincontrol.com' },
            @{ Mode = 'Stale'; Owner = 'selector2._domainkey.example.com'; Source = '8.8.8.8' },
            @{ Mode = 'Error'; Owner = '_dmarc.example.com'; Source = '1.1.1.1' },
            @{ Mode = 'MultipleDmarc'; Owner = '_dmarc.example.com'; Source = '' },
            @{ Mode = 'BadKey'; Owner = ''; Source = '' }
        ) {
            param($Mode, $Owner, $Source)
            $script:failureMode = $Mode
            $script:brokenName = $Owner
            $script:brokenSource = $Source
            Enable-VerifiedDkim $ctx $plans 0 1 | Should -BeFalse
            Should -Invoke Set-DkimSigningConfig -Times 0
            @($ctx.Health | Where-Object Status -EQ Pending).Count | Should -BeGreaterThan 0
        }
        It 'rechecks public DNS before retrying recognized Microsoft detection lag' {
            $script:dnsChecks = 0
            Mock Test-PublicDns { $script:dnsChecks++; return $script:dnsChecks -eq 1 }
            Mock Set-DkimSigningConfig { Write-Error -ErrorId ValidationException -Message 'CNAME record does not exist' -ErrorAction Stop }
            Enable-VerifiedDkim $ctx $plans 1 1 | Should -BeFalse
            Should -Invoke Set-DkimSigningConfig -Times 1
            Should -Invoke Test-PublicDns -Times 2
        }
        It 'does not swallow unrelated Exchange activation failures' {
            Mock Set-DkimSigningConfig { throw 'Permission denied' }
            { Enable-VerifiedDkim $ctx $plans 0 1 } | Should -Throw '*Permission denied*'
        }
        It 'does not disable existing signing when DNS is unhealthy' {
            $script:brokenName = '_dmarc.example.com'
            $script:failureMode = 'Absent'
            Mock Get-DkimConfig { [pscustomobject]@{ Enabled = $true; Status = 'Valid' } }
            Enable-VerifiedDkim $ctx $plans 0 1 | Should -BeFalse
            Should -Invoke Set-DkimSigningConfig -Times 0
        }
        It 'does not claim completion when Exchange readback is not Valid' {
            Mock Get-DkimConfig { [pscustomobject]@{ Enabled = $true; Status = 'CnameMissing' } }
            Enable-VerifiedDkim $ctx $plans 0 1 | Should -BeFalse
            @($ctx.Health | Where-Object { $_.Name -eq 'DKIMEnabled' -and $_.Status -eq 'Pending' }).Count | Should -Be 1
        }
        It 'returns pending on bounded DNS polling expiry' {
            $script:brokenName = '_dmarc.example.com'
            $script:failureMode = 'Absent'
            Wait-PublicDns $ctx $plans 0 1 | Should -BeFalse
            Should -Invoke Start-Sleep -Times 0
        }
    }
}

Describe 'End-to-end workflow with mocked external services' {
    InModuleScope M365DomainAuthentication {
        BeforeEach {
            $script:records = [Collections.Generic.List[object]]::new()
            $script:records.Add((New-TestRecord '@' NS 'ns1.domaincontrol.com'))
            $script:records.Add((New-TestRecord '@' NS 'ns2.domaincontrol.com'))
            $script:records.Add((New-TestRecord '@' TXT 'v=spf1 include:spf.protection.outlook.com -all'))
            $script:mailboxes = @{}
            $script:events = [Collections.Generic.List[string]]::new()
            $script:connectionReads = 0
            $script:config = $null
            $script:dnsBroken = ''
            $script:invokeParameters = @{
                Domain = 'example.com'; AdminUserPrincipalName = 'admin@tenant.onmicrosoft.com'
                GoDaddyToken = (ConvertTo-SecureString 'test-token' -AsPlainText -Force)
                ReportDirectory = (Join-Path $TestDrive 'reports')
            }
            Mock Import-Module {} -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
            Mock Connect-ExchangeOnline {}
            Mock Get-ConnectionInformation {
                $script:connectionReads++
                [pscustomobject]@{ ConnectionId = 'existing'; TenantID = 'other-tenant' }
                if ($script:connectionReads -gt 1) { [pscustomobject]@{ ConnectionId = 'owned'; TenantID = 'test-tenant' } }
            }
            Mock Disconnect-ExchangeOnline {}
            Mock Get-AcceptedDomain { [pscustomobject]@{ DomainName = 'example.com' } }
            Mock Get-DkimSigningConfig { $script:config }
            Mock New-DkimSigningConfig {
                $script:events.Add('CreateDisabledDkim')
                $script:config = [pscustomobject]@{
                    Domain = 'example.com'; Enabled = $false; Status = 'CnameMissing'
                    Selector1CNAME = 'selector1-example-com._domainkey.tenant.r-v1.dkim.mail.microsoft'
                    Selector2CNAME = 'selector2-example-com._domainkey.tenant.onmicrosoft.com'
                }
            }
            Mock Set-DkimSigningConfig {
                $script:events.Add('EnableDkim')
                $script:config.Enabled = $true
                $script:config.Status = 'Valid'
            }
            Mock Get-EXORecipient {
                $address = [regex]::Match($Filter, "smtp:([^']+)").Groups[1].Value
                $script:events.Add("Recipient:$address")
                if ($script:mailboxes.ContainsKey($address)) { $script:mailboxes[$address] }
            }
            Mock Get-EXOMailbox {
                $address = [regex]::Match($Filter, "smtp:([^']+)").Groups[1].Value
                $script:events.Add("MailboxReadback:$address")
                if ($script:mailboxes.ContainsKey($address)) { $script:mailboxes[$address] }
            }
            Mock New-Mailbox {
                $script:events.Add("CreateMailbox:$PrimarySmtpAddress")
                $script:mailboxes[$PrimarySmtpAddress] = New-TestMailbox $PrimarySmtpAddress
                $script:mailboxes[$PrimarySmtpAddress]
            }
            Mock Invoke-RestMethod {
                if ($Uri -notlike 'https://api.godaddy.com/v3/domains/zones/example.com/dns-records*') { throw 'Unexpected API origin or route' }
                if ($Headers.Authorization -ne 'Bearer test-token') { throw 'Wrong authentication' }
                if ($Method -eq 'GET') { return @{ items = @($script:records.ToArray()); totalPages = 1 } }
                if ($Method -eq 'POST') {
                    $record = $Body | ConvertFrom-Json
                    $record | Add-Member NoteProperty recordId ([guid]::NewGuid().ToString())
                    $script:records.Add($record)
                    $script:events.Add("Publish:$($record.type):$($record.name)")
                    return $record
                }
                throw "Unexpected mutating method $Method"
            }
            Mock Get-DnsAnswer {
                if ($Name -eq $script:dnsBroken) { throw 'DNS lookup failed' }
                if ($Type -eq 'NS') {
                    if ($Name -eq 'example.com') {
                        [pscustomobject]@{ Name = $Name; Type = 'NS'; NameHost = 'ns1.domaincontrol.com' }
                        [pscustomobject]@{ Name = $Name; Type = 'NS'; NameHost = 'ns2.domaincontrol.com' }
                    }
                    return
                }
                if ($Name -like '*._domainkey.tenant*') {
                    [pscustomobject]@{ Name = $Name; Type = 'TXT'; Strings = @($script:testKey) }
                    return
                }
                $relative = $Name -replace '\.example\.com$', ''
                foreach ($record in @($script:records | Where-Object { $_.name -eq $relative -and $_.type -eq $Type })) {
                    $script:events.Add("PublicDNS:$($record.name):$Server")
                    if ($Type -eq 'CNAME') { [pscustomobject]@{ Name = $Name; Type = 'CNAME'; NameHost = $record.data } }
                    else { [pscustomobject]@{ Name = $Name; Type = 'TXT'; Strings = @($record.data.Substring(0, 5), $record.data.Substring(5)) } }
                }
            }
            Mock Start-Sleep {}
        }
        It 'previews missing configuration and mailboxes with zero writes' {
            $result = Invoke-M365DomainAuthentication @script:invokeParameters
            $result.State | Should -Be 'Preview'
            Should -Invoke New-Mailbox -Times 0
            Should -Invoke New-DkimSigningConfig -Times 0
            Should -Invoke Set-DkimSigningConfig -Times 0
            Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { $Method -ne 'GET' }
            Test-Path $script:invokeParameters.ReportDirectory | Should -BeFalse
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -ParameterFilter { $ConnectionId -eq 'owned' }
            Should -Invoke Disconnect-ExchangeOnline -Times 0 -ParameterFilter { $ConnectionId -eq 'existing' }
        }
        It 'supports a caller-owned Exchange connection without prompts or disconnects' {
            $parameters = $script:invokeParameters.Clone()
            $parameters.Remove('AdminUserPrincipalName')
            $result = Invoke-M365DomainAuthentication @parameters `
                -ExchangeConnectionId existing -NonInteractive
            $result.State | Should -Be 'Preview'
            $result.Operation | Should -Be 'Preview'
            $result.Tenant | Should -Be 'other-tenant'
            Should -Invoke Connect-ExchangeOnline -Times 0
            Should -Invoke Disconnect-ExchangeOnline -Times 0
        }
        It 'rejects interactive replacement and missing credentials in runner mode' {
            $parameters = $script:invokeParameters.Clone()
            $parameters.Remove('AdminUserPrincipalName')
            $parameters.Remove('GoDaddyToken')
            $result = Invoke-M365DomainAuthentication @parameters `
                -ExchangeConnectionId existing -NonInteractive
            $result.State | Should -Be 'Failed'
            $result.Error | Should -Match 'requires GoDaddyToken'

            $result = Invoke-M365DomainAuthentication @parameters `
                -GoDaddyToken $script:invokeParameters.GoDaddyToken `
                -ExchangeConnectionId existing -NonInteractive -ReplaceConflictingRecords
            $result.State | Should -Be 'Failed'
            $result.Error | Should -Match 'cannot be requested'
            Should -Invoke Invoke-RestMethod -Times 0
        }
        It 'rejects ambiguous caller-owned Exchange connections' {
            Mock Get-ConnectionInformation {
                [pscustomobject]@{ ConnectionId = 'existing'; TenantID = 'other-tenant' }
                [pscustomobject]@{ ConnectionId = 'extra'; TenantID = 'wrong-tenant' }
            }
            $parameters = $script:invokeParameters.Clone()
            $parameters.Remove('AdminUserPrincipalName')
            $result = Invoke-M365DomainAuthentication @parameters `
                -ExchangeConnectionId existing -NonInteractive
            $result.State | Should -Be 'Failed'
            $result.Error | Should -Match 'only active Exchange connection'
            Should -Invoke Get-AcceptedDomain -Times 0
            Should -Invoke Disconnect-ExchangeOnline -Times 0
        }
        It 'creates and disconnects only the external runner Exchange connection' {
            $variable = 'EXTERNAL_TEST_GODADDY_PAT'
            [Environment]::SetEnvironmentVariable($variable, 'test-token', 'Process')
            $script:runnerConnectionReads = 0
            Mock Get-ConnectionInformation {
                $script:runnerConnectionReads++
                if ($script:runnerConnectionReads -gt 1) {
                    [pscustomobject]@{ ConnectionId = 'runner-owned'; TenantID = 'test-tenant' }
                }
            }
            Mock Read-Host { throw 'Runner must not prompt' }
            try {
                $result = Invoke-M365DomainAuthenticationRunner -Domain example.com `
                    -Operation Apply -ExchangeOrganization tenant.onmicrosoft.com `
                    -ExchangeApplicationId 'app-id' -ExchangeCertificateThumbprint 'thumbprint' `
                    -GoDaddyTokenEnvironmentVariable $variable
                $result.State | Should -Be 'Completed'
                $result.Operation | Should -Be 'Apply'
                $result.Tenant | Should -Be 'test-tenant'
                Should -Invoke New-Mailbox -Times 2
                Should -Invoke Set-DkimSigningConfig -Times 1
                Should -Invoke Connect-ExchangeOnline -Times 1 -ParameterFilter {
                    $AppId -eq 'app-id' -and $CertificateThumbprint -eq 'thumbprint' -and
                    $Organization -eq 'tenant.onmicrosoft.com'
                }
                Should -Invoke Disconnect-ExchangeOnline -Times 1 -ParameterFilter {
                    $ConnectionId -eq 'runner-owned'
                }
                Should -Invoke Read-Host -Times 0
            }
            finally {
                [Environment]::SetEnvironmentVariable($variable, $null, 'Process')
            }
        }
        It 'persists structured runner failures without exposing the secret variable' {
            $resultFile = Join-Path $TestDrive 'runner-error.json'
            Mock Get-ConnectionInformation {}
            $result = Invoke-M365DomainAuthenticationRunner -Domain example.com `
                -Operation Preview -ExchangeOrganization tenant.onmicrosoft.com `
                -ExchangeApplicationId 'app-id' -ExchangeCertificateThumbprint 'thumbprint' `
                -GoDaddyTokenEnvironmentVariable EXTERNAL_MISSING_TEST_PAT `
                -ResultFile $resultFile
            $result.State | Should -Be 'Failed'
            $result.Operation | Should -Be 'Preview'
            $result.Error | Should -Match 'missing or empty'
            $result.ResultFile | Should -Be $resultFile
            $persisted = Get-Content -LiteralPath $resultFile -Raw
            $persisted | Should -Not -Match 'test-token'
            ($persisted | ConvertFrom-Json).State | Should -Be 'Failed'
            $schema = Get-Content (Join-Path $PSScriptRoot '..\external-runner-result.schema.json') -Raw
            Test-Json -Json $persisted -Schema $schema | Should -BeTrue
            Should -Invoke Connect-ExchangeOnline -Times 0
        }
        It 'requires an explicit runner operation' {
            (Get-Command Invoke-M365DomainAuthenticationRunner).Parameters.Operation.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Contain $true
        }
        It 'validates the external runner request schema without accepting plaintext secrets' {
            $schema = Get-Content (Join-Path $PSScriptRoot '..\external-runner-request.schema.json') -Raw
            $valid = @{
                domain = 'example.com'; operation = 'Preview'
                exchangeOrganization = 'tenant.onmicrosoft.com'
                exchangeApplicationId = 'app-id'
                exchangeCertificateThumbprint = 'thumbprint'
            } | ConvertTo-Json -Compress
            Test-Json -Json $valid -Schema $schema | Should -BeTrue
            $secretBearing = $valid |
                ConvertFrom-Json -AsHashtable
            $secretBearing.goDaddyToken = 'must-not-be-json'
            { Test-Json -Json ($secretBearing | ConvertTo-Json -Compress) -Schema $schema -ErrorAction Stop } |
                Should -Throw
        }
        It 'keeps Apply WhatIf read-only, including mailbox creation' {
            $result = Invoke-M365DomainAuthentication @script:invokeParameters -Apply -WhatIf
            $result.State | Should -Be 'Preview'
            Should -Invoke New-Mailbox -Times 0
            Should -Invoke New-DkimSigningConfig -Times 0
            Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { $Method -ne 'GET' }
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -ParameterFilter { $ConnectionId -eq 'owned' -and -not $WhatIf }
        }
        It 'creates mailboxes, verifies addresses, publishes DNS, and only then enables DKIM' {
            $result = Invoke-M365DomainAuthentication @script:invokeParameters -Apply
            $result.Error | Should -BeNullOrEmpty
            $result.State | Should -Be 'Completed'
            Should -Invoke New-Mailbox -Times 2 -ParameterFilter { $Shared }
            Should -Invoke New-DkimSigningConfig -Times 1 -ParameterFilter { $Enabled -eq $false }
            Should -Invoke Set-DkimSigningConfig -Times 1 -ParameterFilter { $Enabled -eq $true }
            $publish = $script:events.IndexOf('Publish:TXT:_dmarc')
            $script:events.IndexOf('MailboxReadback:dmarc-rua@example.com') | Should -BeLessThan $publish
            $script:events.IndexOf('MailboxReadback:dmarc-ruf@example.com') | Should -BeLessThan $publish
            $script:events.IndexOf('PublicDNS:_dmarc:8.8.8.8') | Should -BeLessThan $script:events.IndexOf('EnableDkim')
            $script:events.IndexOf('PublicDNS:selector2._domainkey:8.8.8.8') | Should -BeLessThan $script:events.IndexOf('EnableDkim')
            Test-Path (Join-Path $result.RunDirectory 'dns-before.json') | Should -BeTrue
            (Get-Content (Join-Path $result.RunDirectory 'result.json') -Raw) | Should -Not -Match 'test-token'
        }
        It 'is idempotent on a second invocation' {
            (Invoke-M365DomainAuthentication @script:invokeParameters -Apply).State | Should -Be 'Completed'
            $script:connectionReads = 0
            (Invoke-M365DomainAuthentication @script:invokeParameters -Apply).State | Should -Be 'Completed'
            Should -Invoke New-Mailbox -Times 2
            Should -Invoke New-DkimSigningConfig -Times 1
            Should -Invoke Invoke-RestMethod -Times 3 -ParameterFilter { $Method -eq 'POST' }
            Should -Invoke Set-DkimSigningConfig -Times 1
        }
        It 'creates only the missing mailbox when the other already exists' {
            $script:mailboxes['dmarc-rua@example.com'] = New-TestMailbox 'dmarc-rua@example.com'
            (Invoke-M365DomainAuthentication @script:invokeParameters -Apply).State | Should -Be 'Completed'
            Should -Invoke New-Mailbox -Times 1 -ParameterFilter { $PrimarySmtpAddress -eq 'dmarc-ruf@example.com' }
        }
        It 'blocks all mutations for an unaccepted domain' {
            Mock Get-AcceptedDomain { [pscustomobject]@{ DomainName = 'different.test' } }
            (Invoke-M365DomainAuthentication @script:invokeParameters -Apply).State | Should -Be 'Failed'
            Should -Invoke New-Mailbox -Times 0
            Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { $Method -ne 'GET' }
        }
        It 'rejects derived names exceeding DNS limits before any service call' {
            $script:invokeParameters.Domain = (('a' * 63), ('b' * 63), ('c' * 63), ('d' * 45), 'com') -join '.'
            $result = Invoke-M365DomainAuthentication @script:invokeParameters -Apply
            $result.State | Should -Be 'Failed'
            $result.Error | Should -Match 'too long'
            Should -Invoke Invoke-RestMethod -Times 0
            Should -Invoke Connect-ExchangeOnline -Times 0
        }
        It 'blocks all mutations on a GoDaddy access failure and redacts the token' {
            Mock Invoke-RestMethod { throw 'Access denied test-token' }
            $result = Invoke-M365DomainAuthentication @script:invokeParameters -Apply
            $result.State | Should -Be 'Failed'
            $result.Error | Should -Not -Match 'test-token'
            Should -Invoke Connect-ExchangeOnline -Times 0
            Should -Invoke New-Mailbox -Times 0
        }
        It 'blocks all mutations on failed public delegation checks' {
            $script:dnsBroken = 'example.com'
            (Invoke-M365DomainAuthentication @script:invokeParameters -Apply).State | Should -Be 'Failed'
            Should -Invoke New-Mailbox -Times 0
            Should -Invoke Set-DkimSigningConfig -Times 0
        }
        It 'blocks all mutations when a child DNS zone is delegated elsewhere' {
            Mock Get-DnsAnswer {
                if ($Name -in 'example.com', '_domainkey.example.com') {
                    [pscustomobject]@{ Name = $Name; Type = 'NS'; NameHost = 'ns1.domaincontrol.com' }
                    [pscustomobject]@{ Name = $Name; Type = 'NS'; NameHost = 'ns2.domaincontrol.com' }
                }
            }
            $result = Invoke-M365DomainAuthentication @script:invokeParameters -Apply
            $result.State | Should -Be 'Failed'
            $result.Error | Should -Match 'Child-zone delegation'
            Should -Invoke New-Mailbox -Times 0
        }
        It 'preserves existing differing DMARC without override or any mutation' {
            $script:records.Add((New-TestRecord '_dmarc' TXT 'v=DMARC1; p=reject; rua=mailto:old@example.com'))
            (Invoke-M365DomainAuthentication @script:invokeParameters -Apply).State | Should -Be 'Conflict'
            Should -Invoke New-Mailbox -Times 0
            Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { $Method -ne 'GET' }
        }
        It 'does not publish DMARC if a mailbox create succeeds but readback is not ready' {
            Mock Ensure-ReportingMailboxes {
                $null = New-Mailbox -Shared -PrimarySmtpAddress 'dmarc-rua@example.com'
                return $false
            }
            (Invoke-M365DomainAuthentication @script:invokeParameters -Apply).State | Should -Be 'Pending'
            Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { $Method -ne 'GET' }
            Should -Invoke Set-DkimSigningConfig -Times 0
        }
        It 'does not enable DKIM when publication health times out despite successful provider writes' {
            Mock Wait-PublicDns { $false }
            $result = Invoke-M365DomainAuthentication @script:invokeParameters -Apply
            $result.State | Should -Be 'Pending'
            Should -Invoke Invoke-RestMethod -Times 3 -ParameterFilter { $Method -eq 'POST' }
            Should -Invoke Set-DkimSigningConfig -Times 0
        }
        It 'reports final Exchange-state failure without claiming completion' {
            Mock Enable-VerifiedDkim { $false }
            (Invoke-M365DomainAuthentication @script:invokeParameters -Apply).State | Should -Be 'Pending'
        }
        It 'never changes SPF or any unrelated zone data' {
            $script:records.Add((New-TestRecord 'www' A '192.0.2.1'))
            (Invoke-M365DomainAuthentication @script:invokeParameters -Apply).State | Should -Be 'Completed'
            @($script:records | Where-Object name -EQ 'www').Count | Should -Be 1
            Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { $Method -ne 'GET' -and $Body -match '"name":"(@|www)"' }
        }
    }
}
