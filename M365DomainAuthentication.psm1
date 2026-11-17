#requires -Version 7.2

function ConvertTo-DomainName {
    param([string]$Value, [switch]$AllowServiceLabels)
    $name = $Value.Trim().TrimEnd('.').ToLowerInvariant()
    $label = if ($AllowServiceLabels) { '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?' } else { '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?' }
    if ($name.Length -gt 253 -or $name -notmatch "^(?:$label\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$") {
        throw "Invalid DNS domain '$Value'. Use an ASCII/punycode fully qualified domain name."
    }
    return $name
}

function ConvertTo-HostValue {
    param([string]$Value)
    return $Value.Trim().TrimEnd('.').ToLowerInvariant()
}

function Add-Health {
    param($Context, [string]$Name, [string]$Status, [string]$Source, $Expected, $Observed, [string]$Detail = '')
    $Context.Health.Add([pscustomobject]@{
        Name = $Name; Status = $Status; Source = $Source
        Expected = $Expected; Observed = $Observed; Detail = $Detail; CheckedAtUtc = [DateTime]::UtcNow.ToString('o')
    })
}

function Invoke-GoDaddy {
    param($Context, [ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method, [string]$Path, $Body)
    if ($Path -notmatch '^/zones/' -or $Path.Contains('..')) { throw 'Invalid DNS API path.' }
    $headers = @{ Authorization = "Bearer $($Context.Token)" }
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        try {
            $parameters = @{
                Uri = "https://api.godaddy.com/v3/domains$Path"
                Method = $Method; Headers = $headers; ErrorAction = 'Stop'
                TimeoutSec = 30; MaximumRedirection = 0
            }
            if ($null -ne $Body) {
                $parameters.Body = ConvertTo-Json -InputObject $Body -Depth 8 -Compress
                $parameters.ContentType = 'application/json'
            }
            return Invoke-RestMethod @parameters
        }
        catch {
            $code = 0
            if ($null -ne $_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            $providerCode = 'unavailable'
            if ($_.ErrorDetails.Message -cmatch '"code"\s*:\s*"([A-Z][A-Z0-9_]{0,79})"') { $providerCode = $Matches[1] }
            if ($Method -eq 'GET' -and ($code -eq 429 -or $code -ge 500) -and $attempt -lt 2) {
                $delay = 2 * ($attempt + 1)
                $retryHeader = $_.Exception.Response.Headers.RetryAfter
                if ($null -ne $retryHeader.Delta) {
                    $delay = [Math]::Max($delay, $retryHeader.Delta.TotalSeconds)
                }
                elseif ($null -ne $retryHeader.Date) {
                    $delay = [Math]::Max($delay, ($retryHeader.Date - [DateTimeOffset]::UtcNow).TotalSeconds)
                }
                if ($delay -gt 60) { throw 'GoDaddy requests a retry delay longer than 60 seconds. Stop and rerun after the provider Retry-After period.' }
                Start-Sleep -Seconds $delay
                continue
            }
            $reason = switch ($code) {
                401 { 'Authentication refused. Check the GoDaddy PAT and expiry.' }
                403 { 'Access refused. Check PAT scopes and account DNS API eligibility.' }
                404 { 'DNS zone or record not found. Check account ownership and DNS hosting.' }
                429 { 'Rate limit reached. Wait before rerunning.' }
                default { 'Request failed. For a write, its outcome may be uncertain; inspect readback and the saved snapshot.' }
            }
            # Do not expose HTTP exception text or headers, which can contain credentials.
            throw "GoDaddy $Method failed (HTTP $code, code $providerCode). $reason"
        }
    }
}

function Get-ZoneRecords {
    param($Context)
    $records = [Collections.Generic.List[object]]::new()
    for ($page = 1; $page -le 10000; $page++) {
        $response = Invoke-GoDaddy $Context GET "$($Context.ZonePath)/dns-records?page=$page&pageSize=100&totalRequired=true"
        if ($null -eq $response -or $null -eq $response.items -or $null -eq $response.totalPages) {
            throw 'Unexpected GoDaddy DNS pagination response; refusing to treat it as an empty zone.'
        }
        foreach ($record in $response.items) {
            if (-not $record.recordId -or -not $record.name -or -not $record.type -or $null -eq $record.data) {
                throw 'Incomplete GoDaddy DNS record response.'
            }
            $records.Add($record)
        }
        if ($page -ge [int]$response.totalPages) { return $records.ToArray() }
    }
    throw 'GoDaddy pagination exceeded its safety bound.'
}

function Get-DnsAnswer {
    param([string]$Name, [string]$Type, [string]$Server)
    Resolve-DnsName -Name $Name -Type $Type -Server $Server -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop
}

function Get-AuthoritativeServers {
    param($Context, [object[]]$Records)
    $expected = @($Records | Where-Object { $_.type -eq 'NS' -and $_.name -eq '@' } |
        ForEach-Object { ConvertTo-HostValue $_.data } | Sort-Object -Unique)
    if ($expected.Count -eq 0 -or @($expected | Where-Object { $_ -notmatch '\.domaincontrol\.com$' }).Count -gt 0) {
        throw 'Zone does not advertise GoDaddy authoritative nameservers; DNS delegation requires manual review.'
    }
    foreach ($resolver in $Context.Resolvers) {
        $actual = @(Get-DnsAnswer $Context.Zone NS $resolver |
            Where-Object { $_.Type -eq 'NS' -and (ConvertTo-HostValue $_.Name) -eq $Context.Zone } |
            ForEach-Object { ConvertTo-HostValue $_.NameHost } | Sort-Object -Unique)
        if (($actual -join ',') -ne ($expected -join ',')) {
            throw "Public NS delegation for $($Context.Zone) differs from GoDaddy ($resolver)."
        }
        foreach ($owner in @("selector1._domainkey.$($Context.Domain)", "selector2._domainkey.$($Context.Domain)", "_dmarc.$($Context.Domain)")) {
            $candidate = $owner
            while ($candidate -ne $Context.Zone) {
                try {
                    $delegated = @(Get-DnsAnswer $candidate NS $resolver |
                        Where-Object { $_.Type -eq 'NS' -and (ConvertTo-HostValue $_.Name) -eq $candidate })
                    if ($delegated.Count -gt 0) { throw "Child-zone delegation at $candidate requires a different DnsZone or manual resolution." }
                }
                catch {
                    # These negative answers establish no delegation at this label; timeouts/SERVFAIL do not.
                    if ($_.FullyQualifiedErrorId -notmatch 'DNS_INFO_NO_RECORDS|DNS_ERROR_RCODE_NAME_ERROR') { throw }
                }
                $candidate = $candidate.Substring($candidate.IndexOf('.') + 1)
            }
        }
    }
    Add-Health $Context 'Delegation' Pass 'Public DNS' $expected $expected
    return $expected
}

function Get-RelativeName {
    param($Context, [string]$Prefix)
    if ($Context.Domain -eq $Context.Zone) { return $Prefix }
    return "$Prefix.$($Context.Domain.Substring(0, $Context.Domain.Length - $Context.Zone.Length - 1))"
}

function Get-RecipientState {
    param([string]$Address)
    if ($Address -notmatch '^[a-zA-Z0-9.!#$%&*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+$') {
        throw "Invalid reporting address '$Address'."
    }
    $escaped = $Address.Replace("'", "''")
    $recipients = @(Get-EXORecipient -Filter "EmailAddresses -eq 'smtp:$escaped'" -IncludeSoftDeletedRecipients `
        -Properties EmailAddresses, WhenSoftDeleted -ResultSize Unlimited -ErrorAction Stop)
    if ($recipients.Count -eq 0) { return [pscustomobject]@{ State = 'Missing'; Address = $Address; Identity = $null } }
    if ($recipients.Count -ne 1) { return [pscustomobject]@{ State = 'Conflict'; Address = $Address; Identity = $null } }
    $recipient = $recipients[0]
    if ($recipient.WhenSoftDeleted -or $recipient.RecipientTypeDetails -notin 'UserMailbox', 'SharedMailbox') {
        return [pscustomobject]@{ State = 'Conflict'; Address = $Address; Identity = $recipient.Identity }
    }
    $mailboxes = @(Get-EXOMailbox -Filter "EmailAddresses -eq 'smtp:$escaped'" -Properties EmailAddresses `
        -ResultSize Unlimited -ErrorAction Stop)
    if ($mailboxes.Count -ne 1 -or $mailboxes[0].RecipientTypeDetails -notin 'UserMailbox', 'SharedMailbox' -or
        -not $recipient.ExternalDirectoryObjectId -or
        $mailboxes[0].ExternalDirectoryObjectId -ne $recipient.ExternalDirectoryObjectId -or
        @($mailboxes[0].EmailAddresses | Where-Object { "$_" -ieq "smtp:$Address" }).Count -ne 1) {
        return [pscustomobject]@{ State = 'Pending'; Address = $Address; Identity = $recipient.Identity }
    }
    return [pscustomobject]@{ State = 'Ready'; Address = $Address; Identity = $mailboxes[0].ExternalDirectoryObjectId }
}

function Get-DmarcTags {
    param([string]$Value)
    $tags = [ordered]@{}
    foreach ($part in $Value.Split(';')) {
        if (-not $part.Trim()) { continue }
        if ($part -notmatch '^\s*([a-z][a-z0-9]*)\s*=\s*(.+?)\s*$') { throw 'Malformed DMARC tag.' }
        $key = $Matches[1].ToLowerInvariant()
        if ($tags.Contains($key)) { throw "Duplicate DMARC tag '$key'." }
        $tags[$key] = $Matches[2]
    }
    if (@($tags.Keys)[0] -ne 'v' -or $tags.v -cne 'DMARC1' -or $tags.p -cnotin 'none', 'quarantine', 'reject') {
        throw 'DMARC requires a leading v=DMARC1 and a valid p tag.'
    }
    foreach ($key in 'sp', 'np') {
        if ($tags.Contains($key) -and $tags[$key] -cnotin 'none', 'quarantine', 'reject') { throw "Invalid DMARC $key." }
    }
    foreach ($key in 'adkim', 'aspf') {
        if ($tags.Contains($key) -and $tags[$key] -cnotin 'r', 's') { throw "Invalid DMARC $key." }
    }
    if ($tags.Contains('pct') -and ($tags.pct -notmatch '^\d{1,3}$' -or [int]$tags.pct -gt 100)) { throw 'Invalid DMARC pct.' }
    return ,$tags
}

function Get-ReportAddresses {
    param($Tags)
    foreach ($key in 'rua', 'ruf') {
        if (-not $Tags.Contains($key)) { continue }
        foreach ($uri in $Tags[$key].Split(',')) {
            if ($uri.Trim() -notmatch '^mailto:([^!\s,;]+@[^!\s,;]+)(?:!\d+[kmgt]?)?$') {
                throw "Unsupported or malformed DMARC $key URI; manual review required."
            }
            $address = $Matches[1].ToLowerInvariant()
            $mail = [System.Net.Mail.MailAddress]::new($address)
            if ($mail.Address -ne $address) { throw 'Invalid DMARC report address.' }
            $address
        }
    }
}

function ConvertFrom-ProviderTxt {
    param([string]$Value)
    if ($Value.StartsWith('"')) {
        if ($Value -notmatch '^(?:"[^"\\]*"\s*)+$') { throw 'Unsupported quoted TXT encoding; manual review required.' }
        return ([regex]::Matches($Value, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value }) -join ''
    }
    return $Value
}

function Get-DmarcPlan {
    param($Context, [object[]]$Records)
    $name = Get-RelativeName $Context '_dmarc'
    $atName = @($Records | Where-Object { $_.name -ieq $name })
    $policies = @($atName | Where-Object { $_.type -eq 'TXT' -and (ConvertFrom-ProviderTxt $_.data) -match '^\s*v\s*=\s*DMARC1' })
    $tags = $null
    $invalid = $false
    if ($policies.Count -eq 1) {
        try { $tags = Get-DmarcTags (ConvertFrom-ProviderTxt $policies[0].data) }
        catch { $invalid = $true }
    }
    elseif ($policies.Count -gt 1) { $invalid = $true }
    $newPolicy = 'v=DMARC1; p=none; rua=mailto:{0}; ruf=mailto:{1}' -f $Context.Addresses[0], $Context.Addresses[1]
    $desired = $newPolicy
    $changed = $true
    if ($null -ne $tags) {
        $desired = ConvertFrom-ProviderTxt $policies[0].data
        $changed = $tags.rua -cne "mailto:$($Context.Addresses[0])" -or $tags.ruf -cne "mailto:$($Context.Addresses[1])"
        foreach ($address in @(Get-ReportAddresses $tags)) {
            $addressDomain = ($address -split '@')[1]
            if ($addressDomain -notin $Context.AcceptedDomains) {
                Add-Health $Context "ExistingReportAddress:$address" NotVerifiable 'Exchange Online' 'Tenant-local mailbox' 'External destination'
            }
            else {
                $state = Get-RecipientState $address
                Add-Health $Context "ExistingReportAddress:$address" $(if ($state.State -eq 'Ready') { 'Pass' } else { 'Fail' }) 'Exchange Online' 'Ready' $state.State
            }
        }
        if ($changed -and $Context.Replace) {
            $tags.rua = "mailto:$($Context.Addresses[0])"
            $tags.ruf = "mailto:$($Context.Addresses[1])"
            $desired = ($tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
        }
    }
    if ($invalid) {
        $Context.Conflicts.Add('Malformed or multiple DMARC policies require manual resolution; refusing to replace an unknown enforcement policy with p=none.')
    }
    if ($changed -and $null -ne $tags -and -not $Context.Replace) {
        $Context.Conflicts.Add('Existing DMARC reporting destinations differ. Preserved; use ReplaceConflictingRecords and confirm to update reporting tags only.')
    }
    # Unrelated TXT records are not part of this replacement set.
    $managed = @($atName | Where-Object { $_.type -eq 'CNAME' -or $_ -in $policies })
    return [pscustomobject]@{ Name = $name; Type = 'TXT'; Data = $desired; Existing = $managed }
}

function Get-RecordPlan {
    param($Context, [object[]]$Records, $Dkim)
    $plans = [Collections.Generic.List[object]]::new()
    $plans.Add((Get-DmarcPlan $Context $Records))
    if ($null -ne $Dkim) {
        foreach ($index in 1, 2) {
            $target = $Dkim."Selector${index}CNAME"
            if (-not $target) { throw "Microsoft returned an empty selector$index target." }
            $target = ConvertTo-DomainName $target -AllowServiceLabels
            $name = Get-RelativeName $Context "selector$index._domainkey"
            $existing = @($Records | Where-Object { $_.name -ieq $name })
            if (@($existing | Where-Object type -In 'NS', 'SOA').Count -gt 0) {
                $Context.Conflicts.Add("Delegation/protected record at $name requires manual resolution.")
            }
            $plans.Add([pscustomobject]@{ Name = $name; Type = 'CNAME'; Data = $target; Existing = $existing })
        }
    }
    foreach ($plan in $plans) {
        $same = $plan.Existing.Count -eq 1 -and (Test-RecordValue $plan.Existing[0] $plan)
        $action = if ($same) { 'Keep' } elseif ($plan.Existing.Count -eq 0) { 'Create' } else { 'Replace' }
        $plan | Add-Member NoteProperty Action $action
        if ($action -eq 'Replace' -and -not $Context.Replace) { $Context.Conflicts.Add("Conflicting DNS record at $($plan.Name).") }
        $Context.Actions.Add([pscustomobject]@{ Action = $action; Name = $plan.Name; Type = $plan.Type; Data = $plan.Data; Before = $plan.Existing })
    }
    return $plans.ToArray()
}

function Test-RecordValue {
    param($Record, $Plan)
    if ($Record.type -ne $Plan.Type) { return $false }
    if ($Plan.Type -eq 'CNAME') { return (ConvertTo-HostValue $Record.data) -eq (ConvertTo-HostValue $Plan.Data) }
    return (ConvertFrom-ProviderTxt $Record.data) -ceq $Plan.Data
}

function Get-RecordFingerprint {
    param([object[]]$Records)
    return (@($Records | Sort-Object recordId | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}' -f $_.recordId, $_.name, $_.type, $_.data, $_.ttl
    }) -join "`n")
}

function Assert-ReportAddresses {
    param($Context, [string]$Policy)
    $tags = Get-DmarcTags $Policy
    $addresses = @(Get-ReportAddresses $tags | Sort-Object -Unique)
    if (-not $tags.rua -or -not $tags.ruf -or $addresses.Count -eq 0) { throw 'Both RUA and RUF destinations are required for DMARC publication.' }
    foreach ($address in $addresses) {
        if (($address -split '@')[1] -notin $Context.AcceptedDomains) {
            Add-Health $Context "ReportAddress:$address" NotVerifiable 'Exchange Online' 'Verified mailbox' 'External'
            throw "Cannot verify external reporting mailbox $address; DMARC write blocked."
        }
        $state = Get-RecipientState $address
        Add-Health $Context "ReportAddress:$address" $(if ($state.State -eq 'Ready') { 'Pass' } else { 'Fail' }) 'Exchange Online' 'Ready' $state.State
        if ($state.State -ne 'Ready') { throw "Reporting mailbox $address is $($state.State); DMARC write blocked." }
    }
}

function Ensure-ReportingMailboxes {
    param($Context, [int]$TimeoutMinutes, [int]$PollSeconds)
    foreach ($address in $Context.Addresses) {
        $state = Get-RecipientState $address
        if ($state.State -eq 'Conflict') { throw "Recipient collision at $address." }
        if ($state.State -eq 'Missing') {
            $prefix = ($address -split '@')[0]
            $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($address))).Substring(0, 12).ToLowerInvariant()
            $name = "$prefix-$hash"
            try {
                $created = New-Mailbox -Shared -Name $name -Alias $name -DisplayName "$prefix reports ($($Context.Domain))" `
                    -PrimarySmtpAddress $address -ErrorAction Stop
                $Context.Changes.Add([pscustomobject]@{ Action = 'CreateSharedMailbox'; Address = $address; Identity = "$($created.Identity)" })
            }
            catch {
                $after = Get-RecipientState $address
                if ($after.State -ne 'Ready') { throw "Shared mailbox creation failed or is uncertain for $address. Inspect the tenant before rerunning." }
                $Context.Changes.Add([pscustomobject]@{ Action = 'MailboxObservedAfterUncertainCreate'; Address = $address; Identity = $after.Identity })
            }
        }
    }
    $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
    do {
        $ready = $true
        foreach ($address in $Context.Addresses) {
            $state = Get-RecipientState $address
            Add-Health $Context "Mailbox:$address" $(if ($state.State -eq 'Ready') { 'Pass' } else { 'Pending' }) 'Exchange Online readback' 'Ready' $state.State
            if ($state.State -eq 'Conflict') { throw "Recipient collision at $address." }
            if ($state.State -ne 'Ready') { $ready = $false }
        }
        if ($ready) { return $true }
        if ([DateTime]::UtcNow -ge $deadline) { return $false }
        Start-Sleep -Seconds $PollSeconds
    } while ($true)
}

function Set-PlannedRecord {
    param($Context, $Plan)
    if ($Plan.Action -eq 'Keep') { return }
    $current = @(Get-ZoneRecords $Context | Where-Object { $_.name -ieq $Plan.Name })
    $original = @($Context.OriginalRecords | Where-Object { $_.name -ieq $Plan.Name })
    if ((Get-RecordFingerprint $current) -cne (Get-RecordFingerprint $original)) {
        throw "Concurrent DNS change detected at $($Plan.Name); no further writes allowed."
    }
    if ($Plan.Type -eq 'TXT') { Assert-ReportAddresses $Context $Plan.Data }
    $body = @{ name = $Plan.Name; type = $Plan.Type; data = $Plan.Data; ttl = 600 }
    $existing = @($Plan.Existing)
    if ($existing.Count -gt 0) {
        $first = $existing[0]
        if ($first.type -in 'NS', 'SOA') { throw 'Cannot replace protected DNS records.' }
        # CNAME conflicts must be removed before creating a TXT record at the same owner.
        if ($first.type -eq $Plan.Type) {
            $null = Invoke-GoDaddy $Context PUT "$($Context.ZonePath)/dns-records/$([uri]::EscapeDataString($first.recordId))" $body
            $Context.Changes.Add([pscustomobject]@{ Action = 'ReplaceDns'; Name = $Plan.Name; RecordId = $first.recordId })
            $existing = @($existing | Select-Object -Skip 1)
        }
        foreach ($record in $existing) {
            if ($record.type -in 'NS', 'SOA') { throw 'Cannot delete protected DNS records.' }
            $null = Invoke-GoDaddy $Context DELETE "$($Context.ZonePath)/dns-records/$([uri]::EscapeDataString($record.recordId))"
            $Context.Changes.Add([pscustomobject]@{ Action = 'DeleteConflictingDns'; Name = $Plan.Name; RecordId = $record.recordId })
        }
    }
    if ($Plan.Existing.Count -eq 0 -or $Plan.Existing[0].type -ne $Plan.Type) {
        try {
            $created = Invoke-GoDaddy $Context POST "$($Context.ZonePath)/dns-records" $body
            $Context.Changes.Add([pscustomobject]@{ Action = 'CreateDns'; Name = $Plan.Name; RecordId = $created.recordId })
        }
        catch {
            $observed = @(Get-ZoneRecords $Context | Where-Object { $_.name -ieq $Plan.Name -and (Test-RecordValue $_ $Plan) })
            if ($observed.Count -ne 1) { throw "DNS create outcome uncertain at $($Plan.Name). No POST retry performed; inspect the saved snapshot and zone." }
            $Context.Changes.Add([pscustomobject]@{ Action = 'DnsObservedAfterUncertainCreate'; Name = $Plan.Name; RecordId = $observed[0].recordId })
        }
    }
    $after = @(Get-ZoneRecords $Context | Where-Object { $_.name -ieq $Plan.Name -and $_.type -eq $Plan.Type })
    if ($Plan.Type -eq 'TXT') { $after = @($after | Where-Object { (ConvertFrom-ProviderTxt $_.data) -match '^\s*v\s*=\s*DMARC1' }) }
    if ($after.Count -ne 1 -or -not (Test-RecordValue $after[0] $Plan)) { throw "Provider readback failed at $($Plan.Name)." }
    Add-Health $Context "Provider:$($Plan.Name)" Pass 'GoDaddy readback' $Plan.Data $after[0].data
}

function Test-PublicDns {
    param($Context, [object[]]$Plans)
    $passed = $true
    foreach ($source in @($Context.Authorities) + @($Context.Resolvers)) {
        foreach ($plan in $Plans) {
            $owner = "$($plan.Name).$($Context.Zone)"
            try {
                $answer = @(Get-DnsAnswer $owner $plan.Type $source)
                if ($plan.Type -eq 'CNAME') {
                    $values = @($answer | Where-Object { $_.Type -eq 'CNAME' -and (ConvertTo-HostValue $_.Name) -eq $owner } |
                        ForEach-Object { ConvertTo-HostValue $_.NameHost })
                    $okay = $values.Count -eq 1 -and $values[0] -eq (ConvertTo-HostValue $plan.Data)
                }
                else {
                    $values = @($answer | Where-Object { $_.Type -eq 'TXT' -and (ConvertTo-HostValue $_.Name) -eq $owner } |
                        ForEach-Object { $_.Strings -join '' } | Where-Object { $_ -match '^\s*v\s*=\s*DMARC1' })
                    $okay = $values.Count -eq 1 -and $values[0] -ceq $plan.Data
                    if ($okay) { $null = Get-DmarcTags $values[0] }
                }
                Add-Health $Context "DNS:$owner" $(if ($okay) { 'Pass' } else { 'Pending' }) $source $plan.Data $values
                if (-not $okay) { $passed = $false }
            }
            catch {
                Add-Health $Context "DNS:$owner" Pending $source $plan.Data $null $_.Exception.Message
                $passed = $false
            }
        }
    }
    foreach ($source in $Context.Resolvers) {
        foreach ($plan in @($Plans | Where-Object Type -EQ 'CNAME')) {
            try {
                $keys = @(Get-DnsAnswer $plan.Data TXT $source | Where-Object Type -EQ 'TXT' | ForEach-Object { $_.Strings -join '' })
                $okay = $keys.Count -eq 1 -and (Test-DkimPublicKey $keys[0])
                Add-Health $Context "DKIMKey:$($plan.Data)" $(if ($okay) { 'Pass' } else { 'Pending' }) $source 'Usable RSA DKIM key' $keys
                if (-not $okay) { $passed = $false }
            }
            catch {
                Add-Health $Context "DKIMKey:$($plan.Data)" Pending $source 'Usable RSA DKIM key' $null $_.Exception.Message
                $passed = $false
            }
        }
    }
    if (@($Plans | Where-Object Type -EQ 'CNAME').Count -ne 2) {
        Add-Health $Context 'DKIMSelectors' Pending 'Exchange Online' 'Two discovered selector targets' 'Not yet available'
        $passed = $false
    }
    return $passed
}

function Test-DkimPublicKey {
    param([string]$Value)
    $tags = [ordered]@{}
    foreach ($part in $Value.Split(';')) {
        if (-not $part.Trim()) { continue }
        if ($part -notmatch '^\s*([a-z]+)\s*=\s*(.*?)\s*$') { return $false }
        $keyName = $Matches[1]
        if ($tags.Contains($keyName)) { return $false }
        $tags[$keyName] = $Matches[2]
    }
    if (-not $tags.p -or ($tags.Contains('v') -and ($tags.v -cne 'DKIM1' -or @($tags.Keys)[0] -cne 'v')) -or
        ($tags.Contains('k') -and $tags.k -cne 'rsa')) { return $false }
    $key = $tags.p -replace '\s', ''
    $rsa = [Security.Cryptography.RSA]::Create()
    try {
        $bytes = [Convert]::FromBase64String($key)
        $read = 0
        $rsa.ImportSubjectPublicKeyInfo($bytes, [ref]$read)
        return $read -eq $bytes.Length -and $rsa.KeySize -ge 1024
    }
    catch [FormatException] { return $false }
    catch [Security.Cryptography.CryptographicException] { return $false }
    finally { $rsa.Dispose() }
}

function Wait-PublicDns {
    param($Context, $Plans, [int]$TimeoutMinutes, [int]$PollSeconds)
    $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
    do {
        if (Test-PublicDns $Context $Plans) { return $true }
        if ([DateTime]::UtcNow -ge $deadline) { return $false }
        Start-Sleep -Seconds $PollSeconds
    } while ($true)
}

function Get-DkimConfig {
    param([string]$Domain)
    $configs = @(Get-DkimSigningConfig -ErrorAction Stop | Where-Object { "$($_.Domain)" -ieq $Domain -or "$($_.Identity)" -ieq $Domain -or "$($_.Name)" -ieq $Domain })
    if ($configs.Count -gt 1) { throw 'Multiple Exchange DKIM configurations matched the domain.' }
    if ($configs.Count -eq 1) { return $configs[0] }
    return $null
}

function Enable-VerifiedDkim {
    param($Context, $Plans, [int]$TimeoutMinutes, [int]$PollSeconds)
    $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
    do {
        if (-not (Test-PublicDns $Context $Plans)) { return $false }
        $config = Get-DkimConfig $Context.Domain
        if ($config.Enabled -eq $true -and "$($config.Status)" -eq 'Valid') {
            Add-Health $Context 'DKIMEnabled' Pass 'Exchange Online' 'Enabled, Valid' "$($config.Enabled), $($config.Status)"
            return $true
        }
        if ($config.Enabled -ne $true) {
            try {
                Set-DkimSigningConfig -Identity $Context.Domain -Enabled $true -ErrorAction Stop
                $Context.Changes.Add([pscustomobject]@{ Action = 'EnableDkim'; Domain = $Context.Domain })
            }
            catch {
                if ($_.FullyQualifiedErrorId -notmatch 'ValidationException' -or $_.Exception.Message -notmatch 'CNAME.*does not exist') { throw }
                Add-Health $Context 'MicrosoftDnsDetection' Pending 'Exchange Online' 'CNAME detected' 'Microsoft has not detected CNAME'
            }
        }
        $config = Get-DkimConfig $Context.Domain
        if ($config.Enabled -eq $true -and "$($config.Status)" -eq 'Valid') {
            Add-Health $Context 'DKIMEnabled' Pass 'Exchange Online' 'Enabled, Valid' "$($config.Enabled), $($config.Status)"
            return $true
        }
        Add-Health $Context 'DKIMEnabled' Pending 'Exchange Online' 'Enabled, Valid' "$($config.Enabled), $($config.Status)"
        if ([DateTime]::UtcNow -ge $deadline) { return $false }
        Start-Sleep -Seconds $PollSeconds
    } while ($true)
}

function Invoke-M365DomainAuthentication {
    <#
    .SYNOPSIS
    Previews or applies Microsoft 365 DKIM and DMARC setup using GoDaddy DNS.

    .DESCRIPTION
    Processes one domain already accepted by Exchange Online. Preview is read-only
    by default but requires authenticated read access to Microsoft 365 and GoDaddy.
    Apply can create missing reporting shared mailboxes, prepare a disabled DKIM
    configuration, publish DNS records, and enable signing after health checks.

    Reporting addresses are dmarc-rua@<domain> and dmarc-ruf@<domain>. Existing active
    user/shared mailboxes owning these SMTP addresses or aliases are reused.
    Missing mailboxes are created only in apply mode. Every final RUA/RUF address
    is independently verified immediately before a DMARC write. Recipient
    collisions and unverifiable external destinations block unsafe publication.

    Actual selector targets come from Exchange, never inferred tenant names.
    Both selector CNAMEs and the intended DMARC record must match on every required
    authoritative server and both public resolvers; DKIM public keys must resolve.
    Provider API success alone cannot authorize DKIM activation. Final Exchange
    readback must show Enabled=True and Status=Valid. Failed health checks do not
    disable signing that was already enabled.

    New DMARC policies use p=none (monitoring), not enforcement. Existing policy
    tags and unrelated TXT data are preserved. SPF is inspected but never changed.

    .PARAMETER Domain
    Required existing M365 mail domain, for example example.com. Use a single
    ASCII/punycode domain, not a URL, wildcard, or domain list. Case and a trailing
    dot are normalized. The domain must equal DnsZone or be its subdomain.

    .PARAMETER AdminUserPrincipalName
    Administrator sign-in UPN for interactive Exchange Online login with your
    tenant's MFA policy. Required unless ExchangeConnectionId is supplied. This
    UPN may use a different domain from Domain.

    .PARAMETER GoDaddyToken
    GoDaddy production Personal Access Token as a SecureString. If omitted, prompts
    securely using Read-Host. Requires domains.domain:read and domains.dns:update
    scopes plus account/zone API eligibility. Legacy key/secret credentials are
    not supported. Never embed plaintext credentials in commands, files, or logs.

    .PARAMETER DnsZone
    GoDaddy-hosted zone containing the managed records; defaults to Domain.
    For mail.example.com hosted in example.com, specify example.com. Records
    become _dmarc.mail and selector1/selector2._domainkey.mail in that zone.

    .PARAMETER ExchangeConnectionId
    Identifier of an Exchange Online connection already established by the caller.
    The connection must be for the intended tenant and remain in the same
    PowerShell runspace. It is never disconnected by this function. Use this mode
    for external runner-owned Exchange authentication.

    .PARAMETER NonInteractive
    Disallows credential prompts and interactive DNS-replacement confirmation.
    Requires ExchangeConnectionId and a supplied GoDaddyToken. Intended for the
    external runner.

    .PARAMETER Apply
    Authorizes real mailbox, DKIM configuration, and DNS changes. Off by default.
    New resources do not require another prompt unless -Confirm requests one.
    Combining -Apply with -WhatIf remains read-only, including mailbox creation.

    .PARAMETER ReplaceConflictingRecords
    Allows proposing eligible managed DNS replacements. Writes also require
    -Apply and mandatory interactive confirmation showing before/after values.
    Existing DMARC changes replace only RUA/RUF tags, preserving enforcement.
    Does not override recipient collisions, unsafe delegation, or malformed or
    multiple DMARC policies, which require manual resolution. No force bypass.

    .PARAMETER TimeoutMinutes
    Timeout for each polling stage, not a whole-run deadline. Default 10;
    range 1-120. Outstanding queries and the current cycle finish before return.
    Expiry reports Pending; earlier successful changes are not rolled back.

    .PARAMETER PollSeconds
    Delay between polling attempts. Default 30 seconds; range 1-300.

    .PARAMETER ReportDirectory
    Parent directory for unique apply-run snapshots and result.json. Defaults to
    .m365-auth-runs under the current working directory. Preview creates no files.
    Custom locations are not automatically Git-ignored. Protect operational data.

    .INPUTS
    None. Parameters are not bound from pipeline input.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Contains Operation, State, Domain, Tenant, DkimInitiallyEnabled, Health,
    Actions, Changes, Conflicts, Warnings, Error, RunDirectory, and ResultFile.
    States are Preview, Completed,
    Conflict, Pending, Failed, and Partial. Preview is not proof of readiness;
    inspect Health and Conflicts. Only Completed confirms all mandatory gates.
    Health records Pass, Fail, Pending, or NotVerifiable with source, expected and
    observed values, diagnostic Detail, and CheckedAtUtc.
    The function returns an object and does not set script process exit codes.

    .EXAMPLE
    Import-Module .\M365DomainAuthentication.psm1
    Invoke-M365DomainAuthentication -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com

    Discovers current state and health without tenant/DNS writes. Securely prompts
    for the GoDaddy PAT and signs in interactively. Missing DKIM targets remain
    unknown until apply creates a disabled configuration.

    .EXAMPLE
    $token = Read-Host 'GoDaddy production PAT' -AsSecureString
    $result = Invoke-M365DomainAuthentication -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com -GoDaddyToken $token -Apply -Confirm
    $result | Select-Object State, Domain, Tenant, Error
    $result.Health | Group-Object Name, Source | ForEach-Object { $_.Group | Select-Object -Last 1 } | Format-Table Name, Status, Source, Detail -Wrap

    Applies after confirmation using a securely supplied token and inspects the
    latest health observation for each check/source, including partial results.

    .EXAMPLE
    Invoke-M365DomainAuthentication -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com -Apply -WhatIf

    Remains read-only despite -Apply. Authentication and health reads still occur.

    .EXAMPLE
    Invoke-M365DomainAuthentication -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com -ReplaceConflictingRecords
    Invoke-M365DomainAuthentication -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com -ReplaceConflictingRecords -Apply

    First previews proposed replacements, then applies only after the mandatory
    replacement confirmation. Review existing sender usage before confirming.

    .EXAMPLE
    Invoke-M365DomainAuthentication -Domain mail.example.com -DnsZone example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com

    Previews a mail subdomain whose DNS records live in its parent GoDaddy zone.

    .NOTES
    Requires Windows with PowerShell 7.2+ (pwsh), Resolve-DnsName, and a supported
    ExchangeOnlineManagement 3.0+ exposing connection-scoped disconnect.
    Install/update dependencies explicitly; they are never installed silently.
    Use Exchange permissions to read accepted domains, recipients/mailboxes and
    DKIM, create shared mailboxes, and create/update DKIM. No Graph app is needed.
    Only the Exchange connection created by this invocation is disconnected.

    Public delegation must match GoDaddy .domaincontrol.com nameservers.
    Required public resolvers are fixed at 1.1.1.1 and 8.8.8.8. New/replaced DNS
    records use TTL 600 seconds; matching records retain their TTL. Network/DNS
    failures block activation, even if a provider write succeeded.

    -WhatIf forces read-only operation. -Confirm requests the overall apply
    confirmation; it does not suppress the separate replacement confirmation.
    Apply writes dns-before.json before mutation and attempts to save result.json,
    including partial failures. Writes are not transactional; concurrency checks
    cannot eliminate every race. No automatic rollback or mailbox deletion occurs.
    Inspect Changes, saved snapshots, and live state before safe preview/apply
    reruns. Pending/Conflict can follow earlier successful preparation changes.
    Health is timestamped history; earlier pending entries remain after recovery.

    No SPF/MX edits, mailbox access grants, licenses, forwarding, retention,
    report processing, or automatic DMARC enforcement escalation are included.
    RUF can contain sensitive message data and is not supported by every receiver.
    Mailbox existence does not prove delivery. Verify actual report reception and
    send a real message to check aligned dkim=pass and dmarc=pass.

    .LINK
    https://github.com/therealtadda/M3365-dkim-dmarc-autogen#readme

    .LINK
    https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure

    .LINK
    https://developer.godaddy.com/en/docs/api-users/auth
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string]$AdminUserPrincipalName,
        [Security.SecureString]$GoDaddyToken,
        [string]$ExchangeConnectionId,
        [string]$DnsZone,
        [switch]$Apply,
        [switch]$ReplaceConflictingRecords,
        [switch]$NonInteractive,
        [ValidateRange(1, 120)][int]$TimeoutMinutes = 10,
        [ValidateRange(1, 300)][int]$PollSeconds = 30,
        [string]$ReportDirectory = (Join-Path $PWD '.m365-auth-runs')
    )
    $ErrorActionPreference = 'Stop'
    $context = [pscustomobject]@{
        Domain = ''; Zone = ''; ZonePath = ''; Token = ''; Replace = [bool]$ReplaceConflictingRecords
        Resolvers = @('1.1.1.1', '8.8.8.8'); Authorities = @(); AcceptedDomains = @(); OriginalRecords = @()
        Addresses = @(); Actions = [Collections.Generic.List[object]]::new()
        Health = [Collections.Generic.List[object]]::new(); Conflicts = [Collections.Generic.List[string]]::new()
        Changes = [Collections.Generic.List[object]]::new(); Warnings = [Collections.Generic.List[string]]::new()
    }
    $result = [pscustomobject]@{
        Operation = if ($Apply) { 'Apply' } else { 'Preview' }
        State = 'Failed'; Domain = $Domain; Tenant = $null; DkimInitiallyEnabled = $null
        Health = $context.Health; Actions = $context.Actions; Changes = $context.Changes
        Conflicts = $context.Conflicts; Warnings = $context.Warnings; Error = $null; RunDirectory = $null
        ResultFile = $null
    }
    $connectionId = $null
    $mutating = $false
    try {
        $context.Domain = ConvertTo-DomainName $Domain
        $result.Domain = $context.Domain
        $context.Zone = if ($DnsZone) { ConvertTo-DomainName $DnsZone } else { $context.Domain }
        if ($context.Domain -ne $context.Zone -and -not $context.Domain.EndsWith(".$($context.Zone)")) { throw 'Domain must equal DnsZone or be its subdomain.' }
        if ($ExchangeConnectionId -and $AdminUserPrincipalName) {
            throw 'Supply AdminUserPrincipalName or ExchangeConnectionId, not both.'
        }
        if ($NonInteractive -and -not $ExchangeConnectionId) {
            throw 'NonInteractive mode requires an existing ExchangeConnectionId.'
        }
        if ($ExchangeConnectionId -and -not $NonInteractive) {
            throw 'ExchangeConnectionId requires NonInteractive mode.'
        }
        if (-not $ExchangeConnectionId -and $AdminUserPrincipalName -notmatch '^[^@\s]+@[^@\s]+$') {
            throw 'AdminUserPrincipalName must be a sign-in UPN unless ExchangeConnectionId is supplied.'
        }
        if ($NonInteractive -and $ReplaceConflictingRecords) {
            throw 'DNS replacements are interactive and cannot be requested in NonInteractive mode.'
        }
        $context.ZonePath = "/zones/$([uri]::EscapeDataString($context.Zone))"
        $context.Addresses = @("dmarc-rua@$($context.Domain)", "dmarc-ruf@$($context.Domain)")
        if (("selector1._domainkey.$($context.Domain)").Length -gt 253 -or
            @($context.Addresses | Where-Object { $_.Length -gt 254 }).Count -gt 0) {
            throw 'Domain is too long for the derived managed DNS names or reporting SMTP addresses.'
        }
        foreach ($command in 'Resolve-DnsName', 'Get-EXORecipient', 'Get-EXOMailbox') {
            if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Required command $command is missing. See README installation instructions." }
        }
        if (-not $ExchangeConnectionId -and -not (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue)) {
            throw 'Required command Connect-ExchangeOnline is missing. See README installation instructions.'
        }
        if ($null -eq $GoDaddyToken) {
            if ($NonInteractive) { throw 'NonInteractive mode requires GoDaddyToken to be supplied.' }
            $GoDaddyToken = Read-Host 'GoDaddy production PAT (not stored)' -AsSecureString
        }
        $context.Token = [Net.NetworkCredential]::new('', $GoDaddyToken).Password
        if (-not $context.Token -or $context.Token -match '[\r\n]') { throw 'A nonempty GoDaddy PAT is required.' }
        $records = @(Get-ZoneRecords $context)
        $context.OriginalRecords = $records
        Add-Health $context 'GoDaddyReadAccess' Pass 'GoDaddy v3' 'Readable DNS zone' $context.Zone
        $context.Authorities = @(Get-AuthoritativeServers $context $records)
        Import-Module ExchangeOnlineManagement -MinimumVersion 3.0 -ErrorAction Stop
        if (-not $ExchangeConnectionId -and -not (Get-Command Disconnect-ExchangeOnline -ErrorAction Stop).Parameters.ContainsKey('ConnectionId')) {
            throw 'Update ExchangeOnlineManagement: connection-scoped disconnect is required.'
        }
        if ($ExchangeConnectionId) {
            $allConnections = @(Get-ConnectionInformation -ErrorAction Stop)
            $connections = @($allConnections | Where-Object ConnectionId -EQ $ExchangeConnectionId)
            if ($allConnections.Count -ne 1 -or $connections.Count -ne 1) {
                throw "Exchange connection '$ExchangeConnectionId' must be the only active Exchange connection in this PowerShell runspace."
            }
            $connection = $connections[0]
            if (-not $connection.TenantID) {
                throw "Exchange connection '$ExchangeConnectionId' does not expose a tenant identifier."
            }
        }
        else {
            $beforeConnections = @(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { $_.ConnectionId })
            try {
                $null = Connect-ExchangeOnline -UserPrincipalName $AdminUserPrincipalName -ShowBanner:$false -ErrorAction Stop
            }
            finally {
                $newConnections = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object ConnectionId -NotIn $beforeConnections)
                if ($newConnections.Count -eq 1) { $connectionId = $newConnections[0].ConnectionId }
            }
            if (-not $connectionId) { throw 'Could not identify a unique connection created by this invocation; refusing ambiguous tenant access.' }
            $connection = $newConnections[0]
        }
        $result.Tenant = "$($connection.TenantID)"
        $context.AcceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { "$($_.DomainName)".ToLowerInvariant() })
        if ($context.Domain -notin $context.AcceptedDomains) { throw 'Requested domain is not an accepted domain in the connected tenant.' }
        Add-Health $context 'AcceptedDomain' Pass "Tenant $($result.Tenant)" $context.Domain $context.Domain
        $dkim = Get-DkimConfig $context.Domain
        $result.DkimInitiallyEnabled = $null -ne $dkim -and $dkim.Enabled -eq $true
        if ($null -ne $dkim) {
            Add-Health $context 'InitialDkimState' $(if ($dkim.Enabled -eq $true -and "$($dkim.Status)" -eq 'Valid') { 'Pass' } else { 'Pending' }) `
                'Exchange Online' 'Enabled, Valid' "$($dkim.Enabled), $($dkim.Status)"
        }
        foreach ($address in $context.Addresses) {
            $recipient = Get-RecipientState $address
            Add-Health $context "Mailbox:$address" $(if ($recipient.State -eq 'Ready') { 'Pass' } elseif ($recipient.State -eq 'Conflict') { 'Fail' } else { 'Pending' }) 'Exchange Online' 'Ready' $recipient.State
            $context.Actions.Add([pscustomobject]@{ Action = $(if ($recipient.State -eq 'Missing') { 'CreateSharedMailbox' } else { 'ReuseOrWaitMailbox' }); Address = $address; State = $recipient.State })
            if ($recipient.State -eq 'Conflict') { $context.Conflicts.Add("Recipient collision at $address.") }
        }
        $spf = @($records | Where-Object { $_.type -eq 'TXT' -and $_.name -ieq $(if ($context.Domain -eq $context.Zone) { '@' } else { $context.Domain.Substring(0, $context.Domain.Length - $context.Zone.Length - 1) }) } |
            ForEach-Object { ConvertFrom-ProviderTxt $_.data } | Where-Object { $_ -match '^v=spf1(?:\s|$)' })
        if ($spf.Count -ne 1) { $context.Warnings.Add("Found $($spf.Count) SPF records. SPF is not changed.") }
        elseif ($spf[0] -notmatch '(?:^|\s)include:spf\.protection\.outlook\.com(?:\s|$)') { $context.Warnings.Add('SPF does not directly include Microsoft 365; inspect its full evaluation manually. No SPF changes made.') }
        $context.Warnings.Add('SPF inspection is not full SPF evaluation. RUF delivery is receiver-dependent and can contain sensitive message data.')
        $plans = @(Get-RecordPlan $context $records $dkim)
        if ($null -eq $dkim) {
            $context.Actions.Add([pscustomobject]@{ Action = 'CreateDisabledDkimConfig'; Domain = $context.Domain })
            Add-Health $context 'DKIMTargets' Pending 'Exchange Online' 'Actual Microsoft selector targets' 'Requires disabled DKIM configuration creation in apply mode'
        }
        $publicHealthy = Test-PublicDns $context $plans
        if ($result.DkimInitiallyEnabled -and -not $publicHealthy) {
            $context.Warnings.Add('DKIM was already enabled but public DNS health is incomplete. Existing signing is preserved; this run has not verified a repair.')
        }
        if ($context.Conflicts.Count -gt 0) { $result.State = 'Conflict'; return $result }
        if (-not $Apply -or $WhatIfPreference) { $result.State = 'Preview'; return $result }
        $requiredWrites = @(
            if (@($context.Actions | Where-Object Action -EQ 'CreateSharedMailbox').Count -gt 0) { 'New-Mailbox' }
            if ($null -eq $dkim) { 'New-DkimSigningConfig' }
            if ($null -eq $dkim -or -not $dkim.Enabled) { 'Set-DkimSigningConfig' }
        )
        foreach ($command in $requiredWrites) {
            if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
                throw "Connected account does not expose required Exchange cmdlet $command. Check Exchange RBAC before applying."
            }
        }
        if (-not $PSCmdlet.ShouldProcess("$($context.Domain) in tenant $($result.Tenant), GoDaddy zone $($context.Zone)", 'Apply listed mailbox, DNS, and DKIM actions')) {
            $result.State = 'Preview'; return $result
        }
        if (@($plans | Where-Object Action -EQ 'Replace').Count -gt 0) {
            $replacementText = ($context.Actions | ConvertTo-Json -Depth 12)
            if (-not $PSCmdlet.ShouldContinue($replacementText, 'Confirm exact DNS replacements (policy tags are preserved)')) {
                $result.State = 'Conflict'; $context.Conflicts.Add('DNS replacement was not confirmed.'); return $result
            }
        }
        $result.RunDirectory = Join-Path $ReportDirectory ([guid]::NewGuid().ToString())
        $null = New-Item -ItemType Directory -Path $result.RunDirectory -Force
        $managedNames = @('_dmarc', 'selector1._domainkey', 'selector2._domainkey') | ForEach-Object { Get-RelativeName $context $_ }
        ConvertTo-Json -InputObject @($records | Where-Object name -In $managedNames) -Depth 12 |
            Set-Content -LiteralPath (Join-Path $result.RunDirectory 'dns-before.json') -Encoding utf8
        $mutating = $true
        if (-not (Ensure-ReportingMailboxes $context $TimeoutMinutes $PollSeconds)) { $result.State = 'Pending'; return $result }
        if ($null -eq $dkim) {
            $null = New-DkimSigningConfig -DomainName $context.Domain -Enabled $false -ErrorAction Stop
            $context.Changes.Add([pscustomobject]@{ Action = 'CreateDisabledDkimConfig'; Domain = $context.Domain })
            $configDeadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
            do {
                $dkim = Get-DkimConfig $context.Domain
                if ($null -ne $dkim -and $dkim.Selector1CNAME -and $dkim.Selector2CNAME) { break }
                Add-Health $context 'DKIMTargets' Pending 'Exchange Online' 'Both Microsoft selector targets' 'Configuration provisioning'
                if ([DateTime]::UtcNow -ge $configDeadline) { $result.State = 'Pending'; return $result }
                Start-Sleep -Seconds $PollSeconds
            } while ($true)
            $context.Actions.Clear()
            $plans = @(Get-RecordPlan $context $records $dkim)
            if ($context.Conflicts.Count -gt 0) { $result.State = 'Conflict'; return $result }
            if (@($plans | Where-Object Action -EQ 'Replace').Count -gt 0 -and
                -not $PSCmdlet.ShouldContinue(($context.Actions | ConvertTo-Json -Depth 12), 'Confirm DNS replacements with discovered Microsoft selectors')) {
                $context.Conflicts.Add('Discovered selector replacements were not confirmed.'); $result.State = 'Conflict'; return $result
            }
        }
        foreach ($plan in $plans) { Set-PlannedRecord $context $plan }
        if (-not (Wait-PublicDns $context $plans $TimeoutMinutes $PollSeconds)) { $result.State = 'Pending'; return $result }
        if (-not (Enable-VerifiedDkim $context $plans $TimeoutMinutes $PollSeconds)) { $result.State = 'Pending'; return $result }
        $result.State = 'Completed'
        return $result
    }
    catch {
        $message = $_.Exception.Message
        if ($context.Token) { $message = $message.Replace($context.Token, '[REDACTED]') }
        $result.Error = $message
        $result.State = if ($mutating) { 'Partial' } else { 'Failed' }
        Add-Health $context 'Workflow' Fail 'Tool' 'All mandatory gates passing' $null $message
        return $result
    }
    finally {
        $context.Token = ''
        if ($connectionId) {
            try { $null = Disconnect-ExchangeOnline -ConnectionId $connectionId -Confirm:$false -WhatIf:$false -ErrorAction Stop }
            catch { $result.Warnings.Add("Could not disconnect connection $connectionId; disconnect it manually.") }
        }
        if ($result.RunDirectory) {
            try { $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $result.RunDirectory 'result.json') -Encoding utf8 }
            catch { $result.State = 'Partial'; $result.Error = 'Could not persist result.json. Inspect tenant/DNS state and the pre-change snapshot before rerunning.' }
        }
    }
}

function Invoke-M365DomainAuthenticationRunner {
    <#
    .SYNOPSIS
    Runs the DKIM/DMARC workflow with runner-owned Exchange authentication.

    .DESCRIPTION
    Non-interactive external runner for Invoke-M365DomainAuthentication. It uses
    a certificate-backed Exchange Online app registration, creates one connection
    in this PowerShell runspace, reuses it for the workflow, and disconnects only
    that connection. The GoDaddy PAT is read from a secret-provider environment
    variable. Operation is mandatory. Interactive DNS replacements are rejected.

    .PARAMETER Domain
    One existing Microsoft 365 mail domain in the connected tenant.

    .PARAMETER Operation
    Preview for read-only discovery or Apply to authorize idempotent mutations.

    .PARAMETER ExchangeOrganization
    Tenant domain used by Exchange Online app-only certificate authentication.

    .PARAMETER ExchangeApplicationId
    Application (client) ID of the runner-owned Exchange app registration.

    .PARAMETER ExchangeCertificateThumbprint
    Thumbprint of a certificate whose private key is available to this process.

    .PARAMETER GoDaddyTokenEnvironmentVariable
    Name of the environment variable containing the GoDaddy production PAT.
    Defaults to M365_DOMAIN_AUTH_GODADDY_PAT. It is never returned.

    .PARAMETER DnsZone
    Optional GoDaddy parent zone for a subdomain.

    .PARAMETER TimeoutMinutes
    Timeout for each provisioning and publication polling stage, from 1 to 120.

    .PARAMETER PollSeconds
    Delay between polling attempts, from 1 to 300 seconds.

    .PARAMETER ReportDirectory
    Parent directory for apply-run snapshots and result reports.

    .PARAMETER ResultFile
    Optional file to persist the credential-free structured result for Preview or
    Apply, including non-success states and runner errors. The parent directory
    must already exist. This is separate from the engine's apply-run result.json.

    .INPUTS
    None. Parameters are not bound from pipeline input.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    The same structured result as Invoke-M365DomainAuthentication.

    .EXAMPLE
    $result = Invoke-M365DomainAuthenticationRunner -Domain example.com -Operation Preview -ExchangeOrganization tenant.onmicrosoft.com -ExchangeApplicationId $appId -ExchangeCertificateThumbprint $thumbprint

    Performs a read-only preview using a runner-created Exchange connection.

    .EXAMPLE
    $result = Invoke-M365DomainAuthenticationRunner -Domain example.com -Operation Apply -ExchangeOrganization tenant.onmicrosoft.com -ExchangeApplicationId $appId -ExchangeCertificateThumbprint $thumbprint -ReportDirectory $artifactDirectory

    Applies only safe, planned changes. Existing DNS conflicts return Conflict and
    require separate human resolution; the runner cannot force replacements.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][ValidateSet('Preview', 'Apply')][string]$Operation,
        [Parameter(Mandatory)][string]$ExchangeOrganization,
        [Parameter(Mandatory)][string]$ExchangeApplicationId,
        [Parameter(Mandatory)][string]$ExchangeCertificateThumbprint,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')][string]$GoDaddyTokenEnvironmentVariable = 'M365_DOMAIN_AUTH_GODADDY_PAT',
        [string]$DnsZone,
        [ValidateRange(1, 120)][int]$TimeoutMinutes = 10,
        [ValidateRange(1, 300)][int]$PollSeconds = 30,
        [string]$ReportDirectory = (Join-Path $PWD '.m365-auth-runs'),
        [string]$ResultFile
    )
    $tokenValue = $null
    $token = $null
    $connectionIds = @()
    $startedClean = $false
    $result = [pscustomobject]@{
        Operation = $Operation; State = 'Failed'; Domain = $Domain; Tenant = $null
        DkimInitiallyEnabled = $null; Health = @(); Actions = @(); Changes = @()
        Conflicts = @(); Warnings = @(); Error = $null; RunDirectory = $null
        ResultFile = $ResultFile
    }
    try {
        Import-Module ExchangeOnlineManagement -MinimumVersion 3.0 -ErrorAction Stop
        if (-not (Get-Command Disconnect-ExchangeOnline -ErrorAction Stop).Parameters.ContainsKey('ConnectionId')) {
            throw 'Update ExchangeOnlineManagement: connection-scoped disconnect is required.'
        }
        $beforeConnections = @(Get-ConnectionInformation -ErrorAction Stop)
        if ($beforeConnections.Count -ne 0) {
            throw 'The runner requires a clean PowerShell runspace with no pre-existing Exchange connections.'
        }
        $startedClean = $true
        $tokenValue = [Environment]::GetEnvironmentVariable($GoDaddyTokenEnvironmentVariable)
        if ([string]::IsNullOrWhiteSpace($tokenValue)) {
            throw "GoDaddy PAT environment variable '$GoDaddyTokenEnvironmentVariable' is missing or empty."
        }
        $token = $tokenValue | ConvertTo-SecureString -AsPlainText -Force
        $null = Connect-ExchangeOnline `
            -AppId $ExchangeApplicationId `
            -CertificateThumbprint $ExchangeCertificateThumbprint `
            -Organization $ExchangeOrganization `
            -ShowBanner:$false -ErrorAction Stop
        $newConnections = @(Get-ConnectionInformation -ErrorAction Stop)
        $connectionIds = @($newConnections | ForEach-Object { $_.ConnectionId } | Where-Object { $_ })
        if ($newConnections.Count -ne 1) {
            throw 'Could not identify a unique runner-owned Exchange connection; refusing ambiguous tenant access.'
        }
        $connectionId = $connectionIds[0]
        if (-not $connectionId) { throw 'Runner-owned Exchange connection did not expose a connection identifier.' }
        $parameters = @{
            Domain = $Domain
            ExchangeConnectionId = $connectionId
            GoDaddyToken = $token
            DnsZone = $DnsZone
            Apply = $Operation -eq 'Apply'
            NonInteractive = $true
            TimeoutMinutes = $TimeoutMinutes
            PollSeconds = $PollSeconds
            ReportDirectory = $ReportDirectory
        }
        $result = Invoke-M365DomainAuthentication @parameters
        $result.ResultFile = $ResultFile
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Health = @([pscustomobject]@{
            Name = 'ExternalRunner'; Status = 'Fail'; Source = 'External runner'
            Expected = 'Validated request and available external dependencies'
            Observed = $null; Detail = $result.Error; CheckedAtUtc = [DateTime]::UtcNow.ToString('o')
        })
    }
    finally {
        $tokenValue = $null
        $token = $null
        if ($startedClean -and $connectionIds.Count -eq 0) {
            try {
                $connectionIds = @(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object ConnectionId)
            }
            catch {
                $result.State = 'Partial'
                $result.Warnings = @($result.Warnings) + 'Could not inspect runner-created Exchange connections during cleanup; check active connections manually.'
            }
        }
        foreach ($connectionId in $connectionIds) {
            try {
                $null = Disconnect-ExchangeOnline -ConnectionId $connectionId -Confirm:$false -WhatIf:$false -ErrorAction Stop
            }
            catch {
                $result.State = 'Partial'
                $result.Warnings = @($result.Warnings) + "Could not disconnect runner-owned Exchange connection $connectionId; disconnect it manually."
            }
        }
        if ($ResultFile) {
            $temporaryFile = $null
            try {
                $parent = Split-Path -Parent $ResultFile
                if (-not $parent) { $parent = '.' }
                if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                    throw "ResultFile parent directory '$parent' does not exist."
                }
                $temporaryFile = Join-Path $parent ('.' + [IO.Path]::GetFileName($ResultFile) + '.' + [guid]::NewGuid().ToString() + '.tmp')
                $result | ConvertTo-Json -Depth 20 |
                    Set-Content -LiteralPath $temporaryFile -Encoding utf8 -ErrorAction Stop
                Move-Item -LiteralPath $temporaryFile -Destination $ResultFile -Force -ErrorAction Stop
            }
            catch {
                $originalError = $result.Error
                $result.State = 'Partial'
                $result.Error = "Could not persist ResultFile: $($_.Exception.Message)"
                if ($originalError) { $result.Error += " Original error: $originalError" }
                $result.Warnings = @($result.Warnings) + 'The returned object is authoritative because ResultFile could not be written.'
                if ($temporaryFile -and (Test-Path -LiteralPath $temporaryFile)) {
                    Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    return $result
}

Export-ModuleMember -Function Invoke-M365DomainAuthentication, Invoke-M365DomainAuthenticationRunner
