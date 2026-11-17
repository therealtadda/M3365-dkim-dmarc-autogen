<#
.SYNOPSIS
Previews or applies M365 DKIM/DMARC and GoDaddy DNS setup, returning JSON.

.DESCRIPTION
Processes one existing Exchange Online accepted domain using interactive admin
authentication. Preview is read-only by default. -Apply authorizes creation of
missing reporting shared mailboxes and a disabled DKIM configuration, managed DNS
publication, and DKIM activation only after mandatory public health checks.

Reporting addresses are dmarc-rua@<domain> and dmarc-ruf@<domain>. Existing active
user/shared mailboxes are reused, including SMTP aliases; missing ones are created
only in apply mode. Independent mailbox readback validates every final RUA/RUF
address immediately before publishing DMARC. Collisions and unverifiable external
destinations block unsafe publication.

Actual DKIM targets come from Exchange. Both selector CNAMEs and the intended
DMARC record must be visible on every required authoritative nameserver and both
public resolvers, with usable DKIM public keys, before signing can be enabled.
Provider API success is not sufficient. Final Exchange state must be Enabled=True
and Status=Valid. Failed checks never disable DKIM that was already enabled.

New DMARC uses p=none (monitoring). Existing enforcement policy tags and unrelated
records are preserved. SPF is inspected but never edited. Keep this script beside
M365DomainAuthentication.psm1. Use the module for in-session object results;
do not dot-source this entry script because it sets a process exit code.

.PARAMETER Domain
Required existing M365 mail domain, for example example.com. Supply one
ASCII/punycode domain, not a URL, wildcard, or list. Case/trailing dot normalize.
Must equal DnsZone or be its subdomain.

.PARAMETER AdminUserPrincipalName
Required administrator UPN for interactive Exchange Online sign-in following your
tenant's MFA policy. May use a different domain from the mail domain.

.PARAMETER GoDaddyToken
GoDaddy production PAT as a SecureString; securely prompted if omitted. Requires
domains.domain:read and domains.dns:update plus account/zone API eligibility.
Legacy API key/secret credentials are unsupported. Never put plaintext tokens
in commands, files, logs, or chat; use Read-Host -AsSecureString or a secret manager.

.PARAMETER DnsZone
GoDaddy zone containing the records; defaults to Domain. For mail.example.com in
the parent example.com zone, pass example.com. Owners become _dmarc.mail and
selector1/selector2._domainkey.mail relative to that zone.

.PARAMETER Apply
Authorizes real changes; off by default. New resources need no additional prompt
unless -Confirm requests one. -Apply -WhatIf remains read-only, including missing
mailbox and DKIM setup. Read access/authentication are still required.

.PARAMETER ReplaceConflictingRecords
Proposes eligible managed DNS replacements. Actual writes require -Apply plus
mandatory interactive before/after confirmation; no force bypass. Existing DMARC
changes update only RUA/RUF, preserving enforcement and unrelated tags. Cannot
override recipient collisions, unsafe delegation, or malformed/multiple DMARC
policies, which need manual resolution.

.PARAMETER TimeoutMinutes
Timeout per polling stage, not a whole-run deadline. Default 10; range 1-120.
The current query/cycle can extend the return time. Timeout reports Pending and
does not undo earlier successful changes.

.PARAMETER PollSeconds
Delay between polling attempts. Default 30 seconds; range 1-300.

.PARAMETER ReportDirectory
Parent of unique apply-run directories; defaults to .m365-auth-runs under the
current working directory. Contains dns-before.json and attempted result.json.
Preview writes no report files. Protect operational data; custom locations are
not automatically Git-ignored.

.INPUTS
None. Parameters are not bound from pipeline input.

.OUTPUTS
System.String
JSON with State, Domain, Tenant, DkimInitiallyEnabled, Health, Actions, Changes,
Conflicts, Warnings, Error, and RunDirectory. Health contains timestamped
Pass/Fail/Pending/NotVerifiable observations. Inspect the latest per check/source.
Preview is not proof of readiness; only Completed confirms all mandatory gates.

.EXAMPLE
pwsh -NoProfile -File .\Set-M365DomainAuthentication.ps1 -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com
$LASTEXITCODE

Previews current state and health, securely prompts for a PAT, and signs in
interactively. No tenant/DNS writes occur; missing DKIM targets remain unknown.

.EXAMPLE
$token = Read-Host 'GoDaddy production PAT' -AsSecureString
.\Set-M365DomainAuthentication.ps1 -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com -GoDaddyToken $token -Apply -Confirm

Applies using a securely supplied token, with overall apply confirmation.

.EXAMPLE
.\Set-M365DomainAuthentication.ps1 -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com -Apply -WhatIf

Remains read-only even with -Apply. Authentication and health reads still occur.

.EXAMPLE
.\Set-M365DomainAuthentication.ps1 -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com -ReplaceConflictingRecords
.\Set-M365DomainAuthentication.ps1 -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com -ReplaceConflictingRecords -Apply

Previews replacement values, then applies only after mandatory replacement
confirmation. Review selector usage by other mail senders before approving.

.EXAMPLE
.\Set-M365DomainAuthentication.ps1 -Domain mail.example.com -DnsZone example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com

Previews a mail subdomain whose records live in its parent GoDaddy zone.

.EXAMPLE
Import-Module .\M365DomainAuthentication.psm1
$result = Invoke-M365DomainAuthentication -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com
$result | Select-Object State, Domain, Tenant, Error
$result.Health | Group-Object Name, Source | ForEach-Object { $_.Group | Select-Object -Last 1 } | Format-Table Name, Status, Source, Detail -Wrap

Uses the module instead of the entry script to inspect an in-session result
object without setting a script process exit code.

.NOTES
Requires Windows with pwsh 7.2+, Resolve-DnsName, and supported
ExchangeOnlineManagement 3.0+ with connection-scoped disconnect. Install/update
dependencies explicitly. The admin needs accepted-domain/recipient/mailbox/DKIM
read permissions, shared-mailbox creation, and DKIM create/update permissions.
Only the Exchange connection created by this invocation is disconnected.

The GoDaddy production zone must match public .domaincontrol.com delegation.
Public resolvers are fixed at 1.1.1.1 and 8.8.8.8; new/replaced DNS TTL is 600
seconds. Correct existing records keep their TTL. Blocked DNS queries prevent
activation. No new domain onboarding or unattended login is configured.

-WhatIf forces read-only operation. -Confirm requests overall apply confirmation
but does not replace/suppress separate DNS-replacement confirmation.

Exit codes after a result is available:
0 = Preview or Completed.
2 = Conflict or Pending (earlier preparation changes may already exist).
1 = Failed or Partial (inspect Error, Changes, snapshots, and live state).
Startup, module-load, or parameter-binding failures can occur before JSON exists.
The module function returns objects and does not set these process exit codes.

Apply snapshots managed owners to dns-before.json before mutation and attempts
to persist result.json, including partial failures. Writes are nontransactional;
no automatic rollback or mailbox deletion occurs. Concurrent edits can race
provider writes despite pre-write checks. Inspect state, then rerun preview/apply
after resolving conflicts or allowing propagation. Never restore a whole zone
from the managed-record snapshot.

No SPF/MX edits, delegates, licenses, forwarding, retention, report processing,
or automatic DMARC enforcement escalation. RUF may contain sensitive message
data and delivery is receiver-dependent. Mailbox existence is not proof of mail
delivery. Verify reports and a real message's aligned dkim=pass and dmarc=pass.
See the local README.md for setup, troubleshooting, and recovery.

.LINK
Invoke-M365DomainAuthentication

.LINK
https://github.com/therealtadda/M3365-dkim-dmarc-autogen#readme

.LINK
https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure

.LINK
https://developer.godaddy.com/en/docs/api-users/auth
#>

#requires -Version 7.2
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Domain,
    [Parameter(Mandatory)][string]$AdminUserPrincipalName,
    [Security.SecureString]$GoDaddyToken,
    [string]$DnsZone,
    [switch]$Apply,
    [switch]$ReplaceConflictingRecords,
    [ValidateRange(1, 120)][int]$TimeoutMinutes = 10,
    [ValidateRange(1, 300)][int]$PollSeconds = 30,
    [string]$ReportDirectory = (Join-Path $PWD '.m365-auth-runs')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'M365DomainAuthentication.psm1') -Force
$result = Invoke-M365DomainAuthentication @PSBoundParameters
$result | ConvertTo-Json -Depth 20
switch ($result.State) {
    { $_ -in 'Failed', 'Partial' } { exit 1 }
    { $_ -in 'Pending', 'Conflict' } { exit 2 }
    default { exit 0 }
}
