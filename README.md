# Microsoft 365 domain authentication with GoDaddy DNS

A preview-first PowerShell tool for one existing Microsoft 365 mail domain per run. It prepares DKIM, ensures DMARC reporting mailboxes exist, publishes GoDaddy DNS records, checks their public health, and **only then enables DKIM**.

DMARC is a DNS policy, not a feature switch in Microsoft 365. New policies use monitoring (`p=none`), not quarantine or rejection.

**Start with preview.** `-Apply` authorizes real tenant and DNS changes, including shared-mailbox creation. Automated validation uses mocked services; it is not evidence of a successful live run in your tenant or GoDaddy account.

## Contents

- [First-run checklist](#first-run-checklist)
- [Requirements](#requirements)
- [GoDaddy setup](#godaddy-setup)
- [Preview and apply](#preview-and-apply)
- [Parameter reference](#parameter-reference)
- [Built-in PowerShell help](#built-in-powershell-help)
- [Ordered health gates](#ordered-health-gates)
- [RUA and RUF reporting mailboxes](#rua-and-ruf-reporting-mailboxes)
- [Existing DMARC and SPF](#existing-dmarc-and-spf)
- [Results, reruns, and recovery](#results-reruns-and-recovery)
- [Troubleshooting](#troubleshooting)
- [Scope and limitations](#scope-and-limitations)
- [Development](#development)

## First-run checklist

1. Download or clone this repository. Keep `Set-M365DomainAuthentication.ps1` and `M365DomainAuthentication.psm1` together; the script imports the module from its own directory.
2. Open **PowerShell 7 (`pwsh`)**, not Windows PowerShell 5.1, and change to the repository directory. Check `$PSVersionTable.PSVersion` and install the Exchange module as described below.
3. Confirm the mail domain already exists in Microsoft 365, the administrator can manage it, and GoDaddy actually hosts its public DNS. Determine whether `-DnsZone` is needed for a subdomain.
4. Create a GoDaddy production PAT with DNS read/update access. Do not copy it into a script or command as plaintext.
5. Run the preview example below. Replace `example.com` and the admin UPN with your actual values; the admin UPN may use a different domain from the mail domain.
6. Review `Tenant`, `Domain`, `Actions`, `Health`, `Conflicts`, and `Warnings`. Unknown DKIM targets and missing reporting mailboxes are expected preparation items for a new domain; failures and conflicts need review.
7. Run with `-Apply` only after reviewing the plan. Investigate any non-completed result before retrying; do not assume earlier changes were rolled back.
8. Configure authorized access to the reporting mailboxes and perform the real-message authentication check described under [recovery and verification](#results-reruns-and-recovery).

## Requirements

- Windows with PowerShell **7.2 or newer** (`pwsh`) and the Windows `Resolve-DnsName` command. The implementation uses .NET cryptography available in PowerShell 7.2+.
- The domain must already be added to Microsoft 365 and present in Exchange Online accepted domains.
- An interactive Microsoft 365 admin account with MFA and Exchange permissions to read accepted domains, recipients, mailboxes and DKIM configuration, create shared mailboxes, and create/update DKIM configuration. Exchange Administrator is a usual starting role; customized RBAC must grant the required cmdlets. The tool does not assign roles.
- `ExchangeOnlineManagement` **3.0 or newer**, including `Get-ConnectionInformation` and connection-scoped disconnect. Use a current supported release.
- A production GoDaddy **Personal Access Token (PAT)** with `domains.domain:read` and `domains.dns:update`. v3 DNS does not use a legacy API key/secret.
- Public DNS must actually be delegated to the GoDaddy zone. Being the registrar or having an API-readable zone is not enough.
- Outbound HTTPS to Microsoft and GoDaddy, and DNS access to `1.1.1.1`, `8.8.8.8`, and every authoritative GoDaddy nameserver. If the network blocks those lookups, health checks block activation.

The current delegation check specifically requires the zone's apex NS records to use names ending in `.domaincontrol.com`, matching both public resolvers. Custom/vanity nameservers or other DNS providers are not supported by this check even if they are associated with GoDaddy.

Install the Exchange module explicitly in PowerShell 7:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

For an existing installation, use `Update-Module ExchangeOnlineManagement` and start a fresh PowerShell session if the old version is already loaded. A module version number alone is not sufficient: the installed version must expose `Disconnect-ExchangeOnline -ConnectionId`.

Dependencies are never installed silently. No Graph app registration, certificate, scheduled task, cloud automation, or additional paid reporting service is required by this tool.

## GoDaddy setup

Follow [GoDaddy authentication setup](https://developer.godaddy.com/en/docs/api-users/auth/how-to) to create a production PAT. Select only the two scopes above; domain purchases, nameserver changes, and domain deletion are not needed.

API access is subject to GoDaddy account eligibility as well as token scopes. See [current authentication and account requirements](https://developer.godaddy.com/en/docs/api-users/auth). Generating a token does **not** guarantee the account can manage this zone. The tool makes a read-only DNS API call before any tenant or DNS mutation. HTTP 401, 403, 404, and 429 produce actionable errors rather than an empty-record assumption. A successful read verifies read access, not write permission; configure the update scope as well. If access is refused, resolve it with GoDaddy; there is no browser-automation bypass.

The tool uses the [v3 record-scoped DNS API](https://developer.godaddy.com/en/docs/api-users/domains/manage/dns), with page-based reads and per-record create/replace/delete operations. It never replaces an entire zone.

**Do not put the PAT in source code, arguments as plaintext, transcripts, or chat.** Omit `-GoDaddyToken` to receive a secure prompt, or pass a `SecureString` obtained from your secret manager. The PAT necessarily exists briefly as plaintext in process memory for the HTTPS Authorization header; it is not included in output, snapshots, or transport-error messages.

## Preview and apply

Run from this repository in PowerShell 7:

```powershell
# Default: read-only discovery, proposed changes, and current health.
.\Set-M365DomainAuthentication.ps1 `
    -Domain example.com `
    -AdminUserPrincipalName admin@tenant.onmicrosoft.com

# Explicitly apply the planned changes.
.\Set-M365DomainAuthentication.ps1 `
    -Domain example.com `
    -AdminUserPrincipalName admin@tenant.onmicrosoft.com `
    -Apply
```

Both invocations securely prompt for a GoDaddy PAT and connect interactively to Exchange Online. MFA follows your tenant's sign-in policy. A preview still needs read access to both services, but creates no mailboxes, DKIM configuration, DNS records, or report files. If DKIM configuration does not yet exist, preview reports unknown selector targets rather than fabricating them.

The entry script sets a process exit code. For a separate process with an easily captured exit code, use:

```powershell
pwsh -NoProfile -File .\Set-M365DomainAuthentication.ps1 `
    -Domain example.com -AdminUserPrincipalName admin@tenant.onmicrosoft.com
$LASTEXITCODE
```

For in-session PowerShell objects and automation that should not exit its caller, use the module example under [results](#results-reruns-and-recovery). Do not dot-source the entry script.

To keep a token in a variable for repeated runs:

```powershell
$token = Read-Host 'GoDaddy production PAT' -AsSecureString
.\Set-M365DomainAuthentication.ps1 -Domain example.com `
    -AdminUserPrincipalName admin@tenant.onmicrosoft.com -GoDaddyToken $token
```

`-Apply -WhatIf` remains read-only, including missing mailbox/DKIM setup. `-Confirm` can request confirmation for the overall apply operation. Existing DNS replacements additionally require **both** `-ReplaceConflictingRecords` and an interactive confirmation showing the exact before/after record values:

```powershell
.\Set-M365DomainAuthentication.ps1 -Domain example.com `
    -AdminUserPrincipalName admin@tenant.onmicrosoft.com `
    -Apply -ReplaceConflictingRecords
```

There is deliberately no force flag to bypass replacement confirmation. A noninteractive run that needs confirmation cannot safely replace records. Review replacements carefully: selector names can be in use by another mail system.

`-Apply` is permission to carry out the plan; it does not guarantee an extra prompt for new records or mailboxes. Use `-Confirm` if you want an overall apply confirmation. To preview proposed replacements, supply `-ReplaceConflictingRecords` **without** `-Apply`; it cannot replace records in preview.

If `mail.example.com` uses the parent GoDaddy zone:

```powershell
.\Set-M365DomainAuthentication.ps1 -Domain mail.example.com -DnsZone example.com `
    -AdminUserPrincipalName admin@tenant.onmicrosoft.com
```

This maps `_dmarc` to `_dmarc.mail`, and the selectors to `selector1._domainkey.mail` and `selector2._domainkey.mail` in the parent zone. If the subdomain has its own delegated GoDaddy zone, pass that zone instead. Child delegations under managed record names require manual resolution; the tool never changes delegation.

## Parameter reference

The entry script and exported `Invoke-M365DomainAuthentication` function accept the same task parameters:

| Parameter | Required / default | Behavior |
|---|---|---|
| `-Domain <string>` | Required | One existing M365 mail domain, such as `example.com`. Case and a trailing dot are normalized. Use ASCII/punycode for internationalized names; no URL, path, wildcard, or comma-separated list. |
| `-AdminUserPrincipalName <string>` | Required | Administrator sign-in UPN for interactive Exchange Online authentication. |
| `-GoDaddyToken <SecureString>` | Secure prompt if omitted | Production GoDaddy PAT. Obtain with `Read-Host -AsSecureString` or a secret manager, not a plaintext command argument. |
| `-DnsZone <string>` | Defaults to `Domain` | GoDaddy zone containing the managed records. Must equal the mail domain or be its parent at a DNS-label boundary. |
| `-Apply` | Off | Authorizes tenant/DNS mutation. Without it, the tool only previews. |
| `-ReplaceConflictingRecords` | Off | Proposes eligible managed-record replacements; actual replacement still requires `-Apply` and interactive confirmation. Does not override recipient collisions, unsafe delegation, or malformed/multiple DMARC policies. |
| `-TimeoutMinutes <int>` | `10`; range `1`-`120` | Timeout for each polling stage, not a single whole-run deadline. See health-gate timeout limitations below. |
| `-PollSeconds <int>` | `30`; range `1`-`300` | Delay between polling attempts. |
| `-ReportDirectory <string>` | `.m365-auth-runs` under the current working directory | Parent for a unique apply-run directory containing snapshots and results. A custom location is not automatically Git-ignored. |
| `-WhatIf` | Off | Forces read-only behavior even when combined with `-Apply`; authentication and read-only service calls still occur. |
| `-Confirm` | PowerShell confirmation behavior | Requests confirmation for the overall apply operation. Does not replace or suppress the separate DNS-replacement confirmation. |

RUA/RUF addresses, the initial `p=none` policy, new/replaced DNS TTL (`600` seconds), production API origin, and the two public resolvers are fixed in this version, not configurable parameters. Existing matching records keep their current TTL.

## Built-in PowerShell help

Both public entry points include offline comment-based help with parameter guidance,
examples, prerequisites, health gates, and recovery notes. From the repository directory:

```powershell
Import-Module .\M365DomainAuthentication.psm1

# Module command: returns PowerShell result objects when invoked.
Get-Help Invoke-M365DomainAuthentication -Full
Get-Help Invoke-M365DomainAuthentication -Examples
Get-Help Invoke-M365DomainAuthentication -Parameter ReplaceConflictingRecords

# Entry script: emits JSON and sets a process exit code when invoked.
Get-Help .\Set-M365DomainAuthentication.ps1 -Full
Get-Help .\Set-M365DomainAuthentication.ps1 -Examples
Get-Help .\Set-M365DomainAuthentication.ps1 -Parameter DnsZone
```

Reading help does not execute setup, prompt for credentials, or contact Microsoft
365/GoDaddy. `Update-Help` is not required for this local help. After changing or
updating the module files, import with `-Force` or open a fresh PowerShell session
to avoid inspecting a previously loaded version.

## Ordered health gates

| Stage | Required evidence | Failure behavior |
|---|---|---|
| Preflight | Readable GoDaddy zone, matching public GoDaddy delegation, no hidden child delegation, accepted mail domain in the connected tenant, safe recipient/DNS plan | No tenant or DNS mutation |
| Reporting addresses | Independent Exchange recipient and active mailbox readback for both RUA and RUF; exact SMTP/proxy ownership | Create only missing shared mailboxes in apply, wait for provisioning; no DMARC write unless all final destinations are verified immediately before the write |
| DNS publication | Provider readback plus matching selector CNAMEs and exactly one intended DMARC policy on **every authoritative nameserver and both public resolvers** | Bounded polling; no DKIM enablement on missing/stale/conflicting answers, NXDOMAIN, SERVFAIL, or timeout |
| DKIM public keys | Both selector targets resolve through the public resolvers to a non-revoked, parseable RSA DKIM key of at least 1024 bits | No DKIM enablement |
| Microsoft activation | Public DNS passes again immediately before activation; Exchange readback says `Enabled=True`, `Status=Valid` | Retry only recognized Microsoft CNAME-detection lag; otherwise report failure/pending instead of completion |

Creating a **disabled** DKIM configuration is a preparation step needed to get Microsoft's real `Selector1CNAME`/`Selector2CNAME`. It does not enable signing. The tool supports both legacy `onmicrosoft.com` and current dynamically partitioned `dkim.mail.microsoft` targets by reading them from Exchange rather than guessing.

Each polling stage defaults to `-TimeoutMinutes 10` and `-PollSeconds 30`; supported ranges are 1-120 minutes and 1-300 seconds. Individual DNS queries use Windows quick timeouts; each cycle and outstanding network request must finish before the stage can return. Restrictive resolver/network policies can therefore prevent a healthy result even when DNS is correct elsewhere. A timeout does not undo earlier successful changes.

Preview runs the same available read-only health checks. `Health` contains named observations with status (`Pass`, `Fail`, `Pending`, `NotVerifiable`), source, expected/observed data, and details. Polling appends observations, so earlier pending observations remain as diagnostic history; inspect the latest observation per name/source and the overall `State`.

Each observation includes `CheckedAtUtc`. A preview can return `Conflict` or `Failed` instead of `Preview`; none of those read-only outcomes enables features. A `Preview` result can contain pending health checks and is not an all-clear certificate.

If DKIM was already enabled, failed health checks do **not** turn it off. `DkimInitiallyEnabled` records that fact, and the result reports the unhealthy or incomplete workflow instead of claiming repair.

## RUA and RUF reporting mailboxes

The defaults are separate addresses in the mail domain:

| Purpose | Address |
|---|---|
| Aggregate reports (`rua`) | `dmarc-rua@<domain>` |
| Failure/forensic reports (`ruf`) | `dmarc-ruf@<domain>` |

An existing active shared or user mailbox owning the address, even as a proxy alias, is reused without conversion or alias changes. Groups, mail contacts/users, duplicate ownership, and soft-deleted recipients are conflicts, not permission to repurpose the object. Query/permission failures are not interpreted as absence.

When absent, the addresses are created as shared mailboxes in apply mode, with explicit primary SMTP addresses and domain-specific display names. Internal mailbox names/aliases include a deterministic address hash to avoid collisions between domains. Provisioning is independently verified before DMARC publication. A successful `New-Mailbox` response is not enough.

The tool does **not** grant anyone mailbox access, add forwarding, assign licenses, change retention, or delete mailboxes on later failures. Configure authorized access through your normal Exchange administration process. Shared-mailbox size, archive, hold, and licensing restrictions still apply; see [Microsoft shared-mailbox guidance](https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes).

**RUF is receiver-dependent and can contain sensitive message/header information.** Many providers do not send forensic reports. Publishing `ruf` does not guarantee delivery, and `p=none` does not guarantee absence of forensic content. Restrict access and review your organization's privacy/retention requirements. No report parser, ingestion service, or automatic policy escalation is included.

## Existing DMARC and SPF

New DMARC:

```text
v=DMARC1; p=none; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com
```

Existing enforcement policies are **never silently downgraded**. If reporting destinations differ or a reporting tag is missing, the default is to preserve the record and report a conflict. With explicit replacement and confirmation, only `rua`/`ruf` change to the verified local defaults; `p`, `sp`, alignment, and other tags are preserved.

Malformed or multiple DMARC policies require **manual resolution even with the override**, because the tool cannot safely infer which enforcement policy to retain. Unrelated TXT data is preserved. Conflicting records at the two selector names or a conflicting CNAME at `_dmarc` can be replaced only with the explicit override and confirmation. NS/SOA/delegations are never replaced.

Existing tenant-local destinations are checked; existing external destinations are labeled `NotVerifiable`, never assumed valid based on MX or SMTP probing. An external destination may also require [DMARC external reporting authorization](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure) in the receiving domain. The tool does not create external mailboxes or authorization records. It will not publish/rewrite a DMARC record containing unverifiable destinations; use the approved reporting-only replacement to switch to verified local addresses.

SPF is inspected for missing/multiple records and a direct Microsoft 365 include, but **never edited**. This is not a full SPF evaluation: includes, redirects, lookup limits, other senders, and alignment still need review.

Before moving from monitoring to quarantine/reject, inventory every legitimate sender and review aggregate reports. This tool does not automate that enforcement rollout.

## Results, reruns, and recovery

The script emits a structured JSON result. When using the module directly, the same result is a PowerShell object:

```powershell
Import-Module .\M365DomainAuthentication.psm1
$result = Invoke-M365DomainAuthentication -Domain example.com `
    -AdminUserPrincipalName admin@tenant.onmicrosoft.com
$result.Health | Format-Table Name, Status, Source, Detail
```

| State | Script exit code | Meaning |
|---|---|---|
| `Preview` | 0 | Read-only plan/health inspection; not a claim that setup is complete |
| `Completed` | 0 | Required mailbox, DNS, public-key, and Exchange checks passed |
| `Conflict` | 2 | Preserved conflicting state or declined replacement; review `Changes` because discovery after disabled-DKIM preparation can expose a conflict |
| `Pending` | 2 | Provisioning, DNS, or Microsoft detection not ready; earlier changes may already exist |
| `Failed` | 1 | Failed before the mutating workflow began |
| `Partial` | 1 | Failure after mutation began, uncertain write, or inability to persist the final report; inspect actual state |

The exit-code table applies once the tool can load and return a result. PowerShell startup, module-load, and parameter-binding errors can terminate before JSON is produced. Check process errors as well as result data. The module function returns a result object; it does not itself set the entry script's exit codes.

After apply authorization and before mutations, the tool saves a snapshot of all records at the three managed owner names as `.m365-auth-runs\<run-id>\dns-before.json`. It saves credential-free `result.json` with actions, changes, errors, and health observations, including on partial failures. Use `-ReportDirectory` to choose another output location. These files are ignored by Git by default; they contain operational mailbox/domain information, so protect them appropriately.

Writes are record-scoped but **not transactional**. A same-owner read-before-write check detects observed concurrent edits, but GoDaddy offers no atomic compare-and-swap here; another administrator can still race the final request. Do not edit the same records concurrently. Failed create requests are never blindly replayed: the tool reads back the zone to reconcile a lost response and stops if the outcome remains uncertain.

For recovery, first inspect the current public/provider records and Exchange state. Compare affected records with `dns-before.json`, then restore only intended record values using GoDaddy's UI/API after checking for newer external edits. Do not upload the snapshot as a whole-zone replacement. Do not remove reporting mailboxes just because DNS setup failed; they may now be in use. No automatic rollback or bulk deletion is performed.

Rerun the same preview/apply command after resolving access, conflicts, or propagation. Existing correct records and active mailboxes are reused; an enabled/valid DKIM configuration is not recreated. Only the Exchange connection established by this invocation is disconnected.

To inspect an apply-run report, replace the example path with the `RunDirectory` reported by your invocation:

```powershell
$report = Get-Content -LiteralPath '.\.m365-auth-runs\<run-id>\result.json' -Raw |
    ConvertFrom-Json
$report | Select-Object State, Domain, Tenant, Error
$report.Changes | Format-List
$report.Conflicts
$report.Health |
    Group-Object Name, Source |
    ForEach-Object { $_.Group | Select-Object -Last 1 } |
    Format-Table Name, Status, Source, Detail -Wrap
```

If report persistence fails, rely on the returned result and inspect live state; do not assume `result.json` exists or is current. Snapshot/report creation is attempted only for authorized apply runs, not previews or runs blocked before that stage.

Finally send a real message to an independent recipient and inspect `Authentication-Results` for `dkim=pass`, aligned `d=`, and `dmarc=pass`. DNS and configuration checks cannot prove end-to-end signing, reporting delivery, or authentication for every sending system.

## Troubleshooting

| Symptom | What to check / safe next action |
|---|---|
| PowerShell version or `Resolve-DnsName` error | Use PowerShell 7.2+ on Windows and ensure the Windows DNS Client command is available. Linux/macOS are not supported by this version. |
| Missing Exchange command or connection-scoped disconnect | Install/update `ExchangeOnlineManagement` in PowerShell 7, restart the shell, and verify the installed module exposes the required commands. |
| GoDaddy HTTP 401 | Check PAT validity/expiry and that it is a PAT rather than a legacy key/secret. Do not print the credential to diagnose it. |
| GoDaddy HTTP 403 | Check the account's API eligibility, zone access, and both requested scopes. A readable zone does not prove update permission. The error includes a provider code when safely available. |
| GoDaddy HTTP 404 | Verify the zone name, authenticated GoDaddy account, and actual DNS hosting. For a mail subdomain, check whether records belong in the parent `-DnsZone`. |
| GoDaddy HTTP 429 or service error | Allow the provider retry period to pass, inspect any partial changes, then rerun preview. Safe reads have bounded retries; writes are not blindly retried. |
| Delegation mismatch or child-zone conflict | Compare public NS delegation with the selected GoDaddy zone. Resolve delegation or select the correct zone manually; the tool never changes nameservers. |
| Domain not accepted / unexpected tenant | Check the signed-in administrator and target tenant. Add/verify the domain through your normal M365 onboarding process before using this tool. |
| Exchange access denied / missing write cmdlet | Have an administrator review Exchange RBAC for recipient reads, mailbox creation, accepted-domain reads, and DKIM configuration. Do not treat permission errors as missing resources. |
| Recipient collision | Inspect all active and soft-deleted objects owning the address, including proxy aliases. Resolve ownership deliberately; the tool will not convert recipients or delete conflicting objects. |
| Mailbox provisioning pending | Check the created objects and their SMTP addresses, allow provisioning to settle, and rerun. Do not manually create a second mailbox with the same address. |
| Existing DMARC destinations differ | Review the current policy. Preview with `-ReplaceConflictingRecords`, then apply and confirm only if switching both reporting destinations is intended. |
| Malformed/multiple DMARC policies | Resolve manually to one intentional valid policy while preserving your desired enforcement level. The replacement override cannot select a policy for you. |
| DNS health pending despite successful GoDaddy writes | Inspect latest `Health` observations by source. Check exact owner names/targets, stale caches, TXT contents, public-key resolution, and network access to every required DNS source. Do not force DKIM activation. |
| Microsoft still reports missing CNAME | Public DNS and Microsoft's detection can differ temporarily. Review both selector values from Exchange, allow detection to catch up, and rerun. Only a recognized CNAME-detection error is retried automatically. |
| Concurrent change / uncertain write / `Partial` | Stop concurrent edits, compare current state with the snapshot and `Changes`, and rerun preview before deciding what to repair. Do not perform a whole-zone restore. |
| Unable to disconnect or save a report | Follow the returned warning/error. Disconnect only the identified owned Exchange connection if necessary; inspect live tenant/DNS state if the saved report is missing. |

## Scope and limitations

This is an interactively run, single-domain tool. It does not onboard or verify new M365 domains, process a bulk domain list, buy domains, change nameservers, manage other DNS providers, configure unattended authentication, or install a recurring job.

It does not change SPF, MX/mail routing, mailbox permissions, forwarding, licenses, retention, DKIM key rotation, or automatically move DMARC to quarantine/reject. Mailbox existence checks confirm Exchange provisioning and address ownership, **not inbound delivery**; verify existing MX/routing and actual report reception separately. Reporting mailbox names cannot be customized in this version.

The tool requires one intended DMARC policy and exact matching public observations from all required DNS sources. It preserves already-enabled DKIM on health failure and never treats provider API success as proof of publication. No report parsing or guarantee of RUA/RUF delivery is provided.

## Development

The tests mock all Microsoft, GoDaddy, DNS, authentication, and waiting calls. They do not require credentials and do not touch a live tenant or DNS zone.

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser
$r = Invoke-Pester .\tests -Output Detailed -PassThru
if ($r.FailedCount -or $r.FailedContainersCount) { exit 1 }
```

Live integration requires separately authorized tenant and DNS access. It is not performed by the test suite.

## License

Licensed under the [BSD 3-Clause License](LICENSE).
