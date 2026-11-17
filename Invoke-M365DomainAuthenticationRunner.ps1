<#
.SYNOPSIS
Runs a non-interactive DKIM/DMARC Preview or Apply from an external runner.

.DESCRIPTION
Standalone process entry point for automation outside CIPP. It imports the
repository module, creates a certificate-authenticated Exchange Online
connection, obtains the GoDaddy PAT from an environment variable, executes the
domain workflow, and disconnects only the Exchange connection it created.

This script does not import CIPP code, call undocumented CIPP endpoints, or run
as a CIPP custom test. An orchestrator may invoke it after independently
confirming an operation in that CIPP instance's live OpenAPI document.

.PARAMETER Domain
One existing Microsoft 365 accepted mail domain.

.PARAMETER Operation
Required explicit Preview or Apply operation.

.PARAMETER ExchangeOrganization
Tenant domain passed to Connect-ExchangeOnline.

.PARAMETER ExchangeApplicationId
Application (client) ID with the Exchange permissions required by this module.

.PARAMETER ExchangeCertificateThumbprint
Thumbprint of the certificate available to the runner process.

.PARAMETER GoDaddyTokenEnvironmentVariable
Name of the secret-provider-injected process environment variable containing
the GoDaddy production PAT. Defaults to M365_DOMAIN_AUTH_GODADDY_PAT.

.PARAMETER DnsZone
Optional GoDaddy parent zone for a subdomain.

.PARAMETER TimeoutMinutes
Per-stage provisioning/publication timeout from 1 to 120 minutes.

.PARAMETER PollSeconds
Polling delay from 1 to 300 seconds.

.PARAMETER ReportDirectory
Parent for apply-run snapshots and engine result reports.

.PARAMETER ResultFile
Optional file path for the credential-free structured result. Its parent
directory must exist.

.INPUTS
None.

.OUTPUTS
System.String
One JSON result object. Exit 0 for Preview/Completed, 2 for Conflict/Pending, and
1 for Failed/Partial.

.EXAMPLE
$env:M365_DOMAIN_AUTH_GODADDY_PAT = $securelyLoadedPatPlaintext
pwsh -NoProfile -File .\Invoke-M365DomainAuthenticationRunner.ps1 `
  -Domain example.com -Operation Preview `
  -ExchangeOrganization tenant.onmicrosoft.com `
  -ExchangeApplicationId $env:M365_EXO_APP_ID `
  -ExchangeCertificateThumbprint $env:M365_EXO_CERT_THUMBPRINT `
  -ResultFile C:\protected\results\example-preview.json

Performs a read-only preview. The secret provider, not this script, is
responsible for placing and clearing the environment secret.

.EXAMPLE
pwsh -NoProfile -File .\Invoke-M365DomainAuthenticationRunner.ps1 `
  -Domain example.com -Operation Apply `
  -ExchangeOrganization tenant.onmicrosoft.com `
  -ExchangeApplicationId $env:M365_EXO_APP_ID `
  -ExchangeCertificateThumbprint $env:M365_EXO_CERT_THUMBPRINT

Applies only the existing engine's planned, idempotent changes after the caller
has reviewed a Preview result and authorized Apply.
#>
#requires -Version 7.2
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

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'M365DomainAuthentication.psm1') -Force
$result = Invoke-M365DomainAuthenticationRunner @PSBoundParameters
$result | ConvertTo-Json -Depth 20
switch ($result.State) {
    { $_ -in 'Failed', 'Partial' } { exit 1 }
    { $_ -in 'Pending', 'Conflict' } { exit 2 }
    default { exit 0 }
}
