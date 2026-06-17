# DLP Impact Analysis for Microsoft Power Platform

A set of PowerShell scripts that measure the impact of a Microsoft Power Platform
Data Loss Prevention (DLP) policy across one or more environments. The tool
inspects Cloud Flows, Canvas Apps, and Copilot Studio agents, determines which
connectors each resource uses, and reports which resources would be blocked or
flagged by a given DLP policy.

## Overview

The solution is composed of three scripts:

| Script | Purpose |
| ------ | ------- |
| `Setup-SPNPermissions.ps1` | One-time setup. Registers a Service Principal (SPN) as an Application User with the required roles in every Dataverse environment of the tenant. |
| `Analyze-DLPImpact.ps1` | Main script. Interactive analysis of the DLP impact on selected environments and a selected policy. Produces a CSV report. |
| `Debug-BotConnectors.ps1` | Diagnostic helper (currently disabled). Was used to reverse-engineer how Copilot Studio agents reference connectors. Its logic is now built into the main script. |

## How it works

### Authentication model

Both interactive scripts use a hybrid authentication approach:

- **Device Code Flow** for the signed-in administrator. The user authenticates
  once (no browser pop-up): the script prints a code and a URL, the user
  completes the sign-in, and the resulting refresh token is reused to obtain
  per-environment Dataverse tokens.
- **Client Credentials (SPN)** for the `Microsoft.PowerApps.Administration`
  module and for unattended Dataverse calls, using the `ApplicationId` and
  `ClientSecret` from `settings.json`.

The public client ID `1950a258-227b-4e31-a9cf-717495945fc2` (Microsoft Azure
PowerShell) is used for the Device Code Flow.

### `Setup-SPNPermissions.ps1`

Run this once before the first analysis. It:

1. Loads tenant and SPN credentials from `settings.json`.
2. Signs the administrator in via Device Code Flow.
3. Enumerates every Dataverse environment in the tenant.
4. For each environment, registers the SPN as an Application User and assigns
   the `System Administrator` and `Environment Admin` roles. If the SPN already
   exists, only the missing roles are added.

This grants the SPN the access it needs to read flows, apps, and agents from the
Dataverse Web API during analysis.

### `Analyze-DLPImpact.ps1`

The main workflow runs in five steps:

1. **Modules** — verifies and, if needed, installs
   `Microsoft.PowerApps.Administration.PowerShell`.
2. **Authentication** — Device Code Flow for the admin, plus
   `Add-PowerAppsAccount` with the SPN.
3. **Environment selection** — lists all environments and lets you pick one,
   several (comma-separated), or all (`*`).
4. **SPN registration** — ensures the SPN is registered in the selected
   environments (same logic as the setup script).
5. **DLP policy selection and analysis** — lists tenant DLP policies, lets you
   pick one, then analyzes every resource in the selected environments.

For each resource the script extracts the connectors in use and evaluates them
against the policy:

- **Cloud Flows** (Dataverse `workflows`, category 5) — connectors resolved from
  `connectionreferences`, then from the `clientdata` JSON
  (`connectionReferences`, `parameters.$connections`), with a regex fallback.
- **Canvas Apps** (Dataverse `workflows`, category 9) — same connector
  extraction strategy as flows.
- **Copilot Studio agents** (Dataverse `bots`) — connectors parsed from the
  `botcomponents` `data` (YAML) field. Every agent implicitly depends on the
  `shared_microsoftcopilotstudio` platform connector. Built-in capabilities are
  also detected and mapped to dedicated policy connector IDs:
  - `CSKnowledgeDocs` — file-based knowledge sources
  - `CSKnowledgePublicSites` — public web sites / web browsing
  - `CSKnowledgeSharePoint` — SharePoint / OneDrive knowledge sources

### DLP violation logic

A resource is considered **in violation** when:

- It uses a connector classified as **Blocked**, or
- It mixes connectors from two different classified groups (for example
  `Business` and `NonBusiness`), which Power Platform does not allow within the
  same resource.

Each connector is matched against the policy `connectorGroups` to determine its
classification (`Business`, `NonBusiness`, `Blocked`, or `Unclassified`).

### Granular DLP controls (action control / endpoint filtering)

In addition to the connector-group classification, the script can evaluate the
granular controls attached to a classic data policy:

- **Connector action control** — allow/block of individual actions or triggers
  within a connector (`connectorActionConfigurations`, with per-action
  `Allow`/`Block` rules and a default behavior).
- **Connector endpoint filtering** — allow/deny of specific hosts/URLs for the
  six supported connectors: HTTP, HTTP with Microsoft Entra ID, HTTP Webhook,
  SQL Server, Azure Blob Storage, and SMTP (`endpointConfigurations`, with
  ordered `Allow`/`Deny` endpoint rules).

These configurations are retrieved for the selected policy via
`Get-PowerAppDlpPolicyConnectorConfigurations` and the raw object is dumped to
the `debug` folder as `GranularDlp_ConnectorConfig_<timestamp>.json` for
verification.

For each Flow and Canvas App, the script extracts the operation IDs and the
static endpoints used, and flags a resource as a Granular DLP violation when:

- an action it uses is explicitly set to `Block`, or
- a static endpoint it uses falls into a `Deny` endpoint rule.

Limitations (reported as best-effort):

- Endpoints expressed dynamically (variables/expressions) cannot be evaluated.
- Default-deny of *new* actions is not flagged per resource (action-to-connector
  association is not always resolvable from the resource definition).
- Copilot Studio agents are not evaluated for Granular DLP
  (`GranularDlpViolationReason` is set to `Granular DLP non valutato (agente)`);
  they are still evaluated at the connector level.

Granular DLP analysis is controlled from the `GranularDlp` section in the
settings file and can be turned off entirely.

### Advanced Connector Policies (ACP, default-deny allowlist)

ACP are the newest construct: a **default-deny allowlist** of certified
connectors, applied per-environment or inherited from an environment group. Any
connector that is *not* on the allowlist is blocked.

The script evaluates ACP impact as follows:

1. It acquires a token for the Power Platform API
   (`https://api.powerplatform.com`).
2. For each selected environment it resolves the environment group (if any) and
   runs a **discovery** against the candidate endpoints listed in
   `Acp.DiscoveryEndpoints` (templated with `{environmentId}` / `{groupId}`).
3. Every successful response is dumped raw to the `debug` folder as
   `ACP_Discovery_<endpoint>_<timestamp>.json` so the real preview schema can be
   confirmed for your tenant.
4. The allowlist connector IDs are parsed defensively from the response, and a
   resource is flagged as an ACP violation when it uses a connector that is
   **not** present in the allowlist (default-deny).

Limitations (reported as best-effort):

- The endpoint that exposes the effective ACP allowlist is a **preview** feature
  and is not part of the stable public REST reference; the candidate endpoints
  are a starting point and may need adjusting once you inspect the dumped JSON.
- ACP officially covers **certified connectors only** (custom and HTTP
  connectors are not yet supported); custom/HTTP usage is evaluated on a
  best-effort basis.
- ACP is evaluated only when an allowlist is successfully discovered for the
  environment; otherwise the resource is reported as not in ACP scope.

ACP analysis is controlled from the `Acp` section in the settings file and can
be turned off entirely.

### Cross-referencing DLP / Granular DLP / ACP

The three control levels are evaluated independently per resource and then
combined into a single impact verdict:

- `Impacted` is `True` when the resource is blocked by **at least one** of the
  three controls.
- `ImpactCount` is how many of the three controls block it (0–3).
- `ImpactSources` lists which ones, e.g. `DLP + ACP` or `DLP + GranularDLP + ACP`.

The console summary prints an overlap matrix (DLP only, Granular DLP only, ACP
only, each pairwise combination, and all three) plus a dedicated table of the
resources blocked by more than one control at the same time — the highest-risk
items to remediate first.

## Output

The script writes a CSV report and a debug transcript:

- **CSV report** — saved to the `output` folder by default, named
  `DLP_Impact_<timestamp>.csv`. Each row contains:
  `PolicyName`, `PolicyId`, `EnvironmentName`, `EnvironmentId`, `ResourceType`,
  `ResourceName`, `ResourceId`, `Owner`, `State`, `ConnectorsUsed`,
  `ConnectorGroups`, `DlpViolation`, `ViolationReason`, `GranularDlpViolation`,
  `GranularDlpViolationReason`, `AcpViolation`, `AcpViolationReason`,
  `Impacted`, `ImpactCount`, `ImpactSources`.
- **Debug log** — a full PowerShell transcript saved to the `debug` folder,
  named `DLP_Debug_<timestamp>.log`.

A summary of total resources, per-control violations, the cross-referencing
overlap matrix, and unaffected resources is printed to the console at the end of
the run.

## Configuration

Configuration is read from a settings file. The scripts prefer
`settings.local.json` and fall back to `settings.json`. Copy
`settings.sample.json` to `settings.local.json` and fill in your values:

```json
{
    "Auth": {
        "TenantId":      "00000000-0000-0000-0000-000000000000",
        "ApplicationId": "00000000-0000-0000-0000-000000000000",
        "ClientSecret":  "your-client-secret-here"
    },
    "Output": {
        "CsvFolder": "output",
        "DebugFolder": "debug"
    },
    "GranularDlp": {
        "Enabled": true,
        "AnalyzeActionControl": true,
        "AnalyzeEndpointFiltering": true
    },
    "Acp": {
        "Enabled": true,
        "DefaultDeny": true,
        "DiscoveryEndpoints": [
            "https://api.powerplatform.com/environmentmanagement/environmentGroups/{groupId}?api-version=2024-10-01",
            "https://api.powerplatform.com/governance/environmentGroups/{groupId}/ruleSets?api-version=2024-10-01",
            "https://api.powerplatform.com/governance/environments/{environmentId}/connectorPolicies?api-version=2024-10-01"
        ]
    }
}
```

| Key | Description |
| --- | ----------- |
| `Auth.TenantId` | Azure AD / Entra ID tenant ID. |
| `Auth.ApplicationId` | Client ID of the SPN (app registration). |
| `Auth.ClientSecret` | Client secret of the SPN. |
| `Output.CsvFolder` | Folder for the CSV reports. Relative paths resolve against the script folder. |
| `Output.DebugFolder` | Folder for the debug transcript logs. |
| `GranularDlp.Enabled` | Master switch for granular DLP (action control / endpoint filtering) analysis. |
| `GranularDlp.AnalyzeActionControl` | Evaluate per-action `Allow`/`Block` rules. |
| `GranularDlp.AnalyzeEndpointFiltering` | Evaluate endpoint `Allow`/`Deny` rules. |
| `Acp.Enabled` | Master switch for Advanced Connector Policies (default-deny allowlist) analysis. |
| `Acp.DefaultDeny` | Treat connectors not on the discovered allowlist as blocked. |
| `Acp.DiscoveryEndpoints` | Candidate Power Platform API endpoints probed to discover the ACP allowlist (templated with `{environmentId}` / `{groupId}`). |

Both `settings.json` and `settings.local.json` are excluded from source control
via `.gitignore` because they hold real credentials. Keep secrets only in your
local copy.

## Prerequisites

- PowerShell 5.1 or later (PowerShell 7+ recommended).
- The `Microsoft.PowerApps.Administration.PowerShell` module (installed
  automatically by the script if missing).
- An Entra ID app registration (SPN) with a client secret and the
  `Dynamics CRM` (Dataverse) application permission.
- A tenant administrator able to complete the Device Code sign-in and grant the
  SPN access to environments.

## Usage

```powershell
# 1. Create your local settings file and fill in real credentials
Copy-Item settings.sample.json settings.local.json

# 2. One-time: register the SPN in all environments
.\Setup-SPNPermissions.ps1

# 3. Run the impact analysis (interactive)
.\Analyze-DLPImpact.ps1

# Optional: also include resources that use no connectors
.\Analyze-DLPImpact.ps1 -ShowAllResources

# Optional: override the output CSV path
.\Analyze-DLPImpact.ps1 -OutputCsv "C:\Reports\dlp.csv"
```

### Parameters (`Analyze-DLPImpact.ps1`)

| Parameter | Description |
| --------- | ----------- |
| `-TenantId` | Tenant ID. Falls back to `settings.json`. |
| `-ApplicationId` | SPN client ID. Falls back to `settings.json`. |
| `-ClientSecret` | SPN client secret. Falls back to `settings.json`. |
| `-OutputCsv` | Output CSV path. Defaults to `output/DLP_Impact_<timestamp>.csv`. |
| `-DebugFolder` | Folder for the debug transcript. Defaults to `debug`. |
| `-ShowAllResources` | Also include resources without connectors in the report. |

## Project structure

```
Analyze-DLPImpact.ps1      Main analysis script
Setup-SPNPermissions.ps1   One-time SPN registration
settings.local.json        Local credentials, preferred (git-ignored)
settings.json              Local credentials, fallback (git-ignored)
settings.sample.json       Template for the settings file
output/                    Generated CSV reports
debug/                     Debug transcript logs and Debug-BotConnectors.ps1
```

## Security notes

- Never commit `settings.json` with a real client secret. It is git-ignored by
  default.
- If a client secret is ever exposed, rotate it in Entra ID
  (App registrations -> your app -> Certificates & secrets) and update your local
  `settings.json`.
- The SPN is granted high-privilege roles (`System Administrator`,
  `Environment Admin`). Restrict who can access the credentials accordingly.
