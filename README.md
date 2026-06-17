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

## Output

The script writes a CSV report and a debug transcript:

- **CSV report** — saved to the `output` folder by default, named
  `DLP_Impact_<timestamp>.csv`. Each row contains:
  `PolicyName`, `PolicyId`, `EnvironmentName`, `EnvironmentId`, `ResourceType`,
  `ResourceName`, `ResourceId`, `Owner`, `State`, `ConnectorsUsed`,
  `ConnectorGroups`, `DlpViolation`, `ViolationReason`.
- **Debug log** — a full PowerShell transcript saved to the `debug` folder,
  named `DLP_Debug_<timestamp>.log`.

A summary of total resources, violations, and unaffected resources is printed to
the console at the end of the run.

## Configuration

Configuration is read from `settings.json` (copy `settings.sample.json` to start):

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

`settings.json` is excluded from source control via `.gitignore` because it holds
real credentials. Keep the secret only in your local copy.

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
# 1. Create your settings file and fill in real credentials
Copy-Item settings.sample.json settings.json

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
settings.json              Local credentials (git-ignored)
settings.sample.json       Template for settings.json
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
