# Security policy

TenantWise reads who can access what in Microsoft Azure and Entra ID. That information is sensitive, so the app is
built to read as little as needed, keep it on your PC and make tampering visible. This page explains how, and how to
report a problem.

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue:

1. Open the repository's **Security** tab and choose **Report a vulnerability**
   (GitHub private vulnerability reporting).
2. Describe the issue, the affected version and how to reproduce it. Please don't include real tenant data.

What to expect:

| Step | Target |
| --- | --- |
| Acknowledgement | within 5 working days |
| First assessment | within 14 days |
| Fix and release | depends on severity; critical issues get priority |
| Disclosure | coordinated with you once a fixed version is available; you're credited unless you prefer not to be |

TenantWise is maintained by one person in their own time, so these are goals, not contractual commitments.

## Supported versions

| Version | Security fixes |
| --- | --- |
| Latest 1.x release | Yes |
| Older releases | No; please update |

## Security model

**Read-only by design**
- TenantWise only reads: Azure Resource Graph queries and GET requests to Azure Resource Manager and Microsoft Graph.
  It changes nothing in your tenant, with one exception a Global Administrator controls: who may use TenantWise (see below).
- It signs in with *delegated* permissions, so it can never see more than the signed-in person may see.
  Requested scopes: Azure Service Management `user_impersonation`; Microsoft Graph `Directory.Read.All`,
  `RoleManagement.Read.Directory`, `Policy.Read.All`; optionally `EntitlementManagement.Read.All`,
  `PrivilegedEligibilitySchedule.Read.AzureADGroup`, `AuditLog.Read.All`. All are read-only.

**Your own app registration**
- Every organization registers TenantWise in its own tenant (single tenant). There is no shared, publisher-controlled
  registration: the organization decides the app's permissions, can revoke them at any time, and no outside party is
  trusted. TenantWise has no client secret: it's a public client that only signs people in.

**Sign-in**
- Microsoft's own sign-in (MSAL with the Windows account broker): passwords, MFA and Conditional Access are handled
  by Microsoft. TenantWise never sees a password.
- TenantWise does not write tokens to disk itself; token caching is handled by Microsoft's libraries and Windows.

**Who can use what**
- Only Global Administrators can use TenantWise until they give others features in TenantWise's *Users* dashboard,
  per group or per person. Each sign-in checks the Global Administrator role live and reads the person's features from
  the ID token; the app hides and refuses everything else. Each sign-in is logged with its features.
- The ticks are stored as app role assignments on TenantWise's own enterprise application. Writing them is the only
  change TenantWise ever makes in a tenant: only when a Global Administrator saves, with `AppRoleAssignment.ReadWrite.All`
  (and once `Application.ReadWrite.All` to add the features to TenantWise's app registration), requested at that moment
  and never at a normal sign-in. The code only ever targets TenantWise's own application. Changes are logged.
- Features limit what TenantWise lets someone do, not what their own Azure and Entra rights let them read with other tools.

**Your data stays on your PC**
- No telemetry, no analytics, no update checks, no TenantWise servers. The app talks only to Microsoft sign-in,
  Azure Resource Manager and Microsoft Graph.
- Scans, audit scope, access reviews, the list of tenants and settings are encrypted at rest with Windows DPAPI for the
  signed-in Windows user (`%LOCALAPPDATA%\TenantWise`). Other users of the PC can't read them.
- Switching tenant always signs out first; every tenant needs a fresh Microsoft sign-in. The tenant list holds no
  passwords or tokens.
- Presentation mode replaces people's names and emails with placeholders on screen and in exports, for demos.
- Exports (reports, CSV, signed reviews) are written only where you choose, unencrypted, so other tools can open them.
  They name people with administrative rights: treat them as confidential.

**Evidence integrity**
- Every scan records who ran it, when, with which version and what could not be read.
- Scans and exported files get a SHA-256 fingerprint. Sign-ins, scans, comparisons, exports and review sign-offs are
  written to a hash-chained activity log; the app verifies the chain and reports any edited, removed or reordered entry.

**The app itself**
- The interface runs in Microsoft Edge WebView2 from a local folder. Navigation to any other address is blocked and
  opened in your normal browser instead; developer tools are disabled in release builds.
- A Content Security Policy stops the page from contacting the internet: no requests, remote images, fonts, frames or
  forms. All libraries, icons and the font are embedded.
- Messages from the page are only accepted from the app's own local origin, and file names are checked before anything
  is written.
- The installer installs for the current user only and needs no administrator rights. No app ID is built in.

## Verifying a download

- Releases are built from the tagged source by GitHub Actions; the build log is public on the release's workflow run.
- Each release includes `SHA256SUMS.txt`. Check a file with PowerShell: `Get-FileHash .\TenantWise-Setup-<version>.exe`
  and compare the hash.
- Releases are code-signed through SignPath Foundation, after manual approval of each signing request
  ([code signing policy](CODE_SIGNING.md)). Check the signature: `Get-AuthenticodeSignature <file>`.

## Dependencies

- Cytoscape.js, a selection of Fluent UI System Icons and the Inter typeface are embedded (see `THIRD-PARTY-NOTICES.txt`).
- The Windows app uses Microsoft Authentication Library (MSAL), Microsoft Edge WebView2 and System.Text.Json from NuGet.
- Dependabot watches the NuGet packages and the build actions for updates.

## Recommendations for administrators

- Scan with an account that has *Reader* (made PIM-eligible if you use PIM) rather than a standing admin account.
- Grant admin consent only for the permissions you need; the optional ones can be added later.
- Keep exported reports and signed reviews in a protected location, such as your evidence repository.
- Keep TenantWise updated; only the latest release receives security fixes.
