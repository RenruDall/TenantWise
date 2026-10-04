# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

## What is signed

Only files built from this repository's source:

- `TenantWise.exe` and `TenantWise.Core.dll` (the program itself)
- `TenantWise-Setup-<version>.exe` (the installer)

Third-party files shipped with TenantWise (Microsoft Authentication Library, WebView2, System.Text.Json and their
dependencies) are not re-signed; they keep their publishers' own signatures.

## How a release is signed

1. A version tag (`v*`) starts the [GitHub Actions workflow](.github/workflows/main.yml) on GitHub's own Windows runners.
2. The workflow runs the tests, builds the program, and sends the program files to SignPath.
3. Each signing request is **approved manually** by an approver before anything is signed.
4. The signed program files are packed into the installer and the portable zip; the installer is signed the same way.
5. The release is published with `SHA256SUMS.txt`. The build log of every release is public.

Nothing is signed from a developer's PC.

## Team roles

| Role | Who |
|---|---|
| Committers and reviewers | [Michael Ladurner (@RenruDall)](https://github.com/RenruDall) |
| Approvers | [Michael Ladurner (@RenruDall)](https://github.com/RenruDall) |

Contributions from others come in as pull requests and are reviewed before they are merged.
All team members use multi-factor authentication for GitHub and SignPath.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user
or the person installing or operating it.

In detail: TenantWise connects only to Microsoft's own services, and only when the signed-in person signs in or starts
a scan — Microsoft sign-in (`login.microsoftonline.com`), Azure Resource Manager (`management.azure.com`) and
Microsoft Graph (`graph.microsoft.com`). It has no telemetry, no analytics, no update checks and no TenantWise servers.
Scans and settings stay encrypted on the PC (Windows DPAPI). See [SECURITY.md](SECURITY.md).

## Verifying a download

- Right-click the file → *Properties* → *Digital Signatures*: the signer is **SignPath Foundation**.
- Or in PowerShell: `Get-AuthenticodeSignature .\TenantWise-Setup-<version>.exe`
- Compare the SHA-256 hash with `SHA256SUMS.txt` in the release: `Get-FileHash .\TenantWise-Setup-<version>.exe`

## Reporting

Suspect a file signed in TenantWise's name that didn't come from this repository's releases? Report it as described in
[SECURITY.md](SECURITY.md).
