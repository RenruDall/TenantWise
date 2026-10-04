#Requires -Version 7.0
<#
.SYNOPSIS
    Round-trip test: the real TenantWise scanner (C#) against a fake Azure + Entra tenant served over HTTP.

.DESCRIPTION
    - fake_tenant.py  builds the fictional tenant and the API responses it would produce (raw.json) plus expected.json
    - fake_server.py  serves those responses as Resource Graph, ARM and Microsoft Graph (tokens, paging, 429s, 403s)
    - this script compiles src/TenantWise.Core with the test host, scans the fake tenant and checks that every
      resource, connection, identity, role assignment, group member, policy and CA policy comes back exactly —
      nothing missing, nothing extra — and that the HTTP behaviour was right (right token per service, throttling
      retried, no unknown calls).

    Run:  python tests/fake_tenant.py tests/out
          python tests/free_tenant.py tests/out
          pwsh tests/Test-TenantWise.ps1
#>
param([string]$Fixtures = (Join-Path $PSScriptRoot 'out'), [string]$SaveScan)   # -SaveScan <file>: keep the scan result (for trying the page)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$exp = Get-Content (Join-Path $Fixtures 'expected.json') -Raw | ConvertFrom-Json -Depth 20
$raw = Get-Content (Join-Path $Fixtures 'raw.json') -Raw | ConvertFrom-Json -Depth 50
$failures = [System.Collections.Generic.List[string]]::new()

function Check([string]$Name, $Expected, $Actual) {
    $e = @($Expected | ForEach-Object { [string]$_ }); $a = @($Actual | ForEach-Object { [string]$_ })
    $missing = @([Linq.Enumerable]::Except([string[]]$e, [string[]]$a))
    $extra   = @([Linq.Enumerable]::Except([string[]]$a, [string[]]$e))
    if (-not $missing -and -not $extra -and $e.Count -eq $a.Count) { Write-Host ("  PASS  {0,-34} {1,6}" -f $Name, $e.Count) -ForegroundColor Green; return }
    $script:failures.Add($Name)
    Write-Host ("  FAIL  {0,-34} expected {1}, got {2}" -f $Name, $e.Count, $a.Count) -ForegroundColor Red
    $missing | Select-Object -First 8 | ForEach-Object { Write-Host "          missing: $_" -ForegroundColor Red }
    $extra   | Select-Object -First 8 | ForEach-Object { Write-Host "          extra:   $_" -ForegroundColor Red }
}
function Expect([string]$Name, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { Write-Host ("  PASS  {0,-34} {1}" -f $Name, $Detail) -ForegroundColor Green }
    else { $script:failures.Add($Name); Write-Host ("  FAIL  {0,-34} {1}" -f $Name, $Detail) -ForegroundColor Red }
}
# dates come back as DateTime from ConvertFrom-Json; compare them in the fixture's format
function Day($v) { if ($null -eq $v -or $v -eq '') { '' } elseif ($v -is [datetime]) { $v.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } else { [string]$v } }
$edgeKey = { param($e) if ($e.rel -eq 'peered') { 'peered|' + ((@($e.s, $e.t) | Sort-Object) -join '|') } else { "$($e.rel)|$($e.s)|$($e.t)" } }
$ncKey = { param($nc) if (-not $nc) { '' } else { ($nc.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ',' } }

# ------------------------------------------------------------ compile the engine + test host
Write-Host "`nCompiling src/TenantWise.Core with the test host" -ForegroundColor White
$files = @(Get-ChildItem (Join-Path $root 'src/TenantWise.Core/*.cs')) + @(Get-Item (Join-Path $PSScriptRoot 'TestHost.cs'))
$usings = [System.Collections.Generic.SortedSet[string]]::new()
$bodies = foreach ($f in $files) {
    $lines = Get-Content $f
    foreach ($l in $lines) { if ($l -match '^using [\w\.]+;') { [void]$usings.Add($l) } }
    ($lines | Where-Object { $_ -notmatch '^using [\w\.]+;' }) -join "`n"
}
$refs = 'System.Net.Http', 'System.Net.Primitives', 'System.Text.Json', 'System.Text.RegularExpressions', 'System.Linq', 'System.Collections',
        'System.Runtime', 'System.Private.CoreLib', 'System.Memory', 'System.Threading', 'System.Threading.Tasks', 'System.Private.Uri', 'System.Console', 'System.Security.Cryptography', 'System.Text.Encoding.Extensions', 'System.IO.FileSystem', 'System.Runtime.Extensions'
Add-Type -TypeDefinition (($usings -join "`n") + "`n" + ($bodies -join "`n")) -Language CSharp -CompilerOptions '-langversion:9.0' -ReferencedAssemblies $refs
Write-Host '  compiled' -ForegroundColor DarkGray

# ------------------------------------------------------------ fake Azure + Entra
$probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
$python = (Get-Command python3 -ErrorAction SilentlyContinue) ?? (Get-Command python)
$server = Start-Process $python.Source -ArgumentList (Join-Path $PSScriptRoot 'fake_server.py'), (Join-Path $Fixtures 'raw.json'), $port -PassThru -NoNewWindow
$base = "http://127.0.0.1:$port"
try {
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) { try { Invoke-RestMethod "$base/stats" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Milliseconds 200 } }

    # ============================================================ scan
    Write-Host "`nScanning the fake tenant over HTTP" -ForegroundColor White
    $json = [TenantWise.Tests.TestHost]::Run($base, $raw.tenantId, $true, 'fake-arm-token', 'fake-graph-token', $false)
    if ($SaveScan) { Set-Content -Path $SaveScan -Value $json -Encoding utf8 }
    $result = $json | ConvertFrom-Json -Depth 30
    $d = $result.data; $st = $result.stats
    Write-Host ("  scan took {0}s: {1} Resource Graph queries, {2} ARM calls, {3} Graph calls, {4} retries after throttling" -f `
        $st.seconds, $st.resourceGraphQueries, $st.armCalls, $st.graphCalls, $st.retries) -ForegroundColor DarkGray
    $srv = Invoke-RestMethod "$base/stats"

    Write-Host "`nResult" -ForegroundColor White
    Check 'Nodes (id, type, parent, name)' ($exp.nodes | ForEach-Object { "$($_.id)|$($_.type)|$($_.parent)|$($_.name)" }) `
                                           ($d.nodes   | ForEach-Object { "$($_.id)|$($_.type)|$($_.parent)|$($_.name)" })
    Check 'External nodes'                 ($exp.nodes | Where-Object external | ForEach-Object id) ($d.nodes | Where-Object external | ForEach-Object id)
    Check 'Connections'                    ($exp.edges | ForEach-Object { & $edgeKey $_ } | Sort-Object -Unique) ($d.edges | ForEach-Object { & $edgeKey $_ })
    Expect 'Excluded types filtered'       (-not ($d.nodes | Where-Object { $_.type -match '/extensions$|/virtualnetworklinks$' })) 'VM extensions, DNS links'
    Expect 'Route table → firewall links'  (@($d.edges | Where-Object { $_.rel -eq 'routes to' -and $_.s -match '/routetables/' }).Count -gt 0) 'resolved from next-hop IPs'
    Check 'Identities (id, kind, name)'    ($exp.principals | ForEach-Object { "$($_.id)|$($_.kind)|$($_.name)" }) ($d.access.principals | ForEach-Object { "$($_.id)|$($_.kind)|$($_.name)" })
    Check 'Guests'                         $exp.guests ($d.access.principals | Where-Object guest | ForEach-Object id)
    Check 'Disabled accounts'              $exp.disabled ($d.access.principals | Where-Object disabled | ForEach-Object id)
    Check 'Last sign-in'                   ($exp.lastSignIn.PSObject.Properties | ForEach-Object { "$($_.Name)|$(Day $_.Value)" }) `
                                           ($d.access.principals | Where-Object { $_.kind -eq 'user' -and -not $_.unresolved } | ForEach-Object { "$($_.id)|$(Day $_.lastSignIn)" })
    $pv = $d.meta.provenance
    Expect 'Provenance recorded'           ($pv.account -eq 'auditor@test.example' -and $pv.readOnly -and $pv.counts.identities -eq @($d.access.principals).Count -and
                                            $pv.requests.graphCalls -gt 0 -and $pv.started -and $pv.finished) "who, when, sources, counts"
    Check 'Azure roles (active + PIM)'     ($exp.azure | ForEach-Object { "$($_.p)|$($_.role)|$($_.scope)|$($_.status)|$(Day $_.until)" }) ($d.access.azure | ForEach-Object { "$($_.p)|$($_.role)|$($_.scope)|$($_.status)|$(Day $_.until)" })
    Check 'Entra roles (active + PIM)'     ($exp.entra | ForEach-Object { "$($_.p)|$($_.role)|$($_.status)|$($_.priv)|$(Day $_.until)" }) ($d.access.entra | ForEach-Object { "$($_.p)|$($_.role)|$($_.status)|$($_.priv)|$(Day $_.until)" })
    Check 'Access packages → groups'       ($exp.packages | ForEach-Object { "$($_.id)|$($_.name)|$($_.catalog)|" + ((@($_.groups) | Sort-Object) -join ',') }) `
                                           ($d.access.packages | ForEach-Object { "$($_.id)|$($_.name)|$($_.catalog)|" + ((@($_.groups) | Sort-Object) -join ',') })
    Check 'Access package assignments'     ($exp.packageAssignments | ForEach-Object { "$($_.p)|$($_.pkg)|$(Day $_.until)" }) ($d.access.packageAssignments | ForEach-Object { "$($_.p)|$($_.pkg)|$(Day $_.until)" })
    Check 'Pending package requests'       ($exp.packageRequests | ForEach-Object { "$($_.p)|$($_.pkg)" }) ($d.access.packageRequests | ForEach-Object { "$($_.p)|$($_.pkg)" })
    Check 'PIM for Groups (eligible)'      ($exp.groupEligible | ForEach-Object { "$($_.g)|$($_.p)|$(Day $_.until)" }) ($d.access.groupEligible | ForEach-Object { "$($_.g)|$($_.p)|$(Day $_.until)" })
    Check 'Group members'                  ($exp.members.PSObject.Properties | ForEach-Object { "$($_.Name)=" + ((@($_.Value) | Sort-Object) -join ',') }) `
                                           ($d.access.members.PSObject.Properties | ForEach-Object { "$($_.Name)=" + ((@($_.Value) | Sort-Object) -join ',') })
    Check 'Policies (+ non-compliance)'    ($exp.policies | ForEach-Object { "$($_.id)|$($_.name)|$($_.scope)|$($_.enforce)|$($_.initiative)|$(& $ncKey $_.nonCompliant)" }) `
                                           ($d.access.policies | ForEach-Object { "$($_.id)|$($_.name)|$($_.scope)|$($_.enforce)|$($_.initiative)|$(& $ncKey $_.nonCompliant)" })
    Check 'Conditional Access policies'    $exp.ca ($d.access.ca | ForEach-Object name)
    Check 'Nested groups'                  ($exp.nested.PSObject.Properties | ForEach-Object { "$($_.Name)=" + ((@($_.Value) | Sort-Object) -join ',') }) `
                                           ($d.access.nested.PSObject.Properties | ForEach-Object { "$($_.Name)=" + ((@($_.Value) | Sort-Object) -join ',') })
    Check 'Owners of privileged groups'    ($exp.groupOwners.PSObject.Properties | ForEach-Object { "$($_.Name)=" + ((@($_.Value) | Sort-Object) -join ',') }) `
                                           ($d.access.groupOwners.PSObject.Properties | ForEach-Object { "$($_.Name)=" + ((@($_.Value) | Sort-Object) -join ',') })
    Check 'App registrations'              ($exp.apps | ForEach-Object { "$($_.appId)|$($_.name)|$($_.sp)|$($_.creds)|" + ((@($_.owners) | Sort-Object) -join ',') }) `
                                           ($d.access.apps | ForEach-Object { "$($_.appId)|$($_.name)|$($_.sp)|$(@($_.creds).Count)|" + ((@($_.owners) | Sort-Object) -join ',') })
    Expect 'Secret and certificate dates'  (@($d.access.apps | ForEach-Object { $_.creds } | Where-Object { -not $_.end -or $_.t -notin 'secret', 'cert' }).Count -eq 0) 'every credential has a type and an end date'
    Check 'Graph application permissions'  $exp.appPerms ($d.access.appPerms | ForEach-Object { "$($_.p)|$($_.perm)|$([bool]$_.external)" })
    Check 'Cross-tenant partners'          $exp.crossTenant ($d.access.crossTenant.partners | ForEach-Object { "$($_.tenantId)|$($_.mfa)|$($_.device)|$($_.b2bIn)" })
    Expect 'Tenant domain'                 ($d.meta.tenantDomain -eq $exp.tenantDomain) $d.meta.tenantDomain
    Expect 'Tenant name'                   ($d.meta.tenantName -eq $exp.tenantName) $d.meta.tenantName
    Expect 'Denied management group noted' (@($d.meta.warnings | Where-Object { $_ -match $exp.deniedWarning }).Count -gt 0) "$(@($d.meta.warnings).Count) scan notes"

    Write-Host "`nWho can use TenantWise" -ForegroundColor White
    $acc = { param($step) [TenantWise.Tests.TestHost]::Access($base, $exp.twClient, $step) }
    $tw = & $acc 'read' | ConvertFrom-Json -Depth 10
    Expect 'Setup read; missing features found' ($tw.found -and -not $tw.assignmentRequired -and (($tw.missingRoles | Sort-Object) -join ',') -eq (($exp.twMissing | Sort-Object) -join ',')) (($tw.missingRoles) -join ', ')
    Check  'Feature assignments'           $exp.twAssignments ($tw.assignments | ForEach-Object { "$($_.principalId)|$($_.role)" })
    Check  'Assigned group expanded'       $exp.twGroupMembers ($tw.groupMembers.($exp.twGroup) | ForEach-Object id)
    Expect 'Global Administrator detected' ((& $acc 'ga') -eq 'true') 'signed-in person holds Global Administrator'
    $found = & $acc "search:$($exp.twSearch)" | ConvertFrom-Json
    Expect 'Directory search for the picker' (@($found | Where-Object id -eq $exp.twUser30).Count -eq 1) "$(@($found).Count) found for '$($exp.twSearch)'"
    Expect 'Missing features added'        ((& $acc 'setup') -eq '3' -and @((& $acc 'read' | ConvertFrom-Json -Depth 10).missingRoles).Count -eq 0) 'only TenantWise roles; the app''s other role kept'
    Expect 'Setup again changes nothing'   ((& $acc 'setup') -eq '0') 'idempotent'
    Expect 'Group lead gets an extra'      ((& $acc "apply:$($exp.twLead):TenantWise.Export:+") -eq '1/0') 'Export for one member of the group'
    Expect 'Same tick twice: no duplicate' ((& $acc "apply:$($exp.twLead):TenantWise.Export:+") -eq '0/0') ''
    Expect 'Taking a feature away'         ((& $acc "apply:$($exp.twUser30):TenantWise.Findings:-") -eq '0/1') ''
    $after = & $acc 'read' | ConvertFrom-Json -Depth 10
    Expect 'Entra reflects the changes'    (@($after.assignments | Where-Object { $_.principalId -eq $exp.twLead -and $_.role -eq 'TenantWise.Export' }).Count -eq 1 -and
                                            @($after.assignments | Where-Object { $_.principalId -eq $exp.twUser30 -and $_.role -eq 'TenantWise.Findings' }).Count -eq 0) 'read back'
    $err = $null; try { & $acc "apply:$($exp.twLead):Other.Role:+" | Out-Null } catch { $err = $_.Exception.InnerException ?? $_.Exception }
    Expect 'Only TenantWise features'      ($err -and $err.Message -match 'Unknown TenantWise feature') 'other roles refused'
    $srvW = Invoke-RestMethod "$base/stats"
    Expect 'Writes used the write permission' ($srvW.unauthorized -eq 0 -and @($srvW.writes).Count -eq 3) (@($srvW.writes) -join ', ')

    Write-Host "`nHTTP behaviour" -ForegroundColor White
    Expect 'Right token for each service'  ($srv.unauthorized -eq 0) "$($srv.requests) requests"
    Expect 'Throttling (429) retried'      ($srv.throttled -gt 0 -and $st.retries -eq $srv.throttled) "$($srv.throttled) throttled, $($st.retries) retried"
    Expect 'No unknown calls'              (@($srv.unknown).Count -eq 0) ((@($srv.unknown) | Select-Object -First 3) -join '; ')
    Expect 'Well-formed requests'          (@($srv.badRequests).Count -eq 0) ((@($srv.badRequests) | Select-Object -First 3) -join '; ')
    Expect 'Paging used'                   ($srv.arg -gt $st.resourceGraphQueries -and $srv.graph -gt 10) "$($srv.arg) Resource Graph pages for $($st.resourceGraphQueries) queries"

    Write-Host "`nFailure handling" -ForegroundColor White
    $err = $null
    try { [TenantWise.Tests.TestHost]::Run($base, $raw.tenantId, $true, 'expired-token', 'fake-graph-token', $true) | Out-Null } catch { $err = $_.Exception.InnerException ?? $_.Exception }
    Expect 'Bad token stops with 401'      ($err -and $err.Message -match '401') $(if ($err) { $err.Message.Split("`n")[0] } else { 'no error' })
    $azOnly = [TenantWise.Tests.TestHost]::Run($base, $raw.tenantId, $true, 'fake-arm-token', 'wrong-graph-token', $true) | ConvertFrom-Json -Depth 30
    Expect 'No Graph access: Azure only'   (@($azOnly.data.nodes).Count -eq @($d.nodes).Count -and @($azOnly.data.access.entra).Count -eq 0 -and
                                            @($azOnly.data.meta.warnings | Where-Object { $_ -match 'Directory role' }).Count -gt 0) 'resources kept, Entra parts noted as skipped'
} finally {
    if (-not $server.HasExited) { $server.Kill() }
}

# ============================================================ a brand-new free tenant: the edge cases of a first real scan
Write-Host "`nA brand-new free tenant (no management groups, no premium licences, personal-account owner)" -ForegroundColor White
$freeExp = Get-Content (Join-Path $Fixtures 'free-expected.json') -Raw | ConvertFrom-Json -Depth 20
$freeRaw = Get-Content (Join-Path $Fixtures 'free-raw.json') -Raw | ConvertFrom-Json -Depth 50
$probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $probe.Start(); $port2 = $probe.LocalEndpoint.Port; $probe.Stop()
$server2 = Start-Process $python.Source -ArgumentList (Join-Path $PSScriptRoot 'fake_server.py'), (Join-Path $Fixtures 'free-raw.json'), $port2 -PassThru -NoNewWindow
$base2 = "http://127.0.0.1:$port2"
try {
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) { try { Invoke-RestMethod "$base2/stats" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Milliseconds 200 } }
    $json2 = [TenantWise.Tests.TestHost]::Run($base2, $freeRaw.tenantId, $true, 'fake-arm-token', 'fake-graph-token', $true)
    if ($SaveScan) { Set-Content -Path ([IO.Path]::ChangeExtension($SaveScan, '.free.json')) -Value $json2 -Encoding utf8 }
    $f = ($json2 | ConvertFrom-Json -Depth 30).data
    $srv2 = Invoke-RestMethod "$base2/stats"
    Check  'Nodes'                         $freeExp.nodes ($f.nodes | ForEach-Object id)
    Expect 'Subscription under tenant root' (($f.nodes | Where-Object cat -eq 'sub').parent -eq $freeExp.subParent) 'no management group hierarchy yet'
    Check  'Connections'                   $freeExp.edges ($f.edges | ForEach-Object { "$($_.rel)|$($_.s)|$($_.t)" })
    Check  'Azure roles'                   $freeExp.azure ($f.access.azure | ForEach-Object { "$($_.p)|$($_.role)|$($_.scope)|$($_.status)" })
    Check  'Entra roles'                   $freeExp.entra ($f.access.entra | ForEach-Object { "$($_.p)|$($_.role)|$($_.status)" })
    $me = $f.access.principals | Where-Object id -eq $freeExp.me
    Expect 'Owner with #EXT# is no guest'  ($me -and -not $me.guest) "$($me.upn)"
    Expect 'Tenant name'                   ($f.meta.tenantName -eq $freeExp.tenantName) $f.meta.tenantName
    foreach ($n in $freeExp.notes) { Expect "Noted: $n" (@($f.meta.warnings | Where-Object { $_ -match [regex]::Escape($n) }).Count -gt 0) 'skipped, not failed' }
    Expect 'No unknown calls'              (@($srv2.unknown).Count -eq 0) ((@($srv2.unknown) | Select-Object -First 3) -join '; ')
} catch {
    $failures.Add('Free tenant scan'); Write-Host "  FAIL  Free tenant scan: $($_.Exception.InnerException.Message ?? $_.Exception.Message)" -ForegroundColor Red
} finally {
    if (-not $server2.HasExited) { $server2.Kill() }
}

# ============================================================ app roles: what each person may use
Write-Host "`nApp roles" -ForegroundColor White
function Jwt($payload) { $b = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress)); 'eyJhbGciOiJub25lIn0.' + [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') + '.sig' }
$r = [TenantWise.Core.AppAccess]::RolesFromIdToken((Jwt @{ roles = @('TenantWise.Auditor', 'TenantWise.Export'); name = 'Ünïcode Tëst ✓' }))
Expect 'Roles read from the ID token'   (($r -join ',') -eq 'TenantWise.Auditor,TenantWise.Export') ($r -join ', ')
Expect 'Broken token: no roles'         (@([TenantWise.Core.AppAccess]::RolesFromIdToken('garbage')).Count -eq 0) 'no crash'
$d = [TenantWise.Core.AppAccess]::Decide($false, [string[]]@())
Expect 'Default: no access'             (-not $d.Allows('findings') -and -not $d.CanManage -and $d.Note) 'only Global Administrators until someone is given features'
$d = [TenantWise.Core.AppAccess]::Decide($true, [string[]]@())
Expect 'Global Administrator: everything' ($d.Allows('export') -and $d.Allows('signoff') -and $d.CanManage) 'and manages access'
$d = [TenantWise.Core.AppAccess]::Decide($false, [string[]]@('TenantWise.Findings', 'TenantWise.Export', 'TenantWise.Findings', 'Something.Else'))
Expect 'Features add up'                (($d.Features -join ',') -eq 'findings,export' -and -not $d.Allows('audit') -and -not $d.CanManage) ($d.Features -join ', ')
$page = Get-Content (Join-Path $root 'tenantwise.template.html') -Raw
$pageRoles = [regex]::Matches($page, '\["(TenantWise\.\w+)", "([0-9a-f-]{36})", "[^"]*", "[^"]*", "(\w+)"\]') | ForEach-Object { "$($_.Groups[1].Value)|$($_.Groups[2].Value)|$($_.Groups[3].Value)" }
$coreRoles = [TenantWise.Core.AppAccess]::Roles | ForEach-Object { "$($_.Value)|$($_.Id)|$($_.Feature)" }
Check 'Page and app use the same roles' $coreRoles $pageRoles

# ============================================================ evidence: hashes and the tamper-evident activity log
Write-Host "`nEvidence integrity" -ForegroundColor White
Expect 'SHA-256 (known value)'          ([TenantWise.Core.EvidenceLog]::Sha256Hex('abc') -eq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') 'FIPS 180-2 test vector'
$logFile = Join-Path ([IO.Path]::GetTempPath()) "tenantwise-test-$([guid]::NewGuid()).log"
try {
    $log = [TenantWise.Core.EvidenceLog]::new($logFile)
    foreach ($a in 'signed.in', 'scan.completed', 'export.saved', 'review.signed') { [void]$log.Append($a, $null) }
    $v = $log.Verify()
    Expect 'Activity log chain intact'     ($v.Item1 -and $v.Item2 -eq 4) "$($v.Item2) entries"
    $lines = Get-Content $logFile
    $lines[1] = $lines[1].Replace('scan.completed', 'scan.deleted'); Set-Content $logFile $lines
    $v = $log.Verify()
    Expect 'Edited entry detected'         (-not $v.Item1 -and $v.Item3 -match 'Line 2') $v.Item3
    Set-Content $logFile ($lines[0], $lines[2], $lines[3])
    $v = [TenantWise.Core.EvidenceLog]::new($logFile).Verify()
    Expect 'Removed entry detected'        (-not $v.Item1) $v.Item3
} finally { Remove-Item $logFile -ErrorAction SilentlyContinue }

Write-Host ''
if ($failures.Count) { Write-Host "$($failures.Count) check(s) failed: $($failures -join ', ')" -ForegroundColor Red; exit 1 }
Write-Host 'All checks passed.' -ForegroundColor Green
