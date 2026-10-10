// TenantWise.App — MainWindow.cs
// The app window: hosts the TenantWise page in WebView2 and answers its requests (sign in, scan, open a scan,
// save a report, load an older scan to compare, save the audit report or CSV, audit scope, access reviews, the list of tenants
// scanned on this PC, settings, sign out and switch tenant).
// Everything stays on this PC under %LOCALAPPDATA%\TenantWise: scans, audit scope and reviews encrypted for the current
// Windows user (DPAPI). The page itself is served from memory, so no decrypted copy is written to disk. Every sign-in,
// scan, export and review sign-off is recorded in the activity log, whose head is printed into every export.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using TenantWise.Core;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

namespace TenantWise.App
{
    public sealed class MainWindow : Window
    {
        private const string Host = "tenantwise.app";
        private const string CdnTag = "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js\"></script>";
        private const string IconsTag = "<script src=\"lib/tenantwise-icons.js\"></script>";
        private const string FontTag = "<link rel=\"stylesheet\" href=\"lib/tenantwise-font.css\">";
        private const int KeepScans = 30;

        private static readonly string DataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TenantWise");
        private static readonly string LegacyViewDir = Path.Combine(DataDir, "view");             // versions before 1.3 wrote the page here
        private static readonly string SettingsFile = Path.Combine(DataDir, "settings.json");
        private static readonly string TenantsFile = Path.Combine(DataDir, "tenants.dat");        // encrypted: names, IDs, accounts, scan summaries
        private static readonly string PrefsFile = Path.Combine(DataDir, "preferences.dat");      // encrypted: views, columns, thresholds
        private const int KeepSummaries = 30;
        private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        private static readonly string AnchorFile = Path.Combine(DataDir, "activity.anchor");     // encrypted: line count + last hash of the log
        private static readonly string LogCopyFile = Path.Combine(DataDir, "logcopy.dat");        // encrypted: where the log is copied to, if anywhere
        private static readonly EvidenceLog Activity = new EvidenceLog(Path.Combine(DataDir, "activity.log"),
            () => File.Exists(AnchorFile) ? Protect.ReadText(AnchorFile) : null, a => Protect.WriteText(AnchorFile, a));

        // Links TenantWise may open in the browser. Anything else (for example from a name in a scan) is ignored.
        private static readonly string[] ExternalHosts = { "github.com", "portal.azure.com", "entra.microsoft.com", "login.microsoftonline.com",
            "go.microsoft.com", "learn.microsoft.com", "aka.ms", "sharepoint.com" };
        private static string Version => Assembly.GetExecutingAssembly().GetName().Version.ToString(3);

        private readonly WebView2 _web = new WebView2();
        private Auth _auth;
        private string _tenantName;
        private string _current;
        private CancellationTokenSource _scanCts;
        private JsonObject _prefill;
        private AccessDecision _access = AppAccess.Decide(false, null);   // which TenantWise features this person may use
        private byte[] _page = new byte[0];                                // the current page, served from memory
        private CoreWebView2Environment _env;
        private readonly HashSet<string> _reviewEvidence = new HashSet<string>(StringComparer.OrdinalIgnoreCase); // access-review files saved this session

        public MainWindow()
        {
            Title = "TenantWise";
            Width = 1440; Height = 900; MinWidth = 820; MinHeight = 560;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Content = _web;
            using (var icon = Resource("tenantwise.ico")) Icon = BitmapFrame.Create(icon, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
            Loaded += async (s, e) => await InitAsync();
            Closing += (s, e) => { _scanCts?.Cancel(); _page = new byte[0]; };
        }

        // The app was called Rootline before 1.0: carry its local data (scans, reviews, activity log) over once.
        private static void MoveLegacyData()
        {
            try
            {
                var legacy = Path.Combine(Path.GetDirectoryName(DataDir), "Rootline");
                if (Directory.Exists(legacy) && !Directory.Exists(DataDir)) Directory.Move(legacy, DataDir);
            }
            catch (Exception) { /* the old folder stays where it is; nothing is lost */ }
        }

        // ------------------------------------------------------------------ start-up
        private async Task InitAsync()
        {
            MoveLegacyData();
            try { if (File.Exists(LogCopyFile)) Activity.CopyPath = Protect.ReadText(LogCopyFile); } catch (Exception) { }
            try { if (Directory.Exists(LegacyViewDir)) Directory.Delete(LegacyViewDir, true); }   // a decrypted page left by an older version
            catch (Exception) { }
            try
            {
                Directory.CreateDirectory(DataDir);
                _env = await CoreWebView2Environment.CreateAsync(null, Path.Combine(DataDir, "WebView2"));
                await _web.EnsureCoreWebView2Async(_env);
            }
            catch (WebView2RuntimeNotFoundException)
            {
                MessageBox.Show(this, "TenantWise needs the Microsoft Edge WebView2 Runtime, which is part of Windows 11 and most Windows 10 PCs.\n\n" +
                    "Install it from https://go.microsoft.com/fwlink/p/?LinkId=2124703 and open TenantWise again.", "TenantWise", MessageBoxButton.OK, MessageBoxImage.Warning);
                Close();
                return;
            }
            var core = _web.CoreWebView2;
#if !DEBUG
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.AreDefaultContextMenusEnabled = false;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;
#endif
            core.Settings.IsStatusBarEnabled = false;
            try { core.Settings.IsGeneralAutofillEnabled = false; core.Settings.IsPasswordAutosaveEnabled = false; } catch (Exception) { /* older runtime */ }
            // The page is answered from memory: nothing decrypted is written to disk, and nothing is cached.
            core.AddWebResourceRequestedFilter("https://" + Host + "/*", CoreWebView2WebResourceContext.All);
            core.WebResourceRequested += OnResource;
            core.WebMessageReceived += OnMessage;
            core.NewWindowRequested += (s, e) => { e.Handled = true; OpenExternal(e.Uri); };
            core.NavigationStarting += (s, e) =>
            {
                if (!e.Uri.StartsWith("https://" + Host + "/", StringComparison.OrdinalIgnoreCase)) { e.Cancel = true; OpenExternal(e.Uri); }
            };
            core.DownloadStarting += (s, e) => { e.Cancel = true; e.Handled = true; };          // files are saved only through the app
            core.PermissionRequested += (s, e) => { e.State = CoreWebView2PermissionState.Deny; };
            try { await core.Profile.ClearBrowsingDataAsync(CoreWebView2BrowsingDataKinds.DiskCache); } catch (Exception) { /* older runtime */ }

            Log("app.started", new JsonObject { ["version"] = Version });
            ShowView();
        }

        private void OnResource(object sender, CoreWebView2WebResourceRequestedEventArgs e)
        {
            var path = new Uri(e.Request.Uri).AbsolutePath;
            byte[] body = null; string type = null;
            if (path == "/index.html") { body = _page; type = "text/html; charset=utf-8"; }
            else if (path == "/cytoscape.min.js")
            {
                using (var r = Resource("cytoscape.min.js")) using (var m = new MemoryStream()) { r.CopyTo(m); body = m.ToArray(); }
                type = "text/javascript; charset=utf-8";
            }
            e.Response = body == null
                ? _env.CreateWebResourceResponse(null, 404, "Not Found", "Cache-Control: no-store")
                : _env.CreateWebResourceResponse(new MemoryStream(body), 200, "OK", "Content-Type: " + type + "\r\nCache-Control: no-store");
        }

        /// <summary>Records an action in the activity log (who, on which PC, which account and tenant). Never blocks the app.</summary>
        private void Log(string action, JsonObject details = null)
        {
            try
            {
                var d = new JsonObject { ["windowsUser"] = Environment.UserDomainName + "\\" + Environment.UserName, ["machine"] = Environment.MachineName,
                    ["account"] = _auth?.Account, ["tenant"] = _auth?.TenantId, ["app"] = "TenantWise " + Version };
                if (details != null) foreach (var kv in details.ToList()) { details.Remove(kv.Key); d[kv.Key] = kv.Value; }
                Activity.Append(action, d);
            }
            catch (Exception) { /* logging must never stop the work */ }
        }

        // ------------------------------------------------------------------ the page
        private void ShowView()
        {
            string data = null;
            var mayRead = _access.GlobalAdmin || _access.Features.Length > 0;                   // no feature: no scan data in the page
            if (_auth != null && _auth.SignedIn && _current != null && mayRead) data = ReadSnapshot(_current);
            var scanHash = data != null ? EvidenceLog.Sha256Hex(data) : null;
            if (data == null)
            {
                _current = null;
                data = new JsonObject
                {
                    ["meta"] = new JsonObject { ["title"] = "TenantWise", ["empty"] = true, ["tenantId"] = _auth?.TenantId, ["entra"] = _auth?.GraphOk ?? false,
                        ["generated"] = DateTime.UtcNow.ToString("o"), ["scope"] = "", ["warnings"] = new JsonArray() },
                    ["nodes"] = new JsonArray(), ["edges"] = new JsonArray(), ["access"] = null
                }.ToJsonString();
            }
            var app = new JsonObject
            {
                ["native"] = true,
                ["version"] = Version,
                ["signedIn"] = _auth != null && _auth.SignedIn,
                ["lastClientId"] = LastClientId(),
                ["account"] = _auth?.Account,
                ["tenantId"] = _auth?.TenantId,
                ["tenantName"] = _tenantName,
                ["entra"] = _auth?.GraphOk ?? false,
                ["entraProblem"] = _auth?.GraphProblem,
                ["consentUrl"] = _auth?.SignedIn == true ? _auth.AdminConsentUrl : null,
                ["snapshots"] = new JsonArray(Snapshots().Select(s => (JsonNode)new JsonObject { ["name"] = s, ["label"] = Label(s) }).ToArray()),
                ["current"] = _current,
                ["scanSha256"] = scanHash,
                ["auditSettings"] = ReadAudit("settings"),
                ["review"] = _current != null && mayRead ? ReadAudit("reviews\\" + _current) : null,
                ["protectedAtRest"] = true,
                ["tenants"] = TenantsForPage(),
                ["prefs"] = ReadPrefs(),
                ["prefill"] = _prefill?.DeepClone(),
                ["dataDir"] = DataDir,
                ["access"] = _access.ToJson()
            };
            _page = new UTF8Encoding(false).GetBytes(Page(data, app.ToJsonString(), inlineLibrary: false));
            _web.CoreWebView2.Navigate($"https://{Host}/index.html?v={DateTime.UtcNow.Ticks}");
        }

        private static string Page(string dataJson, string appJson, bool inlineLibrary)
        {
            string template;
            using (var r = new StreamReader(Resource("tenantwise.template.html"), Encoding.UTF8)) template = r.ReadToEnd();
            string lib;
            if (inlineLibrary)
                using (var r = new StreamReader(Resource("cytoscape.min.js"), Encoding.UTF8)) lib = "<script>" + r.ReadToEnd().Replace("</script", "<\\/script") + "</script>";
            else lib = "<script src=\"cytoscape.min.js\"></script>";
            string icons;
            using (var r = new StreamReader(Resource("tenantwise-icons.js"), Encoding.UTF8)) icons = "<script>" + r.ReadToEnd().Replace("</script", "<\\/script") + "</script>";
            string font;
            using (var r = new StreamReader(Resource("tenantwise-font.css"), Encoding.UTF8)) font = "<style id=\"tw-font\">" + r.ReadToEnd() + "</style>";

            // Only TenantWise's own scripts may run: each gets this page's one-time nonce; no inline handlers, no CDN.
            var nonceBytes = new byte[18];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(nonceBytes);
            var nonce = Convert.ToBase64String(nonceBytes);
            var scriptSrc = (inlineLibrary ? "" : "'self' ") + "'nonce-" + nonce + "'";
            template = template.Replace("script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com", "script-src " + scriptSrc);
            template = template.Replace(CdnTag, lib).Replace(IconsTag, icons).Replace(FontTag, font)
                .Replace("<script>", "<script nonce=\"" + nonce + "\">").Replace("<script src=", "<script nonce=\"" + nonce + "\" src=");

            // Scan data comes from the tenant: escaping "/" keeps "</script>" and the markers below from ever appearing in it
            // (inside JSON strings "\/" is the same character).
            return template
                .Replace("/*__DATA__*/null", dataJson.Replace("/", "\\/"))
                .Replace("/*__APP__*/null", appJson.Replace("/", "\\/"));
        }

        /// <summary>A line for the end of every exported report: where the activity log stood, so the copy can be checked later.</summary>
        private string EvidenceFooter()
        {
            var (lines, hash, since) = Activity.Head();
            return "<p class=\"meta\" style=\"margin-top:24px;font-size:11px;color:#555\">Evidence: saved with TenantWise " + Version +
                " by " + Html(_auth?.Account) + " (Windows user " + Html(Environment.UserDomainName + "\\" + Environment.UserName) + " on " + Html(Environment.MachineName) +
                "). Activity log at saving: entry " + lines + ", SHA-256 " + hash + (since > 0 ? ", anchored since entry " + since : ", not anchored") +
                ". Times are UTC from this PC's clock.</p>";
        }

        private static string Html(string s) => System.Net.WebUtility.HtmlEncode(s ?? "");

        private static string WithFooter(string html, string footer)
        {
            var i = html.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
            return i < 0 ? html + footer : html.Substring(0, i) + footer + html.Substring(i);
        }

        // ------------------------------------------------------------------ requests from the page
        private async void OnMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            if (!e.Source.StartsWith("https://" + Host + "/", StringComparison.OrdinalIgnoreCase)) return;
            JsonObject msg;
            try { msg = JsonNode.Parse(e.WebMessageAsJson) as JsonObject; } catch (Exception) { return; }
            if (msg == null) return;
            var id = Api.Str(msg["id"]);
            var cmd = Api.Str(msg["cmd"]);
            var args = msg["args"] as JsonObject ?? new JsonObject();
            try
            {
                JsonNode result = null;
                var reload = false;
                switch (cmd)
                {
                    case "signIn":
                        await SignInAsync(Api.Str(args["email"]), Api.Str(args["tenant"]), Api.Str(args["clientId"]));
                        await DecideAccessAsync();
                        OpenNewestScan();
                        Log("signed.in", new JsonObject { ["graph"] = _auth.GraphOk,
                            ["roles"] = new JsonArray(_access.Roles.Select(r => (JsonNode)JsonValue.Create(r)).ToArray()), ["globalAdmin"] = _access.GlobalAdmin });
                        _prefill = null;
                        UpsertTenant(_auth.TenantId, t =>
                        {
                            t["account"] = _auth.Account; t["lastSignIn"] = DateTime.UtcNow.ToString("o"); t["clientId"] = _auth.ClientId;
                            if (!string.IsNullOrEmpty(_tenantName)) t["name"] = _tenantName;
                        });
                        reload = true; break;
                    case "scan":
                        if (!_access.GlobalAdmin && _access.Features.Length == 0) throw new InvalidOperationException(_access.Note);
                        result = await ScanAsync(); reload = true; break;
                    case "dirSearch":                                    // users and groups for the access dashboard
                        Manage();
                        result = await AppAccess.SearchAsync(new Api(Http, _auth), Api.Str(args["q"]), CancellationToken.None);
                        break;
                    case "setupRoles":                                   // adds TenantWise's feature roles to its own app registration
                    {
                        Manage();
                        var n = await AppAccess.SetupRolesAsync(new Api(Http, _auth), _auth.ClientId, CancellationToken.None);
                        Log("access.setup", new JsonObject { ["rolesAdded"] = n });
                        result = await AccessInfoAsync();
                        break;
                    }
                    case "applyAccess":                                  // ticks from the access dashboard → app role assignments
                    {
                        Manage();
                        var changes = (args["changes"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().Select(c => new AppAccess.Change
                            { PrincipalId = Api.Str(c["principalId"]), Role = Api.Str(c["role"]), Grant = c["grant"]?.GetValue<bool>() == true }).ToList();
                        if (changes.Count > 500) throw new InvalidOperationException("Too many changes at once.");
                        var progress = new AppAccess.ApplyProgress();
                        string failure = null;
                        try { await AppAccess.ApplyAsync(new Api(Http, _auth), _auth.ClientId, changes, CancellationToken.None, progress); }
                        catch (Exception ex) { failure = ex.Message; throw; }
                        finally
                        {
                            if (progress.Done.Count > 0)
                                Log("access.changed", new JsonObject { ["granted"] = progress.Granted, ["removed"] = progress.Removed, ["stoppedBy"] = failure,
                                    ["changes"] = new JsonArray(progress.Done.Select(c => (JsonNode)JsonValue.Create(c)).ToArray()) });
                        }
                        result = await AccessInfoAsync();
                        break;
                    }
                    case "appAccess":                                    // who can use TenantWise, and which features
                    {
                        Manage();
                        result = await AccessInfoAsync();
                        break;
                    }
                    case "download":                                    // the whole scan as an offline page
                        Need("export", "saving reports");
                        if (!_access.GlobalAdmin && AppAccess.AllFeatures.Except(new[] { "signoff", "export" }).Any(f => !_access.Allows(f)))
                            throw new InvalidOperationException("A saved report contains the whole scan, so it needs every view (map, access, apps, findings, audit). Export the parts you have instead.");
                        if (!Snapshots().Contains(Api.Str(args["name"]))) throw new InvalidOperationException("That scan isn't available.");
                        result = SaveReport(Api.Str(args["name"])); break;
                    case "savePng":                                     // a picture of the map or network
                        Need("export", "exporting");
                        result = SavePng(Api.Str(args["name"]), Api.Str(args["dataUrl"])); break;
                    case "open":                                        // an older scan from the picker
                    {
                        var name = Api.Str(args["name"]);
                        if (_auth?.SignedIn != true || !Snapshots().Contains(name)) throw new InvalidOperationException("That scan isn't available.");
                        _current = name;
                        Log("scan.opened", new JsonObject { ["scan"] = name });
                        reload = true; break;
                    }
                    case "signOut":
                        Log("signed.out");
                        if (_auth != null) await _auth.SignOutAsync(); _current = null; _tenantName = null; _prefill = null;
                        _access = AppAccess.Decide(false, null); reload = true; break;
                    case "switchTenant":                                 // sign out; the next sign-in is a fresh one, with MFA
                    {
                        var to = Api.Str(args["tenantId"]);
                        var rec = to == null ? null : ReadTenants().OfType<JsonObject>().FirstOrDefault(x => Api.Str(x["tenantId"]) == to);
                        Log("tenant.switch", new JsonObject { ["to"] = to });
                        if (_auth != null) await _auth.SignOutAsync();
                        _current = null; _tenantName = null; _access = AppAccess.Decide(false, null);
                        _prefill = rec == null ? null : new JsonObject { ["tenant"] = to, ["email"] = Api.Str(rec["account"]), ["clientId"] = Api.Str(rec["clientId"]) };
                        reload = true; break;
                    }
                    case "removeTenant":
                    {
                        var tid = (Api.Str(args["tenantId"]) ?? "").ToLowerInvariant();
                        if (!Guid.TryParse(tid, out _)) throw new InvalidOperationException("Unknown tenant.");
                        if (_auth?.SignedIn == true && string.Equals(_auth.TenantId, tid, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidOperationException("You're signed in to this tenant. Switch to another one first.");
                        var deleted = args["deleteData"]?.GetValue<bool>() == true;
                        if (deleted && MessageBox.Show(this, "Delete the scans and drafts of this tenant from this PC?\n\nSigned-off access reviews and their scans are kept: they are audit evidence.",
                                "TenantWise", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK)
                        { result = new JsonObject { ["cancelled"] = true, ["tenants"] = TenantsForPage() }; break; }
                        var list = ReadTenants();
                        foreach (var x in list.OfType<JsonObject>().Where(x => Api.Str(x["tenantId"]) == tid).ToList()) list.Remove(x);
                        WriteTenants(list);
                        var kept = deleted ? DeleteTenantData(tid) : 0;
                        Log("tenant.removed", new JsonObject { ["removedTenant"] = tid, ["deletedData"] = deleted, ["signedReviewsKept"] = kept });
                        result = new JsonObject { ["tenants"] = TenantsForPage() };
                        break;
                    }
                    case "tenantSummary":                                // a short summary of the open scan, for the Tenants view and trends
                    {
                        var scan = Api.Str(args["scan"]);
                        if (_auth?.SignedIn != true || scan == null || scan != _current) throw new InvalidOperationException("Open a scan first.");
                        var entry = new JsonObject { ["scan"] = scan, ["time"] = Api.Str(args["time"]) };
                        foreach (var k in new[] { "high", "medium", "low", "info", "score" })
                            entry[k] = int.TryParse(Api.Str(args[k]), out var n) ? Math.Max(0, Math.Min(n, 100000)) : 0;
                        var grade = Api.Str(args["grade"]) ?? "";
                        entry["grade"] = grade.Length == 1 && "ABCDE".Contains(grade) ? grade : "";
                        entry["reviewSigned"] = Api.Str(ReadAudit("reviews\\" + scan)?["signedOff"]?["time"]);   // from the saved review, not the page
                        UpsertTenant(_auth.TenantId, t =>
                        {
                            var h = t["history"] as JsonArray ?? new JsonArray();
                            var keep = h.OfType<JsonObject>().Where(x => Api.Str(x["scan"]) != scan).Select(x => x.DeepClone()).ToList();
                            keep.Add(entry);
                            t["history"] = new JsonArray(keep.OrderByDescending(x => Api.Str(x["scan"]), StringComparer.Ordinal).Take(KeepSummaries).ToArray());
                            var dom = Api.Str(args["domain"]);
                            if (!string.IsNullOrEmpty(dom) && dom.Length < 256) t["domain"] = dom;
                            if (!string.IsNullOrEmpty(_tenantName)) t["name"] = _tenantName;
                        });
                        result = new JsonObject { ["tenants"] = TenantsForPage() };
                        break;
                    }
                    case "savePrefs":                                    // what to show: views, columns, thresholds, presentation mode
                    {
                        var prefs = args["prefs"] as JsonObject ?? throw new InvalidOperationException("No settings to save.");
                        var text = prefs.ToJsonString();
                        if (text.Length > 65536) throw new InvalidOperationException("Settings are too large.");
                        Protect.WriteText(PrefsFile, text);
                        Log("settings.changed", new JsonObject { ["presentationMode"] = prefs["mask"]?.DeepClone(), ["hiddenViews"] = prefs["hidden"]?.DeepClone() });
                        reload = true; break;
                    }
                    case "openExternal": OpenExternal(Api.Str(args["url"])); break;
                    case "load":                                        // an older scan, for "Changes"
                        Need("audit", "comparing scans");
                        var olderName = Api.Str(args["name"]);
                        var older = (Snapshots().Contains(olderName) ? ReadSnapshot(olderName) : null) ?? throw new InvalidOperationException("That scan no longer exists.");
                        Log("scan.compared", new JsonObject { ["scan"] = _current, ["with"] = Api.Str(args["name"]), ["withSha256"] = EvidenceLog.Sha256Hex(older) });
                        result = JsonNode.Parse(older);
                        break;
                    case "saveText":
                    {
                        var kind = Api.Str(args["kind"]) ?? "";
                        var reviewFile = kind == "access-review" || kind == "access-review-csv";
                        if (reviewFile) { Need("audit", "access reviews"); Need("signoff", "signing off access reviews"); }
                        else Need("export", "exporting");
                        var saved = SaveText(Api.Str(args["name"]), Api.Str(args["text"]), reviewFile ? kind : "export");
                        if (reviewFile && saved?["sha256"] != null && kind == "access-review") _reviewEvidence.Add(Api.Str(saved["sha256"]));
                        result = saved;
                        break;
                    }
                    case "saveSettings":                                 // audit scope: in-scope and production subscriptions
                        Need("audit", "the audit scope");
                        if ((args["settings"]?.ToJsonString() ?? "").Length > 262144) throw new InvalidOperationException("Audit scope is too large.");
                        WriteAudit("settings", args["settings"] as JsonObject ?? new JsonObject());
                        Log("scope.changed", new JsonObject { ["inScope"] = (args["settings"]?["inScope"] as JsonArray)?.Count ?? 0,
                            ["production"] = (args["settings"]?["production"] as JsonArray)?.Count ?? 0, ["microsoft365"] = args["settings"]?["m365"]?.DeepClone() });
                        break;
                    case "saveReview":                                   // access review draft or sign-off, kept with its scan
                    {
                        if (_current == null) throw new InvalidOperationException("Open a scan first.");
                        var review = args["review"] as JsonObject ?? throw new InvalidOperationException("No review to save.");
                        Need("audit", "access reviews");
                        if (review.ToJsonString().Length > 4 * 1024 * 1024) throw new InvalidOperationException("The review is too large.");
                        var existing = ReadAudit("reviews\\" + _current);
                        var existingSign = existing?["signedOff"] as JsonObject;
                        var incomingSign = review["signedOff"] as JsonObject;
                        if (existingSign != null)
                        {
                            if (incomingSign != null && Api.Str(incomingSign["evidenceSha256"]) == Api.Str(existingSign["evidenceSha256"]))
                                break;                                   // the signed review again: it stays as it was signed
                            if (incomingSign != null) throw new InvalidOperationException("This review is already signed off. Start a new review to change decisions.");
                            // a new review: the signed one is kept as a version of its own, never overwritten
                            var version = _current + "~" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
                            WriteAudit("reviews\\" + version, existing);
                            Log("review.reopened", new JsonObject { ["scan"] = _current, ["signedReviewKeptAs"] = version, ["evidenceSha256"] = Api.Str(existingSign["evidenceSha256"]) });
                        }
                        if (incomingSign != null)
                        {
                            Need("signoff", "signing off access reviews");
                            var evidence = Api.Str(incomingSign["evidenceSha256"]);
                            if (evidence == null || !_reviewEvidence.Contains(evidence))
                                throw new InvalidOperationException("Save the review evidence with TenantWise before signing off.");
                            var named = (Api.Str(incomingSign["reviewer"]) ?? "").Trim();
                            review["signedOff"] = new JsonObject
                            {
                                ["reviewer"] = _auth.Account,                // the signed-in account, as Microsoft confirmed it
                                ["onBehalfOf"] = named.Length > 0 && !string.Equals(named, _auth.Account, StringComparison.OrdinalIgnoreCase) ? named : null,
                                ["time"] = DateTime.UtcNow.ToString("o"),
                                ["summary"] = Api.Str(incomingSign["summary"]),
                                ["evidenceSha256"] = evidence,
                                ["selfReviewed"] = int.TryParse(Api.Str(incomingSign["selfReviewed"]), out var own) ? own : 0,
                                ["populationSha256"] = Api.Str(incomingSign["populationSha256"]),
                                // what the review covered (subscriptions, Microsoft 365 options), so the signed population stays as it was
                                ["scope"] = incomingSign["scope"] is JsonObject signScope && signScope.ToJsonString().Length < 65536 ? signScope.DeepClone() : null,
                                ["scanSha256"] = EvidenceLog.Sha256Hex(ReadSnapshot(_current) ?? "")
                            };
                        }
                        WriteAudit("reviews\\" + _current, review);
                        if (review["signedOff"] is JsonObject so)
                        {
                            Log("review.signed", new JsonObject { ["scan"] = _current, ["reviewer"] = Api.Str(so["reviewer"]), ["onBehalfOf"] = Api.Str(so["onBehalfOf"]),
                                ["decisions"] = Api.Str(so["summary"]), ["evidenceSha256"] = Api.Str(so["evidenceSha256"]), ["scanSha256"] = Api.Str(so["scanSha256"]) });
                            result = new JsonObject { ["signedOff"] = so.DeepClone() };
                        }
                        break;
                    }
                    case "activity":
                        Need("audit", "the activity log");
                        var v = Activity.Verify();
                        var copy = Activity.CheckCopy();
                        result = new JsonObject
                        {
                            ["verified"] = v.Ok && copy.Ok, ["lines"] = v.Lines, ["problem"] = v.Problem ?? (copy.Ok ? null : copy.Note), ["anchoredSince"] = v.AnchoredSince,
                            ["copyPath"] = Activity.CopyPath, ["copyNote"] = copy.Note, ["path"] = Path.Combine(DataDir, "activity.log"),
                            ["entries"] = new JsonArray(Activity.Recent(300, _auth?.TenantId).Cast<JsonNode>().ToArray())
                        };
                        break;
                    case "logCopy":                                     // copy every log entry to a folder of your choice, or stop
                    {
                        Need("audit", "the activity log");
                        if (Api.Str(args["action"]) == "stop")
                        {
                            Log("log.copy.stopped", new JsonObject { ["copy"] = Activity.CopyPath });
                            Activity.CopyPath = null;
                            if (File.Exists(LogCopyFile)) File.Delete(LogCopyFile);
                        }
                        else
                        {
                            string folder = null;
                            using (var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = "Folder for a copy of TenantWise's activity log (for example a network share your SIEM collects)", ShowNewFolderButton = true })
                                if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK) folder = dlg.SelectedPath;
                            if (folder == null) { result = new JsonObject { ["cancelled"] = true }; break; }
                            var file = Path.Combine(folder, "TenantWise-activity-" + Environment.MachineName + "-" + Environment.UserName + ".log");
                            Activity.StartCopy(file);
                            Protect.WriteText(LogCopyFile, file);
                            Log("log.copy.started", new JsonObject { ["copy"] = file });
                        }
                        result = new JsonObject { ["copyPath"] = Activity.CopyPath };
                        break;
                    }
                    default: throw new InvalidOperationException("Unknown request " + cmd);
                }
                Reply(id, true, result, null);
                if (reload) ShowView();
            }
            catch (Exception ex)
            {
                Reply(id, false, null, ex is InvalidOperationException ? ex.Message : Auth.Explain(ex));
            }
        }

        private void Manage()
        {
            if (!_access.CanManage) throw new InvalidOperationException("Only Global Administrators of this tenant can manage who uses TenantWise.");
            if (_auth?.GraphOk != true) throw new InvalidOperationException("Entra can't be read with this sign-in.");
        }

        private async Task<JsonObject> AccessInfoAsync()
        {
            var info = await AppAccess.ReadAsync(new Api(Http, _auth), _auth.ClientId, CancellationToken.None);
            var used = new JsonObject();
            foreach (var entry in Activity.Recent(5000, _auth.TenantId).Where(x => Api.Str(x["action"]) == "signed.in"))
            {
                var acct = (Api.Str(entry["account"]) ?? "").ToLowerInvariant();
                if (acct.Length > 0 && !used.ContainsKey(acct)) used[acct] = Api.Str(entry["time"]);
            }
            info["lastUsedOnThisPc"] = used;
            return info;
        }

        /// <summary>Refuses an action the person's TenantWise role doesn't include (the page hides it too).</summary>
        private void Need(string feature, string what)
        {
            if (!_access.Allows(feature))
                throw new InvalidOperationException($"Your TenantWise role doesn't include {what}. Ask a TenantWise administrator.");
        }

        /// <summary>Global Administrators may use everything; everyone else what their TenantWise roles (ID token) give.</summary>
        private async Task DecideAccessAsync()
        {
            var ga = false;
            if (_auth.GraphOk)
                try { ga = await AppAccess.IsGlobalAdminAsync(new Api(Http, _auth), CancellationToken.None); }
                catch (Exception) { /* can't tell: not an administrator */ }
            _access = AppAccess.Decide(ga, _auth.TokenRoles);
            if (!ga && _access.Features.Length == 0 && !_auth.GraphOk)
                _access.Note = "TenantWise can't read Entra with this sign-in, so it can't check your access. " + (_auth.GraphProblem ?? "");
        }

        private void Reply(string id, bool ok, JsonNode result, string error)
        {
            _web.CoreWebView2.PostWebMessageAsJson(new JsonObject { ["type"] = "reply", ["id"] = id, ["ok"] = ok, ["result"] = result, ["error"] = error }.ToJsonString());
        }

        private void ReportProgress(string text)
        {
            _web.CoreWebView2?.PostWebMessageAsJson(new JsonObject { ["type"] = "progress", ["text"] = text }.ToJsonString());
        }

        /// <summary>Each organization registers TenantWise in its own tenant (single tenant), so every sign-in names the
        /// app (client) ID of that tenant's registration and the tenant itself (from the email domain unless given).</summary>
        private async Task SignInAsync(string email, string tenant, string clientId)
        {
            clientId = (clientId ?? "").Trim();
            if (clientId.Length == 0) throw new InvalidOperationException("Enter the app (client) ID of TenantWise's app registration in your tenant.");
            if (!Guid.TryParse(clientId, out _)) throw new InvalidOperationException("The app (client) ID should look like 00000000-0000-0000-0000-000000000000.");
            tenant = (tenant ?? "").Trim();
            if (tenant.Length == 0)
            {
                var at = (email ?? "").LastIndexOf('@');
                tenant = at > 0 ? email.Substring(at + 1).Trim() : "";
            }
            if (tenant.Length == 0) throw new InvalidOperationException("Enter your work email (or the tenant's domain under Advanced).");
            // The window handle is read once, on the UI thread: MSAL asks for it again later from background threads
            // (Graph consent after sign-in, "Manage access"), and WPF objects may only be touched by their own thread.
            var hwnd = Dispatcher.CheckAccess() ? new WindowInteropHelper(this).Handle : Dispatcher.Invoke(() => new WindowInteropHelper(this).Handle);
            _auth = new Auth(clientId, () => hwnd);
            await _auth.SignInAsync(email, tenant, CancellationToken.None);
            SaveClientId(clientId);
            _tenantName = null;
            _current = null;
        }

        /// <summary>After sign-in: the newest scan this person may open (their own; every scan for a Global Administrator).</summary>
        private void OpenNewestScan()
        {
            _current = Snapshots().FirstOrDefault();
            if (_current != null)
                try { _tenantName = Api.Str(JsonNode.Parse(ReadSnapshot(_current))?["meta"]?["tenantName"]); } catch (Exception) { }
        }

        private async Task<JsonNode> ScanAsync()
        {
            if (_auth == null || !_auth.SignedIn) throw new InvalidOperationException("Sign in first.");
            _scanCts = new CancellationTokenSource();
            var api = new Api(Http, _auth);
            var scanner = new Scanner(api, new ScanOptions { TenantId = _auth.TenantId, Entra = _auth.GraphOk, Account = _auth.Account, ToolVersion = Version },
                new Progress<string>(ReportProgress));
            var data = await Task.Run(() => scanner.ScanAsync(_scanCts.Token));
            if (!_auth.GraphOk && _auth.GraphProblem != null)
                (data["meta"]["warnings"] as JsonArray)?.Add("Entra not read: " + _auth.GraphProblem);
            var name = DateTime.Now.ToString("yyyy-MM-dd_HHmmss", CultureInfo.InvariantCulture);
            var dir = SnapshotDir();
            var json = data.ToJsonString();
            Protect.WriteText(Path.Combine(dir, name + ".scan"), json);
            Protect.WriteText(Path.Combine(dir, name + ".owner"), (_auth.Account ?? "").ToLowerInvariant());   // whose scan it is
            var pv = data["meta"]?["provenance"];
            Log("scan.completed", new JsonObject { ["scan"] = name, ["sha256"] = EvidenceLog.Sha256Hex(json),
                ["complete"] = pv?["complete"]?.DeepClone(), ["notes"] = (data["meta"]?["warnings"] as JsonArray)?.Count ?? 0, ["counts"] = pv?["counts"]?.DeepClone() });
            // keep the newest scans, but never one whose access review was signed off: that is audit evidence
            var signed = SignedScans(AuditDir("reviews"));
            foreach (var old in AllSnapshots().Skip(KeepScans).Where(n => !signed.Contains(n)))
                foreach (var ext in new[] { ".scan", ".json", ".owner" }) { var f = Path.Combine(dir, old + ext); if (File.Exists(f)) File.Delete(f); }
            _current = name;
            _tenantName = Api.Str(data["meta"]?["tenantName"]) ?? _tenantName;
            var domain = Api.Str(data["meta"]?["tenantDomain"]);
            UpsertTenant(_auth.TenantId, t =>
            {
                if (!string.IsNullOrEmpty(_tenantName)) t["name"] = _tenantName;
                if (!string.IsNullOrEmpty(domain)) t["domain"] = domain;
                t["lastScan"] = name;
            });
            return new JsonObject { ["name"] = name };
        }

        private JsonNode SaveReport(string name)
        {
            var data = ReadSnapshot(name) ?? throw new InvalidOperationException("That scan no longer exists.");
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save an offline copy of this scan",
                FileName = $"tenantwise_{name}.html",
                Filter = "Web page (*.html)|*.html",
                DefaultExt = ".html"
            };
            if (dlg.ShowDialog(this) != true) return new JsonObject { ["cancelled"] = true };
            // The offline page keeps this person's features and presentation mode (masked names), and says where the log stood.
            var reportApp = new JsonObject
            {
                ["report"] = true, ["version"] = Version, ["account"] = _auth?.Account, ["scanSha256"] = EvidenceLog.Sha256Hex(data),
                ["prefs"] = ReadPrefs(), ["access"] = _access.ToJson(), ["auditSettings"] = ReadAudit("settings"), ["review"] = ReadAudit("reviews\\" + name)
            };
            var features = (reportApp["access"]["features"] as JsonArray)?.Select(Api.Str).Where(f => f != "admin").ToArray() ?? new string[0];
            reportApp["access"]["features"] = new JsonArray(features.Select(f => (JsonNode)JsonValue.Create(f)).ToArray());   // "who uses TenantWise" isn't in a report
            var bytes = new UTF8Encoding(false).GetBytes(WithFooter(Page(data, reportApp.ToJsonString(), inlineLibrary: true), EvidenceFooter()));
            File.WriteAllBytes(dlg.FileName, bytes);
            var sha = EvidenceLog.Sha256Hex(bytes);
            Log("report.saved", new JsonObject { ["scan"] = name, ["file"] = dlg.FileName, ["sha256"] = sha });
            return new JsonObject { ["path"] = dlg.FileName, ["sha256"] = sha };
        }

        /// <summary>Saves a file the page made (audit report or CSV) where the user chooses.</summary>
        private JsonNode SaveText(string name, string text, string kind)
        {
            name = Path.GetFileName(name ?? "");
            var ext = Path.GetExtension(name).ToLowerInvariant();
            if (text == null || (ext != ".html" && ext != ".csv")) throw new InvalidOperationException("Can only save .html or .csv files.");
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = ext == ".csv" ? "Save the access list" : "Save the audit report",
                FileName = name,
                Filter = ext == ".csv" ? "CSV for Excel (*.csv)|*.csv" : "Web page (*.html)|*.html",
                DefaultExt = ext
            };
            if (dlg.ShowDialog(this) != true) return new JsonObject { ["cancelled"] = true };
            if (ext == ".html") text = WithFooter(text, EvidenceFooter());              // where the activity log stood
            var enc = new UTF8Encoding(ext == ".csv");                                  // BOM so Excel reads UTF-8
            var bytes = enc.GetPreamble().Concat(enc.GetBytes(text)).ToArray();
            File.WriteAllBytes(dlg.FileName, bytes);
            var sha = EvidenceLog.Sha256Hex(bytes);                                     // auditors can re-hash the file and compare
            Log("export.saved", new JsonObject { ["kind"] = kind ?? ext.TrimStart('.'), ["scan"] = _current, ["file"] = dlg.FileName, ["sha256"] = sha });
            return new JsonObject { ["path"] = dlg.FileName, ["sha256"] = sha };
        }

        /// <summary>Saves a picture the page drew (map or network) where the user chooses.</summary>
        private JsonNode SavePng(string name, string dataUrl)
        {
            const string prefix = "data:image/png;base64,";
            if (dataUrl == null || !dataUrl.StartsWith(prefix, StringComparison.Ordinal)) throw new InvalidOperationException("Not a picture.");
            var bytes = Convert.FromBase64String(dataUrl.Substring(prefix.Length));
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save a picture", FileName = Path.GetFileName(name ?? "tenantwise.png"), Filter = "PNG picture (*.png)|*.png", DefaultExt = ".png"
            };
            if (dlg.ShowDialog(this) != true) return new JsonObject { ["cancelled"] = true };
            File.WriteAllBytes(dlg.FileName, bytes);
            var sha = EvidenceLog.Sha256Hex(bytes);
            Log("export.saved", new JsonObject { ["kind"] = "picture", ["scan"] = _current, ["file"] = dlg.FileName, ["sha256"] = sha });
            return new JsonObject { ["path"] = dlg.FileName, ["sha256"] = sha };
        }

        /// <summary>Scans whose access review was signed off (also earlier signed versions), from a tenant's reviews folder.</summary>
        private static HashSet<string> SignedScans(string reviewsDir)
        {
            var signed = new HashSet<string>(StringComparer.Ordinal);
            if (!Directory.Exists(reviewsDir)) return signed;
            foreach (var f in Directory.GetFiles(reviewsDir, "*.dat"))
            {
                try
                {
                    if ((JsonNode.Parse(Protect.ReadText(f)) as JsonObject)?["signedOff"] != null)
                        signed.Add(Path.GetFileNameWithoutExtension(f).Split('~')[0]);
                }
                catch (Exception) { /* unreadable: treat as unsigned */ }
            }
            return signed;
        }

        /// <summary>Deletes a tenant's scans and drafts from this PC, keeping signed-off reviews and their scans. Returns how many were kept.</summary>
        private static int DeleteTenantData(string tid)
        {
            var reviews = Path.Combine(DataDir, "audit", tid, "reviews");
            var signed = SignedScans(reviews);
            var scans = Path.Combine(DataDir, "snapshots", tid);
            if (Directory.Exists(scans))
                foreach (var f in Directory.GetFiles(scans))
                    if (!signed.Contains(Path.GetFileNameWithoutExtension(f))) File.Delete(f);
            var audit = Path.Combine(DataDir, "audit", tid);
            if (Directory.Exists(audit))
                foreach (var f in Directory.GetFiles(audit, "*", SearchOption.AllDirectories))
                {
                    var keep = false;
                    if (string.Equals(Path.GetDirectoryName(f), reviews, StringComparison.OrdinalIgnoreCase))
                        try { keep = (JsonNode.Parse(Protect.ReadText(f)) as JsonObject)?["signedOff"] != null; } catch (Exception) { keep = true; }
                    if (!keep) File.Delete(f);
                }
            return signed.Count;
        }

        // ------------------------------------------------------------------ storage
        private string SnapshotDir() => Path.Combine(DataDir, "snapshots", (_auth?.TenantId ?? "unknown").ToLowerInvariant());

        /// <summary>Every scan of the signed-in tenant on this PC, newest first.</summary>
        private List<string> AllSnapshots()
        {
            if (_auth == null || !_auth.SignedIn || !Directory.Exists(SnapshotDir())) return new List<string>();
            return Directory.GetFiles(SnapshotDir()).Where(f => f.EndsWith(".scan", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                .Select(Path.GetFileNameWithoutExtension).Where(IsSnapshotName).Distinct()
                .OrderByDescending(n => n, StringComparer.Ordinal).ToList();
        }

        /// <summary>The scans this person may open: their own; every scan for a Global Administrator. A scan shows what its
        /// account could read, so someone else's scan could show more than this person may see.</summary>
        private List<string> Snapshots()
        {
            var all = AllSnapshots();
            if (_access.GlobalAdmin) return all;
            var me = (_auth?.Account ?? "").ToLowerInvariant();
            return all.Where(n => OwnerOf(n) == me).ToList();
        }

        /// <summary>The account that made a scan. Scans from before 1.3 have no owner file: it's taken from the scan once.</summary>
        private string OwnerOf(string name)
        {
            var f = Path.Combine(SnapshotDir(), name + ".owner");
            try
            {
                if (File.Exists(f)) return Protect.ReadText(f);
                var data = ReadSnapshot(name);
                var owner = (Api.Str(JsonNode.Parse(data ?? "{}")?["meta"]?["provenance"]?["account"]) ?? "").ToLowerInvariant();
                if (owner.Length > 0) Protect.WriteText(f, owner);
                return owner;
            }
            catch (Exception) { return ""; }
        }

        // per-tenant audit scope and access reviews, encrypted like the scans
        private string AuditDir(string sub = null) =>
            Path.Combine(DataDir, "audit", (_auth?.TenantId ?? "unknown").ToLowerInvariant(), sub ?? "");

        private JsonObject ReadAudit(string name)
        {
            try
            {
                var f = Path.Combine(AuditDir(), name + ".dat");
                return _auth?.SignedIn == true && File.Exists(f) ? JsonNode.Parse(Protect.ReadText(f)) as JsonObject : null;
            }
            catch (Exception) { return null; }
        }

        private void WriteAudit(string name, JsonObject value)
        {
            if (_auth?.SignedIn != true) throw new InvalidOperationException("Sign in first.");
            if (name.IndexOfAny(Path.GetInvalidPathChars()) >= 0 || name.Contains("..")) throw new InvalidOperationException("Invalid name.");
            Protect.WriteText(Path.Combine(AuditDir(), name + ".dat"), value.ToJsonString());
        }

        // ------------------------------------------------------------------ tenants scanned on this PC, and settings (both encrypted)
        private static JsonArray ReadTenants()
        {
            try { if (File.Exists(TenantsFile)) return JsonNode.Parse(Protect.ReadText(TenantsFile)) as JsonArray ?? new JsonArray(); }
            catch (Exception) { /* unreadable (other Windows user, damaged): start a new list */ }
            return new JsonArray();
        }

        private static void WriteTenants(JsonArray list) => Protect.WriteText(TenantsFile, list.ToJsonString());

        private static void UpsertTenant(string tenantId, Action<JsonObject> change)
        {
            if (string.IsNullOrEmpty(tenantId)) return;
            var id = tenantId.ToLowerInvariant();
            try
            {
                var list = ReadTenants();
                var t = list.OfType<JsonObject>().FirstOrDefault(x => Api.Str(x["tenantId"]) == id);
                if (t == null) { t = new JsonObject { ["tenantId"] = id, ["history"] = new JsonArray() }; list.Add(t); }
                change(t);
                WriteTenants(list);
            }
            catch (Exception) { /* the list is a convenience: never stop sign-in or a scan for it */ }
        }

        private JsonArray TenantsForPage()
        {
            var list = ReadTenants();
            foreach (var t in list.OfType<JsonObject>())
                t["current"] = _auth?.SignedIn == true && string.Equals(Api.Str(t["tenantId"]), _auth.TenantId, StringComparison.OrdinalIgnoreCase);
            return list;
        }

        private static JsonObject ReadPrefs()
        {
            try { return File.Exists(PrefsFile) ? JsonNode.Parse(Protect.ReadText(PrefsFile)) as JsonObject : null; }
            catch (Exception) { return null; }
        }

        private static bool IsSnapshotName(string n) =>
            n != null && DateTime.TryParseExact(n, "yyyy-MM-dd_HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out _);

        private string ReadSnapshot(string name)
        {
            if (!IsSnapshotName(name)) return null;
            var enc = Path.Combine(SnapshotDir(), name + ".scan");
            if (File.Exists(enc)) return Protect.ReadText(enc);
            var plain = Path.Combine(SnapshotDir(), name + ".json");           // scans from before encryption: encrypt them now
            if (!File.Exists(plain)) return null;
            var text = File.ReadAllText(plain, Encoding.UTF8);
            try { Protect.WriteText(enc, text); File.Delete(plain); } catch (Exception) { /* stays readable; tried again next time */ }
            return text;
        }

        private static string Label(string name) =>
            "Scan " + DateTime.ParseExact(name, "yyyy-MM-dd_HHmmss", CultureInfo.InvariantCulture).ToString("ddd d MMM yyyy, HH:mm", CultureInfo.CurrentCulture);

        /// <summary>The app (client) ID used last, to prefill the sign-in form (each tenant keeps its own in the tenant list).</summary>
        private static string LastClientId()
        {
            try
            {
                if (File.Exists(SettingsFile))
                {
                    var id = Api.Str(JsonNode.Parse(File.ReadAllText(SettingsFile))?["clientId"]);
                    if (Guid.TryParse(id, out _)) return id;
                }
            }
            catch (Exception) { }
            return null;
        }

        private static void SaveClientId(string id)
        {
            Directory.CreateDirectory(DataDir);
            File.WriteAllText(SettingsFile, new JsonObject { ["clientId"] = id }.ToJsonString(), new UTF8Encoding(false));
        }

        private static Stream Resource(string name) =>
            Assembly.GetExecutingAssembly().GetManifestResourceStream(name) ?? throw new InvalidOperationException("Missing resource " + name);

        private static void OpenExternal(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return;
            if (!ExternalHosts.Any(h => u.Host.Equals(h, StringComparison.OrdinalIgnoreCase) || u.Host.EndsWith("." + h, StringComparison.OrdinalIgnoreCase))) return;
            try { Process.Start(new ProcessStartInfo(u.AbsoluteUri) { UseShellExecute = true }); } catch (Exception) { }
        }
    }
}
