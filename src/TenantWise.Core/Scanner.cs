// TenantWise.Core — Scanner.cs
// Reads the estate (read-only) and builds the TenantWise data model: resources and how they connect,
// management groups, Azure RBAC, Azure Policy, Entra directory roles, PIM eligibility, groups and their owners, app registrations
// with their secrets, Microsoft Graph application permissions, cross-tenant access settings and Conditional Access.
// The output format is the one tenantwise.template.html reads.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace TenantWise.Core
{
    public sealed class ScanOptions
    {
        public string TenantId { get; set; }
        public bool Entra { get; set; } = true;
        public ScanScope Scope { get; set; } = new ScanScope();
        public string[] ExcludeTypes { get; set; } =
        {
            "microsoft.compute/virtualmachines/extensions",
            "microsoft.network/privatednszones/virtualnetworklinks",
            "microsoft.alertsmanagement/smartdetectoralertrules"
        };
        public int MaxGroupsExpanded { get; set; } = 300;
        /// <summary>Who runs the scan and with which tool version: recorded in the scan for audit evidence.</summary>
        public string Account { get; set; }
        public string ToolVersion { get; set; }
        /// <summary>Upper bound for reading sign-in activity (pages of 120 users).</summary>
        public int MaxSignInPages { get; set; } = 100;
        /// <summary>Read Microsoft Teams (owners, members, guests, channels) and the SharePoint site inventory.</summary>
        public bool M365 { get; set; } = true;
        public int MaxTeams { get; set; } = 3000;
    }

    public sealed class Scanner
    {
        private static readonly string[] PrivilegedAzureRoles =
            { "Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator", "Reservations Administrator" };
        private static readonly string[] PrivilegedEntraRoles =
        {
            "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator", "Security Administrator",
            "Application Administrator", "Cloud Application Administrator", "Conditional Access Administrator", "Authentication Administrator",
            "Authentication Policy Administrator", "User Administrator", "Exchange Administrator", "SharePoint Administrator", "Intune Administrator",
            "Hybrid Identity Administrator", "Helpdesk Administrator", "Partner Tier2 Support", "Domain Name Administrator",
            "External Identity Provider Administrator", "Groups Administrator", "Password Administrator", "Security Operator",
            "Directory Synchronization Accounts", "Azure DevOps Administrator"
        };
        private static readonly string[] NodeFields = { "id", "rid", "name", "type", "cat", "parent", "sub", "rg", "loc", "sku", "kind", "prefix", "tags", "external" };

        private readonly Api _api;
        private readonly ScanOptions _o;
        private readonly IProgress<string> _progress;
        private readonly string _tenant;

        private readonly Dictionary<string, JsonObject> _nodes = new Dictionary<string, JsonObject>();
        private readonly List<string> _order = new List<string>();
        private readonly JsonArray _edges = new JsonArray();
        private readonly HashSet<string> _edgeKeys = new HashSet<string>();
        private readonly List<string> _warnings = new List<string>();

        public Scanner(Api api, ScanOptions options, IProgress<string> progress = null)
        {
            _api = api;
            _o = options;
            _progress = progress;
            _tenant = (options.TenantId ?? "").ToLowerInvariant();
        }

        public IReadOnlyList<string> Warnings => _warnings;

        // ---------------------------------------------------------------- helpers
        private void Step(string text) { _progress?.Report(text); }

        private static string S(JsonObject row, string prop) => row == null ? "" : (Api.Str(row[prop]) ?? "");

        /// <summary>Rows of a CSV text (quoted fields, doubled quotes, CRLF or LF).</summary>
        internal static List<List<string>> Csv(string text)
        {
            var rows = new List<List<string>>(); var row = new List<string>(); var f = new StringBuilder(); var q = false;
            text = text ?? "";
            for (var k = 0; k < text.Length; k++)
            {
                var c = text[k];
                if (q)
                {
                    if (c == '"' && k + 1 < text.Length && text[k + 1] == '"') { f.Append('"'); k++; }
                    else if (c == '"') q = false;
                    else f.Append(c);
                }
                else if (c == '"') q = true;
                else if (c == ',') { row.Add(f.ToString()); f.Clear(); }
                else if (c == '\n' || c == '\r')
                {
                    if (c == '\r' && k + 1 < text.Length && text[k + 1] == '\n') k++;
                    row.Add(f.ToString()); f.Clear();
                    if (row.Count > 1 || row[0].Length > 0) rows.Add(row);
                    row = new List<string>();
                }
                else f.Append(c);
            }
            if (f.Length > 0 || row.Count > 0) { row.Add(f.ToString()); rows.Add(row); }
            return rows;
        }
        private static string Low(string s) => (s ?? "").ToLowerInvariant();

        private void AddNode(IDictionary<string, object> n)
        {
            var id = (string)n["id"];
            if (string.IsNullOrEmpty(id) || _nodes.ContainsKey(id)) return;
            var o = new JsonObject();
            foreach (var k in NodeFields)
            {
                if (!n.TryGetValue(k, out var v) || v == null) continue;
                if (v is string s) { if (s.Length > 0) o[k] = s; }
                else if (v is bool b) { if (b) o[k] = true; }
                else if (v is JsonNode j) o[k] = j;
            }
            _nodes[id] = o;
            _order.Add(id);
        }

        private void AddEdge(string s, string t, string rel)
        {
            if (string.IsNullOrEmpty(s) || string.IsNullOrEmpty(t)) return;
            s = s.ToLowerInvariant(); t = t.ToLowerInvariant();
            if (s == t) return;
            var key = rel == "peered" ? string.Join("|", new[] { s, t }.OrderBy(x => x, StringComparer.Ordinal)) : s + "|" + t;
            if (_edgeKeys.Add(key)) _edges.Add(new JsonObject { ["s"] = s, ["t"] = t, ["rel"] = rel });
        }

        private async Task TryStep(string what, Func<Task> action)
        {
            try { await action().ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { _warnings.Add(what + " skipped: " + ex.Message); Step("Note: " + what + " skipped (" + ex.Message + ")"); }
        }

        public static string Category(string type)
        {
            if (Regex.IsMatch(type ?? "", @"^microsoft\.(compute|containerservice|containerinstance|web|app|batch)/")) return "compute";
            if (Regex.IsMatch(type ?? "", @"^microsoft\.(network|cdn)/")) return "network";
            if (Regex.IsMatch(type ?? "", @"^microsoft\.(storage|sql|documentdb|dbfor\w+|cache|keyvault|synapse|datafactory|databricks|eventhub|servicebus|kusto|recoveryservices|dataprotection)/")) return "data";
            return "other";
        }

        private static string Root(string id)          // /subscriptions/s/resourcegroups/r/providers/ns/type/name
        {
            var p = id.Split('/');
            return p.Length >= 9 ? string.Join("/", p.Take(9)) : id;
        }

        private static string TypeFromId(string id)
        {
            if (Regex.IsMatch(id, "/subnets/[^/]+$")) return "subnet";
            var p = id.Split('/');
            return p.Length >= 9 ? p[6] + "/" + p[7] : "unknown";
        }

        private string MgId(string name) => Low(name) == _tenant ? "tenant" : "mg:" + Low(name);

        private string ScopeNode(string scope)
        {
            var s = Low(scope).TrimEnd('/');
            if (s.Length == 0) return "tenant";
            var m = Regex.Match(s, "^/providers/microsoft\\.management/managementgroups/([^/]+)$");
            if (m.Success) return MgId(m.Groups[1].Value);
            return s;
        }

        private static JsonNode Tags(JsonNode t)
        {
            if (!(t is JsonObject o) || o.Count == 0) return null;
            var r = new JsonObject();
            foreach (var kv in o) r[kv.Key] = Api.Str(kv.Value) ?? "";
            return r;
        }

        private Task<List<JsonObject>> Q(string query, CancellationToken ct) => _api.QueryAsync(query, ct);

        // ---------------------------------------------------------------- scan
        public async Task<JsonObject> ScanAsync(CancellationToken ct = default(CancellationToken))
        {
            var started = DateTime.UtcNow;
            var rootLabel = "Tenant Root Group";
            var mgNames = new List<string>();
            void Mg(string name) { var n = Low(name); if (n.Length > 0 && !mgNames.Contains(n)) mgNames.Add(n); }
            var exclude = string.Join(", ", _o.ExcludeTypes.Select(x => "'" + x.ToLowerInvariant().Replace("'", "''") + "'"));

            // ---------- management groups + subscriptions
            Step("Reading management groups and subscriptions…");
            await TryStep("Management group list", async () =>
            {
                foreach (var m in await Q(@"resourcecontainers
| where type =~ 'microsoft.management/managementgroups'
| project name, displayName = tostring(properties.displayName), parent = tostring(properties.details.parent.name)", ct).ConfigureAwait(false))
                {
                    var id = MgId(S(m, "name"));
                    Mg(S(m, "name"));
                    if (id == "tenant") { rootLabel = S(m, "displayName"); continue; }
                    var parent = S(m, "parent");
                    AddNode(new Dictionary<string, object> { ["id"] = id, ["name"] = S(m, "displayName"), ["type"] = "managementgroup", ["cat"] = "mg",
                        ["parent"] = parent.Length > 0 ? MgId(parent) : "tenant" });
                }
            }).ConfigureAwait(false);

            foreach (var s in await Q(@"resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId, name, chain = properties.managementGroupAncestorsChain", ct).ConfigureAwait(false))
            {
                var chain = (s["chain"] as JsonArray)?.OfType<JsonObject>().ToList() ?? new List<JsonObject>();
                var ids = chain.Select(c => MgId(S(c, "name"))).ToList();
                for (var i = 0; i < chain.Count; i++)
                {
                    Mg(S(chain[i], "name"));
                    if (ids[i] == "tenant") { rootLabel = S(chain[i], "displayName"); continue; }
                    AddNode(new Dictionary<string, object> { ["id"] = ids[i], ["name"] = S(chain[i], "displayName"), ["type"] = "managementgroup", ["cat"] = "mg",
                        ["parent"] = i + 1 < chain.Count ? ids[i + 1] : "tenant" });
                }
                var sid = Low(S(s, "subscriptionId"));
                AddNode(new Dictionary<string, object> { ["id"] = "/subscriptions/" + sid, ["rid"] = "/subscriptions/" + S(s, "subscriptionId"), ["name"] = S(s, "name"),
                    ["type"] = "microsoft.resources/subscriptions", ["cat"] = "sub", ["parent"] = ids.Count > 0 ? ids[0] : "tenant", ["sub"] = sid });
            }
            // the tenant root goes first so it is the mind map's centre
            _nodes["tenant"] = new JsonObject { ["id"] = "tenant", ["name"] = rootLabel, ["type"] = "tenant", ["cat"] = "tenant" };
            _order.Insert(0, "tenant");

            Step("Reading resource groups…");
            foreach (var g in await Q(@"resourcecontainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| project id = tolower(id), rid = id, name, subscriptionId = tolower(subscriptionId), location, tags", ct).ConfigureAwait(false))
            {
                AddNode(new Dictionary<string, object> { ["id"] = S(g, "id"), ["rid"] = S(g, "rid"), ["name"] = S(g, "name"), ["type"] = "microsoft.resources/resourcegroups",
                    ["cat"] = "rg", ["parent"] = "/subscriptions/" + S(g, "subscriptionId"), ["sub"] = S(g, "subscriptionId"), ["rg"] = S(g, "name"),
                    ["loc"] = S(g, "location"), ["tags"] = Tags(g["tags"]) });
            }

            // ---------- resources
            Step("Reading resources…");
            foreach (var r in await Q($@"resources
| where tolower(type) !in ({exclude})
| project id = tolower(id), rid = id, name, type = tolower(type), subscriptionId = tolower(subscriptionId),
          resourceGroup, location, sku = tostring(sku.name), kind, tags", ct).ConfigureAwait(false))
            {
                var type = S(r, "type");
                AddNode(new Dictionary<string, object> { ["id"] = S(r, "id"), ["rid"] = S(r, "rid"), ["name"] = S(r, "name"), ["type"] = type, ["cat"] = Category(type),
                    ["parent"] = "/subscriptions/" + S(r, "subscriptionId") + "/resourcegroups/" + Low(S(r, "resourceGroup")),
                    ["sub"] = S(r, "subscriptionId"), ["rg"] = S(r, "resourceGroup"), ["loc"] = S(r, "location"), ["sku"] = S(r, "sku"),
                    ["kind"] = S(r, "kind"), ["tags"] = Tags(r["tags"]) });
            }
            foreach (var id in _order)                  // child resources (e.g. SQL databases) hang under their parent resource
            {
                var n = _nodes[id];
                var cat = Api.Str(n["cat"]);
                if (cat == "tenant" || cat == "mg" || cat == "sub" || cat == "rg") continue;
                var p = id.Split('/');
                if (p.Length > 9)
                {
                    var parentId = string.Join("/", p.Take(p.Length - 2));
                    if (_nodes.ContainsKey(parentId)) n["parent"] = parentId;
                }
            }

            // ---------- subnets
            Step("Reading networks and connections…");
            foreach (var s in await Q(@"resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand sn = properties.subnets
| project vnet = tolower(id), id = tolower(tostring(sn.id)), rid = tostring(sn.id), name = tostring(sn.name),
          prefix = iff(isnotempty(tostring(sn.properties.addressPrefix)), tostring(sn.properties.addressPrefix), tostring(sn.properties.addressPrefixes)),
          nsg = tolower(tostring(sn.properties.networkSecurityGroup.id)), rt = tolower(tostring(sn.properties.routeTable.id)),
          nat = tolower(tostring(sn.properties.natGateway.id)), subscriptionId = tolower(subscriptionId), resourceGroup, location", ct).ConfigureAwait(false))
            {
                if (S(s, "id").Length == 0) continue;
                AddNode(new Dictionary<string, object> { ["id"] = S(s, "id"), ["rid"] = S(s, "rid"), ["name"] = S(s, "name"), ["type"] = "subnet", ["cat"] = "subnet",
                    ["parent"] = S(s, "vnet"), ["sub"] = S(s, "subscriptionId"), ["rg"] = S(s, "resourceGroup"), ["loc"] = S(s, "location"), ["prefix"] = S(s, "prefix") });
                AddEdge(S(s, "nsg"), S(s, "id"), "protects");
                AddEdge(S(s, "rt"), S(s, "id"), "routes");
                AddEdge(S(s, "nat"), S(s, "id"), "NAT for");
            }

            // ---------- connections
            var hops = new Dictionary<string, string>();   // private IP -> firewall / appliance VM ("" = ambiguous, overlapping ranges)
            void Hop(string ip, string owner)
            {
                if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(owner)) return;
                hops[ip] = hops.TryGetValue(ip, out var existing) && existing != owner ? "" : owner;
            }

            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.network/networkinterfaces'
| extend owner = tolower(coalesce(tostring(properties.virtualMachine.id), tostring(properties.privateEndpoint.id)))
| extend nsg = tolower(tostring(properties.networkSecurityGroup.id))
| mv-expand c = properties.ipConfigurations
| project s = tolower(id), owner, nsg, subnet = tolower(tostring(c.properties.subnet.id)),
          pip = tolower(tostring(c.properties.publicIPAddress.id)),
          lb = tolower(tostring(c.properties.loadBalancerBackendAddressPools[0].id)),
          agw = tolower(tostring(c.properties.applicationGatewayBackendAddressPools[0].id)),
          ip = tostring(c.properties.privateIPAddress)", ct).ConfigureAwait(false))
            {
                var nic = S(r, "s"); var owner = S(r, "owner");
                Hop(S(r, "ip"), owner.Length > 0 && !owner.Contains("/privateendpoints/") ? owner : nic);
                AddEdge(nic, owner, "NIC of");
                AddEdge(S(r, "nsg"), nic, "protects");
                AddEdge(nic, S(r, "subnet"), "in subnet");
                AddEdge(S(r, "pip"), nic, "public IP of");
                if (S(r, "lb").Length > 0) AddEdge(Root(S(r, "lb")), nic, "balances");
                if (S(r, "agw").Length > 0) AddEdge(Root(S(r, "agw")), nic, "routes to");
            }
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand p = properties.virtualNetworkPeerings
| project s = tolower(id), t = tolower(tostring(p.properties.remoteVirtualNetwork.id))", ct).ConfigureAwait(false))
                AddEdge(S(r, "s"), S(r, "t"), "peered");
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.network/publicipaddresses'
| project s = tolower(id), cfg = tolower(tostring(properties.ipConfiguration.id)), nat = tolower(tostring(properties.natGateway.id))", ct).ConfigureAwait(false))
            {
                if (S(r, "cfg").Length > 0) AddEdge(S(r, "s"), Root(S(r, "cfg")), "public IP of");
                AddEdge(S(r, "s"), S(r, "nat"), "public IP of");
            }
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.network/privateendpoints'
| extend c = iff(array_length(properties.privateLinkServiceConnections) > 0, properties.privateLinkServiceConnections[0], properties.manualPrivateLinkServiceConnections[0])
| project s = tolower(id), subnet = tolower(tostring(properties.subnet.id)), target = tolower(tostring(c.properties.privateLinkServiceId))", ct).ConfigureAwait(false))
            {
                AddEdge(S(r, "s"), S(r, "subnet"), "in subnet");
                AddEdge(S(r, "s"), S(r, "target"), "private link to");
            }
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.compute/disks' and isnotempty(managedBy)
| project s = tolower(id), t = tolower(managedBy)", ct).ConfigureAwait(false))
                AddEdge(S(r, "s"), S(r, "t"), "disk of");
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.web/sites'
| project s = tolower(id), plan = tolower(tostring(properties.serverFarmId)), subnet = tolower(tostring(properties.virtualNetworkSubnetId))", ct).ConfigureAwait(false))
            {
                AddEdge(S(r, "s"), S(r, "plan"), "hosted on");
                AddEdge(S(r, "s"), S(r, "subnet"), "integrated with");
            }
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.containerservice/managedclusters'
| mv-expand p = properties.agentPoolProfiles
| project s = tolower(id), t = tolower(tostring(p.vnetSubnetID))", ct).ConfigureAwait(false))
                AddEdge(S(r, "s"), S(r, "t"), "nodes in");
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.compute/virtualmachinescalesets'
| mv-expand n = properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations
| mv-expand c = n.properties.ipConfigurations
| project s = tolower(id), t = tolower(tostring(c.properties.subnet.id))", ct).ConfigureAwait(false))
                AddEdge(S(r, "s"), S(r, "t"), "in subnet");
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.network/privatednszones/virtualnetworklinks'
| project s = tostring(split(tolower(id), '/virtualnetworklinks/')[0]), t = tolower(tostring(properties.virtualNetwork.id))", ct).ConfigureAwait(false))
                AddEdge(S(r, "s"), S(r, "t"), "DNS linked");
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.network/connections'
| project s = tolower(id), gw = tolower(tostring(properties.virtualNetworkGateway1.id)),
          peer = tolower(coalesce(tostring(properties.virtualNetworkGateway2.id), tostring(properties.localNetworkGateway2.id), tostring(properties.peer.id)))", ct).ConfigureAwait(false))
            {
                AddEdge(S(r, "s"), S(r, "gw"), "connection of");
                AddEdge(S(r, "s"), S(r, "peer"), "connects to");
            }
            foreach (var prop in new[] { "ipConfigurations", "gatewayIPConfigurations", "frontendIPConfigurations" })
            {
                foreach (var r in await Q($@"resources
| where type !in~ ('microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses')
| where isnotnull(properties.{prop})
| mv-expand c = properties.{prop}
| project s = tolower(id), subnet = tolower(tostring(c.properties.subnet.id)), pip = tolower(tostring(c.properties.publicIPAddress.id)),
          ip = tostring(c.properties.privateIPAddress)", ct).ConfigureAwait(false))
                {
                    AddEdge(S(r, "s"), S(r, "subnet"), "in subnet");
                    AddEdge(S(r, "pip"), S(r, "s"), "public IP of");
                    Hop(S(r, "ip"), S(r, "s"));
                }
            }
            foreach (var r in await Q(@"resources
| where type =~ 'microsoft.network/routetables'
| mv-expand r = properties.routes
| where tostring(r.properties.nextHopType) =~ 'VirtualAppliance'
| project s = tolower(id), hop = tostring(r.properties.nextHopIpAddress)", ct).ConfigureAwait(false))
            {
                if (hops.TryGetValue(S(r, "hop"), out var target) && target.Length > 0) AddEdge(S(r, "s"), target, "routes to");
            }

            // targets outside the scanned scope become dashed "external" nodes
            foreach (var e in _edges.OfType<JsonObject>().ToList())
            {
                foreach (var id in new[] { Api.Str(e["s"]), Api.Str(e["t"]) })
                {
                    if (_nodes.ContainsKey(id)) continue;
                    var type = TypeFromId(id);
                    string parent = null;
                    if (type == "subnet")
                    {
                        parent = Regex.Replace(id, "/subnets/[^/]+$", "");
                        if (!_nodes.ContainsKey(parent))
                            AddNode(new Dictionary<string, object> { ["id"] = parent, ["rid"] = parent, ["name"] = parent.Split('/').Last(),
                                ["type"] = "microsoft.network/virtualnetworks", ["cat"] = "network", ["external"] = true });
                    }
                    AddNode(new Dictionary<string, object> { ["id"] = id, ["rid"] = id, ["name"] = id.Split('/').Last(), ["type"] = type,
                        ["cat"] = type == "subnet" ? "subnet" : Category(type), ["parent"] = parent, ["external"] = true });
                }
            }

            // ---------- Azure RBAC
            Step("Reading Azure role assignments…");
            var roleDefs = new Dictionary<string, (string name, bool custom)>();
            await TryStep("Built-in role names", async () =>
            {
                foreach (var d in await _api.ArmListAsync("/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", ct).ConfigureAwait(false))
                    roleDefs[Low(S(d, "name"))] = (Api.Str(d["properties"]?["roleName"]), Api.Str(d["properties"]?["type"]) == "CustomRole");
            }).ConfigureAwait(false);
            await TryStep("Custom role names", async () =>
            {
                foreach (var d in await Q(@"authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions'
| project name = tolower(name), roleName = tostring(properties.roleName), roleType = tostring(properties.type)", ct).ConfigureAwait(false))
                    roleDefs[S(d, "name")] = (S(d, "roleName"), S(d, "roleType") == "CustomRole");
            }).ConfigureAwait(false);

            var assignments = new Dictionary<string, (string p, string ptype, string roleDef, string scope, string cond)>();
            await TryStep("Role assignments (subscriptions and below)", async () =>
            {
                foreach (var a in await Q(@"authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| project id = tolower(id), principalId = tostring(properties.principalId), principalType = tostring(properties.principalType),
          roleDefinitionId = tolower(tostring(properties.roleDefinitionId)), scope = tolower(tostring(properties.scope)),
          condition = tostring(properties.condition)", ct).ConfigureAwait(false))
                    assignments[S(a, "id")] = (S(a, "principalId"), S(a, "principalType"), S(a, "roleDefinitionId"), S(a, "scope"), S(a, "condition"));
            }).ConfigureAwait(false);
            foreach (var mg in mgNames)                  // management-group and root assignments come from ARM
            {
                await TryStep("Role assignments at management group " + mg, async () =>
                {
                    foreach (var a in await _api.ArmListAsync($"/providers/Microsoft.Management/managementGroups/{Uri.EscapeDataString(mg)}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()", ct).ConfigureAwait(false))
                    {
                        var p = a["properties"] as JsonObject;
                        assignments[Low(S(a, "id"))] = (S(p, "principalId"), S(p, "principalType"), Low(S(p, "roleDefinitionId")), Low(S(p, "scope")), S(p, "condition"));
                    }
                }).ConfigureAwait(false);
            }
            // PIM-eligible Azure roles: per management group (at and above) and per subscription (at, above and below)
            Step("Reading PIM-eligible Azure roles…");
            var eligible = new Dictionary<string, (string p, string ptype, string roleDef, string scope, string until)>();
            void AddEligible(JsonObject e)
            {
                var p = e["properties"] as JsonObject;
                if (p == null) return;
                // the same eligibility shows up from several scopes; key it by who / what / where
                var key = S(p, "principalId") + "|" + Low(S(p, "roleDefinitionId")).Split('/').Last() + "|" + Low(S(p, "scope"));
                eligible[key] = (S(p, "principalId"), S(p, "principalType"), Low(S(p, "roleDefinitionId")), Low(S(p, "scope")), S(p, "endDateTime"));
            }
            foreach (var mg in mgNames)
                await TryStep("Eligible Azure roles at management group " + mg, async () =>
                {
                    foreach (var e in await _api.ArmListAsync($"/providers/Microsoft.Management/managementGroups/{Uri.EscapeDataString(mg)}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=atScope()", ct).ConfigureAwait(false))
                        AddEligible(e);
                }).ConfigureAwait(false);
            foreach (var sid in _order.Where(i => i.StartsWith("/subscriptions/") && i.Count(c => c == '/') == 2).ToList())
                await TryStep("Eligible Azure roles in " + Api.Str(_nodes[sid]["name"]), async () =>
                {
                    foreach (var e in await _api.ArmListAsync(sid + "/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01", ct).ConfigureAwait(false))
                        AddEligible(e);
                }).ConfigureAwait(false);

            var azure = new JsonArray();
            var principalKinds = new Dictionary<string, string>();
            void AddAzure(string p, string ptype, string roleDef, string scope, string cond, string status, string until)
            {
                var guid = roleDef.Split('/').Last();
                var has = roleDefs.TryGetValue(guid, out var def);
                var role = has ? def.name : "Role " + guid;
                var o = new JsonObject { ["p"] = p, ["role"] = role, ["custom"] = has && def.custom, ["priv"] = PrivilegedAzureRoles.Contains(role),
                    ["scope"] = ScopeNode(scope), ["cond"] = cond.Length > 0, ["status"] = status };
                if (!string.IsNullOrEmpty(until)) o["until"] = until;
                azure.Add(o);
                if (ptype.Length > 0) principalKinds[p] = ptype;
            }
            foreach (var a in assignments.Values) AddAzure(a.p, a.ptype, a.roleDef, a.scope, a.cond, "active", null);
            foreach (var e in eligible.Values) AddAzure(e.p, e.ptype, e.roleDef, e.scope, "", "eligible", e.until);

            // ---------- Azure Policy
            Step("Reading policy assignments and compliance…");
            var policiesRaw = new Dictionary<string, (string name, string scope, string def, string enforce)>();
            await TryStep("Policy assignments (subscriptions and below)", async () =>
            {
                foreach (var p in await Q(@"policyresources
| where type =~ 'microsoft.authorization/policyassignments'
| project id = tolower(id), name = tostring(properties.displayName), scope = tolower(tostring(properties.scope)),
          definitionId = tolower(tostring(properties.policyDefinitionId)), enforcement = tostring(properties.enforcementMode)", ct).ConfigureAwait(false))
                    policiesRaw[S(p, "id")] = (S(p, "name"), S(p, "scope"), S(p, "definitionId"), S(p, "enforcement"));
            }).ConfigureAwait(false);
            foreach (var mg in mgNames)
            {
                await TryStep("Policy assignments at management group " + mg, async () =>
                {
                    foreach (var p in await _api.ArmListAsync($"/providers/Microsoft.Management/managementGroups/{Uri.EscapeDataString(mg)}/providers/Microsoft.Authorization/policyAssignments?api-version=2023-04-01&$filter=atScope()", ct).ConfigureAwait(false))
                    {
                        var pr = p["properties"] as JsonObject;
                        policiesRaw[Low(S(p, "id"))] = (S(pr, "displayName"), Low(S(pr, "scope")), Low(S(pr, "policyDefinitionId")), S(pr, "enforcementMode"));
                    }
                }).ConfigureAwait(false);
            }
            var nonCompliant = new Dictionary<string, JsonObject>();
            await TryStep("Policy compliance", async () =>
            {
                foreach (var c in await Q(@"policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| where tostring(properties.complianceState) =~ 'NonCompliant'
| summarize n = dcount(tostring(properties.resourceId)) by a = tolower(tostring(properties.policyAssignmentId)), subscriptionId = tolower(subscriptionId)", ct).ConfigureAwait(false))
                {
                    if (!nonCompliant.TryGetValue(S(c, "a"), out var byS)) nonCompliant[S(c, "a")] = byS = new JsonObject();
                    byS[S(c, "subscriptionId")] = int.TryParse(S(c, "n"), out var n) ? n : 0;
                }
            }).ConfigureAwait(false);
            var policies = new JsonArray();
            foreach (var kv in policiesRaw)
            {
                var p = kv.Value;
                policies.Add(new JsonObject { ["id"] = kv.Key, ["name"] = p.name.Length > 0 ? p.name : kv.Key.Split('/').Last(), ["scope"] = ScopeNode(p.scope),
                    ["initiative"] = p.def.Contains("/policysetdefinitions/"), ["enforce"] = p.enforce.Length > 0 ? p.enforce : "Default",
                    ["nonCompliant"] = nonCompliant.TryGetValue(kv.Key, out var nc) ? nc : null });
            }

            // ---------- Entra
            var principals = new Dictionary<string, JsonObject>();
            var entra = new JsonArray();
            var members = new JsonObject();
            var ca = new JsonArray();
            var packages = new JsonArray();
            var packageAssignments = new JsonArray();
            var packageRequests = new JsonArray();
            var groupEligible = new JsonArray();
            var apps = new JsonArray();             // app registrations: credentials and owners
            var appPerms = new JsonArray();         // Microsoft Graph application permissions held by apps
            var groupOwners = new JsonObject();     // owners of groups that hold privileged roles: they can add themselves
            var nested = new JsonObject();          // groups nested inside groups that hold roles
            JsonObject crossTenant = null;
            JsonObject m365 = null;                  // teams, channels and SharePoint sites (when read)
            string tenantName = null, tenantDomain = null;
            void AddPrincipal(JsonObject o)
            {
                var t = S(o, "@odata.type").ToLowerInvariant();
                var kind = t.EndsWith("user") ? "user" : t.EndsWith("group") ? "group" : t.EndsWith("serviceprincipal") ? "sp" : null;
                var id = S(o, "id");
                if (kind == null || id.Length == 0 || principals.ContainsKey(id)) return;
                var upn = S(o, "userPrincipalName");
                var po = new JsonObject { ["id"] = id, ["name"] = S(o, "displayName").Length > 0 ? S(o, "displayName") : id,
                    ["upn"] = upn.Length > 0 ? upn : null, ["kind"] = kind };
                // userType decides when known: the creator of a tenant made with a personal Microsoft account has #EXT# in
                // the UPN but is a member, not a guest. Without userType, #EXT# is the best hint (corrected below).
                var ut = S(o, "userType");
                if (kind == "user" && (ut.Length > 0 ? ut == "Guest" : upn.IndexOf("#EXT#", StringComparison.OrdinalIgnoreCase) >= 0)) po["guest"] = true;
                principals[id] = po;
            }
            if (_o.Entra)
            {
                Step("Reading Entra directory roles…");
                await TryStep("Tenant name", async () =>
                {
                    var org = (await _api.GraphListAsync("/organization?$select=id,displayName,verifiedDomains", ct).ConfigureAwait(false)).FirstOrDefault();
                    tenantName = S(org, "displayName");
                    var domains = (org?["verifiedDomains"] as JsonArray)?.OfType<JsonObject>().ToList() ?? new List<JsonObject>();
                    tenantDomain = S(domains.FirstOrDefault(d => S(d, "isDefault") == "true") ?? domains.FirstOrDefault(), "name");
                    if (tenantDomain.Length == 0) tenantDomain = null;
                }).ConfigureAwait(false);
                var dirRoles = new Dictionary<string, (string name, bool priv)>();
                await TryStep("Directory role definitions", async () =>
                {
                    List<JsonObject> defs;
                    try { defs = await _api.GraphListAsync("/roleManagement/directory/roleDefinitions?$select=id,displayName,isPrivileged", ct).ConfigureAwait(false); }
                    catch (ApiException) { defs = await _api.GraphListAsync("/roleManagement/directory/roleDefinitions?$select=id,displayName", ct).ConfigureAwait(false); }
                    foreach (var d in defs)
                    {
                        var name = S(d, "displayName");
                        var ip = d["isPrivileged"];
                        dirRoles[S(d, "id")] = (name, ip != null ? S(d, "isPrivileged") == "true" : PrivilegedEntraRoles.Contains(name));
                    }
                }).ConfigureAwait(false);
                async Task ReadRoles(string what, string path, string status)
                {
                    await TryStep(what, async () =>
                    {
                        foreach (var a in await _api.GraphListAsync(path, ct).ConfigureAwait(false))
                        {
                            var has = dirRoles.TryGetValue(S(a, "roleDefinitionId"), out var d);
                            var o = new JsonObject { ["p"] = S(a, "principalId"), ["role"] = has ? d.name : S(a, "roleDefinitionId"), ["priv"] = has && d.priv,
                                ["status"] = status, ["scope"] = S(a, "directoryScopeId") };
                            var until = Api.Str(a["scheduleInfo"]?["expiration"]?["endDateTime"]);
                            if (!string.IsNullOrEmpty(until)) o["until"] = until;
                            entra.Add(o);
                        }
                    }).ConfigureAwait(false);
                }
                await ReadRoles("Directory role assignments", "/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId", "active").ConfigureAwait(false);
                await ReadRoles("PIM eligible roles (needs Entra ID P2)", "/roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,roleDefinitionId,directoryScopeId,scheduleInfo", "eligible").ConfigureAwait(false);

                Step("Resolving identities and group members…");
                var ids = azure.Select(a => Api.Str(a["p"])).Concat(entra.Select(a => Api.Str(a["p"])))
                    .Where(x => !string.IsNullOrEmpty(x)).Distinct().ToList();
                await TryStep("Identity names", async () =>
                {
                    for (var i = 0; i < ids.Count; i += 1000)
                    {
                        var body = new JsonObject
                        {
                            ["ids"] = new JsonArray(ids.Skip(i).Take(1000).Select(x => (JsonNode)JsonValue.Create(x)).ToArray()),
                            ["types"] = new JsonArray(JsonValue.Create("user"), JsonValue.Create("group"), JsonValue.Create("servicePrincipal"))
                        };
                        var r = await _api.GraphPostAsync("/directoryObjects/getByIds", body, ct).ConfigureAwait(false);
                        if (r?["value"] is JsonArray v) foreach (var o in v.OfType<JsonObject>()) AddPrincipal(o);
                    }
                }).ConfigureAwait(false);
                var groups = principals.Values.Where(p => Api.Str(p["kind"]) == "group").ToList();   // also used for PIM for Groups below
                if (groups.Count > _o.MaxGroupsExpanded)
                    _warnings.Add($"Only the first {_o.MaxGroupsExpanded} of {groups.Count} groups with roles were expanded to members.");
                foreach (var g in groups.Take(_o.MaxGroupsExpanded))
                {
                    var gid = Api.Str(g["id"]);
                    await TryStep("Members of " + Api.Str(g["name"]), async () =>
                    {
                        var list = new JsonArray();
                        var inner = new JsonArray();
                        foreach (var o in await _api.GraphListAsync($"/groups/{gid}/transitiveMembers?$select=id,displayName,userPrincipalName,userType&$top=999", ct).ConfigureAwait(false))
                        {
                            AddPrincipal(o);
                            var id = S(o, "id");
                            if (!principals.TryGetValue(id, out var p)) continue;
                            if (Api.Str(p["kind"]) != "group") list.Add(id); else inner.Add(id);
                        }
                        members[gid] = list;
                        if (inner.Count > 0) nested[gid] = inner;
                    }).ConfigureAwait(false);
                }
                // ---------- identity governance: access packages and PIM for Groups
                Step("Reading access packages and PIM for Groups…");
                await TryStep("Access packages (needs Entra ID Governance)", async () =>
                {
                    foreach (var p in await _api.GraphListAsync("/identityGovernance/entitlementManagement/accessPackages?$expand=catalog", ct).ConfigureAwait(false))
                    {
                        var pid = S(p, "id");
                        var groupsOf = new JsonArray();
                        var full = await _api.GraphGetAsync($"/identityGovernance/entitlementManagement/accessPackages/{pid}?$expand=resourceRoleScopes($expand=role,scope)", ct).ConfigureAwait(false);
                        foreach (var rrs in (full?["resourceRoleScopes"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
                        {
                            var scope = rrs["scope"] as JsonObject;
                            if (string.Equals(S(scope, "originSystem"), "AadGroup", StringComparison.OrdinalIgnoreCase) && S(scope, "originId").Length > 0)
                                groupsOf.Add(S(scope, "originId"));
                        }
                        packages.Add(new JsonObject { ["id"] = pid, ["name"] = S(p, "displayName"), ["catalog"] = S(p["catalog"] as JsonObject, "displayName"), ["groups"] = groupsOf });
                    }
                }).ConfigureAwait(false);
                if (packages.Count > 0)
                {
                    await TryStep("Access package assignments", async () =>
                    {
                        foreach (var a in await _api.GraphListAsync("/identityGovernance/entitlementManagement/assignments?$expand=target,accessPackage", ct).ConfigureAwait(false))
                        {
                            if (!string.Equals(S(a, "state"), "delivered", StringComparison.OrdinalIgnoreCase)) continue;
                            var o = new JsonObject { ["p"] = S(a["target"] as JsonObject, "objectId"), ["pkg"] = S(a["accessPackage"] as JsonObject, "id") };
                            var until = Api.Str(a["schedule"]?["expiration"]?["endDateTime"]);
                            if (!string.IsNullOrEmpty(until)) o["until"] = until;
                            packageAssignments.Add(o);
                        }
                    }).ConfigureAwait(false);
                    await TryStep("Pending access package requests", async () =>
                    {
                        foreach (var r in await _api.GraphListAsync("/identityGovernance/entitlementManagement/assignmentRequests?$expand=requestor,accessPackage", ct).ConfigureAwait(false))
                        {
                            if (!string.Equals(S(r, "state"), "pendingApproval", StringComparison.OrdinalIgnoreCase)) continue;
                            packageRequests.Add(new JsonObject { ["p"] = S(r["requestor"] as JsonObject, "objectId"), ["pkg"] = S(r["accessPackage"] as JsonObject, "id"),
                                ["created"] = S(r, "createdDateTime") });
                        }
                    }).ConfigureAwait(false);
                }
                var pimGroupsOk = true;
                foreach (var g in groups.Take(_o.MaxGroupsExpanded))
                {
                    if (!pimGroupsOk) break;
                    var gid = Api.Str(g["id"]);
                    try
                    {
                        foreach (var e in await _api.GraphListAsync($"/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$filter=groupId eq '{gid}'", ct).ConfigureAwait(false))
                        {
                            if (!string.Equals(S(e, "accessId"), "member", StringComparison.OrdinalIgnoreCase)) continue;
                            var o = new JsonObject { ["g"] = gid, ["p"] = S(e, "principalId") };
                            if (S(e, "endDateTime").Length > 0) o["until"] = S(e, "endDateTime");
                            groupEligible.Add(o);
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        pimGroupsOk = false;                    // same permission for every group: note it once
                        _warnings.Add("PIM for Groups skipped: " + ex.Message);
                    }
                }
                // identities that only appear in packages, requests or PIM for Groups
                var more = packageAssignments.Concat(packageRequests).Concat(groupEligible).Select(x => Api.Str(x["p"]))
                    .Where(x => !string.IsNullOrEmpty(x) && !principals.ContainsKey(x)).Distinct().ToList();
                if (more.Count > 0)
                    await TryStep("Identity names (governance)", async () =>
                    {
                        for (var i = 0; i < more.Count; i += 1000)
                        {
                            var body = new JsonObject
                            {
                                ["ids"] = new JsonArray(more.Skip(i).Take(1000).Select(x => (JsonNode)JsonValue.Create(x)).ToArray()),
                                ["types"] = new JsonArray(JsonValue.Create("user"), JsonValue.Create("group"), JsonValue.Create("servicePrincipal"))
                            };
                            var r = await _api.GraphPostAsync("/directoryObjects/getByIds", body, ct).ConfigureAwait(false);
                            if (r?["value"] is JsonArray v) foreach (var o in v.OfType<JsonObject>()) AddPrincipal(o);
                        }
                    }).ConfigureAwait(false);

                // ---------- owners of privileged groups: an owner can add anyone, themselves included
                var privHolders = new HashSet<string>(azure.Concat(entra).Where(a => S(a as JsonObject, "priv") == "true").Select(a => Api.Str(a["p"])));
                foreach (var g in groups.Where(x => privHolders.Contains(Api.Str(x["id"]))).Take(_o.MaxGroupsExpanded))
                {
                    var gid = Api.Str(g["id"]);
                    await TryStep("Owners of " + Api.Str(g["name"]), async () =>
                    {
                        var list = new JsonArray();
                        foreach (var o in await _api.GraphListAsync($"/groups/{gid}/owners?$select=id,displayName,userPrincipalName,userType", ct).ConfigureAwait(false))
                        {
                            AddPrincipal(o);
                            if (principals.ContainsKey(S(o, "id"))) list.Add(S(o, "id"));
                        }
                        if (list.Count > 0) groupOwners[gid] = list;
                    }).ConfigureAwait(false);
                }

                // ---------- apps: registrations with their secrets, certificates and owners
                Step("Reading app registrations and their secrets…");
                var spByAppId = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
                await TryStep("Enterprise applications", async () =>
                {
                    foreach (var sp in await _api.GraphListAsync("/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId&$top=999", ct).ConfigureAwait(false))
                        if (S(sp, "appId").Length > 0) spByAppId[S(sp, "appId")] = sp;
                }).ConfigureAwait(false);
                await TryStep("App registrations", async () =>
                {
                    foreach (var a in await _api.GraphListAsync("/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials&$expand=owners&$top=100", ct).ConfigureAwait(false))
                    {
                        var creds = new JsonArray();
                        foreach (var c in (a["passwordCredentials"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
                            creds.Add(new JsonObject { ["t"] = "secret", ["name"] = S(c, "displayName"), ["start"] = S(c, "startDateTime"), ["end"] = S(c, "endDateTime") });
                        foreach (var c in (a["keyCredentials"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
                            creds.Add(new JsonObject { ["t"] = "cert", ["name"] = S(c, "displayName"), ["start"] = S(c, "startDateTime"), ["end"] = S(c, "endDateTime") });
                        var owners = new JsonArray();
                        foreach (var o in (a["owners"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
                        {
                            AddPrincipal(o);
                            if (principals.ContainsKey(S(o, "id"))) owners.Add(S(o, "id"));
                        }
                        var app = new JsonObject { ["id"] = S(a, "id"), ["appId"] = S(a, "appId"), ["name"] = S(a, "displayName"), ["created"] = S(a, "createdDateTime"),
                            ["audience"] = S(a, "signInAudience"), ["owners"] = owners, ["creds"] = creds };
                        if (spByAppId.TryGetValue(S(a, "appId"), out var spo)) app["sp"] = S(spo, "id");
                        apps.Add(app);
                    }
                }).ConfigureAwait(false);
                await TryStep("Microsoft Graph application permissions", async () =>
                {
                    var graphSp = (await _api.GraphListAsync("/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=id,appRoles", ct).ConfigureAwait(false)).FirstOrDefault();
                    if (graphSp == null) return;
                    var roleNames = ((graphSp["appRoles"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>()).ToDictionary(r => S(r, "id"), r => S(r, "value"));
                    var spById = spByAppId.Values.ToDictionary(x => S(x, "id"));
                    foreach (var x in await _api.GraphListAsync($"/servicePrincipals/{S(graphSp, "id")}/appRoleAssignedTo?$top=999", ct).ConfigureAwait(false))
                    {
                        if (!string.Equals(S(x, "principalType"), "ServicePrincipal", StringComparison.OrdinalIgnoreCase)) continue;
                        if (!roleNames.TryGetValue(S(x, "appRoleId"), out var perm)) continue;
                        var o = new JsonObject { ["p"] = S(x, "principalId"), ["name"] = S(x, "principalDisplayName"), ["perm"] = perm };
                        if (spById.TryGetValue(S(x, "principalId"), out var spx) && S(spx, "appOwnerOrganizationId").Length > 0 &&
                            !string.Equals(S(spx, "appOwnerOrganizationId"), _tenant, StringComparison.OrdinalIgnoreCase)) o["external"] = true;
                        appPerms.Add(o);
                    }
                }).ConfigureAwait(false);

                // ---------- cross-tenant access: which other organizations' MFA and devices are trusted
                await TryStep("Cross-tenant access settings", async () =>
                {
                    JsonObject Trust(JsonNode n)
                    {
                        var t = n?["inboundTrust"] as JsonObject;
                        var b2b = Api.Str(n?["b2bCollaborationInbound"]?["usersAndGroups"]?["accessType"]);
                        return new JsonObject { ["mfa"] = S(t, "isMfaAccepted") == "true", ["device"] = S(t, "isCompliantDeviceAccepted") == "true",
                            ["hybrid"] = S(t, "isHybridAzureADJoinedDeviceAccepted") == "true", ["b2bIn"] = string.IsNullOrEmpty(b2b) ? "default" : b2b };
                    }
                    var def = await _api.GraphGetAsync("/policies/crossTenantAccessPolicy/default", ct).ConfigureAwait(false);
                    var partners = new JsonArray();
                    foreach (var p in await _api.GraphListAsync("/policies/crossTenantAccessPolicy/partners", ct).ConfigureAwait(false))
                    {
                        var o = Trust(p); o["tenantId"] = S(p, "tenantId"); partners.Add(o);
                    }
                    crossTenant = new JsonObject { ["default"] = Trust(def), ["partners"] = partners };
                }).ConfigureAwait(false);

                await TryStep("Guest accounts", async () =>
                {
                    var guestIds = new HashSet<string>((await _api.GraphListAsync("/users?$filter=userType eq 'Guest'&$select=id&$top=999", ct).ConfigureAwait(false))
                        .Select(g => S(g, "id")));
                    foreach (var po in principals.Values.Where(x => Api.Str(x["kind"]) == "user"))
                        if (guestIds.Contains(Api.Str(po["id"]))) po["guest"] = true; else po.Remove("guest");
                }).ConfigureAwait(false);

                // leavers and stale accounts: the questions every access review and SOX test asks
                var users = principals.Values.Where(x => Api.Str(x["kind"]) == "user").ToList();
                await TryStep("Disabled accounts", async () =>
                {
                    var disabled = new HashSet<string>((await _api.GraphListAsync("/users?$filter=accountEnabled eq false&$select=id&$top=999", ct).ConfigureAwait(false))
                        .Select(u => S(u, "id")));
                    foreach (var po in users) if (disabled.Contains(Api.Str(po["id"]))) po["disabled"] = true;
                }).ConfigureAwait(false);
                await TryStep("Last sign-in (needs AuditLog.Read.All and Entra ID P1)", async () =>
                {
                    var byId = users.ToDictionary(u => Api.Str(u["id"]));
                    var url = "/users?$select=id,signInActivity&$top=120";
                    for (var page = 0; url != null && byId.Count > 0; page++)
                    {
                        if (page >= _o.MaxSignInPages) { _warnings.Add($"Last sign-in was read for the first {page * 120} users only."); break; }
                        var r = await _api.GraphGetAsync(url, ct).ConfigureAwait(false);
                        foreach (var u in (r?["value"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
                        {
                            if (!byId.TryGetValue(S(u, "id"), out var po)) continue;
                            var a = u["signInActivity"] as JsonObject;
                            var last = new[] { S(a, "lastSuccessfulSignInDateTime"), S(a, "lastSignInDateTime"), S(a, "lastNonInteractiveSignInDateTime") }
                                .Where(x => x.Length > 0).OrderByDescending(x => x, StringComparer.Ordinal).FirstOrDefault();
                            po["lastSignIn"] = last ?? "never";
                        }
                        var next = Api.Str(r?["@odata.nextLink"]);
                        url = string.IsNullOrEmpty(next) ? null : next;
                    }
                }).ConfigureAwait(false);

                Step("Reading Conditional Access policies…");
                await TryStep("Conditional Access policies", async () =>
                {
                    foreach (var p in await _api.GraphListAsync("/identity/conditionalAccess/policies?$select=id,displayName,state", ct).ConfigureAwait(false))
                        ca.Add(new JsonObject { ["name"] = S(p, "displayName"), ["state"] = S(p, "state") });
                }).ConfigureAwait(false);

                // ---------- Microsoft 365: teams with owners, members, guests and channels; the SharePoint site inventory
                if (_o.M365)
                {
                    m365 = new JsonObject();
                    var people = new JsonObject();              // everyone who appears in a team, by object ID
                    void Person(string id, string name, string upn, bool guest)
                    {
                        if (string.IsNullOrEmpty(id) || people.ContainsKey(id)) return;
                        people[id] = new JsonObject { ["name"] = name, ["upn"] = upn, ["guest"] = guest };
                    }
                    bool IsGuest(JsonObject u) => S(u, "userType").Length > 0                 // same rule as for everyone else
                        ? S(u, "userType") == "Guest" : S(u, "userPrincipalName").IndexOf("#EXT#", StringComparison.OrdinalIgnoreCase) >= 0;
                    var teams = new JsonArray();
                    var nickToTeam = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
                    var teamGroups = new List<JsonObject>();
                    Step("Reading Microsoft Teams…");
                    await TryStep("Microsoft Teams", async () =>
                    {
                        teamGroups = await _api.GraphListAsync("/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName,visibility,createdDateTime,mailNickname&$top=999", ct).ConfigureAwait(false);
                    }).ConfigureAwait(false);
                    if (teamGroups.Count > _o.MaxTeams)
                    {
                        _warnings.Add($"Only the first {_o.MaxTeams} of {teamGroups.Count} teams were read.");
                        teamGroups = teamGroups.Take(_o.MaxTeams).ToList();
                    }
                    var channelsDenied = false; var channelMembersDenied = false; var teamErrors = 0; var i = 0;
                    foreach (var g in teamGroups)
                    {
                        if (++i % 25 == 0) Step($"Teams: {i} of {teamGroups.Count}…");
                        var tid = S(g, "id");
                        var team = new JsonObject { ["id"] = tid, ["name"] = S(g, "displayName"), ["visibility"] = S(g, "visibility").ToLowerInvariant(),
                            ["created"] = S(g, "createdDateTime"), ["nick"] = S(g, "mailNickname"),
                            ["owners"] = new JsonArray(), ["members"] = new JsonArray(), ["guests"] = 0, ["channels"] = new JsonArray() };
                        try
                        {
                            var tOwners = new JsonArray(); var tMembers = new JsonArray(); var tGuests = 0;
                            foreach (var o in await _api.GraphListAsync($"/groups/{tid}/owners?$select=id,displayName,userPrincipalName,userType&$top=999", ct).ConfigureAwait(false))
                            {
                                if (!S(o, "@odata.type").EndsWith("user", StringComparison.OrdinalIgnoreCase)) continue;
                                Person(S(o, "id"), S(o, "displayName"), S(o, "userPrincipalName"), IsGuest(o)); tOwners.Add(S(o, "id"));
                            }
                            foreach (var m in await _api.GraphListAsync($"/groups/{tid}/members?$select=id,displayName,userPrincipalName,userType&$top=999", ct).ConfigureAwait(false))
                            {
                                if (!S(m, "@odata.type").EndsWith("user", StringComparison.OrdinalIgnoreCase)) continue;
                                Person(S(m, "id"), S(m, "displayName"), S(m, "userPrincipalName"), IsGuest(m)); tMembers.Add(S(m, "id"));
                                if (IsGuest(m)) tGuests++;
                            }
                            team["owners"] = tOwners; team["members"] = tMembers; team["guests"] = tGuests;
                            var channels = new JsonArray();
                            if (!channelsDenied)
                            {
                                try
                                {
                                    foreach (var c in await _api.GraphListAsync($"/teams/{tid}/channels?$select=id,displayName,membershipType", ct).ConfigureAwait(false))
                                    {
                                        var type = S(c, "membershipType").Length > 0 ? S(c, "membershipType") : "standard";
                                        var ch = new JsonObject { ["id"] = S(c, "id"), ["name"] = S(c, "displayName"), ["type"] = type };
                                        if ((type == "private" || type == "shared") && !channelMembersDenied)   // these have their own members
                                        {
                                            try
                                            {
                                                var cm = new JsonArray();
                                                foreach (var x in await _api.GraphListAsync($"/teams/{tid}/channels/{Uri.EscapeDataString(S(c, "id"))}/members", ct).ConfigureAwait(false))
                                                {
                                                    var uid = S(x, "userId");
                                                    if (uid.Length == 0) continue;
                                                    // people from another organization (shared channels, guests) count as guests
                                                    var home = S(x, "tenantId");
                                                    Person(uid, S(x, "displayName"), S(x, "email"), home.Length > 0 && !string.Equals(home, _tenant, StringComparison.OrdinalIgnoreCase));
                                                    cm.Add(uid);
                                                }
                                                ch["members"] = cm;
                                            }
                                            catch (ApiException ex) when (ex.Status == 401 || ex.Status == 403)
                                            {
                                                channelMembersDenied = true;
                                                _warnings.Add("Members of private and shared channels skipped: needs the ChannelMember.Read.All permission (" + ex.Message + ")");
                                            }
                                        }
                                        channels.Add(ch);
                                    }
                                }
                                catch (ApiException ex) when (ex.Status == 401 || ex.Status == 403)
                                {
                                    channelsDenied = true;
                                    _warnings.Add("Teams channels skipped: needs the Channel.ReadBasic.All and ChannelMember.Read.All permissions (" + ex.Message + ")");
                                }
                            }
                            team["channels"] = channels;
                        }
                        catch (Exception ex) when (!(ex is OperationCanceledException)) { teamErrors++; }
                        teams.Add(team);
                        if (S(team, "nick").Length > 0) nickToTeam[S(team, "nick")] = team;
                    }
                    if (teamErrors > 0) _warnings.Add($"{teamErrors} team(s) couldn't be read completely.");

                    // the SharePoint site inventory comes from Microsoft 365's usage report: every site in the tenant
                    var sites = new JsonArray();
                    var concealed = false; string reportDate = null;
                    Step("Reading the SharePoint site inventory…");
                    await TryStep("SharePoint sites (needs Reports.Read.All and a reports or admin role)", async () =>
                    {
                        var csv = await _api.GraphGetTextAsync("/reports/getSharePointSiteUsageDetail(period='D30')", ct).ConfigureAwait(false);
                        var rows = Csv(csv);
                        if (rows.Count == 0) return;
                        var head = rows[0].Select(h => h.Trim().TrimStart('\uFEFF')).ToList();
                        int Col(string name) => head.FindIndex(h => string.Equals(h, name, StringComparison.OrdinalIgnoreCase));
                        string Cell(List<string> r, string name) { var k = Col(name); return k >= 0 && k < r.Count ? r[k].Trim() : ""; }
                        long Num(List<string> r, string name) => long.TryParse(Cell(r, name), out var v) ? v : 0;
                        foreach (var r in rows.Skip(1))
                        {
                            if (r.Count < 3 || Cell(r, "Is Deleted").Equals("True", StringComparison.OrdinalIgnoreCase)) continue;
                            reportDate = reportDate ?? Cell(r, "Report Refresh Date");
                            var url = Cell(r, "Site URL");
                            if (url.Length == 0 || !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) concealed = true;
                            var site = new JsonObject
                            {
                                ["id"] = Cell(r, "Site Id"), ["url"] = url, ["owner"] = Cell(r, "Owner Display Name"), ["ownerUpn"] = Cell(r, "Owner Principal Name"),
                                ["template"] = Cell(r, "Root Web Template"), ["lastActivity"] = Cell(r, "Last Activity Date"), ["files"] = Num(r, "File Count"),
                                ["storage"] = Num(r, "Storage Used (Byte)"), ["externalSharing"] = Cell(r, "External Sharing"),
                                ["anonymousLinks"] = Num(r, "Anonymous Link Count"), ["guestLinks"] = Num(r, "Secure Link For Guest Count")
                            };
                            // which team a site belongs to: /sites/<mailNickname> (or <mailNickname>-<channel> for a channel site)
                            var path = url.Length > 0 && Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.AbsolutePath.Trim('/') : "";
                            var leaf = path.Contains("/") ? path.Substring(path.IndexOf('/') + 1) : "";
                            site["name"] = leaf.Length > 0 ? Uri.UnescapeDataString(leaf) : (url.Length > 0 && Uri.TryCreate(url, UriKind.Absolute, out var root) ? root.Host : Cell(r, "Site Id"));
                            JsonObject team = null;
                            if (leaf.Length > 0 && !nickToTeam.TryGetValue(leaf, out team))
                            {
                                var dash = leaf.LastIndexOf('-');           // longest team name first: Proj-Alpha-General → Proj-Alpha, then Proj
                                while (team == null && dash > 0) { nickToTeam.TryGetValue(leaf.Substring(0, dash), out team); dash = dash > 0 ? leaf.LastIndexOf('-', dash - 1) : -1; }
                                if (team != null && !S(site, "template").StartsWith("TEAMCHANNEL", StringComparison.OrdinalIgnoreCase)) team = null;
                            }
                            if (team == null && S(site, "template").StartsWith("GROUP", StringComparison.OrdinalIgnoreCase))
                                team = teams.OfType<JsonObject>().FirstOrDefault(t => string.Equals(S(t, "name"), S(site, "owner"), StringComparison.OrdinalIgnoreCase));
                            if (team != null)
                            {
                                site["team"] = S(team, "id");
                                if (S(site, "template").StartsWith("TEAMCHANNEL", StringComparison.OrdinalIgnoreCase)) site["channelSite"] = true;
                                else team["site"] = S(site, "id");
                            }
                            sites.Add(site);
                        }
                        if (concealed) _warnings.Add("SharePoint site names are concealed in Microsoft 365 reports (admin setting \"Display concealed user, group and site names in all reports\"), so sites can't be named or linked to teams.");
                    }).ConfigureAwait(false);
                    m365["teams"] = teams; m365["sites"] = sites; m365["people"] = people;
                    m365["reportDate"] = reportDate; m365["concealed"] = concealed;
                }

            }
            else
            {
                _warnings.Add("Entra data not collected: identities show as object IDs and group members are not expanded.");
            }
            foreach (var a in azure)                    // anything Graph couldn't resolve keeps its object ID
            {
                var p = Api.Str(a["p"]);
                if (principals.ContainsKey(p)) continue;
                principalKinds.TryGetValue(p, out var t);
                var kind = t == "User" ? "user" : t == "Group" ? "group" : t == "ServicePrincipal" ? "sp" : "other";
                principals[p] = new JsonObject { ["id"] = p, ["name"] = p, ["kind"] = kind, ["unresolved"] = true };
            }

            Step("Done.");
            var nodes = new JsonArray();
            foreach (var id in _order) nodes.Add(_nodes[id]);
            return new JsonObject
            {
                ["meta"] = new JsonObject
                {
                    ["title"] = "TenantWise", ["generated"] = DateTime.UtcNow.ToString("o"), ["scope"] = _o.Scope.Describe(),
                    ["tenantId"] = _tenant, ["tenantName"] = tenantName, ["tenantDomain"] = tenantDomain, ["entra"] = _o.Entra,
                    ["warnings"] = new JsonArray(_warnings.Select(w => (JsonNode)JsonValue.Create(w)).ToArray()),
                    // how this information was produced: what auditors ask for to rely on it (completeness and accuracy)
                    ["provenance"] = new JsonObject
                    {
                        ["account"] = _o.Account, ["tool"] = "TenantWise " + (_o.ToolVersion ?? "dev"),
                        ["started"] = started.ToString("o"), ["finished"] = DateTime.UtcNow.ToString("o"),
                        ["sources"] = new JsonArray(JsonValue.Create("Azure Resource Graph (api-version 2022-10-01)"), JsonValue.Create("Azure Resource Manager"),
                            JsonValue.Create(_o.Entra ? "Microsoft Graph v1.0" : "Microsoft Graph not read")),
                        ["requests"] = new JsonObject { ["resourceGraphQueries"] = _api.ResourceGraphQueries, ["armCalls"] = _api.ArmCalls,
                            ["graphCalls"] = _api.GraphCalls, ["retriedAfterThrottling"] = _api.Retries },
                        ["counts"] = new JsonObject { ["nodes"] = nodes.Count, ["connections"] = _edges.Count, ["identities"] = principals.Count,
                            ["azureAssignments"] = azure.Count, ["entraAssignments"] = entra.Count, ["policies"] = policies.Count },
                        ["complete"] = _warnings.Count == 0,
                        ["readOnly"] = true
                    }
                },
                ["nodes"] = nodes,
                ["edges"] = _edges,
                ["access"] = new JsonObject
                {
                    ["principals"] = new JsonArray(principals.Values.Cast<JsonNode>().ToArray()),
                    ["azure"] = azure, ["entra"] = entra, ["members"] = members, ["policies"] = policies, ["ca"] = ca,
                    ["packages"] = packages, ["packageAssignments"] = packageAssignments, ["packageRequests"] = packageRequests, ["groupEligible"] = groupEligible,
                    ["apps"] = apps, ["appPerms"] = appPerms, ["groupOwners"] = groupOwners, ["nested"] = nested, ["crossTenant"] = crossTenant
                },
                ["m365"] = m365
            };
        }
    }
}
