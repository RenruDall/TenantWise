// TenantWise.Core — AppAccess.cs
// Who may use which feature of TenantWise.
// - Global Administrators of the tenant always may use everything, and only they manage access.
// - Everyone else may use nothing until a Global Administrator gives them features in TenantWise's access dashboard:
//   per group, or per person (for example a group lead who gets more than the group). Rights add up: a person gets
//   what all their groups allow plus their own ticks.
// - The ticks are stored where Entra keeps them for every app: as app role assignments on TenantWise's own enterprise
//   application, so every copy of TenantWise reads the same rules at sign-in. Changing them is the only thing TenantWise
//   ever changes in a tenant, and only when a Global Administrator saves in the dashboard.
// Roles decide what TenantWise lets someone do. What they can read is still decided by their own Azure and Entra rights.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace TenantWise.Core
{
    public sealed class AppRoleDef
    {
        public string Value { get; }
        public string Id { get; }
        public string Name { get; }
        public string Description { get; }
        public string Feature { get; }
        public AppRoleDef(string value, string id, string name, string description, string feature)
        { Value = value; Id = id; Name = name; Description = description; Feature = feature; }
    }

    public sealed class AccessDecision
    {
        public bool GlobalAdmin { get; set; }
        public string[] Roles { get; set; } = new string[0];
        public string[] Features { get; set; } = new string[0];
        public string Note { get; set; }
        public bool Allows(string feature) => GlobalAdmin || Features.Contains(feature);
        public bool CanManage => GlobalAdmin;

        public JsonObject ToJson() => new JsonObject
        {
            ["enforced"] = true, ["globalAdmin"] = GlobalAdmin,
            ["roles"] = new JsonArray(Roles.Select(r => (JsonNode)JsonValue.Create(r)).ToArray()),
            ["features"] = new JsonArray((GlobalAdmin ? AppAccess.AllFeatures.Concat(new[] { "admin" }) : Features).Select(r => (JsonNode)JsonValue.Create(r)).ToArray()),
            ["note"] = Note
        };
    }

    public static class AppAccess
    {
        public const string GlobalAdminTemplate = "62e90394-69f5-4237-9190-012177145e10";

        /// <summary>Delegated permissions only "Manage access" uses. They must never be consented for the whole organization.</summary>
        public static readonly string[] WriteScopes = { "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All" };

        /// <summary>The features an administrator can give. Tenants, scanning and personal settings come with any of them.</summary>
        public static readonly string[] AllFeatures = { "map", "access", "apps", "findings", "audit", "signoff", "export" };

        /// <summary>One app role per feature (the IDs never change: they identify the role in every tenant).</summary>
        public static readonly AppRoleDef[] Roles =
        {
            new AppRoleDef("TenantWise.Map", "74ead22e-ecca-56cb-bae5-d164a416afe1", "Map and network", "The map and network views.", "map"),
            new AppRoleDef("TenantWise.Access", "a6e52935-7fec-53cc-9dc2-bca39e066ee3", "Access and identities", "The Access view: who can do what, hidden admins, offboarding checklists.", "access"),
            new AppRoleDef("TenantWise.Apps", "19be756f-e8cd-54cf-9db8-49776f31451b", "Apps and secrets", "The Apps view: app registrations, secrets, certificates, permissions.", "apps"),
            new AppRoleDef("TenantWise.Findings", "cb0c43ba-4e67-5904-81d8-c8c888cb3f5a", "Findings", "The Findings view and the management summary.", "findings"),
            new AppRoleDef("TenantWise.Audit", "34788434-9167-5208-b9dd-998829cc8d2d", "Audit and changes", "The Audit view (evidence, scope, access review decisions, activity log) and Changes.", "audit"),
            new AppRoleDef("TenantWise.SignOff", "b740f296-ed90-54c4-84ba-b9c9a6308549", "Sign off access reviews", "Sign off an access review and save the signed evidence.", "signoff"),
            new AppRoleDef("TenantWise.Export", "2c573786-9b5d-598d-b238-f0a45ef7d477", "Export", "Save reports, CSV exports, the audit report, offboarding checklists and the management summary.", "export"),
        };

        public static AppRoleDef Find(string value) => Roles.FirstOrDefault(r => string.Equals(r.Value, value, StringComparison.OrdinalIgnoreCase));
        public static AppRoleDef FindById(string id) => Roles.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));

        /// <summary>The "roles" claim of an ID token (a JWT). The signature isn't checked: the token comes straight from
        /// Microsoft's sign-in library over the local broker, and the roles only shape what this app shows.</summary>
        public static string[] RolesFromIdToken(string jwt)
        {
            try
            {
                var parts = (jwt ?? "").Split('.');
                if (parts.Length < 2) return new string[0];
                var b64 = parts[1].Replace('-', '+').Replace('_', '/');
                b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
                var payload = JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(b64))) as JsonObject;
                return (payload?["roles"] as JsonArray)?.Select(Api.Str).Where(x => !string.IsNullOrEmpty(x)).ToArray() ?? new string[0];
            }
            catch (Exception) { return new string[0]; }
        }

        /// <summary>What this person may use: everything as an active Global Administrator, otherwise what their roles give.</summary>
        public static AccessDecision Decide(bool globalAdmin, IEnumerable<string> tokenRoles)
        {
            var known = (tokenRoles ?? Enumerable.Empty<string>()).Select(Find).Where(r => r != null).ToList();
            var d = new AccessDecision
            {
                GlobalAdmin = globalAdmin,
                Roles = known.Select(r => r.Value).Distinct().ToArray(),
                Features = known.Select(r => r.Feature).Distinct().OrderBy(f => Array.IndexOf(AllFeatures, f)).ToArray()
            };
            if (!globalAdmin && d.Features.Length == 0)
                d.Note = "A Global Administrator of your organization hasn't given you access to TenantWise yet. Ask them to tick the features you need in TenantWise's access dashboard.";
            return d;
        }

        /// <summary>Whether the signed-in person holds Global Administrator right now (directly or through a role-assignable group).</summary>
        public static async Task<bool> IsGlobalAdminAsync(Api api, CancellationToken ct)
        {
            foreach (var r in await api.GraphListAsync("/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=id,displayName,roleTemplateId", ct).ConfigureAwait(false))
                if (string.Equals(Api.Str(r["roleTemplateId"]), GlobalAdminTemplate, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static async Task<JsonObject> ServicePrincipalAsync(Api api, string clientId, CancellationToken ct) =>
            (await api.GraphListAsync($"/servicePrincipals?$filter=appId eq '{Esc(clientId)}'&$select=id,appId,displayName,appRoles,appRoleAssignmentRequired", ct).ConfigureAwait(false))
                .FirstOrDefault(sp => string.Equals(Api.Str(sp["appId"]), clientId, StringComparison.OrdinalIgnoreCase));

        private static string Esc(string s) => (s ?? "").Replace("'", "''");

        /// <summary>TenantWise's own setup in Entra and everyone it gives features to (groups expanded to their members).</summary>
        public static async Task<JsonObject> ReadAsync(Api api, string clientId, CancellationToken ct)
        {
            var sp = await ServicePrincipalAsync(api, clientId, ct).ConfigureAwait(false);
            var result = new JsonObject { ["found"] = sp != null, ["clientId"] = clientId };
            if (sp == null) return result;
            var defined = ((sp["appRoles"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
                .Where(r => FindById(Api.Str(r["id"])) != null && Api.Str(r["isEnabled"]) != "false").Select(r => Api.Str(r["id"])).ToList();
            result["definedRoles"] = new JsonArray(defined.Select(id => (JsonNode)JsonValue.Create(FindById(id).Value)).ToArray());
            result["missingRoles"] = new JsonArray(Roles.Where(r => !defined.Contains(r.Id, StringComparer.OrdinalIgnoreCase)).Select(r => (JsonNode)JsonValue.Create(r.Value)).ToArray());
            result["assignmentRequired"] = Api.Str(sp["appRoleAssignmentRequired"]) == "true";
            // The write permissions must only ever be consented for the administrator who saves here, never for the
            // whole organization: report a tenant-wide grant so it can be revoked.
            var orgWide = new JsonArray();
            try
            {
                foreach (var g in await api.GraphListAsync($"/oauth2PermissionGrants?$filter=clientId eq '{Esc(Api.Str(sp["id"]))}'", ct).ConfigureAwait(false))
                    if (Api.Str(g["consentType"]) == "AllPrincipals")
                        foreach (var scope in (Api.Str(g["scope"]) ?? "").Split(' '))
                            if (WriteScopes.Contains(scope, StringComparer.OrdinalIgnoreCase)) orgWide.Add(scope);
            }
            catch (ApiException) { /* can't tell; the dashboard shows nothing */ }
            result["orgWideWriteConsent"] = orgWide;
            var list = new JsonArray();
            var groups = new JsonObject();
            foreach (var a in await api.GraphListAsync($"/servicePrincipals/{Api.Str(sp["id"])}/appRoleAssignedTo?$top=999", ct).ConfigureAwait(false))
            {
                var role = FindById(Api.Str(a["appRoleId"]));
                if (role == null) continue;                                   // default access or roles of other versions
                var type = Api.Str(a["principalType"]) ?? "";
                var pid = Api.Str(a["principalId"]);
                list.Add(new JsonObject { ["id"] = Api.Str(a["id"]), ["principalId"] = pid, ["type"] = type, ["name"] = Api.Str(a["principalDisplayName"]),
                    ["role"] = role.Value, ["created"] = Api.Str(a["createdDateTime"]) });
                if (type == "Group" && pid != null && !groups.ContainsKey(pid))
                {
                    var members = new JsonArray();
                    foreach (var m in await api.GraphListAsync($"/groups/{pid}/transitiveMembers?$select=id,displayName,userPrincipalName&$top=999", ct).ConfigureAwait(false))
                        if ((Api.Str(m["@odata.type"]) ?? "").EndsWith("user", StringComparison.OrdinalIgnoreCase))
                            members.Add(new JsonObject { ["id"] = Api.Str(m["id"]), ["name"] = Api.Str(m["displayName"]), ["upn"] = Api.Str(m["userPrincipalName"]) });
                    groups[pid] = members;
                }
            }
            result["assignments"] = list;
            result["groupMembers"] = groups;
            return result;
        }

        /// <summary>Users and groups whose name (or sign-in name) starts with the text, for the dashboard's picker.</summary>
        public static async Task<JsonArray> SearchAsync(Api api, string text, CancellationToken ct)
        {
            var raw = (text ?? "").Trim();
            var found = new JsonArray();
            if (raw.Length < 2) return found;
            var q = Uri.EscapeDataString(Esc(raw));                          // quotes doubled for OData, then URL-encoded
            foreach (var u in await api.GraphListAsync($"/users?$filter=startswith(displayName,'{q}') or startswith(userPrincipalName,'{q}')&$select=id,displayName,userPrincipalName&$top=15", ct).ConfigureAwait(false))
                found.Add(new JsonObject { ["id"] = Api.Str(u["id"]), ["type"] = "User", ["name"] = Api.Str(u["displayName"]), ["upn"] = Api.Str(u["userPrincipalName"]) });
            foreach (var g in await api.GraphListAsync($"/groups?$filter=startswith(displayName,'{q}')&$select=id,displayName,description&$top=15", ct).ConfigureAwait(false))
                found.Add(new JsonObject { ["id"] = Api.Str(g["id"]), ["type"] = "Group", ["name"] = Api.Str(g["displayName"]), ["description"] = Api.Str(g["description"]) });
            return found;
        }

        /// <summary>Adds the feature roles to TenantWise's app registration (only the missing ones; nothing else is touched).</summary>
        public static async Task<int> SetupRolesAsync(Api api, string clientId, CancellationToken ct)
        {
            var app = (await api.GraphListAsync($"/applications?$filter=appId eq '{Esc(clientId)}'&$select=id,appId,appRoles", ct).ConfigureAwait(false))
                .FirstOrDefault(a => string.Equals(Api.Str(a["appId"]), clientId, StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException("TenantWise's app registration wasn't found in this tenant. Each organization registers TenantWise in its own tenant (see the README).");
            var existing = (app["appRoles"] as JsonArray)?.OfType<JsonObject>().Select(r => (JsonObject)r.DeepClone()).ToList() ?? new List<JsonObject>();
            var have = new HashSet<string>(existing.Select(r => (Api.Str(r["id"]) ?? "").ToLowerInvariant()));
            var add = ManifestRoles().OfType<JsonObject>().Where(r => !have.Contains(Api.Str(r["id"]))).Select(r => (JsonObject)r.DeepClone()).ToList();
            if (add.Count == 0) return 0;
            var all = new JsonArray(existing.Concat(add).Cast<JsonNode>().ToArray());
            await api.GraphWriteAsync("graph-setup", "PATCH", $"/applications/{Api.Str(app["id"])}", new JsonObject { ["appRoles"] = all }, ct).ConfigureAwait(false);
            return add.Count;
        }

        /// <summary>One change from the dashboard: give or take one feature from one user or group.</summary>
        public sealed class Change
        {
            public string PrincipalId { get; set; }
            public string Role { get; set; }
            public bool Grant { get; set; }
        }

        /// <summary>What ApplyAsync managed to do, also when it stops part-way (so the app can log it either way).</summary>
        public sealed class ApplyProgress
        {
            public int Granted { get; set; }
            public int Removed { get; set; }
            public List<string> Done { get; } = new List<string>();
        }

        /// <summary>Applies the dashboard's changes as app role assignments on TenantWise's own enterprise application.
        /// Every change is checked before the first one is made; progress shows what was done if Entra refuses one.</summary>
        public static async Task<(int granted, int removed)> ApplyAsync(Api api, string clientId, IList<Change> changes, CancellationToken ct, ApplyProgress progress = null)
        {
            progress = progress ?? new ApplyProgress();
            var checkedChanges = new List<(Change change, AppRoleDef role)>();
            foreach (var c in changes)
            {
                var role = Find(c.Role) ?? throw new InvalidOperationException("Unknown TenantWise feature " + c.Role);
                if (!Guid.TryParse(c.PrincipalId, out _)) throw new InvalidOperationException("Unknown user or group.");
                checkedChanges.Add((c, role));
            }
            var sp = await ServicePrincipalAsync(api, clientId, ct).ConfigureAwait(false)
                ?? throw new InvalidOperationException("TenantWise isn't registered as an enterprise application in this tenant yet.");
            var spId = Api.Str(sp["id"]);
            var current = await api.GraphListAsync($"/servicePrincipals/{spId}/appRoleAssignedTo?$top=999", ct).ConfigureAwait(false);
            foreach (var (c, role) in checkedChanges)
            {
                var have = current.Where(a => Api.Str(a["principalId"]) == c.PrincipalId && string.Equals(Api.Str(a["appRoleId"]), role.Id, StringComparison.OrdinalIgnoreCase)).ToList();
                if (c.Grant && have.Count == 0)
                {
                    await api.GraphWriteAsync("graph-manage", "POST", $"/servicePrincipals/{spId}/appRoleAssignedTo",
                        new JsonObject { ["principalId"] = c.PrincipalId, ["resourceId"] = spId, ["appRoleId"] = role.Id }, ct).ConfigureAwait(false);
                    progress.Granted++;
                    progress.Done.Add("+" + role.Value + " " + c.PrincipalId);
                }
                else if (!c.Grant)
                    foreach (var a in have)
                    {
                        await api.GraphWriteAsync("graph-manage", "DELETE", $"/servicePrincipals/{spId}/appRoleAssignedTo/{Api.Str(a["id"])}", null, ct).ConfigureAwait(false);
                        progress.Removed++;
                        progress.Done.Add("-" + role.Value + " " + c.PrincipalId);
                    }
            }
            return (progress.Granted, progress.Removed);
        }

        /// <summary>The roles as the app registration manifest wants them ("appRoles"), ready to paste.</summary>
        public static JsonArray ManifestRoles() => new JsonArray(Roles.Select(r => (JsonNode)new JsonObject
        {
            ["allowedMemberTypes"] = new JsonArray(JsonValue.Create("User")), ["description"] = r.Description, ["displayName"] = r.Name,
            ["id"] = r.Id, ["isEnabled"] = true, ["value"] = r.Value
        }).ToArray());
    }
}
