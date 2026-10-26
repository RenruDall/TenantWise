// TenantWise.Core — PresentationMask.cs
// Presentation mode for files that leave the app: people's names and emails are replaced with placeholders in the
// scan data itself, before it is written, so a saved report contains no real name or email anywhere (not even in
// its source). The placeholders follow the page's own masking (User 001, Guest 001, User M001…), so a saved report
// looks the same as the screen.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;

namespace TenantWise.Core
{
    public static class PresentationMask
    {
        public const string MaskedAccount = "masked account";

        /// <summary>Returns a masked copy of a scan (JSON text). The original is not changed.</summary>
        public static string Apply(string scanJson) => Apply(scanJson, null);

        /// <summary>Returns a masked copy of a scan and masks <paramref name="alsoMask"/> (for example the access review saved
        /// with it) in place with the same placeholders: sign-in names wherever they appear, and the reviewer.</summary>
        public static string Apply(string scanJson, IEnumerable<JsonNode> alsoMask)
        {
            var root = JsonNode.Parse(scanJson ?? "{}") as JsonObject ?? new JsonObject();
            var names = new Dictionary<string, string>(StringComparer.Ordinal);            // real display name -> placeholder
            var upns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);   // real sign-in name -> placeholder
            void Map(string real, string placeholder, Dictionary<string, string> into)
            {
                if (!string.IsNullOrWhiteSpace(real) && !into.ContainsKey(real)) into[real] = placeholder;
            }

            // 1. identities, numbered in their order like the page does (members and guests counted separately)
            int users = 0, guests = 0;
            var byId = new Dictionary<string, (string Name, string Upn)>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in (root["access"]?["principals"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
            {
                if (Api.Str(p["kind"]) != "user" || Bool(p["unresolved"])) continue;
                var guest = Bool(p["guest"]);
                var n = (guest ? ++guests : ++users).ToString("000");
                var realUpn = Api.Str(p["upn"]);
                var name = (guest ? "Guest " : "User ") + n;
                var upn = (guest ? "guest" : "user") + n + "@" + (guest ? HomeOf(realUpn) ?? "partner" : "masked");
                Map(Api.Str(p["name"]), name, names); Map(realUpn, upn, upns);
                p["name"] = name; p["upn"] = upn;
                if (!string.IsNullOrEmpty(Api.Str(p["id"]))) byId[Api.Str(p["id"])] = (name, upn);
            }

            // 2. people known only from Microsoft 365 (team owners and members, site owners)
            var m365 = root["m365"] as JsonObject;
            var extra = 0;
            if (m365?["people"] is JsonObject people)
                foreach (var kv in people.ToList())
                {
                    if (!(kv.Value is JsonObject u)) continue;
                    var realUpn = Api.Str(u["upn"]);
                    if (byId.TryGetValue(kv.Key, out var same))                      // already masked as an identity: the same placeholder
                    { Map(Api.Str(u["name"]), same.Name, names); Map(realUpn, same.Upn, upns); u["name"] = same.Name; u["upn"] = same.Upn; continue; }
                    var guest = Bool(u["guest"]);
                    var k = (++extra).ToString("000");
                    var name = (guest ? "Guest M" : "User M") + k;
                    var upn = (guest ? "guest-m" : "user-m") + k + "@masked";
                    Map(Api.Str(u["name"]), name, names); Map(realUpn, upn, upns);
                    u["name"] = name; u["upn"] = upn;
                }
            foreach (var site in (m365?["sites"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
            {
                if (!string.IsNullOrEmpty(Api.Str(site["team"]))) continue;       // a team site's owner is the team, not a person (as on the page)
                var realUpn = Api.Str(site["ownerUpn"]);
                var realName = Api.Str(site["owner"]);
                if (string.IsNullOrEmpty(realUpn) && string.IsNullOrEmpty(realName)) continue;
                string upn = null, name = null;
                if (!string.IsNullOrEmpty(realUpn) && !upns.TryGetValue(realUpn, out upn))
                {
                    var k = (++extra).ToString("000");
                    upn = "user-m" + k + "@masked"; name = "User M" + k;
                    Map(realUpn, upn, upns); Map(realName, name, names);
                }
                if (name == null && !string.IsNullOrEmpty(realName) && !names.TryGetValue(realName, out name))
                {
                    var k = (++extra).ToString("000");
                    name = "User M" + k;
                    Map(realName, name, names);
                }
                if (site.ContainsKey("ownerUpn")) site["ownerUpn"] = upn ?? "";
                if (site.ContainsKey("owner")) site["owner"] = name ?? "";
            }

            // 3. who ran the scan
            if (root["meta"]?["provenance"] is JsonObject pv && !string.IsNullOrEmpty(Api.Str(pv["account"])))
            {
                Map(Api.Str(pv["account"]), MaskedAccount, upns);
                pv["account"] = MaskedAccount;
            }

            // 4. anything else that still quotes a sign-in name (tags, notes, warnings): replaced wherever it appears
            var replace = upns.Keys.Where(k => k.Contains("@")).OrderByDescending(k => k.Length).ToList();
            if (replace.Count > 0) Scrub(root, replace, upns);
            foreach (var other in alsoMask ?? Enumerable.Empty<JsonNode>())
            {
                if (other == null) continue;
                if (other["signedOff"] is JsonObject so)                      // who signed is a person too
                    foreach (var k in new[] { "reviewer", "onBehalfOf" })
                        if (!string.IsNullOrEmpty(Api.Str(so[k]))) so[k] = upns.TryGetValue(Api.Str(so[k]), out var m) ? m : MaskedAccount;
                if (replace.Count > 0) Scrub(other, replace, upns);
            }
            return root.ToJsonString();
        }

        private static bool Bool(JsonNode n) => string.Equals(Api.Str(n), "true", StringComparison.OrdinalIgnoreCase);

        /// <summary>The guest's home domain (kept when names are masked), like the page's guestHome.</summary>
        public static string HomeOf(string upn)
        {
            var u = upn ?? "";
            var ext = u.IndexOf("#EXT#@", StringComparison.OrdinalIgnoreCase);
            if (ext > 0) { var local = u.Substring(0, ext); var i = local.LastIndexOf('_'); return i > 0 ? local.Substring(i + 1).ToLowerInvariant() : null; }
            var at = u.LastIndexOf('@');
            return at > 0 ? u.Substring(at + 1).ToLowerInvariant() : null;
        }

        private static void Scrub(JsonNode node, List<string> realUpns, Dictionary<string, string> map)
        {
            if (node is JsonObject o)
                foreach (var kv in o.ToList())
                {
                    if (kv.Value is JsonValue v && v.TryGetValue(out string s)) { var r = ReplaceAll(s, realUpns, map); if (!ReferenceEquals(r, s)) o[kv.Key] = r; }
                    else if (kv.Value != null) Scrub(kv.Value, realUpns, map);
                }
            else if (node is JsonArray a)
                for (var i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonValue v && v.TryGetValue(out string s)) { var r = ReplaceAll(s, realUpns, map); if (!ReferenceEquals(r, s)) a[i] = r; }
                    else if (a[i] != null) Scrub(a[i], realUpns, map);
                }
        }

        private static string ReplaceAll(string s, List<string> realUpns, Dictionary<string, string> map)
        {
            if (string.IsNullOrEmpty(s) || s.IndexOf('@') < 0) return s;
            var result = s;
            foreach (var real in realUpns)
            {
                var i = result.IndexOf(real, StringComparison.OrdinalIgnoreCase);
                while (i >= 0)
                {
                    result = result.Substring(0, i) + map[real] + result.Substring(i + real.Length);
                    i = result.IndexOf(real, i + map[real].Length, StringComparison.OrdinalIgnoreCase);
                }
            }
            return result == s ? s : result;
        }
    }
}
