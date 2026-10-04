// TenantWise.Core — EvidenceLog.cs
// A tamper-evident activity log: one line per action (sign-in, scan, export, review sign-off), each line carrying the
// SHA-256 of the previous line plus its own content. Changing, removing or reordering any line breaks the chain,
// which Verify() reports. Also the hashing helpers used to fingerprint scans and exported files.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace TenantWise.Core
{
    public sealed class EvidenceLog
    {
        private const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";
        private static readonly object Gate = new object();
        private readonly string _path;

        public EvidenceLog(string path) { _path = path; }

        public static string Sha256Hex(byte[] data)
        {
            using (var sha = SHA256.Create())
                return string.Concat(sha.ComputeHash(data).Select(b => b.ToString("x2")));
        }

        public static string Sha256Hex(string text) => Sha256Hex(Encoding.UTF8.GetBytes(text ?? ""));

        /// <summary>Appends an entry: {time, action, ...details}. Returns the entry's hash.</summary>
        public string Append(string action, JsonObject details = null)
        {
            lock (Gate)
            {
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                var prev = Genesis;
                if (File.Exists(_path))
                {
                    var last = File.ReadLines(_path, Encoding.UTF8).LastOrDefault(l => l.Length > 65);
                    if (last != null) prev = last.Substring(0, 64);
                }
                var entry = new JsonObject { ["time"] = DateTime.UtcNow.ToString("o"), ["action"] = action };
                if (details != null)
                    foreach (var kv in details.ToList()) { details.Remove(kv.Key); entry[kv.Key] = kv.Value; }
                var json = entry.ToJsonString();
                var hash = Sha256Hex(prev + "\n" + json);
                File.AppendAllText(_path, hash + " " + json + "\n", new UTF8Encoding(false));
                return hash;
            }
        }

        /// <summary>Checks the whole chain. Problem names the first broken line (1-based), or null when intact.</summary>
        public (bool Ok, int Lines, string Problem) Verify()
        {
            if (!File.Exists(_path)) return (true, 0, null);
            var prev = Genesis;
            var n = 0;
            foreach (var line in File.ReadLines(_path, Encoding.UTF8))
            {
                if (line.Length == 0) continue;
                n++;
                if (line.Length < 66 || line[64] != ' ') return (false, n, $"Line {n} is malformed.");
                var hash = line.Substring(0, 64);
                if (Sha256Hex(prev + "\n" + line.Substring(65)) != hash) return (false, n, $"Line {n} was changed, removed or reordered.");
                prev = hash;
            }
            return (true, n, null);
        }

        /// <summary>The last entries (newest first), optionally only those for one tenant.</summary>
        public List<JsonObject> Recent(int max, string tenantId = null)
        {
            var list = new List<JsonObject>();
            if (!File.Exists(_path)) return list;
            foreach (var line in File.ReadLines(_path, Encoding.UTF8).Reverse())
            {
                if (line.Length < 66) continue;
                JsonObject o;
                try { o = JsonNode.Parse(line.Substring(65)) as JsonObject; } catch (Exception) { continue; }
                if (o == null) continue;
                if (tenantId != null && !string.Equals(Api.Str(o["tenant"]), tenantId, StringComparison.OrdinalIgnoreCase)) continue;
                o["hash"] = line.Substring(0, 64);
                list.Add(o);
                if (list.Count >= max) break;
            }
            return list;
        }
    }
}
