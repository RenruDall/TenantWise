// TenantWise.Core — EvidenceLog.cs
// The activity log: one line per action (sign-in, scan, export, review sign-off), each line carrying the SHA-256 of the
// previous line plus its own content, so an edited, removed or reordered line breaks the chain.
// A hash chain alone can't stop someone who rewrites the whole file, cuts lines off its end or deletes it. Two things
// make that visible too:
//   - an anchor (line count + last hash) kept apart from the log, encrypted for the Windows user by the app: a log that
//     is missing, shorter than the anchor or no longer contains the anchored line is reported;
//   - the same line count and hash printed into every exported report, so copies kept in an evidence store can be
//     compared with the log later (see Head()).
// The log is for showing what was done with TenantWise. The authoritative record of changes in a tenant stays the
// Entra audit log.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;

namespace TenantWise.Core
{
    public sealed class EvidenceLog
    {
        private const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";
        private readonly string _path;
        private readonly Func<string> _readAnchor;
        private readonly Action<string> _writeAnchor;

        public EvidenceLog(string path) : this(path, null, null) { }

        /// <param name="readAnchor">Returns the stored anchor ("lines hash since"), or null when none was stored yet.
        /// "since" is the entry from which the log has been anchored: it moves forward only if the anchor was lost.</param>
        /// <param name="writeAnchor">Stores the anchor after every entry.</param>
        public EvidenceLog(string path, Func<string> readAnchor, Action<string> writeAnchor)
        {
            _path = path;
            _readAnchor = readAnchor;
            _writeAnchor = writeAnchor;
        }

        /// <summary>Optional copy of every entry in a second place (for example a network share a SIEM collects), so the
        /// log can be checked against something the PC's user can't quietly change. Null: no copy.</summary>
        public string CopyPath { get; set; }

        public static string Sha256Hex(byte[] data)
        {
            using (var sha = SHA256.Create())
                return string.Concat(sha.ComputeHash(data).Select(b => b.ToString("x2")));
        }

        public static string Sha256Hex(string text) => Sha256Hex(Encoding.UTF8.GetBytes(text ?? ""));

        // One lock for every TenantWise process of this Windows user, so two windows can't fork the chain.
        private static T Locked<T>(Func<T> work)
        {
            using (var m = new Mutex(false, "Local\\TenantWise.ActivityLog"))
            {
                var mine = false;
                try
                {
                    try { mine = m.WaitOne(TimeSpan.FromSeconds(10)); }
                    catch (AbandonedMutexException) { mine = true; }
                    if (!mine) throw new IOException("The activity log is busy in another TenantWise window.");
                    return work();
                }
                finally { if (mine) m.ReleaseMutex(); }
            }
        }

        /// <summary>Appends an entry: {time, action, ...details}. Returns the entry's hash.</summary>
        public string Append(string action, JsonObject details = null)
        {
            return Locked(() =>
            {
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                var prev = Genesis;
                var count = 0;
                var anchor = ReadAnchor();
                var anchorMatches = anchor.Lines == 0;
                if (File.Exists(_path))
                    foreach (var l in File.ReadLines(_path, Encoding.UTF8))
                        if (l.Length > 65)
                        {
                            prev = l.Substring(0, 64); count++;
                            if (count == anchor.Lines && string.Equals(prev, anchor.Hash, StringComparison.OrdinalIgnoreCase)) anchorMatches = true;
                        }
                // times are UTC from this PC's clock
                var entry = new JsonObject { ["time"] = DateTime.UtcNow.ToString("o"), ["action"] = action };
                if (details != null)
                    foreach (var kv in details.ToList()) { details.Remove(kv.Key); entry[kv.Key] = kv.Value; }
                var json = entry.ToJsonString();
                var hash = Sha256Hex(prev + "\n" + json);
                File.AppendAllText(_path, hash + " " + json + "\n", new UTF8Encoding(false));
                if (!string.IsNullOrEmpty(CopyPath))
                    try { File.AppendAllText(CopyPath, hash + " " + json + "\n", new UTF8Encoding(false)); }
                    catch (Exception) { /* share offline: CheckCopy reports the gap */ }
                // A log that no longer matches its anchor keeps the old anchor, so Verify goes on reporting it.
                if (anchorMatches)
                {
                    var since = anchor.Lines == 0 ? count + 1 : anchor.Since;
                    try { _writeAnchor?.Invoke((count + 1) + " " + hash + " " + since); } catch (Exception) { /* Verify shows the anchor is behind */ }
                }
                return hash;
            });
        }

        /// <summary>The number of entries, the hash of the last one and the entry the anchor starts at (0: none):
        /// printed into exports so they can be checked later.</summary>
        public (int Lines, string Hash, int AnchoredSince) Head()
        {
            return Locked(() =>
            {
                var n = 0; var h = Genesis;
                if (File.Exists(_path))
                    foreach (var l in File.ReadLines(_path, Encoding.UTF8))
                        if (l.Length > 65) { n++; h = l.Substring(0, 64); }
                return (n, h, ReadAnchor().Since);
            });
        }

        private (int Lines, string Hash, int Since) ReadAnchor()
        {
            string anchor = null;
            try { anchor = _readAnchor?.Invoke(); } catch (Exception) { anchor = null; }
            if (string.IsNullOrEmpty(anchor)) return (0, null, 0);
            var parts = anchor.Split(' ');
            if (parts.Length >= 2 && int.TryParse(parts[0], out var lines) && parts[1].Length == 64)
                return (lines, parts[1], parts.Length >= 3 && int.TryParse(parts[2], out var since) ? since : 1);
            return (0, null, 0);
        }

        /// <summary>Checks the whole chain and the anchor. Problem says what's wrong, or null when intact.
        /// AnchoredSince is the entry from which the log is anchored (0: not anchored), to show alongside the result:
        /// an anchor that starts late means it was lost and re-created at that entry.</summary>
        public (bool Ok, int Lines, string Problem, int AnchoredSince) Verify()
        {
            var a = ReadAnchor();
            int anchorLines = a.Lines; string anchorHash = a.Hash;

            if (!File.Exists(_path))
                return anchorLines > 0
                    ? (false, 0, $"The activity log is missing, but {anchorLines} entries were recorded on this PC.", a.Since)
                    : (true, 0, null, a.Since);

            var prev = Genesis;
            var n = 0;
            var anchorSeen = anchorLines == 0;
            foreach (var line in File.ReadLines(_path, Encoding.UTF8))
            {
                if (line.Length == 0) continue;
                n++;
                if (line.Length < 66 || line[64] != ' ') return (false, n, $"Line {n} is malformed.", a.Since);
                var hash = line.Substring(0, 64);
                if (Sha256Hex(prev + "\n" + line.Substring(65)) != hash) return (false, n, $"Line {n} was changed, removed or reordered.", a.Since);
                if (n == anchorLines)
                {
                    if (!string.Equals(hash, anchorHash, StringComparison.OrdinalIgnoreCase))
                        return (false, n, $"The log was rewritten: entry {n} no longer matches what was recorded on this PC.", a.Since);
                    anchorSeen = true;
                }
                prev = hash;
            }
            if (!anchorSeen)
                return (false, n, $"Entries were removed from the end: {anchorLines} were recorded on this PC, {n} are left.", a.Since);
            if (n > 0 && anchorLines == 0 && _readAnchor != null)
                return (false, n, "The log's anchor is missing, so a rewritten or shortened log couldn't be noticed. It is re-created with the next entry.", 0);
            return (true, n, null, a.Since);
        }

        /// <summary>Starts the copy: writes the whole log so far to the copy file (when it's empty) and copies from now on.</summary>
        public void StartCopy(string copyPath)
        {
            Locked(() =>
            {
                var dir = Path.GetDirectoryName(copyPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                if ((!File.Exists(copyPath) || new FileInfo(copyPath).Length == 0) && File.Exists(_path))
                    File.Copy(_path, copyPath, true);
                CopyPath = copyPath;
                return 0;
            });
        }

        /// <summary>Compares the copy with the log: every copied entry must still be in the log, and the copy should be up to date.</summary>
        public (bool Ok, string Note) CheckCopy()
        {
            if (string.IsNullOrEmpty(CopyPath)) return (true, null);
            if (!File.Exists(CopyPath)) return (false, "The copy at " + CopyPath + " can't be read (share offline or file removed).");
            var local = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string lastLocal = null;
            if (File.Exists(_path))
                foreach (var l in File.ReadLines(_path, Encoding.UTF8))
                    if (l.Length > 65) { lastLocal = l.Substring(0, 64); local.Add(lastLocal); }
            string lastCopy = null; var n = 0;
            foreach (var l in File.ReadLines(CopyPath, Encoding.UTF8))
            {
                if (l.Length <= 65) continue;
                n++; lastCopy = l.Substring(0, 64);
                if (!local.Contains(lastCopy))
                    return (false, $"Entry {n} of the copy is no longer in this PC's log: the local log was changed after it was copied.");
            }
            if (!string.Equals(lastCopy, lastLocal, StringComparison.OrdinalIgnoreCase))
                return (true, "The copy is behind this PC's log (the share was unreachable for some entries).");
            return (true, $"The copy at {CopyPath} matches this PC's log ({n} entries).");
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
