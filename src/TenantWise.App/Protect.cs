// TenantWise.App — Protect.cs
// Scans, audit settings and access reviews are encrypted at rest with Windows DPAPI for the current user:
// only the same Windows account on the same PC can read them. Nothing is sent anywhere.
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TenantWise.App
{
    internal static class Protect
    {
        // Kept from the app's former name (Rootline) so data saved by earlier versions still opens.
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Rootline local data v1");

        public static void WriteText(string path, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            var tmp = path + ".tmp";                               // write, then swap: never a half-written file
            File.WriteAllBytes(tmp, ProtectedData.Protect(Encoding.UTF8.GetBytes(text), Entropy, DataProtectionScope.CurrentUser));
            if (File.Exists(path)) File.Delete(path);
            File.Move(tmp, path);
        }

        public static string ReadText(string path) =>
            Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy, DataProtectionScope.CurrentUser));
    }
}
