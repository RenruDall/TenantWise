// Test host: runs the real TenantWise scanner against the fake Azure/Entra web server (tests/fake_server.py).
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using TenantWise.Core;

namespace TenantWise.Tests
{
    public sealed class StaticTokens : ITokenSource
    {
        private readonly string _arm, _graph;
        public StaticTokens(string arm, string graph) { _arm = arm; _graph = graph; }
        public Task<string> GetTokenAsync(string resource, CancellationToken ct)
        {
            if (resource == "arm") return Task.FromResult(_arm);
            if (resource == "graph") return Task.FromResult(_graph);
            if (resource == "graph-manage") return Task.FromResult("fake-graph-manage-token");
            if (resource == "graph-setup") return Task.FromResult("fake-graph-setup-token");
            throw new ArgumentException("Unknown resource " + resource);
        }
    }

    internal sealed class ConsoleProgress : IProgress<string>
    {
        public void Report(string value) { Console.WriteLine("    · " + value); }
    }

    public static class TestHost
    {
        private static Api FakeApi(HttpClient http, string baseUrl) => new Api(http, new StaticTokens("fake-arm-token", "fake-graph-token"),
            new Endpoints { Arm = baseUrl + "/arm", Graph = baseUrl + "/graph/v1.0" }) { RetryDelay = TimeSpan.FromMilliseconds(10) };

        /// <summary>Manage access against the fake Entra. step: read | ga | search:&lt;text&gt; | setup | apply:&lt;principal&gt;:&lt;role&gt;:&lt;+|-&gt;</summary>
        public static string Access(string baseUrl, string clientId, string step)
        {
            using (var http = new HttpClient())
            {
                var api = FakeApi(http, baseUrl);
                var ct = CancellationToken.None;
                if (step == "read") return AppAccess.ReadAsync(api, clientId, ct).GetAwaiter().GetResult().ToJsonString();
                if (step == "ga") return AppAccess.IsGlobalAdminAsync(api, ct).GetAwaiter().GetResult() ? "true" : "false";
                if (step.StartsWith("search:")) return AppAccess.SearchAsync(api, step.Substring(7), ct).GetAwaiter().GetResult().ToJsonString();
                if (step == "setup") return AppAccess.SetupRolesAsync(api, clientId, ct).GetAwaiter().GetResult().ToString();
                var p = step.Split(':');
                var r = AppAccess.ApplyAsync(api, clientId, new[] { new AppAccess.Change { PrincipalId = p[1], Role = p[2], Grant = p[3] == "+" } }, ct).GetAwaiter().GetResult();
                return r.granted + "/" + r.removed;
            }
        }

        /// <summary>Scans the fake tenant; returns {"data": …, "stats": …} as JSON text.</summary>
        public static string Run(string baseUrl, string tenantId, bool entra, string armToken, string graphToken, bool quiet)
        {
            using (var http = new HttpClient())
            {
                var api = new Api(http, new StaticTokens(armToken, graphToken),
                    new Endpoints { Arm = baseUrl + "/arm", Graph = baseUrl + "/graph/v1.0" }) { RetryDelay = TimeSpan.FromMilliseconds(10) };
                var scanner = new Scanner(api, new ScanOptions { TenantId = tenantId, Entra = entra, Account = "auditor@test.example", ToolVersion = "test" }, quiet ? null : new ConsoleProgress());
                var sw = Stopwatch.StartNew();
                var data = scanner.ScanAsync().GetAwaiter().GetResult();
                sw.Stop();
                return new JsonObject
                {
                    ["data"] = data,
                    ["stats"] = new JsonObject
                    {
                        ["seconds"] = Math.Round(sw.Elapsed.TotalSeconds, 2), ["resourceGraphQueries"] = api.ResourceGraphQueries,
                        ["armCalls"] = api.ArmCalls, ["graphCalls"] = api.GraphCalls, ["retries"] = api.Retries
                    }
                }.ToJsonString();
            }
        }
    }
}
