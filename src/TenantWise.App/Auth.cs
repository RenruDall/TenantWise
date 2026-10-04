// TenantWise.App — Auth.cs
// Sign-in with the Microsoft identity platform (MSAL). On Windows the Web Account Manager (WAM) broker is used,
// so people get Microsoft's own sign-in: work email, password or passwordless, MFA, Conditional Access, and
// single sign-on with the account already on the PC. TenantWise never sees a password.
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TenantWise.Core;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;

namespace TenantWise.App
{
    public sealed class Auth : ITokenSource
    {
        // Delegated, read-only permissions. Azure: act as the signed-in user (Reader rights decide what's visible).
        public static readonly string[] ArmScopes = { "https://management.azure.com/user_impersonation" };
        public static readonly string[] GraphScopes =
        {
            "https://graph.microsoft.com/Directory.Read.All",
            "https://graph.microsoft.com/RoleManagement.Read.Directory",
            "https://graph.microsoft.com/Policy.Read.All"
        };

        // Only for "Manage access", asked the moment a Global Administrator saves there; never at normal sign-in.
        public static readonly string[] ManageScopes = { "https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All" };
        public static readonly string[] SetupScopes = { "https://graph.microsoft.com/Application.ReadWrite.All" };

        private readonly string _clientId;
        private readonly Func<IntPtr> _window;
        private IPublicClientApplication _app;
        private IAccount _account;
        private bool _graphRefused;

        public string Account { get; private set; }
        public string TenantId { get; private set; }
        public bool GraphOk { get; private set; }
        public string GraphProblem { get; private set; }
        public string ClientId => _clientId;
        /// <summary>TenantWise app roles from the ID token (assigned by an admin in Enterprise applications).</summary>
        public string[] TokenRoles { get; private set; } = new string[0];
        public bool SignedIn => _account != null;

        public Auth(string clientId, Func<IntPtr> window)
        {
            _clientId = clientId;
            _window = window;
        }

        private IPublicClientApplication Build(string tenant)
        {
            return PublicClientApplicationBuilder.Create(_clientId)
                .WithAuthority(AzureCloudInstance.AzurePublic, string.IsNullOrWhiteSpace(tenant) ? "organizations" : tenant.Trim())
                .WithDefaultRedirectUri()
                .WithParentActivityOrWindow(_window)
                .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows) { Title = "TenantWise" })
                .Build();
        }

        /// <summary>Opens Microsoft's sign-in (email → password/passwordless → MFA). Then asks for directory read access.</summary>
        public async Task SignInAsync(string email, string tenant, CancellationToken ct)
        {
            _app = Build(tenant);
            _graphRefused = false;
            var builder = _app.AcquireTokenInteractive(ArmScopes).WithPrompt(Prompt.SelectAccount);
            if (!string.IsNullOrWhiteSpace(email)) builder = builder.WithLoginHint(email.Trim());
            var r = await builder.ExecuteAsync(ct).ConfigureAwait(false);
            _account = r.Account;
            Account = r.Account?.Username;
            TenantId = r.TenantId;
            TokenRoles = AppAccess.RolesFromIdToken(r.IdToken);

            // Entra is optional: without Graph consent the app still maps Azure.
            try
            {
                await GraphTokenAsync(interactiveAllowed: true, ct).ConfigureAwait(false);
                GraphOk = true;
                GraphProblem = null;
            }
            catch (Exception ex) when (!(ex is OperationCanceledException))
            {
                GraphOk = false;
                _graphRefused = true;
                GraphProblem = Explain(ex);
            }
        }

        public async Task SignOutAsync()
        {
            if (_app != null)
                foreach (var a in await _app.GetAccountsAsync().ConfigureAwait(false))
                    await _app.RemoveAsync(a).ConfigureAwait(false);
            _account = null; Account = null; TenantId = null; GraphOk = false; TokenRoles = new string[0];
        }

        public Task<string> GetTokenAsync(string resource, CancellationToken ct)
        {
            if (resource == "arm") return TokenAsync(ArmScopes, true, ct);
            if (resource == "graph")
            {
                if (_graphRefused) throw new InvalidOperationException(GraphProblem ?? "No access to Microsoft Graph.");
                return GraphTokenAsync(false, ct);
            }
            if (resource == "graph-manage") return TokenAsync(ManageScopes, true, ct);
            if (resource == "graph-setup") return TokenAsync(SetupScopes, true, ct);
            throw new ArgumentException("Unknown resource " + resource);
        }

        private Task<string> GraphTokenAsync(bool interactiveAllowed, CancellationToken ct) => TokenAsync(GraphScopes, interactiveAllowed, ct);

        private async Task<string> TokenAsync(string[] scopes, bool interactiveAllowed, CancellationToken ct)
        {
            if (_app == null || _account == null) throw new InvalidOperationException("Not signed in.");
            try
            {
                return (await _app.AcquireTokenSilent(scopes, _account).ExecuteAsync(ct).ConfigureAwait(false)).AccessToken;
            }
            catch (MsalUiRequiredException) when (interactiveAllowed)
            {
                var r = await _app.AcquireTokenInteractive(scopes).WithAccount(_account).ExecuteAsync(ct).ConfigureAwait(false);
                return r.AccessToken;
            }
        }

        /// <summary>Link an admin opens once to approve TenantWise's read permissions for the whole organization.</summary>
        public string AdminConsentUrl =>
            $"https://login.microsoftonline.com/{(string.IsNullOrEmpty(TenantId) ? "organizations" : TenantId)}/adminconsent?client_id={_clientId}";

        public static string Explain(Exception ex)
        {
            var msg = ex.Message ?? "";
            if (ex is MsalServiceException se)
            {
                if (msg.Contains("AADSTS65001") || msg.Contains("AADSTS90094") || se.ErrorCode == "consent_required")
                    return "An administrator needs to approve TenantWise's read access to the directory once.";
                if (msg.Contains("AADSTS700016"))
                    return "This app (client) ID doesn't exist in that tenant. Each organization registers TenantWise in its own tenant: use the ID from yours.";
                if (msg.Contains("AADSTS90002") || msg.Contains("AADSTS900023"))
                    return "That tenant wasn't found. Check the domain of your email, or enter the tenant's domain or ID under Advanced.";
                if (msg.Contains("AADSTS50194"))
                    return "This app registration only allows sign-ins from its own tenant. Check the tenant under Advanced.";
                if (msg.Contains("AADSTS50076") || msg.Contains("AADSTS50079"))
                    return "Multi-factor authentication is required and wasn't completed.";
                if (msg.Contains("AADSTS53003"))
                    return "Your organization's Conditional Access blocked this sign-in (for example device or location rules).";
            }
            if (ex is MsalClientException ce && ce.ErrorCode == "authentication_canceled") return "Sign-in was cancelled.";
            var first = msg.Split('\n').FirstOrDefault() ?? msg;
            return first.Length > 300 ? first.Substring(0, 300) + "…" : first;
        }
    }
}
