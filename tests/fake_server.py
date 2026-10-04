"""Fake Azure Resource Graph + Azure Resource Manager + Microsoft Graph, as a real HTTP server.

Serves the fake tenant from raw.json (made by fake_tenant.py) so TenantWise's real HTTP code can be tested:
  - ARM calls must carry the ARM token and Graph calls the Graph token (else 401)
  - Resource Graph pages at most 1,000 rows with $skipToken; ARM pages with nextLink; Graph with @odata.nextLink
  - every 9th request is throttled once with 429 + Retry-After, like the real services under load
  - one management group answers 403; getByIds rejects more than 1,000 ids
  - anything it doesn't recognise is answered 404 and counted, so the test fails on unknown calls
GET /stats returns the counters.

Usage: python tests/fake_server.py <raw.json> <port>
"""
import json, re, sys, threading, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

RAW = json.load(open(sys.argv[1]))
PORT = int(sys.argv[2])
BASE = f"http://127.0.0.1:{PORT}"
ARM_TOKEN, GRAPH_TOKEN = "fake-arm-token", "fake-graph-token"
MANAGE_TOKEN, SETUP_TOKEN = "fake-graph-manage-token", "fake-graph-setup-token"     # only for "Manage access" writes
GRAPH_PAGE = 25
STATS = {"requests": 0, "arg": 0, "arm": 0, "graph": 0, "throttled": 0, "unauthorized": 0, "denied": 0, "unknown": [], "badRequests": []}
LOCK = threading.Lock()

ROUTES = [  # (key in raw.json "arg", pattern in the KQL query)
    ("mgs", r"microsoft\.management/managementgroups'"),
    ("subs", r"microsoft\.resources/subscriptions'\s*\n\| project subscriptionId"),
    ("rgs", r"microsoft\.resources/subscriptions/resourcegroups'"),
    ("resources", r"\| where tolower\(type\) !in \("),
    ("subnets", r"mv-expand sn = properties\.subnets"),
    ("nic", r"networkinterfaces'\s*\n\| extend owner"),
    ("peer", r"virtualNetworkPeerings"),
    ("pip", r"publicipaddresses'\s*\n\| project"),
    ("pe", r"privateendpoints'"),
    ("disk", r"compute/disks' and isnotempty\(managedBy\)"),
    ("web", r"microsoft\.web/sites'"),
    ("aks", r"containerservice/managedclusters'"),
    ("vmss", r"virtualmachinescalesets'"),
    ("dns", r"privatednszones/virtualnetworklinks'"),
    ("conn", r"microsoft\.network/connections'"),
    ("routes", r"microsoft\.network/routetables'"),
    ("cfg-ipConfigurations", r"isnotnull\(properties\.ipConfigurations\)"),
    ("cfg-gatewayIPConfigurations", r"isnotnull\(properties\.gatewayIPConfigurations\)"),
    ("cfg-frontendIPConfigurations", r"isnotnull\(properties\.frontendIPConfigurations\)"),
    ("roledefs_custom", r"authorization/roledefinitions'"),
    ("roleassign", r"authorization/roleassignments'"),
    ("policyassign", r"authorization/policyassignments'"),
    ("policystates", r"policyinsights/policystates'"),
]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"   # keep-alive, like the real services

    def log_message(self, *a):  # quiet
        pass

    def send(self, status, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def error(self, status, code, message):
        self.send(status, {"error": {"code": code, "message": message}})

    def unknown(self):
        with LOCK:
            STATS["unknown"].append(f"{self.command} {self.path}")
        self.error(404, "FakeNotFound", f"no fake data for {self.command} {self.path}")

    def gate(self, token):
        """auth + occasional throttling; returns False if the request was already answered"""
        with LOCK:
            STATS["requests"] += 1
            n = STATS["requests"]
        if self.headers.get("Authorization") != f"Bearer {token}":
            with LOCK:
                STATS["unauthorized"] += 1
            self.error(401, "InvalidAuthenticationToken", "wrong or missing token for this service")
            return False
        if n % 9 == 0:
            with LOCK:
                STATS["throttled"] += 1
            self.send(429, {"error": {"code": "TooManyRequests", "message": "slow down"}}, {"Retry-After": "0"})
            return False
        return True

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/stats":
            return self.send(200, STATS)
        if u.path.startswith("/arm/"):
            if not self.gate(ARM_TOKEN):
                return
            STATS["arm"] += 1
            return self.arm(u.path[4:], q, u.query)
        if u.path.startswith("/graph/v1.0/"):
            if not self.gate(GRAPH_TOKEN):
                return
            STATS["graph"] += 1
            return self.graph_get(u.path[len("/graph/v1.0"):], q, u)
        self.unknown()

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if u.path == "/arm/providers/Microsoft.ResourceGraph/resources":
            if not self.gate(ARM_TOKEN):
                return
            STATS["arg"] += 1
            return self.arg(body, urllib.parse.parse_qs(u.query))
        m = re.match(r"^/graph/v1.0/servicePrincipals/([^/]+)/appRoleAssignedTo$", u.path)
        if m:
            if not self.gate(MANAGE_TOKEN):
                return
            STATS["graph"] += 1; STATS.setdefault("writes", []).append("POST assignment")
            sp = next((x for x in RAW["graph"].get("servicePrincipals", []) if x["id"] == m.group(1)), None)
            if not sp or body.get("resourceId") != sp["id"] or body.get("appRoleId") not in [r["id"] for r in sp.get("appRoles", [])]:
                return self.error(400, "Request_BadRequest", "unknown app role or resource")
            obj = RAW["graph"]["objects"].get(body.get("principalId"))
            if not obj:
                return self.error(404, "Request_ResourceNotFound", "no such principal")
            a = {"id": "asg-" + str(len(STATS["writes"])), "principalId": body["principalId"], "principalType": "Group" if obj["@odata.type"].endswith("group") else "User",
                 "principalDisplayName": obj["displayName"], "appRoleId": body["appRoleId"], "resourceId": sp["id"], "createdDateTime": "2026-10-04T10:00:00Z"}
            RAW["graph"].setdefault("assignedTo", {}).setdefault(sp["id"], []).append(a)
            return self.send(201, a)
        if u.path == "/graph/v1.0/directoryObjects/getByIds":
            if not self.gate(GRAPH_TOKEN):
                return
            STATS["graph"] += 1
            ids = body.get("ids", [])
            if len(ids) > 1000:
                return self.error(400, "Request_BadRequest", "getByIds accepts at most 1000 ids")
            objs = RAW["graph"]["objects"]
            # like the real getByIds: default properties only, so no userType
            hidden = ("userType", "accountEnabled", "signInActivity")
            return self.send(200, {"value": [{k: v for k, v in objs[i].items() if k not in hidden} for i in ids if i in objs]})
        self.unknown()

    def do_DELETE(self):
        u = urllib.parse.urlparse(self.path)
        m = re.match(r"^/graph/v1.0/servicePrincipals/([^/]+)/appRoleAssignedTo/([^/]+)$", u.path)
        if not m:
            return self.unknown()
        if not self.gate(MANAGE_TOKEN):
            return
        STATS["graph"] += 1; STATS.setdefault("writes", []).append("DELETE assignment")
        lst = RAW["graph"].get("assignedTo", {}).get(m.group(1), [])
        before = len(lst)
        lst[:] = [a for a in lst if a["id"] != m.group(2)]
        if len(lst) == before:
            return self.error(404, "Request_ResourceNotFound", "no such assignment")
        self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers()

    def do_PATCH(self):
        u = urllib.parse.urlparse(self.path)
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        app = RAW["graph"].get("applications_tw")
        if not app or u.path != "/graph/v1.0/applications/" + app["id"]:
            return self.unknown()
        if not self.gate(SETUP_TOKEN):
            return
        STATS["graph"] += 1; STATS.setdefault("writes", []).append("PATCH application")
        if set(body) != {"appRoles"}:
            return self.error(400, "Request_BadRequest", "only appRoles may change")
        kept = {r["id"] for r in app["appRoles"]}
        if not kept <= {r["id"] for r in body["appRoles"]}:
            return self.error(400, "CannotDeleteOrUpdateEnabledEntitlement", "an enabled app role can't be removed")
        app["appRoles"] = body["appRoles"]
        sp = next(x for x in RAW["graph"]["servicePrincipals"] if x["appId"] == app["appId"])
        sp["appRoles"] = [r for r in body["appRoles"]]
        self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers()

    # ---------------- Resource Graph
    def arg(self, body, q):
        if q.get("api-version") != ["2022-10-01"]:
            STATS["badRequests"].append("ARG api-version " + str(q.get("api-version")))
        query, opts = body.get("query", ""), body.get("options", {})
        top = int(opts.get("$top", 100))
        if top > 1000:
            return self.error(400, "BadRequest", "$top cannot exceed 1000")
        if opts.get("resultFormat") != "objectArray":
            STATS["badRequests"].append("ARG resultFormat " + str(opts.get("resultFormat")))
        key = next((k for k, pat in ROUTES if re.search(pat, query)), None)
        if key is None:
            with LOCK:
                STATS["unknown"].append("ARG query: " + query[:120].replace("\n", " "))
            return self.error(400, "BadRequest", "no fake data for this query")
        rows = RAW["arg"][key]
        if key == "resources":
            excl = re.findall(r"'([^']+)'", query.split("!in (")[1].split(")")[0])
            rows = [r for r in rows if r["type"] not in excl]
        start = int(opts.get("$skipToken") or 0)
        page = rows[start:start + top]
        resp = {"totalRecords": len(rows), "count": len(page), "resultTruncated": "false", "data": page}
        if start + top < len(rows):
            resp["$skipToken"] = str(start + top)
        self.send(200, resp)

    # ---------------- Azure Resource Manager
    def arm(self, path, q, query):
        a = RAW["arm"]
        if path in RAW.get("forbidden", {}):
            st, code, msg = RAW["forbidden"][path]
            return self.error(st, code, msg)
        if path == "/providers/Microsoft.Authorization/roleDefinitions":
            start, size = int(q.get("fakePage", ["0"])[0]), 100
            items = a["roledefs_builtin"]
            resp = {"value": items[start:start + size]}
            if start + size < len(items):
                resp["nextLink"] = f"{BASE}/arm/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&fakePage={start + size}"
            return self.send(200, resp)
        m = re.match(r"^/providers/Microsoft\.Management/managementGroups/([^/]+)/providers/Microsoft\.Authorization/(roleAssignments|policyAssignments)$", path)
        if m:
            mg, kind = urllib.parse.unquote(m.group(1)), m.group(2)
            if q.get("$filter") != ["atScope()"]:
                STATS["badRequests"].append(f"ARM {kind} at {mg} without atScope()")
            if mg in a["denied"]:
                STATS["denied"] += 1
                return self.error(403, "AuthorizationFailed", f"The client does not have authorization over scope {mg}.")
            entry = a["mg"].get(mg)
            if entry is None:
                return self.error(404, "ManagementGroupNotFound", mg)
            return self.send(200, {"value": entry[kind]})
        m = re.match(r"^/providers/Microsoft\.Management/managementGroups/([^/]+)/providers/Microsoft\.Authorization/roleEligibilityScheduleInstances$", path)
        if m:
            mg = urllib.parse.unquote(m.group(1))
            if q.get("$filter") != ["atScope()"] or q.get("api-version") != ["2020-10-01"]:
                STATS["badRequests"].append(f"ARM eligibility at {mg}: {query}")
            if mg in a["denied"]:
                STATS["denied"] += 1
                return self.error(403, "AuthorizationFailed", f"The client does not have authorization over scope {mg}.")
            return self.send(200, {"value": a["mg"][mg]["eligibility"]})
        m = re.match(r"^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/roleEligibilityScheduleInstances$", path)
        if m and m.group(1) in a["subElig"]:
            items = a["subElig"][m.group(1)]
            start = int(q.get("fakePage", ["0"])[0]); size = 2        # tiny pages to exercise nextLink
            resp = {"value": items[start:start + size]}
            if start + size < len(items):
                resp["nextLink"] = f"{BASE}/arm{path}?api-version=2020-10-01&fakePage={start + size}"
            return self.send(200, resp)
        self.unknown()

    # ---------------- Microsoft Graph
    def graph_get(self, path, q, u):
        g = RAW["graph"]
        for key, (st, code, msg) in RAW.get("forbidden", {}).items():   # features the tenant isn't licensed for
            p, _, needle = key.partition("|")                             # "path|text in the query" narrows it
            if path == p and needle in urllib.parse.unquote(u.query):
                return self.error(st, code, msg)
        def paged(items):
            start = int(q.get("$skiptoken", ["0"])[0])
            resp = {"value": items[start:start + GRAPH_PAGE]}
            if start + GRAPH_PAGE < len(items):
                qs = dict((k, v[0]) for k, v in q.items())
                qs["$skiptoken"] = str(start + GRAPH_PAGE)
                resp["@odata.nextLink"] = f"{BASE}/graph/v1.0{path}?{urllib.parse.urlencode(qs)}"
            return self.send(200, resp)
        if path == "/users":
            users = [o for o in g["objects"].values() if o["@odata.type"].endswith("user")]
            f, sel = q.get("$filter", [""])[0], q.get("$select", [""])[0]
            if f == "userType eq 'Guest'":
                return paged([{"id": o["id"], "userType": "Guest"} for o in users if o.get("userType") == "Guest"])
            if f.startswith("startswith(displayName,"):
                t = re.search(r"startswith\(displayName,'([^']*)'\)", f).group(1).lower()
                return paged([{"id": o["id"], "displayName": o["displayName"], "userPrincipalName": o.get("userPrincipalName")} for o in users
                              if o["displayName"].lower().startswith(t) or (o.get("userPrincipalName") or "").lower().startswith(t)][:15])
            if f == "accountEnabled eq false":
                return paged([{"id": o["id"]} for o in users if o.get("accountEnabled") is False])
            if not f and "signInActivity" in sel:
                if int(q.get("$top", ["100"])[0]) > 120:
                    STATS["badRequests"].append("signInActivity with $top over 120")
                return paged([{"id": o["id"], **({"signInActivity": o["signInActivity"]} if "signInActivity" in o else {})} for o in users])
            STATS["badRequests"].append("unexpected /users query " + u.query)
            return self.error(400, "BadRequest", "unexpected query")
        if path == "/me/transitiveMemberOf/microsoft.graph.directoryRole":
            return paged(g.get("directoryRoles", {}).get(g.get("me"), []))
        if path == "/applications" and "appId eq" in q.get("$filter", [""])[0]:
            app = g.get("applications_tw")
            want = re.search(r"appId eq '([^']+)'", q["$filter"][0]).group(1)
            return paged([app] if app and app["appId"] == want else [])
        if path == "/groups" and q.get("$filter", [""])[0].startswith("startswith(displayName,"):
            t = re.search(r"startswith\(displayName,'([^']*)'\)", q["$filter"][0]).group(1).lower()
            return paged([{"id": o["id"], "displayName": o["displayName"]} for o in g["objects"].values() if o["@odata.type"].endswith("group") and o["displayName"].lower().startswith(t)][:15])
        if path == "/organization":
            return self.send(200, {"value": [g["org"]]})
        if path == "/roleManagement/directory/roleDefinitions":
            return paged(g["roleDefinitions"])
        if path == "/roleManagement/directory/roleAssignments":
            return paged(g["roleAssignments"])
        if path == "/roleManagement/directory/roleEligibilitySchedules":
            return paged(g["roleEligibilitySchedules"])
        if path == "/identity/conditionalAccess/policies":
            return paged(g["ca"])
        EM = "/identityGovernance/entitlementManagement"
        if path == EM + "/accessPackages":
            if "catalog" not in q.get("$expand", [""])[0]:
                STATS["badRequests"].append("accessPackages without $expand=catalog")
            return paged(g["accessPackages"])
        m = re.match(r"^/identityGovernance/entitlementManagement/accessPackages/([^/]+)$", path)
        if m and m.group(1) in g["accessPackageDetail"]:
            if "resourceRoleScopes" not in q.get("$expand", [""])[0]:
                STATS["badRequests"].append("accessPackage without $expand=resourceRoleScopes")
            return self.send(200, g["accessPackageDetail"][m.group(1)])
        if path == EM + "/assignments":
            return paged(g["pkgAssignments"])
        if path == EM + "/assignmentRequests":
            return paged(g["pkgRequests"])
        if path == "/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances":
            f = re.match(r"^groupId eq '([^']+)'$", q.get("$filter", [""])[0])
            if not f:   # the real API requires a groupId or principalId filter
                return self.error(400, "BadRequest", "filter on groupId or principalId is required")
            return paged(g["groupElig"].get(f.group(1), []))
        m = re.match(r"^/groups/([^/]+)/owners$", path)
        if m:
            return paged(g.get("owners", {}).get(m.group(1), []))
        if path == "/applications":
            if q.get("$expand", [""])[0] != "owners":
                STATS["badRequests"].append("applications without $expand=owners")
            if int(q.get("$top", ["100"])[0]) > 100:
                STATS["badRequests"].append("applications with $expand and $top over 100")
            return paged(g.get("applications", []))
        if path == "/servicePrincipals":
            f = q.get("$filter", [""])[0]
            sps = g.get("servicePrincipals", [])
            m2 = re.match(r"^appId eq '([^']+)'$", f)
            if m2:
                return paged([x for x in sps if x["appId"] == m2.group(1)])
            if f:
                return self.error(400, "BadRequest", "unexpected filter")
            return paged([{k: v for k, v in x.items() if k not in ("appRoles", "appRoleAssignmentRequired")} for x in sps])
        m = re.match(r"^/servicePrincipals/([^/]+)/appRoleAssignedTo$", path)
        if m and m.group(1) in g.get("assignedTo", {}):
            return paged(g["assignedTo"][m.group(1)])
        if m:
            graph = next((x for x in g.get("servicePrincipals", []) if x["appId"] == "00000003-0000-0000-c000-000000000000"), None)
            if not graph or graph["id"] != m.group(1):
                return self.error(404, "Request_ResourceNotFound", "no such service principal")
            return paged(g.get("graphAssignedTo", []))
        if path == "/policies/crossTenantAccessPolicy/default":
            return self.send(200, g.get("ctDefault", {}))
        if path == "/policies/crossTenantAccessPolicy/partners":
            return paged(g.get("ctPartners", []))
        m = re.match(r"^/groups/([^/]+)/transitiveMembers$", path)
        if m:
            return paged(g["members"].get(m.group(1), []))
        self.unknown()


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
