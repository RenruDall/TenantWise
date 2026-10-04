"""A brand-new free Azure tenant, as someone gets it after signing up with a personal Microsoft account.

The opposite of the big "Alpina" tenant: the edge cases a first real scan meets.
  - no management group hierarchy yet (Resource Graph returns none; the subscription has no ancestors)
  - one subscription, "Azure subscription 1", directly under the tenant root
  - a tiny demo deployment: VM with a public IP, VNet with a subnet without NSG, storage, Network Watcher
  - the signed-in user owns everything; their UPN contains #EXT# (personal account) but they are a MEMBER, not a guest
  - no Entra ID P1/P2 or Governance licence: PIM, Conditional Access and access packages answer 403,
    PIM-eligible Azure roles answer 400

Writes free-raw.json (served by fake_server.py) and free-expected.json.
Usage: python tests/free_tenant.py <out-dir>
"""
import json, os, sys

T = "5f0e2a71-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
SID = "1d2c3b4a-0000-4000-8000-00000000f1ee"
S = f"/subscriptions/{SID}"
RG, NW = f"{S}/resourcegroups/rg-tenantwise-demo", f"{S}/resourcegroups/NetworkWatcherRG"
ME = "c0ffee00-1111-4222-8333-444455556666"
UPN = "michael.example_outlook.com#EXT#@michaelexampleoutlook.onmicrosoft.com"
OWNER, READER, CONTRIB = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "acdd72a7-3385-48ef-bd42-f606fba81ae7", "b24988ac-6180-42a0-ab88-20f7382dd24c"
GA = "62e90394-69f5-4237-9190-012177145e10"

def r(t, name, rg=RG, **kw):
    rid = f"{rg}/providers/{t}/{name}"
    return dict({"id": rid.lower(), "rid": rid, "name": name, "type": t, "subscriptionId": SID, "resourceGroup": rg.split("/")[-1],
                 "location": "westeurope", "sku": "", "kind": "", "tags": None}, **kw)

vnet = r("microsoft.network/virtualnetworks", "vnet-demo")
vm = r("microsoft.compute/virtualmachines", "vm-demo-01", sku="Standard_B2s")
nic = r("microsoft.network/networkinterfaces", "vm-demo-01-nic")
disk = r("microsoft.compute/disks", "vm-demo-01_OsDisk_1", sku="StandardSSD_LRS")
pip = r("microsoft.network/publicipaddresses", "vm-demo-01-ip", sku="Standard")
nsg = r("microsoft.network/networksecuritygroups", "vm-demo-01-nsg")
st = r("microsoft.storage/storageaccounts", "sttenantwisedemo01", sku="Standard_LRS", kind="StorageV2")
nw = r("microsoft.network/networkwatchers", "NetworkWatcher_westeurope", rg=NW)
resources = [vnet, vm, nic, disk, pip, nsg, st, nw]
sn_default = {"vnet": vnet["id"], "id": vnet["id"] + "/subnets/default", "rid": vnet["id"] + "/subnets/default", "name": "default", "prefix": "10.0.0.0/24",
              "nsg": "", "rt": "", "nat": "", "subscriptionId": SID, "resourceGroup": "rg-tenantwise-demo", "location": "westeurope"}
sn_app = dict(sn_default, id=vnet["id"] + "/subnets/snet-app", rid=vnet["id"] + "/subnets/snet-app", name="snet-app", prefix="10.0.1.0/24", nsg=nsg["id"])
lic = lambda what: [403, "Forbidden", f"The tenant needs an Entra ID P2 or Governance licence for {what}."]

raw = {
    "tenantId": T, "account": UPN,
    "arg": {
        "mgs": [],
        "subs": [{"subscriptionId": SID, "name": "Azure subscription 1", "chain": []}],
        "rgs": [{"id": g.lower(), "rid": g, "name": g.split("/")[-1], "subscriptionId": SID, "location": "westeurope", "tags": None} for g in (RG, NW)],
        "resources": resources, "subnets": [sn_default, sn_app],
        "nic": [{"s": nic["id"], "owner": vm["id"], "nsg": nsg["id"], "subnet": sn_app["id"], "pip": pip["id"], "lb": "", "agw": "", "ip": "10.0.1.4"}],
        "peer": [], "pip": [], "pe": [], "disk": [{"s": disk["id"], "t": vm["id"]}], "web": [], "aks": [], "vmss": [], "dns": [], "conn": [],
        "cfg-ipConfigurations": [], "cfg-gatewayIPConfigurations": [], "cfg-frontendIPConfigurations": [], "routes": [],
        "roledefs_custom": [],
        "roleassign": [{"id": f"{S}/providers/microsoft.authorization/roleassignments/0b0e1a2c-0000-4000-8000-000000000001", "principalId": ME,
                        "principalType": "User", "scope": S, "condition": "",
                        "roleDefinitionId": f"{S}/providers/microsoft.authorization/roledefinitions/{OWNER}"}],
        "policyassign": [{"id": f"{S}/providers/microsoft.authorization/policyassignments/securitycenterbuiltin", "name": "ASC Default (subscription: " + SID + ")",
                          "scope": S, "definitionId": "/providers/microsoft.authorization/policysetdefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8", "enforcement": "Default"}],
        "policystates": [{"a": f"{S}/providers/microsoft.authorization/policyassignments/securitycenterbuiltin", "subscriptionId": SID, "n": 3}],
    },
    "arm": {
        "mg": {}, "denied": [], "subElig": {},
        "roledefs_builtin": [{"name": g, "properties": {"roleName": n, "type": "BuiltInRole"}} for g, n in ((OWNER, "Owner"), (READER, "Reader"), (CONTRIB, "Contributor"))],
    },
    "graph": {
        "org": {"id": T, "displayName": "Default Directory"},
        "roleDefinitions": [{"id": GA, "displayName": "Global Administrator", "isPrivileged": True},
                            {"id": "f2ef992c-3afb-46b9-b7cf-a126ee74c451", "displayName": "Global Reader", "isPrivileged": True}],
        "roleAssignments": [{"id": "1", "principalId": ME, "roleDefinitionId": GA, "directoryScopeId": "/"}],
        "roleEligibilitySchedules": [],
        "objects": {ME: {"@odata.type": "#microsoft.graph.user", "id": ME, "displayName": "Michael Example", "userPrincipalName": UPN, "userType": "Member"}},
        "members": {}, "ca": [], "accessPackages": [], "accessPackageDetail": {}, "pkgAssignments": [], "pkgRequests": [], "groupElig": {},
    },
    "forbidden": {
        "/roleManagement/directory/roleEligibilitySchedules": lic("PIM"),
        "/identityGovernance/entitlementManagement/accessPackages": lic("access packages"),
        "/identity/conditionalAccess/policies": [403, "Forbidden", "The tenant needs an Entra ID P1 licence for Conditional Access."],
        f"{S}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances": [400, "AadPremiumLicenseRequired", "PIM needs Entra ID P2."],
        "/users|signInActivity": [403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant", "Sign-in activity needs Entra ID P1."],
    },
}
expected = {
    "tenantName": "Default Directory",
    "subParent": "tenant",
    "nodes": sorted(["tenant", S, RG, NW.lower()] + [x["id"].lower() for x in resources] + [sn_default["id"], sn_app["id"]]),
    "edges": sorted([f"NIC of|{nic['id']}|{vm['id']}", f"in subnet|{nic['id']}|{sn_app['id']}", f"public IP of|{pip['id']}|{nic['id']}",
                     f"protects|{nsg['id']}|{nic['id']}", f"protects|{nsg['id']}|{sn_app['id']}", f"disk of|{disk['id']}|{vm['id']}"]),
    "azure": [f"{ME}|Owner|{S}|active"],
    "entra": [f"{ME}|Global Administrator|active"],
    "me": ME,
    "notes": ["PIM eligible roles", "Access packages", "Conditional Access", "Eligible Azure roles", "Last sign-in"],
}
out = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(out, exist_ok=True)
json.dump(raw, open(os.path.join(out, "free-raw.json"), "w"))
json.dump(expected, open(os.path.join(out, "free-expected.json"), "w"))
print(f"Free tenant: 1 subscription, {len(resources)} resources, no management groups, no premium licences -> {out}")
