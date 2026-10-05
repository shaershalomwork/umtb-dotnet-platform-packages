"""Check README code against its compiled example and validate the fixture structure."""
import json
from pathlib import Path
import textwrap

root = Path(__file__).resolve().parents[1]
readme = (root / "README.md").read_text(encoding="utf-8")
example = (root / "docs/examples/QuickStart.cs").read_text(encoding="utf-8")
snippet = readme.split("<!-- quickstart:start -->", 1)[1].split("<!-- quickstart:end -->", 1)[0]
snippet = snippet.split("```csharp\n", 1)[1].split("```", 1)[0].strip()
compiled = textwrap.dedent(example.split("// README-START\n", 1)[1].split("// README-END", 1)[0]).strip()
assert snippet == compiled, "README quick start differs from the compiled example"
realm = json.loads((root / "keycloak/platform-realm.json").read_text(encoding="utf-8"))
assert realm["accessTokenLifespan"] == 300
clients = {client["clientId"]: client for client in realm["clients"]}
api, web = clients["orders-api"], clients["orders-web"]
assert not any(api[flag] for flag in ["standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled"])
assert web["standardFlowEnabled"] and web["attributes"]["pkce.code.challenge.method"] == "S256"
assert not web["directAccessGrantsEnabled"] and not web["fullScopeAllowed"]
assert web["publicClient"]
assert {"http://localhost:5000/", "http://127.0.0.1:5000/"} <= set(web["redirectUris"])
assert {"http://localhost:5000", "http://127.0.0.1:5000"} <= set(web["webOrigins"])
assert realm["clientScopeMappings"]["orders-api"][0]["client"] == "orders-web"
assert set(web["defaultClientScopes"]) <= {scope["name"] for scope in realm["clientScopes"]}
profile = json.loads(realm["components"]["org.keycloak.userprofile.UserProfileProvider"][0]["config"]["kc.user.profile.config"][0])
assert next(a for a in profile["attributes"] if a["name"] == "nationalId")["permissions"]["edit"] == ["admin"]
assert not realm["defaultGroups"]
print("Compiled README example and realm fixture structure verified")
