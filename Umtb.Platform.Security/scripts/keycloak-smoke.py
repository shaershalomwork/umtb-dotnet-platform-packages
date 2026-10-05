"""Exercise real Keycloak authorization-code + PKCE, then the compiled API. Never print tokens."""
import argparse
import base64
import hashlib
import html.parser
import http.cookiejar
import importlib.util
from pathlib import Path
import secrets
import urllib.error
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location("sample_smoke", Path(__file__).with_name("sample-smoke.py"))
sample = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sample)
ISSUER = "http://127.0.0.1:18080/realms/platform"
CALLBACK = "http://127.0.0.1:18081/callback"


class LoginForm(html.parser.HTMLParser):
    action = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form" and values.get("id") == "kc-form-login":
            self.action = values["action"]


class LocalCallback(urllib.request.HTTPRedirectHandler):
    def __init__(self, callback):
        self.callback = callback

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(self.callback + "?"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class FixtureCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    def return_ok_secure(self, cookie, request):
        # Browsers treat localhost as a secure context. Match that exception only for
        # this fixed, disposable HTTP loopback fixture; retain normal policy elsewhere.
        address = urllib.parse.urlsplit(request.full_url)
        if address.scheme == "http" and address.hostname == "127.0.0.1" and address.port == 18080:
            return True
        return super().return_ok_secure(cookie, request)


def login(username, callback=CALLBACK, origin=None):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)
    query = urllib.parse.urlencode(dict(client_id="orders-web", redirect_uri=callback, response_type="code",
                                       scope="openid profile email", code_challenge_method="S256",
                                       code_challenge=challenge, state=state))
    jar = http.cookiejar.CookieJar(policy=FixtureCookiePolicy())
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), LocalCallback(callback))
    with opener.open(ISSUER + "/protocol/openid-connect/auth?" + query, timeout=15) as response:
        form = LoginForm()
        form.feed(response.read().decode())
    if not form.action:
        raise RuntimeError("Keycloak did not show the expected fixture login form.")
    data = urllib.parse.urlencode(dict(username=username, password="fixture-password", credentialId="")).encode()
    try:
        with opener.open(form.action, data, timeout=15):
            raise RuntimeError("Fixture login did not return an authorization code.")
    except urllib.error.HTTPError as error:
        if error.code not in (302, 303) or not error.headers.get("Location", "").startswith(callback + "?"):
            path = urllib.parse.urlsplit(error.headers.get("Location", error.url)).path
            raise RuntimeError(f"Unexpected Keycloak login response: HTTP {error.code}, path {path}.") from None
        values = urllib.parse.parse_qs(urllib.parse.urlsplit(error.headers["Location"]).query)
    assert values["state"] == [state]
    body = urllib.parse.urlencode(dict(grant_type="authorization_code", client_id="orders-web",
                                      redirect_uri=callback, code_verifier=verifier, code=values["code"][0])).encode()
    request = urllib.request.Request(ISSUER + "/protocol/openid-connect/token", body,
                                     headers={"Origin": origin} if origin else {})
    with opener.open(request, timeout=15) as response:
        if origin:
            assert response.headers.get("Access-Control-Allow-Origin") == origin
        return sample.json.load(response)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework", default="net10.0")
    parser.add_argument("--dotnet", default="dotnet")
    args = parser.parse_args()
    sample.wait_ready(ISSUER + "/.well-known/openid-configuration", attempts=180)
    proc, output, base = sample.start_sample(args.framework, args.dotnet, authority=ISSUER)
    try:
        sample.wait_ready(base + "/health", proc)
        for username, read, write, admin in [("alice", 200, 204, 204), ("reader", 200, 403, 403),
                                            ("writer", 200, 204, 403), ("group-only", 403, 403, 403),
                                            ("role-only", 403, 403, 403), ("unassigned", 403, 403, 403)]:
            tokens = login(username)
            access = tokens["access_token"]
            for path, method, expected in [("/me", "GET", read), ("/write-example", "POST", write), ("/admin-example", "POST", admin)]:
                status, _ = sample.request(base + path, access, method)
                assert status == expected, (username, path, status, expected)
            assert sample.request(base + "/me", tokens["id_token"])[0] == 401
            assert sample.request(base + "/me", tokens["refresh_token"])[0] == 401
            if username == "alice":
                user = sample.json.loads(sample.request(base + "/me", access)[1])
                assert user["nationalIdNumber"] == "001234567"
                assert user["roles"] == ["admin"]
                assert user["groups"] == ["/applications/orders/users"]
                assert sample.request(base + "/documents/owned", access)[0] == 200
                assert sample.request(base + "/documents/shared", access)[0] == 200
                assert sample.request(base + "/documents/private", access)[0] == 403
        # Exercise the Scalar client's registered callback and browser token-exchange origin.
        scalar_tokens = login("alice", callback="http://localhost:5000/", origin="http://localhost:5000")
        assert sample.request(base + "/me", scalar_tokens["access_token"])[0] == 200
        assert sample.request(base + "/")[0] == 200
        print("Keycloak PKCE, Scalar callback/CORS, token types, permissions, identity, and resource smoke passed on " + args.framework)
    finally:
        sample.stop_sample(proc, output)
