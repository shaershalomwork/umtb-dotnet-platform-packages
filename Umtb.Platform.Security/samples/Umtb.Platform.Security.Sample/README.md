# Scalar sample

Scalar is the sample's home page in **Development**. Its OpenAPI document describes both Minimal APIs and controllers. Sign in to Keycloak from Scalar using authorization code + PKCE S256; the API still validates access tokens using `UmtbBearer` and enforces its original permissions.

## Run with the local Keycloak fixture

From the package directory, with Docker's Linux engine running and the .NET 10 SDK/runtime installed:

```powershell
docker compose -f keycloak/compose.yaml up -d
dotnet run --project samples/Umtb.Platform.Security.Sample --framework net10.0
```

Open **http://localhost:5000/**. The `Sample` launch profile sets `Development` and opens this URL when launched from an IDE that supports `launchBrowser`.

In Scalar, choose **Authentication**, select **Keycloak**, then **Authorize**. Each authorization sends `prompt=login` to show the Keycloak login page even with an existing SSO session. Log in with a fixture user such as `alice` or `reader`; all fixture users have the test-only password `fixture-password`. Scalar receives the access token and attaches it to protected API requests. Try `GET /me`, `POST /write-example` and `POST /admin-example` to compare permissions.

The public login client is `orders-web`; the API resource client/audience is `orders-api`. The fixture permits exact callback URLs `http://localhost:5000/` and `http://127.0.0.1:5000/`, with matching web origins. When changing the port or hostname, register that exact home-page URL and origin in Keycloak. If an older fixture container is already running, recreate it to import the updated realm:

```powershell
docker compose -f keycloak/compose.yaml up -d --force-recreate
```

## Use your own Keycloak

Edit `appsettings.Development.json`:

- `Security:Authority`: the exact realm issuer, without a trailing slash.
- `Security:AllowHttpDiscoveryInDevelopment`: `false` for an HTTPS issuer.
- `Scalar:ClientId`: a public browser login client with standard flow enabled and PKCE S256 required. Client authentication, implicit flow and direct access grants should be disabled for this browser client.

Keep `Security:ClientId`, `Audience`, `AllowedGroups` and the role mappings in `appsettings.json` aligned with your API assignments. Give the browser client the API audience, client roles and full group-path mappers described in [the Keycloak setup](../../keycloak/README.md). Register the exact Scalar callback URL (the application's root URL, with a trailing slash) and web origin. No client secret is configured in Scalar.

The local Development configuration points to `http://127.0.0.1:18080/realms/platform`. Outside Development, the UI, its assets and `/openapi/v1.json` are not mapped. Scalar and OpenAPI routes are explicitly anonymous in Development so users can open the page before signing in; API authorization remains in force. Scalar authentication persistence is not enabled.

To stop the local fixture:

```powershell
docker compose -f keycloak/compose.yaml down
```
