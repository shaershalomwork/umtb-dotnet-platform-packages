# Scalar sample

Scalar is the sample's home page in every environment, including **Development**, **Test**, **Staging**, and **Production**. Its OpenAPI document describes both Minimal APIs and controllers. Sign in to Keycloak from Scalar using authorization code + PKCE S256; the API still validates access tokens using `UmtbBearer` and enforces its original permissions.

## Build and run the application image

From the package directory (`Umtb.Platform.Security`), with Docker's Linux engine running:

```powershell
docker build -t umtb-security-sample:local .
docker run --rm --name umtb-security-sample -p 8080:8080 -e Security__Authority=https://identity.example.com/realms/platform umtb-security-sample:local
```

Replace `Security__Authority` with your Keycloak realm's exact HTTPS issuer. The container must be able to reach its discovery and JWKS endpoints and trust its certificate. Override other settings with environment variables when needed, for example `Security__ClientId`, `Security__Audience`, and `Security__AllowedGroups__0` (array index). The application uses the sample's configured API client, audience, groups, and role names unless overridden; no API client secret is required.

In another terminal, check the running application:

```powershell
curl.exe --fail http://localhost:8080/health
```

The root `Dockerfile` publishes only `net10.0` in Release mode using the library project reference. It uses separate build and runtime stages based on Microsoft's .NET images, pins the SDK/runtime patch versions, and starts the API on HTTP port 8080 as a non-root user. The final image contains the published application and ASP.NET Core runtime, without the SDK or test runner. The host needs Docker; it does not need the .NET SDK. Update the image tags when adopting new .NET servicing releases.

The image defaults to `Production`, with Scalar at `/` and OpenAPI at `/openapi/v1.json`. The UI, its assets, and the OpenAPI document are publicly accessible before login; protected API endpoints still require valid tokens and permissions. The existing `scripts/verify-linux.Dockerfile` remains a separate verification image. This application image is the first deployment step; OpenShift resources and HTTPS/forwarded-header configuration for its router still need to be prepared before deployment.

For environment-specific Keycloak settings and a complete configuration file mounted through a ConfigMap, see [OpenShift configuration](../../deploy/openshift/README.md).

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

Configure the settings file or environment variables for your environment (`appsettings.Development.json` for local development, or the mounted configuration described in the [OpenShift instructions](../../deploy/openshift/README.md)):

- `Security:Authority`: the exact realm issuer, without a trailing slash.
- `Security:AllowHttpDiscoveryInDevelopment`: `false` for an HTTPS issuer.
- `Scalar:ClientId`: a public browser login client with standard flow enabled and PKCE S256 required. Client authentication, implicit flow and direct access grants should be disabled for this browser client.
- `Scalar:RedirectUri` (optional): the exact public home-page URL, with a trailing slash, for example `https://api.example.com/`. Set this when the API is behind a proxy and its observed scheme/host differs from the public URL. Environment variable: `Scalar__RedirectUri`. If omitted, the URL is derived from the request's scheme, host, and path base. This setting controls the login callback; it does not replace router HTTPS/forwarded-header configuration.

Keep `Security:ClientId`, `Audience`, `AllowedGroups` and the role mappings in `appsettings.json` aligned with your API assignments. Give the browser client the API audience, client roles and full group-path mappers described in [the Keycloak setup](../../keycloak/README.md). Register the exact Scalar callback URL (the application's root URL, with a trailing slash) and web origin. No client secret is configured in Scalar.

The local Development configuration points to `http://127.0.0.1:18080/realms/platform`. Other environments require an HTTPS issuer. Scalar and OpenAPI routes are explicitly anonymous in every environment so users can open the page before signing in; API authorization remains in force. The local fixture accounts and password are described only in Development. Scalar authentication persistence is not enabled, and no client secret or token is pre-filled in the UI.

To stop the local fixture:

```powershell
docker compose -f keycloak/compose.yaml down
```
