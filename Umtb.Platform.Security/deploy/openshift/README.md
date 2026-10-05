# OpenShift: Keycloak configuration

The application image and arbitrary-UID smoke check are prepared. Router HTTPS/forwarded-header configuration is deferred and must be completed before exposing the API. This directory prepares Keycloak configuration only; it does not deploy the API or provision Keycloak.

## Fill in the environment settings

Copy `appsettings.example.json` to a configuration file for your environment and replace every `REPLACE_` value and the `.invalid` hostname. The template is not a working connection to Keycloak.

- `Authority`: the exact HTTPS realm issuer, without a trailing slash. It must match the discovery document's `issuer` and the access token's `iss`, not just an internal address that reaches Keycloak.
- `ClientId`: the API resource client whose client roles grant access. This is separate from a browser login client.
- `Audience`: the value the API expects in `aud`. Configure an audience mapper in Keycloak; `azp` does not replace `aud`.
- `AllowedGroups`: replace the entire array with the environment's allowed full group paths. At least one entry is required. Group membership alone is insufficient; the user also needs an API client role.
- `RoleNames`: adjust the `Read`, `Write`, and `Admin` values if the API client uses different role names. Keys remain unchanged.
- Claim names must match the Keycloak mappers. Keep HTTP discovery disabled in Production.
- `Scalar:ClientId`: the public browser login client used by Scalar, separate from the API resource client. Enable authorization code with PKCE S256; disable client authentication, implicit flow, and direct grants.
- `Scalar:RedirectUri`: replace `https://api.example.invalid/` with the API's exact public home-page URL, including the trailing slash. Register it as an allowed redirect URI and register its matching web origin in Keycloak. This makes the callback explicit even when the router forwards HTTP to the application. It does not replace the deferred router HTTPS/forwarded-header configuration. Omit this setting only when the request's scheme/host/path base accurately represent the public URL.

Scalar (`/`), its assets, and OpenAPI (`/openapi/v1.json`) are public in every environment, including Production and Test. The API endpoints remain protected. Use the environment's real user accounts; local fixture credentials are not shown outside Development. Both the Pod and the user's browser must be able to reach Keycloak for JWT validation and interactive login respectively.

The API validates JWTs and needs no client secret. These settings can be stored in a ConfigMap. See the repository's [Keycloak setup](../../keycloak/README.md) for the required clients, roles, audience, and group mappers.

## Load the complete file through a ConfigMap

After filling in a file such as `deploy/openshift/appsettings.openshift.json`, select the intended OpenShift project and create or update its ConfigMap:

```powershell
oc project <project-name>
oc create configmap umtb-security-sample-config --from-file=appsettings.json=deploy/openshift/appsettings.openshift.json --dry-run=client -o yaml | oc apply -f -
```

When preparing the Deployment, add the following fields under `spec.template.spec` (merge them with its existing container/volume configuration):

```yaml
containers:
  - name: umtb-security-sample
    # Add the deployment's image, ports, probes, and resource settings separately.
    env:
      - name: ASPNETCORE_ENVIRONMENT
        value: Production
    volumeMounts:
      - name: security-config
        mountPath: /app/appsettings.json
        subPath: appsettings.json
        readOnly: true
volumes:
  - name: security-config
    configMap:
      name: umtb-security-sample-config
```

Mount the file as `/app/appsettings.json`, replacing the image's complete base configuration. Adding an overlay with a shorter array (or overriding only `Security__AllowedGroups__0`) can leave additional group entries from the sample configuration. The complete file prevents those inherited sample entries. Environment variables still override this file; remove unintended `Security__*` overrides from the Deployment.

The ConfigMap and Deployment must be in the same project. A `subPath` mount does not receive ConfigMap file updates, and this application consumes security options at startup. After changing the ConfigMap, restart the Deployment's pods:

```powershell
oc rollout restart deployment/umtb-security-sample
oc rollout status deployment/umtb-security-sample
```

The deployment name above is a proposed name for the later deployment step. No cluster commands are required until the environment values and Deployment are ready.

## Verify the real connection after deployment

The Pod must resolve and reach the realm's HTTPS discovery endpoint (`Authority` plus `/.well-known/openid-configuration`) and its advertised `jwks_uri`. Allow the required network egress. If Keycloak uses an organizational CA, arrange trust in the container's certificate store; do not bypass certificate validation. Router TLS for incoming API requests and HTTPS trust for outgoing Keycloak requests are separate concerns.

Check the application logs for configuration errors. A successful `/health` response only proves that the process responds; it does not verify Keycloak discovery or token validation. Test a protected endpoint with a fresh token issued by the real realm, without recording the token in logs: an authorized user should reach `/me`, a missing/invalid token should receive 401, and an authenticated user without the required group/role should receive 403.

References: [Keycloak hostname/issuer configuration](https://www.keycloak.org/server/hostname), [Kubernetes ConfigMap configuration](https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/), [ConfigMap update behavior](https://kubernetes.io/docs/concepts/configuration/configmap/), [ASP.NET Core configuration providers](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/?view=aspnetcore-10.0).
