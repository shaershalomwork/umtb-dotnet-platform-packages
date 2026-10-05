# Keycloak setup

Use an API resource client separate from the browser login client. The API validates JWTs locally and needs no client secret.

## Production configuration

1. Create a realm and record its exact HTTPS issuer. Set access-token lifetime initially to 300 seconds.
2. Create `orders-api` with `read`, `write`, and `admin` client roles. Disable standard login, implicit flow, direct grants, and service accounts for this API client.
3. Create `orders-web` using authorization code and PKCE S256, with exact redirect URIs and web origins. Disable implicit flow and direct grants. Choose public/confidential login-client authentication to suit the application architecture.
4. Disable full scope allowed on `orders-web` and map only the intended `orders-api` roles in its dedicated role scope. Create and attach `orders-api-access` for token mappers, including a client-role mapper targeting `resource_access.orders-api.roles` as a string array. Keep the mapper scope itself free of role-access restrictions so users without application roles still receive the audience/group claims and reach the API's explicit permission denial.
5. Add an audience mapper including `orders-api` in access tokens. The requesting client in `azp` does not replace audience validation.
6. Add a Group Membership mapper named `groups`, with **Full group path enabled**, in access tokens. Create `/applications/orders/users` and `/applications/orders/admins`. Assign authorized users both an allowed group and application role, directly or through approved group-role mappings. No default application assignments. Composite roles are unnecessary; the package implements the hierarchy.
7. Include subject (`basic` scope in current Keycloak), profile, and email claims. Map managed attribute `nationalId` to the string claim `national_id`. User Profile must allow administrator edits and deny user edits to that attribute, and to managed authorization attributes such as `department`.
8. Evaluate tokens for assigned and unassigned users. Check issuer, audience, subject, timestamps, payload `typ=Bearer`, full group paths, and client-role structure. Confirm fresh tokens lose removed assignments. Never paste live tokens into third-party viewers.

References: [Keycloak administration](https://www.keycloak.org/docs/26.8.0/server_admin/), [OIDC/introspection endpoints](https://www.keycloak.org/securing-apps/oidc-layers).

## Release fixture

`compose.yaml` pins `quay.io/keycloak/keycloak:26.8.0`. `platform-realm.json` includes the described scopes, mappings, managed-attribute permissions, and users with synthetic identifiers. Every fixture user has the **test-only** password `fixture-password`. The browser client uses code/PKCE; no password-grant client is added for testing.

| User | Group | Role | Expected access |
| --- | --- | --- | --- |
| alice | users | admin | read/write/admin; private resource forbidden |
| reader | users | read | read |
| writer | users | write | read/write |
| group-only | users | none | forbidden |
| role-only | none | admin | forbidden |
| unassigned | none | none | forbidden |

With Docker's Linux engine running, Python 3, and .NET installed, run from the `Umtb.Platform.Security/` package directory:

```sh
docker compose -f keycloak/compose.yaml up -d
dotnet build samples/Umtb.Platform.Security.Sample -c Release
python scripts/keycloak-smoke.py --framework net10.0
docker compose -f keycloak/compose.yaml down
```

The script signs in through authorization code + PKCE and exercises the actual sample process. It checks permissions, identity projection, ID/refresh token rejection, and resource rules without printing tokens. Repeat for net8.0 and net9.0 with matching runtimes; CI runs all three on Linux.

Use `--dotnet /path/to/dotnet` for a portable runtime host. The Python runner mirrors browsers' Secure-cookie handling solely for the fixed HTTP loopback fixture at `127.0.0.1:18080`; its normal cookie policy applies everywhere else.

The fixture binds only `127.0.0.1:18080`, uses HTTP with an explicit Development-only API option, and has no persistent database volume. It is a disposable local/CI fixture. Production uses HTTPS and real identity controls. No shared admin password is bootstrapped; provision a separate administrator for manual admin-console review. Recreate the disposable container to reimport fixture changes.

## Scalar login in the sample

The fixture's public `orders-web` client also allows exact redirect URIs `http://localhost:5000/` and `http://127.0.0.1:5000/`, with matching web origins for the browser token exchange. Its existing role scopes, audience/group mappers and S256 PKCE setting apply to Scalar login as well. Run the sample's `Sample` launch profile and use Scalar's **Authenticate** action. See [the sample instructions](../samples/Umtb.Platform.Security.Sample/README.md).
