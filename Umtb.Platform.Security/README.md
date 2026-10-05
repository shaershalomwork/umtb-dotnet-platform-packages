# Umtb.Platform.Security

Keycloak access-token validation, application permissions, and scoped identity for ASP.NET Core 8, 9, and 10. Each API independently validates the original `Authorization: Bearer …` token. No identity headers, shared API keys, default viewer assignment, databases, or controller base classes.

## Quick start

Install `Umtb.Platform.Security` version `0.1.0-preview.1` from your designated feed or the locally packed artifact. Add `using Umtb.Platform.Security;` to `Program.cs`.

Configure `appsettings.json`:

```json
{
  "Security": {
    "Authority": "https://identity.example.com/realms/platform",
    "ClientId": "orders-api",
    "Audience": "orders-api",
    "AllowedGroups": [
      "/applications/orders/users",
      "/applications/orders/admins"
    ],
    "RoleNames": { "Read": "read", "Write": "write", "Admin": "admin" },
    "GroupsClaimType": "groups",
    "NationalIdClaimType": "national_id"
  }
}
```

<!-- quickstart:start -->
```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddUmtbSecurity(builder.Configuration.GetSection("Security"));
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApproveOrder", policy =>
        policy.RequireUmtbPermission(UmtbPermission.Write)
              .RequireClaim("department", "operations"));
});

var app = builder.Build();
app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/me", (ICurrentUser user) => Results.Ok(new
{
    user.UserId, user.Name, user.Roles, user.Groups,
    user.ExpiresAtUtc, user.RemainingLifetime
})).RequireAuthorization(UmtbSecurityPolicies.Read);
app.MapPost("/write-example", () => Results.NoContent())
   .RequireAuthorization(UmtbSecurityPolicies.Write);
app.MapPost("/admin-example", () => Results.NoContent())
   .RequireAuthorization(UmtbSecurityPolicies.Admin);
app.MapPost("/orders/approve", () => Results.NoContent())
   .RequireAuthorization("ApproveOrder");
app.MapGet("/health", () => Results.Ok()).AllowAnonymous();

await app.ValidateUmtbSecurityEndpointsAsync();
await app.RunAsync();
```
<!-- quickstart:end -->

This snippet is compiled with tests and checked against `docs/examples/QuickStart.cs`. The repository sample also includes controllers and resource authorization.

## Application permissions

Every protected operation requires a validated package bearer identity, an allowed application group, and a recognized application role with sufficient permission. Roles come exclusively from `resource_access[ClientId].roles`.

| Assigned permission | Read | Write | Admin |
| --- | --- | --- | --- |
| read | yes | no | no |
| write | yes | yes | no |
| admin | yes | yes | yes |

Realm roles, other clients' roles, and unknown roles are ignored. Groups never manufacture roles. Missing or malformed group/application-role structures grant no access. Both must contain arrays of strings; mixed-type arrays fail closed.

Group paths match exactly and case-sensitively. `/applications/orders` does not match `/applications/orders/admins`, `/Applications/orders`, or a similar prefix. Token values are never trimmed or case-normalized. Configured client roles map to canonical `read`, `write`, and `admin` names.

Controllers use `[Authorize(Policy = UmtbSecurityPolicies.Read)]`; actions can add stricter policies. Policies are cumulative. `RequireUmtbPermission` adds bearer authentication, authenticated identity, application membership, and permission requirements to a custom policy; append ordinary claims or application handlers. Standard `RequireRole` does not implement the package hierarchy.

## Startup audit

Call `ValidateUmtbSecurityEndpointsAsync` after all mapping and before `RunAsync`. Every routed endpoint must declare `AllowAnonymous` or have a named/inline effective policy containing the package requirements. The audit combines controller, action, route-group, inline policy, and authorization-requirement metadata using ASP.NET Core's policy provider. Explicit anonymous endpoints are logged for review.

Missing metadata, bare `[Authorize]`, role-only declarations, unknown policies, extra authentication schemes, and custom endpoint policies missing package requirements fail with the route and repair. Default and fallback policies deny access. A hosted lifecycle guard rejects omitted auditing and re-audits before hosted services start. Do not replace those policies to make bare `[Authorize]` succeed.

Explicit policies do not inherit fallback requirements; include `RequireUmtbPermission` in the effective endpoint policy. See [ASP.NET Core policy authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-10.0).

V1 requires routes, policies, and configuration to be established at startup. Runtime security-metadata mutation, changing options after startup, replacement authentication handlers, and alternative token readers/events are unsupported. Claims transformations must retain the validated identity; adding claims to the existing principal is supported, but extra claims do not change the frozen permission projection. Middleware serving responses before routing/authorization (such as static files or a terminal delegate) is application-owned and cannot be audited as a routed endpoint. Use the illustrated middleware order; the audit does not add middleware.

## Authentication and options

The scheme is named `UmtbBearer`. It requires an exact issuer and audience, a valid signature from HTTPS discovery/JWKS, expiration, lifetime validation, and an asymmetric algorithm allowlist (`RS256` by default). Audience arrays must contain the configured audience; `azp` is not a substitute. Required `sub`, `iat`, and `exp` must be correctly typed and unambiguous. Timestamps must be integral NumericDate seconds in `DateTimeOffset` range; issuance must precede expiration and cannot exceed the current time plus skew. `nbf` is validated when present. After cryptographic validation, payload `typ` must equal Keycloak's `Bearer`, rejecting ID and refresh tokens.

IdentityModel handles discovery caching and key refresh. A discovery outage may permit validation with usable cached keys; tokens that cannot be validated are rejected. The API needs no client secret. The package never disables certificate validation. See [JWT authentication guidance](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-jwt-bearer-authentication?view=aspnetcore-10.0).

| Additional option | Default | Validation |
| --- | --- | --- |
| `AllowedAlgorithms` | `["RS256"]` | Distinct values from RS256/384/512, PS256/384/512, ES256/384/512 |
| `ClockSkew` | `"00:00:30"` | Zero through five minutes |
| `AllowHttpDiscoveryInDevelopment` | `false` | May be true only in Development |

Authority must be an absolute realm issuer URL without a trailing slash, credentials, query, or fragment. Client ID, audience, a nonempty group allowlist, and distinct Read/Write/Admin mappings are required. Role mappings default to `read`, `write`, and `admin`. Errors name the configuration section/key and repair. Options bind once and are validated at startup, including subsequent options configuration. JWT invariants are checked after post-configuration. Configure `UmtbSecurityOptions` instead of replacing validators, events, forwarding, or validation delegates. `MapInboundClaims` and `SaveToken` remain false; client error details are suppressed.

## Scoped current user

`ICurrentUser` uses the same immutable validated projection as authorization. Other schemes, identities merely named `UmtbBearer`, and spoofed headers do not populate it.

| Member | Meaning |
| --- | --- |
| `IsAuthenticated` | Package token validated, even if application assignment is insufficient |
| `UserId`, `Issuer` | `sub` and `iss`; use this pair across realms |
| `Name` | String `name`, falling back to `preferred_username` |
| `Email` | Optional string `email` |
| `NationalIdNumber` | Optional configurable string claim, preserving leading zeros |
| `Roles` | Recognized assigned canonical roles; no invented inherited assignments |
| `Groups` | Exact token matches against configured application groups |
| `IssuedAtUtc`, `ExpiresAtUtc` | Validated UTC `DateTimeOffset` timestamps |
| `RemainingLifetime` | `max(0, exp - TimeProvider.GetUtcNow())`, excluding skew |
| `GetClaimValues(type)` | Read-only additional validated values; empty if absent |

Outside an authenticated request, scalars are null and collections empty. Missing name/email/national ID does not deny access; add an application policy if mandatory. Neither email nor national ID is a stable user key. Lifetime can reach zero during validation tolerance. Hosts can register `TimeProvider` for deterministic calculation. The package does not refresh tokens.

## Resource rules and responses

The package owns identity validation and application permission. Applications own record ownership, sharing, tenant boundaries, query filtering, and existence concealment. After endpoint checks, load the resource and call `IAuthorizationService.AuthorizeAsync(user, resource, policy)`. A resource-only policy can omit package requirements because the routed endpoint has already enforced them. Admin never automatically bypasses resource rules. The sample's illustrative in-memory store demonstrates owner/shared/private access, including an admin denied a private document; replace it with application data and tenant filtering.

- **401** with a bearer challenge: absent, invalid, expired, wrong-issuer, or wrong-audience token.
- **403**: valid identity without the group, role, operation permission, custom claim, or resource access.
- Applications can deliberately return **404** for inaccessible records when existence must be concealed.

See [resource-based authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resource-based?view=aspnetcore-10.0).

## Assignment removal and diagnostics

Valid token assignments remain effective through expiration plus clock skew. Five-minute tokens and 30-second skew can leave approximately five minutes and 30 seconds of access after removal immediately following issuance. Five minutes is a Keycloak setting, not a package maximum; the bound follows `exp`. Logout and session revocation do not notify local JWT validators. Fresh tokens must reflect changed assignments; acquiring them is the login component's responsibility. Introspection should not be assumed to recompute roles. Immediate revocation and shared deny lists are deferred. See [Keycloak OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers).

Package `ILogger` events include categories, route templates, and request trace IDs, never tokens, authorization headers, claim dumps, personal identifiers, or raw exceptions:

| Event ID | Category/purpose |
| --- | --- |
| 1001 | `token_validation_failed` or `invalid_access_token_claims` |
| 1002 | `bearer_challenge` |
| 1003 | `authorization_denied` |
| 1101 | `anonymous_endpoint` (may repeat on final startup audit) |
| 1102 | `endpoint_audit_failed` (count only) |

Framework logging is host-controlled. Keep IdentityModel PII logging disabled and exclude authorization headers from application/proxy logs.

Troubleshooting: startup errors identify an option or route to repair. For 401, check issuer, audience mapper, clock, subject/timestamps, payload token type, and discovery/JWKS reachability without copying tokens into logs. For 403, check the exact client role and full group path in Keycloak's evaluation tools, then custom claims and resource rules. Changed assignments require a fresh token.

## Compatibility

| Asset | JwtBearer dependency | IdentityModel floor |
| --- | --- | --- |
| net8.0 | 8.0.31 | 8.23.0 |
| net9.0 | 9.0.20 | 8.23.0 |
| net10.0 | 10.0.12 | 8.23.0 |

Assets expose identical APIs and reference `Microsoft.AspNetCore.App`; NuGet selects the matching dependency major. Dependencies are centrally pinned and audited transitively. Recommend .NET 10 for new applications; .NET 8 and 9 support ends November 10, 2026 under [Microsoft's lifecycle policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core). Future runtimes require compatibility testing.

V1 covers user access tokens from one realm/client per API. Service accounts, multiple issuers, dynamic endpoint security, online permissions, and immediate revocation are deferred. Package versions are independent of .NET majors. Consult repository compatibility, migration, and release notes before adopting this prerelease.

## Develop and verify this package

Run the following commands from `Umtb.Platform.Security/`. Build with the .NET 10 SDK. Install matching .NET 8, 9, and 10 ASP.NET Core runtimes to run the entire test matrix; tests explicitly reject major-version roll-forward.

```sh
dotnet restore Umtb.Platform.Security.slnx
dotnet build Umtb.Platform.Security.slnx -c Release --no-restore
dotnet test tests/Umtb.Platform.Security.Tests -c Release --no-build --no-restore
python scripts/verify-docs.py
dotnet pack src/Umtb.Platform.Security/Umtb.Platform.Security.csproj -c Release --no-build -o artifacts/packages
python scripts/verify-package.py artifacts/packages/Umtb.Platform.Security.0.1.0-preview.1.nupkg
```

The package solution includes the library, tests, and sample. Only the library is packable; the symbol package accompanies the same primary NuGet package. `Directory.Build.props` and `Directory.Packages.props` apply only inside this package. There are no dependencies on other repository packages. Its current dependencies are published Microsoft packages and the ASP.NET Core shared framework. A future dependency on a sibling package must use a published NuGet version and document its purpose, necessity, and supported versions here.

- [Complete sample](samples/Umtb.Platform.Security.Sample/Program.cs): Minimal APIs, controllers, route groups, custom policies, and resource authorization. Includes [Scalar with Keycloak login](samples/Umtb.Platform.Security.Sample/README.md) at `http://localhost:5000/` in Development; run `dotnet run --project samples/Umtb.Platform.Security.Sample --framework net10.0`.
- [Keycloak setup and reproducible fixture](keycloak/README.md).
- [Compatibility and migration notes](docs/compatibility.md), [changelog](CHANGELOG.md), and [release verification](docs/releasing.md).
- [Verification records and outstanding release gates](docs/verification.md).

Tests and the sample use a project reference for development. Follow the release instructions to switch them to `UsePackedPackage=true` and verify the actual `.nupkg` with a fresh cache. Scripts resolve their inputs relative to this package; generated packages, logs, and verification output belong in its ignored `artifacts/` directory.

The repository's `.github/workflows/security.yml` provisions each runtime on Windows and Linux, builds all targets, installs the actual `.nupkg` in test consumers, and runs the sample. A separate Linux job exercises authorization code with PKCE against pinned Keycloak. Publishing requires a designated NuGet feed and release acceptance; CI does not automatically push packages.
