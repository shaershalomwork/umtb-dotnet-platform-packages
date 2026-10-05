# Compatibility and migration

| Package asset | JwtBearer | IdentityModel OpenIdConnect and transitive IdentityModel libraries |
| --- | --- | --- |
| net8.0 | 8.0.31 | 8.23.0 |
| net9.0 | 9.0.20 | 8.23.0 |
| net10.0 | 10.0.12 | 8.23.0 |

One source/public API targets all three frameworks and references `Microsoft.AspNetCore.App`. Central versions live in `Directory.Packages.props`. Referencing OpenIdConnect directly raises the entire IdentityModel dependency chain above JwtBearer 8's older default. NuGet audit includes transitive dependencies and treats warnings as errors; release checks also inspect the vulnerability report. Review the dependency graph on every release.

The .NET 10 SDK builds this package independently. Consumers need the matching ASP.NET Core runtime. CI explicitly provisions 8/9/10 and tests both Windows and Linux, including consumers of the actual nupkg. Tests assert the running major, so rolling an 8-target test onto 10 does not count as verification. Future .NET versions need compatibility testing before support is claimed.

Recommend .NET 10 for new applications. Microsoft support for .NET 8 and 9 ends November 10, 2026; retained package compatibility is separate from runtime support. See [Microsoft lifecycle](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core) and [NuGet multi-targeting](https://learn.microsoft.com/en-us/nuget/create-packages/supporting-multiple-target-frameworks).

## Migration from identity-header or shared-key integrations

1. Forward the original bearer access token to every API and configure its exact realm issuer and audience.
2. Configure Keycloak client roles, audience, subject, and full-path group mappers. Explicitly assign both application groups and roles; do not retain default viewer access.
3. Replace trusted `x-user-*`/shared-key handling with `AddUmtbSecurity` and normal authentication/authorization middleware.
4. Replace endpoint bare/role-only authorization with named package policies or `RequireUmtbPermission`; mark intentional public routes with `AllowAnonymous`.
5. Add the final endpoint audit before startup. Resolve identities through scoped `ICurrentUser`; use `(Issuer, UserId)` for cross-realm keys.
6. Keep record ownership, tenant filters, and sharing in application code. Admin permission does not bypass them.
7. Account for token-expiry delay after assignment removal. Issue fresh tokens after changes and set the intended access-token lifetime.

There is no earlier released package API to migrate. During prerelease, validate the complete integration before adoption. Do not use service-account tokens or multiple issuers with this v1 contract.

## Versioning

Package versions are independent of .NET majors. Compatible fixes and security dependency updates are patches; compatible additions are minor releases. Changes to group/permission semantics, required settings/claims, public contracts, or framework assets require a major release after 1.0, except explicitly documented corrections to security defects. Publish changelog and migration notes with every such change.
