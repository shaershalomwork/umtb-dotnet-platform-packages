# Changelog

## 0.1.0-preview.1 — unreleased

- Add a multi-stage .NET 10 application image for the sample, with a non-root runtime on port 8080 and documented build/run commands.
- Add an OpenShift Keycloak configuration template and ConfigMap mounting instructions that replace the sample's complete base configuration.
- Expose the sample's Scalar UI and OpenAPI document in all environments, retain API authorization, limit fixture instructions to Development, and allow an explicit public OAuth redirect URI.
- Add net8.0/net9.0/net10.0 package assets with matching JwtBearer majors and an IdentityModel 8.23.0 floor.
- Validate Keycloak access tokens, exact issuer/audience, asymmetric signatures, subject and timestamps, and access-token type.
- Require exact application group membership and explicitly recognized client roles, with read/write/admin hierarchy.
- Add composable policies, final options validation, endpoint auditing, and a startup guard.
- Add immutable scoped current-user projection and structured diagnostics without personal claims or credentials.
- Provide compiled documentation examples, a resource-authorization sample, signed JWT/OIDC/JWKS integration tests, packed consumers, OS/framework CI, and a pinned Keycloak PKCE smoke fixture.
- Consolidate the library and its development infrastructure under `Umtb.Platform.Security/`, with package-local build, dependency, test, and release settings; preserve the public API, package identity, version, and framework targets.

Initial prerelease is pending feed designation and release verification. Version 1.0.0 requires acceptance and successful release gates.
