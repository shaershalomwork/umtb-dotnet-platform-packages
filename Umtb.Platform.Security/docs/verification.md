# Verification records

## Package-directory consolidation — 2026-10-04

The relocated package was verified with SDK 10.0.401 on Windows x64 and in the Linux x64 verification image. All build, dependency, fixture, and script inputs now reside in `Umtb.Platform.Security/`; only GitHub workflow orchestration remains in the repository's `.github/workflows/` directory.

| Verification | net8.0 | net9.0 | net10.0 |
| --- | --- | --- | --- |
| Windows source tests | 131 passed | 131 passed | 131 passed |
| Source tests in an isolated package copy | 131 passed | 131 passed | 131 passed |
| Windows packed-consumer tests | 131 passed | 131 passed | 131 passed |
| Linux packed-consumer tests | 131 passed | 131 passed | 131 passed |
| Sample HTTP smoke | passed on both OSes | passed on both OSes | passed on both OSes |
| Live Keycloak PKCE smoke | passed on both OSes | passed on both OSes | passed on both OSes |
| Standalone NuGet consumer build | passed | passed | passed |

The package directory was copied outside the repository without generated output. Its solution restored, built with zero warnings/errors, passed all source tests, and produced the primary and symbol packages without parent build settings or sibling sources. A separate ASP.NET Core consumer compiled the README quick start using an explicit package version, a fresh NuGet cache, and no repository MSBuild imports.

The Windows/Linux packed-consumer matrix passed 786 cases. Both test and sample restore graphs used the actual NuGet package, and the verifier matched restored assemblies against its contents. Windows and Linux used .NET / ASP.NET Core 8.0.31, 9.0.20, and 10.0.12. The package-only Docker context built successfully; its live checks shared the disposable Keycloak fixture's network namespace. The verification fixture was removed afterward.

Additional checks passed:

- All 26 checked C# source and preserved configuration files matched their pre-move SHA-256 hashes. No source, behavior, dependency version, or framework change was introduced.
- Public API XML matched the previous artifact for all three targets. The package ID remains `Umtb.Platform.Security`, version `0.1.0-preview.1`, with the same framework references and dependency groups.
- The primary package contains the README and three DLL/XML pairs, with no test, sample, Keycloak, or development-script content; the accompanying `.snupkg` was produced.
- README/example equality, realm fixture structure, and Python syntax checks passed.
- The transitive NuGet vulnerability check reported no vulnerable dependencies at verification time.

Artifact, relative to the package directory: `artifacts/packages/Umtb.Platform.Security.0.1.0-preview.1.nupkg` (plus `.snupkg`).

SHA-256: `E3C01AF6A638D3A7FEA4DE149C09ADBC5F40A66569685EDACEA6039A8994A209`.

The updated GitHub Actions workflow has not been dispatched; its builds and OS/framework integration checks were exercised locally. The package remains unpublished pending feed designation and release acceptance. The development solution was restored to normal project references after verification.

## Before directory consolidation — 2026-10-04

This section records verification before the package-directory consolidation. Its artifact path was relative to the former repository-root layout, and its checksum identifies that preserved historical artifact. These results alone do not verify the relocated layout. All current development and release commands run from `Umtb.Platform.Security/`; see [release verification](releasing.md).

Verified on Windows x64 and in a Linux x64 SDK 10.0.401 container. Windows portable runtimes were downloaded from Microsoft's release metadata and SHA-512 checked; the system runtime installation was unchanged. Linux uses the matching official .NET runtime images through `scripts/verify-linux.Dockerfile`.

| Runtime | Windows tests | Linux tests | Sample HTTP smoke | Live Keycloak PKCE smoke |
| --- | --- | --- | --- | --- |
| .NET / ASP.NET Core 8.0.31 | 131 passed | 131 passed | passed on both | passed on both |
| .NET / ASP.NET Core 9.0.20 | 131 passed | 131 passed | passed on both | passed on both |
| .NET / ASP.NET Core 10.0.12 | 131 passed | 131 passed | passed on both | passed on both |

The packed test/sample consumers use `PackageReference`, with the project reference disabled, and a fresh package cache. Tests assert the actual runtime and JwtBearer major. All three library, sample, and test targets compile with zero warnings/errors. Sample checks exercise startup auditing, anonymous health, and bearer challenges; signed-token integration tests compile the actual sample routes/controllers and exercise the permission/resource behavior with controlled OIDC/JWKS responses.

There are 786 passing packed-consumer test cases across the six OS/framework combinations. Live Keycloak 26.8.0 checks use real authorization code with PKCE, all six fixture assignment scenarios, ID/refresh-token rejection, optional identity claims, and owner/shared/private resource authorization. The actual realm import and login flow were verified after correcting its unmanaged-attribute setting and the runner's loopback cookie handling.

Also verified:

- Actual automatic JWKS refresh after key rotation; cached-key behavior during discovery outages.
- NuGet asset/dependency selection, matching restored assembly bytes, three XML documentation files, README, and framework references.
- README snippet equality with its compiled example; Keycloak fixture JSON structure and role-scope/managed-attribute settings.
- NuGet transitive vulnerability audit: no known vulnerabilities reported at verification time.
- Python helper compilation and Git whitespace checks.

Artifact: `artifacts/packages/Umtb.Platform.Security.0.1.0-preview.1.nupkg` (plus `.snupkg`).

SHA-256: `B0DC3FF66FFADBFB3BA0871EF40397FFD37BE31C54FA0AC349C66447141DD643`.

### Outstanding release gates

- The GitHub Actions workflow itself has not been triggered; its runtime/OS matrix and live Keycloak checks were reproduced locally on Windows and Linux.
- The artifact is local and unpublished. A destination feed and release acceptance are not yet designated. Keep it a prerelease until all release gates pass; see `releasing.md`.

The initial sandboxed sample process could not write Windows Event Log; smoke checks were rerun successfully with normal Windows access. This was an execution-environment restriction, not a bypass or change to token validation.
