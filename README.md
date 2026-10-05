# UMTB .NET platform packages

This repository contains .NET packages that share infrastructure capabilities across applications and teams in the organization. The goal is to implement common capabilities once and distribute them as NuGet packages that each application can use as needed.

Each package provides a specific capability and maintains its own code, tests, versions, and release process. The repository brings these packages together, while each application chooses which ones to install. Shared conventions, interfaces, quality standards, and documentation keep the packages consistent across the organization.

## Current package

There is currently one NuGet package intended for publication: [Umtb.Platform.Security](Umtb.Platform.Security/README.md). It provides authentication and authorization for ASP.NET Core 8, 9, and 10:

- Strict validation of JWT tokens issued by Keycloak.
- Application read, write, and admin permissions.
- Auditing of endpoint security settings at application startup.
- Access to current user information throughout an HTTP request.

The package directory also contains tests, samples, and configuration for local development with Keycloak. Keycloak runs as an external service, and its configuration files are not part of the NuGet package. Test and sample projects are not packaged for publication.

## Getting started

1. Read the [security package README](Umtb.Platform.Security/README.md) for installation, configuration, and usage instructions.
2. To develop the package, open `Umtb.Platform.Security/Umtb.Platform.Security.slnx` and work from the package directory following its documentation.
3. Find the package source in `src`, tests in `tests`, and usage examples in `samples`.

Each package is built, tested, and packed independently. Working on one package does not require building or releasing the entire repository.

## Repository structure

```text
umtb-dotnet-platform-packages/
├── README.md
├── .github/workflows/
└── Umtb.Platform.Security/
    ├── Umtb.Platform.Security.slnx
    ├── Directory.Build.props
    ├── Directory.Packages.props
    ├── NuGet.Packed.config
    ├── .dockerignore
    ├── README.md
    ├── CHANGELOG.md
    ├── src/Umtb.Platform.Security/
    ├── tests/
    ├── samples/
    ├── keycloak/
    ├── docs/
    └── scripts/
```

Additional packages will have their own directories at the repository root, named `Umtb.Platform.<Capability>`.

## Repository guidelines

- **Keep each package independent.** Its directory contains its source, tests, samples, documentation, changelog, scripts, and development infrastructure. Each package must support independent consumption, building, testing, packing, and publication.
- **Let each package own its versions and settings.** Each package defines its own version, dependencies, .NET targets, and release process. Root settings must not force all packages to use the same version or .NET targets.
- **Justify dependencies between packages.** Packages in this repository have no dependencies on one another by default. A dependency is allowed only when it is essential to the package's capability. Sharing a repository or seeking consistency is not sufficient justification.
- **Make required dependencies explicit and documented.** The consuming package's README must identify the required package, the dependency's purpose, why it is necessary, and the supported versions. Use published NuGet versions, avoid circular dependencies, and do not require packages to be built or released together.
- **Keep shared information at the root.** The root contains the package catalog, repository guidelines, and settings that apply to all packages. GitHub Actions workflows live in `.github/workflows` and can run separately for each package. If a root solution is added, it is for convenience and must not be required to build an individual package.
