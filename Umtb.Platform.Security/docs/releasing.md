# Release verification

The initial artifact version is `0.1.0-preview.1`. Do not label it 1.0.0 until accepted and every release gate below has passed. CI builds and uploads artifacts; it does not publish to a feed automatically.

Run all commands in this document from `Umtb.Platform.Security/`, the package directory. The solution, build settings, dependency versions, scripts, and output are local to this directory; no sibling package or repository-root build configuration is required.

1. Run the full repository workflow `.github/workflows/security.yml`. It provisions matching .NET 8/9/10 runtimes on Windows/Linux, compiles all source and README examples, tests packed consumers and dependency selection, runs the sample, and runs the pinned Keycloak fixture on Linux.
2. Inspect the transitive vulnerability report. Keep central framework servicing versions and the IdentityModel floor patched, restoring with NuGet audit enabled.
3. Inspect the nupkg's three DLL/XML pairs, README, framework references, and framework-specific dependency groups using `scripts/verify-package.py`.
4. Record runtime versions, test counts, sample results, and Keycloak smoke results. A stopped Docker engine or unavailable CI is an outstanding check, never a passing smoke result.
5. Designate the intended NuGet feed and use its approved credentials/trusted publishing. Publish this exact verified prerelease, then consume it from that feed in an API integration. The repository contains no publishing credentials or assumed public feed destination.
6. After acceptance, set the release version in `Directory.Build.props` and the central consumer reference; update version checks, changelog, and docs together. Repeat all gates before publishing 1.0.0.

Pack the library explicitly after the source build described in the package README:

```sh
dotnet pack src/Umtb.Platform.Security/Umtb.Platform.Security.csproj -c Release --no-build -o artifacts/packages
```

To exercise packed consumers locally, set `NUGET_PACKAGES` to a new, empty directory under this package's `artifacts/` directory before restoring. For example, use `$env:NUGET_PACKAGES = Join-Path $PWD 'artifacts/consumer-cache-<unique-run>'` in PowerShell, or `export NUGET_PACKAGES="$PWD/artifacts/consumer-cache-<unique-run>"` in a POSIX shell, replacing `<unique-run>` with a new value each time. Keep that environment setting for the commands below:

```sh
dotnet restore tests/Umtb.Platform.Security.Tests -p:UsePackedPackage=true --configfile NuGet.Packed.config
dotnet restore samples/Umtb.Platform.Security.Sample -p:UsePackedPackage=true --configfile NuGet.Packed.config
python scripts/verify-package.py artifacts/packages/Umtb.Platform.Security.0.1.0-preview.1.nupkg --assets tests/Umtb.Platform.Security.Tests/obj/project.assets.json
python scripts/verify-package.py artifacts/packages/Umtb.Platform.Security.0.1.0-preview.1.nupkg --assets samples/Umtb.Platform.Security.Sample/obj/project.assets.json
dotnet test tests/Umtb.Platform.Security.Tests -c Release -p:UsePackedPackage=true --no-restore
dotnet build samples/Umtb.Platform.Security.Sample -c Release -p:UsePackedPackage=true --no-restore
python scripts/sample-smoke.py --framework net8.0
python scripts/sample-smoke.py --framework net9.0
python scripts/sample-smoke.py --framework net10.0
```

The fresh cache prevents NuGet from reusing a previous artifact with the same prerelease version. Restore your previous `NUGET_PACKAGES` setting afterward, then run `dotnet restore Umtb.Platform.Security.slnx` to return to normal project references. See [the Keycloak fixture](../keycloak/README.md) for the live identity-provider smoke test.

The Linux matrix can also be reproduced locally with Docker after packing:

```sh
docker build --progress=plain -f scripts/verify-linux.Dockerfile -t umtb-security-verification:local .
docker compose -f keycloak/compose.yaml up -d
docker run --rm --network container:keycloak-keycloak-1 umtb-security-verification:local python3 scripts/keycloak-smoke.py --framework net8.0
docker run --rm --network container:keycloak-keycloak-1 umtb-security-verification:local python3 scripts/keycloak-smoke.py --framework net9.0
docker run --rm --network container:keycloak-keycloak-1 umtb-security-verification:local python3 scripts/keycloak-smoke.py --framework net10.0
docker compose -f keycloak/compose.yaml down
```

The build runs packed consumers, documentation/dependency checks, and sample HTTP smoke tests on all three Linux runtimes. The subsequent runs share the disposable fixture's network namespace so its loopback issuer is reachable. These commands assume Compose's default `keycloak` project name; use the actual fixture container name if you override it.

## Independence and publication

For structural changes, copy this package directory to a temporary location outside the checkout, excluding `bin`, `obj`, `artifacts`, `TestResults`, and Python caches. Run the source restore/build/tests and pack commands there with the documented SDK and runtimes. No root solution, sibling source, or parent MSBuild files may be needed. Then restore and compile standalone consumers for net8.0, net9.0, and net10.0 with an explicit `PackageReference` to `Umtb.Platform.Security` version `0.1.0-preview.1`, using the new package as a local feed and no repository imports.

Inspect the primary package's identity, version, API, dependency groups, framework references, README, and three DLL/XML pairs. Test/sample projects, fixture configuration, and development scripts must not ship. Preserve the symbol package. Record new verification results and checksums; source-path or documentation changes can change artifact bytes without changing its public contract.

Once the intended feed and release acceptance are designated, publish only the exact verified artifact using that feed's approved authentication. The package-specific command is `dotnet nuget push artifacts/packages/Umtb.Platform.Security.0.1.0-preview.1.nupkg --source <approved-feed-url> --no-symbols`; supply any required credentials through the approved secret mechanism. Publish the accompanying symbols separately to the designated symbol service. Consume the published version in an external API integration before recording release completion. No sibling package build, version change, or publication is required.
