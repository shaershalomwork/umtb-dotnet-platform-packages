# Run from the package directory: docker build -f scripts/verify-linux.Dockerfile .
# Local reproduction of the Linux CI matrix, using the same packed artifact as Windows.
FROM mcr.microsoft.com/dotnet/aspnet:8.0.31 AS net8
FROM mcr.microsoft.com/dotnet/aspnet:9.0.20 AS net9
FROM mcr.microsoft.com/dotnet/sdk:10.0.401 AS verification
COPY --from=net8 /usr/share/dotnet/shared/ /usr/share/dotnet/shared/
COPY --from=net9 /usr/share/dotnet/shared/ /usr/share/dotnet/shared/
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN dotnet --list-runtimes
RUN dotnet restore tests/Umtb.Platform.Security.Tests -p:UsePackedPackage=true --configfile NuGet.Packed.config
RUN dotnet restore samples/Umtb.Platform.Security.Sample -p:UsePackedPackage=true --configfile NuGet.Packed.config
RUN dotnet test tests/Umtb.Platform.Security.Tests -c Release -p:UsePackedPackage=true --no-restore
RUN dotnet build samples/Umtb.Platform.Security.Sample -c Release -p:UsePackedPackage=true --no-restore
RUN python3 scripts/verify-docs.py && python3 scripts/verify-package.py artifacts/packages/Umtb.Platform.Security.0.1.0-preview.1.nupkg --assets tests/Umtb.Platform.Security.Tests/obj/project.assets.json
RUN python3 scripts/verify-package.py artifacts/packages/Umtb.Platform.Security.0.1.0-preview.1.nupkg --assets samples/Umtb.Platform.Security.Sample/obj/project.assets.json
RUN python3 scripts/sample-smoke.py --framework net8.0 && python3 scripts/sample-smoke.py --framework net9.0 && python3 scripts/sample-smoke.py --framework net10.0
CMD ["python3", "scripts/keycloak-smoke.py"]
