# Build from the package directory: docker build -t umtb-security-sample:local .
FROM mcr.microsoft.com/dotnet/sdk:10.0.401 AS build
WORKDIR /src

# Restore only the application and its library reference for the selected runtime.
COPY Directory.Build.props Directory.Packages.props ./
COPY src/Umtb.Platform.Security/Umtb.Platform.Security.csproj src/Umtb.Platform.Security/
COPY samples/Umtb.Platform.Security.Sample/Umtb.Platform.Security.Sample.csproj samples/Umtb.Platform.Security.Sample/
RUN dotnet restore samples/Umtb.Platform.Security.Sample/Umtb.Platform.Security.Sample.csproj -p:TargetFrameworks=net10.0

COPY src/Umtb.Platform.Security/ src/Umtb.Platform.Security/
COPY samples/Umtb.Platform.Security.Sample/ samples/Umtb.Platform.Security.Sample/
RUN dotnet publish samples/Umtb.Platform.Security.Sample/Umtb.Platform.Security.Sample.csproj \
    -c Release -f net10.0 -p:TargetFrameworks=net10.0 -p:UseAppHost=false \
    --no-restore -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0.12 AS runtime
WORKDIR /app
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
COPY --from=build /app/publish/ ./
USER $APP_UID
ENTRYPOINT ["dotnet", "Umtb.Platform.Security.Sample.dll"]
