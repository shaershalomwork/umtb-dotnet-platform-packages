using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Routing;

namespace Umtb.Platform.Security.Tests;

public sealed class ScalarDocumentationTests
{
    [Fact]
    public async Task Development_documentation_passes_audit_and_exposes_Keycloak_code_flow()
    {
        await using var host = new TestHost(environment: "Development", documentation: true,
            settings: new() { ["Scalar:ClientId"] = "test-login-client" });
        await host.StartAsync();

        using var page = await host.SendAsync(null, "/");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        Assert.Contains("test-login-client", html);
        Assert.Contains("SHA-256", html);
        Assert.Contains("http://localhost/", html);
        Assert.DoesNotContain("clientSecret", html);

        foreach (var path in new[] { "/scalar.js", "/scalar.aspnetcore.js", "/favicon.svg" })
        {
            using var asset = await host.SendAsync(null, path);
            Assert.Equal(HttpStatusCode.OK, asset.StatusCode);
            Assert.NotEmpty(await asset.Content.ReadAsByteArrayAsync());
        }

        using var response = await host.SendAsync(null, "/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var scheme = document.RootElement.GetProperty("components").GetProperty("securitySchemes").GetProperty("Keycloak");
        Assert.Equal("oauth2", scheme.GetProperty("type").GetString());
        var flow = scheme.GetProperty("flows").GetProperty("authorizationCode");
        Assert.Equal(TestHost.Issuer + "/protocol/openid-connect/auth", flow.GetProperty("authorizationUrl").GetString());
        Assert.Equal(TestHost.Issuer + "/protocol/openid-connect/token", flow.GetProperty("tokenUrl").GetString());
        Assert.False(scheme.GetProperty("flows").TryGetProperty("password", out _));
        var paths = document.RootElement.GetProperty("paths");
        Assert.Equal(9, paths.EnumerateObject().Sum(path => path.Value.EnumerateObject().Count()));
        foreach (var path in paths.EnumerateObject())
        {
            foreach (var operation in path.Value.EnumerateObject())
            {
                if (path.Name == "/health")
                {
                    Assert.False(operation.Value.TryGetProperty("security", out _));
                    continue;
                }
                Assert.True(operation.Value.GetProperty("security")[0].TryGetProperty("Keycloak", out _));
                Assert.True(operation.Value.GetProperty("responses").TryGetProperty("401", out _));
                Assert.True(operation.Value.GetProperty("responses").TryGetProperty("403", out _));
            }
        }

        using var anonymous = await host.SendAsync(null);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        using var reader = await host.SendAsync(host.Token());
        Assert.Equal(HttpStatusCode.OK, reader.StatusCode);
        using var denied = await host.SendAsync(host.Token(), "/admin-example", HttpMethod.Post);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task Documentation_routes_are_absent_outside_Development(string environment)
    {
        await using var host = new TestHost(environment: environment, documentation: true);
        await host.StartAsync();
        var routes = ((IEndpointRouteBuilder)host.App).DataSources.SelectMany(source => source.Endpoints).OfType<RouteEndpoint>();
        Assert.DoesNotContain(routes, route => route.RoutePattern.RawText!.Contains("documentName", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, route => route.RoutePattern.RawText!.Contains("scalar", StringComparison.Ordinal));
        using var response = await host.SendAsync(host.Token("admin"), "/openapi/v1.json");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
