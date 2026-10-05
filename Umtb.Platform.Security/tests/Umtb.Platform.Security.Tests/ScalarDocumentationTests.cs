using System.Net;
using System.Text.Json;

namespace Umtb.Platform.Security.Tests;

public sealed class ScalarDocumentationTests
{
    [Theory]
    [InlineData("Development")]
    [InlineData("Test")]
    [InlineData("Staging")]
    [InlineData("Production")]
    public async Task Documentation_passes_audit_and_exposes_Keycloak_code_flow_in_every_environment(string environment)
    {
        await using var host = new TestHost(environment: environment, documentation: true,
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
        var description = document.RootElement.GetProperty("info").GetProperty("description").GetString()!;
        if (environment == "Development") Assert.Contains("fixture-password", description);
        else
        {
            Assert.DoesNotContain("fixture-password", description);
            Assert.DoesNotContain("reader", description);
            Assert.DoesNotContain("alice", description);
        }
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
                var expectedTag = path.Name == "/controller/orders"
                    ? "Controller examples"
                    : "Minimal API examples";
                Assert.Equal(expectedTag, Assert.Single(operation.Value.GetProperty("tags").EnumerateArray()).GetString());
                Assert.False(string.IsNullOrWhiteSpace(operation.Value.GetProperty("summary").GetString()));
                Assert.False(string.IsNullOrWhiteSpace(operation.Value.GetProperty("description").GetString()));
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
    [InlineData("Test")]
    public async Task Scalar_uses_configured_public_redirect_uri_behind_a_proxy(string environment)
    {
        const string redirectUri = "https://api.example.test/sample/";
        await using var host = new TestHost(environment: environment, documentation: true,
            settings: new() { ["Scalar:RedirectUri"] = redirectUri });
        await host.StartAsync();
        using var response = await host.SendAsync(null, "/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains(redirectUri, html);
        Assert.DoesNotContain("http://localhost/", html);
    }
}
