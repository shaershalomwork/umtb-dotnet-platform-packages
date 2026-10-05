using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;

namespace Umtb.Platform.Security.Tests;

public sealed class CurrentUserTests
{
    [Fact]
    public async Task No_request_returns_empty_scoped_identity()
    {
        await using var host = new TestHost();
        using var scope = host.App.Services.CreateScope();
        var user = scope.ServiceProvider.GetRequiredService<ICurrentUser>();
        Assert.Same(user, scope.ServiceProvider.GetRequiredService<ICurrentUser>());
        using var otherScope = host.App.Services.CreateScope();
        Assert.NotSame(user, otherScope.ServiceProvider.GetRequiredService<ICurrentUser>());
        Assert.False(user.IsAuthenticated);
        Assert.Null(user.UserId);
        Assert.Null(user.Issuer);
        Assert.Null(user.Name);
        Assert.Null(user.Email);
        Assert.Null(user.NationalIdNumber);
        Assert.Null(user.IssuedAtUtc);
        Assert.Null(user.ExpiresAtUtc);
        Assert.Null(user.RemainingLifetime);
        Assert.Empty(user.Roles);
        Assert.Empty(user.Groups);
        Assert.Empty(user.GetClaimValues("absent"));
    }

    [Fact]
    public async Task Unrelated_authenticated_identity_is_not_trusted()
    {
        await using var host = new TestHost();
        using var scope = host.App.Services.CreateScope();
        var accessor = scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>();
        accessor.HttpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "spoofed")], "UmtbBearer"))
        };
        try { Assert.False(scope.ServiceProvider.GetRequiredService<ICurrentUser>().IsAuthenticated); }
        finally { accessor.HttpContext = null; }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Optional_claims_do_not_deny_access_and_name_falls_back(bool username)
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token(change: p =>
        {
            p.Remove("name"); p.Remove("email"); p.Remove("national_id"); p.Remove("department");
            if (username) p["preferred_username"] = "alice-login";
        }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(username ? "alice-login" : null, json.GetProperty("name").GetString());
        Assert.Equal(JsonValueKind.Null, json.GetProperty("email").ValueKind);
        Assert.Equal(JsonValueKind.Null, json.GetProperty("nationalIdNumber").ValueKind);
        Assert.Empty(json.GetProperty("departments").EnumerateArray());
    }

    [Fact]
    public async Task Configured_optional_claim_and_role_names_are_used()
    {
        await using var host = new TestHost(settings: new()
        {
            ["Security:RoleNames:Write"] = "editor", ["Security:NationalIdClaimType"] = "employee_id",
            ["Security:GroupsClaimType"] = "application_groups"
        });
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token("editor", p =>
        {
            p["employee_id"] = "0001"; p["application_groups"] = new[] { TestHost.Group };
        }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("0001", json.GetProperty("nationalIdNumber").GetString());
        Assert.Equal("write", Assert.Single(json.GetProperty("roles").EnumerateArray()).GetString());
    }

    [Theory]
    [InlineData(120)]
    [InlineData(-5)]
    public async Task Lifetime_uses_time_provider_and_clamps_to_zero(int seconds)
    {
        await using var host = new TestHost();
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        host.Clock.FixedTime = now;
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token(change: p =>
        {
            p["iat"] = now.AddMinutes(-1).ToUnixTimeSeconds(); p["exp"] = now.AddSeconds(seconds).ToUnixTimeSeconds();
        }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(now.AddSeconds(seconds), json.GetProperty("expiresAtUtc").GetDateTimeOffset());
        Assert.Equal(TimeSpan.FromSeconds(Math.Max(0, seconds)), TimeSpan.Parse(json.GetProperty("remainingLifetime").GetString()!));
    }

    [Fact]
    public async Task Requests_do_not_leak_identity_or_claim_values_to_each_other()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        await Task.WhenAll(Enumerable.Range(0, 12).Select(async id =>
        {
            using var response = await host.SendAsync(host.Token(change: p => { p["sub"] = "user-" + id; p["department"] = new[] { "a", "b" }; }));
            var json = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal("user-" + id, json.GetProperty("userId").GetString());
            Assert.Equal(2, json.GetProperty("departments").GetArrayLength());
        }));
        using var anonymous = await host.SendAsync(null);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [Fact]
    public async Task Package_diagnostics_do_not_contain_credentials_or_personal_claims()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        var token = host.Token("unknown");
        using var denied = await host.SendAsync(token);
        using var invalid = await host.SendAsync("not-a-jwt");
        var entries = host.Logs.Entries.Where(e => e.Category.StartsWith("Umtb.Platform.Security.", StringComparison.Ordinal)).ToArray();
        Assert.Contains(entries, e => e.EventId == 1001);
        Assert.Contains(entries, e => e.EventId == 1002);
        Assert.Contains(entries, e => e.EventId == 1003 && e.Message.Contains("/me", StringComparison.Ordinal));
        foreach (var entry in entries)
            foreach (var secret in new[] { token, "not-a-jwt", "Alice Example", "alice@example.test", "001234567" })
                Assert.DoesNotContain(secret, entry.Message);
    }
}
