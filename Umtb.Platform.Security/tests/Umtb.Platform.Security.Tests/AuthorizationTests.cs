using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Umtb.Platform.Security.Tests;

public sealed class AuthorizationTests
{
    [Theory]
    [InlineData("read", "/me", "GET", 200)]
    [InlineData("read", "/write-example", "POST", 403)]
    [InlineData("read", "/admin-example", "POST", 403)]
    [InlineData("write", "/me", "GET", 200)]
    [InlineData("write", "/write-example", "POST", 204)]
    [InlineData("write", "/admin-example", "POST", 403)]
    [InlineData("admin", "/me", "GET", 200)]
    [InlineData("admin", "/write-example", "POST", 204)]
    [InlineData("admin", "/admin-example", "POST", 204)]
    public async Task Permission_hierarchy(string role, string route, string method, int status)
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token(role), route, new HttpMethod(method));
        Assert.Equal(status, (int)response.StatusCode);
    }

    public static IEnumerable<object[]> MissingAccess()
    {
        yield return ["groups", null!];
        yield return ["groups", new[] { "/applications/orders/users/admins" }];
        yield return ["groups", new[] { "/applications/orders/users-extra" }];
        yield return ["groups", new[] { "/Applications/orders/users" }];
        yield return ["groups", new[] { " /applications/orders/users" }];
        yield return ["groups", new[] { "/applications/orders/users " }];
        yield return ["groups", TestHost.Group];
        yield return ["groups", new object[] { TestHost.Group, 4 }];
        yield return ["groups", new { path = TestHost.Group }];
        yield return ["resource_access", null!];
        yield return ["resource_access", new { other_api = new { roles = new[] { "admin" } } }];
        yield return ["resource_access", new Dictionary<string, object> { ["orders-api"] = new { roles = new[] { "viewer" } } }];
        yield return ["resource_access", new Dictionary<string, object> { ["orders-api"] = new { roles = "admin" } }];
        yield return ["resource_access", new Dictionary<string, object> { ["orders-api"] = new { roles = new object[] { "admin", 42 } } }];
        yield return ["resource_access", "not-json"];
    }

    [Theory]
    [MemberData(nameof(MissingAccess))]
    public async Task Missing_or_malformed_application_assignment_is_forbidden(string claim, object? value)
    {
        await using var host = new TestHost();
        await host.StartAsync();
        var token = host.Token(change: p =>
        {
            if (value is null) p.Remove(claim); else p[claim] = value;
            p["realm_access"] = new { roles = new[] { "admin" } };
        });
        using var response = await host.SendAsync(token);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task No_assignment_and_duplicate_assignment_claims_fail_closed()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var neither = await host.SendAsync(host.Token(change: p => { p.Remove("groups"); p.Remove("resource_access"); }));
        Assert.Equal(HttpStatusCode.Forbidden, neither.StatusCode);
        using var duplicate = await host.SendAsync(host.Token(payloadSuffix: "\"groups\":[\"/applications/orders/users\"]"));
        Assert.Equal(HttpStatusCode.Forbidden, duplicate.StatusCode);
    }

    [Theory]
    [InlineData("/controller/orders")]
    [InlineData("/reports/daily")]
    public async Task Controller_and_route_group_metadata_is_honored(string path)
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token(), path);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var anonymous = await host.SendAsync(null, path);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [Fact]
    public async Task Cumulative_controller_policies_enforce_write()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var read = await host.SendAsync(host.Token(), "/controller/orders", HttpMethod.Post);
        using var write = await host.SendAsync(host.Token("write"), "/controller/orders", HttpMethod.Post);
        Assert.Equal(HttpStatusCode.Forbidden, read.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, write.StatusCode);
    }

    [Theory]
    [InlineData("write", "operations", true, 204)]
    [InlineData("write", "sales", true, 403)]
    [InlineData("read", "operations", true, 403)]
    [InlineData("write", "operations", false, 403)]
    public async Task Custom_policy_requires_all_application_and_custom_checks(string role, string department, bool group, int status)
    {
        await using var host = new TestHost();
        await host.StartAsync();
        var token = host.Token(role, p => { p["department"] = department; if (!group) p.Remove("groups"); });
        using var response = await host.SendAsync(token, "/orders/approve", HttpMethod.Post);
        Assert.Equal(status, (int)response.StatusCode);
    }

    [Theory]
    [InlineData("read", "owned", 200)]
    [InlineData("read", "shared", 200)]
    [InlineData("read", "private", 403)]
    [InlineData("admin", "private", 403)]
    public async Task Resource_rules_do_not_grant_admin_bypass(string role, string document, int status)
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token(role), "/documents/" + document);
        Assert.Equal(status, (int)response.StatusCode);
    }

    [Fact]
    public async Task Spoofed_headers_and_shared_key_do_not_authenticate()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        host.Client.DefaultRequestHeaders.Add("x-user-id", "alice");
        host.Client.DefaultRequestHeaders.Add("x-user-roles", "admin");
        host.Client.DefaultRequestHeaders.Add("x-user-groups", TestHost.Group);
        host.Client.DefaultRequestHeaders.Add("x-api-key", "shared-api-key");
        using var response = await host.SendAsync(null);
        using var health = await host.SendAsync(null, "/health");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }

    [Fact]
    public async Task Role_removal_affects_new_tokens_while_old_token_remains_valid()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        var oldToken = host.Token();
        var freshToken = host.Token(change: p => p.Remove("resource_access"));
        using var fresh = await host.SendAsync(freshToken);
        using var old = await host.SendAsync(oldToken);
        Assert.Equal(HttpStatusCode.Forbidden, fresh.StatusCode);
        Assert.Equal(HttpStatusCode.OK, old.StatusCode);
    }

    [Fact]
    public async Task Projection_preserves_assigned_roles_and_optional_identity_data()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token("admin"));
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("001234567", json.GetProperty("nationalIdNumber").GetString());
        Assert.Equal("alice", json.GetProperty("userId").GetString());
        Assert.Equal(TestHost.Issuer, json.GetProperty("issuer").GetString());
        Assert.Equal("Alice Example", json.GetProperty("name").GetString());
        Assert.Equal("alice@example.test", json.GetProperty("email").GetString());
        Assert.Equal("admin", Assert.Single(json.GetProperty("roles").EnumerateArray()).GetString());
        Assert.Equal(TestHost.Group, Assert.Single(json.GetProperty("groups").EnumerateArray()).GetString());
        Assert.Equal("operations", Assert.Single(json.GetProperty("departments").EnumerateArray()).GetString());
        Assert.Equal(TimeSpan.Zero, json.GetProperty("issuedAtUtc").GetDateTimeOffset().Offset);
    }
}
