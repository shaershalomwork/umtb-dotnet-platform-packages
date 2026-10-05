using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Umtb.Platform.Security.Tests;

public sealed class AuthenticationTests
{
    public static IEnumerable<object[]> InvalidClaims()
    {
        yield return ["iss", "https://other.test/realms/platform"];
        yield return ["aud", "wrong-api"];
        yield return ["aud", "orders-api/"];
        yield return ["aud", new[] { "other-api", "unrelated-api" }];
        yield return ["aud", new object[] { "orders-api", 42 }];
        yield return ["exp", null!];
        yield return ["exp", DateTimeOffset.UtcNow.AddMinutes(-2).ToUnixTimeSeconds()];
        yield return ["nbf", DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds()];
        yield return ["sub", null!];
        yield return ["sub", " "];
        yield return ["sub", new[] { "alice", "bob" }];
        yield return ["sub", 42];
        yield return ["iat", null!];
        yield return ["iat", "invalid"];
        yield return ["iat", "1234567"];
        yield return ["iat", 1.5];
        yield return ["iat", long.MaxValue];
        yield return ["iat", DateTimeOffset.UtcNow.AddMinutes(6).ToUnixTimeSeconds()];
        yield return ["exp", "1234567"];
        yield return ["exp", long.MaxValue];
        yield return ["nbf", "1234567"];
        yield return ["typ", "ID"];
        yield return ["typ", "Refresh"];
        yield return ["typ", null!];
    }

    [Theory]
    [MemberData(nameof(InvalidClaims))]
    public async Task Invalid_tokens_receive_generic_bearer_challenge(string claim, object? value)
    {
        await using var host = new TestHost();
        await host.StartAsync();
        var token = host.Token(change: p => { if (value is null) p.Remove(claim); else p[claim] = value; });
        using var response = await host.SendAsync(token);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer", Assert.Single(response.Headers.WwwAuthenticate).ToString());
        Assert.DoesNotContain(token, await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("none")]
    [InlineData("RS512")]
    public async Task Unsigned_or_disallowed_algorithm_is_rejected(string algorithm)
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token(algorithm: algorithm));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Bad_signature_is_rejected()
    {
        await using var host = new TestHost();
        using var otherKey = RSA.Create(2048);
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token(key: otherKey));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("\"sub\":\"alice\"")]
    [InlineData("\"iat\":123")]
    [InlineData("\"exp\":123")]
    [InlineData("\"typ\":\"Bearer\"")]
    [InlineData("\"iss\":\"https://identity.test/realms/platform\"")]
    [InlineData("\"aud\":\"orders-api\"")]
    public async Task Ambiguous_security_claims_are_rejected(string duplicate)
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token(payloadSuffix: duplicate));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Audience_array_containing_expected_audience_is_accepted()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token(change: p => p["aud"] = new[] { "account", "orders-api" }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Discovery_failure_without_cached_keys_fails_closed()
    {
        await using var host = new TestHost();
        host.Discovery.Fail = true;
        await host.StartAsync();
        using var response = await host.SendAsync(host.Token());
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Cached_keys_work_during_discovery_outage_and_unknown_keys_fail()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        var token = host.Token();
        using var first = await host.SendAsync(token);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        host.Discovery.Fail = true;
        using var cached = await host.SendAsync(token);
        Assert.Equal(HttpStatusCode.OK, cached.StatusCode);
        using var otherKey = RSA.Create(2048);
        host.Discovery.KeyId = "unknown";
        using var unknown = await host.SendAsync(host.Token(key: otherKey));
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
    }

    [Fact]
    public async Task Key_rotation_refreshes_JWKS_and_accepts_new_signing_key()
    {
        await using var host = new TestHost();
        await host.StartAsync();
        using var first = await host.SendAsync(host.Token());
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using var oldKey = host.Discovery.Key;
        host.Discovery.Key = RSA.Create(2048);
        host.Discovery.KeyId = "rotated";
        // Sign first so lazy RSA key creation does not race the background JWKS reader.
        var token = host.Token();
        // Let JwtBearer/IdentityModel request refresh after seeing an unknown kid.
        HttpStatusCode status = default;
        for (var attempt = 0; attempt < 30; attempt++)
        {
            using var response = await host.SendAsync(token);
            status = response.StatusCode;
            if (status == HttpStatusCode.OK) break;
            await Task.Delay(100);
        }
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.True(host.Discovery.Requests >= 4);
    }
}
