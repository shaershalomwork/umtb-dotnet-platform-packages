using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Umtb.Platform.Security.Tests;

public sealed class StartupTests
{
    [Theory]
    [InlineData("missing")]
    [InlineData("bare")]
    [InlineData("roles")]
    [InlineData("unknown")]
    [InlineData("unsafe")]
    [InlineData("inline")]
    [InlineData("cookies")]
    public async Task Unsafe_endpoints_fail_with_route_and_repair(string kind)
    {
        await using var host = new TestHost(services => services.AddAuthorization(o =>
            o.AddPolicy("Unsafe", p => p.RequireAuthenticatedUser())), app =>
        {
            var route = app.MapGet("/unsafe", () => "never");
            switch (kind)
            {
                case "bare": route.RequireAuthorization(); break;
                case "roles": route.RequireAuthorization(new AuthorizeAttribute { Roles = "admin" }); break;
                case "unknown": route.RequireAuthorization("Unknown"); break;
                case "unsafe": route.RequireAuthorization("Unsafe"); break;
                case "inline": route.RequireAuthorization(p => p.RequireClaim("department")); break;
                case "cookies": route.RequireAuthorization(p => p.RequireUmtbPermission(UmtbPermission.Read).AddAuthenticationSchemes("Cookies")); break;
            }
        });
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => host.App.ValidateUmtbSecurityEndpointsAsync());
        Assert.Contains("/unsafe", error.Message);
        Assert.Contains("RequireUmtbPermission", error.Message);
    }

    [Fact]
    public async Task Safe_inline_policy_and_anonymous_override_pass_audit()
    {
        await using var host = new TestHost(map: app =>
        {
            app.MapGet("/safe", () => "ok").RequireAuthorization(p => p.RequireUmtbPermission(UmtbPermission.Write));
            app.MapGroup("/public").RequireAuthorization(UmtbSecurityPolicies.Admin)
                .MapGet("/health", () => "ok").AllowAnonymous();
        });
        await host.StartAsync();
        using var response = await host.SendAsync(null, "/public/health");
        Assert.True(response.IsSuccessStatusCode);
        Assert.Contains(host.Logs.Entries, e => e.EventId == 1101 && e.Message.Contains("/public/health", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Omitted_audit_fails_startup()
    {
        await using var host = new TestHost();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(audit: false));
        Assert.Contains("ValidateUmtbSecurityEndpointsAsync", error.Message);
    }

    [Fact]
    public async Task Unsafe_route_added_after_audit_fails_startup()
    {
        await using var host = new TestHost();
        await host.App.ValidateUmtbSecurityEndpointsAsync();
        host.App.MapGet("/late", () => "unsafe");
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(audit: false));
        Assert.Contains("/late", error.Message);
    }

    [Theory]
    [InlineData("Authority", "http://identity.test/realms/platform")]
    [InlineData("Authority", "not-a-url")]
    [InlineData("Authority", "https://identity.test/realms/platform/")]
    [InlineData("Authority", "https://user:password@identity.test/realms/platform")]
    [InlineData("ClientId", " ")]
    [InlineData("Audience", "")]
    [InlineData("AllowedGroups:0", "orders")]
    [InlineData("AllowedGroups:0", "/orders/")]
    [InlineData("RoleNames:Write", "read")]
    [InlineData("RoleNames:Admin", " ")]
    [InlineData("GroupsClaimType", "")]
    [InlineData("NationalIdClaimType", " ")]
    [InlineData("AllowedAlgorithms:0", "HS256")]
    [InlineData("AllowedAlgorithms:0", "none")]
    [InlineData("ClockSkew", "00:06:00")]
    [InlineData("AllowHttpDiscoveryInDevelopment", "true")]
    public async Task Invalid_configuration_identifies_key(string key, string value)
    {
        await using var host = new TestHost(settings: new() { ["Security:" + key] = value });
        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => host.App.ValidateUmtbSecurityEndpointsAsync());
        Assert.Contains("Security:" + key.Split(':')[0], error.Message);
    }

    [Fact]
    public async Task Empty_allowlist_fails_final_bound_options_validation()
    {
        await using var host = new TestHost(s => s.PostConfigure<UmtbSecurityOptions>(o => o.AllowedGroups = []));
        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => host.App.ValidateUmtbSecurityEndpointsAsync());
        Assert.Contains("Security:AllowedGroups", error.Message);
    }

    [Fact]
    public async Task Explicit_development_HTTP_setting_is_accepted_only_in_development()
    {
        await using var host = new TestHost(settings: new()
        {
            ["Security:Authority"] = "http://localhost:18080/realms/platform",
            ["Security:AllowHttpDiscoveryInDevelopment"] = "true"
        }, environment: "Development");
        await host.StartAsync();
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("lifetime")]
    [InlineData("expiration")]
    [InlineData("signed")]
    [InlineData("algorithms")]
    [InlineData("events")]
    [InlineData("signature_delegate")]
    [InlineData("issuer_delegate")]
    [InlineData("lifetime_delegate")]
    [InlineData("mapping")]
    [InlineData("forwarding")]
    [InlineData("metadata")]
    [InlineData("configuration_manager")]
    public async Task Later_unsafe_bearer_configuration_is_rejected(string change)
    {
        await using var host = new TestHost(s => s.PostConfigure<JwtBearerOptions>("UmtbBearer", o =>
        {
            switch (change)
            {
                case "signature": o.TokenValidationParameters.ValidateIssuerSigningKey = false; break;
                case "issuer": o.TokenValidationParameters.ValidateIssuer = false; break;
                case "audience": o.TokenValidationParameters.ValidateAudience = false; break;
                case "lifetime": o.TokenValidationParameters.ValidateLifetime = false; break;
                case "expiration": o.TokenValidationParameters.RequireExpirationTime = false; break;
                case "signed": o.TokenValidationParameters.RequireSignedTokens = false; break;
                case "algorithms": o.TokenValidationParameters.ValidAlgorithms = ["HS256"]; break;
                case "events": o.Events = new JwtBearerEvents(); break;
                case "signature_delegate": o.TokenValidationParameters.SignatureValidator = (_, _) => null!; break;
                case "issuer_delegate": o.TokenValidationParameters.IssuerValidator = (i, _, _) => i; break;
                case "lifetime_delegate": o.TokenValidationParameters.LifetimeValidator = (_, _, _, _) => true; break;
                case "mapping": o.MapInboundClaims = true; break;
                case "forwarding": o.ForwardDefault = "Cookies"; break;
                case "metadata": o.MetadataAddress = "https://wrong.test/discovery"; break;
                case "configuration_manager": o.ConfigurationManager = new Microsoft.IdentityModel.Protocols.StaticConfigurationManager<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>(new()); break;
            }
        }));
        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => host.App.ValidateUmtbSecurityEndpointsAsync());
        Assert.Contains("invariants", error.Message);
    }

    [Fact]
    public async Task Default_and_fallback_policy_overrides_are_rejected()
    {
        await using var host = new TestHost(s => s.AddAuthorization(o => o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => host.App.ValidateUmtbSecurityEndpointsAsync());
        Assert.Contains("fallback", error.Message);
    }

    [Fact]
    public async Task Cookie_default_cannot_replace_package_bearer()
    {
        await using var host = new TestHost(s => s.Configure<AuthenticationOptions>(o => o.DefaultAuthenticateScheme = "Cookies"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => host.App.ValidateUmtbSecurityEndpointsAsync());
    }
}
