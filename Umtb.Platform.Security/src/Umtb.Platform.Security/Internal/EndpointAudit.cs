using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Umtb.Platform.Security.Internal;

internal sealed class SecurityRegistration
{
    internal const string Scheme = "UmtbBearer";
}

internal sealed class EndpointAudit(IAuthorizationPolicyProvider provider, IOptionsMonitor<JwtBearerOptions> bearer,
    IOptions<AuthenticationOptions> authentication, IAuthenticationSchemeProvider schemes, ILogger<EndpointAudit> logger)
{
    private WebApplication? application;

    internal async Task ValidateAsync(WebApplication app)
    {
        // Force final bound and post-configured authentication options before inspecting routes.
        _ = bearer.Get(SecurityRegistration.Scheme);
        var defaults = authentication.Value;
        if (defaults.DefaultAuthenticateScheme != SecurityRegistration.Scheme ||
            defaults.DefaultChallengeScheme != SecurityRegistration.Scheme || defaults.DefaultForbidScheme != SecurityRegistration.Scheme ||
            (await schemes.GetSchemeAsync(SecurityRegistration.Scheme))?.HandlerType != typeof(JwtBearerHandler))
            throw new InvalidOperationException("Keep UmtbBearer as the default authenticate, challenge, and forbid scheme and retain its JwtBearerHandler.");
        var fallback = await provider.GetFallbackPolicyAsync();
        var defaultPolicy = await provider.GetDefaultPolicyAsync();
        if (!Denies(fallback) || !Denies(defaultPolicy))
            throw new InvalidOperationException("Keep the UMTB deny default and fallback policies. Use a named policy with RequireUmtbPermission for protected endpoints.");

        var routes = (IEndpointRouteBuilder)app;
        var endpoints = routes.DataSources.SelectMany(source => source.Endpoints).ToArray();
        var errors = new List<string>();
        foreach (var endpoint in endpoints.OfType<RouteEndpoint>())
        {
            var route = endpoint.RoutePattern.RawText ?? "(unnamed route)";
            if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
            {
                logger.LogInformation(new EventId(1101, "anonymous_endpoint"), "Explicit anonymous endpoint: {RouteTemplate}", route);
                continue;
            }
            var data = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>();
            var inline = endpoint.Metadata.GetOrderedMetadata<AuthorizationPolicy>();
            AuthorizationPolicy? effective;
            try
            {
                effective = await AuthorizationPolicy.CombineAsync(provider, data, inline);
                var requirements = endpoint.Metadata.GetOrderedMetadata<IAuthorizationRequirementData>()
                    .SelectMany(d => d.GetRequirements()).ToArray();
                if (requirements.Length > 0)
                {
                    var builder = effective is null ? new AuthorizationPolicyBuilder() : new AuthorizationPolicyBuilder(effective);
                    effective = builder.AddRequirements(requirements).Build();
                }
            }
            catch (InvalidOperationException)
            {
                errors.Add($"Route '{route}' references an unknown or invalid policy. Register the named policy using RequireUmtbPermission.");
                continue;
            }
            var explicitPolicy = inline.Count > 0 || data.Any(d => !string.IsNullOrWhiteSpace(d.Policy));
            if (!explicitPolicy || effective is null ||
                !effective.AuthenticationSchemes.Distinct(StringComparer.Ordinal).SequenceEqual([SecurityRegistration.Scheme]) ||
                effective.Requirements.OfType<DenyRequirement>().Any() ||
                !effective.Requirements.OfType<DenyAnonymousAuthorizationRequirement>().Any() ||
                !effective.Requirements.OfType<ApplicationAccessRequirement>().Any() ||
                !effective.Requirements.OfType<PermissionRequirement>().Any())
                errors.Add($"Route '{route}' needs a named or inline policy containing RequireUmtbPermission (or UmtbSecurityPolicies.Read/Write/Admin), or explicit AllowAnonymous. Bare Authorize and role-only policies are insufficient.");
        }
        if (errors.Count > 0)
        {
            logger.LogError(new EventId(1102, "endpoint_audit_failed"), "Endpoint security audit failed for {EndpointCount} endpoints", errors.Count);
            throw new InvalidOperationException(string.Join(Environment.NewLine, errors));
        }
        application = app;
    }

    internal Task EnsureAuditedAsync()
    {
        if (application is null)
            throw new InvalidOperationException("Call await app.ValidateUmtbSecurityEndpointsAsync() after mapping all endpoints and before RunAsync().");
        // ASP.NET Core may rebuild route objects as the pipeline is finalized. Recheck effective
        // policies, rather than comparing object identity, before any hosted service starts.
        return ValidateAsync(application);
    }

    private static bool Denies(AuthorizationPolicy? policy) => policy is not null &&
        policy.Requirements.OfType<DenyRequirement>().Any() && policy.AuthenticationSchemes.SequenceEqual([SecurityRegistration.Scheme]);
}

internal sealed class StartupGuard(EndpointAudit audit) : IHostedLifecycleService
{
    public Task StartingAsync(CancellationToken cancellationToken) => audit.EnsureAuditedAsync();
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
