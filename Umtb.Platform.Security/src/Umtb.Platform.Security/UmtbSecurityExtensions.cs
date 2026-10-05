using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Umtb.Platform.Security.Internal;

namespace Umtb.Platform.Security;

/// <summary>Registers and audits the application's UMTB security integration.</summary>
public static class UmtbSecurityExtensions
{
    /// <summary>Registers one realm/client bearer scheme, permission policies, and scoped current user.</summary>
    /// <param name="services">Application service collection.</param>
    /// <param name="configuration">Configuration section containing UmtbSecurityOptions.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddUmtbSecurity(this IServiceCollection services, IConfigurationSection configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        if (services.Any(d => d.ServiceType == typeof(SecurityRegistration)))
            throw new InvalidOperationException("AddUmtbSecurity supports one registration per host.");
        services.AddSingleton<SecurityRegistration>();
        services.AddOptions<UmtbSecurityOptions>().Configure(o => configuration.Bind(o)).ValidateOnStart();
        services.AddSingleton<IValidateOptions<UmtbSecurityOptions>>(sp =>
            new OptionsValidation(sp.GetRequiredService<IHostEnvironment>(), configuration.Path));
        services.TryAddSingleton(TimeProvider.System);
        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUser, CurrentUser>();
        services.AddSingleton<SecurityEvents>();
        services.AddSingleton<BearerConfiguration>();
        services.AddSingleton<IConfigureOptions<JwtBearerOptions>>(sp => sp.GetRequiredService<BearerConfiguration>());
        services.AddSingleton<IValidateOptions<JwtBearerOptions>>(sp => sp.GetRequiredService<BearerConfiguration>());
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = SecurityRegistration.Scheme;
            options.DefaultChallengeScheme = SecurityRegistration.Scheme;
            options.DefaultForbidScheme = SecurityRegistration.Scheme;
        }).AddJwtBearer(SecurityRegistration.Scheme, _ => { });
        services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>>(sp => sp.GetRequiredService<BearerConfiguration>());
        services.AddOptions<JwtBearerOptions>(SecurityRegistration.Scheme).ValidateOnStart();
        services.AddAuthorization(options =>
        {
            var deny = new AuthorizationPolicyBuilder(SecurityRegistration.Scheme).AddRequirements(new DenyRequirement()).Build();
            options.DefaultPolicy = deny;
            options.FallbackPolicy = deny;
            options.AddPolicy(UmtbSecurityPolicies.Read, p => p.RequireUmtbPermission(UmtbPermission.Read));
            options.AddPolicy(UmtbSecurityPolicies.Write, p => p.RequireUmtbPermission(UmtbPermission.Write));
            options.AddPolicy(UmtbSecurityPolicies.Admin, p => p.RequireUmtbPermission(UmtbPermission.Admin));
        });
        services.AddSingleton<IAuthorizationHandler, ApplicationAccessHandler>();
        services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
        services.AddSingleton<EndpointAudit>();
        services.AddHostedService<StartupGuard>();
        return services;
    }

    /// <summary>Adds the package bearer scheme, authenticated identity, application access, and permission requirements.</summary>
    /// <param name="policy">Policy builder to extend with package requirements.</param>
    /// <param name="permission">Minimum permission; higher assigned permissions satisfy it.</param>
    /// <returns>The policy builder for further application requirements.</returns>
    public static AuthorizationPolicyBuilder RequireUmtbPermission(this AuthorizationPolicyBuilder policy, UmtbPermission permission)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (!Enum.IsDefined(permission)) throw new ArgumentOutOfRangeException(nameof(permission));
        policy.AddAuthenticationSchemes(SecurityRegistration.Scheme);
        policy.RequireAuthenticatedUser();
        policy.AddRequirements(new ApplicationAccessRequirement(), new PermissionRequirement(permission));
        return policy;
    }

    /// <summary>Audits all mapped routes. Call after mapping endpoints and before RunAsync; fails on unsafe effective policies.</summary>
    /// <param name="app">Fully mapped application.</param>
    /// <returns>A task completing when endpoint and configuration validation succeeds.</returns>
    public static Task ValidateUmtbSecurityEndpointsAsync(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.Services.GetRequiredService<EndpointAudit>().ValidateAsync(app);
    }
}
