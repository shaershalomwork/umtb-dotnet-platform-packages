using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Runtime.CompilerServices;

namespace Umtb.Platform.Security.Internal;

internal sealed class BearerConfiguration(IOptions<UmtbSecurityOptions> security, SecurityEvents events)
    : IConfigureNamedOptions<JwtBearerOptions>, IPostConfigureOptions<JwtBearerOptions>, IValidateOptions<JwtBearerOptions>
{
    private readonly JsonWebTokenHandler handler = new() { MapInboundClaims = false };
    private readonly ConditionalWeakTable<JwtBearerOptions, ConfigurationManager<OpenIdConnectConfiguration>> managers = new();
    private string ExactIssuer(string issuer, SecurityToken token, TokenValidationParameters parameters) =>
        issuer == security.Value.Authority ? issuer : throw new SecurityTokenInvalidIssuerException("Invalid issuer.");

    public void Configure(JwtBearerOptions options) => Configure(Options.DefaultName, options);
    public void Configure(string? name, JwtBearerOptions options)
    {
        if (name != SecurityRegistration.Scheme) return;
        var settings = security.Value;
        options.Authority = settings.Authority;
        options.Audience = settings.Audience;
        options.RequireHttpsMetadata = !settings.AllowHttpDiscoveryInDevelopment;
        options.MapInboundClaims = false;
        options.SaveToken = false;
        options.IncludeErrorDetails = false;
        options.RefreshOnIssuerKeyNotFound = true;
        options.Events = events;
        options.TokenHandlers.Clear();
        options.TokenHandlers.Add(handler);
        options.TokenValidationParameters = new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidIssuer = settings.Authority,
            IssuerValidator = ExactIssuer,
            ValidateAudience = true,
            RequireAudience = true,
            ValidAudience = settings.Audience,
            IgnoreTrailingSlashWhenValidatingAudience = false,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = settings.ClockSkew,
            ValidAlgorithms = settings.AllowedAlgorithms.ToArray(),
            AuthenticationType = SecurityRegistration.Scheme,
            NameClaimType = "name",
            RoleClaimType = "__umtb_unused_role",
            LogTokenId = false,
            IncludeTokenOnFailedValidation = false
        };
    }

    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        if (name != SecurityRegistration.Scheme) return;
        // Retain standard IdentityModel discovery, caching and key refresh, but own the retriever
        // so a later configuration cannot replace discovery with untrusted static signing keys.
        var settings = security.Value;
        var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
            settings.Authority + "/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(options.Backchannel ?? throw new OptionsValidationException(name,
                typeof(JwtBearerOptions), ["Retain the framework's discovery backchannel configuration."]))
            { RequireHttps = !settings.AllowHttpDiscoveryInDevelopment })
        {
            RefreshInterval = options.RefreshInterval,
            AutomaticRefreshInterval = options.AutomaticRefreshInterval
        };
        options.ConfigurationManager = manager;
        managers.Add(options, manager);
    }

    public ValidateOptionsResult Validate(string? name, JwtBearerOptions options)
    {
        if (name != SecurityRegistration.Scheme) return ValidateOptionsResult.Skip;
        var settings = security.Value;
        var p = options.TokenValidationParameters;
        // Validate the final options after all consumer Configure/PostConfigure registrations.
        var safe = options.Authority == settings.Authority && options.Audience == settings.Audience &&
            managers.TryGetValue(options, out var manager) && ReferenceEquals(options.ConfigurationManager, manager) &&
            manager.MetadataAddress == settings.Authority + "/.well-known/openid-configuration" &&
            manager.ConfigurationEventHandler is null &&
            options.MetadataAddress == settings.Authority + "/.well-known/openid-configuration" &&
            options.RequireHttpsMetadata == !settings.AllowHttpDiscoveryInDevelopment &&
            !options.MapInboundClaims && !handler.MapInboundClaims && !options.SaveToken && !options.IncludeErrorDetails &&
            options.RefreshOnIssuerKeyNotFound && !options.UseSecurityTokenValidators &&
            options.TokenHandlers.Count == 1 && ReferenceEquals(options.TokenHandlers[0], handler) &&
            ReferenceEquals(options.Events, events) && options.EventsType is null &&
            options.ForwardDefault is null && options.ForwardAuthenticate is null && options.ForwardChallenge is null &&
            options.ForwardForbid is null && options.ForwardDefaultSelector is null && options.Configuration is null &&
            p.GetType() == typeof(TokenValidationParameters) &&
            p.RequireSignedTokens && p.ValidateIssuerSigningKey && p.ValidateIssuer && p.ValidateAudience &&
            p.RequireAudience && p.ValidateLifetime && p.RequireExpirationTime &&
            p.ValidIssuer == settings.Authority && p.ValidAudience == settings.Audience &&
            p.ValidIssuers is null && p.ValidAudiences is null && !p.IgnoreTrailingSlashWhenValidatingAudience &&
            p.ClockSkew == settings.ClockSkew && p.ValidAlgorithms is not null &&
            p.ValidAlgorithms.SequenceEqual(settings.AllowedAlgorithms, StringComparer.Ordinal) &&
            p.IssuerValidator == (IssuerValidator)ExactIssuer && p.IssuerValidatorUsingConfiguration is null &&
            p.SignatureValidator is null && p.SignatureValidatorUsingConfiguration is null &&
            p.AlgorithmValidator is null && p.AudienceValidator is null && p.LifetimeValidator is null &&
            p.IssuerSigningKeyValidator is null && p.IssuerSigningKeyValidatorUsingConfiguration is null &&
            p.IssuerSigningKeyResolver is null && p.IssuerSigningKeyResolverUsingConfiguration is null &&
            p.IssuerSigningKey is null && p.IssuerSigningKeys is null &&
            p.TokenReader is null && p.TransformBeforeSignatureValidation is null && p.ConfigurationManager is null &&
            !p.IncludeTokenOnFailedValidation && !p.LogTokenId;
        return safe ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(
            "UmtbBearer authentication invariants were changed. Configure Security options; do not replace package token validators, events, forwarding, issuers, audiences, or validation parameters.");
    }
}
