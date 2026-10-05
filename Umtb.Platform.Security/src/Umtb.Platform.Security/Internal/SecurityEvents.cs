using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Umtb.Platform.Security.Internal;

internal sealed class SecurityEvents(IOptions<UmtbSecurityOptions> options, TimeProvider timeProvider,
    ILogger<SecurityEvents> logger) : JwtBearerEvents
{
    // Never invoke a consumer-assigned OnMessageReceived delegate to obtain tokens from headers,
    // cookies or query strings. JwtBearer's standard Authorization: Bearer extraction follows.
    public override Task MessageReceived(MessageReceivedContext context) => Task.CompletedTask;

    public override Task TokenValidated(TokenValidatedContext context)
    {
        if (context.SecurityToken is not JsonWebToken token || context.Principal?.Identity is not ClaimsIdentity identity ||
            !ClaimProjection.TryCreate(token, context.Principal, options.Value, timeProvider.GetUtcNow(), out var projection))
        {
            context.Fail("Invalid access token.");
            Log(context.HttpContext, 1001, "invalid_access_token_claims");
        }
        else context.Principal = new ClaimsPrincipal(new ValidatedIdentity(identity, projection!));
        return Task.CompletedTask;
    }

    public override Task AuthenticationFailed(AuthenticationFailedContext context)
    {
        Log(context.HttpContext, 1001, "token_validation_failed");
        return Task.CompletedTask;
    }

    public override Task Challenge(JwtBearerChallengeContext context)
    {
        Log(context.HttpContext, 1002, "bearer_challenge");
        return Task.CompletedTask;
    }

    public override Task Forbidden(ForbiddenContext context)
    {
        Log(context.HttpContext, 1003, "authorization_denied");
        return Task.CompletedTask;
    }

    private void Log(HttpContext context, int id, string category) => logger.LogInformation(new EventId(id, category),
        "Security {FailureCategory}; route {RouteTemplate}; trace {TraceId}", category,
        (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? "(unrouted)", context.TraceIdentifier);
}
