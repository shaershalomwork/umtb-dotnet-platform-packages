using Microsoft.AspNetCore.Http;

namespace Umtb.Platform.Security.Internal;

internal sealed class CurrentUser(IHttpContextAccessor accessor, TimeProvider timeProvider) : ICurrentUser
{
    private ClaimProjection? User => ClaimProjection.FromPrincipal(accessor.HttpContext?.User);
    public bool IsAuthenticated => User is not null;
    public string? UserId => User?.UserId;
    public string? Issuer => User?.Issuer;
    public string? Name => User?.Name;
    public string? Email => User?.Email;
    public string? NationalIdNumber => User?.NationalIdNumber;
    public IReadOnlyList<string> Roles => User?.Roles ?? Array.Empty<string>();
    public IReadOnlyList<string> Groups => User?.Groups ?? Array.Empty<string>();
    public DateTimeOffset? IssuedAtUtc => User?.IssuedAtUtc;
    public DateTimeOffset? ExpiresAtUtc => User?.ExpiresAtUtc;
    public TimeSpan? RemainingLifetime => ExpiresAtUtc is { } expiration
        ? TimeSpan.FromTicks(Math.Max(0, (expiration - timeProvider.GetUtcNow()).Ticks)) : null;
    public IReadOnlyList<string> GetClaimValues(string claimType)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimType);
        return User?.Claims.TryGetValue(claimType, out var values) == true ? values : Array.Empty<string>();
    }
}
