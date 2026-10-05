namespace Umtb.Platform.Security;

/// <summary>Scoped view of the validated package bearer identity. Empty outside an authenticated request.</summary>
public interface ICurrentUser
{
    /// <summary>Whether the current principal contains a validated package bearer identity.</summary>
    bool IsAuthenticated { get; }
    /// <summary>Stable subject identifier. Combine with Issuer across realms.</summary>
    string? UserId { get; }
    /// <summary>Exact issuer of the validated access token.</summary>
    string? Issuer { get; }
    /// <summary>Name, falling back to preferred_username; null if absent.</summary>
    string? Name { get; }
    /// <summary>Optional email address; never a stable user key.</summary>
    string? Email { get; }
    /// <summary>Optional national ID string, including any leading zeros.</summary>
    string? NationalIdNumber { get; }
    /// <summary>Assigned recognized roles as read, write, or admin; excludes implied lower permissions.</summary>
    IReadOnlyList<string> Roles { get; }
    /// <summary>Exact token group paths also present in the application allowlist.</summary>
    IReadOnlyList<string> Groups { get; }
    /// <summary>Validated iat timestamp, in UTC.</summary>
    DateTimeOffset? IssuedAtUtc { get; }
    /// <summary>Validated exp timestamp, in UTC.</summary>
    DateTimeOffset? ExpiresAtUtc { get; }
    /// <summary>Time until exp, clamped to zero, excluding validation clock skew. Does not refresh tokens.</summary>
    TimeSpan? RemainingLifetime { get; }
    /// <summary>Returns read-only additional validated claim values, or an empty collection if absent.</summary>
    IReadOnlyList<string> GetClaimValues(string claimType);
}
