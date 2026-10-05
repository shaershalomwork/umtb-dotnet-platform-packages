namespace Umtb.Platform.Security;

/// <summary>Settings for one Keycloak realm and API resource client. Validated at startup.</summary>
public sealed class UmtbSecurityOptions
{
    /// <summary>Exact issuer URL, for example https://identity.example.com/realms/platform.</summary>
    public string Authority { get; set; } = "";
    /// <summary>Resource client whose client roles grant application permissions.</summary>
    public string ClientId { get; set; } = "";
    /// <summary>Exact audience required in the access token's aud claim.</summary>
    public string Audience { get; set; } = "";
    /// <summary>Allowed full group paths, compared using ordinal, case-sensitive equality.</summary>
    public string[] AllowedGroups { get; set; } = [];
    /// <summary>Client role names keyed by Read, Write, and Admin. Values must be distinct.</summary>
    public Dictionary<string, string> RoleNames { get; set; } = new(StringComparer.Ordinal)
    {
        ["Read"] = "read", ["Write"] = "write", ["Admin"] = "admin"
    };
    /// <summary>Token claim holding an array of full group paths.</summary>
    public string GroupsClaimType { get; set; } = "groups";
    /// <summary>Optional string claim containing the managed national ID, preserving leading zeros.</summary>
    public string NationalIdClaimType { get; set; } = "national_id";
    /// <summary>Allowed asymmetric JOSE algorithms. Defaults to RS256.</summary>
    public string[] AllowedAlgorithms { get; set; } = ["RS256"];
    /// <summary>Lifetime validation tolerance. Defaults to 30 seconds; maximum five minutes.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
    /// <summary>Allows HTTP discovery only when the host environment is Development.</summary>
    public bool AllowHttpDiscoveryInDevelopment { get; set; }
}
