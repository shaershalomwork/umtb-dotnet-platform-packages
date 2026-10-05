namespace Umtb.Platform.Security;

/// <summary>Application permissions ordered from least to most privileged.</summary>
public enum UmtbPermission
{
    /// <summary>Read application data, subject to application resource rules.</summary>
    Read = 1,
    /// <summary>Write application data; also satisfies read requirements.</summary>
    Write = 2,
    /// <summary>Administer the application; also satisfies write and read requirements.</summary>
    Admin = 3
}

/// <summary>Named policies that include bearer identity, application membership, and permission checks.</summary>
public static class UmtbSecurityPolicies
{
    /// <summary>Requires at least read permission.</summary>
    public const string Read = "Umtb.Read";
    /// <summary>Requires at least write permission.</summary>
    public const string Write = "Umtb.Write";
    /// <summary>Requires admin permission.</summary>
    public const string Admin = "Umtb.Admin";
}
