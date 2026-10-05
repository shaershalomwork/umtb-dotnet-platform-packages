using System.Collections.ObjectModel;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Umtb.Platform.Security.Internal;

internal sealed record ClaimProjection(
    string UserId, string Issuer, string? Name, string? Email, string? NationalIdNumber,
    IReadOnlyList<string> Roles, IReadOnlyList<string> Groups, UmtbPermission? Permission,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Claims)
{
    internal static ClaimProjection? FromPrincipal(ClaimsPrincipal? principal)
    {
        var identities = principal?.Identities.OfType<ValidatedIdentity>().Take(2).ToArray();
        return identities is { Length: 1 } ? identities[0].Projection : null;
    }

    // This method is called only by OnTokenValidated, after the real bearer handler succeeds.
    internal static bool TryCreate(JsonWebToken token, ClaimsPrincipal principal, UmtbSecurityOptions options,
        DateTimeOffset now, out ClaimProjection? projection)
    {
        projection = null;
        try
        {
            using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || token.IsEncrypted ||
                !UniqueString(root, "sub", out var sub) || string.IsNullOrWhiteSpace(sub) ||
                !UniqueString(root, "iss", out var issuer) || issuer != options.Authority ||
                !UniqueString(root, "typ", out var type) || type != "Bearer" ||
                !Timestamp(root, "iat", out var issued) || !Timestamp(root, "exp", out var expires) ||
                issued >= expires || issued > now + options.ClockSkew ||
                !ValidAudience(root, options.Audience) ||
                (root.TryGetProperty("nbf", out _) && (!Timestamp(root, "nbf", out var notBefore) || notBefore > expires)))
                return false;

            var roles = ReadRoles(root, options);
            var groups = ReadGroups(root, options);
            var permission = roles.Contains("admin") ? UmtbPermission.Admin :
                roles.Contains("write") ? UmtbPermission.Write : roles.Contains("read") ? UmtbPermission.Read : (UmtbPermission?)null;
            var claims = principal.Claims.GroupBy(c => c.Type, StringComparer.Ordinal).ToDictionary(
                g => g.Key, g => (IReadOnlyList<string>)Array.AsReadOnly(g.Select(c => c.Value).ToArray()), StringComparer.Ordinal);
            projection = new(sub!, issuer!, OptionalString(root, "name") ?? OptionalString(root, "preferred_username"),
                OptionalString(root, "email"), OptionalString(root, options.NationalIdClaimType), roles, groups, permission,
                issued, expires, new ReadOnlyDictionary<string, IReadOnlyList<string>>(claims));
            return true;
        }
        catch (Exception error) when (error is JsonException or FormatException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static IReadOnlyList<string> ReadRoles(JsonElement root, UmtbSecurityOptions options)
    {
        if (!Unique(root, "resource_access", out var access) || access.ValueKind != JsonValueKind.Object ||
            !Unique(access, options.ClientId, out var client) || client.ValueKind != JsonValueKind.Object ||
            !Unique(client, "roles", out var roles) || !StringArray(roles, out var assigned)) return Array.Empty<string>();
        return Array.AsReadOnly(new[] { "Read", "Write", "Admin" }
            .Where(key => assigned.Contains(options.RoleNames[key], StringComparer.Ordinal)).Select(key => key.ToLowerInvariant()).ToArray());
    }

    private static IReadOnlyList<string> ReadGroups(JsonElement root, UmtbSecurityOptions options)
    {
        if (!Unique(root, options.GroupsClaimType, out var groups) || !StringArray(groups, out var assigned)) return Array.Empty<string>();
        return Array.AsReadOnly(assigned.Where(g => options.AllowedGroups.Contains(g, StringComparer.Ordinal)).Distinct(StringComparer.Ordinal).ToArray());
    }

    private static bool StringArray(JsonElement element, out string[] values)
    {
        values = [];
        if (element.ValueKind != JsonValueKind.Array || element.EnumerateArray().Any(e => e.ValueKind != JsonValueKind.String)) return false;
        values = element.EnumerateArray().Select(e => e.GetString()!).ToArray();
        return true;
    }

    private static bool ValidAudience(JsonElement root, string expected)
    {
        if (!Unique(root, "aud", out var audience)) return false;
        return audience.ValueKind == JsonValueKind.String ? audience.GetString() == expected :
            StringArray(audience, out var values) && values.Contains(expected, StringComparer.Ordinal);
    }

    private static bool Unique(JsonElement root, string name, out JsonElement value)
    {
        value = default;
        var found = false;
        foreach (var property in root.EnumerateObject())
        {
            if (property.Name != name) continue;
            if (found) return false;
            value = property.Value;
            found = true;
        }
        return found;
    }

    private static bool UniqueString(JsonElement root, string name, out string? value)
    {
        value = null;
        if (!Unique(root, name, out var element) || element.ValueKind != JsonValueKind.String) return false;
        value = element.GetString();
        return true;
    }

    private static string? OptionalString(JsonElement root, string name) => UniqueString(root, name, out var value) ? value : null;

    private static bool Timestamp(JsonElement root, string name, out DateTimeOffset value)
    {
        value = default;
        if (!Unique(root, name, out var element) || element.ValueKind != JsonValueKind.Number || !element.TryGetInt64(out var seconds)) return false;
        try { value = DateTimeOffset.FromUnixTimeSeconds(seconds); return true; }
        catch (ArgumentOutOfRangeException) { return false; }
    }
}

internal sealed class ValidatedIdentity(ClaimsIdentity identity, ClaimProjection projection)
    : ClaimsIdentity(identity.Claims, SecurityRegistration.Scheme, "name", "__umtb_unused_role")
{
    internal ClaimProjection Projection { get; } = projection;
    public override ClaimsIdentity Clone() => new ValidatedIdentity(this, Projection);
}
