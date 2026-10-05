using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Umtb.Platform.Security.Internal;

internal sealed class OptionsValidation(IHostEnvironment environment, string sectionPath)
    : IValidateOptions<UmtbSecurityOptions>
{
    internal static readonly string[] AsymmetricAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

    public ValidateOptionsResult Validate(string? name, UmtbSecurityOptions options)
    {
        var errors = new List<string>();
        void Error(string key, string repair) => errors.Add($"{sectionPath}:{key} {repair}");
        if (!Uri.TryCreate(options.Authority, UriKind.Absolute, out var uri) ||
            (uri.Scheme != "https" && uri.Scheme != "http") ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) || options.Authority != options.Authority.Trim() ||
            options.Authority.EndsWith('/'))
            Error("Authority", "must be an absolute realm issuer URL without credentials, query, fragment, whitespace, or a trailing slash.");
        else if (uri.Scheme != "https" && !(options.AllowHttpDiscoveryInDevelopment && environment.IsDevelopment()))
            Error("Authority", "must use HTTPS. HTTP requires AllowHttpDiscoveryInDevelopment=true and the Development environment.");
        if (options.AllowHttpDiscoveryInDevelopment && !environment.IsDevelopment())
            Error("AllowHttpDiscoveryInDevelopment", "must be false outside Development.");
        foreach (var entry in new[] { ("ClientId", options.ClientId), ("Audience", options.Audience),
                     ("GroupsClaimType", options.GroupsClaimType), ("NationalIdClaimType", options.NationalIdClaimType) })
            if (!Clean(entry.Item2)) Error(entry.Item1, "must be a nonempty value without surrounding whitespace.");
        if (options.AllowedGroups is not { Length: > 0 } || options.AllowedGroups.Any(g =>
                !Clean(g) || !g.StartsWith('/') || g.Length < 2 || g.EndsWith('/') || g.Contains("//")) ||
            options.AllowedGroups.Distinct(StringComparer.Ordinal).Count() != options.AllowedGroups.Length)
            Error("AllowedGroups", "must contain distinct full Keycloak group paths. Configure an application group such as /applications/orders/users.");
        if (options.RoleNames is null || options.RoleNames.Count != 3 ||
            new[] { "Read", "Write", "Admin" }.Any(k => !options.RoleNames.TryGetValue(k, out var v) || !Clean(v)) ||
            options.RoleNames.Values.Distinct(StringComparer.Ordinal).Count() != 3)
            Error("RoleNames", "must map Read, Write, and Admin to three distinct, nonempty client role names.");
        if (options.AllowedAlgorithms is not { Length: > 0 } ||
            options.AllowedAlgorithms.Any(a => !AsymmetricAlgorithms.Contains(a, StringComparer.Ordinal)) ||
            options.AllowedAlgorithms.Distinct(StringComparer.Ordinal).Count() != options.AllowedAlgorithms.Length)
            Error("AllowedAlgorithms", "must contain distinct asymmetric JOSE algorithms, for example RS256. Symmetric and unsigned tokens are forbidden.");
        if (options.ClockSkew < TimeSpan.Zero || options.ClockSkew > TimeSpan.FromMinutes(5))
            Error("ClockSkew", "must be between zero and five minutes. Use 00:00:30 unless a smaller tolerance is required.");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    private static bool Clean(string? value) => !string.IsNullOrWhiteSpace(value) && value == value.Trim();
}
