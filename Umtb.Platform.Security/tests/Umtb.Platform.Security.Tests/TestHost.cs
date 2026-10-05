using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Umtb.Platform.Security.Sample;

namespace Umtb.Platform.Security.Tests;

internal sealed class TestHost : IAsyncDisposable
{
    internal const string Issuer = "https://identity.test/realms/platform";
    internal const string Group = "/applications/orders/users";
    internal WebApplication App { get; }
    internal HttpClient Client { get; private set; } = null!;
    internal DiscoveryHandler Discovery { get; } = new();
    internal TestClock Clock { get; } = new();
    internal CapturedLogs Logs { get; } = new();

    internal TestHost(Action<IServiceCollection>? configure = null, Action<WebApplication>? map = null,
        Dictionary<string, string?>? settings = null, string environment = "Production", bool documentation = false)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(Logs);
        var values = new Dictionary<string, string?>
        {
            ["Security:Authority"] = Issuer, ["Security:ClientId"] = "orders-api", ["Security:Audience"] = "orders-api",
            ["Security:AllowedGroups:0"] = Group
        };
        if (settings is not null) foreach (var pair in settings) values[pair.Key] = pair.Value;
        builder.Configuration.AddInMemoryCollection(values);
        builder.Services.AddUmtbSecurity(builder.Configuration.GetSection("Security"));
        builder.Services.AddSingleton<TimeProvider>(Clock);
        builder.Services.Configure<JwtBearerOptions>("UmtbBearer", o => o.BackchannelHttpHandler = Discovery);
        DemoApplication.AddServices(builder.Services);
        if (documentation) SampleApiDocumentation.AddServices(builder);
        configure?.Invoke(builder.Services);
        App = builder.Build();
        App.UseRouting();
        App.UseAuthentication();
        App.UseAuthorization();
        if (map is null) DemoApplication.MapEndpoints(App); else map(App);
        if (documentation) SampleApiDocumentation.MapEndpoints(App);
    }

    internal async Task StartAsync(bool audit = true)
    {
        if (audit) await App.ValidateUmtbSecurityEndpointsAsync();
        await App.StartAsync();
        Client = App.GetTestClient();
    }

    internal async Task<HttpResponseMessage> SendAsync(string? token, string path = "/me", HttpMethod? method = null)
    {
        using var request = new HttpRequestMessage(method ?? HttpMethod.Get, path);
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await Client.SendAsync(request);
    }

    internal string Token(string role = "read", Action<Dictionary<string, object?>>? change = null,
        RSA? key = null, string algorithm = "RS256", string? payloadSuffix = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = Issuer, ["aud"] = "orders-api", ["sub"] = "alice", ["iat"] = now - 10,
            ["exp"] = now + 300, ["typ"] = "Bearer", ["groups"] = new[] { Group },
            ["resource_access"] = new Dictionary<string, object> { ["orders-api"] = new { roles = new[] { role } } },
            ["name"] = "Alice Example", ["email"] = "alice@example.test", ["national_id"] = "001234567",
            ["department"] = "operations"
        };
        change?.Invoke(payload);
        var json = JsonSerializer.Serialize(payload);
        if (payloadSuffix is not null) json = json[..^1] + "," + payloadSuffix + "}";
        var header = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = algorithm, typ = "JWT", kid = Discovery.KeyId }));
        var content = header + "." + Base64UrlEncoder.Encode(json);
        var signature = algorithm == "none" ? "" : Base64UrlEncoder.Encode((key ?? Discovery.Key).SignData(
            Encoding.ASCII.GetBytes(content), algorithm == "RS512" ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));
        return content + "." + signature;
    }

    public async ValueTask DisposeAsync()
    {
        Client?.Dispose();
        await App.DisposeAsync();
        Discovery.Key.Dispose();
    }
}

internal sealed class TestClock : TimeProvider
{
    internal DateTimeOffset? FixedTime { get; set; }
    public override DateTimeOffset GetUtcNow() => FixedTime ?? DateTimeOffset.UtcNow;
}

internal sealed class DiscoveryHandler : HttpMessageHandler
{
    internal RSA Key { get; set; } = RSA.Create(2048);
    internal string KeyId { get; set; } = "key-1";
    internal bool Fail { get; set; }
    internal int Requests { get; private set; }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests++;
        if (Fail) throw new HttpRequestException("Controlled discovery failure.");
        string json;
        if (request.RequestUri!.AbsolutePath.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
            json = JsonSerializer.Serialize(new { issuer = TestHost.Issuer, jwks_uri = TestHost.Issuer + "/certs" });
        else if (request.RequestUri.AbsolutePath.EndsWith("/certs", StringComparison.Ordinal))
        {
            var parameters = Key.ExportParameters(false);
            json = JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", use = "sig", kid = KeyId,
                n = Base64UrlEncoder.Encode(parameters.Modulus), e = Base64UrlEncoder.Encode(parameters.Exponent) } } });
        }
        else throw new InvalidOperationException("Unexpected discovery URL.");
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") });
    }
}

internal sealed class CapturedLogs : ILoggerProvider
{
    internal readonly System.Collections.Concurrent.ConcurrentQueue<(string Category, int EventId, string Message)> Entries = new();
    public ILogger CreateLogger(string categoryName) => new Capture(categoryName, Entries);
    public void Dispose() { }
    private sealed class Capture(string category, System.Collections.Concurrent.ConcurrentQueue<(string, int, string)> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => entries.Enqueue((category, eventId.Id, formatter(state, exception) + (exception is null ? "" : " [" + exception.GetType().Name + "]")));
    }
}
