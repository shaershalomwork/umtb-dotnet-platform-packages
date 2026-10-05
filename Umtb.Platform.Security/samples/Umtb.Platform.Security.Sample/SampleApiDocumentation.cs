using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;
using Scalar.AspNetCore;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Umtb.Platform.Security.Sample;

public static class SampleApiDocumentation
{
    private const string LoginScheme = "Keycloak";

    public static void AddServices(WebApplicationBuilder builder)
    {
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();
        builder.Services.AddOptions<SwaggerGenOptions>().Configure<IOptions<UmtbSecurityOptions>>((options, security) =>
        {
            var issuer = security.Value.Authority;
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Umtb.Platform.Security Sample",
                Version = "v1",
                Description = builder.Environment.IsDevelopment() ? """
                    1. With local Keycloak running, select **Authentication > Keycloak > Authorize**.
                    2. On the Keycloak login page, enter a username below and password `fixture-password` (local test accounts only).
                    3. Once back in Scalar, send these requests and compare the responses:

                    | User | `GET /me` (Read) | `POST /write-example` (Write) | `POST /admin-example` (Admin) |
                    | --- | --- | --- | --- |
                    | `reader` | 200 | 403 | 403 |
                    | `writer` | 200 | 204 | 403 |
                    | `alice` | 200 | 204 | 204 |

                    **Login flow:** Keycloak returns an authorization code; Scalar exchanges it for an access token using PKCE
                    and sends it in the `Authorization: Bearer` header. The API validates the signature, lifetime, issuer and audience,
                    then checks an allowed group and an `orders-api` client role. Write includes Read; Admin includes both.

                    **200/204:** Success. **401:** Missing or invalid token. **403:** Insufficient permission.
                    Each authorization requests a fresh Keycloak login so you can test a different user.
                    """ : """
                    Select **Authentication > Keycloak > Authorize** and sign in with an account from this environment's realm.
                    Scalar uses authorization code with PKCE S256 and sends the access token as `Authorization: Bearer`.
                    The API validates the token and requires an allowed group plus the API client's roles.

                    Try `GET /me`, `POST /write-example`, and `POST /admin-example` to check Read, Write, and Admin access.
                    Write includes Read; Admin includes both. **200/204:** Success. **401:** Missing or invalid token.
                    **403:** Insufficient permission. Each authorization requests a fresh Keycloak login.
                    """
            });
            options.AddSecurityDefinition(LoginScheme, new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.OAuth2,
                Flows = new OpenApiOAuthFlows
                {
                    AuthorizationCode = new OpenApiOAuthFlow
                    {
                        AuthorizationUrl = new Uri(issuer + "/protocol/openid-connect/auth"),
                        TokenUrl = new Uri(issuer + "/protocol/openid-connect/token"),
                        Scopes = new Dictionary<string, string>
                        {
                            ["openid"] = "OpenID Connect", ["profile"] = "User profile", ["email"] = "Email"
                        }
                    }
                }
            });
            options.OperationFilter<SecurityOperationFilter>();
        });
    }

    public static void MapEndpoints(WebApplication app)
    {
        app.MapSwagger("/openapi/{documentName}.json").AllowAnonymous();
        app.MapScalarApiReference("/", (options, context) => options
            .WithTitle("Umtb Platform Security")
            .DisableDefaultFonts()
            .DisableAgent()
            .AddPreferredSecuritySchemes([LoginScheme])
            .AddAuthorizationCodeFlow(LoginScheme, flow =>
            {
                flow.ClientId = app.Configuration["Scalar:ClientId"] ?? "orders-web";
                flow.Pkce = Pkce.Sha256;
                flow.AddQueryParameter("prompt", "login");
                flow.SelectedScopes = ["openid", "profile", "email"];
                flow.RedirectUri = app.Configuration["Scalar:RedirectUri"]
                    ?? $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/";
            })).AllowAnonymous();
    }

    private sealed class SecurityOperationFilter : IOperationFilter
    {
        public void Apply(OpenApiOperation operation, OperationFilterContext context)
        {
            if (context.ApiDescription.ActionDescriptor.EndpointMetadata.OfType<IAllowAnonymous>().Any()) return;

            // These are OIDC scopes; application permissions still come from Keycloak client roles.
            operation.Security =
            [
                new OpenApiSecurityRequirement
                {
                    [new OpenApiSecuritySchemeReference(LoginScheme, context.Document)] = ["openid", "profile", "email"]
                }
            ];
            operation.Responses ??= [];
            operation.Responses.TryAdd("401", new OpenApiResponse { Description = "Missing or invalid access token" });
            operation.Responses.TryAdd("403", new OpenApiResponse { Description = "Insufficient application or resource permission" });
        }
    }
}
