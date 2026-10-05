using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Umtb.Platform.Security.Sample;

public static class DemoApplication
{
    public static void AddServices(IServiceCollection services)
    {
        services.AddControllers().AddApplicationPart(typeof(OrdersController).Assembly);
        services.AddAuthorization(options =>
        {
            options.AddPolicy("ApproveOrder", policy => policy.RequireUmtbPermission(UmtbPermission.Write)
                .RequireClaim("department", "operations"));
            // Resource policies run inside an endpoint that already checked application access.
            options.AddPolicy("ReadDocument", policy => policy.AddRequirements(new ReadDocumentRequirement()));
        });
        services.AddScoped<IAuthorizationHandler, ReadDocumentHandler>();
    }

    public static void MapEndpoints(WebApplication app)
    {
        var minimalApis = app.MapGroup("").WithTags("Minimal API examples");
        minimalApis.MapGet("/me", (ICurrentUser user) => Results.Ok(new
        {
            user.IsAuthenticated, user.UserId, user.Issuer, user.Name, user.Email,
            user.NationalIdNumber, user.Roles, user.Groups, user.IssuedAtUtc,
            user.ExpiresAtUtc, user.RemainingLifetime,
            Departments = user.GetClaimValues("department")
        })).WithSummary("Get the current user")
            .WithDescription("Returns the authenticated user's identity, roles, groups, department claims and token lifetime through ICurrentUser. Requires Read permission; Write and Admin also grant access.")
            .RequireAuthorization(UmtbSecurityPolicies.Read);
        minimalApis.MapPost("/write-example", () => Results.NoContent()).Produces(StatusCodes.Status204NoContent)
            .WithSummary("Check Write permission")
            .WithDescription("Demonstrates a Minimal API protected by the Write policy. Returns 204 for users with Write or Admin permission. No data is modified.")
            .RequireAuthorization(UmtbSecurityPolicies.Write);
        minimalApis.MapPost("/admin-example", () => Results.NoContent()).Produces(StatusCodes.Status204NoContent)
            .WithSummary("Check Admin permission")
            .WithDescription("Demonstrates a Minimal API protected by the Admin policy. Returns 204 for users with Admin permission. Read or Write alone is insufficient. No data is modified.")
            .RequireAuthorization(UmtbSecurityPolicies.Admin);
        minimalApis.MapPost("/orders/approve", () => Results.NoContent()).Produces(StatusCodes.Status204NoContent)
            .WithSummary("Check the order approval policy")
            .WithDescription("Demonstrates the custom ApproveOrder policy: requires Write permission (also granted by Admin) and a department claim equal to operations. Returns 204 when both conditions are met. No order is modified.")
            .RequireAuthorization("ApproveOrder");
        minimalApis.MapGet("/health", () => Results.Ok(new { status = "ok" }))
            .WithSummary("Check application health")
            .WithDescription("Returns a static status of ok. Demonstrates anonymous access with AllowAnonymous; no token or application permission is required. This endpoint does not check external dependencies.")
            .AllowAnonymous();
        var reports = minimalApis.MapGroup("/reports").RequireAuthorization(UmtbSecurityPolicies.Read);
        reports.MapGet("/daily", () => Results.Ok(new { total = 42 }))
            .WithSummary("Get the sample daily report")
            .WithDescription("Returns a static report with total 42. Demonstrates inheriting the Read policy from a route group. Users with Read, Write or Admin permission can access it.");
        minimalApis.MapGet("/documents/{id}", async (string id, HttpContext http, ICurrentUser user, IAuthorizationService authorization) =>
        {
            // Replace this store with application-owned, tenant-filtered data loading.
            var document = id switch
            {
                "owned" => new Document(id, user.Issuer!, "alice", []),
                "shared" => new Document(id, user.Issuer!, "owner", ["alice"]),
                "private" => new Document(id, user.Issuer!, "owner", []),
                _ => null
            };
            if (document is null) return Results.NotFound();
            var result = await authorization.AuthorizeAsync(http.User, document, "ReadDocument");
            return result.Succeeded ? Results.Ok(new { document.Id }) : Results.Forbid();
        }).WithSummary("Read a document with resource authorization")
            .WithDescription("Requires Read permission, then checks the ReadDocument resource policy: the user's issuer must match the document's issuer and the user must own the document or appear in SharedWith. Try owned, shared or private; owned and shared use alice as the sample user. Returns 200 with the document ID, 403 when resource access is denied, or 404 for an unknown ID.")
            .RequireAuthorization(UmtbSecurityPolicies.Read);
        app.MapControllers();
    }
}

public sealed record Document(string Id, string Issuer, string OwnerId, string[] SharedWith);
public sealed class ReadDocumentRequirement : IAuthorizationRequirement;
public sealed class ReadDocumentHandler(ICurrentUser user) : AuthorizationHandler<ReadDocumentRequirement, Document>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ReadDocumentRequirement requirement, Document resource)
    {
        if (user.IsAuthenticated && user.Issuer == resource.Issuer &&
            (user.UserId == resource.OwnerId || resource.SharedWith.Contains(user.UserId, StringComparer.Ordinal)))
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}

[ApiController]
[Route("controller/orders")]
[Tags("Controller examples")]
[Authorize(Policy = UmtbSecurityPolicies.Read)]
public sealed class OrdersController : ControllerBase
{
    [HttpGet]
    [EndpointSummary("Check Read permission on a controller")]
    [EndpointDescription("Returns a sample response with source set to controller. Demonstrates inheriting the controller's Authorize attribute with the Read policy. Users with Read, Write or Admin permission can access it.")]
    public IActionResult Get() => Ok(new { source = "controller" });

    [HttpPost]
    [EndpointSummary("Check Write permission on a controller action")]
    [EndpointDescription("Demonstrates combining the controller's Read policy with the action's Write policy through Authorize attributes. Returns 204 for users with Write or Admin permission. No order is created or modified.")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [Authorize(Policy = UmtbSecurityPolicies.Write)]
    public IActionResult Post() => NoContent();
}
