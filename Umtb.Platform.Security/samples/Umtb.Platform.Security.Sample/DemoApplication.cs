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
        app.MapGet("/me", (ICurrentUser user) => Results.Ok(new
        {
            user.IsAuthenticated, user.UserId, user.Issuer, user.Name, user.Email,
            user.NationalIdNumber, user.Roles, user.Groups, user.IssuedAtUtc,
            user.ExpiresAtUtc, user.RemainingLifetime,
            Departments = user.GetClaimValues("department")
        })).RequireAuthorization(UmtbSecurityPolicies.Read);
        app.MapPost("/write-example", () => Results.NoContent()).Produces(StatusCodes.Status204NoContent)
            .RequireAuthorization(UmtbSecurityPolicies.Write);
        app.MapPost("/admin-example", () => Results.NoContent()).Produces(StatusCodes.Status204NoContent)
            .RequireAuthorization(UmtbSecurityPolicies.Admin);
        app.MapPost("/orders/approve", () => Results.NoContent()).Produces(StatusCodes.Status204NoContent)
            .RequireAuthorization("ApproveOrder");
        app.MapGet("/health", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
        var reports = app.MapGroup("/reports").RequireAuthorization(UmtbSecurityPolicies.Read);
        reports.MapGet("/daily", () => Results.Ok(new { total = 42 }));
        app.MapGet("/documents/{id}", async (string id, HttpContext http, ICurrentUser user, IAuthorizationService authorization) =>
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
        }).RequireAuthorization(UmtbSecurityPolicies.Read);
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
[Authorize(Policy = UmtbSecurityPolicies.Read)]
public sealed class OrdersController : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok(new { source = "controller" });

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [Authorize(Policy = UmtbSecurityPolicies.Write)]
    public IActionResult Post() => NoContent();
}
