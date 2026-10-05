using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Umtb.Platform.Security;

internal static class QuickStart
{
    internal static async Task RunAsync(string[] args)
    {
        // README-START
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddUmtbSecurity(builder.Configuration.GetSection("Security"));
        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("ApproveOrder", policy =>
                policy.RequireUmtbPermission(UmtbPermission.Write)
                      .RequireClaim("department", "operations"));
        });

        var app = builder.Build();
        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/me", (ICurrentUser user) => Results.Ok(new
        {
            user.UserId, user.Name, user.Roles, user.Groups,
            user.ExpiresAtUtc, user.RemainingLifetime
        })).RequireAuthorization(UmtbSecurityPolicies.Read);
        app.MapPost("/write-example", () => Results.NoContent())
           .RequireAuthorization(UmtbSecurityPolicies.Write);
        app.MapPost("/admin-example", () => Results.NoContent())
           .RequireAuthorization(UmtbSecurityPolicies.Admin);
        app.MapPost("/orders/approve", () => Results.NoContent())
           .RequireAuthorization("ApproveOrder");
        app.MapGet("/health", () => Results.Ok()).AllowAnonymous();

        await app.ValidateUmtbSecurityEndpointsAsync();
        await app.RunAsync();
        // README-END
    }
}
