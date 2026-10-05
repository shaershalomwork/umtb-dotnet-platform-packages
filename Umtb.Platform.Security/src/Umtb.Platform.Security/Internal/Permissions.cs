using Microsoft.AspNetCore.Authorization;

namespace Umtb.Platform.Security.Internal;

internal sealed record ApplicationAccessRequirement : IAuthorizationRequirement;
internal sealed record PermissionRequirement(UmtbPermission Permission) : IAuthorizationRequirement;
internal sealed record DenyRequirement : IAuthorizationRequirement;

internal sealed class ApplicationAccessHandler : AuthorizationHandler<ApplicationAccessRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApplicationAccessRequirement requirement)
    {
        if (ClaimProjection.FromPrincipal(context.User) is { Groups.Count: > 0, Roles.Count: > 0 }) context.Succeed(requirement);
        return Task.CompletedTask;
    }
}

internal sealed class PermissionHandler : AuthorizationHandler<PermissionRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        if (ClaimProjection.FromPrincipal(context.User)?.Permission >= requirement.Permission) context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
