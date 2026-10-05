using System.Reflection;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Umtb.Platform.Security.Tests;

public sealed class RuntimeTests
{
    [Fact]
    public void Runtime_and_JwtBearer_major_match_the_compiled_target()
    {
#if NET8_0
        const int expected = 8;
#elif NET9_0
        const int expected = 9;
#else
        const int expected = 10;
#endif
        Assert.Equal(expected, Environment.Version.Major);
        Assert.Equal(expected, typeof(JwtBearerHandler).Assembly.GetName().Version!.Major);
        Assert.Equal(new Version(8, 23, 0, 0), typeof(Microsoft.IdentityModel.Tokens.TokenValidationParameters).Assembly.GetName().Version);
    }
}
