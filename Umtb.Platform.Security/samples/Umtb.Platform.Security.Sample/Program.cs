using Umtb.Platform.Security;
using Umtb.Platform.Security.Sample;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddUmtbSecurity(builder.Configuration.GetSection("Security"));
DemoApplication.AddServices(builder.Services);
SampleApiDocumentation.AddServices(builder);

var app = builder.Build();
app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
DemoApplication.MapEndpoints(app);
SampleApiDocumentation.MapEndpoints(app);
await app.ValidateUmtbSecurityEndpointsAsync();
await app.RunAsync();
