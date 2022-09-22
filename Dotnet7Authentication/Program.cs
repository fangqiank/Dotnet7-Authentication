using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

const string AuthSchema = "cookie";
const string AuthSchema2 = "cookie2";

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
//builder.Services.AddRazorPages();

builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
//builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddAuthentication(AuthSchema)
    .AddCookie(AuthSchema)
    .AddCookie(AuthSchema2);

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("prc passport", pb =>
    {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(AuthSchema)
            .AddRequirements()
            .RequireClaim("passport_type", "prc");

    });
});

var app = builder.Build();

//app.Use((ctx, next) =>
//{
//    var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();

//    var protector = idp.CreateProtector("auth-cookie");

//    var authCookie = ctx.Request.Headers.Cookie
//        .FirstOrDefault(x => x.StartsWith("auth="));

//    var protectorPayload = authCookie.Split('=').Last();
//    var payload = protector.Unprotect(protectorPayload);
//    var parts = payload.Split(":");
//    var key = parts[0];
//    var value = parts[1];

//    var claims = new List<Claim>();
//    claims.Add(new Claim(key, value));
//    var identity = new ClaimsIdentity(claims);
//    ctx.User = new ClaimsPrincipal(identity);


//    return next();
//});

// Configure the HTTP request pipeline.
//if (!app.Environment.IsDevelopment())
//{
//    app.UseExceptionHandler("/Error");
//    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
//    app.UseHsts();
//}

//app.UseHttpsRedirection();
//app.UseStaticFiles();

//app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

//app.MapRazorPages();

//app.Use((ctx, next) =>
//{
//    if (ctx.Request.Path.StartsWithSegments("/login"))
//    {
//        return next();
//    }

//    if(!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema))
//    {
//        ctx.Response.StatusCode = 401;
//        return Task.CompletedTask;
//    }

//    if (!ctx.User.HasClaim("passport_type", "prc"))
//    {
//        ctx.Response.StatusCode = 403;
//        return Task.CompletedTask;
//    }

//    return next();
//});

//[Authorize(Policy = "prc passport")]
app.MapGet("/unsecure", (HttpContext ctx) =>
{

    return ctx.User.FindFirst("usr")?.Value ?? "Empty";

    //return payload;
}).RequireAuthorization("prc passport");

app.MapGet("/passport", (HttpContext ctx) =>
{
    //if(!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema))
    //{
    //    ctx.Response.StatusCode = 401;
    //    return "";
    //}

    //if(!ctx.User.HasClaim("passport_type", "prc"))
    //{
    //    ctx.Response.StatusCode = 403;
    //    return "";
    //}

    return "allowed";
    
});

app.MapGet("/visa", (HttpContext ctx) =>
{
    //if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema2))
    //{
    //    ctx.Response.StatusCode = 401;
    //    return "";
    //}

    //if (!ctx.User.HasClaim("passport_type", "prc"))
    //{
    //    ctx.Response.StatusCode = 403;
    //    return "";
    //}

    return "allowed";

});

app.MapGet("/login", async (HttpContext ctx /*IAuthService auth*/) =>
{
    //var protector = idp.CreateProtector("auth-cookie");
    //ctx.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr:zhangsan")}";
    //auth.Signin();

    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "zhangsan"));
    claims.Add(new Claim("passport_type", "prc"));
    var identity = new ClaimsIdentity(claims, AuthSchema);
    var user = new ClaimsPrincipal(identity);
    await ctx.SignInAsync("cookie", user);


    return "ok";
}).AllowAnonymous();

app.Run();
