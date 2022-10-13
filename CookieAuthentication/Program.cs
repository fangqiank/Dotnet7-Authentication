using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container

builder.Services.AddAuthentication()
    .AddCookie("default", o =>
    {
        o.Cookie.Name = "mycookie";
        //o.Cookie.Domain = "";
        //o.Cookie.Path = "/test";
        //o.Cookie.HttpOnly = false;
        //o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        //o.Cookie.SameSite = SameSiteMode.Lax;

        o.ExpireTimeSpan = TimeSpan.FromSeconds(10);
        o.SlidingExpiration = true;
    });

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("mypolicy", pb =>
        pb.RequireAuthenticatedUser()
          .RequireClaim("doesnotexist", "nonesense"));
});

builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseStaticFiles();

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello World");

app.MapPost("/login", async (HttpContext ctx) =>
{
    await ctx.SignInAsync("default", new ClaimsPrincipal(
        new ClaimsIdentity(
            new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            },
            "default"
            )
        ), new AuthenticationProperties()
        {
            IsPersistent = true,
        });

    return "ok";
});

app.MapGet("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync("default", new AuthenticationProperties
    {
        IsPersistent = true,
    });

    return "ok";
});

app.MapGet("/test", () => "Hello World").RequireAuthorization("mypolicy");

app.MapGet("test22", async (HttpContext ctx) =>
{
    await ctx.ChallengeAsync("default", new AuthenticationProperties()
    {
        RedirectUri = "/anything-that-we-want"
    });
}); 

app.MapDefaultControllerRoute();

app.Run();
