using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
    .AddScheme<CookieAuthenticationOptions, VistorAuthHandler>(
    "vistor", o =>  { })
    .AddCookie("local")
    .AddCookie("patreon-cookie")
    .AddOAuth("external-patreon", o =>
    {
        o.SignInScheme = "patreon-cookie";

        o.ClientId = "id";
        o.ClientSecret = "secret";

        o.AuthorizationEndpoint = "https://oauth.mocklab.io/oauth/authorize";
        o.TokenEndpoint = "https://oauth.mocklab.io/oauth/authorize";
        o.UserInformationEndpoint = "https://oauth.mocklab.io/userinfo";
        
        o.CallbackPath = "/cb-patreon";
        o.Scope.Add("profile");
        o.SaveTokens = true;
    });


builder.Services.AddAuthorization( x=>
{
    x.AddPolicy("customer", p =>
    {
        p.AddAuthenticationSchemes("patreon-cookie", "local", "vistor")
            .RequireAuthenticatedUser();
    });

    x.AddPolicy("user", p =>
    {
        p.AddAuthenticationSchemes("local")
        .RequireAuthenticatedUser();
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();


app.MapGet("/", ctx => Task.FromResult("HEllo World"))
    .RequireAuthorization("customer");

app.MapGet("/login-local", async ctx =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "zhangsan"));
    var identity = new ClaimsIdentity(claims, "local");
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync("local",user);

});

app.MapGet("/login-patreon", 
    async ctx => await ctx.ChallengeAsync("external-patreon",
        new AuthenticationProperties()
        {
            RedirectUri = "/"
        }))
    .RequireAuthorization("user");

app.Run();

public class VistorAuthHandler : CookieAuthenticationHandler
{
    public VistorAuthHandler(
        IOptionsMonitor<CookieAuthenticationOptions> options, 
        ILoggerFactory logger, 
        UrlEncoder encoder, 
        ISystemClock clock
        ) : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();

        if (result.Succeeded)
            return result;

        var claims = new List<Claim>();
        claims.Add(new Claim("usr", "zhangsan"));
        var identity = new ClaimsIdentity(claims, "vistor");
        var user = new ClaimsPrincipal(identity);

        await Context.SignInAsync("vistor", user);

        return AuthenticateResult.Success(new AuthenticationTicket(user, "vistor"));
    }
}