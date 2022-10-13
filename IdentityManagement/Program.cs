using IdentityManagement.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddDefaultTokenProviders();

builder.Services.AddDataProtection();

//builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

builder.Services.AddScoped<Database>();
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("Manager",po =>
    {
        po.RequireAuthenticatedUser()
        .AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme)
        .RequireClaim("role", "Manager");
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello world");

app.MapGet("/protected", () => "something super secret!")
    .RequireAuthorization("Manager");

//app.MapGet("/test", (
//    UserManager<IdentityUser> userMgr,
//    SignInManager<IdentityUser> signMgr
//    ) =>
//{
//    //userMgr.ResetPasswordAsync();
//});

app.MapGet("/register", async (
    string username, 
    string password, 
    IPasswordHasher<User> hasher,
    Database db, 
    HttpContext ctx
    ) =>
{
    var user = new User()
    {
        Username = username,
    };
    user.PasswordHash = hasher.HashPassword(user, password);

    await db.PutAsync(user);

    await ctx.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        UserHelper.Convert(user)
        );

    return user;
});

app.MapGet("/login", async (
    string username,
    string password,
    IPasswordHasher<User> hasher,
    Database db,
    HttpContext ctx
    ) =>
{
    var user = await db.GetUserAsync(username);
    
    var result =hasher.VerifyHashedPassword(user, user.PasswordHash, password);

    if (result == PasswordVerificationResult.Failed)
        return "Bad Credentals";

    await ctx.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        UserHelper.Convert(user)
        );

    return "Logged In";
});

app.MapGet("/promote", async (
    string username,
    Database db
    ) =>
{
    var user = await db.GetUserAsync(username);
    user.Claims.Add(
        new UserClaim() 
        { 
            Type = "role", 
            Value = "Manager" 
        });
    await db.PutAsync(user);

    return "Promoted";
});

app.MapGet("/start-reset-password", async (
    string username,
    Database db, 
    IDataProtectionProvider provider
    ) =>
{
    var protector = provider.CreateProtector("PasswordReset");
    var user = await db.GetUserAsync(username);

    return protector.Protect(user.Username);
});

app.MapGet("/end-reset-password", async (
    string username,
    string password,
    string hash,
    Database db,
    IPasswordHasher<User> hasher,
    IDataProtectionProvider provider
    ) =>
{
    var protector = provider.CreateProtector("PasswordReset");
    var hashUsername = protector.Unprotect(hash);
    if (hashUsername != username)
        return "Bad hash";

    var user = await db.GetUserAsync(username);
    user.PasswordHash = hasher.HashPassword(user, password);
    await db.PutAsync(user);

    return "password reset";
});

app.Run();

//internal record WeatherForecast(DateTime Date, int TemperatureC, string? Summary)
//{
//    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
//}

public class UserHelper
{
    public static ClaimsPrincipal Convert(User user)
    {
        var claims = new List<Claim>()
        {
            new Claim("username", user.Username)
        };

        claims.AddRange(user.Claims.Select(x => new Claim(x.Type, x.Value)));   

        var identity = new ClaimsIdentity(
            claims, 
            CookieAuthenticationDefaults.AuthenticationScheme
            );

        return new ClaimsPrincipal(identity);
    }
}