using Microsoft.AspNetCore.DataProtection;
using System.Runtime.Intrinsics.Arm;

namespace Dotnet7Authentication.Services
{
    public class AuthService : IAuthService
    {
        private readonly IDataProtectionProvider _idp;
        private readonly IHttpContextAccessor _http;

        public AuthService(IDataProtectionProvider idp,
            IHttpContextAccessor http)
        {
            _idp = idp;
            _http = http;
        }

        public async Task Signin()
        {
            var protector = _idp.CreateProtector("auth-cookie");
            _http.HttpContext.Response.Headers["set-cookie"] = $"" +
                $"auth={protector.Protect("usr:zhangsan")}";
        }
    }
}
