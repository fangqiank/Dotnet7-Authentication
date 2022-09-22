using Microsoft.AspNetCore.Authorization;

namespace Dotnet7Authentication.Services
{
    public class MyRequirement: IAuthorizationRequirement
    {

    }

    public class MyRequirementHandler : AuthorizationHandler<MyRequirement>
    {
        public MyRequirementHandler()
        {

        }
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MyRequirement requirement)
        {
            //context.User
            //context.Succeed(new MyRequirement )

            return Task.CompletedTask;
        }
    }
}
