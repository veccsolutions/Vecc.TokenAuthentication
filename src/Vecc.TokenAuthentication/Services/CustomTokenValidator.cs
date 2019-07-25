using System;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Vecc.TokenAuthentication.Services
{
    public class CustomTokenValidator : ISecurityTokenValidator
    {
        public const string TokenPrefix = "Vecc-";
        public const string LoginProvider = nameof(CustomTokenValidator);

        private readonly byte[] _signingSecurityKey = Encoding.UTF8.GetBytes("SecurityKey1234567890");
        private readonly HttpContextAccessor _httpContextAccessor = new HttpContextAccessor();

        public bool CanValidateToken => true;

        public int MaximumTokenSizeInBytes { get; set; }

        public bool CanReadToken(string securityToken) => securityToken?.StartsWith(TokenPrefix) ?? false;

        public ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            if (!CanReadToken(securityToken))
            {
                validatedToken = null;
                return null;
            }

            ClaimsPrincipal result = null;
            SecurityToken token = null;

            // Unfortunately we don't have any easy access to the service provider so we are relying on the context accessor.
            var serviceProvider = _httpContextAccessor.HttpContext.RequestServices;
            var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var principalFactory = serviceProvider.GetRequiredService<IUserClaimsPrincipalFactory<IdentityUser>>();

            Task.WaitAll(Task.Run(async () =>
            {
                var applicationUser = await userManager.FindByLoginAsync(LoginProvider, securityToken.Substring(TokenPrefix.Length));

                if (applicationUser == null)
                {
                    // In Core 2.2 you need to throw an exception to signal that validation failed, core 1.x was return null.
                    throw new SecurityTokenException("Token not recognized");
                }

                result = await principalFactory.CreateAsync(applicationUser);
                token = new CustomSecurityToken(applicationUser.Id, LoginProvider,
                                                new SymmetricSecurityKey(this._signingSecurityKey),
                                                new SymmetricSecurityKey(this._signingSecurityKey),
                                                DateTime.MinValue,
                                                DateTime.MaxValue);
            }));

            validatedToken = token;
            return result;
        }
    }
}
