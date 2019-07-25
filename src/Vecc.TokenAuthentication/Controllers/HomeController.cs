using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Vecc.TokenAuthentication.Models;
using Vecc.TokenAuthentication.Services;

namespace Vecc.TokenAuthentication.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;

        public HomeController(UserManager<IdentityUser> userManager)
        {
            this._userManager = userManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Authorize]
        public async Task<IActionResult> ListLogins()
        {
            var user = await _userManager.GetUserAsync(this.User);
            var result = await _userManager.GetLoginsAsync(user);

            return Ok(result);
        }

        [Authorize]
        public async Task<IActionResult> AddToken(string token)
        {
            var user = await _userManager.GetUserAsync(this.User);
            if (string.IsNullOrWhiteSpace(token))
            {
                token = Guid.NewGuid().ToString();
            }

            var result = await _userManager.AddLoginAsync(user, new UserLoginInfo(CustomTokenValidator.LoginProvider, token, "Test Token-" + DateTime.UtcNow));
            if (result.Succeeded)
            {
                return Ok($"Authorization: Bearer {CustomTokenValidator.TokenPrefix}{token}");
            }

            return this.StatusCode(500, result);
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<IActionResult> TestToken()
        {
            var user = await _userManager.GetUserAsync(this.User);

            return Ok(user);
        }
    }
}
