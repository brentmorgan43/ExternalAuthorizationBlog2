using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using ExternalAuthorization.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ExternalAuthorization.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> SignInManager;
        public AccountController(SignInManager<ApplicationUser> signInManager)
        {
            SignInManager = signInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult FacebookLogin()
        {
            // Request a redirect to the external login provider.
            var redirectUrl = "./Account/FacebookLoginCallback";
            var properties = new AuthenticationProperties();
            properties.RedirectUri = redirectUrl;
            properties.Items.Add("LoginProvider", "Facebook");
            var cr = new ChallengeResult("Facebook", properties);
            return cr;
        }

        public IActionResult FacebookLoginCallback()
        {
            return View("Register");
        }

        public async Task<JsonResult> RetrieveExternalAuthClaims()
        {
            var info = await SignInManager.GetExternalLoginInfoAsync();

            Dictionary<string, string> claims = new Dictionary<string, string>();
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
            {
                claims.Add("Email", info.Principal.FindFirstValue(ClaimTypes.Email));
            }
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.GivenName))
            {
                claims.Add("FirstName", info.Principal.FindFirstValue(ClaimTypes.GivenName));
            }
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Surname))
            {
                claims.Add("LastName", info.Principal.FindFirstValue(ClaimTypes.Surname));
            }

            return Json(claims);
        }
    }
}