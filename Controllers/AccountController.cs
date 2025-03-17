using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RoleAuthentification.Services;

namespace RoleAuthentification.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly TokenService _tokenService;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, TokenService tokenService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenService = tokenService;
        }

        [HttpGet]
        public IActionResult Login() => View();

        [HttpPost]
        public async Task<IActionResult> Login(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid email or password.");
                return View();
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Invalid email or password.");
                return View();
            }

            var roles = await _userManager.GetRolesAsync(user);
            var token = _tokenService.GenerateToken(user, roles);

            Response.Cookies.Append("AuthToken", token, new CookieOptions
            {
                HttpOnly = true, 
                Secure = true,   
                Expires = DateTime.UtcNow.AddHours(1)
            });

            return RedirectToAction("Index", "Home");
        }

    }
}
