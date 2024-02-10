using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Win32;
using UserAuthorization.API.Entities;
using UserAuthorization.API.Entities.Authentication.SignUp;
using UserAuthorization.Facade.Models;
using UserAuthorization.Facade.Services;

namespace UserAuthorization.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailRepository _emailService;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailRepository emailServce)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailServce;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser request, string role)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var emailExist = await _userManager.FindByEmailAsync(request.Email);
                    var usernameExist = await _userManager.FindByNameAsync(request.Username);
                    if (emailExist != null || usernameExist != null)
                    {
                        return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "User already exists!" });
                    }

                    IdentityUser user = new()
                    {
                        Email = request.Email,
                        SecurityStamp = Guid.NewGuid().ToString(),
                        UserName = request.Username,
                    };

                    var findRole = await _roleManager.RoleExistsAsync(role);
                    if (!findRole)
                    {
                        return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = $"Role '{role}' not found!" });
                    }

                    var result = await _userManager.CreateAsync(user, request.Password);
                    if (!result.Succeeded)
                    {
                        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to register, please check username, email or password!" });
                    }

                    await _userManager.AddToRoleAsync(user, role);

                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
                    var message = new Message(new string[] { user.Email! }, "Confirmation email link", confirmationLink!);
                    _emailService.SendEmail(message);

                    return StatusCode(StatusCodes.Status201Created, new Response { Status = "Success", Message = $"User created success and verification email send to {user.Email} !" });
                }
                else
                {
                    return BadRequest(ModelState);
                }

            }
            catch (Exception e)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = e.Message });
            }
        }


        [HttpGet]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            try
            { 
                if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
                {
                    return BadRequest(new Response { Status = "Error", Message = "Token and email are required." });
                }

                if (!_emailService.IsValidEmail(email))
                {
                    return BadRequest(new Response { Status = "Error", Message = "Invalid email format." });
                }

                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to confirm email." });
                }

                if(user.EmailConfirmed)
                {
                    return BadRequest(new Response { Status = "Error", Message = "Email has already been verified." });
                }
          

                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to register, please check username, email or password!" });
                }

                return StatusCode(StatusCodes.Status201Created, new Response { Status = "Success", Message = "Verify email successfully!" });

            }
            catch (Exception e)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = e.Message });
            }
        }

    }
}
