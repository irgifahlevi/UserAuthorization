using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Win32;
using UserAuthorization.API.Entities;
using UserAuthorization.API.Entities.Authentication.SignUp;

namespace UserAuthorization.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
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

                    return StatusCode(StatusCodes.Status201Created, new Response { Status = "Success", Message = "User created successfully!" });
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
    }
}
