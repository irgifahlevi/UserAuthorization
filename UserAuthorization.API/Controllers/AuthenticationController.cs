using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Win32;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserAuthorization.API.Entities;
using UserAuthorization.API.Entities.Authentication.Login;
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
        private readonly SignInManager<IdentityUser> _signInManager;

        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailRepository emailServce, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailServce;
            _signInManager = signInManager;
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
                        TwoFactorEnabled = true
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

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginUser request)
        {
            try
            {
                if(ModelState.IsValid)
                {
                    var user = await _userManager.FindByEmailAsync(request.Email);

                    if (user != null || (await _userManager.CheckPasswordAsync(user, request.Password)))
                    {
                        if (user.TwoFactorEnabled)
                        {
                            var userName = await _userManager.FindByNameAsync(user.UserName);
                            await _signInManager.SignOutAsync();
                            await _signInManager.PasswordSignInAsync(userName, request.Password, false, false);

                            var provider = await _userManager.GetValidTwoFactorProvidersAsync(user);
                            if(provider != null)
                            {
                                var otpCode = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                                var message = new Message(new string[] { user.Email! }, "OTP Verification", $"Code OTP Verification : {otpCode}");
                                _emailService.SendEmail(message);

                                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"We have send an OTP to your email {user.Email}" });
                            }         
                        }
                        else
                        {
                            var authClaims = new List<Claim>
                            {
                                new Claim(ClaimTypes.Name, user.UserName),
                                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                            };

                            var userRole = await _userManager.GetRolesAsync(user);

                            foreach (var role in userRole)
                            {
                                authClaims.Add(new Claim(ClaimTypes.Role, role));
                            }

                            var jwtToken = GetToken(authClaims);

                            if (jwtToken != null)
                            {
                                var message = new Message(new string[] { user.Email! }, "Login information", $"Login success! date : {DateTime.Now}");
                                _emailService.SendEmail(message);
                            }

                            return Ok(new
                            {
                                token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                                expirrd = jwtToken.ValidTo
                            });
                        }
                    }

                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Login failed, please check email or password!" });
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


        [HttpPost]
        [Route("OTP-2FA")]
        public async Task<IActionResult> Verification2FA(VerificationOTP request)
        {
            try
            {
                if(ModelState.IsValid)
                {
                    if (!_emailService.IsValidEmail(request.Email))
                    {
                        return BadRequest(new Response { Status = "Error", Message = "Invalid email format." });
                    }

                    var user = await _userManager.FindByEmailAsync(request.Email);
                    var verifyOtp = await _signInManager.TwoFactorSignInAsync("Email", request.OtpCode, false, false);

                    if (user != null && verifyOtp.Succeeded)
                    {
                        var authClaims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, user.UserName),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                        };

                        var userRole = await _userManager.GetRolesAsync(user);

                        foreach (var role in userRole)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, role));
                        }

                        var jwtToken = GetToken(authClaims);

                        if (jwtToken != null)
                        {
                            var message = new Message(new string[] { user.Email! }, "Login information", $"Login success! date : {DateTime.Now}");
                            _emailService.SendEmail(message);
                        }

                        return Ok(new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                            expirrd = jwtToken.ValidTo
                        });
                    }

                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Verify OTP failed, please check code OTP or email!" });

                }
                else
                {
                    return BadRequest(ModelState);
                }
            }
            catch (Exception e)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = e.Message});
            }
        }
        private JwtSecurityToken GetToken(List<Claim> authClaim)
        {
            var authSignKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(60),
                claims: authClaim,
                signingCredentials: new SigningCredentials(authSignKey, SecurityAlgorithms.HmacSha512)

                );
            return token;
        }

    }
}
