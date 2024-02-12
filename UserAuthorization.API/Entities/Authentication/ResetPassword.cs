using System.ComponentModel.DataAnnotations;

namespace UserAuthorization.API.Entities.Authentication
{
    public class ResetPassword
    {
        [Required]
        public string Password { get; set; } = null!;
        [Compare("Password", ErrorMessage = "This password not match")]
        public string ConfirmPassword { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string Token { get; set; } = null!;
    }
}
