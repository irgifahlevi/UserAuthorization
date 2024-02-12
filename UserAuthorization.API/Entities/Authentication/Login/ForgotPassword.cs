using System.ComponentModel.DataAnnotations;

namespace UserAuthorization.API.Entities.Authentication.Login
{
    public class ForgotPassword
    {
        [EmailAddress]
        [Required(ErrorMessage = "Email is required!")]
        [StringLength(50, ErrorMessage = "Email must not exceed 100 characters.")]
        public string Email { get; set; }
    }
}
