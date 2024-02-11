using System.ComponentModel.DataAnnotations;

namespace UserAuthorization.API.Entities.Authentication.Login
{
    public class VerificationOTP
    {
        [Required(ErrorMessage = "OTP is required!")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "OTP must be exactly 6 characters long.")]
        public string OtpCode { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required!")]
        [StringLength(50, ErrorMessage = "Email must not exceed 100 characters.")]
        public string Email { get; set; }
    }
}
