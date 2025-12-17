using System.ComponentModel.DataAnnotations;

namespace AppRoteiros.Auth.Web.Dtos.Auth
{
    /// <summary>
    /// Request para reenviar confirmação de e-mail.
    /// Usado em: POST /api/auth/resend-confirmation
    /// </summary>
    public class ResendEmailConfirmationRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
}
