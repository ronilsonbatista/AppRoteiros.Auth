using System.ComponentModel.DataAnnotations;

namespace AppRoteiros.Auth.Web.Dtos.Auth
{
    /// <summary>
    /// Request para confirmar e-mail.
    /// Usado em: POST /api/auth/confirm-email
    /// </summary>
    public class ConfirmEmailRequest
    {
        /// <summary>
        /// Id do usuário (Identity UserId).
        /// </summary>
        [Required]
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// Token gerado pelo Identity em GenerateEmailConfirmationTokenAsync.
        /// Normalmente vai em um link enviado por e-mail (URL encoded).
        /// </summary>
        [Required]
        public string Token { get; set; } = string.Empty;
    }
}
