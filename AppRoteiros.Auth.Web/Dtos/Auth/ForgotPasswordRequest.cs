using System.ComponentModel.DataAnnotations;

namespace AppRoteiros.Auth.Web.Dtos.Auth
{
    /// <summary>
    /// Request para iniciar o fluxo de recuperação de senha.
    /// Usado em: POST /api/auth/forgot-password
    /// </summary>
    public class ForgotPasswordRequest
    {
        /// <summary>
        /// E-mail do usuário que deseja recuperar a senha.
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
}
