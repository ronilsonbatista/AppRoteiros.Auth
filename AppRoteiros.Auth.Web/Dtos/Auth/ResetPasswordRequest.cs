using System.ComponentModel.DataAnnotations;

namespace AppRoteiros.Auth.Web.Dtos.Auth
{
    /// <summary>
    /// Request para finalizar a redefinição de senha.
    /// Usado em: POST /api/auth/reset-password
    /// </summary>
    public class ResetPasswordRequest
    {
        /// <summary>
        /// E-mail do usuário.
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Token gerado pelo Identity (forgot-password).
        /// </summary>
        [Required]
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// Nova senha.
        /// Regra:
        /// - mínimo 8 caracteres
        /// - pelo menos 1 letra maiúscula
        /// </summary>
        [Required]
        [MinLength(8)]
        [RegularExpression(
            @"^(?=.*[A-Z]).{8,}$",
            ErrorMessage = "A senha deve ter pelo menos 8 caracteres e 1 letra maiúscula."
        )]
        public string NewPassword { get; set; } = string.Empty;

        /// <summary>
        /// Confirmação da nova senha.
        /// </summary>
        [Required]
        [Compare(nameof(NewPassword), ErrorMessage = "A confirmação da nova senha não confere.")]
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }
}
