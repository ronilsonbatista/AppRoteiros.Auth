using System.ComponentModel.DataAnnotations;

namespace AppRoteiros.Auth.Web.Dtos.Users
{
    /// <summary>
    /// Resposta padrão do perfil do usuário.
    /// Usado em:
    /// - GET /api/users/me
    /// - PUT /api/users/me
    /// </summary>
    public class UserProfileResponse
    {
        public string Id { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;

        public string? FirstName { get; set; }

        public string? LastName { get; set; }

        public string? PhoneNumber { get; set; }
    }

    /// <summary>
    /// Request para atualização do perfil do usuário autenticado.
    /// Usado em: PUT /api/users/me
    /// </summary>
    public class UpdateProfileRequest
    {
        [Required]
        [MaxLength(100)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [MaxLength(100)]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [Phone]
        public string PhoneNumber { get; set; } = string.Empty;
    }

    /// <summary>
    /// Request para troca de senha do usuário autenticado.
    /// Usado em: POST /api/users/change-password
    /// </summary>
    public class ChangePasswordRequest
    {
        /// <summary>
        /// Senha atual do usuário (obrigatória).
        /// </summary>
        [Required]
        public string CurrentPassword { get; set; } = string.Empty;

        /// <summary>
        /// Nova senha (obrigatória).
        /// Regra mínima:
        /// - Pelo menos 8 caracteres
        /// - Pelo menos 1 letra maiúscula
        /// </summary>
        [Required]
        [MinLength(8)]
        [RegularExpression(@"^(?=.*[A-Z]).{8,}$",
            ErrorMessage = "A nova senha deve ter pelo menos 8 caracteres e 1 letra maiúscula.")]
        public string NewPassword { get; set; } = string.Empty;

        /// <summary>
        /// Confirmação da nova senha (obrigatória).
        /// Deve ser igual ao campo NewPassword.
        /// </summary>
        [Required]
        [Compare(nameof(NewPassword), ErrorMessage = "A confirmação da nova senha não confere.")]
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }
}
