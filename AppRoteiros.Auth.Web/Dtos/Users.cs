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
}
