using System.ComponentModel.DataAnnotations;

namespace AppRoteiros.Auth.Web.Dtos.Auth
{
    /// <summary>
    /// Request para logout (revogar um refresh token específico).
    /// Usado em: POST /api/auth/logout
    /// </summary>
    public class LogoutRequest
    {
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
