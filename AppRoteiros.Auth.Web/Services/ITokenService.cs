using System.Threading.Tasks;
using AppRoteiros.Auth.Web.Domain.Entities;

namespace AppRoteiros.Auth.Web.Services
{
    /// <summary>
    /// Serviço responsável por geração e renovação de tokens (JWT + Refresh Tokens).
    /// </summary>
    public interface ITokenService
    {
        Task<TokenResult> GenerateTokensAsync(ApplicationUser user);

        /// <summary>
        /// Faz rotação do refresh token:
        /// - valida refresh token atual
        /// - revoga o atual
        /// - emite novo access + novo refresh
        /// </summary>
        Task<TokenResult?> RefreshTokensAsync(string refreshToken);

        /// <summary>
        /// Revoga (invalida) um refresh token específico.
        /// </summary>
        Task<bool> RevokeRefreshTokenAsync(string refreshToken);

        /// <summary>
        /// Revoga todos os refresh tokens de um usuário.
        /// </summary>
        Task<int> RevokeAllRefreshTokensAsync(string userId);
    }

    /// <summary>
    /// Resultado padrão do TokenService.
    /// </summary>
    public class TokenResult
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public int ExpiresInSeconds { get; set; }
    }
}
