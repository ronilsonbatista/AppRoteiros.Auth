using System.Threading.Tasks;
using AppRoteiros.Auth.Web.Domain.Entities;

namespace AppRoteiros.Auth.Web.Services
{
    public class TokenResult
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public int ExpiresInSeconds { get; set; }
    }

    public interface ITokenService
    {
        Task<TokenResult> GenerateTokensAsync(ApplicationUser user);
        Task<TokenResult?> RefreshTokensAsync(string refreshToken);
    }
}
