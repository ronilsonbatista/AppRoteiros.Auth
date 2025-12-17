using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AppRoteiros.Auth.Web.Data;
using AppRoteiros.Auth.Web.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AppRoteiros.Auth.Web.Services
{
    /// <summary>
    /// TokenService:
    /// - Gera JWT (AccessToken)
    /// - Gera e persiste RefreshToken
    /// - Faz rotação de RefreshToken
    /// - Revoga tokens
    /// </summary>
    public class TokenService : ITokenService
    {
        private readonly ApplicationDbContext _db;
        private readonly IConfiguration _config;

        public TokenService(ApplicationDbContext db, IConfiguration config)
        {
            _db = db;
            _config = config;
        }

        public async Task<TokenResult> GenerateTokensAsync(ApplicationUser user)
        {
            var accessToken = GenerateJwt(user);

            // Tempo de expiração do refresh token (ex: 30 dias)
            var refreshDays = int.TryParse(_config["Jwt:RefreshTokenDays"], out var d) ? d : 30;
            var refreshToken = GenerateSecureToken();

            var rt = new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                Token = refreshToken,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(refreshDays),
                RevokedAt = null
            };

            _db.RefreshTokens.Add(rt);
            await _db.SaveChangesAsync();

            return new TokenResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresInSeconds = GetAccessTokenExpiresInSeconds()
            };
        }

        public async Task<TokenResult?> RefreshTokensAsync(string refreshToken)
        {
            var existing = await _db.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == refreshToken);

            if (existing == null) return null;
            if (existing.RevokedAt != null) return null;
            if (existing.ExpiresAt <= DateTime.UtcNow) return null;

            // Revoga o refresh token atual (rotação)
            existing.RevokedAt = DateTime.UtcNow;

            // Emite novos tokens
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == existing.UserId);
            if (user == null) return null;

            var result = await GenerateTokensAsync(user);

            // Salva a revogação do token anterior
            await _db.SaveChangesAsync();

            return result;
        }

        public async Task<bool> RevokeRefreshTokenAsync(string refreshToken)
        {
            var existing = await _db.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == refreshToken);

            if (existing == null) return false;

            if (existing.RevokedAt != null) return true; // já revogado

            existing.RevokedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
            return true;
        }

        public async Task<int> RevokeAllRefreshTokensAsync(string userId)
        {
            var tokens = await _db.RefreshTokens
                .Where(x => x.UserId == userId && x.RevokedAt == null && x.ExpiresAt > DateTime.UtcNow)
                .ToListAsync();

            foreach (var t in tokens)
                t.RevokedAt = DateTime.UtcNow;

            await _db.SaveChangesAsync();
            return tokens.Count;
        }

        // ----------------------
        // Helpers (JWT + tokens)
        // ----------------------

        private string GenerateJwt(ApplicationUser user)
        {
            var key = _config["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key não configurado.");
            var issuer = _config["Jwt:Issuer"] ?? "AppRoteiros.Auth";
            var audience = _config["Jwt:Audience"] ?? "AppRoteiros";

            var expiresMinutes = int.TryParse(_config["Jwt:AccessTokenMinutes"], out var m) ? m : 15;

            var claims = new[]
            {
                // sub: userId (padrão recomendado)
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),

                // email (útil no app)
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),

                // claim padrão do Identity
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiresMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private int GetAccessTokenExpiresInSeconds()
        {
            var expiresMinutes = int.TryParse(_config["Jwt:AccessTokenMinutes"], out var m) ? m : 15;
            return expiresMinutes * 60;
        }

        private static string GenerateSecureToken()
        {
            // Token aleatório criptograficamente forte (refresh token)
            var bytes = RandomNumberGenerator.GetBytes(64);
            return Convert.ToBase64String(bytes);
        }
    }
}
