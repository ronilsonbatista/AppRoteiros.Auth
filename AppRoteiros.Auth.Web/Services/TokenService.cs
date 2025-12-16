using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AppRoteiros.Auth.Web.Config;
using AppRoteiros.Auth.Web.Data;
using AppRoteiros.Auth.Web.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AppRoteiros.Auth.Web.Services
{
    /// <summary>
    /// Serviço responsável por:
    /// - Gerar AccessToken (JWT)
    /// - Criar RefreshToken persistido no banco
    /// - Rotacionar RefreshToken no endpoint /refresh
    /// </summary>
    public class TokenService : ITokenService
    {
        private readonly JwtSettings _jwtSettings;
        private readonly ApplicationDbContext _dbContext;

        public TokenService(IOptions<JwtSettings> jwtSettings, ApplicationDbContext dbContext)
        {
            _jwtSettings = jwtSettings.Value;
            _dbContext = dbContext;
        }

        /// <summary>
        /// Gera um par de tokens: AccessToken + RefreshToken.
        /// </summary>
        public async Task<TokenResult> GenerateTokensAsync(ApplicationUser user)
        {
            var now = DateTime.UtcNow;

            // Claims do JWT (o app mobile vai usar principalmente o "sub" = userId)
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("firstName", user.FirstName ?? string.Empty),
                new Claim("lastName", user.LastName ?? string.Empty)
            };

            // Assinatura do token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expires = now.AddMinutes(_jwtSettings.AccessTokenMinutes);

            var jwt = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                notBefore: now,
                expires: expires,
                signingCredentials: creds
            );

            var accessToken = new JwtSecurityTokenHandler().WriteToken(jwt);

            // Cria e salva RefreshToken no banco
            var refreshToken = await CreateRefreshTokenAsync(user);

            return new TokenResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
                ExpiresInSeconds = _jwtSettings.AccessTokenMinutes * 60
            };
        }

        /// <summary>
        /// Rotaciona tokens com base em um refreshToken existente.
        /// 1) Valida token e expiração
        /// 2) Revoga token antigo
        /// 3) Gera um novo par de tokens
        /// </summary>
        public async Task<TokenResult?> RefreshTokensAsync(string refreshToken)
        {
            var existing = await _dbContext.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == refreshToken && !rt.IsRevoked);

            if (existing == null)
                return null;

            if (existing.ExpiresAt <= DateTime.UtcNow)
                return null;

            if (existing.User == null)
                return null;

            // Revoga o token antigo antes de emitir um novo
            existing.IsRevoked = true;
            await _dbContext.SaveChangesAsync();

            return await GenerateTokensAsync(existing.User);
        }

        /// <summary>
        /// Cria e persiste um refresh token para o usuário.
        /// </summary>
        private async Task<RefreshToken> CreateRefreshTokenAsync(ApplicationUser user)
        {
            var token = GenerateSecureToken();

            var refreshToken = new RefreshToken
            {
                Token = token,
                UserId = user.Id,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenDays),
                IsRevoked = false
            };

            _dbContext.RefreshTokens.Add(refreshToken);
            await _dbContext.SaveChangesAsync();

            return refreshToken;
        }

        /// <summary>
        /// Gera um token criptograficamente seguro.
        /// </summary>
        private static string GenerateSecureToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}
