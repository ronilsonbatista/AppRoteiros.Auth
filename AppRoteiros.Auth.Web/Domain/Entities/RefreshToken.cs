using System;

namespace AppRoteiros.Auth.Web.Domain.Entities
{
    /// <summary>
    /// Entidade responsável por armazenar Refresh Tokens.
    /// Um usuário pode ter vários (multi-device).
    /// </summary>
    public class RefreshToken
    {
        public Guid Id { get; set; }

        /// <summary>
        /// Token em si (string segura).
        /// </summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// Usuário dono do token.
        /// </summary>
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// Data de criação do token.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Data de expiração do token.
        /// </summary>
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// Data de revogação (logout / rotação).
        /// NULL = token ativo.
        /// </summary>
        public DateTime? RevokedAt { get; set; }

        // Navegação (opcional, mas recomendada)
        public ApplicationUser? User { get; set; }
    }
}
