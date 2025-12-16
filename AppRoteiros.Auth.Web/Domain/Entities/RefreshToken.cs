using System;

namespace AppRoteiros.Auth.Web.Domain.Entities
{
    /// <summary>
    /// Entidade persistida no banco para controle de Refresh Tokens.
    /// Importante: isso NÃO é DTO. Isso é ENTIDADE.
    /// </summary>
    public class RefreshToken
    {
        /// <summary>
        /// Chave primária (Identity do EF).
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Token em si (string segura, gerada com RNG criptográfico).
        /// </summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// Usuário dono do refresh token (FK para AspNetUsers).
        /// </summary>
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// Data de expiração do refresh token.
        /// </summary>
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// Data de criação do refresh token.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Marca se o token foi revogado (logout, rotação, etc.).
        /// </summary>
        public bool IsRevoked { get; set; } = false;

        /// <summary>
        /// Navegação para o usuário.
        /// </summary>
        public ApplicationUser? User { get; set; }
    }
}
