using System;
using AppRoteiros.Auth.Web.Domain.Entities;

namespace AppRoteiros.Auth.Web.Dtos.Auth
{
    public class RefreshToken
    {
        public int Id { get; set; }

        public string Token { get; set; } = string.Empty;

        public string UserId { get; set; } = string.Empty;

        public DateTime ExpiresAt { get; set; }

        public DateTime CreatedAt { get; set; }

        public bool IsRevoked { get; set; } = false;

        public ApplicationUser? User { get; set; }
    }
}
