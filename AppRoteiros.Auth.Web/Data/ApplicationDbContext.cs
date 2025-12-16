using AppRoteiros.Auth.Web.Domain.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AppRoteiros.Auth.Web.Data
{
    /// <summary>
    /// DbContext principal do projeto.
    /// Herda do IdentityDbContext para criar as tabelas do Identity automaticamente.
    /// </summary>
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        /// <summary>
        /// Tabela de RefreshTokens (persistência para rotação e segurança do JWT).
        /// </summary>
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configurações do relacionamento RefreshToken -> ApplicationUser
            builder.Entity<RefreshToken>(entity =>
            {
                entity.HasKey(rt => rt.Id);

                entity.HasOne(rt => rt.User)
                    .WithMany()
                    .HasForeignKey(rt => rt.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.Property(rt => rt.Token)
                    .IsRequired();

                entity.Property(rt => rt.UserId)
                    .IsRequired();
            });
        }
    }
}
