using System.Text;
using AppRoteiros.Auth.Web.Config;
using AppRoteiros.Auth.Web.Data;
using AppRoteiros.Auth.Web.Domain.Entities;
using AppRoteiros.Auth.Web.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// ==========================================
// 1. CONFIGURAÇÃO DO BANCO (SQL SERVER)
// ==========================================
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// ==========================================
// 2. IDENTITY (REGISTRO + LOGIN + USERSTORE)
// ==========================================
builder.Services.AddDefaultIdentity<ApplicationUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;

    options.Password.RequiredLength = 8;
    options.Password.RequireUppercase = true;

    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// ==========================================
// 3. CONFIGURAÇÃO DO JWT
// ==========================================
builder.Services.Configure<JwtSettings>(
    builder.Configuration.GetSection("Jwt"));

var jwtSettings = builder.Configuration.GetSection("Jwt").Get<JwtSettings>()
    ?? throw new Exception("JWT settings not configured.");

// Adicionar autenticação JWT
builder.Services.AddAuthentication(options =>
{
    // Cookie continua funcionando para a parte MVC,
    // mas APIs vão usar JwtBearer explicitamente.
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,

        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,

        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtSettings.Key)),

        ClockSkew = TimeSpan.Zero // sem tolerância extra de expiração
    };
});

// ==========================================
// 4. SERVICES (INJEÇÃO DE DEPENDÊNCIA)
// ==========================================
builder.Services.AddScoped<ITokenService, TokenService>();

// MVC + Razor Pages (para identidade visual padrão)
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

// ==========================================
// 5. SWAGGER (opcional – ligado se quiser)
// ==========================================
// builder.Services.AddEndpointsApiExplorer();
// builder.Services.AddSwaggerGen();

var app = builder.Build();

// ==========================================
// 6. CONFIGURAÇÃO DO PIPELINE HTTP
// ==========================================

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// (opcional) Swagger para APIs – útil para testes
// if (app.Environment.IsDevelopment())
// {
//     app.UseSwagger();
//     app.UseSwaggerUI();
// }

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// ORDEM CERTA: primeiro autenticação, depois autorização
app.UseAuthentication();
app.UseAuthorization();

// MVC tradicional (HomeController etc.)
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Razor Pages (Identity UI)
app.MapRazorPages();

// Endpoint opcional de health check
// app.MapHealthChecks("/health");

app.Run();
