using System;
using Microsoft.OpenApi.Models;
using System.Text;
using AppRoteiros.Auth.Web.Data;
using AppRoteiros.Auth.Web.Domain.Entities;
using AppRoteiros.Auth.Web.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;


var builder = WebApplication.CreateBuilder(args);

// ------------------------------------
// Database (EF Core)
// ------------------------------------
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// ------------------------------------
// Identity
// ------------------------------------
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        // Senha (alinhado com o que você definiu)
        options.Password.RequiredLength = 8;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireDigit = false;
        options.Password.RequireNonAlphanumeric = false;

        // Usuário
        options.User.RequireUniqueEmail = true;

        // Confirmar e-mail antes de logar (você já está validando no controller,
        // mas aqui também fica coerente caso use [Authorize] + Identity em outros fluxos)
        options.SignIn.RequireConfirmedEmail = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// ------------------------------------
// JWT Authentication
// ------------------------------------
// Requer appsettings.json:
// "Jwt": { "Key": "...", "Issuer": "...", "Audience": "...", "AccessTokenMinutes": "15", "RefreshTokenDays": "30" }
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];

if (string.IsNullOrWhiteSpace(jwtKey))
    throw new InvalidOperationException("Jwt:Key não configurado no appsettings.json.");

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;
        options.SaveToken = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),

            ValidateIssuer = !string.IsNullOrWhiteSpace(jwtIssuer),
            ValidIssuer = jwtIssuer,

            ValidateAudience = !string.IsNullOrWhiteSpace(jwtAudience),
            ValidAudience = jwtAudience,

            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30) // tolerância pequena
        };
    });

// ------------------------------------
// Controllers (MVC + API)
// ------------------------------------
builder.Services.AddControllersWithViews();

// ------------------------------------
// App Services
// ------------------------------------
// Seu TokenService (confirme se o namespace e a classe batem com o projeto)
builder.Services.AddScoped<ITokenService, TokenService>();

// ------------------------------------
// Swagger / OpenAPI
// ------------------------------------
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "AppRoteiros.Auth API",
        Version = "v1",
        Description = "API de autenticação do AppRoteiros (Identity + JWT + Refresh Tokens)."
    });

    // Permitir Authorize (Bearer Token) no Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Informe: Bearer {seu_token_jwt}"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // (Opcional) Se você ativar XML docs, dá para habilitar aqui também.
    // c.IncludeXmlComments(xmlPath);
});

var app = builder.Build();

// ------------------------------------
// Pipeline
// ------------------------------------
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();

    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "AppRoteiros.Auth API v1");
        c.RoutePrefix = "swagger"; // /swagger
    });
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Importante: Authentication antes de Authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
