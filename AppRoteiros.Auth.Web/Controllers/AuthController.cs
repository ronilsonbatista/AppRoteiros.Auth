using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using AppRoteiros.Auth.Web.Domain.Entities;
using AppRoteiros.Auth.Web.Dtos.Auth;
using AppRoteiros.Auth.Web.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AppRoteiros.Auth.Web.Controllers.Api
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITokenService _tokenService;
        private readonly ILogger<AuthController> _logger;
        private readonly IHostEnvironment _env;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            ITokenService tokenService,
            ILogger<AuthController> logger,
            IHostEnvironment env)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _logger = logger;
            _env = env;
        }

        [HttpGet("ping")]
        public IActionResult Ping()
        {
            return Ok(new { ok = true, feature = "auth" });
        }

        /// <summary>
        /// POST /api/auth/register
        /// Cria usuário e gera token de confirmação de e-mail.
        /// Em DEV, retorna o token para teste via Postman.
        /// </summary>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var existing = await _userManager.FindByEmailAsync(request.Email);
            if (existing != null)
                return Conflict(new { message = "E-mail já cadastrado." });

            var user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                PhoneNumber = request.PhoneNumber
            };

            var result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(error.Code, error.Description);

                return BadRequest(ModelState);
            }

            // Gera token de confirmação de e-mail
            var confirmToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            if (_env.IsDevelopment())
            {
                // Em DEV retornamos token + userId para testar sem serviço de e-mail.
                return Ok(new RegisterResponse
                {
                    Message = "Usuário criado. (DEV) Confirme o e-mail usando /api/auth/confirm-email.",
                    UserId = user.Id,
                    ConfirmEmailToken = confirmToken
                });
            }

            // Em PROD, você deve enviar esse token por e-mail (link).
            _logger.LogInformation("Usuário criado para {Email}. Token de confirmação gerado e deve ser enviado por e-mail.", request.Email);

            return Ok(new RegisterResponse
            {
                Message = "Usuário criado com sucesso. Verifique seu e-mail para confirmar a conta."
            });
        }

        /// <summary>
        /// POST /api/auth/confirm-email
        /// Confirma o e-mail do usuário usando token gerado no register (ou resend).
        /// </summary>
        [HttpPost("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
            {
                // Segurança: não revela muito detalhe
                return BadRequest(new { message = "Dados inválidos para confirmação." });
            }

            // Alguns tokens vêm com espaços ao invés de "+"
            var token = request.Token.Replace(" ", "+");

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(error.Code, error.Description);

                return BadRequest(ModelState);
            }

            return Ok(new { message = "E-mail confirmado com sucesso." });
        }

        /// <summary>
        /// POST /api/auth/resend-confirmation
        /// Reenvia (gera novamente) token de confirmação de e-mail.
        /// Em DEV retorna token para facilitar teste.
        /// Em PROD você enviaria por e-mail.
        /// </summary>
        [HttpPost("resend-confirmation")]
        public async Task<IActionResult> ResendConfirmation([FromBody] ResendEmailConfirmationRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Segurança: resposta sempre genérica
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return Ok(new
                {
                    message = "Se o e-mail existir, enviaremos um novo link de confirmação."
                });
            }

            if (user.EmailConfirmed)
            {
                return Ok(new
                {
                    message = "E-mail já confirmado."
                });
            }

            var confirmToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            if (_env.IsDevelopment())
            {
                return Ok(new
                {
                    message = "Token gerado (DEV). Use em /api/auth/confirm-email.",
                    userId = user.Id,
                    confirmEmailToken = confirmToken
                });
            }

            _logger.LogInformation("Reenvio de confirmação solicitado para {Email}. Token gerado e deve ser enviado por e-mail.", request.Email);

            return Ok(new
            {
                message = "Se o e-mail existir, enviaremos um novo link de confirmação."
            });
        }

        /// <summary>
        /// POST /api/auth/login
        /// Valida credenciais e retorna tokens.
        /// Recomendado: bloquear login se e-mail não estiver confirmado.
        /// </summary>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return Unauthorized(new { message = "Credenciais inválidas." });

            // Bloqueia login se e-mail não estiver confirmado (recomendado)
            if (!user.EmailConfirmed)
                return StatusCode(403, new { message = "Confirme seu e-mail para entrar." });

            var ok = await _userManager.CheckPasswordAsync(user, request.Password);
            if (!ok)
                return Unauthorized(new { message = "Credenciais inválidas." });

            var tokenResult = await _tokenService.GenerateTokensAsync(user);

            return Ok(new
            {
                accessToken = tokenResult.AccessToken,
                refreshToken = tokenResult.RefreshToken,
                expiresInSeconds = tokenResult.ExpiresInSeconds,
                user = new
                {
                    id = user.Id,
                    email = user.Email ?? string.Empty,
                    firstName = user.FirstName,
                    lastName = user.LastName
                }
            });
        }

        /// <summary>
        /// POST /api/auth/refresh
        /// Rotaciona refresh token e retorna um novo par de tokens.
        /// </summary>
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var refreshed = await _tokenService.RefreshTokensAsync(request.RefreshToken);
            if (refreshed == null)
                return Unauthorized(new { message = "Refresh token inválido ou expirado." });

            return Ok(new
            {
                accessToken = refreshed.AccessToken,
                refreshToken = refreshed.RefreshToken,
                expiresInSeconds = refreshed.ExpiresInSeconds
            });
        }

        /// <summary>
        /// POST /api/auth/forgot-password
        /// Gera token de reset. Em DEV retorna no response para teste.
        /// </summary>
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
            {
                return Ok(new ForgotPasswordResponse
                {
                    Message = "Se o e-mail existir, enviaremos instruções para redefinir a senha."
                });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            if (_env.IsDevelopment())
            {
                return Ok(new ForgotPasswordResponse
                {
                    Message = "Token gerado (DEV). Use em /api/auth/reset-password.",
                    ResetToken = token
                });
            }

            _logger.LogInformation("Forgot-password solicitado para {Email}. Token gerado e deve ser enviado por e-mail.", request.Email);

            return Ok(new ForgotPasswordResponse
            {
                Message = "Se o e-mail existir, enviaremos instruções para redefinir a senha."
            });
        }

        /// <summary>
        /// POST /api/auth/reset-password
        /// Reseta a senha usando token gerado em forgot-password.
        /// </summary>
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
            {
                return Ok(new { message = "Se os dados estiverem corretos, a senha será redefinida." });
            }

            var token = request.Token.Replace(" ", "+");
            var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(error.Code, error.Description);

                return BadRequest(ModelState);
            }

            return Ok(new { message = "Senha redefinida com sucesso." });
        }

        /// <summary>
        /// POST /api/auth/logout
        /// Revoga um refresh token específico (logout do device/app).
        /// Requer JWT (usuário autenticado).
        /// </summary>
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var revoked = await _tokenService.RevokeRefreshTokenAsync(request.RefreshToken);

            // Segurança: mesmo se token não existir, devolvemos OK
            return Ok(new { message = "Logout realizado com sucesso.", revoked });
        }

        /// <summary>
        /// POST /api/auth/logout-all
        /// Revoga todos os refresh tokens do usuário autenticado.
        /// Requer JWT (usuário autenticado).
        /// </summary>
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpPost("logout-all")]
        public async Task<IActionResult> LogoutAll()
        {
            var userId = User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                         ?? User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
                return Unauthorized(new { message = "Token inválido ou usuário não identificado." });

            var count = await _tokenService.RevokeAllRefreshTokensAsync(userId);

            return Ok(new { message = "Logout global realizado com sucesso.", revokedTokens = count });
        }
    }
}
