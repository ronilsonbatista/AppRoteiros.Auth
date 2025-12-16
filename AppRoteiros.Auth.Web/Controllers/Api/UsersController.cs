using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using AppRoteiros.Auth.Web.Domain.Entities;
using AppRoteiros.Auth.Web.Dtos.Users;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AppRoteiros.Auth.Web.Controllers.Api
{
    /// <summary>
    /// Endpoints relacionados ao usuário autenticado.
    /// Todos exigem JWT Bearer.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<UsersController> _logger;

        public UsersController(
            UserManager<ApplicationUser> userManager,
            ILogger<UsersController> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        /// <summary>
        /// Retorna o perfil do usuário autenticado.
        /// GET /api/users/me
        /// </summary>
        [HttpGet("me")]
        public async Task<IActionResult> Me()
        {
            // Recupera o userId do JWT
            var userId = User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                         ?? User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Acesso ao /api/users/me sem userId nas claims.");
                return Unauthorized(new { message = "Token inválido ou usuário não identificado." });
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("Usuário não encontrado para o id {UserId} no /me.", userId);
                return NotFound(new { message = "Usuário não encontrado." });
            }

            var response = new UserProfileResponse
            {
                Id = user.Id,
                Email = user.Email ?? string.Empty,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber
            };

            return Ok(response);
        }

        /// <summary>
        /// Atualiza nome/sobrenome/telefone do usuário autenticado.
        /// PUT /api/users/me
        /// </summary>
        [HttpPut("me")]
        public async Task<IActionResult> UpdateMe([FromBody] UpdateProfileRequest request)
        {
            // Validações do DTO
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Recupera o userId do JWT
            var userId = User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                         ?? User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("PUT /api/users/me sem userId nas claims.");
                return Unauthorized(new { message = "Token inválido ou usuário não identificado." });
            }

            // Busca usuário no banco
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("Usuário não encontrado para o id {UserId} no PUT /me.", userId);
                return NotFound(new { message = "Usuário não encontrado." });
            }

            // Atualiza campos permitidos
            user.FirstName = request.FirstName;
            user.LastName = request.LastName;
            user.PhoneNumber = request.PhoneNumber;

            // Persiste alterações via Identity
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(error.Code, error.Description);

                return BadRequest(ModelState);
            }

            // Retorna perfil atualizado
            var response = new UserProfileResponse
            {
                Id = user.Id,
                Email = user.Email ?? string.Empty,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber
            };

            return Ok(response);
        }
    }
}
