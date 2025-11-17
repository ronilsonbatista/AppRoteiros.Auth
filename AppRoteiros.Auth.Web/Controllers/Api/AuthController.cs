using Microsoft.AspNetCore.Mvc;

namespace AppRoteiros.Auth.Web.Controllers.Api
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        [HttpGet("ping")]
        public IActionResult Ping() => Ok(new { ok = true, feature = "auth" });
    }
}
