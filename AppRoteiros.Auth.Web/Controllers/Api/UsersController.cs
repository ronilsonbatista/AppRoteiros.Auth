using Microsoft.AspNetCore.Mvc;

namespace AppRoteiros.Auth.Web.Controllers.Api
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        [HttpGet("ping")]
        public IActionResult Ping() => Ok(new { ok = true, feature = "users" });
    }
}
