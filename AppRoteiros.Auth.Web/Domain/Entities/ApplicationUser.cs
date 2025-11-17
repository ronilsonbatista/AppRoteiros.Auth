using Microsoft.AspNetCore.Identity;

namespace AppRoteiros.Auth.Web.Domain.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }

        // PhoneNumber já vem da IdentityUser
    }
}
