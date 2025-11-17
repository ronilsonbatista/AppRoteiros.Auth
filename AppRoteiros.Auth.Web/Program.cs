using AppRoteiros.Auth.Web.Data;
using AppRoteiros.Auth.Web.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Identity com ApplicationUser
builder.Services.AddDefaultIdentity<ApplicationUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.Password.RequiredLength = 8;
    options.Password.RequireUppercase = true;
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>();

// MVC + Razor Pages (IMPORTANTE para o Identity UI)
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();          // <-- garante as páginas de Register/Login

builder.Services.AddHealthChecks();        // se você já colocou

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// Rotas MVC
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Rotas das Razor Pages do Identity (REGISTRAR/LOGIN)
app.MapRazorPages();                       // <-- sem isso o botão não funciona

// Health
app.MapHealthChecks("/health");

app.Run();
