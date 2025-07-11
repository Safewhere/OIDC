using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace web_client.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;
    private readonly IConfiguration _configuration;

    public IndexModel(ILogger<IndexModel> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public string? AccessToken { get; set; }
    public string? IdentityToken { get; set; }
    public string HelloWorldApiUrl { get; set; } = string.Empty;

    public async Task OnGetAsync()
    {
        HelloWorldApiUrl = _configuration["Api:HelloWorldUrl"] ?? "";
        if (User.Identity?.IsAuthenticated ?? false)
        {
            AccessToken = await HttpContext.GetTokenAsync("access_token");
            IdentityToken = await HttpContext.GetTokenAsync("id_token");
        }
    }
}
