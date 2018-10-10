using System.Security.Claims;

namespace WpfDesktopApp
{
    public class AuthenticationResult
    {
        public string AccessToken { get; set; }
        public ClaimsPrincipal ClaimsPrincipal { get; set; }
    }
}
