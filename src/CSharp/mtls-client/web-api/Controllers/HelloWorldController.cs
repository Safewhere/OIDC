using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace web_api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class HelloWorldController : ControllerBase
    {
        private readonly ILogger<HelloWorldController> _logger;

        public HelloWorldController(ILogger<HelloWorldController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Authorize]
        public IActionResult Get()
        {
            _logger.LogInformation("HelloWorld endpoint accessed successfully");
            _logger.LogInformation("User authenticated: {IsAuthenticated}", User.Identity?.IsAuthenticated);
            _logger.LogInformation("User name: {Name}", User.Identity?.Name);
            _logger.LogInformation("User claims count: {ClaimsCount}", User.Claims?.Count() ?? 0);
            
            return Ok("Hello, World!");
        }

        [HttpGet("test")]
        public IActionResult Test()
        {
            _logger.LogInformation("Test endpoint accessed (no authorization required)");
            return Ok("Test endpoint works - no authorization required");
        }
    }
}
