using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;

namespace web_client.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ApiProxyController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ApiProxyController> _logger;

        public ApiProxyController(IConfiguration configuration, ILogger<ApiProxyController> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        [HttpGet("helloworld")]
        public async Task<IActionResult> CallHelloWorldApi()
        {
            try
            {
                var accessToken = await HttpContext.GetTokenAsync("access_token");
                if (string.IsNullOrEmpty(accessToken))
                {
                    _logger.LogWarning("No access token available");
                    return Unauthorized("No access token available");
                }

                _logger.LogInformation("Access token obtained, length: {Length}", accessToken.Length);

                var helloWorldApiUrl = _configuration["Api:HelloWorldUrl"];
                if (string.IsNullOrEmpty(helloWorldApiUrl))
                {
                    _logger.LogError("API URL not configured");
                    return BadRequest("API URL not configured");
                }

                _logger.LogInformation("Making API call to: {Url}", helloWorldApiUrl);

                // Create HttpClientHandler with client certificate
                var handler = new HttpClientHandler();
                var clientCert = ConfigurationData.ClientCertificate;
                if (clientCert != null)
                {
                    handler.ClientCertificates.Add(clientCert);
                    _logger.LogInformation("Client certificate added. Subject: {Subject}, Thumbprint: {Thumbprint}", 
                        clientCert.Subject, clientCert.Thumbprint);
                }
                else
                {
                    _logger.LogWarning("No client certificate available");
                }

                using var httpClient = new HttpClient(handler);
                httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                _logger.LogInformation("Sending HTTP request with Bearer token and client certificate");
                var response = await httpClient.GetAsync(helloWorldApiUrl);
                
                _logger.LogInformation("API response: {StatusCode} {ReasonPhrase}", 
                    response.StatusCode, response.ReasonPhrase);
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    _logger.LogInformation("API call successful, response: {Content}", content);
                    return Ok(content);
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("API call failed: {StatusCode} {ReasonPhrase} - {Content}", 
                        response.StatusCode, response.ReasonPhrase, errorContent);
                    return StatusCode((int)response.StatusCode, $"Error: {response.StatusCode} {response.ReasonPhrase} - {errorContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occurred while calling API");
                return StatusCode(500, $"Request failed: {ex.Message}");
            }
        }
    }
}