using OAuth2ClientSamples.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;

namespace AspnetWebMvc.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var url = OAuth2Client.CreateHybridUrl(
                ApplicationSettings.Authority,
                ApplicationSettings.ClientId,
                ApplicationSettings.Scope,
                ApplicationSettings.RedirectUri, 
                ApplicationSettings.ResponseType,
                ApplicationSettings.State, 
                ApplicationSettings.Prompt);

            ViewBag.AuthorizeUrl = url;
            return View();
        }

        public ActionResult HybridCallback(string Code)
        {
            ViewBag.Message = "Code received.";
            string url = HttpContext.Request.RawUrl;
            var query = HttpUtility.ParseQueryString(Request.Url.AbsoluteUri);

            ViewBag.Code = Request.QueryString["code"] ?? "none";
            ViewBag.Error = Request.QueryString["error"] ?? "none";

            return View("HybridCallback");
        }

        public ActionResult TokenCallback()
        {
            ViewBag.Message = "Token received.";
            ViewBag.Code = Request.QueryString["code"] ?? "none";
            ViewBag.Error = Request.QueryString["error"] ?? "none";

            return View("CodeCallback");
        }
        
        
        [HttpPost]
        public ActionResult RenewToken(string refreshToken)
        {
            var client = new OAuth2Client(
                new Uri(ApplicationSettings.Authority),
                ApplicationSettings.ClientId,
                ApplicationSettings.ClientSecret);
            var response = client.RequestAccessTokenRefreshToken(refreshToken);
            return View("TokenReceived", response);
        }

        private OAuth2TokenResponse NegotiateToken(string code)
        {
            var client = new OAuth2Client(
               new Uri(ApplicationSettings.Authority),
               ApplicationSettings.ClientId,
               ApplicationSettings.ClientSecret);

            var additionalProperties = new Dictionary<string, string> { { "state", ApplicationSettings.State } };

            var response = client.RequestAccessTokenCode(
                code,
                new Uri(ApplicationSettings.RedirectUri),
                additionalProperties
                );
            return response;
        }

        public ActionResult Contact()
        {
            ViewData["Message"] = "Safewhere contact page.";

            return View();
        }

        public ActionResult About()
        {
            return View();
        }
    }
}