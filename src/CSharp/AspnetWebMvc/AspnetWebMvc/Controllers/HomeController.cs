using OAuth2ClientSamples.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Helpers;
using System.Web.Http;
using System.Web.Mvc;

namespace AspnetWebMvc.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var hybridUrl = OAuth2Client.CreateAuthorizationUrl(
                ApplicationSettings.Authority,
                ApplicationSettings.ClientId,
                ApplicationSettings.Scope,
                ApplicationSettings.RedirectUri, 
                ApplicationSettings.ResponseType,
                string.Empty,
                ApplicationSettings.State, 
                ApplicationSettings.Prompt);

            var codeFlowUrl = OAuth2Client.CreateAuthorizationUrl(
                ApplicationSettings.Authority,
                ApplicationSettings.ClientId,
                ApplicationSettings.Scope,
                ApplicationSettings.RedirectUri,
                "code",
                ApplicationSettings.ResponseMode,
                ApplicationSettings.State,
                ApplicationSettings.Prompt);

            var implicitUrl = OAuth2Client.CreateAuthorizationUrl(
               ApplicationSettings.Authority,
               ApplicationSettings.ClientId,
               ApplicationSettings.Scope,
               ApplicationSettings.RedirectUri,
               ApplicationSettings.ResponseType,
               ApplicationSettings.ResponseMode,
               ApplicationSettings.State,
               ApplicationSettings.Prompt);

            ViewBag.HybridAuthorizeUrl = hybridUrl;
            ViewBag.CodeFlowAuthorizeUrl = codeFlowUrl;
            ViewBag.ImplicitFlowAuthorizeUrl = implicitUrl;
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

        public ActionResult ImplicitCallback(OAuth2TokenResponse response)
        {
            if (ApplicationSettings.ResponseMode == "form_post")
            {
                ViewBag.AccessToken = string.IsNullOrEmpty(response.Access_Token) ? "none" : response.Access_Token;
                ViewBag.IdToken = string.IsNullOrEmpty(response.Id_Token) ? "none" : response.Id_Token;
                ViewBag.Error = Request.QueryString["error"] ?? "none";
            }
            ViewBag.ResponseMode = ApplicationSettings.ResponseMode;

            return View("ImplicitCallback");
        }

        public ActionResult CodeFlowCallback(OAuth2TokenResponse response)
        {
            ViewBag.Message = "Code received.";
            if (ApplicationSettings.ResponseMode == "form_post")
            {
                ViewBag.Code = string.IsNullOrEmpty(response.Code) ? "none" : response.Code;
                ViewBag.Error = Request.QueryString["error"] ?? "none";
            }
            else
            {
                ViewBag.Code = Request.QueryString["code"] ?? "none";
                ViewBag.Error = Request.QueryString["error"] ?? "none";
            }

            return View("CodeFlowCallback");
        }

        public ActionResult TokenCallback()
        {
            ViewBag.Message = "Token received.";
            ViewBag.Code = Request.QueryString["code"] ?? "none";
            ViewBag.Error = Request.QueryString["error"] ?? "none";

            return View("CodeCallback");
        }
        
        
        [System.Web.Mvc.HttpPost]
        public ActionResult RenewToken(string refreshToken)
        {
            var client = new OAuth2Client(
                new Uri(ApplicationSettings.Authority),
                ApplicationSettings.ClientId,
                ApplicationSettings.ClientSecret);
            var response = client.RequestAccessTokenRefreshToken(refreshToken);
            return View("TokenReceived", response);
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