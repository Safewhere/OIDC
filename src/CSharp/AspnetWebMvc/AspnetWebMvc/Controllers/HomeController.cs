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
                ApplicationSettings.HybridClientId,
                ApplicationSettings.Scope,
                ApplicationSettings.HybridRedirectUri, 
                ApplicationSettings.HybridResponseType,
                string.Empty,
                ApplicationSettings.MaxAge,
                ApplicationSettings.State, 
                ApplicationSettings.Prompt);

            var codeFlowUrl = OAuth2Client.CreateAuthorizationUrl(
                ApplicationSettings.Authority,
                ApplicationSettings.CodeFlowClientId,
                ApplicationSettings.Scope,
                ApplicationSettings.CodeFlowRedirectUri,
                "code",
                ApplicationSettings.ResponseMode,
                ApplicationSettings.MaxAge,
                ApplicationSettings.State,
                ApplicationSettings.Prompt);

            var implicitUrl = OAuth2Client.CreateAuthorizationUrl(
               ApplicationSettings.Authority,
               ApplicationSettings.ImplicitClientId,
               ApplicationSettings.Scope,
               ApplicationSettings.ImplicitRedirectUri,
               ApplicationSettings.ImplicitResponseType,
               ApplicationSettings.ResponseMode,
               ApplicationSettings.MaxAge,
               ApplicationSettings.State,
               ApplicationSettings.Prompt);

            ViewBag.HybridAuthorizeUrl = hybridUrl;
            ViewBag.CodeFlowAuthorizeUrl = codeFlowUrl;
            ViewBag.ImplicitFlowAuthorizeUrl = implicitUrl;
            return View();
        }

        public ActionResult Jwks()
        {
            var jwks = System.IO.File.ReadAllText(Server.MapPath(@"~/App_Data/jwks.json"));
            return Content(jwks, "application/json");
        }

        public ActionResult HybridCallback(string Code)
        {
            ViewBag.Message = "Code received.";
            ViewBag.ReturnUrl = ApplicationSettings.HybridRedirectUri;
            ViewBag.ClientId = ApplicationSettings.HybridClientId;

            return View("HybridCallback");
        }

        public ActionResult ImplicitCallback(OAuth2TokenResponse response)
        {
            if (ApplicationSettings.ResponseMode == "form_post")
            {
                ViewBag.AccessToken = string.IsNullOrEmpty(response.Access_Token) ? "none" : response.Access_Token;
                ViewBag.IdToken = string.IsNullOrEmpty(response.Id_Token) ? "none" : response.Id_Token;
                ViewBag.Error = response.Error ?? "none";
                ViewBag.ErrorDescription = response.Error_Description ?? "none";
            }
            ViewBag.ResponseMode = ApplicationSettings.ResponseMode;

            return View("ImplicitCallback");
        }

        public ActionResult CodeFlowCallback(OAuth2TokenResponse response)
        {
            ViewBag.Message = "Response received.";
            ViewBag.ReturnUrl = ApplicationSettings.CodeFlowRedirectUri;
            ViewBag.ClientId = ApplicationSettings.CodeFlowClientId;
            if (ApplicationSettings.ResponseMode == "form_post")
            {
                ViewBag.Code = string.IsNullOrEmpty(response.Code) ? "none" : response.Code;
                ViewBag.Error = response.Error ?? "none";
                ViewBag.ErrorDescription = response.Error_Description ?? "none";
            }
            else
            {
                ViewBag.Code = Request.QueryString["code"] ?? "none";
                ViewBag.Error = Request.QueryString["error"] ?? "none";
                ViewBag.ErrorDescription = Request.QueryString["error_description"] ?? "none";
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