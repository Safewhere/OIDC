using OAuth2ClientSamples.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace AspnetWebMvc.Controllers
{
    public class Oauth2Controller : Controller
    {
        public class TokenRequest
        {
            public string Code { get; set; }
        }

        [HttpPost]
        public ActionResult GetToken(TokenRequest tokenRequest)
        {
            var client = new OAuth2Client(
                new Uri(ApplicationSettings.Authority),
                ApplicationSettings.ClientId,
                ApplicationSettings.ClientSecret);

            var response = client.RequestAccessTokenCode(
                tokenRequest.Code,
                new Uri(ApplicationSettings.RedirectUri));

            return Json(new { success = true , response });
        }

        [HttpPost]
        public ActionResult RenewToken(TokenRequest tokenRequest)
        {
            var client = new OAuth2Client(
                new Uri(ApplicationSettings.Authority),
                ApplicationSettings.ClientId,
                ApplicationSettings.ClientSecret);
            var response = client.RequestAccessTokenRefreshToken(tokenRequest.Code);
            return Json(new { success = true, response });
        }

    }
}