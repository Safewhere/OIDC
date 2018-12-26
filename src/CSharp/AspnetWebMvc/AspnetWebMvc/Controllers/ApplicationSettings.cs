using System.Configuration;
using System.Web;

namespace OAuth2ClientSamples.Controllers
{
    public class ApplicationSettings
    {
        public static string Authority
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:Authority"];
            }
        }
        public static string ClientId
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ClientId"];
            }
        }
        public static string ClientSecret
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ClientSecret"];
            }
        }
        public static string ResponseType
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ResponseType"];
            }
        }
        public static string ResponseMode
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:ResponseMode"];
            }
        }
        public static string Scope
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:Scope"];
            }
        }
        public static string State
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:State"];
            }
        }
        public static string Prompt
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:Prompt"];
            }
        }
        public static string RedirectUri
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:RedirectUri"];
            }
        }
        public static string PostLogoutRedirectUri
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:PostLogoutRedirectUri"];
            }
        }

        public static string UrlEncode(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                return HttpUtility.UrlEncode(value);
            }

            return string.Empty;
        }
    }
}