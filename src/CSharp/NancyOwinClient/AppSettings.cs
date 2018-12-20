using System;
using System.Configuration;

namespace NancyOwinClient
{
    public class AppSettings
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
        public static string Scope
        {
            get
            {
                return ConfigurationManager.AppSettings["IdentifyOauth2:Scope"];
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
    }
}
