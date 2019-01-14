using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;

namespace AspnetWebMvc
{
    public class OAuth2TokenResponse
    {
        public OAuth2TokenResponse() { }

        public string Access_Token { get; set; }

        public string Id_Token { get; set; }


        public string Refresh_Token { get; set; }

        public string TokenType { get; set; }

        public int ExpiresIn { get; set; }

        public string Code { get; set; }

        public string Error { get; set; }

        public string Error_Description { get; set; }

        public string State { get; set; }
    }
}