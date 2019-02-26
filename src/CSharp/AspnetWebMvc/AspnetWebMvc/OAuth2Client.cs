/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see Thinktecture.IdentityModel.License.txt
 */

using Newtonsoft.Json.Linq;
using OAuth2ClientSamples.Controllers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Web;

namespace AspnetWebMvc
{
    public class OAuth2Client
    {
        private Uri uri;

        private HttpClient _client;

        public OAuth2Client(Uri address)
        {
            this._client = new HttpClient()
            {
                BaseAddress = address
            };
        }

        public OAuth2Client(Uri address, string clientId, string clientSecret) : this(address)
        {
            this.uri = address;
            var byteArray = new UTF8Encoding().GetBytes(string.Format("{0}:{1}", clientId, clientSecret));
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
        }

        internal static string CreateAuthorizationUrl(string authority
                                                        , string clientId
                                                        , string scope
                                                        , string redirectUri
                                                        , string responseType
                                                        , string responseMode
                                                        , string maxAge
                                                        , string state = null
                                                        , string prompt=null)
        {
            string nonce = Guid.NewGuid().ToString("N");

            return OAuth2Client.CreateUrl(GenerateAuthorizeEndpoint(authority), clientId, scope, redirectUri, responseType
                            , responseMode, maxAge, state, prompt, nonce);
        }

        public OAuth2TokenResponse RequestAccessTokenCode(string code, Uri redirectUri, Dictionary<string, string> additionalProperties = null)
        {
            HttpResponseMessage result = this._client.PostAsync(GenerateTokenEndpoint(this.uri.AbsoluteUri), (HttpContent)this.CreateFormCode(code, redirectUri, additionalProperties)).Result;
            result.EnsureSuccessStatusCode();
            return this.CreateResponseFromJson(JObject.Parse(result.Content.ReadAsStringAsync().Result));
        }

        public OAuth2TokenResponse RequestAccessTokenRefreshToken(string refreshToken, Dictionary<string, string> additionalProperties = null)
        {
            HttpResponseMessage result = this._client.PostAsync(GenerateTokenEndpoint(this.uri.AbsoluteUri), (HttpContent)this.CreateFormRefreshToken(refreshToken, additionalProperties)).Result;
            result.EnsureSuccessStatusCode();
            return this.CreateResponseFromJson(JObject.Parse(result.Content.ReadAsStringAsync().Result));
        }

        private static string GenerateAuthorizeEndpoint(string authority)
        {
            return string.Format("{0}authorize.idp", authority);
        }

        private static string GenerateTokenEndpoint(string authority)
        {
            var endpoint = string.Format("{0}token.idp", authority);
            return endpoint;
        }

        private static string CreateUrl(string endpoint
                                , string clientId
                                , string scope
                                , string redirectUri
                                , string responseType
                                , string responseMode
                                , string maxAge
                                , string state = null
                                , string prompt = null
                                , string nonce = null)
        {
            string str = string.Format("{0}?client_id={1}&scope={2}&redirect_uri={3}&response_type={4}"
                , endpoint
                , ApplicationSettings.UrlEncode(clientId)
                , ApplicationSettings.UrlEncode(scope)
                , ApplicationSettings.UrlEncode(redirectUri)
                , ApplicationSettings.UrlEncode(responseType));
            if (!string.IsNullOrEmpty(maxAge))
            {
                str = string.Format("{0}&max_age={1}", str, ApplicationSettings.UrlEncode(maxAge));
            }
            if (!string.IsNullOrEmpty(responseMode))
            {
                str = string.Format("{0}&response_mode={1}", str, ApplicationSettings.UrlEncode(responseMode));
            }
            if (!string.IsNullOrWhiteSpace(state))
            {
                str = string.Format("{0}&state={1}", str, ApplicationSettings.UrlEncode(state));
            }
            if (!string.IsNullOrWhiteSpace(prompt))
            {
                str = string.Format("{0}&prompt={1}", str, ApplicationSettings.UrlEncode(prompt));
            }
            if (!string.IsNullOrWhiteSpace(nonce))
            {
                str = string.Format("{0}&nonce={1}", str, ApplicationSettings.UrlEncode(nonce));
            }
            return str;
        }

        private OAuth2TokenResponse CreateResponseFromJson(JObject json)
        {
            OAuth2TokenResponse accessTokenResponse = new OAuth2TokenResponse()
            {
                Access_Token = json["access_token"].ToString(),
                Id_Token = json["id_token"].ToString(),
                TokenType = json["token_type"].ToString(),
                ExpiresIn = int.Parse(json["expires_in"].ToString())
            };
            if (json["refresh_token"] != null)
                accessTokenResponse.Refresh_Token = json["refresh_token"].ToString();
            return accessTokenResponse;
        }

        protected virtual FormUrlEncodedContent CreateFormRefreshToken(string refreshToken, Dictionary<string, string> additionalProperties = null)
        {
            return OAuth2Client.CreateForm(new Dictionary<string, string>()
                    {
                        {
                            "grant_type",
                            "refresh_token"
                        },
                        {
                            "refresh_token",
                            refreshToken
                        }
                    }, additionalProperties);
        }

        protected virtual FormUrlEncodedContent CreateFormCode(string code, Uri redirectUri, Dictionary<string, string> additionalProperties = null)
        {
            return OAuth2Client.CreateForm(new Dictionary<string, string>()
                  {
                        {
                          "grant_type",
                          "authorization_code"
                        },
                        {
                          "redirect_uri",
                          redirectUri.AbsoluteUri
                        },
                        {
                          "code",
                          code
                        }
                  }, additionalProperties);
        }

        /// <summary>
        /// FormUrlEncodes both Sets of Key Value Pairs into one form object
        /// 
        /// </summary>
        /// <param name="explicitProperties"/><param name="additionalProperties"/>
        /// <returns/>
        private static FormUrlEncodedContent CreateForm(Dictionary<string, string> explicitProperties, Dictionary<string, string> additionalProperties = null)
        {
            return new FormUrlEncodedContent((IEnumerable<KeyValuePair<string, string>>)OAuth2Client.MergeAdditionKeyValuePairsIntoExplicitKeyValuePairs(explicitProperties, additionalProperties));
        }
        
        /// <summary>
         /// Merges additional into explicit properties keeping all explicit properties intact
         /// 
         /// </summary>
         /// <param name="explicitProperties"/><param name="additionalProperties"/>
         /// <returns/>
        private static Dictionary<string, string> MergeAdditionKeyValuePairsIntoExplicitKeyValuePairs(Dictionary<string, string> explicitProperties, Dictionary<string, string> additionalProperties = null)
        {
            Dictionary<string, string> dictionary = explicitProperties;
            if (additionalProperties != null)
                dictionary = Enumerable.ToDictionary(Enumerable.Concat(explicitProperties
                    , Enumerable.Where(additionalProperties
                    , (add => !explicitProperties.ContainsKey(add.Key))))
                    , (final => final.Key)
                    , (final => final.Value));
            return dictionary;
        }
    }
}