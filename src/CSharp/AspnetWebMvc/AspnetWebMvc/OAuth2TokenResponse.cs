namespace AspnetWebMvc
{
    public class OAuth2TokenResponse
    {
        public OAuth2TokenResponse() { }

        public string AccessToken { get; set; }
        public string IdToken { get; set; }
        public string RefreshToken { get; set; }
        public string TokenType { get; set; }
        public int ExpiresIn { get; set; }
    }
}