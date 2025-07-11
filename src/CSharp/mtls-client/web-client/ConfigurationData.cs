using System.Security.Cryptography.X509Certificates;

namespace web_client
{

    public static class ConfigurationData
    {
        public static X509Certificate2 ClientCertificate { get; set; } = null!;
    }

}
