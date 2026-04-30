# Solution Guide: ASP.NET Core OIDC mTLS Web Client & API with DPoP Support

This solution demonstrates a secure integration between a Razor Pages web client using OpenID Connect (OIDC) and a console app using the Client Credentials with mTLS (mutual TLS) for the token endpoint and certificate-bound access tokens. Both applications support **DPoP (Demonstration of Proof-of-Possession)** per RFC 9449 for enhanced security.
Both applications then will use the Access token to call an example REST API.

Support **HTTP Message Signatures** per RFC 9421 for enhanced request integrity and authenticity. By default, the feature is disabled and can be enabled via configuration.

---

## Projects Overview

### web-client (ASP.NET Core Razor Pages Application)
- Provides OIDC login with an external provider (Identify Tenant).
- Uses a client certificate for mTLS at the token endpoint.
- Displays Access Token after login.
- Allows users to call the HelloWorld API through a server-side proxy that includes the client certificate in the HTTPS connection.

### Console app (Client Credentials Flow with mTLS and DPoP Support)

- Demonstrates how a non-interactive client (console application) can obtain an access token using the OAuth2 Client Credentials flow with mutual TLS (mTLS) at the token endpoint.
- Supports DPoP (Demonstration of Proof-of-Possession) per RFC 9449 for enhanced token security.
- Uses a client certificate to authenticate to the token endpoint and receive a certificate-bound access token.
- Generates fresh DPoP proof tokens for both token requests and API calls, ensuring proper proof-of-possession validation.
- Supports HTTP Message Signatures per RFC 9421 when calling the API endpoint.
- Calls the HelloWorld API endpoint using the access token and the same client certificate for mTLS.
- Validates the API response to ensure successful authentication and authorization.

### Invoke-MtlsClient.ps1 under powershell-script folder

A PowerShell 5.1 script that replicates the functionality of the .NET `console app`

It demonstrates:

- **mTLS** client certificate authentication for token requests
- **DPoP** (RFC 9449) proof-of-possession tokens
- **HTTP Message Signatures** (RFC 9421) on API calls

| Parameter  | Description |
|---|---|
| `Authority` | OAuth2 authorization server base URL, such as `https://identify.example.com/runtime/oauth2` |
| `ClientId` | Client ID registered at the authority, such as `clientid_mTLS-console-app` |
| `CertificatePath` | Full path to the mTLS client certificate, such as `C:\Temp\mTLS Testcertificate.pfx` |
| `CertificatePassword` | Password for the .pfx file |
| `ApiEndpoint` | Resource server endpoint to call, such as `https://localhost:7102/HelloWorld` |
| `UseDPoP` | Enable DPoP proof tokens. Default is `$true`|
| `DPoPAlg` | DPoP signing algorithm (`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`). Default is `PS256` |
| `DPoPMethod` | HTTP method for the token-request DPoP proof. Default is `POST` |
| `UseHttpSignatures` | Enable HTTP Message Signatures (RFC 9421) on the API call. Default is  `$false` |

Sample:

- Run with DPoP only (default)

```powershell

.\Invoke-MtlsClient.ps1 -Authority "https://identify01new.identify.safewhere.com/runtime/oauth2" `
    -ClientId "clientid_mTLS-console-app" `
    -CertificatePath "c:\Temp\mTLS Testcertificate.pfx" `
    -CertificatePassword "Test!234" `
    -ApiEndpoint "https://localhost:7102/HelloWorld" `
    -UseDPoP $true `
    -DPoPAlg "PS256" `
    -UseHttpSignatures $false
```

![Sample 01](powershell-script/sample-01.png)

- Run with DPoP + HTTP Message Signatures

```powershell

.\Invoke-MtlsClient.ps1 -Authority "https://identify01new.identify.safewhere.com/runtime/oauth2" `
    -ClientId "clientid_mTLS-console-app" `
    -CertificatePath "c:\Temp\mTLS Testcertificate.pfx" `
    -CertificatePassword "Test!234" `
    -ApiEndpoint "https://localhost:7102/HelloWorld" `
    -UseDPoP $true `
    -DPoPAlg "PS256" `
    -UseHttpSignatures true
```
![Sample 02](powershell-script/sample-02.png)

### web-api (ASP.NET Core Web API with DPoP Validation)
- Secured with JWT Bearer authentication.
- Comprehensive DPoP proof validation according to RFC 9449 including:
  - DPoP proof JWT signature verification using embedded JWK
  - Access token binding validation via `cnf.jkt` claims
  - HTTP method (`htm`) and URI (`htu`) claim validation
  - `jti` validation for replay protection is ignored for this demo web api.
- HTTP Message Signatures validation per RFC 9421 using the **NSign library**.
- Validates the JWT signature and the `cnf` claim against the client certificate provided via mTLS.
- Configurable DPoP enforcement mode - can require DPoP authentication or accept both DPoP and Bearer tokens.
- Exposes a HelloWorld endpoint that requires a valid, certificate-bound access token.

---

## Configuration Steps

Configuration steps to Ctrl-F5 run the solution locally:

### Prerequisites
- .NET 8 SDK installed
- A valid Identify Tenant setup with mTLS support, and lets say `https://identify.example.com/`. Search and replace `identify.example.com` with your actual tenant domain.
- A client certificate in PFX format for mTLS authentication (with private key).
- A public certificate for the web-api to validate the JWT signature and the `cnf` claim.

#### Generate a self-signed client certficate from a self-signed CA

##### Generate the self-signed CA

1. Open the below content using Windows PowerShell ISE (Run as Administrator)

```PowerShell
# Set certificate parameters
$certPath = "C:\temp"
$caName = "Globeteam CA"
$pfxPassword = ConvertTo-SecureString -String "Test!234" -Force -AsPlainText
$startDate = Get-Date "07/01/2025"
$endDate = Get-Date "12/31/2033"

# 1. reate folder if it doesn't exist
if (-not (Test-Path $certPath)) {
    New-Item -ItemType Directory -Path $certPath | Out-Null
}

# 2. Create self-signed root CA certificate in the LocalMachine\My store
$rootCert = New-SelfSignedCertificate `
    -Subject "CN=$($caName), DC=com" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyExportPolicy Exportable `
    -KeyUsage CertSign, CRLSign, DigitalSignature `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
    -KeySpec 1 `
    -NotBefore $startDate `
    -NotAfter $endDate `
    -KeyLength 2048 `
    -Type Custom `
    -TextExtension @("2.5.29.19={critical}{text}ca=true") # Mark as CA

# 3. Export the root CA to a .cer file
$exportPath = Join-Path $certPath "$($caName).cer"
Export-Certificate -Cert $rootCert -FilePath $exportPath

# 4. Export the root CA to .pfx
Export-PfxCertificate -Cert $rootCert -FilePath "$certPath\$($caName).pfx" -Password $pfxPassword

# 5. Remove certificate from LocalMachine\My store
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "My", "LocalMachine"
$store.Open("ReadWrite")

$certToRemove = $store.Certificates | Where-Object { $_.Thumbprint -eq $rootCert.Thumbprint }

if ($certToRemove) {
    Write-Host "Removing certificate with thumbprint $($rootCert.Thumbprint)"
    $store.Remove($certToRemove)
} else {
    Write-Warning "Certificate with thumbprint $($rootCert.Thumbprint) not found in store."
}

$store.Close()
```

2. Update its parameters:

	- `$certPath`: Specify path to store the CA file.
	- `$caFileName`: Specify CA file name.
	- `$pfxPassword`: Default password is `Test!234`
	- `$startDate` and `$endDate`: Specify certificate validity

3. Execute the script.

A self-signed CA is generated, and located under `$certPath`.

##### Generate the self-signed client certificate issued from above CA

1. Open the below content using Windows PowerShell ISE (Run as Administrator)

```powershell
# Set certificate parameters
$certPath = "C:\temp"
$caName = "Globeteam CA"
$capfxPath = "$certPath\$($caName).pfx"
$clientCertName = "mTLS Testcertificate"
$capfxPassword = ConvertTo-SecureString -String "Test!234" -Force -AsPlainText
$clientpfxPassword = ConvertTo-SecureString -String "Test!234" -Force -AsPlainText
$startDate = Get-Date "07/01/2025"
$endDate = Get-Date "12/31/2033"

# 1. Check if CA PFX exists
if (-not (Test-Path $capfxPath)) {
    Write-Error "CA certificate file not found: $capfxPath"
    exit 1
}

# 2. Load CA from PFX with private key
$caCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$caCert.Import($capfxPath, $capfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet)

# 3. Add CA cert to LocalMachine\My store (required for use with -Signer)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "My", "LocalMachine"
$store.Open("ReadWrite")
$store.Add($caCert)
$store.Close()

Write-Host "CA certificate imported with thumbprint: $($caCert.Thumbprint)"

# 4. Create a certificate signed by the CA
$clientCert = New-SelfSignedCertificate `
    -Subject "CN=$clientCertName" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyExportPolicy Exportable `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
    -KeySpec 1 `
    -NotBefore $startDate `
    -NotAfter $endDate `
    -KeyLength 2048 `
    -Signer $caCert `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") # EKU: Server Auth, Client Auth

# 5. Export the client certificate
Export-Certificate -Cert $clientCert -FilePath "$certPath\$($clientCertName).cer"
Export-PfxCertificate -Cert $clientCert -FilePath "$certPath\$($clientCertName).pfx" -Password $clientpfxPassword
# 6. Clean up: remove client cert from store
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "My", "LocalMachine"
$store.Open("ReadWrite")

$certToRemove = $store.Certificates | Where-Object { $_.Thumbprint -eq $clientCert.Thumbprint }
if ($certToRemove) {
    Write-Host "Removing client certificate with thumbprint $($clientCert.Thumbprint)"
    $store.Remove($certToRemove)
} else {
    Write-Warning "Client certificate not found for cleanup."
}

# 7. Clean up: remove CA cert from store
$caToRemove = $store.Certificates | Where-Object { $_.Thumbprint -eq $caCert.Thumbprint }
if ($caToRemove) {
    Write-Host "Removing CA certificate with thumbprint $($caCert.Thumbprint)"
    $store.Remove($caToRemove)
} else {
    Write-Warning "CA certificate not found for cleanup."
}

$store.Close()
```

2. Update its parameters:

	- `$certPath`: Specify path to store the client certificate file.
	- `$caName`: Specify CA name.
	- `clientCertName`: Specify client certificate name.
	- `$capfxPassword`: Default password for CA certificate is `Test!234`
	- `$pfxPassword`: Default password for generated client certificate is `Test!234`
	- `$startDate` and `$endDate`: Specify certificate validity of the client certificate.

3. Execute the script.

A self-signed client certificate is generated, and located under `$certPath`.

#### Additional setup on web server 
 
To ensure proper mutual TLS authentication, add or update the following registry keys on your Identify server if they haven't been configured yet:

1. Open the registry editor on Identify server. 
2. Navigate to: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL

- Add the key: `SendTrustedIssuerList` (DWORD) with the value `0`. If this key already exists, set its value to `0`. This setting prevents the server from sending the list of trusted certificate authorities to clients during the TLS handshake, which can reduce handshake size and may help avoid issues with clients that cannot handle large or complex issuer lists.
- Add the key: `ClientAuthTrustMode` (DWORD) with the value `2`. If this key already exists, set its value to `2`. This instructs the server to trust client certificates based only on explicitly trusted intermediate CAs, so you do not need to add each client certificate individually to the server's trusted store.

For more details on default values and behaviors of ClientAuthTrustMode, refer to the official documentation: https://learn.microsoft.com/en-us/windows-server/security/tls/what-s-new-in-tls-ssl-schannel-ssp-overview
    
1. Exit the registry editor. 
2. Reboot the Identify server to apply the changes.   

#### Disable client certificate revocation at IIS 

This step is needed when we use client certificates from self-signed CAs. Therefore, we need to disable Client Certificate Revocation at the IIS level. In this sample, my Identify site is identify01.identify.safewhere.com

1. Run the CMD as Administrator
2. Run this command line:

```powershell
netsh http show sslcert
```

3. Verify the value for "Verify Client Certificate Revocation". If it's "Enabled", we need to go to the next step.
4. Backup the certificate Hash and hostname:port  
5. Delete the existing binding with the next command line:

```powershell
netsh http delete sslcert hostnameport=identify.example.com:443
```

6. Add the binding again using netsh as shown below:

```powershell
netsh http add sslcert hostnameport=identify.example.com:443 certhash=0fbabd59cbfc2e478ff5b629463cd0fd06b23d66 appid={4dc3e181-e14b-4a21-b022-59fc669b0914} certstorename=My verifyclientcertrevocation=disable
```
7. Run this command line:

```powershell
netsh http show sslcert
```

to verify the value at "Verify Client Certificate Revocation". They must be disabled. 

8. Import the public key of self-signed CAs to **LocalMachine\Trusted Root Certification Authorities**.

### Generate the client jwks for the client Certificate

Given that you have already a client certificate with .pfx format. follow the steps below:

1. Open the below content using Windows PowerShell ISE (Run as Administrator)

```powershell
# Set certificate parameters
$certPath = "C:\temp"
$clientCertName = "mTLS Testcertificate"
$pfxPath = "$certPath\$($clientCertName).pfx"
$pemPath = "$certPath\$($clientCertName).pem"
$pfxPassword = ConvertTo-SecureString -String "Test!234" -AsPlainText -Force

# Load the certificate from PFX
$pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$pfxCert.Import($pfxPath, $pfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

# Export the certificate part as Base64 (PEM format)
$pemContent = "-----BEGIN CERTIFICATE-----`n" +
              [Convert]::ToBase64String($pfxCert.RawData, 'InsertLineBreaks') +
              "`n-----END CERTIFICATE-----"

# Write to file
Set-Content -Path $pemPath -Value $pemContent -Encoding ascii
```

2. Update its parameters:

	- `$certPath`: Specify path to store the client certificate file.
	- `$filename`: Specify client certificate name.
	- `$pfxPassword`: Specify password for client certificate. Default is `Test!234`

3. Execute the script. Then, a self-signed PEM file is generated, and located under `$certPath`.

4. Open the below content using Windows PowerShell ISE

```powershell
# Set certificate parameters
$certPath = "C:\temp"
$clientCertName = "mTLS Testcertificate"
$pemPath = "$certPath\$($clientCertName).pem"

# Read the file and isolate the base64 certificate lines
$pemContent = Get-Content $pemPath -Raw
$base64Cert = ($pemContent -split "`r?`n" | Where-Object {
    $_ -match '^[A-Za-z0-9+/=]+$'
}) -join ""

# Convert to byte array (DER format)
$certBytes = [Convert]::FromBase64String($base64Cert)

# Compute SHA-1 hash
$sha1 = [System.Security.Cryptography.SHA1]::Create()
$hashBytes = $sha1.ComputeHash($certBytes)

# Encode as base64url (no padding, -/_ instead of +/)
$base64Url = [Convert]::ToBase64String($hashBytes).Replace('+','-').Replace('/','_').Replace('=','')

# Output the key ID
Write-Output "kid: $base64Url"

```

5. Update its parameters:

	- `$certPath`: Specify path to store the client certificate file.
	- `$filename`: Specify client certificate name.
	
6. Execute the script.
7. Convert PEM to JWK:

- Go to [jwkset.com/generate](https://jwkset.com/generate):
	- Paste your PEM content to **PEM encoded key or certificate** text input.
	
```
-----BEGIN CERTIFICATE-----
base64-cert
-----END CERTIFICATE-----
```

	- Input the kid value collected from previous step.
	- Select **RS256** under the **Key algorithm** dropdown list.
	- Select **Signature** under the **Key use** dropdown list
	- Press **Generate** button.
 
Here is an example of a generated JSON Web Key:

```JSON
{
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "your-key-id",
    "x5c": [
        "base64-cert"
    ],
    "x5t": "your-key-id",
    "x5t#S256": "AbrsA....w_g",
    "n": "base64url-modulus",
    "e": "AQAB"
}
```

Note: You can also use the sample file `mTLS Testcertificate.pfx` (password: `Test!234`), which is issued by the self-signed `Globeteam CA` and located in the `Certificates` folder.

Here is its JSON Web Key:

```JSON
{
  "kty": "RSA",
  "use": "sig",
  "alg": "RS256",
  "kid": "HS77HforPCQsrfsNtAFW96vifPk",
  "x5c": [
    "MIIDRjCCAi6gAwIBAgIQHlBEkrUOlYhPnY2qlqvp5DANBgkqhkiG9w0BAQsFADAsMRMwEQYKCZImiZPyLGQBGRYDY29tMRUwEwYDVQQDDAxHbG9iZXRlYW0gQ0EwHhcNMjUwNjMwMTcwMDAwWhcNMzMxMjMwMTcwMDAwWjAfMR0wGwYDVQQDDBRtVExTIFRlc3RjZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN0v09GMQxzXYFtNuzzm2wDt2obvb1hCy4NVhGlX8bdQ/RK3t5hu5JZf93iDwf1RQT9yyhqgNJq3SK1v1JuqiXm5qtQltaQqc6Qtp52rxFz7v/HudwTQlm2JHxwUofBll/AHj+Cy+VRNiuHmT44MR6WoktHBCLn24HCpEJ32m6x5yzpCufR99ToV9uZiy/jICNbWYc+s74rJ/5m2yeOb6CXucoSlW3DJMO6eu58av64hlaESgi2+spJnVkimz746+u4lkIhnSCvmKcGLnzJDPMfo8k8kQtjf9EEskEbXG6YH9BgYxxKyww+9zE7cRoKmt+fUr94yKScyUP155NfsY8kCAwEAAaNxMG8wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBQ/r39C5X92De30IWETcX6ia+GeFzAdBgNVHQ4EFgQU6iGrlvMsFXPY615Q54ZCzoGXkX4wDQYJKoZIhvcNAQELBQADggEBAISgcoraSnCdOxDTp0DjR6R5KwLnfhJDcOimAoUjS4VeyiAxmcGkCyt18Xhfg//YvYjajHIRpVjYiq458obSPsaE4MBw9JKitaX1rz8Vp2ZjzyGv5/tVIL6/2WP+D0qehpJfSA6AI8SjNzTsWsHZTz7gsMHLci7nKj8fjFH/sFIhnCOSgn2fysfC4nRng3GWVKWNU9yhuZmeki/tf6jtQLZTB7DJJ8D/7BbuVKOokw6agUJlFTHsvpkzkUAOKNdfJCGhoswej3fkvijiu93ZiyofcaXXLEln5y4KiL1nUYQPbhMD/21rm+8K57sBIU0vJORoWIk0j19us+sJ71FATUA="
  ],
  "x5t": "HS77HforPCQsrfsNtAFW96vifPk",
  "x5t#S256": "FumM1Xqmy-CEBVNY8ukrerAz6JGl_qdzv2ei14RqZNY",
  "n": "3S_T0YxDHNdgW027PObbAO3ahu9vWELLg1WEaVfxt1D9Ere3mG7kll_3eIPB_VFBP3LKGqA0mrdIrW_Um6qJebmq1CW1pCpzpC2nnavEXPu_8e53BNCWbYkfHBSh8GWX8AeP4LL5VE2K4eZPjgxHpaiS0cEIufbgcKkQnfabrHnLOkK59H31OhX25mLL-MgI1tZhz6zvisn_mbbJ45voJe5yhKVbcMkw7p67nxq_riGVoRKCLb6ykmdWSKbPvjr67iWQiGdIK-YpwYufMkM8x-jyTyRC2N_0QSyQRtcbpgf0GBjHErLDD73MTtxGgqa359Sv3jIpJzJQ_Xnk1-xjyQ",
  "e": "AQAB"
}
```

### Resolve error 500.19 when calling Identify mTLS endpoint

You may encounter an `Internal Server Error` from IIS when invoking the mTLS endpoint. This typically corresponds to error code `500.19`, which indicates a configuration issue in the site's web.config.

Here's a checklist to help you troubleshoot on Identify web server:

1. Ensure that the public key of your self-signed CA is imported to: **LocalMachine\Trusted Root Certification Authorities** 
2. Unlock configuration in IIS: 
- Access IIS, open **Configuration editor** on the Runtime of the tenant website. 
- Expand the section: `system.webServer/security/access`
- Click "Unlock Section" to allow modifications to access-related configuration

### Configure the web-api

1. Update `appsettings.json` in the web-api project with your JWT authority and audience.

```JSON
"Jwt": {
    "Authority": "https://identify.example.com/runtime/oauth2",
    "Audience": "https://localhost:7102/",
    "EnforceDpop": true
  },
"HttpSignatures": {
    "Enabled": true,
    "MaxAge": 300
  }
```

**DPoP Configuration:**
- `EnforceDpop`: Set to `true` to require DPoP authentication for all requests, or `false` to accept both DPoP and Bearer tokens (default: `false`)

**HTTP Message Signatures Configuration:**
- `Enabled`: Set to `true` to enable HTTP Message Signatures validation, `false` to disable (default: `false`)
- `MaxAge`: Maximum age in seconds for signature freshness validation (default: `300`)

Make sure the self-signed CA that issued the client certificates is imported into the **LocalMachine\Trusted Root Certification Authorities** store on the server hosting the web API.

2. Run the web-api:dotnet run --project ./web-api/web-api.csproj

As a result , the web-api will start on `https://localhost:7102`. (see the configuration in `launchSettings.json`)

### Configure the console-app

1. Prepare your OAuth connection in Identify Tenant

   Log in **Admin UI portal**. Create a new OAuth application in your Identify Tenant with the following settings:
   - Connection tab:
   	 - **Client ID**: Your application client ID
	 - **Client Secret**: Fill a dummy value.
     - **Client jwks**: input its JWK format as generate above

     
        ```JSON	 
	         {
            "keys": [
                jwk01, jwk02
            ]
        }
        ```

        Where, `jwk01` and `jwk02` are JSON Web Key objects.


     - **Allowed Callback URIs**: Fill a dummy value, e.g. `https://identify.test.example.com/runtime`
     - **Security token audiences**: `https://localhost:7102/` 


   - Security tab:
     - **JWS algorithm**: `RSASigning`
     - **Allow Client Credentials Flow**: Enabled

2. Place your client certificate (PFX) in a secure location and update the path and password in configuration.
3. Update `App.config` in the console-app project with your Identify Tenant details:

```XML
  <appSettings>
    <add key="Authority" value="https://identify.example.com/runtime/oauth2" />
    <add key="ClientId" value="[Your App Client Id]" />
    <add key="CertificatePath" value="[Path to your certificate]" />
    <add key="CertificatePassword" value="[Certificate password]" />
    <add key="ApiEndpoint" value="https://localhost:7102/HelloWorld"/>
    <add key="UseDpop" value="True"/>
    <add key="DpopAlg" value="PS256"/>
    <add key="DpopMethod" value="POST"/>
    <add key="UseHttpSignatures" value="False"/>
    <add key="UseOidcClientPackage" value="True"/>
  </appSettings>
```

**DPoP Configuration Options:**
- `UseDpop`: Set to `True` to enable DPoP proof generation, `False` for standard Bearer token flow (default: `False`)
- `DpopAlg`: Cryptographic algorithm for DPoP proof signing. Supported algorithms: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512` (default: `PS256`)
- `DpopMethod`: HTTP method for token endpoint requests (default: `POST`)

**HTTP Message Signatures Configuration Options:**
- `UseHttpSignatures`: Set to `True` to enable HTTP Message Signatures generation, `False` to disable (default: `False`)

Just keep `ApiEndpoint` as it is, this is the default API endpoint when running locally.

The Console app demonstrates calling the REST API with DPoP proof and Access token using both the `Duende.IdentityModel.OidcClient` package and the built-in .NET `HttpClientHandler`.
Control the usage of `Duende.IdentityModel.OidcClient` for API calls via the `UseOidcClientPackage` setting.

4. Run the console-app:dotnet run --project ./console-app/console-app.csproj

As result, the console-app will start.

### Call the HelloWorld API
- Use the web-client UI or a tool like `curl` to call the HelloWorld endpoint.
- You must provide:
  - The `Authorization: Bearer <access_token>` header (from the web-client)
  - A client certificate via mTLS connection for certificate-bound token validation
- The web-client provides a button "Call HelloWorld API" to call the API with the necessary headers and automatically includes the client certificate via mTLS connection.

### Expected Response
Hello, World!

---

## Notes
- The API will reject requests if the access token is missing, invalid.
- **DPoP Notes**:
  - When DPoP is enabled, the API validates key binding (`cnf.jkt`)
  - DPoP proofs must be fresh (generated within 5 minutes) and unique (different `jti` values)
  - The console app automatically generates fresh DPoP proofs for each API call to comply with RFC 9449
  - DPoP enforcement can be configured per environment - useful for gradual rollout
- **HTTP Message Signatures Notes**:
  - Uses **NSign library** for professional RFC 9421 compliance
  - When enabled, requests must include valid `Signature` and `Signature-Input` headers
  - Signatures are validated against the expected components and algorithm
  - Signature freshness is enforced (default 5-minute window)
- All projects target .NET 8.
