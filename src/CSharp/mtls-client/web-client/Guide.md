# Solution Guide: ASP.NET Core OIDC mTLS Web Client & API

This solution demonstrates a secure integration between a Razor Pages web client and a Web API using OpenID Connect (OIDC) with mTLS (mutual TLS) for the token endpoint and certificate-bound access tokens.

---

## Projects Overview

### 1. web-client (ASP.NET Core Razor Pages Application)
- Provides OIDC login with an external provider (Identify Tenant).
- Uses a client certificate for mTLS at the token endpoint.
- Displays Access Token and Identity Token after login.
- Allows users to call the HelloWorld API through a server-side proxy that includes the client certificate in the HTTPS connection.

### 2. web-api (ASP.NET Core Web API)
- Secured with JWT Bearer authentication.
- Validates the JWT signature and the `cnf` claim against the client certificate provided via mTLS.
- Exposes a HelloWorld endpoint that requires a valid, certificate-bound access token.

---

## Configuration Steps

Configuration steps to Ctr-F5 run the solution locally:

### Prerequisites
- .NET 8 SDK installed
- A valid Identify Tenant setup with mTLS support, and lets say `https://identify.example.com/`. Search and replace `identify.example.com` with your actual tenant domain.
- A client certificate in PFX format for mTLS authentication (with private key).
- A public certificate for the web-api to validate the JWT signature and the `cnf` claim.

#### Additional setup on web server 
 
Add the 2 following registry keys to your Identify server in case they haven't been added before: 

1. Open the registry on Identify server. 
2. Go to: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
   - Add the key: "SendTrustedIssuerList" (DWORD) with the value: 0. In case this key exists, set it 0  
   - Add the key: "ClientAuthTrustMode" (DWORD) with the value: 2. In case this key exists, set it 2   

3. Exit the registry and reset the Identify server   
4. Reboot the Identify server 

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

8. Import the public key of self-signed CAs to **LocalMachine\Trusted Root Certificate Authority**.

### Generate the client jwks for the client Certificate

Given that you have a client certificate with .pfx format.

Follow the steps:

1. Extract public key from PFX:

```bash
openssl pkcs12 -in client.pfx -clcerts -nokeys -out client-cert.pem
```

2. Open the below content using Windows PowerShell ISE (Run as Administrator)

```powershell
# Path to your PEM file
$pemPath = "C:\temp\client-cert.pem"

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

3. Update path to your PEM file on `$pemPath`
4. Execute the script.
5. Convert PEM to JWK:

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

### Resolve error 500.19 when calling Identify mTLS endpoint

You can encounter error: `Internal Server Error` from IIS when invoking the mTLS endpoint. It is due to the error code: `500.19.33` which relates to the Config error code.

Here's a checklist to help you troubleshoot:

1. Ensure to import the public key of self-signed CAs is to **LocalMachine\Trusted Root Certification Authorities**.
2. Unlock the configuration on IIS: 
- Access IIS, open Configuration editor on the Runtime of the tenant website. 
- Access section: `system.webServer/security/access`
- Choose "Unlock Section" 

### Configure the web-client

1. Prepare your OAuth/OIDC connection in Identify Tenant

   Log in **Admin UI portal**. Create a new OIDC client in your Identify Tenant with the following settings:
   - Connection tab:
   	 - **Client ID**: Your application client ID
	 - **Client Secret**: Your application client secret
     - **Client jwks**: input its JWK format as generate above
     - **Allowed Callback URIs**: `https://localhost:5254/signin-oidc`
     - **Post Logout Redirect URI**: `https://localhost:5254/signout-callback-oidc`
     - **Security token audiences**: `https://localhost:7102/` 


   - Security tab:
     - **JWS algorithm**: `RSASigning`
     - **Allow Http Redirects**: Enabled
     - **Allow Code Flow**: Enabled

2. Place your client certificate (PFX) in a secure location and update the path and password in configuration.
3. Update `appsettings.json` in the web-client project with your Identify Tenant details:

```JSON
"OIDC": {
      "Authority": "https://identify.example.com/runtime/oauth2",
      "ClientId": "[Your client Id]",
      "CallbackPath": "/signin-oidc",
      "Certificate": {
        "Path": "[full file path to your PFX certificate (include a private key)]",
        "Password": "[the certificate password]"
      }
    }
```
Api configuration:

```JSON
"Api": {
    "HelloWorldUrl": "https://localhost:7102/HelloWorld"
  }
```
Just keep it as it is, this is the default API endpoint when running locally.

4. Run the web-client:dotnet run --project ./web-client/web-client.csproj
   As result, the web-client will start on `https://localhost:5254`. (see the configuration in `launchSettings.json`)

### 2. Configure the web-api
1. Update `appsettings.json` in the web-api project with your JWT authority, audience, and the path to the public certificate for signature and the `cnf` claim validation.

```JSON
"Jwt": {
    "Authority": "https://identify.example.com/runtime/oauth2",
    "Audience": "https://localhost:7102/",
    "Certificate": {
      "Path": "[Full path to the public certificate to validate the signature and the `cnf` claim]"
    }
  }
```

2. Run the web-api:dotnet run --project ./web-api/web-api.csproj
As a result , the web-api will start on `https://localhost:7102`. (see the configuration in `launchSettings.json`)

---

## How to Use the Solution

### 1. Obtain an Access Token using the web-client
- Start the web-client and log in with your Identify tenant via the browser.
- After successful authentication, the home page will display your Access Token and Identity Token.
- Copy the Access Token for use in API requests.

### 2. Call the HelloWorld API
- Use the web-client UI or a tool like `curl` to call the HelloWorld endpoint.
- You must provide:
  - The `Authorization: Bearer <access_token>` header (from the web-client)
  - A client certificate via mTLS connection for certificate-bound token validation
- The web-client provides a button "Call HelloWorld API" to call the API with the necessary headers and automatically includes the client certificate via mTLS connection.

### 3. Expected Response
Hello, World!
---

## Notes
- The authorize endpoint does not require mTLS, but the token endpoint does.
- The API will reject requests if the access token is missing, invalid, or the client certificate does not match the `cnf` claim in the token.
- Both projects target .NET 8.
