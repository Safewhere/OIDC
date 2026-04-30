#Requires -Version 5.1

param(
    [string]$Authority           = "https://identify.example.com/runtime/oauth2",
    [string]$ClientId            = "[Your App Client Id]",
    [string]$CertificatePath     = "[Path to your certificate]",
    [string]$CertificatePassword = "[Certificate password]",
    [string]$ApiEndpoint         = "https://localhost:7102/HelloWorld",
    [bool]  $UseDPoP             = $true,
    [ValidateSet("RS256","RS384","RS512","PS256","PS384","PS512")]
    [string]$DPoPAlg             = "PS256",
    [string]$DPoPMethod          = "POST",                               
    [bool]  $UseHttpSignatures   = $false
)

# ─── Load .NET assemblies needed for HttpClient ──────────────────────────────
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Security

# ─── Console Helpers ─────────────────────────────────────────────────────────

function Write-Header([string]$msg) {
    Write-Host "`n🚀 $msg" -ForegroundColor Magenta
    Write-Host ("=" * ($msg.Length + 3)) -ForegroundColor Magenta
}
function Write-Info([string]$msg)    { Write-Host "i  $msg" -ForegroundColor Cyan    }
function Write-Success([string]$msg) { Write-Host "OK $msg" -ForegroundColor Green   }
function Write-Err([string]$msg)     { Write-Host "!! $msg" -ForegroundColor Red     }
function Write-Warn([string]$msg)    { Write-Host "W  $msg" -ForegroundColor Yellow  }
function Write-Data([string]$label, [string]$value) {
    Write-Host "$label`: " -ForegroundColor DarkGray -NoNewline
    Write-Host $value      -ForegroundColor White
}
function Write-Json([string]$json) { Write-Host $json -ForegroundColor DarkYellow }

# ─── Base64Url Helpers ────────────────────────────────────────────────────────

function ConvertTo-Base64Url([byte[]]$bytes) {
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function ConvertFrom-Base64Url([string]$s) {
    $s = $s.Replace('-','+').Replace('_','/')
    switch ($s.Length % 4) {
        2 { $s += '==' }
        3 { $s += '='  }
    }
    return [Convert]::FromBase64String($s)
}

# ─── JWT read helpers (no validation) ────────────────────────────────────────

function Read-JwtSection([string]$token, [int]$index) {
    $part = $token.Split('.')[$index]
    return [System.Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $part))
}

# ─── Algorithm resolver (DPoP) ───────────────────────────────────────────────

function Resolve-AlgParams([string]$alg) {
    switch ($alg.ToUpper()) {
        "RS256" { return @{ Hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256; Padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 } }
        "RS384" { return @{ Hash = [System.Security.Cryptography.HashAlgorithmName]::SHA384; Padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 } }
        "RS512" { return @{ Hash = [System.Security.Cryptography.HashAlgorithmName]::SHA512; Padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 } }
        "PS256" { return @{ Hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256; Padding = [System.Security.Cryptography.RSASignaturePadding]::Pss   } }
        "PS384" { return @{ Hash = [System.Security.Cryptography.HashAlgorithmName]::SHA384; Padding = [System.Security.Cryptography.RSASignaturePadding]::Pss   } }
        "PS512" { return @{ Hash = [System.Security.Cryptography.HashAlgorithmName]::SHA512; Padding = [System.Security.Cryptography.RSASignaturePadding]::Pss   } }
        default { throw "Unsupported DPoP algorithm: $alg. Supported: RS256, RS384, RS512, PS256, PS384, PS512" }
    }
}

# ─── RSA Key Generation ───────────────────────────────────────────────────────

function New-RSAKeyPair {
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
    return $rsa
}

function Get-PublicJwk([System.Security.Cryptography.RSACryptoServiceProvider]$rsa) {
    $p = $rsa.ExportParameters($false)
    return [ordered]@{
        kty = "RSA"
        e   = ConvertTo-Base64Url $p.Exponent
        n   = ConvertTo-Base64Url $p.Modulus
    }
}

function Get-FullJwk([System.Security.Cryptography.RSACryptoServiceProvider]$rsa, [string]$alg) {
    $p = $rsa.ExportParameters($true)
    return [ordered]@{
        kty = "RSA"; alg = $alg
        e   = ConvertTo-Base64Url $p.Exponent
        n   = ConvertTo-Base64Url $p.Modulus
        d   = ConvertTo-Base64Url $p.D
        p   = ConvertTo-Base64Url $p.P
        q   = ConvertTo-Base64Url $p.Q
        dp  = ConvertTo-Base64Url $p.DP
        dq  = ConvertTo-Base64Url $p.DQ
        qi  = ConvertTo-Base64Url $p.InverseQ
    }
}

# ─── Compute JWK SHA-256 thumbprint (RFC 7638) ───────────────────────────────

function Get-JwkThumbprint([System.Security.Cryptography.RSACryptoServiceProvider]$rsa) {
    $pub = Get-PublicJwk $rsa
    $thumbprintJson = "{`"e`":`"$($pub.e)`",`"kty`":`"$($pub.kty)`",`"n`":`"$($pub.n)`"}"
    $sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    $hash   = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($thumbprintJson))
    $sha256.Dispose()
    return ConvertTo-Base64Url $hash
}

# ─── RSACng signing helper (supports both PKCS1 and PSS) ─────────────────────

function Invoke-RsaSign {
    param(
        [System.Security.Cryptography.RSACryptoServiceProvider]$Rsa,
        [byte[]]$Data,
        [System.Security.Cryptography.HashAlgorithmName]$Hash,
        [System.Security.Cryptography.RSASignaturePadding]$Padding
    )
    $rsaParams = $Rsa.ExportParameters($true)
    $rsaCng    = New-Object System.Security.Cryptography.RSACng(2048)
    $rsaCng.ImportParameters($rsaParams)
    $sig = $rsaCng.SignData($Data, $Hash, $Padding)
    $rsaCng.Dispose()
    return $sig
}

# ─── DPoP Proof Generator ────────────────────────────────────────────────────

function New-DPoPProof {
    param(
        [System.Security.Cryptography.RSACryptoServiceProvider]$Rsa,
        [string]$Alg,
        [string]$Method,
        [string]$Url,
        [string]$AccessToken = $null
    )

    $algParams = Resolve-AlgParams $Alg

    $jwk    = Get-PublicJwk $Rsa
    $header = [ordered]@{ typ = "dpop+jwt"; alg = $Alg; jwk = $jwk }
    $headerJson    = $header | ConvertTo-Json -Compress -Depth 5
    $headerEncoded = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($headerJson))

    $rng      = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $jtiBytes = New-Object byte[] 32
    $rng.GetBytes($jtiBytes)
    $rng.Dispose()

    $payload = [ordered]@{
        jti = ConvertTo-Base64Url $jtiBytes
        htm = $Method.ToUpper()
        htu = $Url
        iat = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }

    if ($AccessToken) {
        $sha256  = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
        $athHash = $sha256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($AccessToken))
        $sha256.Dispose()
        $payload["ath"] = ConvertTo-Base64Url $athHash
    }

    $payloadJson    = $payload | ConvertTo-Json -Compress
    $payloadEncoded = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
    $signingInput   = "$headerEncoded.$payloadEncoded"

    $sig = Invoke-RsaSign -Rsa $Rsa `
                          -Data ([System.Text.Encoding]::ASCII.GetBytes($signingInput)) `
                          -Hash $algParams.Hash `
                          -Padding $algParams.Padding

    return "$signingInput.$(ConvertTo-Base64Url $sig)"
}

# ─── HTTP Message Signatures (RFC 9421) ──────────────────────────────────────
# Server requirements (web-api\Program.cs RequestSignatureVerificationOptions):
#   AlgorithmRequired = CreatedRequired = ExpiresRequired = KeyIdRequired = TagRequired = true
#   TagsToVerify = ["nsign-example-client"]
#   Verification key extracted from DPoP embedded JWK → keyid must equal Get-JwkThumbprint

function New-HttpMessageSignature {
    param(
        [System.Security.Cryptography.RSACryptoServiceProvider]$Rsa,
        [string]$KeyId,
        [string]$Method,
        [string]$Url,
        [string]$SignatureName = "http-msg-sign"
    )

    $uri           = [System.Uri]$Url
    $createdOffset = [DateTimeOffset]::UtcNow.AddMinutes(-2)
    $expiresOffset = $createdOffset.AddMinutes(10)
    $created       = $createdOffset.ToUnixTimeSeconds()
    $expires       = $expiresOffset.ToUnixTimeSeconds()
    $nonce         = [System.Guid]::NewGuid().ToString("N")

    # Components match C# NSign order: RequestTargetUri, Method, Scheme, Authority
    $componentList  = '"@target-uri" "@method" "@scheme" "@authority"'
    $sigParamsValue = "($componentList)" +
                      ";created=$created" +
                      ";expires=$expires" +
                      ";nonce=`"$nonce`"" +
                      ";tag=`"nsign-example-client`"" +
                      ";alg=`"rsa-pss-sha512`"" +   # Required: AlgorithmRequired = true
                      ";keyid=`"$KeyId`""

    # RFC 9421 §2.5 signature base — LF separated, NOT CRLF
    $sigBaseLines = @(
        "`"@target-uri`": $($uri.AbsoluteUri)",
        "`"@method`": $($Method.ToUpper())",
        "`"@scheme`": $($uri.Scheme)",
        "`"@authority`": $($uri.Authority)",
        "`"@signature-params`": $sigParamsValue"
    )
    $signatureBase = $sigBaseLines -join "`n"
    $sigBaseBytes  = [System.Text.Encoding]::UTF8.GetBytes($signatureBase)

    Write-Info "HTTP Signature base:"
    Write-Json $signatureBase

    # RSA-PSS SHA-512 — matches C# RsaPssSha512SignatureProvider
    $sig       = Invoke-RsaSign -Rsa $Rsa `
                                -Data $sigBaseBytes `
                                -Hash ([System.Security.Cryptography.HashAlgorithmName]::SHA512) `
                                -Padding ([System.Security.Cryptography.RSASignaturePadding]::Pss)
    $sigBase64 = [Convert]::ToBase64String($sig)

    return @{
        SignatureInput = "$SignatureName=$sigParamsValue"
        Signature      = "${SignatureName}=:${sigBase64}:"
    }
}

# ─── SSL bypass (PS5 / .NET Framework) ───────────────────────────────────────

function Disable-SslValidation {
    if (-not ([System.Management.Automation.PSTypeName]'TrustAll').Type) {
        Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TrustAll {
    public static void Enable() {
        ServicePointManager.ServerCertificateValidationCallback =
            (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) => true;
    }
}
"@
    }
    [TrustAll]::Enable()
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.SecurityProtocolType]::Tls12 -bor
        [System.Net.SecurityProtocolType]::Tls11
}

# ─── HttpClient helpers ───────────────────────────────────────────────────────

function New-MtlsHttpClient([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.ClientCertificates.Add($Cert) | Out-Null
    return New-Object System.Net.Http.HttpClient($handler)
}

function New-PlainHttpClient {
    $handler = New-Object System.Net.Http.HttpClientHandler
    return New-Object System.Net.Http.HttpClient($handler)
}

# ─── Main ─────────────────────────────────────────────────────────────────────

try {
    Write-Header "mTLS Client Application Starting"

    $tokenEndpoint = "$Authority/mtls/token.idp"

    Write-Success "Configuration loaded successfully"
    Write-Data "Authority"           $Authority
    Write-Data "Client ID"           $ClientId
    Write-Data "API Endpoint"        $ApiEndpoint
    Write-Data "Use DPoP"            $UseDPoP.ToString()
    Write-Data "Use HTTP Signatures" $UseHttpSignatures.ToString()

    Disable-SslValidation

    # ── Key Generation — mirrors: if (useDpop || useHttpSignatures) ──────
    $rsa       = $null
    $keyId     = $null
    $dpopProof = $null

    if ($UseDPoP -or $UseHttpSignatures) {
        Write-Header "Key Generation"
        Write-Info "Generating RSA key pair with algorithm: $DPoPAlg"
        $rsa   = New-RSAKeyPair
        $keyId = Get-JwkThumbprint $rsa

        $jwkPublic = Get-PublicJwk $rsa
        Write-Data "JWK (public)"              ($jwkPublic | ConvertTo-Json -Compress)
        Write-Data "JWK Thumbprint (keyid)"    $keyId
        # Full JWK (dev only — mirrors WriteData("JWK", jwk) in C#)
        Write-Data "JWK (full/private — dev only)" ((Get-FullJwk $rsa $DPoPAlg) | ConvertTo-Json -Compress)

        Write-Success "Key pair generated successfully"
    }

    # ── DPoP for token request — mirrors DPoPProofRequest { Url, Method } ──
    if ($UseDPoP) {
        Write-Header "DPoP Token for Token Request"
        Write-Info "Generating DPoP token for token request (method: $DPoPMethod)"
        $dpopProof = New-DPoPProof -Rsa $rsa -Alg $DPoPAlg -Method $DPoPMethod -Url $tokenEndpoint
        Write-Data "Token Request DPoP Token" $dpopProof
        Write-Success "DPoP token for token request generated successfully"
    }

    # ── Certificate Loading ───────────────────────────────────────────────
    Write-Header "Certificate Loading"
    $clientCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                      $CertificatePath, $CertificatePassword,
                      [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
    Write-Success "Client certificate loaded successfully"
    Write-Data "Certificate Subject"    $clientCert.Subject
    Write-Data "Certificate Thumbprint" $clientCert.Thumbprint

    # ── Token Request (Client Credentials + mTLS) ─────────────────────────
    Write-Header "Token Request (Client Credentials Flow)"
    Write-Info "Requesting access token using client credentials flow with mTLS"
    Write-Data "Token Endpoint" $tokenEndpoint

    $mtlsClient = New-MtlsHttpClient $clientCert

    $formDict = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $formDict.Add("grant_type", "client_credentials")
    $formDict.Add("client_id",  $ClientId)            # mirrors request.Parameters.Add("client_id", clientId)
    $formContent = New-Object System.Net.Http.FormUrlEncodedContent($formDict)

    $tokenRequest         = New-Object System.Net.Http.HttpRequestMessage(
                                [System.Net.Http.HttpMethod]::Post, $tokenEndpoint)
    $tokenRequest.Content = $formContent

    if ($UseDPoP) {
        $tokenRequest.Headers.Add("DPoP", $dpopProof)
        Write-Info "DPoP header added to token request"
    }

    $tokenHttpResponse = $mtlsClient.SendAsync($tokenRequest).GetAwaiter().GetResult()
    $tokenBody         = $tokenHttpResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()

    if (-not $tokenHttpResponse.IsSuccessStatusCode) {
        Write-Err "Token request failed: $([int]$tokenHttpResponse.StatusCode) — $tokenBody"
        exit 1
    }

    Write-Success "Token request successful!"
    $tokenObj = $tokenBody | ConvertFrom-Json
    Write-Json ($tokenObj | ConvertTo-Json -Depth 5)

    $accessToken = $tokenObj.access_token
    $tokenType   = $tokenObj.token_type

    # ── Access Token Details ──────────────────────────────────────────────
    Write-Header "Access Token Details"
    Write-Info "Access Token (Header):"
    Write-Json (Read-JwtSection $accessToken 0)
    Write-Info "Access Token (Payload):"
    Write-Json (Read-JwtSection $accessToken 1)

    # ── API Call — mirrors CallRestApiWithStandardHandlerAsync ────────────
    Write-Header "API Call"
    $apiClient = New-PlainHttpClient   # mirrors: apiHandler.ClientCertificates.Clear()

    if ($UseDPoP) {
        Write-Header "Generate New DPoP Token for API Call"
        Write-Info "Generating fresh DPoP token for API request per RFC 9449"

        # Fresh proof per RFC 9449 with AccessToken → ath claim
        $apiDpopProof = New-DPoPProof -Rsa $rsa -Alg $DPoPAlg -Method "GET" `
                                      -Url $ApiEndpoint -AccessToken $accessToken
        Write-Data "API DPoP Token" $apiDpopProof
        Write-Success "Fresh DPoP token generated for API call"

        # Fix: mirrors apiHttpClient.DefaultRequestHeaders.Clear() before Add("DPoP")
        $apiClient.DefaultRequestHeaders.Clear()
        $apiClient.DefaultRequestHeaders.Add("DPoP", $apiDpopProof)
        Write-Info "Fresh DPoP header added to API request"
    }

    if ($UseHttpSignatures) {
        Write-Header "HTTP Message Signatures (RFC 9421)"
        Write-Info "Generating HTTP message signature (RSA-PSS SHA-512, matching NSign RsaPssSha512SignatureProvider)"
        Write-Data "Key ID" $keyId

        $httpSig = New-HttpMessageSignature -Rsa $rsa -KeyId $keyId -Method "GET" -Url $ApiEndpoint
        $apiClient.DefaultRequestHeaders.Add("Signature-Input", $httpSig.SignatureInput)
        $apiClient.DefaultRequestHeaders.Add("Signature",       $httpSig.Signature)
        Write-Data "Signature-Input" $httpSig.SignatureInput
        Write-Data "Signature"       $httpSig.Signature
        Write-Success "HTTP message signature headers added to API request"
    }

    $apiClient.DefaultRequestHeaders.Authorization =
        New-Object System.Net.Http.Headers.AuthenticationHeaderValue($tokenType, $accessToken)
    Write-Data "Authorization Scheme" $tokenType

    Write-Info "Sending HTTP request with custom HTTP Message Signatures"
    Write-Data "API Endpoint" $ApiEndpoint

    $apiResponse = $apiClient.GetAsync($ApiEndpoint).GetAwaiter().GetResult()
    $apiBody     = $apiResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()

    if ($apiResponse.IsSuccessStatusCode) {
        Write-Success "API call successful! Status: $([int]$apiResponse.StatusCode) $($apiResponse.ReasonPhrase)"
        Write-Info "API Response:"
        Write-Json $apiBody

        if ($UseHttpSignatures) {
            foreach ($h in $apiResponse.Headers) {
                if ($h.Key -match '^Signature') {
                    Write-Data $h.Key ($h.Value -join ", ")
                }
            }
        }
    }
    else {
        Write-Err "API call failed: $([int]$apiResponse.StatusCode) $($apiResponse.ReasonPhrase)"
        if ($apiBody) { Write-Err "Error Content: $apiBody" }
    }

    Write-Header "Application Completed"
    Write-Info "Press any key to exit..."
    Read-Host
}
catch {
    Write-Err "Application failed with exception: $($_.Exception.Message)"
    if ($_.Exception.InnerException) {
        Write-Err "Inner Exception: $($_.Exception.InnerException.Message)"
    }
    exit 1
}
finally {
    if ($rsa)        { $rsa.Dispose()        }
    if ($mtlsClient) { $mtlsClient.Dispose() }
    if ($apiClient)  { $apiClient.Dispose()  }
}