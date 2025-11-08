using Duende.IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace web_api
{
    public static class DPoPValidator
    {
        // Helper method to validate DPoP proof token according to RFC 9449
        public static (bool IsValid, string ErrorCode, string ErrorMessage) ValidateDPoPProof(string dpopHeader, HttpContext httpContext, SecurityToken? accessToken)
        {
            try
            {
                if (string.IsNullOrEmpty(dpopHeader))
                {
                    return (false, "dpop_required", "DPoP header is missing");
                }
                
                Console.WriteLine("[DPOP] Starting comprehensive DPoP validation per RFC 9449");
                
                // STEP 1: Parse the DPoP proof JWT
                var handler = new JwtSecurityTokenHandler();
                if (!handler.CanReadToken(dpopHeader))
                {
                    return (false, "invalid_dpop_proof", "Invalid DPoP proof token format");
                }
                
                var dpopToken = handler.ReadJwtToken(dpopHeader);
                Console.WriteLine("   [SUCCESS] DPoP proof JWT parsed successfully");
                
                // STEP 2: Validate DPoP proof JWT structure and headers
                // Validate typ header
                if (!dpopToken.Header.TryGetValue("typ", out var typ) || !typ.Equals("dpop+jwt"))
                {
                    return (false, "invalid_dpop_proof", "Invalid typ header in DPoP proof - must be 'dpop+jwt'");
                }
                
                // Validate alg header (must be asymmetric algorithm)
                if (!dpopToken.Header.TryGetValue("alg", out var alg) || string.IsNullOrEmpty(alg?.ToString()))
                {
                    return (false, "invalid_dpop_proof", "Missing alg header in DPoP proof");
                }
                
                var algorithm = alg.ToString();
                if (!IsValidDPoPAlgorithm(algorithm))
                {
                    return (false, "invalid_dpop_proof", $"Invalid algorithm for DPoP proof: {algorithm}. Must be asymmetric algorithm");
                }
                
                // Extract embedded JWK
                if (!dpopToken.Header.TryGetValue("jwk", out var jwkObj))
                {
                    return (false, "invalid_dpop_proof", "Missing jwk header in DPoP proof");
                }
                
                Console.WriteLine($"   [SUCCESS] DPoP proof structure valid (typ: {typ}, alg: {algorithm})");
                
                // STEP 3: Validate DPoP proof signature using embedded JWK
                var signatureValidation = ValidateDPoPProofSignature(dpopHeader, jwkObj);
                if (!signatureValidation.IsValid)
                {
                    return (false, "invalid_dpop_proof", $"DPoP proof signature validation failed: {signatureValidation.ErrorMessage}");
                }
                
                Console.WriteLine("   [SUCCESS] DPoP proof signature validated successfully");
                
                // STEP 4: Calculate JWK thumbprint for access token binding validation
                var jwkJson = JsonSerializer.Serialize(jwkObj);
                var jwkThumbprint = CalculateJWKThumbprint(jwkJson);
                if (string.IsNullOrEmpty(jwkThumbprint))
                {
                    return (false, "invalid_dpop_proof", "Failed to calculate JWK thumbprint from DPoP proof");
                }
                
                Console.WriteLine($"   [INFO] JWK thumbprint calculated: {jwkThumbprint}");
                
                // STEP 5: Validate access token binding (cnf.jkt claim) and ath (access token hash)
                var tokenBindingValidation = ValidateAccessTokenBinding(httpContext, jwkThumbprint, out string accessTokenString);
                if (!tokenBindingValidation.IsValid)
                {
                    return (false, tokenBindingValidation.ErrorCode, $"Access token binding validation failed: {tokenBindingValidation.ErrorMessage}");
                }
                
                Console.WriteLine("   [SUCCESS] Access token binding validated successfully");
                
                // STEP 6: Validate DPoP proof payload claims
                var payload = dpopToken.Payload;
                
                // Validate htm claim (HTTP method)
                if (!payload.TryGetValue("htm", out var htm) || 
                    !string.Equals(htm?.ToString(), httpContext.Request.Method, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, "invalid_dpop_proof", $"htm claim mismatch. Expected: {httpContext.Request.Method}, Got: {htm}");
                }
                
                // Validate htu claim (HTTP URI) - must match full request URL
                if (!payload.TryGetValue("htu", out var htu))
                {
                    return (false, "invalid_dpop_proof", "Missing htu claim in DPoP proof");
                }
                
                var normalizedHtu = NormalizeUri(new Uri(htu.ToString() ?? string.Empty));
                var requestUri = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}{httpContext.Request.Path}";
                var normalizedRequestUri = NormalizeUri(new Uri(requestUri));
                if (!string.Equals(normalizedHtu, normalizedRequestUri, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, "invalid_dpop_proof", $"htu claim mismatch. Expected: {requestUri}, Got: {htu}");
                }
                
                // Validate iat claim (issued at time) - must be recent
                if (!payload.TryGetValue("iat", out var iat))
                {
                    return (false, "invalid_dpop_proof", "Missing iat claim in DPoP proof");
                }
                
                var issuedAt = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(iat));
                var now = DateTimeOffset.UtcNow;
                var timeDifference = Math.Abs((now - issuedAt).TotalMinutes);
                
                // Strict timing for DPoP proofs (5 minutes as per RFC 9449)
                if (timeDifference > 5)
                {
                    return (false, "invalid_dpop_proof", $"DPoP proof token is too old or from the future. Time difference: {timeDifference} minutes (max 5 minutes allowed)");
                }

                // Validate jti claim (JWT ID) - must be unique for replay protection
                // This is a demo resource server, ignore implementing jti nonce tracking to prevent replay attacks
                if (!payload.TryGetValue("jti", out var jti) || string.IsNullOrEmpty(jti?.ToString()))
                {
                    return (false, "invalid_dpop_proof", "Missing or empty jti claim in DPoP proof");
                }

                /*
                 * When the DPoP proof is used in conjunction with the presentation of an access token in protected resource access (see Section 7), the DPoP proof MUST also contain the following claim:
                ath: Hash of the access token. The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.
                 */
                if (payload.TryGetValue("ath", out var ath))
                {
                    // hash the access token and do matching validation
                    using var sha256 = SHA256.Create();
                    var hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(accessTokenString));
                    var expectedAth = Base64Url.Encode(hash);

                    if (!ath.Equals(expectedAth))
                    {
                        return (false, "invalid_dpop_proof", "DPoP's ath does not match the received Access token.");
                    }
                }
                else
                {
                    return (false, "invalid_dpop_proof", "Missing ath claim in DPoP proof when access token is presented.");
                }

                Console.WriteLine($"   [INFO] jti claim present: {jti} (replay protection - should be tracked in production)");
                
                Console.WriteLine($"   [SUCCESS] DPoP proof claims validated (htm: {htm}, htu: {htu}, iat: {issuedAt:yyyy-MM-dd HH:mm:ss} UTC)");
                
                Console.WriteLine("[SUCCESS] RFC 9449 compliant DPoP validation completed successfully");
                
                return (true, string.Empty, string.Empty);
            }
            catch (Exception ex)
            {
                return (false, "invalid_dpop_proof", $"Exception during DPoP validation: {ex.Message}");
            }
        }

        // Helper method to validate access token binding via cnf.jkt claim
        public static (bool IsValid, string ErrorCode, string ErrorMessage) ValidateAccessTokenBinding(HttpContext httpContext, string expectedJwkThumbprint, out string accessTokenString)
        {
            try
            {
                accessTokenString = string.Empty;
                // Get access token from Authorization header
                var authHeader = httpContext.Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader))
                {
                    return (false, "invalid_request", "Missing Authorization header for access token binding validation");
                }
                
                // Extract access token string
                if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
                {
                    accessTokenString = authHeader.Substring(5).Trim();
                }
                else if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    accessTokenString = authHeader.Substring(7).Trim();
                }
                else
                {
                    return (false, "invalid_request", "Invalid Authorization header format for access token binding validation");
                }
                
                if (string.IsNullOrEmpty(accessTokenString))
                {
                    return (false, "invalid_token", "Empty access token string for binding validation");
                }
                
                // Parse access token to extract cnf claim
                var tokenHandler = new JwtSecurityTokenHandler();
                if (!tokenHandler.CanReadToken(accessTokenString))
                {
                    return (false, "invalid_token", "Cannot parse access token for binding validation");
                }
                
                var accessToken = tokenHandler.ReadJwtToken(accessTokenString);
                
                // Look for cnf (confirmation) claim
                var cnfClaim = accessToken.Claims.FirstOrDefault(c => c.Type == "cnf");
                if (cnfClaim == null)
                {
                    return (false, "invalid_token", "Access token missing cnf (confirmation) claim - not DPoP-bound");
                }
                
                // Parse cnf claim JSON
                var cnfJson = JsonDocument.Parse(cnfClaim.Value);
                if (!cnfJson.RootElement.TryGetProperty("jkt", out var jktElement))
                {
                    return (false, "invalid_token", "Access token cnf claim missing jkt (JWK thumbprint) property");
                }
                
                var accessTokenJwkThumbprint = jktElement.GetString();
                if (string.IsNullOrEmpty(accessTokenJwkThumbprint))
                {
                    return (false, "invalid_token", "Access token cnf.jkt claim is empty");
                }
                
                // Compare JWK thumbprints
                if (!string.Equals(expectedJwkThumbprint, accessTokenJwkThumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"   [ERROR] JWK thumbprint mismatch:");
                    Console.WriteLine($"      DPoP proof JWK thumbprint: {expectedJwkThumbprint}");
                    Console.WriteLine($"      Access token cnf.jkt:      {accessTokenJwkThumbprint}");
                    return (false, "invalid_token", "JWK thumbprint mismatch between DPoP proof and access token cnf.jkt claim");
                }

                // Validate 
                
                Console.WriteLine($"   [SUCCESS] JWK thumbprint match confirmed: {expectedJwkThumbprint}");
                return (true, string.Empty, string.Empty);
            }
            catch (Exception ex)
            {
                accessTokenString = string.Empty;
                return (false, "invalid_token", $"Exception during access token binding validation: {ex.Message}");
            }
        }

        // Helper method to calculate JWK thumbprint per RFC 7638
        public static string CalculateJWKThumbprint(string jwkJson)
        {
            try
            {
                var jwk = JsonWebKey.Create(jwkJson);
                var hash = jwk.ComputeJwkThumbprint();
                
                // Return base64url-encoded thumbprint
                return Base64UrlEncoder.Encode(hash);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   [ERROR] Failed to calculate JWK thumbprint: {ex.Message}");
                return string.Empty;
            }
        }

        public static bool IsValidDPoPAlgorithm(string algorithm)
        {
            // Valid asymmetric algorithms for DPoP per RFC 9449
            var validAlgorithms = new[] { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" };
            return validAlgorithms.Contains(algorithm, StringComparer.OrdinalIgnoreCase);
        }

        // Helper method to validate DPoP proof signature using embedded JWK
        public static (bool IsValid, string ErrorMessage) ValidateDPoPProofSignature(string dpopProofToken, object jwkObj)
        {
            try
            {
                // Convert JWK object to JSON string for processing
                var jwkJson = JsonSerializer.Serialize(jwkObj);
                
                // Create JsonWebKey from the embedded JWK
                var jsonWebKey = new JsonWebKey(jwkJson);
                
                // Validate that the JWK has the required properties for signature validation
                if (string.IsNullOrEmpty(jsonWebKey.Kty))
                {
                    return (false, "JWK missing key type (kty)");
                }
                
                // Create token validation parameters for DPoP proof signature validation
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,           // DPoP proofs don't have issuers
                    ValidateAudience = false,         // DPoP proofs don't have audiences
                    ValidateLifetime = false,         // We validate iat separately with custom logic
                    ValidateIssuerSigningKey = true,  // This is what we want to validate
                    IssuerSigningKey = jsonWebKey,
                    ClockSkew = TimeSpan.Zero         // No clock skew for DPoP proof validation
                };
                
                // Validate the DPoP proof signature
                var tokenHandler = new JwtSecurityTokenHandler();
                
                try
                {
                    // Validate the token signature against the embedded JWK
                    var principal = tokenHandler.ValidateToken(dpopProofToken, validationParameters, out var validatedToken);
                    
                    if (validatedToken is JwtSecurityToken validatedJwt)
                    {
                        Console.WriteLine($"   [SUCCESS] DPoP proof signature validated successfully");
                        Console.WriteLine($"      Algorithm: {validatedJwt.Header.Alg}");
                        Console.WriteLine($"      Key Type: {jsonWebKey.Kty}");
                        return (true, string.Empty);
                    }
                    else
                    {
                        return (false, "DPoP proof validation returned unexpected token type");
                    }
                }
                catch (SecurityTokenSignatureKeyNotFoundException ex)
                {
                    return (false, $"Cannot validate DPoP proof signature - key not found: {ex.Message}");
                }
                catch (SecurityTokenInvalidSignatureException ex)
                {
                    return (false, $"DPoP proof has invalid signature: {ex.Message}");
                }
                catch (SecurityTokenValidationException ex)
                {
                    return (false, $"DPoP proof signature validation failed: {ex.Message}");
                }
            }
            catch (ArgumentException ex)
            {
                return (false, $"Invalid JWK format in DPoP proof: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Exception during DPoP signature validation: {ex.Message}");
            }
        }

        private static string NormalizeUri(Uri uri)
        {
            if (uri == null)
                return string.Empty;

            // Perform syntax-based and scheme-based normalization
            var builder = new UriBuilder(uri)
            {
                // Remove query and fragment as per DPoP specification
                Query = string.Empty,
                Fragment = string.Empty,
                // Normalize scheme to lowercase
                Scheme = uri.Scheme.ToLowerInvariant(),
                // Normalize host to lowercase
                Host = uri.Host.ToLowerInvariant()
            };

            // Remove default ports
            if ((builder.Scheme == "http" && builder.Port == 80) ||
                (builder.Scheme == "https" && builder.Port == 443))
            {
                builder.Port = -1;
            }

            return builder.Uri.ToString().TrimEnd('/');
        }
    }
}