using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using FhirCandle.Authorization.Models;
using FhirCandle.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using AuthorizationInfo = FhirCandle.Authorization.Models.AuthorizationInfo;

namespace FhirCandle.Authorization.Services
{
    public class SmartClientManager : ISmartClientManager
    {
        /// <summary>The smart clients.</summary>
        private Dictionary<string, ClientInfo> _clients = new(StringComparer.Ordinal);

        /// <summary>Gets the clients.</summary>
        public Dictionary<string, ClientInfo> SmartClients => _clients;

        /// <summary>The logger.</summary>
        private ILogger _logger;


        public SmartClientManager(ILogger logger)
        {
            _logger = logger ?? NullLoggerFactory.Instance.CreateLogger<SmartAuthManager>();
        }



        /// <summary>
        /// Attempts to register client a string from the given SmartClientRegistration.
        /// </summary>
        /// <param name="registration">The registration.</param>
        /// <param name="clientId">    [out] The client's identifier.</param>
        /// <param name="messages">    [out] The messages.</param>
        /// <returns>True if it succeeds, false if it fails.</returns>
        public override bool TryRegisterClient(SmartClientRegistration registration, string clientId, List<string> messages)
        {
            messages = new List<string>();

            // check for this client already existing
            if (string.IsNullOrEmpty(registration.ClientName))
            {
                string msg = $"TryRegisterClient <<< request is missing client name.";
                messages.Add(msg);
                _logger.LogWarning(msg);
                clientId = string.Empty;
                return false;
            }

            // grab the client name for simplicity
            string clientName = registration.ClientName;

            // assign a new client id if this client already exists
            clientId = clientName.Replace(" ", string.Empty);
            if (_clients.ContainsKey(clientId))
            {
                clientId = Guid.NewGuid().ToString();
            }

            //if (!registration.Keys.Any())
            //{
            //    _logger.LogWarning($"TryRegisterClient <<< request {clientName} is missing keys.");
            //    clientId = string.Empty;
            //    return false;
            //}

            // create our base client info
            ClientInfo smartClient = new()
            {
                ClientId = clientId, ClientName = clientName, Registration = registration,
            };

            ProcessKeys(clientName, smartClient, registration.KeySet, messages);

            if (!smartClient.Keys.Any())
            {
                string msg = $"TryRegisterClient <<< request {clientName} has no keys.";
                messages.Add(msg);
                _logger.LogWarning(msg);
            }

            smartClient.Activity.Add(new() { RequestType = "registration", Success = true, });

            _clients.Add(clientId, smartClient);

            return true;
        }


        /// <summary>Process the keys.</summary>
        /// <param name="clientName">  Name of the client.</param>
        /// <param name="smartClient"> The smart client.</param>
        /// <param name="keySet">The JSON Web Key Set.</param>
        /// <param name="messages">    [out] The messages.</param>
        /// <param name="jwksUrl">     (Optional) URL of the jwks.</param>
        private void ProcessKeys(
            string clientName,
            ClientInfo smartClient,
            JsonWebKeySet keySet,
            List<string> messages,
            string? jwksUrl = null)
        {
            foreach (JsonWebKey jwksKey in keySet.Keys)
            {
                if (string.IsNullOrEmpty(jwksKey.Alg))
                {
                    string msg = $"TryRegisterClient <<< request {clientName} has a key missing the algorithm.";
                    messages.Add(msg);
                    _logger.LogWarning(msg);
                    continue;
                }

                if (!TryProcessKey(clientName, jwksKey, out SecurityKey resolvedKey, out List<string> subMessages))
                {
                    if (subMessages.Any())
                    {
                        messages.AddRange(subMessages);
                    }

                    string msg =
                        $"TryRegisterClient <<< request {clientName}:{jwksKey.Alg} could not be processed and will not be available.";
                    messages.Add(msg);
                    _logger.LogWarning(msg);
                    continue;
                }

                string keyId = jwksKey.KeyId ?? jwksUrl ?? string.Empty;

                // add or update this key
                smartClient.Keys[keyId] = resolvedKey;
            }
        }

        /// <summary>Attempts to process key.</summary>
        /// <param name="clientName"> Name of the client.</param>
        /// <param name="webKey">     The web key.</param>
        /// <param name="securityKey">[out] The security key.</param>
        /// <param name="messages">   [out] The messages.</param>
        /// <returns>True if it succeeds, false if it fails.</returns>
        public override bool TryProcessKey(string clientName, JsonWebKey webKey, out SecurityKey securityKey, out List<string> messages)
        {
            messages = new();

            if (string.IsNullOrEmpty(webKey.Alg))
            {
                string msg = $"TryRegisterClient <<< request {clientName} has a key missing the algorithm (alg).";
                messages.Add(msg);
                _logger.LogWarning(msg);
                securityKey = null!;
                return false;
            }

            SecurityKey? resolvedKey = null;

            switch (webKey.Alg)
            {
                case "RS384":
                    {
                        bool valid = true;

                        if (string.IsNullOrEmpty(webKey.N))
                        {
                            string msg =
                                $"TryRegisterClient <<< request {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA Modulus (n).";
                            messages.Add(msg);
                            _logger.LogWarning(msg);
                            valid = false;
                        }

                        if (string.IsNullOrEmpty(webKey.E))
                        {
                            string msg =
                                $"TryRegisterClient <<< request {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA Exponent (e).";
                            messages.Add(msg);
                            _logger.LogWarning(msg);
                            valid = false;
                        }

                        if (webKey.KeyOps.Contains("sign"))
                        {
                            if (string.IsNullOrEmpty(webKey.D))
                            {
                                string msg =
                                    $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA Private Exponent (d).";
                                messages.Add(msg);
                                _logger.LogWarning(msg);
                                valid = false;
                            }

                            if (string.IsNullOrEmpty(webKey.P))
                            {
                                string msg =
                                    $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA First Prime Factor (p).";
                                messages.Add(msg);
                                _logger.LogWarning(msg);
                                valid = false;
                            }

                            if (string.IsNullOrEmpty(webKey.Q))
                            {
                                string msg =
                                    $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA Second Prime Factor (q).";
                                messages.Add(msg);
                                _logger.LogWarning(msg);
                                valid = false;
                            }

                            if (string.IsNullOrEmpty(webKey.DP))
                            {
                                string msg =
                                    $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA FirstFactorCrtExponent (dp).";
                                messages.Add(msg);
                                _logger.LogWarning(msg);
                                valid = false;
                            }

                            if (string.IsNullOrEmpty(webKey.DQ))
                            {
                                string msg =
                                    $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA SecondFactorCrtExponent (dq).";
                                messages.Add(msg);
                                _logger.LogWarning(msg);
                                valid = false;
                            }

                            if (string.IsNullOrEmpty(webKey.QI))
                            {
                                string msg =
                                    $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA FirstCrtCoefficient (qi).";
                                messages.Add(msg);
                                _logger.LogWarning(msg);
                                valid = false;
                            }
                        }

                        if (!valid)
                        {
                            securityKey = null!;
                            return false;
                        }

                        System.Security.Cryptography.RSACryptoServiceProvider rsa = new();

                        rsa.ImportParameters(new System.Security.Cryptography.RSAParameters()
                        {
                            Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
                            Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
                            D = string.IsNullOrEmpty(webKey.D) ? null : Base64UrlEncoder.DecodeBytes(webKey.D),
                            P = string.IsNullOrEmpty(webKey.P) ? null : Base64UrlEncoder.DecodeBytes(webKey.P),
                            Q = string.IsNullOrEmpty(webKey.Q) ? null : Base64UrlEncoder.DecodeBytes(webKey.Q),
                            DP = string.IsNullOrEmpty(webKey.DP) ? null : Base64UrlEncoder.DecodeBytes(webKey.DP),
                            DQ = string.IsNullOrEmpty(webKey.DQ) ? null : Base64UrlEncoder.DecodeBytes(webKey.DQ),
                            InverseQ = string.IsNullOrEmpty(webKey.QI) ? null : Base64UrlEncoder.DecodeBytes(webKey.QI),
                        });

                        resolvedKey = new RsaSecurityKey(rsa);
                    }
                    break;

                case "ES384":
                    {
                        bool valid = true;

                        if (string.IsNullOrEmpty(webKey.Crv))
                        {
                            string msg =
                                $"TryRegisterClient <<< request {clientName}:{webKey.Alg} is missing the ECDSA Curve (crv).";
                            messages.Add(msg);
                            _logger.LogWarning(msg);
                            valid = false;
                        }

                        if (string.IsNullOrEmpty(webKey.X))
                        {
                            string msg =
                                $"TryRegisterClient <<< request {clientName}:{webKey.Alg} is missing the ECDSA X coordinate (x).";
                            messages.Add(msg);
                            _logger.LogWarning(msg);
                            valid = false;
                        }

                        if (string.IsNullOrEmpty(webKey.Y))
                        {
                            string msg =
                                $"TryRegisterClient <<< request {clientName}:{webKey.Alg} is missing the ECDSA Y coordinate (y).";
                            messages.Add(msg);
                            _logger.LogWarning(msg);
                            valid = false;
                        }

                        if (webKey.KeyOps.Contains("sign"))
                        {
                            if (string.IsNullOrEmpty(webKey.D))
                            {
                                string msg =
                                    $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the ECC Private Key (d).";
                                messages.Add(msg);
                                _logger.LogWarning(msg);
                                valid = false;
                            }
                        }

                        if (!valid)
                        {
                            securityKey = null!;
                            return false;
                        }

                        ECCurve curve;

                        try
                        {
                            // try to use the named curve
                            curve = ECCurve.CreateFromFriendlyName(webKey.Crv);
                        }
                        catch (Exception)
                        {
                            // assume it is the default curve
                            curve = ECCurve.NamedCurves.nistP384;
                        }

                        ECParameters parameters = new()
                        {
                            Curve = curve,
                            Q = new()
                            {
                                X = Base64UrlEncoder.DecodeBytes(webKey.X),
                                Y = Base64UrlEncoder.DecodeBytes(webKey.Y),
                            },
                            D = string.IsNullOrEmpty(webKey.D) ? null : Base64UrlEncoder.DecodeBytes(webKey.D),
                        };

                        System.Security.Cryptography.ECDsa ecdsa =
                            System.Security.Cryptography.ECDsaCng.Create(parameters);
                        resolvedKey = new ECDsaSecurityKey(ecdsa);
                    }
                    break;
            }

            if (resolvedKey == null)
            {
                string msg =
                    $"TryRegisterClient <<< request {clientName}:{webKey.Alg} could not be resolved and will not be available.";
                messages.Add(msg);
                _logger.LogWarning(msg);
                securityKey = null!;
                return false;
            }

            resolvedKey.KeyId = webKey.KeyId;

            securityKey = resolvedKey;
            return true;
        }

        public override bool TryClientAssertionExchange(string clientAssertion,
            List<string> messages, TenantConfiguration tenant,
            out ClientInfo? smartClient )
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            smartClient = null;

            if (!tokenHandler.CanReadToken(clientAssertion))
            {
                string msg = $"TryClientAssertionExchange <<< invalid client assertion.";
                messages.Add(msg);
                _logger.LogWarning(msg);
                return false;
            }

            // read the token so we can get the claims
            JwtSecurityToken jwtToken = tokenHandler.ReadJwtToken(clientAssertion);

            //// check to see if we are an audience on the key
            //if (!jwtToken.Audiences.Any(a => a.Equals(tenant.BaseUrl, StringComparison.OrdinalIgnoreCase)))
            //{
            //    string msg = $"TryClientAssertionExchange <<< client assertion audience is not valid against tenant {tenantName} ({tenant.BaseUrl}).";
            //    messages.Add(msg);
            //    _logger.LogWarning(msg);
            //    response = null!;
            //    return false;
            //}

            var clientId = jwtToken.Issuer;

            // if (!_clients.TryGetValue(clientId, out ClientInfo? smartClient))
            if (!_clients.TryGetValue(clientId, out smartClient))
            {
                string msg =
                    $"TryClientAssertionExchange <<< client assertion issuer {jwtToken.Issuer} is not a registered client.";
                messages.Add(msg);
                _logger.LogWarning(msg);
                return false;
            }

            // check to see if there is a keyset url
            if (jwtToken.Header.TryGetValue("jku", out object? jku) &&
                (jku != null) &&
                (jku is string keySetUrl))
            {
                try
                {
                    // use the keyset url to get the keys via http
                    using (HttpClient client = new())
                    {
                        string keySetJson = client.GetStringAsync(keySetUrl).Result;
                        JsonWebKeySet clientKeys = new(keySetJson);

                        if (clientKeys == null)
                        {
                            string msg =
                                $"TryClientAssertionExchange <<< failed to parse key set from: {keySetUrl}: retrieved {keySetJson}";
                            messages.Add(msg);
                            _logger.LogWarning(msg);
                            return false;
                        }

                        ProcessKeys(smartClient.ClientName, smartClient, clientKeys, messages, keySetUrl);
                    }
                }
                catch (Exception ex)
                {
                    string msg =
                        $"TryClientAssertionExchange <<< failed to retrieve key set (jku) from: {keySetUrl}: {ex.Message}";
                    messages.Add(msg);
                    _logger.LogWarning(msg);
                    return false;
                }
            }
            else
            {
                keySetUrl = string.Empty;
            }

            if (!jwtToken.Header.TryGetValue("kid", out object? kid) ||
                (kid == null) ||
                (kid is not string signingKeyId))
            {
                if (!string.IsNullOrEmpty(keySetUrl))
                {
                    signingKeyId = keySetUrl;
                }
                else
                {
                    string msg = $"TryClientAssertionExchange <<< client assertion does not have a key id (kid).";
                    messages.Add(msg);
                    _logger.LogWarning(msg);

                    smartClient.Activity.Add(new()
                    {
                        RequestType = "client_assertion", Success = false, Message = msg
                    });

                    return false;
                }
            }

            if (!smartClient.Keys.Any())
            {
                string msg = $"TryClientAssertionExchange <<< client has NO keys.";
                messages.Add(msg);
                _logger.LogWarning(msg);

                smartClient.Activity.Add(new() { RequestType = "client_assertion", Success = false, Message = msg });

                return false;
            }

            if (!smartClient.Keys.TryGetValue(signingKeyId, out SecurityKey? signingKey) ||
                (signingKey == null))
            {
                string msg =
                    $"TryClientAssertionExchange <<< client assertion signing key id (kid) {signingKeyId} was not found in client {clientId}.";
                messages.Add(msg);
                _logger.LogWarning(msg);

                smartClient.Activity.Add(new() { RequestType = "client_assertion", Success = false, Message = msg });

                return false;
            }

            TokenValidationParameters tokenValidationParameters;

            // for debugging, we want to test each component alone
            bool tokenIsValid = true;

            try
            {
                tokenValidationParameters = new()
                {
                    ValidateLifetime = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = smartClient.Keys.Values,
                };

                tokenHandler.ValidateToken(clientAssertion, tokenValidationParameters,
                    out SecurityToken validatedToken);
            }
            catch (Exception ex)
            {
                tokenIsValid = false;
                string msg = ex.InnerException == null
                    ? $"TryClientAssertionExchange <<< token validation failed: {ex.Message}."
                    : $"TryClientAssertionExchange <<< token validation failed: {ex.Message}:{ex.InnerException.Message}.";
                messages.Add(msg);
                _logger.LogWarning(msg);
            }

            try
            {
                tokenValidationParameters = new()
                {
                    ValidateLifetime = false,
                    ValidateAudience = false,
                    ValidateIssuerSigningKey = false,
                    ValidateIssuer = true,
                    ValidIssuer = clientId,
                    IssuerSigningKeys = smartClient.Keys.Values,
                };

                tokenHandler.ValidateToken(clientAssertion, tokenValidationParameters,
                    out SecurityToken validatedToken);
            }
            catch (Exception ex)
            {
                tokenIsValid = false;
                string msg = ex.InnerException == null
                    ? $"TryClientAssertionExchange <<< token validation failed: {ex.Message}."
                    : $"TryClientAssertionExchange <<< token validation failed: {ex.Message}:{ex.InnerException.Message}.";
                messages.Add(msg);
                _logger.LogWarning(msg);
            }

            try
            {
                tokenValidationParameters = new()
                {
                    ValidateLifetime = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = false,
                    ValidateAudience = true,
                    ValidAudience = tenant.BaseUrl,
                    IssuerSigningKeys = smartClient.Keys.Values,
                };

                tokenHandler.ValidateToken(clientAssertion, tokenValidationParameters,
                    out SecurityToken validatedToken);
            }
            catch (Exception ex)
            {
                tokenIsValid = false;
                string msg = ex.InnerException == null
                    ? $"TryClientAssertionExchange <<< token validation failed: {ex.Message}."
                    : $"TryClientAssertionExchange <<< token validation failed: {ex.Message}:{ex.InnerException.Message}.";
                messages.Add(msg);
                _logger.LogWarning(msg);
            }

            try
            {
                tokenValidationParameters = new()
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = false,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    IssuerSigningKeys = smartClient.Keys.Values,
                };

                tokenHandler.ValidateToken(clientAssertion, tokenValidationParameters,
                    out SecurityToken validatedToken);
            }
            catch (Exception ex)
            {
                tokenIsValid = false;
                string msg = ex.InnerException == null
                    ? $"TryClientAssertionExchange <<< token validation failed: {ex.Message}."
                    : $"TryClientAssertionExchange <<< token validation failed: {ex.Message}:{ex.InnerException.Message}.";
                messages.Add(msg);
                _logger.LogWarning(msg);
            }

            if (!tokenIsValid)
            {

                smartClient.Activity.Add(new()
                {
                    RequestType = "client_assertion",
                    Success = false,
                    Message = $"Failed to validate client assertion: {clientAssertion}\n" +
                              string.Join("\n", messages),
                });

                return false;
            }

            return true;
        }

    }
}
