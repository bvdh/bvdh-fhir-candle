﻿// <copyright file="SmartAuthManager.cs" company="Microsoft Corporation">
//     Copyright (c) Microsoft Corporation. All rights reserved.
//     Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// </copyright>

using System.IdentityModel.Tokens.Jwt;
using System.Text;
using FhirCandle.Authorization.Models;
using FhirCandle.Configuration;
using FhirCandle.Models;
using FhirCandle.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using AuthorizationInfo = FhirCandle.Authorization.Models.AuthorizationInfo;

namespace FhirCandle.Authorization.Services;

/// <summary>Manager for smart authentications.</summary>
public class SmartAuthorizationManager : ISmartAuthorizationManager, IDisposable
{
    /// <summary>(Immutable) The jwt signing value.</summary>
    private const string _jwtSign = "***NotSecure!DoNotUseInProduction!ThisIsForDevOnly!***";
    private JwtHelper _jwtHelper;

    /// <summary>(Immutable) The token expiration in minutes.</summary>
    private const int _tokenExpirationMinutes = 30;

    /// <summary>True if has disposed, false if not.</summary>
    private bool _hasDisposed = false;

    /// <summary>True if is initialized, false if not.</summary>
    private bool _isInitialized = false;

    /// <summary>The logger.</summary>
    private ILogger _logger;

    /// <summary>The tenants.</summary>
    private Dictionary<string, TenantConfiguration> _tenants;

    /// <summary>The server configuration.</summary>
    private CandleConfig _serverConfig;

    /// <summary>The smart configs.</summary>
    private Dictionary<string, SmartWellKnown> _smartConfigs = new(StringComparer.OrdinalIgnoreCase);

    // /// <summary>The smart clients.</summary>
    // private Dictionary<string, ClientInfo> _clients = new(StringComparer.Ordinal);
    private ISmartClientManager _clientManager;

    /// <summary>The authorizations.</summary>
    private Dictionary<string, AuthorizationInfo> _authorizations = new();

    /// <summary>
    /// Initializes a new instance of the fhir.candle.Services.SmartAuthManager class.
    /// </summary>
    /// <param name="tenants">            The tenants.</param>
    /// <param name="serverConfiguration">The server configuration.</param>
    /// <param name="logger">             The logger.</param>
    public SmartAuthorizationManager(
        Dictionary<string, TenantConfiguration> tenants,
        CandleConfig serverConfiguration,
        ILogger<SmartAuthorizationManager>? logger)
    {
        _tenants = tenants;
        _serverConfig = serverConfiguration;
        _logger = logger ?? NullLoggerFactory.Instance.CreateLogger<SmartAuthorizationManager>();
        _clientManager = new SmartClientManager(_logger);
        _jwtHelper = new JwtHelper(_jwtSign, _clientManager);
    }

    /// <summary>Gets a value indicating whether this object is enabled.</summary>
    public bool IsEnabled => _smartConfigs.Any();

    /// <summary>Gets the smart configuration by tenant.</summary>
    public Dictionary<string, SmartWellKnown> SmartConfigurationByTenant => _smartConfigs;

    /// <summary>Gets the smart authorizations.</summary>
    public Dictionary<string, AuthorizationInfo> SmartAuthorizations => _authorizations;

    /// <summary>Gets the clients.</summary>
    public Dictionary<string, SmartClientInfo> SmartClients => _clientManager.getSmartClients();

    /// <summary>Query if 'tenant' has tenant.</summary>
    /// <param name="tenant">The tenant.</param>
    /// <returns>True if tenant, false if not.</returns>
    public bool HasTenant(string tenant)
    {
        return _tenants.ContainsKey(tenant);
    }

    /// <summary>Attempts to get authorization.</summary>
    /// <param name="tenant">The tenant name.</param>
    /// <param name="code">  The authorization code or authorization header.</param>
    /// <param name="auth">  [out] The authentication.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool TryGetAuthorization(string tenant, string code, out AuthorizationInfo auth)
    {
        if (string.IsNullOrEmpty(code))
        {
            auth = null!;
            return false;
        }

        if (string.IsNullOrEmpty(tenant))
        {
            auth = null!;
            return false;
        }

        if (code.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            code = code.Substring(7);

            if (code.Length >= 36)
            {
                code = code.Substring(0, 36);
            }
        }

        string key = tenant + ":" + code;

        if (!_authorizations.TryGetValue(key, out AuthorizationInfo? local))
        {
            auth = null!;
            return false;
        }

        if (!local.Tenant.Equals(tenant, StringComparison.OrdinalIgnoreCase))
        {
            auth = null!;
            return false;
        }

        auth = local;
        return true;
    }

    /// <summary>Gets an authorization.</summary>
    /// <param name="tenant">The tenant.</param>
    /// <param name="code">  The authorization code or authorization header.</param>
    /// <returns>The authorization.</returns>
    public AuthorizationInfo? GetAuthorization(string tenant, string code)
    {
        if (TryGetAuthorization(tenant, code, out AuthorizationInfo auth))
        {
            return auth;
        }

        return null;
    }

    /// <summary>Attempts to update authentication.</summary>
    /// <param name="tenant">The tenant name.</param>
    /// <param name="code">  The authorization code.</param>
    /// <param name="auth">  [out] The authentication.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool TryUpdateAuth(string tenant, string code, AuthorizationInfo auth)
    {
        string key = tenant + ":" + code;

        if (!_authorizations.TryGetValue(key, out AuthorizationInfo? local))
        {
            return false;
        }

        if (!local.Tenant.Equals(tenant, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // update our last access
        auth.LastAccessed = DateTimeOffset.UtcNow;
        auth.Expires = DateTimeOffset.UtcNow.AddMinutes(_tokenExpirationMinutes);

        _authorizations[key] = auth;
        return true;
    }

    /// <summary>Attempts to get the authorization client redirect URL.</summary>
    /// <param name="tenant">          The tenant name.</param>
    /// <param name="code">            The authorization code.</param>
    /// <param name="redirect">        [out] The redirect.</param>
    /// <param name="error">           (Optional) The error.</param>
    /// <param name="errorDescription">(Optional) Information describing the error.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool TryGetClientRedirect(
        string tenant,
        string code,
        out string redirect,
        string error = "",
        string errorDescription = "")
    {
        string key = tenant + ":" + code;

        if (!_authorizations.TryGetValue(key, out AuthorizationInfo? local))
        {
            redirect = string.Empty;
            return false;
        }

        if (!local.Tenant.Equals(tenant, StringComparison.OrdinalIgnoreCase))
        {
            redirect = string.Empty;
            return false;
        }

        if (string.IsNullOrEmpty(_authorizations[key].RequestParameters.RedirectUri))
        {
            redirect = string.Empty;
            return false;
        }

        // update our last access
        _authorizations[key].LastAccessed = DateTimeOffset.UtcNow;
        _authorizations[key].Expires = DateTimeOffset.UtcNow.AddMinutes(_tokenExpirationMinutes);

        string redirectUri = _authorizations[key].RequestParameters.RedirectUri;

        // check for an error state redirection
        if (!string.IsNullOrEmpty(error))
        {
            // use our key as the authorization code
            if (redirectUri.Contains('?'))
            {
                redirect = $"{redirectUri}&error={System.Web.HttpUtility.UrlEncode(error)}";
            }
            else
            {
                redirect = $"{redirectUri}?error={System.Web.HttpUtility.UrlEncode(error)}";
            }

            if (!string.IsNullOrEmpty(errorDescription))
            {
                redirect = redirect + $"&error_description={System.Web.HttpUtility.UrlEncode(errorDescription)}";
            }

            return true;
        }

        // use our key as the authorization code
        if (redirectUri.Contains('?'))
        {
            redirect = $"{redirectUri}&code={_authorizations[key].AuthCode}&state={_authorizations[key].RequestParameters.State}";
        }
        else
        {
            redirect = $"{redirectUri}?code={_authorizations[key].AuthCode}&state={_authorizations[key].RequestParameters.State}";
        }

        return true;
    }

    /// <summary>Attempts to exchange a refresh token for a new access token.</summary>
    /// <param name="tenant">      The tenant.</param>
    /// <param name="refreshToken">The refresh token.</param>
    /// <param name="clientId">    The client's identifier.</param>
    /// <param name="response">    [out] The response.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool TrySmartRefresh(
        string tenant,
        string refreshToken,
        string clientId,
        out AuthorizationInfo.SmartResponse response)
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            _logger.LogWarning("TrySmartRefresh <<< request is missing refresh token.");
            response = null!;
            return false;
        }

        if (refreshToken.Length < 36)
        {
            _logger.LogWarning($"TrySmartRefresh <<< request {refreshToken} is malformed.");
            response = null!;
            return false;
        }

        string code = refreshToken.Substring(0, 36);
        string key = tenant + ":" + code;

        if (!_authorizations.TryGetValue(key, out AuthorizationInfo? local))
        {
            _logger.LogWarning($"TrySmartRefresh <<< auth {key} does not exist.");
            response = null!;
            return false;
        }

        if (string.IsNullOrEmpty(tenant))
        {
            string msg = $"TrySmartRefresh <<< refresh of {refreshToken} is missing the tenant.";
            local.Activity.Add(new()
            {
                RequestType = "refresh_token",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (string.IsNullOrEmpty(clientId))
        {
            string msg = $"TrySmartRefresh <<< refresh of {refreshToken} is missing the client id.";
            local.Activity.Add(new()
            {
                RequestType = "refresh_token",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (!local.Tenant.Equals(tenant, StringComparison.OrdinalIgnoreCase))
        {
            string msg = $"TrySmartRefresh <<< {key} tenant ({local.Tenant}) does not match request: {tenant}.";
            local.Activity.Add(new()
            {
                RequestType = "refresh_token",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (!clientId.Equals(local.RequestParameters.ClientId, StringComparison.Ordinal))
        {
            string msg = $"TrySmartRefresh <<< {key} client ({local.RequestParameters.ClientId}) does not match request: {clientId}.";
            local.Activity.Add(new()
            {
                RequestType = "refresh_token",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (local.Response == null)
        {
            string msg = $"TrySmartRefresh <<< {key} does not have an issued refresh token.";
            local.Activity.Add(new()
            {
                RequestType = "refresh_token",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (!refreshToken.Equals(local.Response.RefreshToken, StringComparison.Ordinal))
        {
            string msg = $"TrySmartRefresh <<< {key} refresh token {refreshToken} does not match issued: {local.Response.RefreshToken}.";
            local.Activity.Add(new()
            {
                RequestType = "refresh_token",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        // handle our 'always on' token
        if (code.Equals(Guid.Empty.ToString()))
        {
            // update our last access
            local.LastAccessed = DateTimeOffset.UtcNow;
        }
        else
        {
            // update our last access and expiration
            local.LastAccessed = DateTimeOffset.UtcNow;
            local.Expires = DateTimeOffset.UtcNow.AddMinutes(_tokenExpirationMinutes);

            // update the access and refresh tokens
            local.Response = local.Response with
            {
                AccessToken = code + "_" + Guid.NewGuid().ToString(),
                RefreshToken = code + "_" + Guid.NewGuid().ToString(),
            };
        }

        local.Activity.Add(new()
        {
            RequestType = "refresh_token",
            Success = true,
            Message = $"Refreshed access: {local.Response.AccessToken}, refresh token: {local.Response.RefreshToken}"
        });

        response = local.Response!;
        return true;
    }

    /// <summary>Query if this request is authorized.</summary>
    /// <param name="ctx">The context.</param>
    /// <returns>True if authorized, false if not.</returns>
    public bool IsAuthorized(FhirRequestContext ctx)
    {
        // any request to a tenant without SMART is authorized
        if ((!_tenants.TryGetValue(ctx.TenantName, out TenantConfiguration? tConfig)) ||
            (tConfig == null) ||
            ((tConfig.SmartRequired == false) && (tConfig.SmartAllowed == false)))
        {
            return true;
        }

        // capabilities are always authorized
        if (ctx.Interaction == Common.StoreInteractionCodes.SystemCapabilities)
        {
            return true;
        }

        // a request without auth is ok if SMART is optional
        if (tConfig.SmartAllowed && (ctx.Authorization == null))
        {
            return true;
        }

        // other requests without auth fail
        if (ctx.Authorization == null)
        {
            _logger.LogWarning($"IsAuthorized <<< request {ctx.HttpMethod} {ctx.Url} requires authorization.");
            return false;
        }

        // check for special admin access
        if (ctx.Authorization.Key.Equals(Guid.Empty.ToString()))
        {
            return true;
        }

        if (string.IsNullOrEmpty(ctx.TenantName))
        {
            _logger.LogWarning($"IsAuthorized <<< request {ctx.HttpMethod} {ctx.Url} is missing the tenant.");
            return false;
        }

        if (!ctx.TenantName.Equals(ctx.Authorization.Tenant, StringComparison.OrdinalIgnoreCase))
        {
            string msg = $"IsAuthorized <<< request {ctx.HttpMethod} {ctx.Url}: tenant {ctx.TenantName} does not match auth: {ctx.Authorization.Tenant}.";
            ctx.Authorization.Activity.Add(new()
            {
                RequestType = "refresh_token",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            return false;
        }

        return ctx.IsAuthorized();
    }

    /// <summary>
    /// Attempts to register client a string from the given SmartClientRegistration.
    /// </summary>
    /// <param name="registration">The registration.</param>
    /// <param name="clientId">    [out] The client's identifier.</param>
    /// <param name="messages">    [out] The messages.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool TryRegisterClient(
        SmartClientRegistration registration,
        out string clientId,
        out List<string> messages)
    {
        var theClientId = "";
        var theMessages = new List<string>();
        var result = _clientManager.TryRegisterClient(registration, out theClientId, out theMessages);

        clientId = theClientId;
        messages = theMessages;
        return result;
        // messages = new List<string>();
        //
        // // check for this client already existing
        // if (string.IsNullOrEmpty(registration.ClientName))
        // {
        //     string msg = $"TryRegisterClient <<< request is missing client name.";
        //     messages.Add(msg);
        //     _logger.LogWarning(msg);
        //     clientId = string.Empty;
        //     return false;
        // }
        //
        // // grab the client name for simplicity
        // string clientName = registration.ClientName;
        //
        // // assign a new client id if this client already exists
        // clientId = clientName.Replace(" ", string.Empty);
        // if (_clients.ContainsKey(clientId))
        // {
        //     clientId = Guid.NewGuid().ToString();
        // }
        //
        // //if (!registration.Keys.Any())
        // //{
        // //    _logger.LogWarning($"TryRegisterClient <<< request {clientName} is missing keys.");
        // //    clientId = string.Empty;
        // //    return false;
        // //}
        //
        // // create our base client info
        // ClientInfo smartClient = new()
        // {
        //     ClientId = clientId,
        //     ClientName = clientName,
        //     Registration = registration,
        // };
        //
        // ProcessKeys(clientName, smartClient, registration.KeySet, messages);
        //
        // if (!smartClient.Keys.Any())
        // {
        //     string msg = $"TryRegisterClient <<< request {clientName} has no keys.";
        //     messages.Add(msg);
        //     _logger.LogWarning(msg);
        // }
        //
        // smartClient.Activity.Add(new()
        // {
        //     RequestType = "registration",
        //     Success = true,
        // });
        //
        // _clients.Add(clientId, smartClient);
        //
        // return true;
    }

    // /// <summary>Process the keys.</summary>
    // /// <param name="clientName">  Name of the client.</param>
    // /// <param name="smartClient"> The smart client.</param>
    // /// <param name="keySet">The JSON Web Key Set.</param>
    // /// <param name="messages">    [out] The messages.</param>
    // /// <param name="jwksUrl">     (Optional) URL of the jwks.</param>
    // private void ProcessKeys(
    //     string clientName,
    //     ClientInfo smartClient,
    //     JsonWebKeySet keySet,
    //     List<string> messages,
    //     string? jwksUrl = null)
    // {
    //     foreach (JsonWebKey jwksKey in keySet.Keys)
    //     {
    //         if (string.IsNullOrEmpty(jwksKey.Alg))
    //         {
    //             string msg = $"TryRegisterClient <<< request {clientName} has a key missing the algorithm.";
    //             messages.Add(msg);
    //             _logger.LogWarning(msg);
    //             continue;
    //         }
    //
    //         if (!TryProcessKey(clientName, jwksKey, out SecurityKey resolvedKey, out List<string> subMessages))
    //         {
    //             if (subMessages.Any())
    //             {
    //                 messages.AddRange(subMessages);
    //             }
    //             string msg = $"TryRegisterClient <<< request {clientName}:{jwksKey.Alg} could not be processed and will not be available.";
    //             messages.Add(msg);
    //             _logger.LogWarning(msg);
    //             continue;
    //         }
    //
    //         string keyId = jwksKey.KeyId ?? jwksUrl ?? string.Empty;
    //
    //         // add or update this key
    //         smartClient.Keys[keyId] = resolvedKey;
    //     }
    // }
    //
    // /// <summary>Attempts to process key.</summary>
    // /// <param name="clientName"> Name of the client.</param>
    // /// <param name="webKey">     The web key.</param>
    // /// <param name="securityKey">[out] The security key.</param>
    // /// <param name="messages">   [out] The messages.</param>
    // /// <returns>True if it succeeds, false if it fails.</returns>
    // private bool TryProcessKey(
    //     string clientName,
    //     JsonWebKey webKey,
    //     out SecurityKey securityKey,
    //     out List<string> messages)
    // {
    //     messages = new();
    //
    //     if (string.IsNullOrEmpty(webKey.Alg))
    //     {
    //         string msg = $"TryRegisterClient <<< request {clientName} has a key missing the algorithm (alg).";
    //         messages.Add(msg);
    //         _logger.LogWarning(msg);
    //         securityKey = null!;
    //         return false;
    //     }
    //
    //     SecurityKey? resolvedKey = null;
    //
    //     switch (webKey.Alg)
    //     {
    //         case "RS384":
    //             {
    //                 bool valid = true;
    //
    //                 if (string.IsNullOrEmpty(webKey.N))
    //                 {
    //                     string msg = $"TryRegisterClient <<< request {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA Modulus (n).";
    //                     messages.Add(msg);
    //                     _logger.LogWarning(msg);
    //                     valid = false;
    //                 }
    //
    //                 if (string.IsNullOrEmpty(webKey.E))
    //                 {
    //                     string msg = $"TryRegisterClient <<< request {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA Exponent (e).";
    //                     messages.Add(msg);
    //                     _logger.LogWarning(msg);
    //                     valid = false;
    //                 }
    //
    //                 if (webKey.KeyOps.Contains("sign"))
    //                 {
    //                     if (string.IsNullOrEmpty(webKey.D))
    //                     {
    //                         string msg = $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA Private Exponent (d).";
    //                         messages.Add(msg);
    //                         _logger.LogWarning(msg);
    //                         valid = false;
    //                     }
    //
    //                     if (string.IsNullOrEmpty(webKey.P))
    //                     {
    //                         string msg = $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA First Prime Factor (p).";
    //                         messages.Add(msg);
    //                         _logger.LogWarning(msg);
    //                         valid = false;
    //                     }
    //
    //                     if (string.IsNullOrEmpty(webKey.Q))
    //                     {
    //                         string msg = $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA Second Prime Factor (q).";
    //                         messages.Add(msg);
    //                         _logger.LogWarning(msg);
    //                         valid = false;
    //                     }
    //
    //                     if (string.IsNullOrEmpty(webKey.DP))
    //                     {
    //                         string msg = $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA FirstFactorCrtExponent (dp).";
    //                         messages.Add(msg);
    //                         _logger.LogWarning(msg);
    //                         valid = false;
    //                     }
    //
    //                     if (string.IsNullOrEmpty(webKey.DQ))
    //                     {
    //                         string msg = $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA SecondFactorCrtExponent (dq).";
    //                         messages.Add(msg);
    //                         _logger.LogWarning(msg);
    //                         valid = false;
    //                     }
    //
    //                     if (string.IsNullOrEmpty(webKey.QI))
    //                     {
    //                         string msg = $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the RSA FirstCrtCoefficient (qi).";
    //                         messages.Add(msg);
    //                         _logger.LogWarning(msg);
    //                         valid = false;
    //                     }
    //                 }
    //
    //                 if (!valid)
    //                 {
    //                     securityKey = null!;
    //                     return false;
    //                 }
    //
    //                 System.Security.Cryptography.RSACryptoServiceProvider rsa = new();
    //
    //                 rsa.ImportParameters(new System.Security.Cryptography.RSAParameters()
    //                 {
    //                     Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
    //                     Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
    //                     D = string.IsNullOrEmpty(webKey.D) ? null : Base64UrlEncoder.DecodeBytes(webKey.D),
    //                     P = string.IsNullOrEmpty(webKey.P) ? null : Base64UrlEncoder.DecodeBytes(webKey.P),
    //                     Q = string.IsNullOrEmpty(webKey.Q) ? null : Base64UrlEncoder.DecodeBytes(webKey.Q),
    //                     DP = string.IsNullOrEmpty(webKey.DP) ? null : Base64UrlEncoder.DecodeBytes(webKey.DP),
    //                     DQ = string.IsNullOrEmpty(webKey.DQ) ? null : Base64UrlEncoder.DecodeBytes(webKey.DQ),
    //                     InverseQ = string.IsNullOrEmpty(webKey.QI) ? null : Base64UrlEncoder.DecodeBytes(webKey.QI),
    //                 });
    //
    //                 resolvedKey = new RsaSecurityKey(rsa);
    //             }
    //             break;
    //
    //         case "ES384":
    //             {
    //                 bool valid = true;
    //
    //                 if (string.IsNullOrEmpty(webKey.Crv))
    //                 {
    //                     string msg = $"TryRegisterClient <<< request {clientName}:{webKey.Alg} is missing the ECDSA Curve (crv).";
    //                     messages.Add(msg);
    //                     _logger.LogWarning(msg);
    //                     valid = false;
    //                 }
    //
    //                 if (string.IsNullOrEmpty(webKey.X))
    //                 {
    //                     string msg = $"TryRegisterClient <<< request {clientName}:{webKey.Alg} is missing the ECDSA X coordinate (x).";
    //                     messages.Add(msg);
    //                     _logger.LogWarning(msg);
    //                     valid = false;
    //                 }
    //
    //                 if (string.IsNullOrEmpty(webKey.Y))
    //                 {
    //                     string msg = $"TryRegisterClient <<< request {clientName}:{webKey.Alg} is missing the ECDSA Y coordinate (y).";
    //                     messages.Add(msg);
    //                     _logger.LogWarning(msg);
    //                     valid = false;
    //                 }
    //
    //                 if (webKey.KeyOps.Contains("sign"))
    //                 {
    //                     if (string.IsNullOrEmpty(webKey.D))
    //                     {
    //                         string msg = $"TryRegisterClient <<< signing key {clientName}:{webKey.Alg}:{webKey.KeyId} is missing the ECC Private Key (d).";
    //                         messages.Add(msg);
    //                         _logger.LogWarning(msg);
    //                         valid = false;
    //                     }
    //                 }
    //
    //                 if (!valid)
    //                 {
    //                     securityKey = null!;
    //                     return false;
    //                 }
    //
    //                 ECCurve curve;
    //
    //                 try
    //                 {
    //                     // try to use the named curve
    //                     curve = ECCurve.CreateFromFriendlyName(webKey.Crv);
    //                 }
    //                 catch (Exception)
    //                 {
    //                     // assume it is the default curve
    //                     curve = ECCurve.NamedCurves.nistP384;
    //                 }
    //
    //                 ECParameters parameters = new()
    //                 {
    //                     Curve = curve,
    //                     Q = new()
    //                     {
    //                         X = Base64UrlEncoder.DecodeBytes(webKey.X),
    //                         Y = Base64UrlEncoder.DecodeBytes(webKey.Y),
    //                     },
    //                     D = string.IsNullOrEmpty(webKey.D) ? null : Base64UrlEncoder.DecodeBytes(webKey.D),
    //                 };
    //
    //                 System.Security.Cryptography.ECDsa ecdsa = System.Security.Cryptography.ECDsaCng.Create(parameters);
    //                 resolvedKey = new ECDsaSecurityKey(ecdsa);
    //             }
    //             break;
    //     }
    //
    //     if (resolvedKey == null)
    //     {
    //         string msg = $"TryRegisterClient <<< request {clientName}:{webKey.Alg} could not be resolved and will not be available.";
    //         messages.Add(msg);
    //         _logger.LogWarning(msg);
    //         securityKey = null!;
    //         return false;
    //     }
    //
    //     resolvedKey.KeyId = webKey.KeyId;
    //
    //     securityKey = resolvedKey;
    //     return true;
    // }

    /// <summary>Attempts to create smart response.</summary>
    /// <param name="tenant">             The tenant name.</param>
    /// <param name="authCode">           The authorization code.</param>
    /// <param name="clientId">           The client's identifier.</param>
    /// <param name="clientSecret">       The client secret.</param>
    /// <param name="codeVerifier">       The code verifier.</param>
    /// <param name="response">           [out] The response.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool TryCreateSmartResponse(
        string tenant,
        string authCode,
        string clientId,
        string clientSecret,
        string codeVerifier,
        out AuthorizationInfo.SmartResponse response)
    {
        if (string.IsNullOrEmpty(authCode))
        {
            _logger.LogWarning("TryCreateSmartResponse <<< request is missing authorization code.");
            response = null!;
            return false;
        }

        if (authCode.Length < 36)
        {
            _logger.LogWarning($"TryCreateSmartResponse <<< request {authCode} is malformed.");
            response = null!;
            return false;
        }

        string code = authCode.Substring(0, 36);
        string key = tenant + ":" + code;

        if (!_authorizations.TryGetValue(key, out AuthorizationInfo? local))
        {
            _logger.LogWarning($"TryCreateSmartResponse <<< auth {key} does not exist.");
            response = null!;
            return false;
        }

        if (string.IsNullOrEmpty(tenant))
        {
            string msg = $"TryCreateSmartResponse <<< request {authCode} is missing the tenant.";
            local.Activity.Add(new()
            {
                RequestType = "authorization_code",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (string.IsNullOrEmpty(clientId))
        {
            string msg = $"TryCreateSmartResponse <<< request {authCode} is missing the client id.";
            local.Activity.Add(new()
            {
                RequestType = "authorization_code",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (!local.Tenant.Equals(tenant, StringComparison.OrdinalIgnoreCase))
        {
            string msg = $"TryCreateSmartResponse <<< {key} tenant ({local.Tenant}) does not match request: {tenant}.";
            local.Activity.Add(new()
            {
                RequestType = "authorization_code",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (!clientId.Equals(local.RequestParameters.ClientId, StringComparison.Ordinal))
        {
            string msg = $"TryCreateSmartResponse <<< {key} client ({local.RequestParameters.ClientId}) does not match request: {clientId}.";
            local.Activity.Add(new()
            {
                RequestType = "authorization_code",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        // check the PKCE code if one has been provided
        if (!string.IsNullOrEmpty(local.RequestParameters.PkceChallenge))
        {
            if (string.IsNullOrEmpty(codeVerifier))
            {
                string msg = $"TryCreateSmartResponse <<< code verifier is required if initial request contains PKCE!";
                local.Activity.Add(new()
                {
                    RequestType = "authorization_code",
                    Success = false,
                    Message = msg,
                });
                _logger.LogWarning(msg);
                response = null!;
                return false;
            }

            string coded = string.Empty;

            using (System.Security.Cryptography.SHA256 s256 = System.Security.Cryptography.SHA256.Create())
            {
                byte[] hash = s256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                coded = Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder.Encode(hash);
            }

            if (!coded.Equals(local.RequestParameters.PkceChallenge, StringComparison.Ordinal))
            {
                string msg = $"TryCreateSmartResponse <<< code verifier does not match PKCE challenge!";
                local.Activity.Add(new()
                {
                    RequestType = "authorization_code",
                    Success = false,
                    Message = msg,
                });
                _logger.LogWarning(msg);
                response = null!;
                return false;
            }
        }

        IEnumerable<string> permittedScopes = local.Scopes.Where(kvp => kvp.Value == true).Select(kvp => kvp.Key);

        extractScopes(permittedScopes, out HashSet<string> userScopes, out HashSet<string> patientScopes);
        local.UserScopes = userScopes;
        local.PatientScopes = patientScopes;

        // create our FHIR Context
        List<AuthorizationInfo.SmartFhirContext> fhirContext = new();

        if (!string.IsNullOrEmpty(local.LaunchPractitioner))
        {
            fhirContext.Add(new()
            {
                Type = "Practitioner",
                Reference = local.LaunchPractitioner.StartsWith("Practitioner/") ? local.LaunchPractitioner : "Practitioner/" + local.LaunchPractitioner,
            });
        }

        // check for 'special' code
        if (code.Equals(Guid.Empty.ToString()))
        {
            // update our last access
            local.LastAccessed = DateTimeOffset.UtcNow;

            // create our response
            local.Response = new()
            {
                PatientId = local.LaunchPatient,
                FhirContext = fhirContext.Any() ? fhirContext : null,
                TokenType = "bearer",
                Scopes = string.Join(" ", permittedScopes),
                ClientId = local.RequestParameters.ClientId,
                IdToken = _jwtHelper.GenerateIdJwt(_tenants[tenant].BaseUrl, local),
                AccessToken = code + "_" + code,
                RefreshToken = code + "_" + code,
            };
        }
        else
        {
            // update our last access and expiration
            local.LastAccessed = DateTimeOffset.UtcNow;
            local.Expires = DateTimeOffset.UtcNow.AddMinutes(_tokenExpirationMinutes);

            // create our response
            local.Response = new()
            {
                PatientId = local.LaunchPatient,
                FhirContext = fhirContext.Any() ? fhirContext : null,
                TokenType = "bearer",
                Scopes = string.Join(" ", permittedScopes),
                ClientId = local.RequestParameters.ClientId,
                IdToken = _jwtHelper.GenerateIdJwt(_tenants[tenant].BaseUrl, local),
                AccessToken = code + "_" + Guid.NewGuid().ToString(),    // GenerateAccessJwt(_tenants[tenant].BaseUrl, local),
                RefreshToken = code + "_" + Guid.NewGuid().ToString()
            };
        }

        local.Activity.Add(new()
        {
            RequestType = "authorization_code",
            Success = true,
            Message = $"Granted access token: {local.Response.AccessToken}, refresh token: {local.Response.RefreshToken}"
        });

        response = local.Response!;
        return true;
    }

    /// <summary>Attempts to client assertion exchange.</summary>
    /// <param name="tenantName">         The tenant.</param>
    /// <param name="remoteIpAddress">    The remote IP address.</param>
    /// <param name="clientAssertionType">Type of the client assertion.</param>
    /// <param name="clientAssertion">    The client assertion.</param>
    /// <param name="scopes">             The scopes.</param>
    /// <param name="response">           [out] The response.</param>
    /// <param name="messages">           [out] The messages.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool TryClientAssertionExchange(
        string tenantName,
        string remoteIpAddress,
        string clientAssertionType,
        string clientAssertion,
        IEnumerable<string> scopes,
        out AuthorizationInfo.SmartResponse response,
        out List<string> messages)
    {
        messages = new();

        if (string.IsNullOrEmpty(tenantName))
        {
            string msg = $"TryClientAssertionExchange <<< request {clientAssertion} is missing the tenant.";
            messages.Add(msg);
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (!_tenants.TryGetValue(tenantName, out TenantConfiguration? tenant) ||
            (tenant == null))
        {
            string msg = $"TryClientAssertionExchange <<< request {clientAssertion} has an unknown tenant {tenantName}.";
            messages.Add(msg);
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (!clientAssertionType.Equals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
        {
            string msg = $"TryClientAssertionExchange <<< invalid client assertion type: {clientAssertionType}.";
            messages.Add(msg);
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (string.IsNullOrEmpty(clientAssertion))
        {
            string msg = $"TryClientAssertionExchange <<< missing client assertion.";
            messages.Add(msg);
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (!_clientManager.TryClientAssertionExchange(clientAssertion, messages, tenant, out SmartClientInfo? smartClient))
        {
            response = null;
            return false;
        }

        var clientId = smartClient.ClientId;

        string code = Guid.NewGuid().ToString();

        extractScopes(scopes, out HashSet<string> userScopes, out HashSet<string> patientScopes);

        DateTime expiration = DateTime.UtcNow.AddHours(24);

        response = new()
        {
            TokenType = "bearer",
            Scopes = string.Join(" ", scopes),
            ClientId = clientId,
            IdToken = _jwtHelper.GenerateIdJwt(_tenants[tenantName].BaseUrl, clientId, clientId, expiration, _tenants[tenantName].BaseUrl),
            AccessToken = code + "_" + Guid.NewGuid().ToString(),    // GenerateAccessJwt(_tenants[tenant].BaseUrl, local),
            RefreshToken = code + "_" + Guid.NewGuid().ToString()
        };

        AuthorizationInfo auth = new()
        {
            Key = code,
            Tenant = tenantName,
            RemoteIpAddress = remoteIpAddress,
            RequestParameters = new()
            {
                ClientId = clientId,
                Scope = string.Join(" ", scopes),
                Audience = tenant.BaseUrl,
            },
            Expires = new DateTimeOffset(expiration).ToUniversalTime(),
        };

        _authorizations.Add(tenantName + ":" + code, auth);

        smartClient.Activity.Add(new()
        {
            RequestType = "client_assertion",
            Success = true,
            Message = $"Granted access token: {response.AccessToken}, refresh token: {response.RefreshToken}"
        });

        return true;
    }



    /// <summary>Extracts the scopes.</summary>
    /// <param name="scopes">       The scopes.</param>
    /// <param name="userScopes">   [out] The user scopes.</param>
    /// <param name="patientScopes">[out] The patient scopes.</param>
    private void extractScopes(
        IEnumerable<string> scopes,
        out HashSet<string> userScopes,
        out HashSet<string> patientScopes)
    {
        userScopes = new();
        patientScopes = new();

        // normalize our allowed scopes
        foreach (string scope in scopes)
        {
            // scopes we care about are [context]/[resource].[action][?granular]
            string[] components = scope.Split('/', '.', '?');

            // we do not care about scopes that do not match our pattern
            if (components.Length < 3)
            {
                continue;
            }

            switch (components[0])
            {
                case "user":
                    AddScope(components[1], components[2].ToLowerInvariant(), ref userScopes);
                    break;

                case "patient":
                    AddScope(components[1], components[2].ToLowerInvariant(), ref patientScopes);
                    break;
            }
        }

        void AddScope(string resource, string actions, ref HashSet<string> scopeSet)
        {
            if (string.IsNullOrEmpty(resource) || string.IsNullOrEmpty(actions))
            {
                return;
            }

            // check for v1 scopes and all (*)
            switch (actions)
            {
                case "read":
                    {
                        scopeSet.Add(resource + ".r");
                        scopeSet.Add(resource + ".s");
                        return;
                    }

                case "write":
                    {
                        scopeSet.Add(resource + ".c");
                        scopeSet.Add(resource + ".u");
                        scopeSet.Add(resource + ".d");
                        return;
                    }

                case "*":
                    {
                        scopeSet.Add(resource + ".c");
                        scopeSet.Add(resource + ".r");
                        scopeSet.Add(resource + ".u");
                        scopeSet.Add(resource + ".d");
                        scopeSet.Add(resource + ".s");
                        return;
                    }
            }

            // v2 scopes can be in any order
            if (actions.Contains('c'))
            {
                scopeSet.Add(resource + ".c");
            }

            if (actions.Contains('r'))
            {
                scopeSet.Add(resource + ".r");
            }

            if (actions.Contains('u'))
            {
                scopeSet.Add(resource + ".u");
            }

            if (actions.Contains('d'))
            {
                scopeSet.Add(resource + ".d");
            }

            if (actions.Contains('s'))
            {
                scopeSet.Add(resource + ".s");
            }
        }
    }



    /// <summary>Attempts to introspection.</summary>
    /// <param name="tenant">  The tenant.</param>
    /// <param name="token">   The token.</param>
    /// <param name="response">[out] The response.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool TryIntrospection(
        string tenant,
        string token,
        out AuthorizationInfo.IntrospectionResponse? response)
    {
        if (string.IsNullOrEmpty(token))
        {
            _logger.LogWarning("TryIntrospection <<< request is missing token.");
            response = null!;
            return false;
        }

        if (token.Length < 36)
        {
            _logger.LogWarning($"TryIntrospection <<< request {token} is malformed.");
            response = null;
            return false;
        }

        string code = token.Substring(0, 36);
        string key = tenant + ":" + code;

        if (!_authorizations.TryGetValue(key, out AuthorizationInfo? local))
        {
            _logger.LogWarning($"TryIntrospection <<< auth {key} was not found.");
            response = null!;
            return false;
        }

        if (string.IsNullOrEmpty(tenant))
        {
            string msg = $"TryIntrospection <<< request {token} is missing the tenant.";
            local.Activity.Add(new()
            {
                RequestType = "authorization_code",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (!local.Tenant.Equals(tenant, StringComparison.OrdinalIgnoreCase))
        {
            string msg = $"TryIntrospection <<< {key} tenant ({local.Tenant}) does not match request: {tenant}.";
            local.Activity.Add(new()
            {
                RequestType = "authorization_code",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null!;
            return false;
        }

        if (local.Response == null)
        {
            string msg = $"TryIntrospection <<< {key} has not retrieved an access token.";
            local.Activity.Add(new()
            {
                RequestType = "authorization_code",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null;
            return false;
        }

        if (!token.Equals(local.Response.AccessToken, StringComparison.Ordinal))
        {
            string msg = $"TryIntrospection <<< {key} access token ({local.Response.AccessToken}) does not match request: {token}.";
            local.Activity.Add(new()
            {
                RequestType = "authorization_code",
                Success = false,
                Message = msg,
            });
            _logger.LogWarning(msg);
            response = null;
            return false;
        }

        response = new()
        {
            Active = true,
            Scopes = string.Join(' ', local.Scopes.Where(kvp => kvp.Value == true).Select(kvp => kvp.Key)),
            ClientId = local.RequestParameters.ClientId,
            Username = local.UserId,
            Subject = local.UserId.GetHashCode().ToString(),
            Audience = local.RequestParameters.Audience,
            ExpiresAt = local.Expires.ToUnixTimeSeconds(),
            IssuedAt = local.LastAccessed.ToUnixTimeSeconds(),
        };

        return true;
    }


    /// <summary>Initializes this service.</summary>
    /// <exception cref="Exception">Thrown when an exception error condition occurs.</exception>
    public void Init()
    {
        if (_isInitialized)
        {
            return;
        }

        _isInitialized = true;

        _logger.LogInformation("SmartAuthManager <<< Creating FHIR tenants...");

        // initialize the requested fhir stores
        foreach ((string name, TenantConfiguration config) in _tenants)
        {
            // build smart config
            if (!config.SmartRequired && !config.SmartAllowed)
            {
                continue;
            }

            _smartConfigs.Add(name, new()
            {
                GrantTypes = new string[]
                {
                    "authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"
                },
                AuthorizationEndpoint = $"{_serverConfig.PublicUrl}/_smart/{name}/authorize",
                TokenEndpoint = $"{_serverConfig.PublicUrl}/_smart/{name}/token",
                TokenEndpointAuthMethods = new string[]
                {
                    //"client_secret_post",
                    "client_secret_basic",
                    "private_key_jwt",
                },
                TokenEndpointAuthSigningAlgs = new string[]
                {
                    "RS384",
                    "ES384",
                },
                RegistrationEndpoint = $"{_serverConfig.PublicUrl}/_smart/{name}/register",
                //AppStateEndpoint = $"{config.BaseUrl}/auth/appstate",
                SupportedScopes = new string[]
                {
                    //"openid",
                    "profile",
                    //"offline_access",
                    "fhirUser",
                    "launch",
                    "launch/patient",
                    "launch/practitioner",
                    //"launch/encounter",
                    //"patient/*.read",
                    //"patient/*.r",
                    "patient/*.*",
                    //"user/*.read",
                    //"user/*.rs",
                    "user/*.*",
                    "system/*.*",
                },
                SupportedResponseTypes = new string[]
                {
                    "code",                     // Authorization Code Flow
                    "id_token",                 // Implicit Flow
                    //"id_token token",         // Implicit Flow
                    "code id_token",            // Hybrid Flow
                    //"code token",             // Hybrid Flow
                    //"code token id_token",    // Hybrid Flow
                    "refresh_token",
                },
                ManagementEndpoint = $"{_serverConfig.PublicUrl}/smart/clients",
                IntrospectionEndpoint = $"{_serverConfig.PublicUrl}/_smart/{name}/introspect",
                //RecovationEndpoint = $"{config.BaseUrl}/auth/revoke",
                Capabilities = new string[]
                {
                    // TODO replace with more appropriate names.
                    "smart-imaging-access",                     // Imaging Access using dual-launch token exchange
                    "dual-launch-access",                       // Alternative for previous - signal support for dual access

                    //"launch-ehr",                             // SMART's EHR Launch mode
                    "launch-standalone",                        // SMART's Standalone Launch mode
                    //"authorize-post",                         // POST-based authorization
                    "client-public",                            // SMART's public client profile (no client authentication)
                    "client-confidential-symmetric",            // SMART's symmetric confidential client profile ("client secret" authentication)
                    "client-confidential-asymmetric",           // SMART's asymmetric confidential client profile ("JWT authentication")
                    //"sso-openid-connect",                     // SMART's OpenID Connect profile
                    //"context-banner",                         // "need patient banner" launch context (conveyed via need_patient_banner token parameter)
                    //"context-style",                          // "SMART style URL" launch context (conveyed via smart_style_url token parameter). This capability is deemed experimental.
                    //"context-ehr-patient",                    // patient-level launch context (requested by launch/patient scope, conveyed via patient token parameter)
                    //"context-ehr-encounter",                  // encounter-level launch context (requested by launch/encounter scope, conveyed via encounter token parameter)
                    "context-standalone-patient",               // patient-level launch context (requested by launch/patient scope, conveyed via patient token parameter)
                    //"context-standalone-encounter",           // encounter-level launch context (requested by launch/encounter scope, conveyed via encounter token parameter)
                    //"permission-offline",                     // refresh tokens (requested by offline_access scope)
                    //"permission-online",                      // refresh tokens (requested by online_access scope)
                    "permission-patient",                       // patient-level scopes (e.g., patient/Observation.rs)
                    "permission-user",                          // user-level scopes (e.g., user/Appointment.rs)
                    "permission-v1",                            // SMARTv1 scope syntax (e.g., patient/Observation.read)
                    "permission-v2",                            // SMARTv2 granular scope syntax (e.g., patient/Observation.rs?...)
                    //"smart-app-state",                        // managing SMART App State - experimental
                },
                SupportedChallengeMethods = new string[]
                {
                    "S256",
                },
            });

            // create our 'always available' authorization
            AuthorizationInfo auth = new()
            {
                Key = Guid.Empty.ToString(),
                Tenant = name,
                RemoteIpAddress = "127.0.0.1",
                Created = DateTimeOffset.UtcNow,
                LastAccessed = DateTimeOffset.UtcNow,
                Expires = DateTimeOffset.MaxValue,
                UserId = "administrator",
                RequestParameters = new()
                {
                    ResponseType = "code",
                    ClientId = "fhir-candle",
                    RedirectUri = string.Empty,
                    Scope = "fhirUser profile user/*.*",
                    Audience = $"{_serverConfig.PublicUrl}/fhir/{name}",
                },
                AuthCode = Guid.Empty.ToString() + "_" + Guid.Empty.ToString(),
            };

            foreach (string scopeKey in auth.Scopes.Keys)
            {
                auth.Scopes[scopeKey] = true;
            }

            auth.UserScopes.Add("*.*");

            auth.Response = new()
            {
                TokenType = "bearer",
                Scopes = "fhirUser profile user/*.*",
                ClientId = "fhir-candle",
                IdToken = _jwtHelper.GenerateIdJwt(auth.RequestParameters.Audience, auth),
                AccessToken = Guid.Empty.ToString() + "_" + Guid.Empty.ToString(),
                RefreshToken = Guid.Empty.ToString() + "_" + Guid.Empty.ToString(),
            };

            _authorizations.Add(name + ":" + Guid.Empty.ToString(), auth);
        }

        // look for preconfigured users
        //string root =
        //    Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location ?? AppContext.BaseDirectory) ??
        //    Environment.CurrentDirectory ??
        //    string.Empty;

        //if (!string.IsNullOrEmpty(_serverConfig.ReferenceImplementation))
        //{
        //    // look for a package supplemental directory
        //    string supplemental = string.IsNullOrEmpty(_serverConfig.SourceDirectory)
        //        ? Program.FindRelativeDir(root, Path.Combine("fhirData", _serverConfig.ReferenceImplementation), false)
        //        : Path.Combine(_serverConfig.SourceDirectory, _serverConfig.ReferenceImplementation);

        //    LoadRiContents(supplemental);
        //}
    }

    /// <summary>Request authentication.</summary>
    /// <param name="tenant">             The tenant.</param>
    /// <param name="remoteIpAddress">    The remote IP address.</param>
    /// <param name="responseType">       Fixed value: code.</param>
    /// <param name="clientId">           The client's identifier.</param>
    /// <param name="redirectUri">        Must match one of the client's pre-registered redirect URIs.</param>
    /// <param name="launch">             When using the EHR Launch flow, this must match the launch
    ///     value received from the EHR. Omitted when using the Standalone Launch.</param>
    /// <param name="scope">              Must describe the access that the app needs.</param>
    /// <param name="state">              An opaque value used by the client to maintain state between
    ///     the request and callback.</param>
    /// <param name="audience">           URL of the EHR resource server from which the app wishes to
    ///     retrieve FHIR data.</param>
    /// <param name="pkceChallenge">      This parameter is generated by the app and used for the code challenge, as specified by PKCE. (required v2, opt v1)</param>
    /// <param name="pkceMethod">         Method used for the code_challenge parameter. (required v2,  opt v1)</param>
    /// <param name="idTokenHint">        ID token as hint for dual launch.</param>
    /// <param name="redirectDestination">[out] The redirect destination.</param>
    /// <param name="authKey">            [out] The authentication key.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool RequestAuth(string tenant,
        string remoteIpAddress,
        string responseType,
        string clientId,
        string redirectUri,
        string? launch,
        string scope,
        string state,
        string audience,
        string? pkceChallenge,
        string? pkceMethod,
        string? idTokenHint,
        out string redirectDestination,
        out string authKey)
    {
        if (!_smartConfigs.ContainsKey(tenant))
        {
            redirectDestination = string.Empty;
            authKey = string.Empty;
            return false;
        }

        // check our audience
        if (!audience.Equals(_tenants[tenant].BaseUrl, StringComparison.OrdinalIgnoreCase))
        {
            if (audience.EndsWith('/') && !_tenants[tenant].BaseUrl.EndsWith('/'))
            {
                if (!audience.Equals(_tenants[tenant].BaseUrl + "/", StringComparison.OrdinalIgnoreCase))
                {
                    redirectDestination = string.Empty;
                    authKey = string.Empty;
                    return false;
                }
            }
            else if (_tenants[tenant].BaseUrl.EndsWith('/') && !audience.EndsWith('/'))
            {
                if (!audience.Equals(_tenants[tenant].BaseUrl.Substring(0, _tenants[tenant].BaseUrl.Length - 1), StringComparison.OrdinalIgnoreCase))
                {
                    redirectDestination = string.Empty;
                    authKey = string.Empty;
                    return false;
                }
            }
            else
            {
                redirectDestination = string.Empty;
                authKey = string.Empty;
                return false;
            }
        }

        // create our auth
        AuthorizationInfo auth = new()
        {
            Key = Guid.NewGuid().ToString(),
            Tenant = tenant,
            RemoteIpAddress = remoteIpAddress,
            RequestParameters = new()
            {
                ResponseType = responseType,
                ClientId = clientId,
                RedirectUri = redirectUri,
                Launch = launch,
                Scope = scope,
                State = state,
                Audience = audience,
                IdTokenHint = idTokenHint,
                PkceChallenge = pkceChallenge,
                PkceMethod = pkceMethod,
            },
            Expires = DateTimeOffset.UtcNow.AddMinutes(_tokenExpirationMinutes),
        };

        auth.AuthCode = auth.Key + "_" + Guid.NewGuid().ToString();

        _authorizations.Add(tenant + ":" + auth.Key, auth);
        authKey = auth.Key;

        if (string.IsNullOrEmpty(idTokenHint))
        {
            redirectDestination = $"/smart/login?store={tenant}&key={auth.Key}";
            return true;
        }

        // parse id token hint
        if (!_jwtHelper.ParseIdToken(idTokenHint, out SecurityToken? token))
        {
            redirectDestination = string.Empty;
            return false;
        }

        string tokenIss = token.Issuer;

        if (tokenIss.Equals(audience))
        {
            // redirect to this server - login as normal
            redirectDestination = $"/smart/login?store={tenant}&key={auth.Key}";
            return true;
        }

        // load well known endpoint
        HttpClient client = new HttpClient();
        string wellKnownUrl = $"{tokenIss}/.well-known/smart-configuration";
        SmartWellKnown? wellKnownResponse;
        try
        {
            wellKnownResponse =
                client.GetFromJsonAsync<SmartWellKnown>(wellKnownUrl).GetAwaiter().GetResult();
        }
        catch (Exception e)
        {
            redirectDestination = string.Empty;
            return false;
        }

        if ( wellKnownResponse == null)
        {
            redirectDestination = string.Empty;
            return false;
        }
        auth.EhrLaunch = new AuthorizationInfo.EhrLaunchData( tokenIss, wellKnownResponse );

        string authorizeEndpoint = wellKnownResponse.AuthorizationEndpoint;
        redirectDestination = authorizeEndpoint + (authorizeEndpoint.Contains('?') ? "&" : "?") +
                               "response_type=code" +
                              $"&client_id={clientId}" +
                               "&redirect_uri=/smart/ehr_redirect" +
                              $"&state={tenant + ":" + auth.Key}" +
                              $"&id_tokent_hint={idTokenHint}" +
                               "&prompt=none" +
                              $"&aud={tokenIss}" +
                              $"&scope={scope}";
        return true;
    }

    public bool TryEhrRedirect(string storeName, string code, string state, out string redirect )
    {
        if (!_authorizations.TryGetValue(storeName + ":" + state, out AuthorizationInfo? auth))
        {
            _logger.LogWarning($"EHR redirect with {state} not found.");
            redirect = "";
            return false;
        }

        // get token
        // load well known endpoint
        HttpClient client = new HttpClient();
        string tokenUrl = auth.EhrLaunch.SmartWellKnown.TokenEndpoint;
        string url = tokenUrl + (tokenUrl.Contains('?') ? "&" : "?") +
                     "grant_type=authorization_code" +
                     $"&code={code}" +
                     "&redirect_uri=/smart/ehr_redirect";


        TokenResponse? tokenResponse;
        try
        {
            tokenResponse =
                client.GetFromJsonAsync<TokenResponse>(url).GetAwaiter().GetResult();
        }
        catch (Exception e)
        {
            redirect = "";
            return false;
        }

        // update our last access
        auth.LastAccessed = DateTimeOffset.UtcNow;

        // GET patient and User
        string? patient;
        string? user;

        // FhirClient fhirClient;
        try
        {
            tokenResponse =
                client.GetFromJsonAsync<TokenResponse>(url).GetAwaiter().GetResult();
        }
        catch (Exception e)
        {
            redirect = "";
            return false;
        }

        // GET

    //     // create our response
    //     local.Response = new()
    //     {
    //         PatientId = local.LaunchPatient,
    //         FhirContext = fhirContext.Any() ? fhirContext : null,
    //         TokenType = "bearer",
    //         Scopes = string.Join(" ", permittedScopes),
    //         ClientId = local.RequestParameters.ClientId,
    //         IdToken = _jwtHelper.GenerateIdJwt(_tenants[tenant].BaseUrl, local),
    //         AccessToken = code + "_" + code,
    //         RefreshToken = code + "_" + code,
    //     };
    // }
    // else
    // {
    //     // update our last access and expiration
    //     local.LastAccessed = DateTimeOffset.UtcNow;
    //     local.Expires = DateTimeOffset.UtcNow.AddMinutes(_tokenExpirationMinutes);
    //
    //     // create our response
    //     local.Response = new()
    //     {
    //         PatientId = local.LaunchPatient,
    //         FhirContext = fhirContext.Any() ? fhirContext : null,
    //         TokenType = "bearer",
    //         Scopes = string.Join(" ", permittedScopes),
    //         ClientId = local.RequestParameters.ClientId,
    //         IdToken = _jwtHelper.GenerateIdJwt(_tenants[tenant].BaseUrl, local),
    //         AccessToken = code + "_" + Guid.NewGuid().ToString(),    // GenerateAccessJwt(_tenants[tenant].BaseUrl, local),
    //         RefreshToken = code + "_" + Guid.NewGuid().ToString()
    //     };
    // }
    //
    // local.Activity.Add(new()
    // {
    //     RequestType = "authorization_code",
    //     Success = true,
    //     Message = $"Granted access token: {local.Response.AccessToken}, refresh token: {local.Response.RefreshToken}"
    // });
    //
    // response = local.Response!;
    // return true;
        redirect = "";
        return false;
    }


    /// <summary>Triggered when the application host is ready to start the service.</summary>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>An asynchronous result.</returns>
    Task IHostedService.StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting SmartAuthManager...");

        Init();

        return Task.CompletedTask;
    }

    /// <summary>Triggered when the application host is performing a graceful shutdown.</summary>
    /// <param name="cancellationToken">Indicates that the shutdown process should no longer be
    ///  graceful.</param>
    /// <returns>An asynchronous result.</returns>
    Task IHostedService.StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    /// <summary>
    /// Releases the unmanaged resources used by the
    /// FhirModelComparer.Server.Services.FhirManagerService and optionally releases the managed
    /// resources.
    /// </summary>
    /// <param name="disposing">True to release both managed and unmanaged resources; false to
    ///  release only unmanaged resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!_hasDisposed)
        {
            // dispose managed state (managed objects)
            if (disposing)
            {
                //foreach (IFhirStore store in _storesByController.Values)
                //{
                //    store.OnSubscriptionSendEvent -= FhirStoreManager_OnSubscriptionSendEvent;
                //}
            }

            // free unmanaged resources (unmanaged objects) and override finalizer
            // set large fields to null
            _hasDisposed = true;
        }
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged
    /// resources.
    /// </summary>
    void IDisposable.Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
