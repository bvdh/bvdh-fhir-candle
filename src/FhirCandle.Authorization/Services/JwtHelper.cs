using System.IdentityModel.Tokens.Jwt;
using FhirCandle.Authorization.Models;
using Microsoft.IdentityModel.Tokens;

namespace FhirCandle.Authorization.Services
{
    public class JwtHelper
    {
        /// <summary>(Immutable) The jwt signing value in bytes.</summary>
        private readonly byte[] _jwtBytes;

        private readonly ISmartClientManager _clientManager;

        public JwtHelper(string seed, ISmartClientManager smartClientManager)
        {
            _jwtBytes = System.Text.Encoding.UTF8.GetBytes(seed);
            _clientManager = smartClientManager;

        }


        /// <summary>Generates a signed jwt.</summary>
        /// <param name="issuer">    The issuer.</param>
        /// <param name="subject">   The subject.</param>
        /// <param name="audience">  URL of the EHR resource server from which the app wishes to retrieve
        ///  FHIR data.</param>
        /// <param name="expiration">The expiration Date/Time.</param>
        /// <param name="webKey">    The web key.</param>
        /// <param name="jti">       (Optional) The jti.</param>
        /// <returns>The signed jwt.</returns>
        public string GenerateSignedJwt(
            string issuer,
            string subject,
            string audience,
            string jti,
            DateTime expiration,
            JsonWebKey webKey)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new System.Security.Claims.Claim[]
                {
                    //new("iss", issuer),
                    new("sub", subject),
                    //new("aud", audience),
                    new("jti", jti),
                }),
                Expires = expiration,
                Audience = audience,
                Issuer = issuer,
                IssuedAt = DateTime.UtcNow,
            };

            if ( _clientManager.TryProcessKey(issuer, webKey, out SecurityKey securityKey, out _))
            {
                tokenDescriptor.SigningCredentials = new SigningCredentials(securityKey, webKey.Alg);
            }

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        /// <summary>Generates an id-token jwt.</summary>
        /// <param name="rootUrl">URL of the root.</param>
        /// <param name="auth">   [out] The authentication.</param>
        /// <returns>The identifier jwt.</returns>
        public string GenerateIdJwt(string rootUrl, AuthorizationInfo auth)
        {
            return GenerateIdJwt(
                rootUrl,
                auth.Key + "_" + Guid.NewGuid(),
                auth.UserId,
                auth.RequestParameters.Audience,
                auth.LastAccessed.DateTime,
                auth.Expires.DateTime);
        }
        /// <summary>Generates an id-token jwt.</summary>
        /// <param name="rootUrl">URL of the root.</param>
        /// <param name="auth">   [out] The authentication.</param>
        /// <returns>The identifier jwt.</returns>
        public string GenerateIdJwt(string rootUrl, string sub, string userId, string audience, DateTime lastAccessed, DateTime expires )
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new System.Security.Claims.Claim[]
                {
                    new("sub", sub),
                    new("profile", userId),
                    new("fhirUser", userId),
                    new("jti", Guid.NewGuid().ToString()),
                }),
                Expires = expires,
                Audience = audience,
                Issuer = rootUrl,
                IssuedAt = lastAccessed,
                SigningCredentials = new(new SymmetricSecurityKey(_jwtBytes), SecurityAlgorithms.HmacSha256Signature),
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        /// <summary>Generates an id-token jwt.</summary>
        /// <param name="rootUrl"> URL of the root.</param>
        /// <param name="subRoot"> The sub root.</param>
        /// <param name="userId">  Identifier for the user.</param>
        /// <param name="expires"> The expires Date/Time.</param>
        /// <param name="audience">URL of the EHR resource server from which the app wishes to retrieve
        ///  FHIR data.</param>
        /// <returns>The identifier jwt.</returns>
        internal string GenerateIdJwt(
            string rootUrl,
            string subRoot,
            string userId,
            DateTime expires,
            string audience)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new System.Security.Claims.Claim[]
                {
                    new("sub", subRoot + "_" + Guid.NewGuid().ToString()),
                    new("profile", userId),
                    new("fhirUser", userId),
                    new("jti", Guid.NewGuid().ToString()),
                }),
                Expires = expires,
                Audience = audience,
                Issuer = rootUrl,
                IssuedAt = DateTime.Now,
                SigningCredentials = new(new SymmetricSecurityKey(_jwtBytes), SecurityAlgorithms.HmacSha256Signature),
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        /// <summary>Generates an access-token jwt.</summary>
        /// <param name="rootUrl">URL of the root.</param>
        /// <param name="auth">   [out] The authentication.</param>
        /// <returns>The jwt.</returns>
        internal string GenerateAccessJwt(string rootUrl, AuthorizationInfo auth)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new System.Security.Claims.Claim[]
                {
                    new("sub", auth.UserId.GetHashCode().ToString()),
                    new("jti", Guid.NewGuid().ToString()),
                    //new("aud", auth.RequestParameters.Audience),
                    //new("iss", rootUrl),
                    //new("exp", auth.Expires.ToUnixTimeSeconds().ToString()),
                    //new("iat", auth.Created.ToUnixTimeSeconds().ToString()),
                }),
                Expires = auth.Expires.DateTime,
                Audience = auth.RequestParameters.Audience,
                Issuer = rootUrl,
                IssuedAt = auth.LastAccessed.DateTime,
                SigningCredentials = new(new SymmetricSecurityKey(_jwtBytes), SecurityAlgorithms.HmacSha256Signature),
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public object validateToken(string jwtTokenStr, SecurityKey publicKey, out SecurityToken? validatedToken )
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            var jsonToken = tokenHandler.ReadToken(jwtTokenStr);

            var validationParameters = new TokenValidationParameters()
            {
                ValidateLifetime = false, // Because there is no expiration in the generated token
                ValidateAudience = false, // Because there is no audiance in the generated token
                ValidateIssuer = false,   // Because there is no issuer in the generated token
                ValidIssuer = "Sample",
                ValidAudience = "Sample",
                IssuerSigningKey = publicKey
            };
            try
            {
                var principal = tokenHandler.ValidateToken(jwtTokenStr, validationParameters, out validatedToken);
            }
            catch (Exception e)
            {
                validatedToken = null;
                return false;
            }
            return true;
        }

        public bool ParseIdToken(string idTokenHint, out SecurityToken? jsonToken)
        {
            try
            {
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                jsonToken = tokenHandler.ReadToken(idTokenHint);
                return true;
            }
            catch (Exception e)
            {
                jsonToken = null;
                return false;
            }
        }
    }
}
