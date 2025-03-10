using fhir.candle.Tests.Extensions;
using FhirCandle.Authorization.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using Xunit.Abstractions;

namespace fhir.candle.Tests
{
    public class JwtTests: IDisposable
    {
        [FileData("data/smart/smart.rs384.private.json", "data/smart/smart.rs384.public.json")]
        [Theory]
        public void TestIdTokenGeneration(string privateJson, string publicJson)
        {
            string iss = "https://example.com";
            string baseUrl = "http://localhost/fhir/r4";

            JsonWebKeySet privateKeySet = new(privateJson);
            JsonWebKeySet publicKeySet = new(publicJson);

            JsonWebKey? signingKey = privateKeySet.Keys.Where(wk => wk.KeyOps.Contains("sign")).FirstOrDefault();
            JsonWebKey? verifyKey  = privateKeySet.Keys.Where(wk => wk.KeyOps.Contains("verify")).FirstOrDefault();

            signingKey.ShouldNotBeNull("there should be a 'sign' capable key in the private set");
            if (signingKey == null)
            {
                return;
            }
            JwtHelper jwtHelper = new JwtHelper("seed", new SmartClientManager(NullLoggerFactory.Instance.CreateLogger<SmartAuthorizationManager>()));
            string clientAssertion = jwtHelper.GenerateSignedJwt(
                iss,
                iss,
                baseUrl,
                Guid.NewGuid().ToString(),
                DateTime.UtcNow.AddMinutes(10),
                signingKey);

            clientAssertion.ShouldNotBeNull();

            SecurityToken token;
            jwtHelper.validateToken(clientAssertion, verifyKey, out token ).ShouldBe(true);
            token.ShouldNotBeNull();
            token.Issuer.ShouldBe(iss);

        }

        private readonly ITestOutputHelper _testOutputHelper;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtTests"/> class.
        /// </summary>
        /// <param name="testOutputHelper">The test output helper.</param>
        public JwtTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged
        /// resources.
        /// </summary>
        public void Dispose()
        {
            // cleanup
        }
    }
}
