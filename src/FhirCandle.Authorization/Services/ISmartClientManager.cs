using FhirCandle.Authorization.Models;
using FhirCandle.Models;
using Microsoft.IdentityModel.Tokens;

namespace FhirCandle.Authorization.Services
{
    public abstract class ISmartClientManager
    {
        public Dictionary<string,ClientInfo> SmartClients { get; }

        public abstract bool TryClientAssertionExchange(string clientAssertion,
            List<string> messages, TenantConfiguration tenant,
            out ClientInfo? smartClient);

        public abstract bool TryRegisterClient(SmartClientRegistration registration, string theClientId, List<string> theMessages);

        public abstract bool TryProcessKey(string clientName, JsonWebKey webKey, out SecurityKey securityKey,
            out List<string> messages);
    }
}
