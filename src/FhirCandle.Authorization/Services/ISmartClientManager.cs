using FhirCandle.Authorization.Models;
using FhirCandle.Models;
using Microsoft.IdentityModel.Tokens;

namespace FhirCandle.Authorization.Services
{
    public abstract class ISmartClientManager
    {
        public abstract Dictionary<string,SmartClientInfo> getSmartClients();

        public abstract bool TryClientAssertionExchange(string clientAssertion,
            List<string> messages, TenantConfiguration tenant,
            out SmartClientInfo? smartClient);

        public abstract bool TryRegisterClient(SmartClientRegistration registration, out string theClientId, out List<string> theMessages);

        public abstract bool TryProcessKey(string clientName, JsonWebKey webKey, out SecurityKey securityKey,
            out List<string> messages);
    }
}
