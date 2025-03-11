// <copyright file="SmartAuthManager.cs" company="Microsoft Corporation">
//     Copyright (c) Microsoft Corporation. All rights reserved.
//     Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// </copyright>


using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using FhirCandle.Authorization.Models;
using FhirCandle.Authorization.Services;
using FhirCandle.Configuration;
using FhirCandle.Models;
using FhirCandle.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace fhir.candle.Services;

/// <summary>Manager for smart authentications.</summary>
public class SmartAuthManager : SmartAuthorizationManager, ISmartAuthManager, IDisposable
{
    public SmartAuthManager(
        Dictionary<string, TenantConfiguration> tenants,
        IFhirStoreManager fhirStores,
        CandleConfig serverConfiguration,
        ILogger<SmartAuthorizationManager>? logger) : base(tenants, fhirStores, serverConfiguration, logger)
    {
    }
}
