﻿// <copyright file="FhirRequestContext.cs" company="Microsoft Corporation">
//     Copyright (c) Microsoft Corporation. All rights reserved.
//     Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// </copyright>

using FhirCandle.Storage;
using Microsoft.Extensions.Primitives;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Mime;
using System.Reflection.PortableExecutable;
using static FhirCandle.Storage.Common;

namespace FhirCandle.Models;

/// <summary>A FHIR request context.</summary>
public record class FhirRequestContext
{
    private string? _url = null;
    private string _httpMethod = string.Empty;
    private IFhirStore _store = null!;
    private StoreInteractionCodes? _interaction = null;
    private string _errorMessage = string.Empty;
    private string _urlPath = string.Empty;
    private string _urlQuery = string.Empty;
    private string _resourceType = string.Empty;
    private string _id = string.Empty;
    private string _operationName = string.Empty;
    private string _compartmentType = string.Empty;
    private string _version = string.Empty;

    /// <summary>Initializes a new instance of the <see cref="FhirRequestContext"/> class.</summary>
    public FhirRequestContext() { }

    /// <summary>Initializes a new instance of the <see cref="FhirRequestContext"/> class.</summary>
    /// <param name="store">     The store.</param>
    /// <param name="httpMethod">The HTTP method.</param>
    /// <param name="url">       URL of the resource.</param>
    [SetsRequiredMembers]
    public FhirRequestContext(
        IFhirStore store,
        string httpMethod,
        string url)
    {
        Store = store;
        TenantName = store.Config.ControllerName;
        HttpMethod = httpMethod;
        Url = url;
        _ = TryParseRequest();
    }

    /// <summary>Initializes a new instance of the <see cref="FhirRequestContext"/> class.</summary>
    /// <param name="other">The other.</param>
    [SetsRequiredMembers]
    protected FhirRequestContext(FhirRequestContext other)
    {
        TenantName = other.TenantName;
        Store = other.Store;
        HttpMethod = other.HttpMethod;
        Url = other.Url;
        Authorization = other.Authorization;
        SourceContent = other.SourceContent;
        SourceFormat = other.SourceFormat;
        DestinationFormat = other.DestinationFormat;
        SerializePretty = other.SerializePretty;
        SerializeSummaryFlag = other.SerializeSummaryFlag;
        IfMatch = other.IfMatch;
        IfModifiedSince = other.IfModifiedSince;
        IfNoneMatch = other.IfNoneMatch;
        IfNoneExist = other.IfNoneExist;
        AllowExistingId = other.AllowExistingId;
        AllowCreateAsUpdate = other.AllowCreateAsUpdate;
        _errorMessage = other.ErrorMessage;
        RequestHeaders = other.RequestHeaders.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

        // make sure to read interaction before other 'parseable' properties
        Interaction = other.Interaction;
        UrlPath = other.UrlPath;
        UrlQuery = other.UrlQuery;
        ResourceType = other.ResourceType;
        Id = other.Id;
        OperationName = other.OperationName;
        CompartmentType = other.CompartmentType;
        Version = other.Version;
    }

    /// <summary>Gets or initializes the name of the tenant.</summary>
    public required string TenantName { get; init; }

    /// <summary>Gets or sets the store.</summary>
    public required IFhirStore Store 
    { 
        get => _store;
        init
        {
            _store = value;
            _ = TryParseRequest();
        }
    }

    /// <summary>Gets or initializes the HTTP method.</summary>
    public required string HttpMethod 
    { 
        get => _httpMethod;
        init
        {
            _httpMethod = value.ToUpperInvariant();
            _ = TryParseRequest();
        }
    }

    /// <summary>Gets or initializes the URL of the document.</summary>
    public required string Url 
    { 
        get => _url ?? string.Empty;
        init
        {
            _url = value;
            _ = TryParseRequest();
        }
    }

    /// <summary>Gets or initializes the authorization.</summary>
    public required AuthorizationInfo? Authorization { get; init; }

    /// <summary>Gets or initializes source format.</summary>
    public string SourceFormat { get; init; } = string.Empty;

    /// <summary>Gets or initializes source content.</summary>
    public string SourceContent { get; init; } = string.Empty;
    
    /// <summary>Gets or initializes destination format (default to fhir+json).</summary>
    public string DestinationFormat { get; init; } = "application/fhir+json";

    /// <summary>Gets or initializes a value indicating whether the serialize pretty.</summary>
    public bool SerializePretty { get; init; } = false;

    /// <summary>Gets or initializes the serialize summary flag.</summary>
    public string SerializeSummaryFlag { get; init; } = string.Empty;

    /// <summary>Gets or initializes if match.</summary>
    public string IfMatch { get; init; } = string.Empty;

    /// <summary>Gets or initializes if modified since.</summary>
    public string IfModifiedSince { get; init; } = string.Empty;

    /// <summary>Gets or initializes if none match.</summary>
    public string IfNoneMatch { get; init; } = string.Empty;

    /// <summary>Gets or initializes if none exist.</summary>
    public string IfNoneExist { get; init; } = string.Empty;

    /// <summary>
    /// Gets or initializes a value indicating whether we allow existing identifier.
    /// </summary>
    public bool AllowExistingId { get; init; } = true;

    /// <summary>
    /// Gets or initializes a value indicating whether we allow create as update.
    /// </summary>
    public bool AllowCreateAsUpdate { get; init; } = true;

    /// <summary>Gets a message describing the error.</summary>
    public string ErrorMessage { get => _errorMessage; }

    /// <summary>Gets the full pathname of the URL file.</summary>
    public string UrlPath { get => _urlPath; init => _urlPath = value; }

    /// <summary>Gets the URL query.</summary>
    public string UrlQuery { get => _urlQuery; init => _urlQuery = value; }

    /// <summary>Gets or initializes the request headers.</summary>
    public Dictionary<string, StringValues> RequestHeaders { get; init; } = new Dictionary<string, StringValues>();

    /// <summary>Gets the type of the resource.</summary>
    public string ResourceType { get => _resourceType; init => _resourceType = value; }

    /// <summary>Gets the identifier.</summary>
    public string Id { get => _id; init => _id = value; }

    /// <summary>Gets the name of the operation.</summary>
    public string OperationName { get => _operationName; init => _operationName = value; }

    /// <summary>Gets the type of the compartment.</summary>
    public string CompartmentType { get => _compartmentType; init => _compartmentType = value; }

    /// <summary>Get the version.</summary>
    public string Version { get => _version; init => _version = value; }

    /// <summary>Gets or intializes the interaction.</summary>
    public StoreInteractionCodes? Interaction { get => _interaction; init => _interaction = value; }

    /// <summary>Query if this object is authorized.</summary>
    /// <returns>True if authorized, false if not.</returns>
    public bool IsAuthorized()
    {
        if (Authorization == null)
        {
            if (Store.Config.SmartRequired)
            {
                return false;
            }

            return true;
        }

        if (_interaction == null)
        {
            if ((!TryParseRequest()) ||
                (_interaction == null))
            {
                return false;
            }
        }

        return Authorization.IsAuthorized((StoreInteractionCodes)_interaction, _httpMethod, _resourceType);
    }

    /// <summary>Attempts to parse this request.</summary>
    /// <returns>True if it succeeds, false if it fails.</returns>
    internal bool TryParseRequest()
    {
        if ((_store == null) ||
            string.IsNullOrEmpty(_httpMethod) ||
            (_url == null))
        {
            return false;
        }

        if (_interaction != null)
        {
            return true;
        }

        string requestUrlPath;
        string requestUrlQuery;

        string[] pathAndQuery = _url.Split('?', StringSplitOptions.RemoveEmptyEntries);

        switch (pathAndQuery.Length)
        {
            case 0:
                requestUrlPath = string.Empty;
                requestUrlQuery = string.Empty;
                break;

            case 1:
                if (_url.StartsWith('?'))
                {
                    requestUrlPath = string.Empty;
                    requestUrlQuery = pathAndQuery[0];
                }
                else
                {
                    requestUrlPath = pathAndQuery[0];
                    requestUrlQuery = string.Empty;
                }
                break;

            case 2:
                requestUrlPath = pathAndQuery[0];
                requestUrlQuery = pathAndQuery[1];
                break;

            default:
                // assume there are query parameters that contain '?'
                requestUrlPath = pathAndQuery[0];
                requestUrlQuery = string.Join('?', pathAndQuery[1..]);
                break;
        }

        if (requestUrlPath.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            requestUrlPath.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            requestUrlPath = requestUrlPath.Substring(requestUrlPath.IndexOf(':'));
            string configUrl = _store.Config.BaseUrl.Substring(_store.Config.BaseUrl.IndexOf(':'));

            if (requestUrlPath.StartsWith(configUrl, StringComparison.OrdinalIgnoreCase))
            {
                requestUrlPath = requestUrlPath.Substring(configUrl.Length);
                if (requestUrlPath.StartsWith('/'))
                {
                    requestUrlPath = requestUrlPath.Substring(1);
                }
            }
            else
            {
                _errorMessage = $"DetermineInteraction: Full URL: {_url} cannot be parsed!";
                Console.WriteLine(_errorMessage);

                return false;
            }
        }

        _urlPath = requestUrlPath;
        _urlQuery = requestUrlQuery;

        bool hasQueryParameters = false;
        if (!string.IsNullOrEmpty(requestUrlQuery))
        {
            // need to parse into KVPs

            System.Collections.Specialized.NameValueCollection queryParams = System.Web.HttpUtility.ParseQueryString(requestUrlQuery);

            foreach (string? key in queryParams.AllKeys ?? Array.Empty<string>())
            {
                if (string.IsNullOrEmpty(key) ||
                    Search.Common.HttpParameters.Contains(key) ||
                    Search.Common.SearchResultParameters.Contains(key))
                {
                    continue;
                }

                hasQueryParameters = true;
                break;
            }
        }

        string[] pathComponents = requestUrlPath.Split('/', StringSplitOptions.RemoveEmptyEntries);

        bool hasValidResourceType = pathComponents.Any()
            ? _store.Keys.Contains(pathComponents[0])
            : false;

        if (hasValidResourceType)
        {
            _resourceType = pathComponents[0];
        }

        switch (_httpMethod)
        {
            case "GET":
                {
                    switch (pathComponents.Length)
                    {
                        case 0:
                            {
                                _interaction = StoreInteractionCodes.SystemSearch;

                                return true;
                            }

                        case 1:
                            {
                                if (hasValidResourceType)
                                {
                                    _interaction = StoreInteractionCodes.TypeSearch;

                                    return true;
                                }

                                if (pathComponents[0].Equals("metadata", StringComparison.Ordinal))
                                {
                                    _interaction = StoreInteractionCodes.SystemCapabilities;

                                    return true;
                                }

                                if (pathComponents[0].Equals("_history", StringComparison.Ordinal))
                                {
                                    _interaction = StoreInteractionCodes.SystemHistory;

                                    return true;
                                }

                                if (pathComponents[0].StartsWith('$'))
                                {
                                    _operationName = pathComponents[0];
                                    _interaction = StoreInteractionCodes.SystemOperation;

                                    return true;
                                }
                            }
                            break;

                        case 2:
                            {
                                if (hasValidResourceType)
                                {
                                    if (pathComponents[1].StartsWith('$'))
                                    {
                                        _operationName = pathComponents[1];
                                        _interaction = StoreInteractionCodes.TypeOperation;

                                        return true;
                                    }

                                    _id = pathComponents[1];
                                    _interaction = StoreInteractionCodes.InstanceRead;

                                    return true;
                                }
                            }
                            break;

                        case 3:
                            {
                                if (hasValidResourceType)
                                {
                                    if (pathComponents[2].StartsWith('$'))
                                    {
                                        _id = pathComponents[1];
                                        _operationName = pathComponents[2];
                                        _interaction = StoreInteractionCodes.InstanceOperation;

                                        return true;
                                    }

                                    if (pathComponents[2].Equals("_history", StringComparison.Ordinal))
                                    {
                                        _id = pathComponents[1];
                                        _interaction = StoreInteractionCodes.InstanceReadHistory;
                                    
                                        return true;
                                    }

                                    if (pathComponents[2].Equals("*", StringComparison.Ordinal))
                                    {
                                        _id = pathComponents[1];
                                        _compartmentType = pathComponents[2];
                                        _interaction = StoreInteractionCodes.CompartmentSearch;

                                        return true;
                                    }

                                    if (_store.Keys.Contains(pathComponents[2]))
                                    {
                                        _id = pathComponents[1];
                                        _compartmentType = pathComponents[2];
                                        _interaction = StoreInteractionCodes.CompartmentTypeSearch;

                                        return true;
                                    }
                                }
                            }
                            break;

                        case 4:
                            {
                                if (hasValidResourceType &&
                                    pathComponents[2].Equals("_history", StringComparison.Ordinal) &&
                                    (!pathComponents[3].StartsWith('$')))
                                {
                                    _id = pathComponents[1];
                                    _version = pathComponents[3];
                                    _interaction = StoreInteractionCodes.InstanceReadVersion;

                                    return true;
                                }
                            }
                            break;
                    }
                }
                break;

            // head is allowed on a subset of GET requests - specifically cacheable reads (instance/capabilities)
            case "HEAD":
                {
                    switch (pathComponents.Length)
                    {
                        case 1:
                            {
                                if (pathComponents[0].Equals("metadata", StringComparison.Ordinal))
                                {
                                    _interaction = StoreInteractionCodes.SystemCapabilities;

                                    return true;
                                }
                            }
                            break;

                        case 2:
                            {
                                if (hasValidResourceType &&
                                    (!pathComponents[1].StartsWith('$')))
                                {
                                    _id = pathComponents[1];
                                    _interaction = StoreInteractionCodes.InstanceRead;

                                    return true;
                                }
                            }
                            break;

                        case 4:
                            {
                                if (hasValidResourceType &&
                                    pathComponents[2].Equals("_history", StringComparison.Ordinal) &&
                                    (!pathComponents[3].StartsWith('$')))
                                {
                                    _id = pathComponents[1];
                                    _version = pathComponents[3];
                                    _interaction = StoreInteractionCodes.InstanceReadVersion;

                                    return true;
                                }
                            }
                            break;
                    }
                }
                break;


            case "POST":
                {
                    switch (pathComponents.Length)
                    {
                        case 0:
                            {
                                _interaction = StoreInteractionCodes.SystemBundle;

                                return true;
                            }

                        case 1:
                            {
                                if (hasValidResourceType)
                                {
                                    _interaction = hasQueryParameters ? StoreInteractionCodes.TypeCreateConditional : StoreInteractionCodes.TypeCreate;

                                    return true;
                                }

                                if (pathComponents[0].Equals("_search", StringComparison.Ordinal))
                                {
                                    _interaction = StoreInteractionCodes.SystemSearch;

                                    return true;
                                }

                                if (pathComponents[0].StartsWith('$'))
                                {
                                    _operationName = pathComponents[0];
                                    _interaction = StoreInteractionCodes.SystemOperation;

                                    return true;
                                }
                            }
                            break;

                        case 2:
                            {
                                if (hasValidResourceType)
                                {
                                    if (pathComponents[1].Equals("_search", StringComparison.Ordinal))
                                    {
                                        _interaction = StoreInteractionCodes.TypeSearch;

                                        return true;
                                    }

                                    if (pathComponents[1].StartsWith('$'))
                                    {
                                        _operationName = pathComponents[1];
                                        _interaction = StoreInteractionCodes.TypeOperation;

                                        return true;
                                    }
                                }
                            }
                            break;

                        case 3:
                            {
                                if (hasValidResourceType)
                                {
                                    if (pathComponents[2].StartsWith('$'))
                                    {
                                        _id = pathComponents[1];
                                        _operationName = pathComponents[2];
                                        _interaction = StoreInteractionCodes.InstanceOperation;

                                        return true;
                                    }

                                    if (pathComponents[2].Equals("_search", StringComparison.Ordinal))
                                    {
                                        _id = pathComponents[1];
                                        _interaction = StoreInteractionCodes.CompartmentSearch;

                                        return true;
                                    }
                                }
                            }
                            break;

                        case 4:
                            {
                                if (hasValidResourceType &&
                                    pathComponents[3].Equals("_search", StringComparison.Ordinal) &&
                                    _store.Keys.Contains(pathComponents[3]))
                                {
                                    _id = pathComponents[1];
                                    _compartmentType = pathComponents[3];
                                    _interaction = StoreInteractionCodes.CompartmentTypeSearch;

                                    return true;
                                }
                            }
                            break;
                    }
                }
                break;

            case "DELETE":
                {
                    switch (pathComponents.Length)
                    {
                        case 0:
                            {
                                _interaction = StoreInteractionCodes.SystemDeleteConditional;

                                return true;
                            }

                        case 1:
                            {
                                if (hasValidResourceType)
                                {
                                    _interaction = StoreInteractionCodes.TypeDeleteConditional;

                                    return true;
                                }
                            }
                            break;

                        case 2:
                            {
                                if (hasValidResourceType &&
                                    (!pathComponents[1].StartsWith('$')))
                                {
                                    _id = pathComponents[1];
                                    _interaction = StoreInteractionCodes.InstanceDelete;

                                    return true;
                                }
                            }
                            break;

                        case 3:
                            {
                                if (hasValidResourceType &&
                                    pathComponents[2].Equals("_history", StringComparison.Ordinal))
                                {
                                    _id = pathComponents[1];
                                    _interaction = StoreInteractionCodes.InstanceDeleteHistory;

                                    return true;
                                }
                            }
                            break;

                        case 4:
                            {
                                if (hasValidResourceType &&
                                    pathComponents[2].Equals("_history", StringComparison.Ordinal) &&
                                    (!pathComponents[3].StartsWith('$')))
                                {
                                    _id = pathComponents[1];
                                    _version = pathComponents[3];
                                    _interaction = StoreInteractionCodes.InstanceDeleteVersion;

                                    return true;
                                }
                            }
                            break;
                    }
                }
                break;

            case "PUT":
                {
                    switch (pathComponents.Length)
                    {
                        case 2:
                            {
                                if (hasValidResourceType &&
                                    (!pathComponents[1].StartsWith('$')))
                                {
                                    _id = pathComponents[1];
                                    _interaction = hasQueryParameters ? StoreInteractionCodes.InstanceUpdateConditional : StoreInteractionCodes.InstanceUpdate;

                                    return true;
                                }
                            }
                            break;
                    }
                }
                break;

            case "PATCH":
                {
                    switch (pathComponents.Length)
                    {
                        case 2:
                            {
                                if (hasValidResourceType &&
                                    (!pathComponents[1].StartsWith('$')))
                                {
                                    _id = pathComponents[1];
                                    _interaction = hasQueryParameters ? StoreInteractionCodes.InstancePatchConditional : StoreInteractionCodes.InstancePatch;

                                    return true;
                                }
                            }
                            break;
                    }
                }
                break;
        }

        _errorMessage = $"TryParseRequest: {_httpMethod} {_url} cannot be parsed into a valid interaction!";
        Console.WriteLine(_errorMessage);

        return false;
    }
}
