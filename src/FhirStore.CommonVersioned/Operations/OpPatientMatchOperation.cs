// <copyright file="OpSubscriptionEvents.cs" company="Microsoft Corporation">
//     Copyright (c) Microsoft Corporation. All rights reserved.
//     Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// </copyright>

using System.Net;
using FhirCandle.Extensions;
using FhirCandle.Operations;
using FhirCandle.Utils;
using FhirCandle.Models;
using FhirCandle.Storage;
using FhirCandle.Client;
using Hl7.Fhir.Model;

namespace FhirCandle.Operations;

/// <summary>The FHIR Patient match operation.</summary>
public class OpPatientMatchOperation : IFhirOperation
{
    /// <summary>Gets the name of the operation.</summary>
    public string OperationName => "$match";

    /// <summary>Gets the operation version.</summary>
    public string OperationVersion => "0.0.1";

    /// <summary>Gets the canonical by FHIR version.</summary>
    public Dictionary<FhirCandle.Utils.FhirReleases.FhirSequenceCodes, string> CanonicalByFhirVersion => new()
    {
        { FhirCandle.Utils.FhirReleases.FhirSequenceCodes.R4, "http://hl7.org/fhir/OperationDefinition/Patient-match" },
        { FhirCandle.Utils.FhirReleases.FhirSequenceCodes.R4B, "http://hl7.org/fhir/OperationDefinition/Patient-match" },
        { FhirCandle.Utils.FhirReleases.FhirSequenceCodes.R5, "http://hl7.org/fhir/OperationDefinition/Patient-match" },
    };

	/// <summary>Gets a value indicating whether this operation is a named query.</summary>
    public bool IsNamedQuery => false;

    /// <summary>Gets a value indicating whether we allow get.</summary>
    public bool AllowGet => true;

    /// <summary>Gets a value indicating whether we allow post.</summary>
    public bool AllowPost => true;

    /// <summary>Gets a value indicating whether we allow system level.</summary>
    public bool AllowSystemLevel => false;

    /// <summary>Gets a value indicating whether we allow resource level.</summary>
    public bool AllowResourceLevel => true;

    /// <summary>Gets a value indicating whether we allow instance level.</summary>
    public bool AllowInstanceLevel => false;

    /// <summary>Gets a value indicating whether the accepts non FHIR.</summary>
    public bool AcceptsNonFhir => false;

    public bool ReturnsNonFhir { get; }

    /// <summary>
    /// If this operation requires a specific FHIR package to be loaded, the package identifier.
    /// </summary>
    public string RequiresPackage => string.Empty;

    /// <summary>Gets the supported resources.</summary>
    public HashSet<string> SupportedResources => new()
    {
        "Patient"
    };

	/// <summary>Executes the Subscription/$events operation.</summary>
    /// <param name="ctx">          The authentication.</param>
    /// <param name="store">        The store.</param>
    /// <param name="resourceStore">The resource store.</param>
    /// <param name="focusResource">The focus resource.</param>
    /// <param name="bodyResource"> The body resource.</param>
    /// <param name="opResponse">   [out] The response resource.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool DoOperation(
        FhirRequestContext ctx,
        Storage.VersionedFhirStore store,
        Storage.IVersionedResourceStore? resourceStore,
        Hl7.Fhir.Model.Resource? focusResource,
        Hl7.Fhir.Model.Resource? bodyResource,
        out FhirResponseContext opResponse)
    {
        // split the url query
        System.Collections.Specialized.NameValueCollection queryParams = System.Web.HttpUtility.ParseQueryString(ctx.UrlQuery);
        // string[] paramValues = queryParams.GetValues("param") ?? [];

        if ( bodyResource is not { TypeName: "Parameters" } )
        {
           opResponse = new FhirResponseContext
           {
                StatusCode = HttpStatusCode.BadRequest,
                Outcome = FhirCandle.Serialization.SerializationUtils.BuildOutcomeForRequest(
                    HttpStatusCode.BadRequest,
                    $"Operation requires a body of type Parameters."),
            };
            return false;
        }
        Parameters input = bodyResource as Parameters??new Parameters();

        var resourceParam = input.Parameter
            .FirstOrDefault(p => p.Name == "resource");
        var onlyCertainMatchesParam = input.Parameter
            .FirstOrDefault(p => p.Name == "onlyCertainMatches");
        var countParam = input.Parameter
            .FirstOrDefault(p => p.Name == "count");

        if (resourceParam == null || resourceParam.Resource == null || resourceParam.Resource.TypeName != "Patient")
        {
            opResponse = new()
            {
                StatusCode = HttpStatusCode.BadRequest,
                Outcome = FhirCandle.Serialization.SerializationUtils.BuildOutcomeForRequest(
                    HttpStatusCode.BadRequest,
                    $"Operation requires a param with name 'resource' of type 'Patient'."),
            };
            return false;
        }

        Patient refPatient = resourceParam.Resource as Patient ?? new Patient();
        Integer? count = countParam?.Value as Integer;
        bool onlyCertainMatches = (onlyCertainMatchesParam?.Value as FhirBoolean).Value??false;

        Bundle result = new();
        string error = "";

        if( !findMatchingPatients( store, refPatient, count, onlyCertainMatches, out result, out error))
        {
            opResponse = new()
            {
                StatusCode = HttpStatusCode.InternalServerError,
                Outcome = FhirCandle.Serialization.SerializationUtils.BuildOutcomeForRequest(
                    HttpStatusCode.InternalServerError,
                    $"Operation failed with message {error}."),
            };
            return false;
        }

        opResponse = new()
        {
            StatusCode = System.Net.HttpStatusCode.OK,
            Resource = result,
            Outcome = new OperationOutcome()
            {
                Id = Guid.NewGuid().ToString(),
                Issue =
                [
                    new OperationOutcome.IssueComponent()
                    {
                        Severity = OperationOutcome.IssueSeverity.Success,
                        Code = OperationOutcome.IssueType.Success,
                        Diagnostics = "Feature request query has been processed.",
                    }
                ],
            }
        };

        return true;
    }

    private bool findMatchingPatients(VersionedFhirStore store, Patient refPatient, Integer? count,
        bool onlyCertainMatches, out Bundle result, out string error)
    {
        error = "-";
        result = new Bundle() { Type = Bundle.BundleType.Searchset, Entry = [] };

        // onlyCertainMatches requires identifiers
        if (!refPatient.Identifier.Any() && onlyCertainMatches)
        {
            return true;
        }

        string query = "?identifier=" + refPatient.Identifier
            .Where(identifier => identifier.Use != Identifier.IdentifierUse.Old)
            .Select(identifier => identifier.System + "|" + identifier.Value)
            .Aggregate((i1, i2) => $"{i1},{i2}");

        FhirResponseContext opResponse = SearchForPatients(store, query);

        if (opResponse.StatusCode != HttpStatusCode.OK)
        {
            error = $"Failed to search for patients. Status code: {opResponse.StatusCode}";
            return false;
        }

        List<Patient> patients = (opResponse.Resource as Bundle ?? new Bundle()).Entry
            .Select(e => e.Resource)
            .Where(res => res != null)
            .Where(res => res.TypeName == "Patient")
            .Select(res => res as Patient)
            .ToList()!;

        if (onlyCertainMatches)
        {
            if (patients.Count == 1)
            {
                result.Entry = patients
                    .Select(patient => new Bundle.EntryComponent()
                        {
                            Resource = patient,
                            Search = new Bundle.SearchComponent()
                            {
                                Extension =
                                [
                                    new Extension()
                                    {
                                        Url = "http://hl7.org/fhir/StructureDefinition/match-grade",
                                        Value = new Code("certain")
                                    }
                                ],
                                Mode = Bundle.SearchEntryMode.Match,
                                Score = 1.0m
                            }
                        }
                    ).ToList();
            }

            return true;
        }


        result.Entry = patients
            .Select(patient => new Bundle.EntryComponent()
                {
                    Resource = patient,
                    Search =
                    {
                        Extension = new List<Extension>(){
                            new Extension()
                            {
                                Url = "http://hl7.org/fhir/StructureDefinition/match-grade",
                                Value = new Code("probable")
                            }
                        },
                        Mode = Bundle.SearchEntryMode.Match,
                        Score = 0.9m
                    }
                }
            ).ToList();


        // TODO other fields like name, gender and birthdate can be used to filter the results
        return true;
    }

    private FhirResponseContext SearchForPatients(VersionedFhirStore store, string query )
    {
        FhirRequestContext ctx = new FhirRequestContext
        {
            TenantName = store.Config.ControllerName,
            Store = store,
            HttpMethod = "GET",
            SourceObject = null,
            Url = $"Patient/{query}",
            Authorization = null,
        };
        store.TypeSearch(ctx, out FhirResponseContext opResponse);

        return opResponse;
    }

    public OperationDefinition? GetDefinition(FhirReleases.FhirSequenceCodes fhirVersion)
    {
        return new()
        {
            Id = OperationName.Substring(1) + "-" + OperationVersion.Replace('.', '-'),
            Name = OperationName,
            Url = CanonicalByFhirVersion[fhirVersion],
            Status = Hl7.Fhir.Model.PublicationStatus.Draft,
            Kind = IsNamedQuery ? Hl7.Fhir.Model.OperationDefinition.OperationKind.Query : Hl7.Fhir.Model.OperationDefinition.OperationKind.Operation,
            Code = OperationName.Substring(1),
            Resource = SupportedResources.CopyTargetsNullable(),
            System = AllowSystemLevel,
            Type = AllowResourceLevel,
            Instance = AllowInstanceLevel,
            Description = "A Master Patient Index ([MPI](http://en.wikipedia.org/wiki/Enterprise_master_patient_index) ) is a service used to manage patient identification in a context where multiple patient databases exist. Healthcare applications and middleware use the MPI to match patients between the databases, and to store new patient details as they are encountered. MPIs are highly specialized applications, often tailored extensively to the institution's particular mix of patients. MPIs can also be run on a regional and national basis.  \n\nTo ask an MPI to match a patient, clients use the \"$match\" operation, which accepts a patient resource which may be only partially complete. The data provided is interpreted as an MPI input and processed by an algorithm of some kind that uses the data to determine the most appropriate matches in the patient set.  Note that different MPI matching algorithms have different required inputs. The generic $match operation does not specify any particular algorithm, nor a minimum set of information that must be provided when asking for an MPI match operation to be performed, but many implementations will have a set of minimum information, which may be declared in their definition of the $match operation by specifying a profile on the resource parameter, indicating which properties are required in the search.  The patient resource submitted to the operation does not have to be complete, nor does it need to pass validation (i.e. mandatory fields don't need to be populated), but it does have to be a valid instance, as it is used as the reference data to match against.",
            Parameter =
            [
                new()
                {
                    Name = "resource",
                    Use = Hl7.Fhir.Model.OperationParameterUse.In,
                    Min = 1,
                    Max = "1",
                    Type = Hl7.Fhir.Model.FHIRAllTypes.Resource,
                    Documentation = "Use this to provide an entire set of patient details for the MPI to match against (e.g. POST a patient record to Patient/$match).",
                },

                new()
                {
                    Name = "onlyCertainMatches",
                    Use = Hl7.Fhir.Model.OperationParameterUse.In,
                    Min = 0,
                    Max = "1",
                    Type = Hl7.Fhir.Model.FHIRAllTypes.Boolean,
                    Documentation = "If there are multiple potential matches, then the match should not return the results with this flag set to true.  When false, the server may return multiple results with each result graded accordingly.",
                },

                new()
                {
                    Name = "count",
                    Use = Hl7.Fhir.Model.OperationParameterUse.In,
                    Min = 0,
                    Max = "1",
                    Type = Hl7.Fhir.Model.FHIRAllTypes.Integer,
                    Documentation = "The maximum number of records to return. If no value is provided, the server decides how many matches to return. Note that clients should be careful when using this, as it may prevent probable - and valid - matches from being returned",
                },

                new()
                {
                    Name = "return",
                    Use = Hl7.Fhir.Model.OperationParameterUse.Out,
                    Min = 1,
                    Max = "1",
                    Type = Hl7.Fhir.Model.FHIRAllTypes.Bundle,
                    Documentation = "A bundle contain a set of Patient records that represent possible matches, optionally it may also contain an OperationOutcome with further information about the search results (such as warnings or information messages, such as a count of records that were close but eliminated)  If the operation was unsuccessful, then an OperationOutcome may be returned along with a BadRequest status Code (e.g. security issue, or insufficient properties in patient fragment - check against profile)",
                }
            ],
        };
    }
}

internal class SwCandleClient
{
    private readonly VersionedFhirStore _store;

    public SwCandleClient(VersionedFhirStore store)
    {
        _store = store;
    }
}
