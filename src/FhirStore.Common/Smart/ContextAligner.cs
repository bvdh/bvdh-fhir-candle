using System.Net;
using FhirCandle.Models;
using FhirCandle.Storage;
using Hl7.Fhir.Model;
using Hl7.Fhir.Rest;
using Hl7.Fhir.Serialization;

namespace FhirCandle.Smart
{
    public class ContextAligner(string fhirServerUrl, IFhirStore store)
    {
        private readonly string _fhirServerUrl = fhirServerUrl;
        private readonly FhirClient _fhirClient = new(fhirServerUrl, new FhirClientSettings()
        {
            ParserSettings = new ParserSettings()
            {
                PermissiveParsing = true
            }
        });

        public async Task<string?> GetMatchingPatientId(string foreignPatientId )
        {
            string theForeignPatientId = foreignPatientId.StartsWith("Patient/")
                ? foreignPatientId
                : $"Patient/{foreignPatientId}";
            Patient? foreignPatient = await _fhirClient.ReadAsync<Patient>( theForeignPatientId );
            if (foreignPatient == null)
            {
                return null;
            }

            if (!foreignPatient.Identifier.Any() )
            {
                return null;
            }

            string query = "?identifier=" + foreignPatient.Identifier
                .Where(identifier => identifier.Use != Identifier.IdentifierUse.Old)
                .Select(identifier => identifier.System + "|" + identifier.Value)
                .Aggregate((i1, i2) => $"{i1},{i2}");

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

            if (opResponse.StatusCode != HttpStatusCode.OK)
            {
                // error = $"Failed to search for patients. Status code: {opResponse.StatusCode}";
                return null;
            }

            List<Patient> patients = (opResponse.Resource as Bundle ?? new Bundle()).Entry
                .Select(e => e.Resource)
                .Where(res => res != null)
                .Where(res => res.TypeName == "Patient")
                .Select(res => res as Patient)
                .ToList()!;

            if (patients.Count == 1)
            {
                return patients[0].Id;
            }

            return null;

        }

        public List<string> GetMatchingImagingStudies(string foreignPatient, string? patientId)
        {
            string foreignPatientReference = foreignPatient.StartsWith("Patient/")?foreignPatient:"Patient/" + foreignPatient;
            List<ImagingStudy> imagingStudies = new List<ImagingStudy>();
            List<ImagingStudy> foreignImagingStudies = new List<ImagingStudy>();
            var foreignImagingStudiesBundle = _fhirClient.SearchAsync<ImagingStudy>(new string[] { $"subject={foreignPatientReference}" })
                .GetAwaiter()
                .GetResult();
            while (foreignImagingStudiesBundle != null)
            {
                List<ImagingStudy> bundleList = foreignImagingStudiesBundle.Entry
                    .Select(e => e.Resource)
                    .Where(res => res != null)
                    .Where(res => res!.TypeName == "ImagingStudy")
                    .Select(res => res as ImagingStudy)
                    .ToList()!;
                foreignImagingStudies.AddRange(bundleList);
                foreignImagingStudiesBundle = _fhirClient.ContinueAsync(foreignImagingStudiesBundle)
                    .GetAwaiter()
                    .GetResult();
            }

            foreach (var foreignImagingStudie in foreignImagingStudies)
            {
                string query = "?identifier=" + foreignImagingStudie.Identifier
                    .Where(identifier => identifier.Use != Identifier.IdentifierUse.Old)
                    .Select(identifier => identifier.System + "|" + identifier.Value)
                    .Aggregate((i1, i2) => $"{i1},{i2}");

                FhirRequestContext ctx = new FhirRequestContext
                {
                    TenantName = store.Config.ControllerName,
                    Store = store,
                    HttpMethod = "GET",
                    SourceObject = null,
                    Url = $"ImagingStudy/{query}",
                    Authorization = null,
                };
                store.TypeSearch(ctx, out FhirResponseContext opResponse);
                if (opResponse.StatusCode == HttpStatusCode.OK)
                {
                    List<ImagingStudy> imagingStudyList =(opResponse.Resource as Bundle ?? new Bundle()).Entry
                            .Select(e => e.Resource)
                            .Where(res => res != null)
                            .Where(res => res.TypeName == "ImagingStudy")
                            .Select(res => res as ImagingStudy)
                            .ToList()!;
                    imagingStudies.AddRange( imagingStudyList );
                }
            }

            List<string> result = imagingStudies
                .Select(imagingStudy => imagingStudy.Identifier.FirstOrDefault()?.Value)
                .Select(identiferString => identiferString ?? "unknown")
                .ToList();

            return result;
        }
    }
}
