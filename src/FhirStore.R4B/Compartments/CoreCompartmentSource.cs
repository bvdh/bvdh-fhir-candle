﻿// <copyright file="CoreCompartmentSource.cs" company="Microsoft Corporation">
//     Copyright (c) Microsoft Corporation. All rights reserved.
//     Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// </copyright>

using FhirCandle.Serialization;
using Hl7.Fhir.Model;

namespace FhirCandle.Compartments;

public class CoreCompartmentSource
{
    public static Hl7.Fhir.Model.CompartmentDefinition[] GetCompartments() => new CoreCompartmentSource().getCompartments();

    private Hl7.Fhir.Model.CompartmentDefinition[] getCompartments() =>
        _compartmentDefinitions
            .Select(json => SerializationUtils.DeserializeFhir<CompartmentDefinition>(json, "application/fhir+json"))
            .ToArray();

    private string[] _compartmentDefinitions = [
        _compartmentDefinitionDevice,
        _compartmentDefinitionEncounter,
        _compartmentDefinitionPatient,
        _compartmentDefinitionPractitioner,
        _compartmentDefinitionRelatedPerson,
        ];

    private const string _compartmentDefinitionDevice = """
        {
            "resourceType": "CompartmentDefinition",
            "id": "device",
            "meta": {
                "lastUpdated": "2022-05-28T12:47:40.239+10:00"
            },
            "url": "http://hl7.org/fhir/CompartmentDefinition/device",
            "version": "4.3.0",
            "name": "Base FHIR compartment definition for Device",
            "status": "draft",
            "experimental": true,
            "date": "2022-05-28T12:47:40+10:00",
            "publisher": "FHIR Project Team",
            "contact": [
                {
                    "telecom": [
                        {
                            "system": "url",
                            "value": "http://hl7.org/fhir"
                        }
                    ]
                }
            ],
            "description": "There is an instance of the device compartment for each Device resource, and the identity of the compartment is the same as the Device. The set of resources associated with a particular device",
            "code": "Device",
            "search": true,
            "resource": [
                {
                    "code": "Account",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "ActivityDefinition"
                },
                {
                    "code": "AdministrableProductDefinition"
                },
                {
                    "code": "AdverseEvent"
                },
                {
                    "code": "AllergyIntolerance"
                },
                {
                    "code": "Appointment",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "AppointmentResponse",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "AuditEvent",
                    "param": [
                        "agent"
                    ]
                },
                {
                    "code": "Basic"
                },
                {
                    "code": "Binary"
                },
                {
                    "code": "BiologicallyDerivedProduct"
                },
                {
                    "code": "BodyStructure"
                },
                {
                    "code": "Bundle"
                },
                {
                    "code": "CapabilityStatement"
                },
                {
                    "code": "CarePlan"
                },
                {
                    "code": "CareTeam"
                },
                {
                    "code": "CatalogEntry"
                },
                {
                    "code": "ChargeItem",
                    "param": [
                        "enterer",
                        "performer-actor"
                    ]
                },
                {
                    "code": "ChargeItemDefinition"
                },
                {
                    "code": "Citation"
                },
                {
                    "code": "Claim",
                    "param": [
                        "procedure-udi",
                        "item-udi",
                        "detail-udi",
                        "subdetail-udi"
                    ]
                },
                {
                    "code": "ClaimResponse"
                },
                {
                    "code": "ClinicalImpression"
                },
                {
                    "code": "ClinicalUseDefinition"
                },
                {
                    "code": "CodeSystem"
                },
                {
                    "code": "Communication",
                    "param": [
                        "sender",
                        "recipient"
                    ]
                },
                {
                    "code": "CommunicationRequest",
                    "param": [
                        "sender",
                        "recipient"
                    ]
                },
                {
                    "code": "CompartmentDefinition"
                },
                {
                    "code": "Composition",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "ConceptMap"
                },
                {
                    "code": "Condition"
                },
                {
                    "code": "Consent"
                },
                {
                    "code": "Contract"
                },
                {
                    "code": "Coverage"
                },
                {
                    "code": "CoverageEligibilityRequest"
                },
                {
                    "code": "CoverageEligibilityResponse"
                },
                {
                    "code": "DetectedIssue",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "Device"
                },
                {
                    "code": "DeviceDefinition"
                },
                {
                    "code": "DeviceMetric"
                },
                {
                    "code": "DeviceRequest",
                    "param": [
                        "device",
                        "subject",
                        "requester",
                        "performer"
                    ]
                },
                {
                    "code": "DeviceUseStatement",
                    "param": [
                        "device"
                    ]
                },
                {
                    "code": "DiagnosticReport",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "DocumentManifest",
                    "param": [
                        "subject",
                        "author"
                    ]
                },
                {
                    "code": "DocumentReference",
                    "param": [
                        "subject",
                        "author"
                    ]
                },
                {
                    "code": "Encounter"
                },
                {
                    "code": "Endpoint"
                },
                {
                    "code": "EnrollmentRequest"
                },
                {
                    "code": "EnrollmentResponse"
                },
                {
                    "code": "EpisodeOfCare"
                },
                {
                    "code": "EventDefinition"
                },
                {
                    "code": "Evidence"
                },
                {
                    "code": "EvidenceReport"
                },
                {
                    "code": "EvidenceVariable"
                },
                {
                    "code": "ExampleScenario"
                },
                {
                    "code": "ExplanationOfBenefit",
                    "param": [
                        "procedure-udi",
                        "item-udi",
                        "detail-udi",
                        "subdetail-udi"
                    ]
                },
                {
                    "code": "FamilyMemberHistory"
                },
                {
                    "code": "Flag",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "Goal"
                },
                {
                    "code": "GraphDefinition"
                },
                {
                    "code": "Group",
                    "param": [
                        "member"
                    ]
                },
                {
                    "code": "GuidanceResponse"
                },
                {
                    "code": "HealthcareService"
                },
                {
                    "code": "ImagingStudy"
                },
                {
                    "code": "Immunization"
                },
                {
                    "code": "ImmunizationEvaluation"
                },
                {
                    "code": "ImmunizationRecommendation"
                },
                {
                    "code": "ImplementationGuide"
                },
                {
                    "code": "Ingredient"
                },
                {
                    "code": "InsurancePlan"
                },
                {
                    "code": "Invoice",
                    "param": [
                        "participant"
                    ]
                },
                {
                    "code": "Library"
                },
                {
                    "code": "Linkage"
                },
                {
                    "code": "List",
                    "param": [
                        "subject",
                        "source"
                    ]
                },
                {
                    "code": "Location"
                },
                {
                    "code": "ManufacturedItemDefinition"
                },
                {
                    "code": "Measure"
                },
                {
                    "code": "MeasureReport"
                },
                {
                    "code": "Media",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "Medication"
                },
                {
                    "code": "MedicationAdministration",
                    "param": [
                        "device"
                    ]
                },
                {
                    "code": "MedicationDispense"
                },
                {
                    "code": "MedicationKnowledge"
                },
                {
                    "code": "MedicationRequest"
                },
                {
                    "code": "MedicationStatement"
                },
                {
                    "code": "MedicinalProductDefinition"
                },
                {
                    "code": "MessageDefinition"
                },
                {
                    "code": "MessageHeader",
                    "param": [
                        "target"
                    ]
                },
                {
                    "code": "MolecularSequence"
                },
                {
                    "code": "NamingSystem"
                },
                {
                    "code": "NutritionOrder"
                },
                {
                    "code": "NutritionProduct"
                },
                {
                    "code": "Observation",
                    "param": [
                        "subject",
                        "device"
                    ]
                },
                {
                    "code": "ObservationDefinition"
                },
                {
                    "code": "OperationDefinition"
                },
                {
                    "code": "OperationOutcome"
                },
                {
                    "code": "Organization"
                },
                {
                    "code": "OrganizationAffiliation"
                },
                {
                    "code": "PackagedProductDefinition"
                },
                {
                    "code": "Patient"
                },
                {
                    "code": "PaymentNotice"
                },
                {
                    "code": "PaymentReconciliation"
                },
                {
                    "code": "Person"
                },
                {
                    "code": "PlanDefinition"
                },
                {
                    "code": "Practitioner"
                },
                {
                    "code": "PractitionerRole"
                },
                {
                    "code": "Procedure"
                },
                {
                    "code": "Provenance",
                    "param": [
                        "agent"
                    ]
                },
                {
                    "code": "Questionnaire"
                },
                {
                    "code": "QuestionnaireResponse",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "RegulatedAuthorization"
                },
                {
                    "code": "RelatedPerson"
                },
                {
                    "code": "RequestGroup",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "ResearchDefinition"
                },
                {
                    "code": "ResearchElementDefinition"
                },
                {
                    "code": "ResearchStudy"
                },
                {
                    "code": "ResearchSubject"
                },
                {
                    "code": "RiskAssessment",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "Schedule",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "SearchParameter"
                },
                {
                    "code": "ServiceRequest",
                    "param": [
                        "performer",
                        "requester"
                    ]
                },
                {
                    "code": "Slot"
                },
                {
                    "code": "Specimen",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "SpecimenDefinition"
                },
                {
                    "code": "StructureDefinition"
                },
                {
                    "code": "StructureMap"
                },
                {
                    "code": "Subscription"
                },
                {
                    "code": "SubscriptionStatus"
                },
                {
                    "code": "SubscriptionTopic"
                },
                {
                    "code": "Substance"
                },
                {
                    "code": "SubstanceDefinition"
                },
                {
                    "code": "SupplyDelivery"
                },
                {
                    "code": "SupplyRequest",
                    "param": [
                        "requester"
                    ]
                },
                {
                    "code": "Task"
                },
                {
                    "code": "TerminologyCapabilities"
                },
                {
                    "code": "TestReport"
                },
                {
                    "code": "TestScript"
                },
                {
                    "code": "ValueSet"
                },
                {
                    "code": "VerificationResult"
                },
                {
                    "code": "VisionPrescription"
                }
            ]
        }
        """;

    private const string _compartmentDefinitionEncounter = """
        {
            "resourceType": "CompartmentDefinition",
            "id": "encounter",
            "meta": {
                "lastUpdated": "2022-05-28T12:47:40.239+10:00"
            },
            "url": "http://hl7.org/fhir/CompartmentDefinition/encounter",
            "version": "4.3.0",
            "name": "Base FHIR compartment definition for Encounter",
            "status": "draft",
            "experimental": true,
            "date": "2022-05-28T12:47:40+10:00",
            "publisher": "FHIR Project Team",
            "contact": [
                {
                    "telecom": [
                        {
                            "system": "url",
                            "value": "http://hl7.org/fhir"
                        }
                    ]
                }
            ],
            "description": "There is an instance of the encounter compartment for each encounter resource, and the identity of the compartment is the same as the encounter. The set of resources associated with a particular encounter",
            "code": "Encounter",
            "search": true,
            "resource": [
                {
                    "code": "Account"
                },
                {
                    "code": "ActivityDefinition"
                },
                {
                    "code": "AdministrableProductDefinition"
                },
                {
                    "code": "AdverseEvent"
                },
                {
                    "code": "AllergyIntolerance"
                },
                {
                    "code": "Appointment"
                },
                {
                    "code": "AppointmentResponse"
                },
                {
                    "code": "AuditEvent"
                },
                {
                    "code": "Basic"
                },
                {
                    "code": "Binary"
                },
                {
                    "code": "BiologicallyDerivedProduct"
                },
                {
                    "code": "BodyStructure"
                },
                {
                    "code": "Bundle"
                },
                {
                    "code": "CapabilityStatement"
                },
                {
                    "code": "CarePlan",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "CareTeam",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "CatalogEntry"
                },
                {
                    "code": "ChargeItem",
                    "param": [
                        "context"
                    ]
                },
                {
                    "code": "ChargeItemDefinition"
                },
                {
                    "code": "Citation"
                },
                {
                    "code": "Claim",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "ClaimResponse"
                },
                {
                    "code": "ClinicalImpression",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "ClinicalUseDefinition"
                },
                {
                    "code": "CodeSystem"
                },
                {
                    "code": "Communication",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "CommunicationRequest",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "CompartmentDefinition"
                },
                {
                    "code": "Composition",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "ConceptMap"
                },
                {
                    "code": "Condition",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "Consent"
                },
                {
                    "code": "Contract"
                },
                {
                    "code": "Coverage"
                },
                {
                    "code": "CoverageEligibilityRequest"
                },
                {
                    "code": "CoverageEligibilityResponse"
                },
                {
                    "code": "DetectedIssue"
                },
                {
                    "code": "Device"
                },
                {
                    "code": "DeviceDefinition"
                },
                {
                    "code": "DeviceMetric"
                },
                {
                    "code": "DeviceRequest",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "DeviceUseStatement"
                },
                {
                    "code": "DiagnosticReport",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "DocumentManifest",
                    "param": [
                        "related-ref"
                    ]
                },
                {
                    "code": "DocumentReference",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "Encounter",
                    "param": [
                        "{def}"
                    ]
                },
                {
                    "code": "Endpoint"
                },
                {
                    "code": "EnrollmentRequest"
                },
                {
                    "code": "EnrollmentResponse"
                },
                {
                    "code": "EpisodeOfCare"
                },
                {
                    "code": "EventDefinition"
                },
                {
                    "code": "Evidence"
                },
                {
                    "code": "EvidenceReport"
                },
                {
                    "code": "EvidenceVariable"
                },
                {
                    "code": "ExampleScenario"
                },
                {
                    "code": "ExplanationOfBenefit",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "FamilyMemberHistory"
                },
                {
                    "code": "Flag"
                },
                {
                    "code": "Goal"
                },
                {
                    "code": "GraphDefinition"
                },
                {
                    "code": "Group"
                },
                {
                    "code": "GuidanceResponse"
                },
                {
                    "code": "HealthcareService"
                },
                {
                    "code": "ImagingStudy"
                },
                {
                    "code": "Immunization"
                },
                {
                    "code": "ImmunizationEvaluation"
                },
                {
                    "code": "ImmunizationRecommendation"
                },
                {
                    "code": "ImplementationGuide"
                },
                {
                    "code": "Ingredient"
                },
                {
                    "code": "InsurancePlan"
                },
                {
                    "code": "Invoice"
                },
                {
                    "code": "Library"
                },
                {
                    "code": "Linkage"
                },
                {
                    "code": "List"
                },
                {
                    "code": "Location"
                },
                {
                    "code": "ManufacturedItemDefinition"
                },
                {
                    "code": "Measure"
                },
                {
                    "code": "MeasureReport"
                },
                {
                    "code": "Media",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "Medication"
                },
                {
                    "code": "MedicationAdministration",
                    "param": [
                        "context"
                    ]
                },
                {
                    "code": "MedicationDispense"
                },
                {
                    "code": "MedicationKnowledge"
                },
                {
                    "code": "MedicationRequest",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "MedicationStatement"
                },
                {
                    "code": "MedicinalProductDefinition"
                },
                {
                    "code": "MessageDefinition"
                },
                {
                    "code": "MessageHeader"
                },
                {
                    "code": "MolecularSequence"
                },
                {
                    "code": "NamingSystem"
                },
                {
                    "code": "NutritionOrder",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "NutritionProduct"
                },
                {
                    "code": "Observation",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "ObservationDefinition"
                },
                {
                    "code": "OperationDefinition"
                },
                {
                    "code": "OperationOutcome"
                },
                {
                    "code": "Organization"
                },
                {
                    "code": "OrganizationAffiliation"
                },
                {
                    "code": "PackagedProductDefinition"
                },
                {
                    "code": "Patient"
                },
                {
                    "code": "PaymentNotice"
                },
                {
                    "code": "PaymentReconciliation"
                },
                {
                    "code": "Person"
                },
                {
                    "code": "PlanDefinition"
                },
                {
                    "code": "Practitioner"
                },
                {
                    "code": "PractitionerRole"
                },
                {
                    "code": "Procedure",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "Provenance"
                },
                {
                    "code": "Questionnaire"
                },
                {
                    "code": "QuestionnaireResponse",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "RegulatedAuthorization"
                },
                {
                    "code": "RelatedPerson"
                },
                {
                    "code": "RequestGroup",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "ResearchDefinition"
                },
                {
                    "code": "ResearchElementDefinition"
                },
                {
                    "code": "ResearchStudy"
                },
                {
                    "code": "ResearchSubject"
                },
                {
                    "code": "RiskAssessment"
                },
                {
                    "code": "Schedule"
                },
                {
                    "code": "SearchParameter"
                },
                {
                    "code": "ServiceRequest",
                    "param": [
                        "encounter"
                    ]
                },
                {
                    "code": "Slot"
                },
                {
                    "code": "Specimen"
                },
                {
                    "code": "SpecimenDefinition"
                },
                {
                    "code": "StructureDefinition"
                },
                {
                    "code": "StructureMap"
                },
                {
                    "code": "Subscription"
                },
                {
                    "code": "SubscriptionStatus"
                },
                {
                    "code": "SubscriptionTopic"
                },
                {
                    "code": "Substance"
                },
                {
                    "code": "SubstanceDefinition"
                },
                {
                    "code": "SupplyDelivery"
                },
                {
                    "code": "SupplyRequest"
                },
                {
                    "code": "Task"
                },
                {
                    "code": "TerminologyCapabilities"
                },
                {
                    "code": "TestReport"
                },
                {
                    "code": "TestScript"
                },
                {
                    "code": "ValueSet"
                },
                {
                    "code": "VerificationResult"
                },
                {
                    "code": "VisionPrescription",
                    "param": [
                        "encounter"
                    ]
                }
            ]
        }
        """;

    private const string _compartmentDefinitionPatient = """
        {
            "resourceType": "CompartmentDefinition",
            "id": "patient",
            "meta": {
                "lastUpdated": "2022-05-28T12:47:40.239+10:00"
            },
            "url": "http://hl7.org/fhir/CompartmentDefinition/patient",
            "version": "4.3.0",
            "name": "Base FHIR compartment definition for Patient",
            "status": "draft",
            "experimental": true,
            "date": "2022-05-28T12:47:40+10:00",
            "publisher": "FHIR Project Team",
            "contact": [
                {
                    "telecom": [
                        {
                            "system": "url",
                            "value": "http://hl7.org/fhir"
                        }
                    ]
                }
            ],
            "description": "There is an instance of the patient compartment for each patient resource, and the identity of the compartment is the same as the patient. When a patient is linked to another patient, all the records associated with the linked patient are in the compartment associated with the target of the link.. The set of resources associated with a particular patient",
            "code": "Patient",
            "search": true,
            "resource": [
                {
                    "code": "Account",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "ActivityDefinition"
                },
                {
                    "code": "AdministrableProductDefinition"
                },
                {
                    "code": "AdverseEvent",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "AllergyIntolerance",
                    "param": [
                        "patient",
                        "recorder",
                        "asserter"
                    ]
                },
                {
                    "code": "Appointment",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "AppointmentResponse",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "AuditEvent",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Basic",
                    "param": [
                        "patient",
                        "author"
                    ]
                },
                {
                    "code": "Binary"
                },
                {
                    "code": "BiologicallyDerivedProduct"
                },
                {
                    "code": "BodyStructure",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Bundle"
                },
                {
                    "code": "CapabilityStatement"
                },
                {
                    "code": "CarePlan",
                    "param": [
                        "patient",
                        "performer"
                    ]
                },
                {
                    "code": "CareTeam",
                    "param": [
                        "patient",
                        "participant"
                    ]
                },
                {
                    "code": "CatalogEntry"
                },
                {
                    "code": "ChargeItem",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "ChargeItemDefinition"
                },
                {
                    "code": "Citation"
                },
                {
                    "code": "Claim",
                    "param": [
                        "patient",
                        "payee"
                    ]
                },
                {
                    "code": "ClaimResponse",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "ClinicalImpression",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "ClinicalUseDefinition"
                },
                {
                    "code": "CodeSystem"
                },
                {
                    "code": "Communication",
                    "param": [
                        "subject",
                        "sender",
                        "recipient"
                    ]
                },
                {
                    "code": "CommunicationRequest",
                    "param": [
                        "subject",
                        "sender",
                        "recipient",
                        "requester"
                    ]
                },
                {
                    "code": "CompartmentDefinition"
                },
                {
                    "code": "Composition",
                    "param": [
                        "subject",
                        "author",
                        "attester"
                    ]
                },
                {
                    "code": "ConceptMap"
                },
                {
                    "code": "Condition",
                    "param": [
                        "patient",
                        "asserter"
                    ]
                },
                {
                    "code": "Consent",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Contract"
                },
                {
                    "code": "Coverage",
                    "param": [
                        "policy-holder",
                        "subscriber",
                        "beneficiary",
                        "payor"
                    ]
                },
                {
                    "code": "CoverageEligibilityRequest",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "CoverageEligibilityResponse",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "DetectedIssue",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Device"
                },
                {
                    "code": "DeviceDefinition"
                },
                {
                    "code": "DeviceMetric"
                },
                {
                    "code": "DeviceRequest",
                    "param": [
                        "subject",
                        "performer"
                    ]
                },
                {
                    "code": "DeviceUseStatement",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "DiagnosticReport",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "DocumentManifest",
                    "param": [
                        "subject",
                        "author",
                        "recipient"
                    ]
                },
                {
                    "code": "DocumentReference",
                    "param": [
                        "subject",
                        "author"
                    ]
                },
                {
                    "code": "Encounter",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Endpoint"
                },
                {
                    "code": "EnrollmentRequest",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "EnrollmentResponse"
                },
                {
                    "code": "EpisodeOfCare",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "EventDefinition"
                },
                {
                    "code": "Evidence"
                },
                {
                    "code": "EvidenceReport"
                },
                {
                    "code": "EvidenceVariable"
                },
                {
                    "code": "ExampleScenario"
                },
                {
                    "code": "ExplanationOfBenefit",
                    "param": [
                        "patient",
                        "payee"
                    ]
                },
                {
                    "code": "FamilyMemberHistory",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Flag",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Goal",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "GraphDefinition"
                },
                {
                    "code": "Group",
                    "param": [
                        "member"
                    ]
                },
                {
                    "code": "GuidanceResponse"
                },
                {
                    "code": "HealthcareService"
                },
                {
                    "code": "ImagingStudy",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Immunization",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "ImmunizationEvaluation",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "ImmunizationRecommendation",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "ImplementationGuide"
                },
                {
                    "code": "Ingredient"
                },
                {
                    "code": "InsurancePlan"
                },
                {
                    "code": "Invoice",
                    "param": [
                        "subject",
                        "patient",
                        "recipient"
                    ]
                },
                {
                    "code": "Library"
                },
                {
                    "code": "Linkage"
                },
                {
                    "code": "List",
                    "param": [
                        "subject",
                        "source"
                    ]
                },
                {
                    "code": "Location"
                },
                {
                    "code": "ManufacturedItemDefinition"
                },
                {
                    "code": "Measure"
                },
                {
                    "code": "MeasureReport",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Media",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "Medication"
                },
                {
                    "code": "MedicationAdministration",
                    "param": [
                        "patient",
                        "performer",
                        "subject"
                    ]
                },
                {
                    "code": "MedicationDispense",
                    "param": [
                        "subject",
                        "patient",
                        "receiver"
                    ]
                },
                {
                    "code": "MedicationKnowledge"
                },
                {
                    "code": "MedicationRequest",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "MedicationStatement",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "MedicinalProductDefinition"
                },
                {
                    "code": "MessageDefinition"
                },
                {
                    "code": "MessageHeader"
                },
                {
                    "code": "MolecularSequence",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "NamingSystem"
                },
                {
                    "code": "NutritionOrder",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "NutritionProduct"
                },
                {
                    "code": "Observation",
                    "param": [
                        "subject",
                        "performer"
                    ]
                },
                {
                    "code": "ObservationDefinition"
                },
                {
                    "code": "OperationDefinition"
                },
                {
                    "code": "OperationOutcome"
                },
                {
                    "code": "Organization"
                },
                {
                    "code": "OrganizationAffiliation"
                },
                {
                    "code": "PackagedProductDefinition"
                },
                {
                    "code": "Patient",
                    "param": [
                        "link"
                    ]
                },
                {
                    "code": "PaymentNotice"
                },
                {
                    "code": "PaymentReconciliation"
                },
                {
                    "code": "Person",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "PlanDefinition"
                },
                {
                    "code": "Practitioner"
                },
                {
                    "code": "PractitionerRole"
                },
                {
                    "code": "Procedure",
                    "param": [
                        "patient",
                        "performer"
                    ]
                },
                {
                    "code": "Provenance",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "Questionnaire"
                },
                {
                    "code": "QuestionnaireResponse",
                    "param": [
                        "subject",
                        "author"
                    ]
                },
                {
                    "code": "RegulatedAuthorization"
                },
                {
                    "code": "RelatedPerson",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "RequestGroup",
                    "param": [
                        "subject",
                        "participant"
                    ]
                },
                {
                    "code": "ResearchDefinition"
                },
                {
                    "code": "ResearchElementDefinition"
                },
                {
                    "code": "ResearchStudy"
                },
                {
                    "code": "ResearchSubject",
                    "param": [
                        "individual"
                    ]
                },
                {
                    "code": "RiskAssessment",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "Schedule",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "SearchParameter"
                },
                {
                    "code": "ServiceRequest",
                    "param": [
                        "subject",
                        "performer"
                    ]
                },
                {
                    "code": "Slot"
                },
                {
                    "code": "Specimen",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "SpecimenDefinition"
                },
                {
                    "code": "StructureDefinition"
                },
                {
                    "code": "StructureMap"
                },
                {
                    "code": "Subscription"
                },
                {
                    "code": "SubscriptionStatus"
                },
                {
                    "code": "SubscriptionTopic"
                },
                {
                    "code": "Substance"
                },
                {
                    "code": "SubstanceDefinition"
                },
                {
                    "code": "SupplyDelivery",
                    "param": [
                        "patient"
                    ]
                },
                {
                    "code": "SupplyRequest",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "Task"
                },
                {
                    "code": "TerminologyCapabilities"
                },
                {
                    "code": "TestReport"
                },
                {
                    "code": "TestScript"
                },
                {
                    "code": "ValueSet"
                },
                {
                    "code": "VerificationResult"
                },
                {
                    "code": "VisionPrescription",
                    "param": [
                        "patient"
                    ]
                }
            ]
        }
        """;

    private const string _compartmentDefinitionPractitioner = """
        {
            "resourceType": "CompartmentDefinition",
            "id": "practitioner",
            "meta": {
                "lastUpdated": "2022-05-28T12:47:40.239+10:00"
            },
            "url": "http://hl7.org/fhir/CompartmentDefinition/practitioner",
            "version": "4.3.0",
            "name": "Base FHIR compartment definition for Practitioner",
            "status": "draft",
            "experimental": true,
            "date": "2022-05-28T12:47:40+10:00",
            "publisher": "FHIR Project Team",
            "contact": [
                {
                    "telecom": [
                        {
                            "system": "url",
                            "value": "http://hl7.org/fhir"
                        }
                    ]
                }
            ],
            "description": "There is an instance of the practitioner compartment for each Practitioner resource, and the identity of the compartment is the same as the Practitioner. The set of resources associated with a particular practitioner",
            "code": "Practitioner",
            "search": true,
            "resource": [
                {
                    "code": "Account",
                    "param": [
                        "subject"
                    ]
                },
                {
                    "code": "ActivityDefinition"
                },
                {
                    "code": "AdministrableProductDefinition"
                },
                {
                    "code": "AdverseEvent",
                    "param": [
                        "recorder"
                    ]
                },
                {
                    "code": "AllergyIntolerance",
                    "param": [
                        "recorder",
                        "asserter"
                    ]
                },
                {
                    "code": "Appointment",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "AppointmentResponse",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "AuditEvent",
                    "param": [
                        "agent"
                    ]
                },
                {
                    "code": "Basic",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "Binary"
                },
                {
                    "code": "BiologicallyDerivedProduct"
                },
                {
                    "code": "BodyStructure"
                },
                {
                    "code": "Bundle"
                },
                {
                    "code": "CapabilityStatement"
                },
                {
                    "code": "CarePlan",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "CareTeam",
                    "param": [
                        "participant"
                    ]
                },
                {
                    "code": "CatalogEntry"
                },
                {
                    "code": "ChargeItem",
                    "param": [
                        "enterer",
                        "performer-actor"
                    ]
                },
                {
                    "code": "ChargeItemDefinition"
                },
                {
                    "code": "Citation"
                },
                {
                    "code": "Claim",
                    "param": [
                        "enterer",
                        "provider",
                        "payee",
                        "care-team"
                    ]
                },
                {
                    "code": "ClaimResponse",
                    "param": [
                        "requestor"
                    ]
                },
                {
                    "code": "ClinicalImpression",
                    "param": [
                        "assessor"
                    ]
                },
                {
                    "code": "ClinicalUseDefinition"
                },
                {
                    "code": "CodeSystem"
                },
                {
                    "code": "Communication",
                    "param": [
                        "sender",
                        "recipient"
                    ]
                },
                {
                    "code": "CommunicationRequest",
                    "param": [
                        "sender",
                        "recipient",
                        "requester"
                    ]
                },
                {
                    "code": "CompartmentDefinition"
                },
                {
                    "code": "Composition",
                    "param": [
                        "subject",
                        "author",
                        "attester"
                    ]
                },
                {
                    "code": "ConceptMap"
                },
                {
                    "code": "Condition",
                    "param": [
                        "asserter"
                    ]
                },
                {
                    "code": "Consent"
                },
                {
                    "code": "Contract"
                },
                {
                    "code": "Coverage"
                },
                {
                    "code": "CoverageEligibilityRequest",
                    "param": [
                        "enterer",
                        "provider"
                    ]
                },
                {
                    "code": "CoverageEligibilityResponse",
                    "param": [
                        "requestor"
                    ]
                },
                {
                    "code": "DetectedIssue",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "Device"
                },
                {
                    "code": "DeviceDefinition"
                },
                {
                    "code": "DeviceMetric"
                },
                {
                    "code": "DeviceRequest",
                    "param": [
                        "requester",
                        "performer"
                    ]
                },
                {
                    "code": "DeviceUseStatement"
                },
                {
                    "code": "DiagnosticReport",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "DocumentManifest",
                    "param": [
                        "subject",
                        "author",
                        "recipient"
                    ]
                },
                {
                    "code": "DocumentReference",
                    "param": [
                        "subject",
                        "author",
                        "authenticator"
                    ]
                },
                {
                    "code": "Encounter",
                    "param": [
                        "practitioner",
                        "participant"
                    ]
                },
                {
                    "code": "Endpoint"
                },
                {
                    "code": "EnrollmentRequest"
                },
                {
                    "code": "EnrollmentResponse"
                },
                {
                    "code": "EpisodeOfCare",
                    "param": [
                        "care-manager"
                    ]
                },
                {
                    "code": "EventDefinition"
                },
                {
                    "code": "Evidence"
                },
                {
                    "code": "EvidenceReport"
                },
                {
                    "code": "EvidenceVariable"
                },
                {
                    "code": "ExampleScenario"
                },
                {
                    "code": "ExplanationOfBenefit",
                    "param": [
                        "enterer",
                        "provider",
                        "payee",
                        "care-team"
                    ]
                },
                {
                    "code": "FamilyMemberHistory"
                },
                {
                    "code": "Flag",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "Goal"
                },
                {
                    "code": "GraphDefinition"
                },
                {
                    "code": "Group",
                    "param": [
                        "member"
                    ]
                },
                {
                    "code": "GuidanceResponse"
                },
                {
                    "code": "HealthcareService"
                },
                {
                    "code": "ImagingStudy"
                },
                {
                    "code": "Immunization",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "ImmunizationEvaluation"
                },
                {
                    "code": "ImmunizationRecommendation"
                },
                {
                    "code": "ImplementationGuide"
                },
                {
                    "code": "Ingredient"
                },
                {
                    "code": "InsurancePlan"
                },
                {
                    "code": "Invoice",
                    "param": [
                        "participant"
                    ]
                },
                {
                    "code": "Library"
                },
                {
                    "code": "Linkage",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "List",
                    "param": [
                        "source"
                    ]
                },
                {
                    "code": "Location"
                },
                {
                    "code": "ManufacturedItemDefinition"
                },
                {
                    "code": "Measure"
                },
                {
                    "code": "MeasureReport"
                },
                {
                    "code": "Media",
                    "param": [
                        "subject",
                        "operator"
                    ]
                },
                {
                    "code": "Medication"
                },
                {
                    "code": "MedicationAdministration",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "MedicationDispense",
                    "param": [
                        "performer",
                        "receiver"
                    ]
                },
                {
                    "code": "MedicationKnowledge"
                },
                {
                    "code": "MedicationRequest",
                    "param": [
                        "requester"
                    ]
                },
                {
                    "code": "MedicationStatement",
                    "param": [
                        "source"
                    ]
                },
                {
                    "code": "MedicinalProductDefinition"
                },
                {
                    "code": "MessageDefinition"
                },
                {
                    "code": "MessageHeader",
                    "param": [
                        "receiver",
                        "author",
                        "responsible",
                        "enterer"
                    ]
                },
                {
                    "code": "MolecularSequence"
                },
                {
                    "code": "NamingSystem"
                },
                {
                    "code": "NutritionOrder",
                    "param": [
                        "provider"
                    ]
                },
                {
                    "code": "NutritionProduct"
                },
                {
                    "code": "Observation",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "ObservationDefinition"
                },
                {
                    "code": "OperationDefinition"
                },
                {
                    "code": "OperationOutcome"
                },
                {
                    "code": "Organization"
                },
                {
                    "code": "OrganizationAffiliation"
                },
                {
                    "code": "PackagedProductDefinition"
                },
                {
                    "code": "Patient",
                    "param": [
                        "general-practitioner"
                    ]
                },
                {
                    "code": "PaymentNotice",
                    "param": [
                        "provider"
                    ]
                },
                {
                    "code": "PaymentReconciliation",
                    "param": [
                        "requestor"
                    ]
                },
                {
                    "code": "Person",
                    "param": [
                        "practitioner"
                    ]
                },
                {
                    "code": "PlanDefinition"
                },
                {
                    "code": "Practitioner",
                    "param": [
                        "{def}"
                    ]
                },
                {
                    "code": "PractitionerRole",
                    "param": [
                        "practitioner"
                    ]
                },
                {
                    "code": "Procedure",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "Provenance",
                    "param": [
                        "agent"
                    ]
                },
                {
                    "code": "Questionnaire"
                },
                {
                    "code": "QuestionnaireResponse",
                    "param": [
                        "author",
                        "source"
                    ]
                },
                {
                    "code": "RegulatedAuthorization"
                },
                {
                    "code": "RelatedPerson"
                },
                {
                    "code": "RequestGroup",
                    "param": [
                        "participant",
                        "author"
                    ]
                },
                {
                    "code": "ResearchDefinition"
                },
                {
                    "code": "ResearchElementDefinition"
                },
                {
                    "code": "ResearchStudy",
                    "param": [
                        "principalinvestigator"
                    ]
                },
                {
                    "code": "ResearchSubject"
                },
                {
                    "code": "RiskAssessment",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "Schedule",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "SearchParameter"
                },
                {
                    "code": "ServiceRequest",
                    "param": [
                        "performer",
                        "requester"
                    ]
                },
                {
                    "code": "Slot"
                },
                {
                    "code": "Specimen",
                    "param": [
                        "collector"
                    ]
                },
                {
                    "code": "SpecimenDefinition"
                },
                {
                    "code": "StructureDefinition"
                },
                {
                    "code": "StructureMap"
                },
                {
                    "code": "Subscription"
                },
                {
                    "code": "SubscriptionStatus"
                },
                {
                    "code": "SubscriptionTopic"
                },
                {
                    "code": "Substance"
                },
                {
                    "code": "SubstanceDefinition"
                },
                {
                    "code": "SupplyDelivery",
                    "param": [
                        "supplier",
                        "receiver"
                    ]
                },
                {
                    "code": "SupplyRequest",
                    "param": [
                        "requester"
                    ]
                },
                {
                    "code": "Task"
                },
                {
                    "code": "TerminologyCapabilities"
                },
                {
                    "code": "TestReport"
                },
                {
                    "code": "TestScript"
                },
                {
                    "code": "ValueSet"
                },
                {
                    "code": "VerificationResult"
                },
                {
                    "code": "VisionPrescription",
                    "param": [
                        "prescriber"
                    ]
                }
            ]
        }
        """;

    private const string _compartmentDefinitionRelatedPerson = """
        {
            "resourceType": "CompartmentDefinition",
            "id": "relatedPerson",
            "meta": {
                "lastUpdated": "2022-05-28T12:47:40.239+10:00"
            },
            "url": "http://hl7.org/fhir/CompartmentDefinition/relatedPerson",
            "version": "4.3.0",
            "name": "Base FHIR compartment definition for RelatedPerson",
            "status": "draft",
            "experimental": true,
            "date": "2022-05-28T12:47:40+10:00",
            "publisher": "FHIR Project Team",
            "contact": [
                {
                    "telecom": [
                        {
                            "system": "url",
                            "value": "http://hl7.org/fhir"
                        }
                    ]
                }
            ],
            "description": "There is an instance of the relatedPerson compartment for each relatedPerson resource, and the identity of the compartment is the same as the relatedPerson. The set of resources associated with a particular 'related person'",
            "code": "RelatedPerson",
            "search": true,
            "resource": [
                {
                    "code": "Account"
                },
                {
                    "code": "ActivityDefinition"
                },
                {
                    "code": "AdministrableProductDefinition"
                },
                {
                    "code": "AdverseEvent",
                    "param": [
                        "recorder"
                    ]
                },
                {
                    "code": "AllergyIntolerance",
                    "param": [
                        "asserter"
                    ]
                },
                {
                    "code": "Appointment",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "AppointmentResponse",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "AuditEvent"
                },
                {
                    "code": "Basic",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "Binary"
                },
                {
                    "code": "BiologicallyDerivedProduct"
                },
                {
                    "code": "BodyStructure"
                },
                {
                    "code": "Bundle"
                },
                {
                    "code": "CapabilityStatement"
                },
                {
                    "code": "CarePlan",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "CareTeam",
                    "param": [
                        "participant"
                    ]
                },
                {
                    "code": "CatalogEntry"
                },
                {
                    "code": "ChargeItem",
                    "param": [
                        "enterer",
                        "performer-actor"
                    ]
                },
                {
                    "code": "ChargeItemDefinition"
                },
                {
                    "code": "Citation"
                },
                {
                    "code": "Claim",
                    "param": [
                        "payee"
                    ]
                },
                {
                    "code": "ClaimResponse"
                },
                {
                    "code": "ClinicalImpression"
                },
                {
                    "code": "ClinicalUseDefinition"
                },
                {
                    "code": "CodeSystem"
                },
                {
                    "code": "Communication",
                    "param": [
                        "sender",
                        "recipient"
                    ]
                },
                {
                    "code": "CommunicationRequest",
                    "param": [
                        "sender",
                        "recipient",
                        "requester"
                    ]
                },
                {
                    "code": "CompartmentDefinition"
                },
                {
                    "code": "Composition",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "ConceptMap"
                },
                {
                    "code": "Condition",
                    "param": [
                        "asserter"
                    ]
                },
                {
                    "code": "Consent"
                },
                {
                    "code": "Contract"
                },
                {
                    "code": "Coverage",
                    "param": [
                        "policy-holder",
                        "subscriber",
                        "payor"
                    ]
                },
                {
                    "code": "CoverageEligibilityRequest"
                },
                {
                    "code": "CoverageEligibilityResponse"
                },
                {
                    "code": "DetectedIssue"
                },
                {
                    "code": "Device"
                },
                {
                    "code": "DeviceDefinition"
                },
                {
                    "code": "DeviceMetric"
                },
                {
                    "code": "DeviceRequest"
                },
                {
                    "code": "DeviceUseStatement"
                },
                {
                    "code": "DiagnosticReport"
                },
                {
                    "code": "DocumentManifest",
                    "param": [
                        "author",
                        "recipient"
                    ]
                },
                {
                    "code": "DocumentReference",
                    "param": [
                        "author"
                    ]
                },
                {
                    "code": "Encounter",
                    "param": [
                        "participant"
                    ]
                },
                {
                    "code": "Endpoint"
                },
                {
                    "code": "EnrollmentRequest"
                },
                {
                    "code": "EnrollmentResponse"
                },
                {
                    "code": "EpisodeOfCare"
                },
                {
                    "code": "EventDefinition"
                },
                {
                    "code": "Evidence"
                },
                {
                    "code": "EvidenceReport"
                },
                {
                    "code": "EvidenceVariable"
                },
                {
                    "code": "ExampleScenario"
                },
                {
                    "code": "ExplanationOfBenefit",
                    "param": [
                        "payee"
                    ]
                },
                {
                    "code": "FamilyMemberHistory"
                },
                {
                    "code": "Flag"
                },
                {
                    "code": "Goal"
                },
                {
                    "code": "GraphDefinition"
                },
                {
                    "code": "Group"
                },
                {
                    "code": "GuidanceResponse"
                },
                {
                    "code": "HealthcareService"
                },
                {
                    "code": "ImagingStudy"
                },
                {
                    "code": "Immunization"
                },
                {
                    "code": "ImmunizationEvaluation"
                },
                {
                    "code": "ImmunizationRecommendation"
                },
                {
                    "code": "ImplementationGuide"
                },
                {
                    "code": "Ingredient"
                },
                {
                    "code": "InsurancePlan"
                },
                {
                    "code": "Invoice",
                    "param": [
                        "recipient"
                    ]
                },
                {
                    "code": "Library"
                },
                {
                    "code": "Linkage"
                },
                {
                    "code": "List"
                },
                {
                    "code": "Location"
                },
                {
                    "code": "ManufacturedItemDefinition"
                },
                {
                    "code": "Measure"
                },
                {
                    "code": "MeasureReport"
                },
                {
                    "code": "Media"
                },
                {
                    "code": "Medication"
                },
                {
                    "code": "MedicationAdministration",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "MedicationDispense"
                },
                {
                    "code": "MedicationKnowledge"
                },
                {
                    "code": "MedicationRequest"
                },
                {
                    "code": "MedicationStatement",
                    "param": [
                        "source"
                    ]
                },
                {
                    "code": "MedicinalProductDefinition"
                },
                {
                    "code": "MessageDefinition"
                },
                {
                    "code": "MessageHeader"
                },
                {
                    "code": "MolecularSequence"
                },
                {
                    "code": "NamingSystem"
                },
                {
                    "code": "NutritionOrder"
                },
                {
                    "code": "NutritionProduct"
                },
                {
                    "code": "Observation",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "ObservationDefinition"
                },
                {
                    "code": "OperationDefinition"
                },
                {
                    "code": "OperationOutcome"
                },
                {
                    "code": "Organization"
                },
                {
                    "code": "OrganizationAffiliation"
                },
                {
                    "code": "PackagedProductDefinition"
                },
                {
                    "code": "Patient",
                    "param": [
                        "link"
                    ]
                },
                {
                    "code": "PaymentNotice"
                },
                {
                    "code": "PaymentReconciliation"
                },
                {
                    "code": "Person",
                    "param": [
                        "link"
                    ]
                },
                {
                    "code": "PlanDefinition"
                },
                {
                    "code": "Practitioner"
                },
                {
                    "code": "PractitionerRole"
                },
                {
                    "code": "Procedure",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "Provenance",
                    "param": [
                        "agent"
                    ]
                },
                {
                    "code": "Questionnaire"
                },
                {
                    "code": "QuestionnaireResponse",
                    "param": [
                        "author",
                        "source"
                    ]
                },
                {
                    "code": "RegulatedAuthorization"
                },
                {
                    "code": "RelatedPerson",
                    "param": [
                        "{def}"
                    ]
                },
                {
                    "code": "RequestGroup",
                    "param": [
                        "participant"
                    ]
                },
                {
                    "code": "ResearchDefinition"
                },
                {
                    "code": "ResearchElementDefinition"
                },
                {
                    "code": "ResearchStudy"
                },
                {
                    "code": "ResearchSubject"
                },
                {
                    "code": "RiskAssessment"
                },
                {
                    "code": "Schedule",
                    "param": [
                        "actor"
                    ]
                },
                {
                    "code": "SearchParameter"
                },
                {
                    "code": "ServiceRequest",
                    "param": [
                        "performer"
                    ]
                },
                {
                    "code": "Slot"
                },
                {
                    "code": "Specimen"
                },
                {
                    "code": "SpecimenDefinition"
                },
                {
                    "code": "StructureDefinition"
                },
                {
                    "code": "StructureMap"
                },
                {
                    "code": "Subscription"
                },
                {
                    "code": "SubscriptionStatus"
                },
                {
                    "code": "SubscriptionTopic"
                },
                {
                    "code": "Substance"
                },
                {
                    "code": "SubstanceDefinition"
                },
                {
                    "code": "SupplyDelivery"
                },
                {
                    "code": "SupplyRequest",
                    "param": [
                        "requester"
                    ]
                },
                {
                    "code": "Task"
                },
                {
                    "code": "TerminologyCapabilities"
                },
                {
                    "code": "TestReport"
                },
                {
                    "code": "TestScript"
                },
                {
                    "code": "ValueSet"
                },
                {
                    "code": "VerificationResult"
                },
                {
                    "code": "VisionPrescription"
                }
            ]
        }
        """;
}
