﻿// <copyright file="SubscriptionConverter.cs" company="Microsoft Corporation">
//     Copyright (c) Microsoft Corporation. All rights reserved.
//     Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// </copyright>

using FhirStore.Models;
using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;

namespace FhirStore.Versioned.Shims.Subscriptions;

/// <summary>A subscription format converter.</summary>
public class SubscriptionConverter
{
    /// <summary>Attempts to parse a ParsedSubscription from the given object.</summary>
    /// <param name="subscription">The subscription.</param>
    /// <param name="common">      [out] The common.</param>
    /// <returns>True if it succeeds, false if it fails.</returns>
    public bool TryParse(object subscription, out ParsedSubscription common)
    {
        if ((subscription == null) ||
            (subscription is not Hl7.Fhir.Model.Subscription sub) ||
            string.IsNullOrEmpty(sub.Id) ||
            string.IsNullOrEmpty(sub.Topic))
        {
            common = null!;
            return false;
        }

        common = new()
        {
            Id = sub.Id,
            TopicUrl = sub.Topic,
            ChannelSystem = sub.ChannelType?.System ?? string.Empty,
            ChannelCode = sub.ChannelType?.Code ?? string.Empty,
            Endpoint = sub.Endpoint,
            HeartbeatSeconds = sub.HeartbeatPeriod ?? 0,
            TimeoutSeconds = sub.Timeout ?? 0,
            ContentType = sub.ContentType,
            ContentLevel = sub.Content?.ToString() ?? string.Empty,
            MaxEventsPerNotification = sub.MaxCount ?? 0,
        };

        // add parameters
        if (sub.Parameter?.Any() ?? false)
        {
            foreach (Hl7.Fhir.Model.Subscription.ParameterComponent param in sub.Parameter)
            {
                if (!common.Parameters.ContainsKey(param.Name))
                {
                    common.Parameters.Add(param.Name, new());
                }

                common.Parameters[param.Name].Add(param.Value.ToString());
            }
        }

        // add filters
        if (sub.FilterBy?.Any() ?? false)
        {
            foreach (Hl7.Fhir.Model.Subscription.FilterByComponent filter in sub.FilterBy)
            {
                string key = string.IsNullOrEmpty(filter.ResourceType) ? "*" : filter.ResourceType;

                if (!common.Filters.ContainsKey(key))
                {
                    common.Filters.Add(key, new());
                }

                common.Filters[key].Add(new(
                    filter.ResourceType ?? string.Empty,
                    filter.FilterParameter,
                    filter.Comparator?.ToString() ?? string.Empty,
                    filter.Modifier?.ToString() ?? string.Empty,
                    filter.Value));
            }
        }

        return true;
    }

    public Hl7.Fhir.Model.Resource StatusForSubscription(
        ParsedSubscription subscription,
        string notificationType,
        string baseUrl)
    {
        if (!Enum.TryParse(subscription.CurrentStatus, out SubscriptionStatusCodes statusCode))
        {
            statusCode = SubscriptionStatusCodes.Active;
        }

        return new Hl7.Fhir.Model.SubscriptionStatus()
        {
            Subscription = new ResourceReference(baseUrl + "/Subscription/" + subscription.Id),
            Topic = subscription.TopicUrl,
            EventsSinceSubscriptionStart = subscription.CurrentEventCount,
            Status = statusCode,
            Type = Hl7.Fhir.Utility.EnumUtility.ParseLiteral<SubscriptionStatus.SubscriptionNotificationType>(notificationType),
        };
    }

    /// <summary>
    /// Build a bundle of subscription events into the desired format and content level.
    /// </summary>
    /// <param name="subscription">    The subscription the events belong to.</param>
    /// <param name="eventNumbers">    One or more event numbers to include.</param>
    /// <param name="notificationType">Type of notification (e.g., 'notification-event')</param>
    /// <param name="contentLevel">    Override for the content level specified in the subscription.</param>
    /// <returns></returns>
    public Bundle? BundleForSubscriptionEvents(
        ParsedSubscription subscription,
        IEnumerable<long> eventNumbers,
        string notificationType,
        string baseUrl,
        string contentLevel = "")
    {
        if (string.IsNullOrEmpty(contentLevel))
        {
            contentLevel = subscription.ContentLevel;
        }

        // create our notification bundle
        Bundle bundle = new()
        {
            Type = Bundle.BundleType.SubscriptionNotification,
            Timestamp = DateTimeOffset.Now,
            Entry = new(),
        };

        if (!Enum.TryParse(subscription.CurrentStatus, out SubscriptionStatusCodes statusCode))
        {
            statusCode = SubscriptionStatusCodes.Active;
        }

        // create our status resource
        SubscriptionStatus status = new()
        {
            Subscription = new ResourceReference(baseUrl + "/Subscription/" + subscription.Id),
            Topic = subscription.TopicUrl,
            EventsSinceSubscriptionStart = subscription.CurrentEventCount,
            Status = statusCode,
            Type = Hl7.Fhir.Utility.EnumUtility.ParseLiteral<SubscriptionStatus.SubscriptionNotificationType>(notificationType),
            NotificationEvent = new(),
        };

        // add a status placeholder to the bundle
        bundle.Entry.Add(new Bundle.EntryComponent());

        HashSet<string> addedResources = new();

        bool isEmpty = contentLevel.Equals("empty", StringComparison.Ordinal);
        bool isFullResource = contentLevel.Equals("full-resource", StringComparison.Ordinal);

        // determine behavior of no event numbers
        if (!eventNumbers.Any())
        {
            // query-event should send all
            if (notificationType.Equals("query-event"))
            {
                eventNumbers = subscription.GeneratedEvents.Keys;
            }
            // others send the most recent if there is one
            else if (subscription.GeneratedEvents.Any())
            {
                eventNumbers = new long[] { subscription.GeneratedEvents.Keys.Last() };
            }
            else
            {
                eventNumbers = Array.Empty<long>();
            }
        }

        // iterate over the events
        foreach (long eventNumber in eventNumbers)
        {
            if (!subscription.GeneratedEvents.ContainsKey(eventNumber))
            {
                continue;
            }

            SubscriptionEvent se = subscription.GeneratedEvents[eventNumber];

            // check for empty notifications
            if (isEmpty)
            {
                // add just this event number to our status
                status.NotificationEvent.Add(new()
                {
                    EventNumber = eventNumber,
                    Timestamp = se.Timestamp,
                });

                // empty notifications do not contain bundle entries
                continue;
            }

            Resource r = (Resource)se.Focus;
            string relativeUrl = $"{r.TypeName}/{r.Id}";

            // add this event to our status
            status.NotificationEvent.Add(new()
            {
                EventNumber = eventNumber,
                Focus = new ResourceReference(baseUrl + "/" + relativeUrl),
                AdditionalContext = (se.AdditionalContext?.Any() ?? false)
                    ? se.AdditionalContext.Select(o => new ResourceReference($"{baseUrl}/{((Resource)o).TypeName}/{((Resource)o).Id}")).ToList()
                    : new List<ResourceReference>(),
                Timestamp = se.Timestamp,
            });

            // add the focus to our bundle
            if (!addedResources.Contains(relativeUrl))
            {
                addedResources.Add(relativeUrl);

                if (isFullResource)
                {
                    bundle.Entry.Add(new Bundle.EntryComponent()
                    {
                        FullUrl = baseUrl + "/" + relativeUrl,
                        Resource = r,
                    });
                }
            }

            // add any additional context
            if (se.AdditionalContext?.Any() ?? false)
            {
                foreach (object ac in se.AdditionalContext)
                {
                    Resource acr = (Resource)ac;
                    string acrRelative = $"{acr.TypeName}/{acr.Id}";

                    if (!addedResources.Contains(acrRelative))
                    {
                        addedResources.Add(acrRelative);

                        if (isFullResource)
                        {
                            bundle.Entry.Add(new Bundle.EntryComponent()
                            {
                                FullUrl = baseUrl + "/" + acrRelative,
                                Resource = acr,
                            });
                        }
                    }
                }
            }
        }

        // set our status information in our bundle
        bundle.Entry[0].Resource = status;

        return bundle;
    }
}
