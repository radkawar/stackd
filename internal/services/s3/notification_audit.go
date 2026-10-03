package s3

import api "stackd/internal/awsapi/s3"

// CloudTrail records XML element names and collapses singleton repeated
// elements. Keep the submitted values, not the admitted/generated rule IDs.
func notificationParameters(c *apiCall, in *api.NotificationConfiguration) {
	c.params["notification"] = ""
	if in == nil {
		return
	}
	document := map[string]any{"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"}
	appendRule := func(name, destinationName, destination string, id *api.NotificationId, events api.EventList, filter *api.NotificationConfigurationFilter) {
		rule := map[string]any{destinationName: destination}
		if id != nil {
			rule["Id"] = *id
		}
		for _, event := range events {
			appendNotificationElement(rule, "Event", event)
		}
		if filter != nil {
			projected := map[string]any{}
			if filter.Key != nil {
				key := map[string]any{}
				for _, value := range filter.Key.FilterRules {
					appendNotificationElement(key, "FilterRule", value)
				}
				projected["S3Key"] = key
			}
			rule["Filter"] = projected
		}
		appendNotificationElement(document, name, rule)
	}
	for _, rule := range in.TopicConfigurations {
		appendRule("TopicConfiguration", "Topic", value(rule.TopicArn), rule.Id, rule.Events, rule.Filter)
	}
	for _, rule := range in.QueueConfigurations {
		appendRule("QueueConfiguration", "Queue", value(rule.QueueArn), rule.Id, rule.Events, rule.Filter)
	}
	for _, rule := range in.LambdaFunctionConfigurations {
		appendRule("CloudFunctionConfiguration", "CloudFunction", value(rule.LambdaFunctionArn), rule.Id, rule.Events, rule.Filter)
	}
	if in.EventBridgeConfiguration != nil {
		document["EventBridgeConfiguration"] = map[string]any{}
	}
	c.params["NotificationConfiguration"] = document
}

func appendNotificationElement(document map[string]any, name string, value any) {
	previous, exists := document[name]
	if !exists {
		document[name] = value
	} else if repeated, ok := previous.([]any); ok {
		document[name] = append(repeated, value)
	} else {
		document[name] = []any{previous, value}
	}
}
