package s3

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

const notificationEventOverlap = "Configurations overlap. Configurations on the same bucket cannot share a common event type."

var (
	notificationTopicARN  = regexp.MustCompile(`^arn:aws[a-zA-Z\-]*:sns:[a-zA-Z0-9\-]+:[0-9]{12}:[a-zA-Z0-9\-_]{1,256}$`)
	notificationQueueARN  = regexp.MustCompile(`^arn:aws[a-zA-Z\-]*:sqs:[a-zA-Z0-9\-]+:[0-9]{12}:[a-zA-Z0-9\-_]{1,80}$`)
	notificationLambdaARN = regexp.MustCompile(`^arn:aws[a-zA-Z\-]*:lambda:[a-zA-Z0-9\-]+:[0-9]{12}:function:[a-zA-Z0-9\-_]+(:[a-zA-Z0-9$_\-]+)?$`)
)

func parseNotificationConfiguration(in *api.NotificationConfiguration, bucket BucketRecord) (NotificationConfiguration, *awswire.Error) {
	if in == nil {
		return NotificationConfiguration{}, malformedXML()
	}
	count := len(in.TopicConfigurations) + len(in.QueueConfigurations) + len(in.LambdaFunctionConfigurations)
	if count > 100 {
		return NotificationConfiguration{}, failure("InvalidRequest", "Too many configurations submitted. The maximum number of configurations is 100", 400)
	}
	out := NotificationConfiguration{
		EventBridge: in.EventBridgeConfiguration != nil,
		Rules:       make([]NotificationRule, 0, count),
	}
	ids := make(map[string]struct{}, cap(out.Rules))
	appendRule := func(protocol NotificationProtocol, destination string, id *api.NotificationId, events api.EventList, filter *api.NotificationConfigurationFilter) *awswire.Error {
		rule, wire := parseNotificationRule(protocol, destination, value(id), events, filter, bucket)
		if wire != nil {
			return wire
		}
		if _, exists := ids[rule.ID]; exists {
			return invalid("Same ID used for multiple configurations. IDs must be unique.")
		}
		ids[rule.ID] = struct{}{}
		out.Rules = append(out.Rules, rule)
		return nil
	}
	for _, rule := range in.TopicConfigurations {
		if wire := appendRule(NotificationSNS, value(rule.TopicArn), rule.Id, rule.Events, rule.Filter); wire != nil {
			return NotificationConfiguration{}, wire
		}
	}
	for _, rule := range in.QueueConfigurations {
		if wire := appendRule(NotificationSQS, value(rule.QueueArn), rule.Id, rule.Events, rule.Filter); wire != nil {
			return NotificationConfiguration{}, wire
		}
	}
	for _, rule := range in.LambdaFunctionConfigurations {
		if wire := appendRule(NotificationLambda, value(rule.LambdaFunctionArn), rule.Id, rule.Events, rule.Filter); wire != nil {
			return NotificationConfiguration{}, wire
		}
	}
	for i, rule := range out.Rules {
		prefix, suffix := notificationFilterValues(rule)
		for _, previous := range out.Rules[:i] {
			if !notificationEventsOverlap(rule.Events, previous.Events) {
				continue
			}
			otherPrefix, otherSuffix := notificationFilterValues(previous)
			if (strings.HasPrefix(prefix, otherPrefix) || strings.HasPrefix(otherPrefix, prefix)) &&
				(strings.HasSuffix(suffix, otherSuffix) || strings.HasSuffix(otherSuffix, suffix)) {
				if len(rule.Filters) == 0 && len(previous.Filters) == 0 {
					return NotificationConfiguration{}, invalid(notificationEventOverlap)
				}
				return NotificationConfiguration{}, invalid("Configuration is ambiguously defined. Cannot have overlapping suffixes in two rules if the prefixes are overlapping for the same event type.")
			}
		}
	}
	return out, nil
}

func parseNotificationRule(protocol NotificationProtocol, destination, id string, events api.EventList, filter *api.NotificationConfigurationFilter, bucket BucketRecord) (NotificationRule, *awswire.Error) {
	if len(id) > 255 {
		return NotificationRule{}, invalid("ID length exceeded allowed limit of 255")
	}
	if len(events) == 0 || destination == "" {
		return NotificationRule{}, malformedXML()
	}
	if wire := validateNotificationARN(protocol, destination, bucket); wire != nil {
		return NotificationRule{}, wire
	}
	rule := NotificationRule{ID: id, Protocol: protocol, DestinationARN: destination, Events: make([]string, 0, len(events))}
	for _, event := range events {
		name := string(event)
		for _, previous := range rule.Events {
			if notificationEventIncludes(name, previous) || notificationEventIncludes(previous, name) {
				return NotificationRule{}, invalid(notificationEventOverlap)
			}
		}
		rule.Events = append(rule.Events, name)
	}
	if filter != nil {
		if filter.Key == nil || len(filter.Key.FilterRules) == 0 {
			return NotificationRule{}, malformedXML()
		}
		rule.Filters = make([]NotificationFilter, 0, len(filter.Key.FilterRules))
		var prefix, suffix bool
		for _, raw := range filter.Key.FilterRules {
			name := value(raw.Name)
			switch {
			case strings.EqualFold(name, "prefix"):
				if prefix {
					return NotificationRule{}, invalid("Cannot specify more than one prefix rule in a filter.")
				}
				prefix, name = true, "Prefix"
			case strings.EqualFold(name, "suffix"):
				if suffix {
					return NotificationRule{}, invalid("Cannot specify more than one suffix rule in a filter.")
				}
				suffix, name = true, "Suffix"
			default:
				return NotificationRule{}, invalid("filter rule name must be either prefix or suffix")
			}
			v := value(raw.Value)
			if len(v) > 1024 {
				return NotificationRule{}, invalid("Size of filter rule value cannot exceed 1024 bytes in UTF-8 representation")
			}
			rule.Filters = append(rule.Filters, NotificationFilter{Name: name, Value: v})
		}
	}
	if rule.ID == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			return NotificationRule{}, failure("InternalError", "An internal error occurred.", 500)
		}
		// Native generated IDs are base64-encoded UUID strings.
		rule.ID = base64.StdEncoding.EncodeToString([]byte(id.String()))
	}
	return rule, nil
}

func validateNotificationARN(protocol NotificationProtocol, destination string, bucket BucketRecord) *awswire.Error {
	parsed, err := arn.Parse(destination)
	if err != nil {
		return invalid("The ARN could not be parsed")
	}
	var pattern *regexp.Regexp
	var nativePattern string
	switch protocol {
	case NotificationSNS:
		pattern = notificationTopicARN
		nativePattern = `^arn:aws[\p{Alpha}\-]*:sns:[\p{Alnum}\-]+:[\p{Digit}]{12}:[\p{Alnum}\-_]{1,256}$`
	case NotificationSQS:
		if parsed.Service == "sqs" && strings.HasSuffix(parsed.Resource, ".fifo") {
			return invalid("FIFO SQS queues are not supported.")
		}
		pattern = notificationQueueARN
		nativePattern = `^arn:aws[\p{Alpha}\-]*:sqs:[\p{Alnum}\-]+:[\p{Digit}]{12}:[\p{Alnum}\-_]{1,80}$`
	case NotificationLambda:
		pattern = notificationLambdaARN
		nativePattern = pattern.String()
	default:
		return invalid("The notification destination service is not valid")
	}
	if !pattern.MatchString(destination) || parsed.Partition != bucket.Key.Partition {
		return invalid("The ARN failed to satisfy constraint: Member must satisfy regular expression pattern: " + nativePattern)
	}
	if parsed.Region != bucket.Region {
		return invalid("The notification destination service region is not valid for the bucket location constraint")
	}
	return nil
}

func notificationConfigurationOutput(in NotificationConfiguration) *api.GetBucketNotificationConfigurationOutput {
	out := &api.GetBucketNotificationConfigurationOutput{}
	if in.EventBridge {
		out.EventBridgeConfiguration = &api.EventBridgeConfiguration{}
	}
	for _, rule := range in.Rules {
		id := api.NotificationId(rule.ID)
		events := make(api.EventList, len(rule.Events))
		for i, event := range rule.Events {
			events[i] = api.Event(event)
		}
		var filter *api.NotificationConfigurationFilter
		if len(rule.Filters) != 0 {
			filter = &api.NotificationConfigurationFilter{Key: &api.S3KeyFilter{FilterRules: make(api.FilterRuleList, len(rule.Filters))}}
			for i, stored := range rule.Filters {
				name, v := api.FilterRuleName(stored.Name), api.FilterRuleValue(stored.Value)
				filter.Key.FilterRules[i] = api.FilterRule{Name: &name, Value: &v}
			}
		}
		switch rule.Protocol {
		case NotificationSNS:
			destination := api.TopicArn(rule.DestinationARN)
			out.TopicConfigurations = append(out.TopicConfigurations, api.TopicConfiguration{Id: &id, TopicArn: &destination, Events: events, Filter: filter})
		case NotificationSQS:
			destination := api.QueueArn(rule.DestinationARN)
			out.QueueConfigurations = append(out.QueueConfigurations, api.QueueConfiguration{Id: &id, QueueArn: &destination, Events: events, Filter: filter})
		case NotificationLambda:
			destination := api.LambdaFunctionArn(rule.DestinationARN)
			out.LambdaFunctionConfigurations = append(out.LambdaFunctionConfigurations, api.LambdaFunctionConfiguration{Id: &id, LambdaFunctionArn: &destination, Events: events, Filter: filter})
		}
	}
	return out
}

func notificationEventIncludes(pattern, event string) bool {
	return pattern == event || strings.HasSuffix(pattern, ":*") && strings.HasPrefix(event, strings.TrimSuffix(pattern, "*"))
}

func notificationEventsOverlap(a, b []string) bool {
	for _, left := range a {
		for _, right := range b {
			if notificationEventIncludes(left, right) || notificationEventIncludes(right, left) {
				return true
			}
		}
	}
	return false
}

func notificationFilterValues(rule NotificationRule) (prefix, suffix string) {
	for _, filter := range rule.Filters {
		decoded, err := url.QueryUnescape(filter.Value)
		if err != nil {
			// TODO: Comeback capture delivery matching for admitted malformed
			// escapes. Preserve the entire value literally rather than partially
			// decoding it or turning a decoding failure into a match-all filter.
			decoded = filter.Value
		}
		switch filter.Name {
		case "Prefix":
			prefix = decoded
		case "Suffix":
			suffix = decoded
		}
	}
	return prefix, suffix
}

func notificationMatches(rule NotificationRule, key, event string) bool {
	for _, subscribed := range rule.Events {
		if notificationEventIncludes(subscribed, event) {
			prefix, suffix := notificationFilterValues(rule)
			return strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix)
		}
	}
	return false
}
