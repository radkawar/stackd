package cloudtrail

import (
	"slices"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/cloudtrail"
	"stackd/internal/awswire"
	"stackd/journal"
)

func defaultSelection() Selection {
	return Selection{Basic: []BasicSelector{{IncludeManagement: true}}}
}

func decodeSelection(in *api.PutEventSelectorsInput) (Selection, *awswire.Error) {
	invalid := func(message string) (Selection, *awswire.Error) {
		return Selection{}, failure("InvalidEventSelectorsException", message)
	}
	if in == nil || (in.EventSelectors != nil && in.AdvancedEventSelectors != nil) || (len(in.EventSelectors) == 0 && len(in.AdvancedEventSelectors) == 0) {
		return invalid("Specify one nonempty event selector family.")
	}
	if len(in.EventSelectors) > 5 || len(in.AdvancedEventSelectors) > 5 {
		return invalid("A trail supports at most five event selectors.")
	}
	var selection Selection
	resources := 0
	for _, input := range in.EventSelectors {
		selector := BasicSelector{IncludeManagement: true}
		if input.IncludeManagementEvents != nil {
			selector.IncludeManagement = bool(*input.IncludeManagementEvents)
		}
		if input.ReadWriteType != nil {
			switch string(*input.ReadWriteType) {
			case "All":
			case "ReadOnly", "WriteOnly":
				readOnly := string(*input.ReadWriteType) == "ReadOnly"
				selector.ReadOnly = &readOnly
			default:
				return invalid("ReadWriteType must be All, ReadOnly, or WriteOnly.")
			}
		}
		for _, source := range input.ExcludeManagementEventSources {
			if !managementExclusion(string(source)) {
				return invalid("Only KMS and RDS Data API management event sources may be excluded.")
			}
			selector.ExcludedSources = append(selector.ExcludedSources, string(source))
		}
		for _, inputResource := range input.DataResources {
			if inputResource.Type == nil || len(inputResource.Values) == 0 {
				return invalid("A data resource requires a supported type and at least one ARN value.")
			}
			resource := DataResource{Type: string(*inputResource.Type)}
			for _, value := range inputResource.Values {
				if !validBasicARN(resource.Type, string(value)) {
					return invalid("The data resource type and ARN value are not a valid basic selector combination.")
				}
				resource.ARNPrefixes = append(resource.ARNPrefixes, string(value))
				// Selecting every resource of a type does not consume the
				// individual-resource quota.
				if strings.Count(string(value), ":") != 2 {
					resources++
				}
			}
			selector.DataResources = append(selector.DataResources, resource)
		}
		selection.Basic = append(selection.Basic, selector)
	}
	if resources > 250 {
		return invalid("A trail supports at most 250 individual data resources across its selectors.")
	}
	values := 0
	for _, input := range in.AdvancedEventSelectors {
		selector := AdvancedSelector{}
		if input.Name != nil {
			selector.Name = string(*input.Name)
		}
		category, resourceType := "", ""
		seen := make(map[string]bool, len(input.FieldSelectors))
		for _, inputField := range input.FieldSelectors {
			if inputField.Field == nil || seen[string(*inputField.Field)] {
				return invalid("Each advanced selector field must be specified exactly once.")
			}
			field := FieldSelector{Field: string(*inputField.Field)}
			seen[field.Field] = true
			for _, operator := range []struct {
				name   string
				values api.Operator
			}{
				{"Equals", inputField.Equals}, {"StartsWith", inputField.StartsWith}, {"EndsWith", inputField.EndsWith},
				{"NotEquals", inputField.NotEquals}, {"NotStartsWith", inputField.NotStartsWith}, {"NotEndsWith", inputField.NotEndsWith},
			} {
				if operator.values == nil {
					continue
				}
				if len(operator.values) == 0 {
					return invalid("A field operator requires at least one value.")
				}
				test := FieldTest{Operator: operator.name, Values: make([]string, len(operator.values))}
				for i, value := range operator.values {
					if value == "" {
						return invalid("Field operator values must not be empty.")
					}
					test.Values[i] = string(value)
				}
				values += len(test.Values)
				field.Tests = append(field.Tests, test)
			}
			if len(field.Tests) == 0 {
				return invalid("An advanced field selector requires an operator.")
			}
			if field.Field == "eventCategory" || field.Field == "resources.type" || field.Field == "readOnly" {
				if len(field.Tests) != 1 || field.Tests[0].Operator != "Equals" || len(field.Tests[0].Values) != 1 {
					return invalid("eventCategory, resources.type, and readOnly require Equals with one value.")
				}
				switch field.Field {
				case "eventCategory":
					category = field.Tests[0].Values[0]
				case "resources.type":
					resourceType = field.Tests[0].Values[0]
				case "readOnly":
					if value := field.Tests[0].Values[0]; value != "true" && value != "false" {
						return invalid("readOnly must equal true or false.")
					}
				}
			}
			selector.Fields = append(selector.Fields, field)
		}
		switch category {
		case "Management", "Data":
		case "NetworkActivity", "Insight", "ConfigurationItem", "Evidence", "ActivityAuditLog":
			return Selection{}, failure("UnsupportedOperationException", "Only native Management and Data event categories are supported for trail delivery.")
		default:
			return invalid("An advanced selector requires a valid eventCategory.")
		}
		if category == "Data" && !validResourceType(resourceType) {
			return invalid("A Data selector requires one valid resources.type.")
		}
		for _, field := range selector.Fields {
			switch field.Field {
			case "eventCategory", "readOnly":
			case "eventSource":
				if category == "Management" {
					for _, test := range field.Tests {
						if test.Operator != "NotEquals" {
							return invalid("Management eventSource supports only NotEquals.")
						}
						for _, value := range test.Values {
							if !managementExclusion(value) {
								return invalid("Only KMS and RDS Data API management event sources may be excluded.")
							}
						}
					}
				}
			case "resources.type", "resources.ARN", "eventName", "eventType", "userIdentity.arn", "sessionCredentialFromConsole":
				if category != "Data" {
					return invalid("This field is not supported for management events on trails.")
				}
				if field.Field == "sessionCredentialFromConsole" {
					for _, test := range field.Tests {
						if (test.Operator != "Equals" && test.Operator != "NotEquals") || len(test.Values) != 1 || test.Values[0] != "true" {
							return invalid("sessionCredentialFromConsole supports Equals or NotEquals with true.")
						}
					}
					return Selection{}, failure("UnsupportedOperationException", "Native API producers do not capture console session credentials.")
				}
				if field.Field == "resources.ARN" {
					for _, test := range field.Tests {
						if test.Operator != "Equals" && test.Operator != "NotEquals" {
							continue
						}
						for _, value := range test.Values {
							if !validResourceARN(resourceType, value, false) {
								return invalid("Equals and NotEquals require a resource ARN of the selected type.")
							}
						}
					}
				}
			default:
				return invalid("The advanced selector field is not supported for this event category.")
			}
		}
		selection.Advanced = append(selection.Advanced, selector)
	}
	if values > 500 {
		return invalid("A trail supports at most 500 advanced selector condition values.")
	}
	return selection, nil
}

func managementExclusion(source string) bool {
	return source == "kms.amazonaws.com" || source == "rdsdata.amazonaws.com"
}

func validBasicARN(resourceType, value string) bool {
	service := ""
	switch resourceType {
	case "AWS::S3::Object":
		service = "s3"
	case "AWS::Lambda::Function":
		service = "lambda"
	case "AWS::DynamoDB::Table":
		service = "dynamodb"
	default:
		return false
	}
	parts := strings.SplitN(value, ":", 6)
	if len(parts) == 3 {
		return parts[0] == "arn" && validARNPartition(parts[1]) && parts[2] == service
	}
	return validResourceARN(resourceType, value, true)
}

func validARNPartition(partition string) bool {
	switch partition {
	case "aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f", "aws-eusc":
		return true
	}
	return false
}

func validResourceARN(resourceType, value string, prefix bool) bool {
	parts := strings.SplitN(value, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || !validARNPartition(parts[1]) || parts[2] == "" || parts[5] == "" {
		return false
	}
	if parts[4] != "" {
		if len(parts[4]) != 12 {
			return false
		}
		for _, digit := range parts[4] {
			if digit < '0' || digit > '9' {
				return false
			}
		}
	}
	switch resourceType {
	case "AWS::S3::Object":
		bucket, key, found := strings.Cut(parts[5], "/")
		return parts[2] == "s3" && parts[3] == "" && parts[4] == "" && found && bucket != "" && (prefix || key != "")
	case "AWS::Lambda::Function":
		name, found := strings.CutPrefix(parts[5], "function:")
		return parts[2] == "lambda" && parts[3] != "" && len(parts[4]) == 12 && found && name != "" && (prefix || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == "")
	case "AWS::DynamoDB::Table":
		return parts[2] == "dynamodb" && parts[3] != "" && len(parts[4]) == 12 && strings.HasPrefix(parts[5], "table/") && len(parts[5]) > len("table/")
	}
	return true
}

// selectionOutput retains the submitted advanced field order, as Put does.
// Get orders its detached projection without changing admission configuration.
func selectionOutput(selection Selection) (api.EventSelectors, api.AdvancedEventSelectors) {
	var basic api.EventSelectors
	var advanced api.AdvancedEventSelectors
	for _, selector := range selection.Basic {
		readWrite := api.ReadWriteType("All")
		if selector.ReadOnly != nil {
			readWrite = "WriteOnly"
			if *selector.ReadOnly {
				readWrite = "ReadOnly"
			}
		}
		management := api.Boolean(selector.IncludeManagement)
		out := api.EventSelector{ReadWriteType: &readWrite, IncludeManagementEvents: &management, DataResources: api.DataResources{}, ExcludeManagementEventSources: api.ExcludeManagementEventSources{}}
		for _, source := range selector.ExcludedSources {
			out.ExcludeManagementEventSources = append(out.ExcludeManagementEventSources, api.String(source))
		}
		for _, resource := range selector.DataResources {
			item := api.DataResource{Type: str(resource.Type), Values: make(api.DataResourceValues, len(resource.ARNPrefixes))}
			for i, value := range resource.ARNPrefixes {
				item.Values[i] = api.String(value)
			}
			out.DataResources = append(out.DataResources, item)
		}
		basic = append(basic, out)
	}
	for _, selector := range selection.Advanced {
		out := api.AdvancedEventSelector{FieldSelectors: make(api.AdvancedFieldSelectors, 0, len(selector.Fields))}
		if selector.Name != "" {
			name := api.SelectorName(selector.Name)
			out.Name = &name
		}
		for _, field := range selector.Fields {
			name := api.SelectorField(field.Field)
			item := api.AdvancedFieldSelector{Field: &name}
			for _, test := range field.Tests {
				values := make(api.Operator, len(test.Values))
				for i, value := range test.Values {
					values[i] = api.OperatorValue(value)
				}
				switch test.Operator {
				case "Equals":
					item.Equals = values
				case "StartsWith":
					item.StartsWith = values
				case "EndsWith":
					item.EndsWith = values
				case "NotEquals":
					item.NotEquals = values
				case "NotStartsWith":
					item.NotStartsWith = values
				case "NotEndsWith":
					item.NotEndsWith = values
				}
			}
			out.FieldSelectors = append(out.FieldSelectors, item)
		}
		advanced = append(advanced, out)
	}
	return basic, advanced
}

func matchesSelection(selection Selection, event journal.Event) bool {
	call := event.APICallCompleted
	if call == nil || (call.Category != journal.CategoryManagement && call.Category != journal.CategoryData) {
		return false
	}
	for _, selector := range selection.Basic {
		if selector.ReadOnly != nil && *selector.ReadOnly != call.ReadOnly {
			continue
		}
		if call.Category == journal.CategoryManagement {
			if selector.IncludeManagement && !slices.Contains(selector.ExcludedSources, call.EventSource) {
				return true
			}
			continue
		}
		for _, resource := range selector.DataResources {
			for _, native := range call.EventResources {
				if native.Type != resource.Type {
					continue
				}
				actual := native.ARN
				if actual == "" {
					actual = native.ARNPrefix
				}
				for _, prefix := range resource.ARNPrefixes {
					// Lambda ARNs select one function, not similarly named functions.
					if resource.Type == "AWS::Lambda::Function" && strings.Count(prefix, ":") > 2 {
						if actual == prefix {
							return true
						}
					} else if strings.HasPrefix(actual, prefix) {
						return true
					}
				}
			}
		}
	}
	for _, selector := range selection.Advanced {
		matched := true
		for _, field := range selector.Fields {
			if !matchesAdvancedField(field, event) {
				matched = false
				break
			}
		}
		if matched && len(selector.Fields) != 0 {
			return true
		}
	}
	return false
}

func matchesAdvancedField(field FieldSelector, event journal.Event) bool {
	call := event.APICallCompleted
	value := ""
	switch field.Field {
	case "eventCategory":
		value = string(call.Category)
	case "eventSource":
		value = call.EventSource
	case "eventName":
		value = call.EventName
	case "eventType":
		value = "AwsApiCall"
	case "readOnly":
		value = strconv.FormatBool(call.ReadOnly)
	case "userIdentity.arn":
		value = event.ActorARN
	case "resources.type", "resources.ARN":
	default:
		return false
	}
	// Positive operators (and their values) form one OR group. Every negative
	// condition must pass; a single excluded value vetoes the whole field,
	// including when a different resource in the same event matched positively.
	hasPositive, positive := false, false
	for _, test := range field.Tests {
		negative := strings.HasPrefix(test.Operator, "Not")
		if !negative {
			hasPositive = true
		}
		for _, expected := range test.Values {
			matched := false
			if field.Field == "resources.type" || field.Field == "resources.ARN" {
				for _, resource := range call.EventResources {
					actual := resource.ARN
					if actual == "" {
						actual = resource.ARNPrefix
					}
					if field.Field == "resources.type" {
						actual = resource.Type
					}
					if matchesFieldValue(test.Operator, actual, expected) {
						matched = true
						break
					}
				}
			} else {
				matched = matchesFieldValue(test.Operator, value, expected)
			}
			if negative && matched {
				return false
			}
			positive = positive || (!negative && matched)
		}
	}
	return !hasPositive || positive
}

func matchesFieldValue(operator, actual, expected string) bool {
	switch operator {
	case "Equals", "NotEquals":
		return actual == expected
	case "StartsWith", "NotStartsWith":
		return strings.HasPrefix(actual, expected)
	case "EndsWith", "NotEndsWith":
		return strings.HasSuffix(actual, expected)
	}
	return false
}
