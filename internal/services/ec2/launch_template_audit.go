package ec2

import (
	"encoding/json"
	"strconv"
	"strings"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
)

func launchTemplateAction(action string) bool {
	switch action {
	case "CreateLaunchTemplate", "CreateLaunchTemplateVersion", "DescribeLaunchTemplates", "DescribeLaunchTemplateVersions", "ModifyLaunchTemplate", "DeleteLaunchTemplate", "DeleteLaunchTemplateVersions", "GetLaunchTemplateData":
		return true
	}
	return false
}

var launchTemplateAuditResponse = awsapi.DocumentProjection{PreserveNames: true, Fields: map[string]awsapi.FieldProjection{
	"LaunchTemplateVersion.LaunchTemplateData.UserData": {Mode: awsapi.RedactValueField, Redaction: "<sensitiveDataRemoved>"},
	"LaunchTemplate.CreateTime":                         {TimeLayout: "2006-01-02T15:04:05.000Z"},
	"LaunchTemplateVersion.CreateTime":                  {TimeLayout: "2006-01-02T15:04:05.000Z"},
}}

// Native template APIs retain XML-shaped request envelopes, including the query
// indices, but infer nonnegative numeric version text as numbers in CloudTrail.
func launchTemplateAuditRequest(document json.RawMessage) (json.RawMessage, error) {
	if len(document) == 0 || string(document) == "null" {
		return json.Marshal("")
	}
	var value any
	if err := json.Unmarshal(document, &value); err != nil {
		return nil, err
	}
	var visit func(any, string) any
	visit = func(v any, key string) any {
		switch v := v.(type) {
		case map[string]any:
			for k, c := range v {
				childKey := k
				if k == "content" {
					childKey = key
				}
				v[k] = visit(c, childKey)
				if child, ok := v[k].(map[string]any); ok && len(child) == 0 {
					delete(v, k)
				}
			}
			return v
		case []any:
			for i, c := range v {
				v[i] = visit(c, key)
			}
			return v
		case string:
			if key == "SourceVersion" || key == "SetDefaultVersion" || key == "MinVersion" || key == "MaxVersion" || key == "LaunchTemplateVersion" {
				if v != "" && !strings.HasPrefix(v, "-") {
					if n, err := strconv.ParseUint(v, 10, 64); err == nil {
						return n
					}
				}
			}
		}
		return v
	}
	cleaned := visit(value, "")
	if object, ok := cleaned.(map[string]any); ok && len(object) == 0 {
		return json.Marshal("")
	}
	return json.Marshal(cleaned)
}

// Unlike the older EC2 APIs, template responses preserve ISO millisecond times
// and singular XML item envelopes, collapsing a one-element set to an object.
func launchTemplateAuditResponseDocument(model awscatalog.Service, id awscatalog.ShapeID, document json.RawMessage) (json.RawMessage, error) {
	if len(document) == 0 || string(document) == "null" {
		return document, nil
	}
	shape, _ := model.Shape(id)
	if shape.Kind != "structure" {
		return document, nil
	}
	var original map[string]json.RawMessage
	if err := json.Unmarshal(document, &original); err != nil {
		return nil, err
	}
	out := map[string]json.RawMessage{}
	for _, member := range shape.Members {
		value, present := original[member.Name]
		if !present {
			continue
		}
		target, _ := model.Shape(member.Target)
		name := member.XMLName
		if name == "" {
			name = ec2AuditLower(member.Name)
		}
		if target.Kind == "list" || target.Kind == "set" {
			var items []json.RawMessage
			if err := json.Unmarshal(value, &items); err != nil {
				return nil, err
			}
			if len(items) == 0 {
				continue
			}
			for i, item := range items {
				v, err := launchTemplateAuditResponseDocument(model, target.Member.Target, item)
				if err != nil {
					return nil, err
				}
				items[i] = v
			}
			itemName := target.Member.XMLName
			if itemName == "" {
				itemName = "item"
			}
			var child any = items
			if len(items) == 1 {
				child = items[0]
			}
			encoded, err := json.Marshal(map[string]any{itemName: child})
			if err != nil {
				return nil, err
			}
			out[name] = encoded
		} else {
			encoded, err := launchTemplateAuditResponseDocument(model, member.Target, value)
			if err != nil {
				return nil, err
			}
			out[name] = encoded
		}
	}
	return json.Marshal(out)
}
