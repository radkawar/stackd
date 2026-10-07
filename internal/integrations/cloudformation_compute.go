package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationComputeHandlers is the explicit bounded compute resource registry.
// Every command enters the existing service owner's authorization boundary.
// TODO: Comeback extend bounded compute properties and genuine
// runtime/callback custom-resource lifecycles.
func CloudFormationComputeHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::IAM::Role":                      cfnIAMRole{commands},
		"AWS::IAM::Policy":                    cfnIAMPolicy{commands},
		"AWS::IAM::ManagedPolicy":             cfnIAMManagedPolicy{commands},
		"AWS::Lambda::Function":               cfnLambdaFunction{commands},
		"AWS::Lambda::Alias":                  cfnLambdaAlias{commands},
		"AWS::Lambda::Version":                cfnLambdaVersion{commands},
		"AWS::Lambda::LayerVersion":           cfnLambdaLayerVersion{commands},
		"AWS::Lambda::LayerVersionPermission": cfnLambdaLayerPermission{commands},
		"AWS::Lambda::Permission":             cfnLambdaPermission{commands},
		"AWS::Lambda::ResourcePolicy":         cfnLambdaResourcePolicy{commands},
		"AWS::Lambda::EventSourceMapping":     cfnLambdaMapping{commands},
		"AWS::Events::EventBus":               cfnEventBus{commands},
		"AWS::Events::Rule":                   cfnEventRule{commands},
		"AWS::Logs::LogGroup":                 cfnLogGroup{commands},
	}
}

const cfnComputeTagPrefix = "stackd:cloudformation:"

func cfnComputeCall[T any](ctx context.Context, c StepFunctionsCommands, service, operation string, input map[string]any) (*T, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	out, rejected := c.Call(ctx, service, operation, body)
	if rejected != nil {
		return nil, rejected
	}
	typed, ok := out.Output.(*T)
	if !ok {
		return nil, fmt.Errorf("%s.%s returned unexpected output %T", service, operation, out.Output)
	}
	return typed, nil
}

func cfnComputeRun(ctx context.Context, c StepFunctionsCommands, service, operation string, input map[string]any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	_, rejected := c.Call(ctx, service, operation, body)
	if rejected != nil {
		return rejected
	}
	return nil
}

func cfnComputeMissing(err error) bool {
	var wire *awswire.Error
	return errors.As(err, &wire) && (wire.Code == "NoSuchEntity" || wire.Code == "ResourceNotFoundException" || wire.Code == "ResourceNotFound")
}

func cfnComputeAbsent(err error) error {
	if cfnComputeMissing(err) {
		return nil
	}
	return err
}
func cfnComputeValue[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func cfnComputeString(p map[string]any, key string) string { v, _ := p[key].(string); return v }
func cfnComputeDefault(p map[string]any, key string, fallback any) any {
	if v, ok := p[key]; ok {
		return v
	}
	return fallback
}
func cfnComputeCopy(p map[string]any, keys ...string) map[string]any {
	out := make(map[string]any, len(keys))
	for _, key := range keys {
		if value, ok := p[key]; ok {
			out[key] = value
		}
	}
	return out
}
func cfnComputeChanged(a, b map[string]any, keys ...string) bool {
	for _, key := range keys {
		if !reflect.DeepEqual(a[key], b[key]) {
			return true
		}
	}
	return false
}
func cfnComputeObject(v any) (map[string]any, bool) { p, ok := v.(map[string]any); return p, ok }
func cfnComputeProperties(p map[string]any, allowed ...string) error {
	for key := range p {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unsupported CloudFormation property %s", key)
		}
	}
	return nil
}
func cfnComputeRequired(p map[string]any, keys ...string) error {
	for _, key := range keys {
		if p[key] == nil {
			return fmt.Errorf("%s is required", key)
		}
	}
	return nil
}
func cfnComputeStrings(p map[string]any, keys ...string) error {
	for _, key := range keys {
		if v, ok := p[key]; ok {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("%s must be a string", key)
			}
		}
	}
	return nil
}
func cfnComputeStringList(p map[string]any, key string) ([]string, error) {
	v, found := p[key]
	if !found {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list", key)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("%s entries must be nonempty strings", key)
		}
		out = append(out, text)
	}
	return out, nil
}
func cfnComputeDocument(v any) (string, error) {
	if text, ok := v.(string); ok {
		if !json.Valid([]byte(text)) {
			return "", fmt.Errorf("invalid JSON document")
		}
		return text, nil
	}
	if _, ok := v.(map[string]any); !ok {
		return "", fmt.Errorf("document must be a JSON object")
	}
	data, err := json.Marshal(v)
	return string(data), err
}
func cfnComputeHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:12])
}
func cfnComputeName(r cloudformation.ResourceRequest, property string, limit int) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	if name := cfnComputeString(r.Properties, property); name != "" {
		return name
	}
	prefix := r.StackName + "-" + r.LogicalID
	var safe strings.Builder
	for _, ch := range prefix {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' {
			safe.WriteRune(ch)
		}
	}
	prefix = safe.String()
	if len(prefix) > limit-25 {
		prefix = prefix[:limit-25]
	}
	return prefix + "-" + cfnComputeHash(r.StackID+"/"+r.LogicalID+"/"+r.Token)
}
func cfnComputeTags(p map[string]any) (map[string]string, error) {
	tags := map[string]string{}
	if p["Tags"] == nil {
		return tags, nil
	}
	list, ok := p["Tags"].([]any)
	if !ok {
		return nil, fmt.Errorf("property Tags must be a list")
	}
	for _, item := range list {
		tag, ok := cfnComputeObject(item)
		if !ok {
			return nil, fmt.Errorf("property Tags entries must be objects")
		}
		if err := cfnComputeProperties(tag, "Key", "Value"); err != nil {
			return nil, err
		}
		key, keyOK := tag["Key"].(string)
		value, valueOK := tag["Value"].(string)
		if !keyOK || !valueOK || key == "" {
			return nil, fmt.Errorf("property Tags requires string Key and Value")
		}
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, fmt.Errorf("reserved tag key %s", key)
		}
		if _, duplicate := tags[key]; duplicate {
			return nil, fmt.Errorf("duplicate tag key %s", key)
		}
		tags[key] = value
	}
	return tags, nil
}

// cfnResourceTags merges only customer stack/resource tags. Native private claims
// are carried by the owner context, never synthesized into public metadata.
func cfnResourceTags(r cloudformation.ResourceRequest) map[string]string {
	var tags map[string]string
	if len(r.Tags) != 0 {
		tags = make(map[string]string, len(r.Tags))
	}
	for key, value := range r.Tags {
		tags[key] = value
	}
	if r.Properties["Tags"] != nil {
		resource, _ := cfnComputeTags(r.Properties)
		if len(resource) != 0 && tags == nil {
			return resource
		}
		for key, value := range resource {
			tags[key] = value
		}
	}
	return tags
}
func cfnComputeTagList(tags map[string]string) []map[string]string {
	if len(tags) == 0 {
		return nil
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]map[string]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, map[string]string{"Key": key, "Value": tags[key]})
	}
	return out
}
func cfnComputeRemovedTags(current, desired map[string]string) []string {
	var keys []string
	for key := range current {
		if _, found := desired[key]; !found {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}
