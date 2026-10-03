package integrations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

const cfnMessagingOwnerTag = "stackd:cloudformation:owner"
const cfnMessagingTokenTag = "stackd:cloudformation:create-token"
const cfnMessagingPolicyTag = "stackd:cloudformation:policy"

// CloudFormationMessagingHandlers registers only resources backed by the real
// typed S3, SQS and SNS command owners. No resource state lives in this adapter.
func CloudFormationMessagingHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::S3::Bucket":        cfnS3Bucket{commands},
		"AWS::S3::BucketPolicy":  cfnS3BucketPolicy{commands},
		"AWS::SQS::Queue":        cfnSQSQueue{commands},
		"AWS::SQS::QueuePolicy":  cfnSQSQueuePolicy{commands},
		"AWS::SNS::Topic":        cfnSNSTopic{commands},
		"AWS::SNS::TopicPolicy":  cfnSNSTopicPolicy{commands},
		"AWS::SNS::Subscription": cfnSNSSubscription{commands},
	}
}

func cfnMessagingCall[T any](ctx context.Context, commands StepFunctionsCommands, service, operation string, input any) (*T, error) {
	result, wire := commands.CallTyped(ctx, service, operation, input)
	if wire != nil {
		return nil, wire
	}
	out, ok := result.Output.(*T)
	if !ok || out == nil {
		return nil, fmt.Errorf("%s.%s returned unexpected typed output %T", service, operation, result.Output)
	}
	return out, nil
}

func cfnMessagingExec(ctx context.Context, commands StepFunctionsCommands, service, operation string, input any) error {
	_, wire := commands.CallTyped(ctx, service, operation, input)
	if wire != nil {
		return wire
	}
	return nil
}

func cfnMessagingMissing(err error, codes ...string) bool {
	var wire *awswire.Error
	if !errors.As(err, &wire) {
		return false
	}
	for _, code := range codes {
		if wire.Code == code {
			return true
		}
	}
	return false
}

func cfnMessagingDecode(p cloudformation.Properties, out any) error {
	for name, value := range p {
		if value == nil {
			return fmt.Errorf("property %s must not be null; use AWS::NoValue to omit it", name)
		}
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("unsupported or invalid CloudFormation properties: %w", err)
	}
	return nil
}

// CloudFormation accepts scalar strings produced by Ref for boolean/integer
// resource properties. Keep this coercion at the template/owner boundary.
type cfnMessagingBool bool

func (b *cfnMessagingBool) UnmarshalJSON(raw []byte) error {
	text := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
	}
	if text != "true" && text != "false" {
		return fmt.Errorf("expected true or false, got %s", raw)
	}
	*b = cfnMessagingBool(text == "true")
	return nil
}

type cfnMessagingInt int64

func (n *cfnMessagingInt) UnmarshalJSON(raw []byte) error {
	text := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
	}
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("expected integer: %w", err)
	}
	*n = cfnMessagingInt(v)
	return nil
}

type cfnMessagingTag struct {
	Key   string
	Value string
}

func cfnMessagingTags(r cloudformation.ResourceRequest, tags []cfnMessagingTag) (map[string]string, error) {
	out := make(map[string]string, len(r.Tags)+len(tags)+2)
	for k, v := range r.Tags {
		out[k] = v
	}
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		if seen[tag.Key] {
			return nil, fmt.Errorf("duplicate tag %q", tag.Key)
		}
		seen[tag.Key] = true
		out[tag.Key] = tag.Value
	}
	for k, v := range out {
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") || strings.HasPrefix(strings.ToLower(k), "stackd:cloudformation:") {
			return nil, fmt.Errorf("invalid or reserved tag %q", k)
		}
	}
	out[cfnMessagingOwnerTag] = cfnMessagingOwner(r)
	out[cfnMessagingTokenTag] = cfnMessagingHash(r.Token)
	return out, nil
}
func cfnMessagingHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}
func cfnMessagingOwner(r cloudformation.ResourceRequest) string {
	return cfnMessagingHash(r.StackID + "\x00" + r.LogicalID)
}
func cfnMessagingOwned(tags map[string]string, r cloudformation.ResourceRequest) error {
	if tags[cfnMessagingOwnerTag] != cfnMessagingOwner(r) || tags[cfnMessagingTokenTag] != cfnMessagingHash(r.Token) {
		return fmt.Errorf("resource already exists and is not owned by this CloudFormation resource incarnation")
	}
	return nil
}
func cfnMessagingKeys[K ~string, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}
func cfnMessagingName(r cloudformation.ResourceRequest, max int, fifo bool) string {
	var b strings.Builder
	for _, ch := range strings.ToLower(r.StackName + "-" + r.LogicalID) {
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' {
			b.WriteRune(ch)
		}
	}
	prefix := strings.Trim(b.String(), "-")
	if prefix == "" {
		prefix = "stack"
	}
	suffix := "-" + cfnMessagingHash(r.StackID + "\x00" + r.LogicalID + "\x00" + r.Token)[:16]
	if fifo {
		suffix += ".fifo"
	}
	if len(prefix) > max-len(suffix) {
		prefix = prefix[:max-len(suffix)]
	}
	return prefix + suffix
}
func cfnMessagingChanged(a, b cloudformation.Properties, keys ...string) bool {
	for _, k := range keys {
		if !reflect.DeepEqual(a[k], b[k]) {
			return true
		}
	}
	return false
}
func cfnMessagingJSON(v any) (string, error) { raw, err := json.Marshal(v); return string(raw), err }
func cfnMessagingPolicy(p map[string]any) (string, error) {
	if len(p) == 0 {
		return "", fmt.Errorf("PolicyDocument must be a nonempty JSON object")
	}
	doc, err := cfnMessagingJSON(p)
	if err != nil {
		return "", err
	}
	if err := authorization.ValidateResourcePolicy([]byte(doc)); err != nil {
		return "", fmt.Errorf("invalid PolicyDocument: %w", err)
	}
	return doc, nil
}
func cfnMessagingResult(id string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id}
}
func cfnMessagingReplacement(named bool, changed bool) (bool, error) {
	if named && changed {
		return false, fmt.Errorf("replacement requires a new custom resource name")
	}
	return changed, nil
}
func cfnMessagingScopeARN(r cloudformation.ResourceRequest, arn, service string) error {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != r.Scope.Partition || parts[2] != service || parts[3] != r.Scope.Region || parts[4] != r.Scope.Account {
		return fmt.Errorf("%s must identify a %s resource in the stack account, partition and region", arn, service)
	}
	return nil
}

func cfnMessagingMarker(r cloudformation.ResourceRequest) string {
	return cfnMessagingOwner(r) + ":" + cfnMessagingHash(r.Token)
}
func cfnMessagingEqualJSON(a, b string) bool {
	var left, right any
	if json.Unmarshal([]byte(a), &left) != nil || json.Unmarshal([]byte(b), &right) != nil {
		return a == b
	}
	return reflect.DeepEqual(left, right)
}
func cfnMessagingUnique(values []string, name string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty", name)
	}
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			return fmt.Errorf("%s contains an empty or duplicate target", name)
		}
		seen[v] = true
	}
	return nil
}
