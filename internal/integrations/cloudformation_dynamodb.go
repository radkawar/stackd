package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/dynamodb"
	"stackd/internal/services/kinesis"
)

// CloudFormationDataStreamHandlers registers DynamoDB and Kinesis resources
// whose effects are owned by the existing typed service commands. Native table
// and stream readiness is observed through those owners; nothing is retained here.
func CloudFormationDataStreamHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::DynamoDB::Table":         cfnDynamoDBTable{commands},
		"AWS::DynamoDB::GlobalTable":   cfnDynamoDBGlobalTable{commands},
		"AWS::Kinesis::Stream":         cfnKinesisStream{commands},
		"AWS::Kinesis::StreamConsumer": cfnKinesisConsumer{commands},
		"AWS::Kinesis::ResourcePolicy": cfnKinesisResourcePolicy{commands},
	}
}

func cfnDDBOwnerContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return dynamodb.WithResourceOwner(ctx, dynamodb.ResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}, create)
}

func cfnKinesisOwnerContext(ctx context.Context, r cloudformation.ResourceRequest, kind string, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return kinesis.WithResourceOwner(ctx, kinesis.ResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}, kind, create)
}

func cfnDataCreateTags(r cloudformation.ResourceRequest) map[string]string {
	tags, _ := cfnComputeTags(r.Properties)
	for key, value := range r.Tags {
		if _, exists := tags[key]; !exists {
			tags[key] = value
		}
	}
	return tags
}

// cfnDataInt reads generated numeric members, including absent values.
func cfnDataInt[T ~int32 | ~int64](v *T) int64 {
	if v == nil {
		return 0
	}
	return int64(*v)
}

func cfnDataBool[T ~bool](v *T) bool { return v != nil && bool(*v) }

// cfnDataRegion runs an owner command against a sibling Region under the same
// caller identity. Owners still evaluate the regional ARN and authorization.
func cfnDataRegion(ctx context.Context, region string) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.Region = region
	return awsctx.WithMetadata(ctx, metadata)
}

// cfnDataJSON projects a generated owner shape into CloudFormation's
// identically named JSON members.
func cfnDataJSON(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// cfnDataUnsupported rejects template features for which the selected owner
// has no implemented effect, instead of silently dropping them.
func cfnDataUnsupported(owner string, present map[string]bool) error {
	names := make([]string, 0, len(present))
	for name, ok := range present {
		if ok {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	return fmt.Errorf("%s does not implement CloudFormation properties: %s", owner, strings.Join(names, ", "))
}

func cfnDataRaw(raw json.RawMessage) bool { return len(raw) != 0 }

func cfnDataPolicyDocument(document map[string]any) (string, error) {
	if len(document) == 0 {
		return "", fmt.Errorf("PolicyDocument must be a nonempty JSON object")
	}
	raw, err := json.Marshal(document)
	return string(raw), err
}

func cfnDataEqualJSON(a, b string) bool {
	var left, right any
	if json.Unmarshal([]byte(a), &left) != nil || json.Unmarshal([]byte(b), &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

// cfnDataUserTags projects customer tags into read models.
func cfnDataUserTags(tags map[string]string) []any {
	return cfnResourcePublicTags(tags)
}

func cfnDataChangedTags(current, desired map[string]string) map[string]string {
	changed := map[string]string{}
	for key, value := range desired {
		if existing, ok := current[key]; !ok || existing != value {
			changed[key] = value
		}
	}
	return changed
}

func cfnDataTimestamp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
