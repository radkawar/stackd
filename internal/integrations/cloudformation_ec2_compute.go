package integrations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationEC2ComputeHandlers binds official EC2 compute resources to the
// existing authorized EC2/EBS owners. Instance readiness is observed from EC2's
// native runtime controller, never synthesized from launch admission.
func CloudFormationEC2ComputeHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::EC2::Instance":                  cfnEC2Instance{commands},
		"AWS::EC2::LaunchTemplate":            cfnEC2LaunchTemplate{commands},
		"AWS::EC2::Volume":                    cfnEC2Volume{commands},
		"AWS::EC2::VolumeAttachment":          cfnEC2VolumeAttachment{commands},
		"AWS::EC2::KeyPair":                   cfnEC2KeyPair{commands},
		"AWS::EC2::SnapshotBlockPublicAccess": cfnEC2SnapshotBlockPublicAccess{commands},
	}
}

func cfnEC2ComputeProjection(value any) (cloudformation.Properties, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var p cloudformation.Properties
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	return p, nil
}

func cfnEC2ComputePublicTags(tags api.TagList) []any {
	out := []any{}
	for _, tag := range tags {
		key := cfnComputeValue(tag.Key)
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			continue
		}
		out = append(out, map[string]any{"Key": key, "Value": cfnComputeValue(tag.Value)})
	}
	return out
}

func cfnEC2ComputeBool[T ~bool](p *T) bool { return p != nil && bool(*p) }

func cfnEC2ComputeMissing(kind, id string) error {
	return &awswire.Error{Code: "InvalidResource.NotFound", Message: fmt.Sprintf("EC2 %s %s does not exist", kind, id), StatusCode: 400}
}

func cfnEC2ComputeValidate(p cloudformation.Properties, allowed ...string) error {
	if err := cfnComputeProperties(p, allowed...); err != nil {
		return err
	}
	_, err := cfnEC2NetworkTags(p)
	return err
}

func cfnEC2ComputeEqual(a, b any) bool {
	// Both sides may originate from a generated DTO or resolved template; JSON
	// normalizes integer representations without treating absent as zero.
	aa, ea := json.Marshal(a)
	bb, eb := json.Marshal(b)
	return ea == nil && eb == nil && bytes.Equal(aa, bb)
}
