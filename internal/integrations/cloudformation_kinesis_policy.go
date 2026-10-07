package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	kinesisapi "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// cfnKinesisResourcePolicy attaches policies through the native owner's private,
// transactionally committed policy claim. Direct Cloud Control mutations retain
// ordinary native authority, including deletion of unclaimed policies.
type cfnKinesisResourcePolicy struct{ commands StepFunctionsCommands }

type cfnKinesisPolicyProperties struct {
	ResourceArn    string
	ResourcePolicy map[string]any
}

func cfnKinesisPolicyDecode(raw cloudformation.Properties) (cfnKinesisPolicyProperties, string, error) {
	var p cfnKinesisPolicyProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, "", err
	}
	if p.ResourceArn == "" || !strings.Contains(p.ResourceArn, ":kinesis:") || !strings.Contains(p.ResourceArn, ":stream/") {
		return p, "", fmt.Errorf("ResourceArn must identify a Kinesis stream or consumer")
	}
	document, err := cfnDataPolicyDocument(p.ResourcePolicy)
	return p, document, err
}

func (h cfnKinesisResourcePolicy) Validate(p cloudformation.Properties) error {
	_, _, err := cfnKinesisPolicyDecode(p)
	return err
}

func (h cfnKinesisResourcePolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	if _, _, err := cfnKinesisPolicyDecode(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "ResourceArn"), nil
}

func (h cfnKinesisResourcePolicy) current(ctx context.Context, arn string) (string, error) {
	out, err := cfnComputeCall[kinesisapi.GetResourcePolicyOutput](ctx, h.commands, "kinesis", "GetResourcePolicy", map[string]any{"ResourceARN": arn})
	if err != nil {
		return "", err
	}
	if policy := cfnComputeValue(out.Policy); policy != "{}" {
		return policy, nil
	}
	return "", nil
}

func (h cfnKinesisResourcePolicy) apply(ctx context.Context, r cloudformation.ResourceRequest, createOnly bool) (cloudformation.ResourceResult, error) {
	p, document, err := cfnKinesisPolicyDecode(r.Properties)
	if err != nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, err
	}
	if err := cfnMessagingScopeARN(r, p.ResourceArn, "kinesis"); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnKinesisOwnerContext(ctx, r, "policy", createOnly)
	err = cfnComputeRun(ctx, h.commands, "kinesis", "PutResourcePolicy", map[string]any{"ResourceARN": p.ResourceArn, "Policy": document})
	if err != nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, err
	}
	return cloudformation.ResourceResult{PhysicalID: p.ResourceArn, Ref: p.ResourceArn}, nil
}

func (h cfnKinesisResourcePolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.apply(ctx, r, true)
}

func (h cfnKinesisResourcePolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.apply(ctx, r, false)
}

func (h cfnKinesisResourcePolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	arn := r.PhysicalID
	if arn == "" {
		arn = cfnComputeString(r.Properties, "ResourceArn")
	}
	if arn == "" {
		return nil
	}
	ctx = cfnKinesisOwnerContext(ctx, r, "policy", false)
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "kinesis", "DeleteResourcePolicy", map[string]any{"ResourceARN": arn}))
}

func (h cfnKinesisResourcePolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	policy, err := h.current(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if policy == "" {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "No resource policy found for resource ARN " + r.PhysicalID + ".", StatusCode: 400}
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(policy), &document); err != nil {
		return nil, err
	}
	return cloudformation.Properties{"ResourceArn": r.PhysicalID, "ResourcePolicy": document}, nil
}

// List reports stream and consumer policies currently attached by the owner.
func (h cfnKinesisResourcePolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	streams, err := (cfnKinesisStream(h)).List(ctx, r)
	if err != nil {
		return nil, err
	}
	consumers, err := (cfnKinesisConsumer(h)).List(ctx, r)
	if err != nil {
		return nil, err
	}
	result := []cloudformation.ResourceDescription{}
	for _, item := range append(streams, consumers...) {
		arn := cfnComputeString(item.Properties, "Arn")
		if arn == "" {
			arn = cfnComputeString(item.Properties, "ConsumerARN")
		}
		if arn == "" {
			continue
		}
		policy, err := h.current(ctx, arn)
		if err != nil {
			return nil, err
		}
		if policy != "" {
			result = append(result, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"ResourceArn": arn}})
		}
	}
	return result, nil
}
