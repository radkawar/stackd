package integrations

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

// EC2 ownership is a private native claim admitted in the same
// transaction as the resource. Public tags are customer metadata only; they
// neither grant nor revoke CloudFormation ownership.
type cfnEC2NativeOwnerService interface {
	CloudFormationCreation(context.Context, string, string) (string, error)
	CloudFormationOwned(context.Context, string, string, string) error
}

func cfnEC2NativeIdentity(r cloudformation.ResourceRequest) string {
	return r.StackID + "/" + r.LogicalID + "/" + r.Token
}

// cfnEC2NativeContext admits creation (create/recover-create) or fences a
// mutation of r.PhysicalID. Cloud Control direct mutations are ordinary native
// calls: they retain an existing private claim but are not stack-fenced.
func cfnEC2NativeContext(ctx context.Context, r cloudformation.ResourceRequest, intent string) context.Context {
	return cfnEC2NativeTargetContext(ctx, r, intent, r.PhysicalID)
}

func cfnEC2NativeTargetContext(ctx context.Context, r cloudformation.ResourceRequest, intent, id string) context.Context {
	switch intent {
	case "create", "recover-create":
		return ec2.WithCloudFormationCreation(ctx, r.Type, cfnEC2NativeIdentity(r))
	default:
		if r.CloudControl {
			return ctx
		}
		return ec2.WithCloudFormationMutation(ctx, r.Type, cfnEC2NativeIdentity(r), id)
	}
}

func cfnEC2NativeOwner(c StepFunctionsCommands) (cfnEC2NativeOwnerService, error) {
	provider, ok := c.providers["ec2"]
	if !ok {
		return nil, fmt.Errorf("EC2 owner is unavailable")
	}
	owner, ok := provider.executor.(cfnEC2NativeOwnerService)
	if !ok {
		return nil, fmt.Errorf("EC2 owner does not support private CloudFormation ownership")
	}
	return owner, nil
}

// cfnEC2NativeOwned observes the exact private claim under current IAM.
func cfnEC2NativeOwned(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, id string) error {
	if r.CloudControl {
		return nil
	}
	if r.Token == "" {
		return fmt.Errorf("EC2 ownership requires a resource incarnation")
	}
	owner, err := cfnEC2NativeOwner(c)
	if err != nil {
		return err
	}
	return owner.CloudFormationOwned(ctx, r.Type, cfnEC2NativeIdentity(r), id)
}

// cfnEC2NativeRecover returns the exact admitted resource, or "" when native
// state certifies that this incarnation never admitted a creation.
func cfnEC2NativeRecover(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest) (string, error) {
	if r.Token == "" {
		return "", fmt.Errorf("EC2 creation recovery requires a resource incarnation")
	}
	owner, err := cfnEC2NativeOwner(c)
	if err != nil {
		return "", err
	}
	id, err := owner.CloudFormationCreation(ctx, r.Type, cfnEC2NativeIdentity(r))
	if errors.Is(err, ec2.ErrNotFound) {
		if r.PhysicalID != "" {
			return "", fmt.Errorf("supplied EC2 physical identity has no admission for this resource incarnation")
		}
		return "", nil
	}
	if err != nil {
		return id, err
	}
	if r.PhysicalID != "" && r.PhysicalID != id {
		// KeyPair's public primary identifier is its name, while the private
		// admission always records the immutable native key-pair ID.
		if r.Type == "AWS::EC2::KeyPair" {
			pair, err := (cfnEC2KeyPair{c}).getID(ctx, id)
			if err != nil {
				return "", err
			}
			if r.PhysicalID == cfnComputeValue(pair.KeyName) {
				return id, nil
			}
		}
		return "", fmt.Errorf("supplied EC2 physical identity differs from this resource incarnation's admission")
	}
	return id, nil
}

// cfnEC2NetworkTags validates customer metadata. Only AWS-reserved keys are
// rejected; stackd-prefixed keys are ordinary customer tags.
func cfnEC2NetworkTags(p map[string]any) (map[string]string, error) {
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

func cfnEC2NetworkDesiredTags(r cloudformation.ResourceRequest) map[string]string {
	tags := make(map[string]string, len(r.Tags))
	for key, value := range r.Tags {
		tags[key] = value
	}
	resource, _ := cfnEC2NetworkTags(r.Properties)
	for key, value := range resource {
		tags[key] = value
	}
	return tags
}

func cfnEC2NetworkTagSpecifications(r cloudformation.ResourceRequest, resourceType string) []map[string]any {
	return []map[string]any{{"ResourceType": resourceType, "Tags": cfnComputeTagList(cfnEC2NetworkDesiredTags(r))}}
}

// cfnEC2NetworkUpdateTags converges template-managed metadata on id. It removes
// only keys the previous template managed, never out-of-band customer tags.
func cfnEC2NetworkUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, id string, current map[string]string) error {
	ctx = cfnEC2NativeTargetContext(ctx, r, "mutate", id)
	desired := cfnEC2NetworkDesiredTags(r)
	previous, _ := cfnEC2NetworkTags(r.Previous)
	var removed []string
	for key := range previous {
		if _, keep := desired[key]; !keep {
			if _, live := current[key]; live {
				removed = append(removed, key)
			}
		}
	}
	sort.Strings(removed)
	if len(removed) != 0 {
		tags := make([]map[string]string, 0, len(removed))
		for _, key := range removed {
			tags = append(tags, map[string]string{"Key": key})
		}
		if err := cfnComputeRun(ctx, c, "ec2", "DeleteTags", map[string]any{"Resources": []string{id}, "Tags": tags}); err != nil {
			return err
		}
	}
	changed := map[string]string{}
	for key, value := range desired {
		if old, ok := current[key]; !ok || old != value {
			changed[key] = value
		}
	}
	if len(changed) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "ec2", "CreateTags", map[string]any{"Resources": []string{id}, "Tags": cfnComputeTagList(changed)})
}

// cfnEC2NetworkUserTags projects every customer tag, including stackd-prefixed
// keys; only AWS-reserved keys are omitted.
func cfnEC2NetworkUserTags(tags api.TagList) []map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := cfnComputeValue(tag.Key)
		if !strings.HasPrefix(strings.ToLower(key), "aws:") {
			out[key] = cfnComputeValue(tag.Value)
		}
	}
	return cfnComputeTagList(out)
}
