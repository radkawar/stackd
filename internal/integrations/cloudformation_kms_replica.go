package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/kms"
)

// ReplicaKey's creation is ReplicateKey in the primary Region, not CreateKey
// in the stack Region. All subsequent effects address the regional replica.
type cfnKMSReplicaKey struct{ commands StepFunctionsCommands }

var cfnKMSKeyIDPattern = regexp.MustCompile(`^(mrk-[0-9a-f]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)
var cfnKMSAccountPattern = regexp.MustCompile(`^[0-9]{12}$`)

func cfnKMSKeyARN(arn string) ([]string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "kms" || parts[3] == "" || !cfnKMSAccountPattern.MatchString(parts[4]) || !strings.HasPrefix(parts[5], "key/") || !cfnKMSKeyIDPattern.MatchString(strings.TrimPrefix(parts[5], "key/")) {
		return nil, fmt.Errorf("a KMS key ARN is required; aliases and bare key IDs are not accepted")
	}
	return parts, nil
}

func cfnKMSIdentifier(ctx context.Context, id string) (string, error) {
	if !strings.HasPrefix(id, "arn:") {
		if !cfnKMSKeyIDPattern.MatchString(id) {
			return "", &awswire.Error{Code: "NotFoundException", Message: "Invalid KMS key identifier", StatusCode: 400}
		}
		return id, nil
	}
	parts, err := cfnKMSKeyARN(id)
	m := awsctx.FromContext(ctx)
	if err != nil || parts[1] != m.Partition || parts[3] != m.Region || parts[4] != m.AccountID {
		return "", &awswire.Error{Code: "NotFoundException", Message: "KMS key is outside the resource account, Region, or partition", StatusCode: 400}
	}
	return strings.TrimPrefix(parts[5], "key/"), nil
}

func cfnKMSKeyContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return kms.WithKeyResourceOwner(ctx, kms.KeyResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

func cfnKMSKeyCreationContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	// Cloud Control also has a stable create request incarnation. Only creation
	// uses it; subsequent direct reads and mutations retain native authority.
	return kms.WithKeyResourceOwner(ctx, kms.KeyResourceOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

func cfnKMSPendingWindow(p cloudformation.Properties) (int64, error) {
	raw, present := p["PendingWindowInDays"]
	if !present {
		return 30, nil
	}
	var days int64
	switch n := raw.(type) {
	case int:
		days = int64(n)
	case int32:
		days = int64(n)
	case int64:
		days = n
	case float64:
		if n < 7 || n > 30 || n != float64(int64(n)) {
			return 0, fmt.Errorf("PendingWindowInDays must be an integer between 7 and 30")
		}
		days = int64(n)
	case json.Number:
		var err error
		days, err = n.Int64()
		if err != nil {
			return 0, fmt.Errorf("PendingWindowInDays must be an integer between 7 and 30")
		}
	default:
		return 0, fmt.Errorf("PendingWindowInDays must be an integer between 7 and 30")
	}
	if days < 7 || days > 30 {
		return 0, fmt.Errorf("PendingWindowInDays must be an integer between 7 and 30")
	}
	return days, nil
}

func cfnKMSPolicy(document any) (string, error) {
	policy, err := cfnComputeDocument(document)
	if err != nil {
		return "", err
	}
	characters := 0
	for _, r := range policy {
		characters++
		if characters > 32768 {
			return "", fmt.Errorf("KeyPolicy must contain between 1 and 32768 characters")
		}
		if r != '\t' && r != '\n' && r != '\r' && (r < 0x20 || r > 0xff) {
			return "", fmt.Errorf("KeyPolicy contains a character outside the KMS policy character set")
		}
	}
	if characters == 0 {
		return "", fmt.Errorf("KeyPolicy must contain between 1 and 32768 characters")
	}
	return policy, nil
}

func (h cfnKMSReplicaKey) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "PrimaryKeyArn", "KeyPolicy", "Description", "Enabled", "PendingWindowInDays", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "PrimaryKeyArn", "KeyPolicy"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "PrimaryKeyArn", "Description"); err != nil {
		return err
	}
	arn := cfnComputeString(p, "PrimaryKeyArn")
	if len(arn) > 256 {
		return fmt.Errorf("PrimaryKeyArn must contain between 1 and 256 characters")
	}
	if _, err := cfnKMSKeyARN(arn); err != nil {
		return fmt.Errorf("PrimaryKeyArn: %w", err)
	}
	if utf8.RuneCountInString(cfnComputeString(p, "Description")) > 8192 {
		return fmt.Errorf("description must not exceed 8192 characters")
	}
	if enabled, present := p["Enabled"]; present {
		if _, ok := enabled.(bool); !ok {
			return fmt.Errorf("enabled must be a boolean")
		}
	}
	if _, err := cfnKMSPendingWindow(p); err != nil {
		return err
	}
	if _, err := cfnKMSPolicy(p["KeyPolicy"]); err != nil {
		return err
	}
	tags, err := cfnComputeTags(p)
	if err != nil {
		return err
	}
	for key, value := range tags {
		if utf8.RuneCountInString(key) > 128 || utf8.RuneCountInString(value) > 256 {
			return fmt.Errorf("KMS tag keys and values must not exceed 128 and 256 characters")
		}
	}
	return nil
}

func (h cfnKMSReplicaKey) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "PrimaryKeyArn"), h.Validate(b)
}

func (h cfnKMSReplicaKey) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	primary := cfnComputeString(r.Properties, "PrimaryKeyArn")
	parts, _ := cfnKMSKeyARN(primary)
	m := awsctx.FromContext(ctx)
	if parts[1] != m.Partition || parts[4] != m.AccountID || parts[3] == m.Region {
		return cloudformation.ResourceResult{}, fmt.Errorf("PrimaryKeyArn must identify a primary key in this account and partition, in a different Region")
	}
	policy, err := cfnKMSPolicy(r.Properties["KeyPolicy"])
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := map[string]any{"KeyId": primary, "ReplicaRegion": m.Region, "Policy": policy, "Description": cfnComputeString(r.Properties, "Description"), "Tags": cfnKMSTags(cfnResourceTags(r))}
	m.Region = parts[3]
	primaryContext := awsctx.WithMetadata(cfnKMSKeyCreationContext(ctx, r), m)
	out, err := cfnComputeCall[api.ReplicateKeyOutput](primaryContext, h.commands, "kms", "ReplicateKey", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnKMSMetadataResult(out.ReplicaKeyMetadata), nil
}

func cfnKMSReplicaRequest(r cloudformation.ResourceRequest) cloudformation.ResourceRequest {
	r.Properties = cloudformation.Properties(cfnComputeCopy(r.Properties, "KeyPolicy", "Description", "Enabled", "PendingWindowInDays", "Tags"))
	r.Properties["Enabled"] = cfnComputeDefault(r.Properties, "Enabled", true)
	r.Previous = cloudformation.Properties(cfnComputeCopy(r.Previous, "KeyPolicy", "Description", "Enabled", "PendingWindowInDays", "Tags"))
	return r
}

func (h cfnKMSReplicaKey) describe(ctx context.Context, r cloudformation.ResourceRequest) (*api.KeyMetadata, error) {
	id, err := cfnKMSIdentifier(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.DescribeKeyOutput](cfnKMSKeyContext(ctx, r), h.commands, "kms", "DescribeKey", map[string]any{"KeyId": id})
	if err != nil {
		return nil, err
	}
	key := out.KeyMetadata
	if key == nil || key.MultiRegionConfiguration == nil || cfnComputeValue(key.MultiRegionConfiguration.MultiRegionKeyType) != "REPLICA" {
		return nil, &awswire.Error{Code: "NotFoundException", Message: "The key is not a multi-Region replica", StatusCode: 400}
	}
	return key, nil
}

func (h cfnKMSReplicaKey) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if replace {
		return cloudformation.ResourceResult{}, fmt.Errorf("changing PrimaryKeyArn requires replacement")
	}
	if _, err := h.describe(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return (cfnKMSKey(h)).Update(ctx, cfnKMSReplicaRequest(r))
}

func (h cfnKMSReplicaKey) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := h.ValidateDeletionPolicy(r.DeletionPolicy); err != nil {
		return err
	}
	if _, err := h.describe(ctx, r); err != nil {
		return cfnKMSAbsent(err)
	}
	return (cfnKMSKey(h)).Delete(ctx, r)
}

func (h cfnKMSReplicaKey) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	key, err := h.describe(ctx, r)
	if err != nil {
		return false, err
	}
	switch state := cfnComputeValue(key.KeyState); state {
	case "Creating", "Updating":
		return false, nil
	case "Enabled", "Disabled", "PendingImport":
		// ReplicateKey creates an enabled key (or a key awaiting imported
		// material). Creation only disables when requested; it does not enable
		// a recovered key or fabricate material for PendingImport.
		if cfnComputeDefault(r.Properties, "Enabled", true) == false && state != "Disabled" {
			if err := cfnComputeRun(cfnKMSKeyContext(ctx, r), h.commands, "kms", "DisableKey", map[string]any{"KeyId": r.PhysicalID}); err != nil {
				return false, err
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("KMS replica cannot stabilize in state %s", state)
	}
}

func (h cfnKMSReplicaKey) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	key, err := h.describe(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}, err
	}
	return cfnKMSMetadataResult(key), nil
}

func (h cfnKMSReplicaKey) ValidateDeletionPolicy(policy string) error {
	return (cfnKMSKey{}).ValidateDeletionPolicy(policy)
}

func (h cfnKMSKey) ValidateDeletionPolicy(policy string) error {
	if policy == "Snapshot" {
		return fmt.Errorf("KMS keys do not support Snapshot deletion")
	}
	return nil
}
