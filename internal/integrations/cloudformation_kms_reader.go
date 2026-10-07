package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	api "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

func cfnKMSMetadataResult(key *api.KeyMetadata) cloudformation.ResourceResult {
	if key == nil {
		return cloudformation.ResourceResult{}
	}
	id := cfnComputeValue(key.KeyId)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": cfnComputeValue(key.Arn), "KeyId": id}}
}

func cfnKMSPendingDeletion(key *api.KeyMetadata) bool {
	state := cfnComputeValue(key.KeyState)
	return state == "PendingDeletion" || state == "PendingReplicaDeletion"
}

func cfnKMSMetadataProperties(key *api.KeyMetadata, replica bool) cloudformation.Properties {
	p := cloudformation.Properties{"KeyId": cfnComputeValue(key.KeyId), "Arn": cfnComputeValue(key.Arn), "Description": cfnComputeValue(key.Description), "Enabled": key.Enabled != nil && bool(*key.Enabled)}
	if replica {
		p["PrimaryKeyArn"] = cfnComputeValue(key.MultiRegionConfiguration.PrimaryKey.Arn)
	} else {
		p["KeySpec"], p["KeyUsage"], p["Origin"] = cfnComputeValue(key.KeySpec), cfnComputeValue(key.KeyUsage), cfnComputeValue(key.Origin)
		p["MultiRegion"] = key.MultiRegion != nil && bool(*key.MultiRegion)
	}
	return p
}

func (h cfnKMSKey) readProperties(ctx context.Context, r cloudformation.ResourceRequest, key *api.KeyMetadata, replica bool) (cloudformation.Properties, error) {
	ctx = cfnKMSKeyContext(ctx, r)
	id := cfnComputeValue(key.KeyId)
	out, err := cfnComputeCall[api.GetKeyPolicyOutput](ctx, h.commands, "kms", "GetKeyPolicy", map[string]any{"KeyId": id, "PolicyName": "default"})
	if err != nil {
		return nil, err
	}
	var policy map[string]any
	if err := json.Unmarshal([]byte(cfnComputeValue(out.Policy)), &policy); err != nil {
		return nil, fmt.Errorf("KMS returned an invalid key policy: %w", err)
	}
	tags, err := h.tags(ctx, id)
	if err != nil {
		return nil, err
	}
	p := cfnKMSMetadataProperties(key, replica)
	p["KeyPolicy"], p["Tags"] = policy, cfnResourcePublicTags(tags)
	if !replica {
		rotation, err := cfnComputeCall[api.GetKeyRotationStatusOutput](ctx, h.commands, "kms", "GetKeyRotationStatus", map[string]any{"KeyId": id})
		if err != nil {
			return nil, err
		}
		p["EnableKeyRotation"] = rotation.KeyRotationEnabled != nil && bool(*rotation.KeyRotationEnabled)
	}
	// PendingWindowInDays is write-only. The current policy and enabled state
	// come from KMS, never from the stack's retained template properties.
	return p, nil
}

func (h cfnKMSKey) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	id, err := cfnKMSIdentifier(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.DescribeKeyOutput](cfnKMSKeyContext(ctx, r), h.commands, "kms", "DescribeKey", map[string]any{"KeyId": id})
	if err != nil {
		return nil, err
	}
	if out.KeyMetadata == nil || cfnKMSPendingDeletion(out.KeyMetadata) {
		return nil, &awswire.Error{Code: "NotFoundException", Message: "The KMS key is absent or scheduled for deletion", StatusCode: 400}
	}
	return h.readProperties(ctx, r, out.KeyMetadata, false)
}

func (h cfnKMSReplicaKey) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	key, err := h.describe(ctx, r)
	if err != nil {
		return nil, err
	}
	if cfnKMSPendingDeletion(key) {
		return nil, &awswire.Error{Code: "NotFoundException", Message: "The KMS replica is scheduled for deletion", StatusCode: 400}
	}
	return (cfnKMSKey(h)).readProperties(ctx, r, key, true)
}

func (h cfnKMSKey) list(ctx context.Context, r cloudformation.ResourceRequest, replicas bool) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListKeysOutput](ctx, h.commands, "kms", "ListKeys", input)
		if err != nil {
			return nil, err
		}
		for _, entry := range out.Keys {
			id := cfnComputeValue(entry.KeyId)
			key, err := cfnComputeCall[api.DescribeKeyOutput](ctx, h.commands, "kms", "DescribeKey", map[string]any{"KeyId": id})
			if err != nil {
				return nil, err
			}
			metadata := key.KeyMetadata
			if metadata == nil || cfnKMSPendingDeletion(metadata) {
				continue
			}
			isReplica := metadata.MultiRegionConfiguration != nil && cfnComputeValue(metadata.MultiRegionConfiguration.MultiRegionKeyType) == "REPLICA"
			if replicas != isReplica {
				continue
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: id, Properties: cfnKMSMetadataProperties(metadata, replicas)})
		}
		if marker := cfnComputeValue(out.NextMarker); marker != "" {
			input["Marker"] = marker
		} else {
			break
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Identifier < rows[j].Identifier })
	return rows, nil
}

func (h cfnKMSKey) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return h.list(ctx, r, false)
}

func (h cfnKMSReplicaKey) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return (cfnKMSKey(h)).list(ctx, r, true)
}

func (h cfnKMSKey) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnKMSIdentifier(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(cfnKMSKeyContext(ctx, r), id)
}

func cfnKMSAliasIdentifier(ctx context.Context, id string) (string, error) {
	if strings.HasPrefix(id, "arn:") {
		parts := strings.SplitN(id, ":", 6)
		m := awsctx.FromContext(ctx)
		if len(parts) != 6 || parts[1] != m.Partition || parts[2] != "kms" || parts[3] != m.Region || parts[4] != m.AccountID {
			return "", &awswire.Error{Code: "NotFoundException", Message: "KMS alias is outside the resource account, Region, or partition", StatusCode: 400}
		}
		id = parts[5]
	}
	if !strings.HasPrefix(id, "alias/") {
		return "", &awswire.Error{Code: "NotFoundException", Message: "Invalid KMS alias identifier", StatusCode: 400}
	}
	return id, nil
}

func (h cfnKMSAlias) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	ctx = cfnKMSAliasContext(ctx, r)
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListAliasesOutput](ctx, h.commands, "kms", "ListAliases", input)
		if err != nil {
			return nil, err
		}
		for _, alias := range out.Aliases {
			name, target := cfnComputeValue(alias.AliasName), cfnComputeValue(alias.TargetKeyId)
			rows = append(rows, cloudformation.ResourceDescription{Identifier: name, Properties: cloudformation.Properties{"AliasName": name, "TargetKeyId": target}})
		}
		if marker := cfnComputeValue(out.NextMarker); marker != "" {
			input["Marker"] = marker
		} else {
			break
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Identifier < rows[j].Identifier })
	return rows, nil
}

func (h cfnKMSAlias) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, err := cfnKMSAliasIdentifier(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	rows, err := h.List(ctx, r)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Identifier == name {
			return row.Properties, nil
		}
	}
	return nil, &awswire.Error{Code: "NotFoundException", Message: "KMS alias does not exist in this scope or resource incarnation", StatusCode: 400}
}

func (h cfnKMSAlias) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(p, "AliasName")
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name}, nil
}
