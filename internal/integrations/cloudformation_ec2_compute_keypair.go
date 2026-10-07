package integrations

import (
	"context"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	ec2 "stackd/internal/services/ec2"
)

type cfnEC2KeyPair struct{ commands StepFunctionsCommands }

func (h cfnEC2KeyPair) Validate(p cloudformation.Properties) error {
	if err := cfnEC2ComputeValidate(p, "KeyName", "KeyType", "KeyFormat", "PublicKeyMaterial", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "KeyName"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "KeyName", "KeyType", "KeyFormat", "PublicKeyMaterial"); err != nil {
		return err
	}
	if cfnComputeString(p, "KeyName") == "" {
		return fmt.Errorf("KeyName must not be empty")
	}
	return nil
}
func (h cfnEC2KeyPair) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "KeyName", "KeyType", "KeyFormat", "PublicKeyMaterial", "Tags"), nil
}
func (h cfnEC2KeyPair) pairs(ctx context.Context, in map[string]any) ([]api.KeyPairInfo, error) {
	in["IncludePublicKey"] = true
	out, err := cfnComputeCall[api.DescribeKeyPairsResult](ctx, h.commands, "ec2", "DescribeKeyPairs", in)
	if err != nil {
		return nil, err
	}
	return out.KeyPairs, nil
}
func (h cfnEC2KeyPair) get(ctx context.Context, name string) (api.KeyPairInfo, error) {
	rows, err := h.pairs(ctx, map[string]any{"KeyNames": []string{name}})
	// The official additional identifier is KeyPairId. Resolve the primary
	// KeyName first, then the alternate ID without conflating a missing ID
	// with the native DescribeKeyPairs validation error for explicit ID lists.
	if cfnEC2Missing(err) && strings.HasPrefix(name, "key-") {
		rows, err = h.pairs(ctx, map[string]any{"Filters": []map[string]any{{"Name": "key-pair-id", "Values": []string{name}}}})
	}
	if err != nil {
		return api.KeyPairInfo{}, err
	}
	if len(rows) != 1 {
		return api.KeyPairInfo{}, cfnEC2ComputeMissing("key pair", name)
	}
	return rows[0], nil
}
func (h cfnEC2KeyPair) getID(ctx context.Context, id string) (api.KeyPairInfo, error) {
	rows, err := h.pairs(ctx, map[string]any{"KeyPairIds": []string{id}})
	if err != nil {
		return api.KeyPairInfo{}, err
	}
	if len(rows) != 1 || cfnComputeValue(rows[0].KeyPairId) != id {
		return api.KeyPairInfo{}, cfnEC2ComputeMissing("key pair", id)
	}
	return rows[0], nil
}
func cfnEC2KeyPairResult(v api.KeyPairInfo) cloudformation.ResourceResult {
	name := cfnComputeValue(v.KeyName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"KeyPairId": cfnComputeValue(v.KeyPairId), "KeyFingerprint": cfnComputeValue(v.KeyFingerprint)}}
}
func (h cfnEC2KeyPair) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "KeyName")
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if id != "" {
		return h.RecoverCreation(ctx, r)
	}
	in := cfnComputeCopy(r.Properties, "KeyName", "KeyType", "KeyFormat")
	in["TagSpecifications"] = cfnEC2NetworkTagSpecifications(r, "key-pair")
	creationCtx := cfnEC2NativeContext(ctx, r, "create")
	if material, found := r.Properties["PublicKeyMaterial"]; found {
		delete(in, "KeyType")
		delete(in, "KeyFormat")
		// The SDK command bridge binds blobs from UTF-8 text; only the EC2
		// Query transport base64-encodes PublicKeyMaterial.
		in["PublicKeyMaterial"] = material.(string)
		if _, err := cfnComputeCall[api.ImportKeyPairResult](creationCtx, h.commands, "ec2", "ImportKeyPair", in); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	} else {
		// Key and encrypted private parameter commit together through the owner
		// transaction. A failed persistence never leaves a generated orphan key.
		creationCtx = ec2.WithKeyPairMaterialSink(creationCtx, func(txctx context.Context, pair *api.KeyPair) error {
			id := cfnComputeValue(pair.KeyPairId)
			private := cfnComputeValue(pair.KeyMaterial)
			if id == "" || private == "" {
				return fmt.Errorf("CreateKeyPair returned no key identity or private material")
			}
			return cfnComputeRun(txctx, h.commands, "ssm", "PutParameter", map[string]any{"Name": "/ec2/keypair/" + id, "Value": private, "Type": "SecureString", "Tier": "Standard", "Overwrite": false})
		})
		if _, err := cfnComputeCall[api.KeyPair](creationCtx, h.commands, "ec2", "CreateKeyPair", in); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	v, err := h.get(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEC2KeyPairResult(v), cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.KeyPairId))
}
func (h cfnEC2KeyPair) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if changed, _ := h.Replacement(r.Previous, r.Properties); changed {
		return cloudformation.ResourceResult{}, fmt.Errorf("key pair updates require replacement")
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEC2KeyPairResult(v), cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.KeyPairId))
}
func (h cfnEC2KeyPair) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.get(ctx, r.PhysicalID)
	if cfnEC2Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.KeyPairId)); err != nil {
		return err
	}
	// The trusted sink joins the native delete transaction after current IAM
	// and the exact key mutation fence. Either both rows commit or neither does.
	ctx = ec2.WithKeyPairDeletionSink(ctx, func(txctx context.Context, id string) error { return h.deletePrivateParameter(txctx, r, id) })
	err = cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", cfnComputeValue(v.KeyPairId)), h.commands, "ec2", "DeleteKeyPair", map[string]any{"KeyPairId": cfnComputeValue(v.KeyPairId)})
	if cfnEC2Missing(err) {
		return nil
	}
	return err
}
func cfnEC2KeyPairProjection(v api.KeyPairInfo) cloudformation.Properties {
	p := cloudformation.Properties{"KeyName": cfnComputeValue(v.KeyName), "KeyType": cfnComputeValue(v.KeyType), "KeyPairId": cfnComputeValue(v.KeyPairId), "KeyFingerprint": cfnComputeValue(v.KeyFingerprint), "Tags": cfnEC2ComputePublicTags(v.Tags)}
	if v.PublicKey != nil {
		p["PublicKeyMaterial"] = cfnComputeValue(v.PublicKey)
	}
	return p
}
func (h cfnEC2KeyPair) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	var v api.KeyPairInfo
	var err error
	if r.CloudControl {
		v, err = h.get(ctx, r.PhysicalID)
	} else {
		// Stack reads resolve the immutable scoped admission, not a same-name
		// native replacement. The public physical identifier remains KeyName.
		var id string
		id, err = cfnEC2NativeRecover(ctx, h.commands, r)
		if err == nil && id == "" {
			err = cfnEC2NotFound(r.Type)
		}
		if err == nil {
			v, err = h.getID(ctx, id)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.KeyPairId)); err != nil {
		return nil, err
	}
	return cfnEC2KeyPairProjection(v), nil
}
func (h cfnEC2KeyPair) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := h.pairs(ctx, map[string]any{})
	if err != nil {
		return nil, err
	}
	out := []cloudformation.ResourceDescription{}
	for _, v := range rows {
		if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.KeyPairId)); err != nil {
			continue
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: cfnComputeValue(v.KeyName), Properties: cfnEC2KeyPairProjection(v)})
	}
	return out, nil
}
func (h cfnEC2KeyPair) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.KeyPairId)); err != nil {
		return false, err
	}
	if r.Properties["PublicKeyMaterial"] == nil {
		if err := h.privateAvailable(ctx, cfnComputeValue(v.KeyPairId)); err != nil {
			return false, err
		}
	}
	return true, nil
}
func (h cfnEC2KeyPair) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if cfnEC2Missing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.KeyPairId))
}
func (h cfnEC2KeyPair) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if id == "" {
		return cloudformation.ResourceResult{}, cfnEC2NotFound(r.Type)
	}
	v, err := h.getID(ctx, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, id); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if r.Properties["PublicKeyMaterial"] == nil {
		if err := h.privateAvailable(ctx, id); err != nil {
			return cfnEC2KeyPairResult(v), err
		}
	}
	return cfnEC2KeyPairResult(v), nil
}
