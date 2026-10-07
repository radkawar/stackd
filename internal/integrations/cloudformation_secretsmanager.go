package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	docdbapi "stackd/internal/awsapi/docdb"
	rdsapi "stackd/internal/awsapi/rds"
	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/secretsmanager"
)

// Secrets Manager: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_SecretsManager.html
// Secret values are written only through the owner's encrypted versions;
// generated passwords come from the owner's GetRandomPassword command.

func cfnSecretMissing(err error) bool {
	return cfnMessagingMissing(err, "ResourceNotFoundException")
}

func cfnSecretDescribe(ctx context.Context, c StepFunctionsCommands, id string) (*api.DescribeSecretOutput, map[string]string, error) {
	out, err := cfnComputeCall[api.DescribeSecretOutput](ctx, c, "secretsmanager", "DescribeSecret", map[string]any{"SecretId": id})
	if err != nil {
		return nil, nil, err
	}
	if out.DeletedDate != nil {
		return nil, nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "The secret is scheduled for deletion.", StatusCode: 400}
	}
	tags := make(map[string]string, len(out.Tags))
	for _, t := range out.Tags {
		tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return out, tags, nil
}

func cfnSecretTagger(c StepFunctionsCommands, arn string) cfnAppTagged {
	return cfnAppTagged{
		list: func(ctx context.Context) (map[string]string, error) {
			_, tags, err := cfnSecretDescribe(ctx, c, arn)
			return tags, err
		},
		tag: func(ctx context.Context, tags map[string]string) error {
			return cfnComputeRun(ctx, c, "secretsmanager", "TagResource", map[string]any{"SecretId": arn, "Tags": cfnComputeTagList(tags)})
		},
		untag: func(ctx context.Context, keys []string) error {
			return cfnComputeRun(ctx, c, "secretsmanager", "UntagResource", map[string]any{"SecretId": arn, "TagKeys": keys})
		},
	}
}

func cfnSecretResult(arn string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"Id": arn}}
}

func cfnSecretList(ctx context.Context, c StepFunctionsCommands) ([]api.SecretListEntry, error) {
	var rows []api.SecretListEntry
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListSecretsOutput](ctx, c, "secretsmanager", "ListSecrets", in)
		if err != nil {
			return nil, err
		}
		rows = append(rows, out.SecretList...)
		next := cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
		if next == in["NextToken"] {
			return nil, fmt.Errorf("secrets Manager pagination did not advance")
		}
		in["NextToken"] = next
	}
}

// cfnSecretToken is a deterministic owner version token for one incarnation.
func cfnSecretToken(r cloudformation.ResourceRequest, purpose string) string {
	return cfnMessagingHash(r.StackID + "\x00" + r.LogicalID + "\x00" + r.Token + "\x00" + purpose)
}

type cfnSecret struct{ commands StepFunctionsCommands }

var cfnSecretGenerateBooleans = []string{"ExcludeUppercase", "ExcludeLowercase", "ExcludeNumbers", "ExcludePunctuation", "IncludeSpace", "RequireEachIncludedType"}

func (h cfnSecret) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "KmsKeyId", "SecretString", "GenerateSecretString", "ReplicaRegions", "Tags", "Type"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Description", "KmsKeyId", "SecretString", "Type"); err != nil {
		return err
	}
	if p["SecretString"] != nil && p["GenerateSecretString"] != nil {
		return fmt.Errorf("specify either SecretString or GenerateSecretString, not both")
	}
	if _, _, err := cfnSecretGenerator(p); err != nil {
		return err
	}
	if _, err := cfnSecretReplicas(p); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnSecret) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}

// cfnSecretGenerator splits GenerateSecretString into the owner's
// GetRandomPassword input and the optional JSON template placement.
func cfnSecretGenerator(p cloudformation.Properties) (map[string]any, map[string]any, error) {
	v, ok := p["GenerateSecretString"]
	if !ok {
		return nil, nil, nil
	}
	g, ok := cfnComputeObject(v)
	if !ok {
		return nil, nil, fmt.Errorf("GenerateSecretString must be an object")
	}
	if err := cfnComputeProperties(g, append([]string{"ExcludeCharacters", "GenerateStringKey", "PasswordLength", "SecretStringTemplate"}, cfnSecretGenerateBooleans...)...); err != nil {
		return nil, nil, err
	}
	if err := cfnComputeStrings(g, "ExcludeCharacters", "GenerateStringKey", "SecretStringTemplate"); err != nil {
		return nil, nil, err
	}
	in := cfnComputeCopy(g, "ExcludeCharacters")
	if err := cfnAppNumbers(in, g, []string{"PasswordLength"}, nil); err != nil {
		return nil, nil, err
	}
	for _, key := range cfnSecretGenerateBooleans {
		if b, present, err := cfnAppBoolean(g, key); err != nil {
			return nil, nil, err
		} else if present {
			in[key] = b
		}
	}
	key, template := cfnComputeString(g, "GenerateStringKey"), cfnComputeString(g, "SecretStringTemplate")
	if (key == "") != (template == "") {
		return nil, nil, fmt.Errorf("GenerateStringKey and SecretStringTemplate must be specified together")
	}
	if key == "" {
		return in, nil, nil
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(template), &document); err != nil || document == nil {
		return nil, nil, fmt.Errorf("SecretStringTemplate must be a JSON object")
	}
	return in, map[string]any{"key": key, "document": document}, nil
}

func cfnSecretReplicas(p cloudformation.Properties) (map[string]string, error) {
	out := map[string]string{}
	v, ok := p["ReplicaRegions"]
	if !ok {
		return out, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("ReplicaRegions must be a list")
	}
	for _, item := range list {
		replica, ok := cfnComputeObject(item)
		if !ok {
			return nil, fmt.Errorf("ReplicaRegions entries must be objects")
		}
		if err := cfnComputeProperties(replica, "Region", "KmsKeyId"); err != nil {
			return nil, err
		}
		if err := cfnComputeRequired(replica, "Region"); err != nil {
			return nil, err
		}
		if err := cfnComputeStrings(replica, "Region", "KmsKeyId"); err != nil {
			return nil, err
		}
		region := cfnComputeString(replica, "Region")
		if _, duplicate := out[region]; duplicate {
			return nil, fmt.Errorf("duplicate replica region %s", region)
		}
		out[region] = cfnComputeString(replica, "KmsKeyId")
	}
	return out, nil
}

func cfnSecretReplicaInput(replicas map[string]string, regions []string) []any {
	out := make([]any, 0, len(regions))
	for _, region := range regions {
		item := map[string]any{"Region": region}
		if key := replicas[region]; key != "" {
			item["KmsKeyId"] = key
		}
		out = append(out, item)
	}
	return out
}

// value produces the desired SecretString, generating passwords through the
// owner. It reports false for an intentionally empty secret.
func (h cfnSecret) value(ctx context.Context, p cloudformation.Properties) (string, bool, error) {
	if v, ok := p["SecretString"].(string); ok {
		return v, true, nil
	}
	in, template, err := cfnSecretGenerator(p)
	if err != nil || in == nil {
		return "", false, err
	}
	out, err := cfnComputeCall[api.GetRandomPasswordOutput](ctx, h.commands, "secretsmanager", "GetRandomPassword", in)
	if err != nil {
		return "", false, err
	}
	password := cfnComputeValue(out.RandomPassword)
	if template == nil {
		return password, true, nil
	}
	document := maps.Clone(template["document"].(map[string]any))
	document[template["key"].(string)] = password
	body, err := json.Marshal(document)
	return string(body), true, err
}

func (h cfnSecret) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnSecretOwnerContext(ctx, r, "secret", true, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 256)
	existing, _, err := cfnSecretDescribe(ctx, h.commands, name)
	if err == nil {
		return cfnSecretResult(cfnComputeValue(existing.ARN)), nil
	}
	if !cfnSecretMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "Description", "KmsKeyId", "Type")
	in["Name"], in["Tags"] = name, cfnComputeTagList(cfnAppCustomerTags(r))
	secret, present, err := h.value(ctx, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if present {
		in["SecretString"], in["ClientRequestToken"] = secret, cfnSecretToken(r, "create")
	}
	if replicas, _ := cfnSecretReplicas(r.Properties); len(replicas) > 0 {
		in["AddReplicaRegions"] = cfnSecretReplicaInput(replicas, cfnMessagingKeys(replicas))
	}
	out, err := cfnComputeCall[api.CreateSecretOutput](ctx, h.commands, "secretsmanager", "CreateSecret", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnSecretResult(cfnComputeValue(out.ARN)), nil
}

func (h cfnSecret) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnSecretOwnerContext(ctx, r, "secret", false, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	current, tags, err := cfnSecretDescribe(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnSecretResult(r.PhysicalID)
	in := map[string]any{"SecretId": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", "")}
	if cfnComputeChanged(r.Previous, r.Properties, "KmsKeyId") {
		// The owner's default key is the empty configuration (aws/secretsmanager).
		in["KmsKeyId"] = cfnComputeDefault(r.Properties, "KmsKeyId", "")
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Type") {
		in["Type"] = cfnComputeDefault(r.Properties, "Type", "")
	}
	if cfnComputeChanged(r.Previous, r.Properties, "SecretString", "GenerateSecretString") {
		secret, present, err := h.value(ctx, r.Properties)
		if err != nil {
			return result, err
		}
		if present {
			in["SecretString"] = secret
		}
	}
	if err := cfnComputeRun(ctx, h.commands, "secretsmanager", "UpdateSecret", in); err != nil {
		return result, err
	}
	if err := h.replicate(ctx, r, current); err != nil {
		return result, err
	}
	t := cfnSecretTagger(h.commands, r.PhysicalID)
	return result, cfnAppTagSync(ctx, tags, cfnAppCustomerTags(r), t.tag, t.untag)
}

// replicate reconciles replica regions; a changed replica key is a removal
// followed by a new replica, as the owner keeps a replica's key fixed.
func (h cfnSecret) replicate(ctx context.Context, r cloudformation.ResourceRequest, current *api.DescribeSecretOutput) error {
	desired, _ := cfnSecretReplicas(r.Properties)
	existing := map[string]string{}
	for _, s := range current.ReplicationStatus {
		existing[cfnComputeValue(s.Region)] = cfnComputeValue(s.KmsKeyId)
	}
	var remove, add []string
	for _, region := range cfnMessagingKeys(existing) {
		key, keep := desired[region]
		if !keep || key != "" && key != existing[region] {
			remove = append(remove, region)
		}
	}
	for _, region := range cfnMessagingKeys(desired) {
		if _, ok := existing[region]; !ok || slices.Contains(remove, region) {
			add = append(add, region)
		}
	}
	if len(remove) > 0 {
		if err := cfnComputeRun(ctx, h.commands, "secretsmanager", "RemoveRegionsFromReplication", map[string]any{"SecretId": r.PhysicalID, "RemoveReplicaRegions": remove}); err != nil {
			return err
		}
	}
	if len(add) > 0 {
		return cfnComputeRun(ctx, h.commands, "secretsmanager", "ReplicateSecretToRegions", map[string]any{"SecretId": r.PhysicalID, "AddReplicaRegions": cfnSecretReplicaInput(desired, add)})
	}
	return nil
}

// Stabilize waits for the owner's asynchronous replication to finish.
func (h cfnSecret) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnSecretOwnerContext(ctx, r, "secret", false, false)
	current, _, err := cfnSecretDescribe(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return false, err
	}
	desired, _ := cfnSecretReplicas(r.Properties)
	synced := 0
	for _, s := range current.ReplicationStatus {
		region := cfnComputeValue(s.Region)
		if _, ok := desired[region]; !ok {
			continue
		}
		switch cfnComputeValue(s.Status) {
		case "InSync":
			synced++
		case "Failed":
			return false, fmt.Errorf("replication of %s to %s failed: %s", r.PhysicalID, region, cfnComputeValue(s.StatusMessage))
		}
	}
	return synced == len(desired), nil
}

// Delete removes replicas, then deletes the secret without a recovery window,
// as CloudFormation does for AWS::SecretsManager::Secret.
func (h cfnSecret) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnSecretOwnerContext(ctx, r, "secret", false, false)
	current, _, err := cfnSecretDescribe(ctx, h.commands, r.PhysicalID)
	if cfnSecretMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(current.ReplicationStatus) > 0 {
		regions := make([]string, 0, len(current.ReplicationStatus))
		for _, s := range current.ReplicationStatus {
			regions = append(regions, cfnComputeValue(s.Region))
		}
		if err := cfnComputeRun(ctx, h.commands, "secretsmanager", "RemoveRegionsFromReplication", map[string]any{"SecretId": r.PhysicalID, "RemoveReplicaRegions": regions}); err != nil && !cfnSecretMissing(err) {
			return err
		}
	}
	err = cfnComputeRun(ctx, h.commands, "secretsmanager", "DeleteSecret", map[string]any{"SecretId": r.PhysicalID, "ForceDeleteWithoutRecovery": true})
	if cfnSecretMissing(err) {
		return nil
	}
	return err
}

func cfnSecretProperties(arn string, name, description, key *string, kind string, replicas []api.ReplicationStatusType, tags map[string]string) cloudformation.Properties {
	p := cloudformation.Properties{"Id": arn, "Tags": cfnAppUserTags(tags)}
	if name != nil {
		p["Name"] = *name
	}
	if description != nil {
		p["Description"] = *description
	}
	if key != nil && *key != "" {
		p["KmsKeyId"] = *key
	}
	if kind != "" {
		p["Type"] = kind
	}
	if len(replicas) > 0 {
		list := make([]any, 0, len(replicas))
		for _, s := range replicas {
			item := map[string]any{"Region": cfnComputeValue(s.Region)}
			if s.KmsKeyId != nil {
				item["KmsKeyId"] = cfnComputeValue(s.KmsKeyId)
			}
			list = append(list, item)
		}
		p["ReplicaRegions"] = list
	}
	return p
}

func (h cfnSecret) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	s, tags, err := cfnSecretDescribe(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return cfnSecretProperties(cfnComputeValue(s.ARN), (*string)(s.Name), (*string)(s.Description), (*string)(s.KmsKeyId), cfnComputeValue(s.Type), s.ReplicationStatus, tags), nil
}

func (h cfnSecret) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := cfnSecretList(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(rows))
	for _, s := range rows {
		if s.DeletedDate != nil || s.OwningService != nil {
			continue
		}
		arn := cfnComputeValue(s.ARN)
		out = append(out, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"Id": arn, "Name": cfnComputeValue(s.Name)}})
	}
	return out, nil
}

// Each aspect has an independent private claim committed by the native owner
// in the same transaction as its policy, rotation schedule or attachment write.
type cfnSecretAspect struct {
	commands StepFunctionsCommands
	kind     string
}

func (a cfnSecretAspect) create(ctx context.Context, r cloudformation.ResourceRequest, effect func(context.Context, string) error) (cloudformation.ResourceResult, error) {
	secret, _, err := cfnSecretDescribe(ctx, a.commands, cfnComputeString(r.Properties, "SecretId"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnComputeValue(secret.ARN)
	ownedContext := cfnSecretOwnerContext(ctx, r, a.kind, true, false)
	if err := effect(ownedContext, arn); err != nil {
		// A lost admitted reply still returns the real edge identity, whereas
		// rejected admission cannot borrow the preexisting parent secret's ID.
		_, _, observation := cfnSecretDescribe(cfnSecretOwnerContext(ctx, r, a.kind, true, false), a.commands, arn)
		if observation == nil {
			return cfnSecretResult(arn), err
		}
		return cloudformation.ResourceResult{}, err
	}
	return cfnSecretResult(arn), nil
}

func (a cfnSecretAspect) update(ctx context.Context, r cloudformation.ResourceRequest, effect func(context.Context, string) error) (cloudformation.ResourceResult, error) {
	ctx = cfnSecretOwnerContext(ctx, r, a.kind, false, false)
	return cfnSecretResult(r.PhysicalID), effect(ctx, r.PhysicalID)
}

func (a cfnSecretAspect) remove(ctx context.Context, r cloudformation.ResourceRequest, effect func(context.Context, string) error) error {
	ctx = cfnSecretOwnerContext(ctx, r, a.kind, false, true)
	_, _, err := cfnSecretDescribe(ctx, a.commands, r.PhysicalID)
	if cfnSecretMissing(err) || secretsmanager.IsCloudFormationOwnershipMismatch(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = effect(ctx, r.PhysicalID)
	if cfnSecretMissing(err) {
		return nil
	}
	return err
}

func cfnSecretAspectList(ctx context.Context, c StepFunctionsCommands, include func(api.SecretListEntry) (bool, error)) ([]cloudformation.ResourceDescription, error) {
	rows, err := cfnSecretList(ctx, c)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, s := range rows {
		if s.DeletedDate != nil {
			continue
		}
		ok, err := include(s)
		if err != nil {
			return nil, err
		}
		if ok {
			arn := cfnComputeValue(s.ARN)
			out = append(out, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"Id": arn, "SecretId": arn}})
		}
	}
	return out, nil
}

type cfnSecretPolicy struct{ commands StepFunctionsCommands }

func (h cfnSecretPolicy) aspect() cfnSecretAspect {
	return cfnSecretAspect{h.commands, "policy"}
}

func (h cfnSecretPolicy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "SecretId", "ResourcePolicy", "BlockPublicPolicy"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "SecretId", "ResourcePolicy"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "SecretId"); err != nil {
		return err
	}
	if _, err := cfnComputeDocument(p["ResourcePolicy"]); err != nil {
		return fmt.Errorf("ResourcePolicy: %w", err)
	}
	_, _, err := cfnAppBoolean(p, "BlockPublicPolicy")
	return err
}
func (h cfnSecretPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "SecretId"), h.Validate(b)
}

func (h cfnSecretPolicy) put(r cloudformation.ResourceRequest) func(context.Context, string) error {
	return func(ctx context.Context, arn string) error {
		policy, err := cfnComputeDocument(r.Properties["ResourcePolicy"])
		if err != nil {
			return err
		}
		in := map[string]any{"SecretId": arn, "ResourcePolicy": policy}
		if block, present, _ := cfnAppBoolean(r.Properties, "BlockPublicPolicy"); present {
			in["BlockPublicPolicy"] = block
		}
		return cfnComputeRun(ctx, h.commands, "secretsmanager", "PutResourcePolicy", in)
	}
}

func (h cfnSecretPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.aspect().create(ctx, r, h.put(r))
}

func (h cfnSecretPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.aspect().update(ctx, r, h.put(r))
}

func (h cfnSecretPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return h.aspect().remove(ctx, r, func(ctx context.Context, arn string) error {
		return cfnComputeRun(ctx, h.commands, "secretsmanager", "DeleteResourcePolicy", map[string]any{"SecretId": arn})
	})
}

func (h cfnSecretPolicy) policy(ctx context.Context, arn string) (string, error) {
	out, err := cfnComputeCall[api.GetResourcePolicyOutput](ctx, h.commands, "secretsmanager", "GetResourcePolicy", map[string]any{"SecretId": arn})
	if err != nil {
		return "", err
	}
	return cfnComputeValue(out.ResourcePolicy), nil
}

func (h cfnSecretPolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	policy, err := h.policy(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if policy == "" {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "The secret has no resource policy.", StatusCode: 400}
	}
	var document any
	if err := json.Unmarshal([]byte(policy), &document); err != nil {
		return nil, fmt.Errorf("invalid owner resource policy: %w", err)
	}
	return cloudformation.Properties{"Id": r.PhysicalID, "SecretId": r.PhysicalID, "ResourcePolicy": document}, nil
}

func (h cfnSecretPolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return cfnSecretAspectList(ctx, h.commands, func(s api.SecretListEntry) (bool, error) {
		policy, err := h.policy(ctx, cfnComputeValue(s.ARN))
		return policy != "", err
	})
}

// cfnSecretRotation configures Lambda rotation through the owner's
// RotateSecret command, which invokes the rotation function.
type cfnSecretRotation struct{ commands StepFunctionsCommands }

func (h cfnSecretRotation) aspect() cfnSecretAspect {
	return cfnSecretAspect{h.commands, "rotation"}
}

func (h cfnSecretRotation) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "SecretId", "RotationLambdaARN", "RotationRules", "RotateImmediatelyOnUpdate", "HostedRotationLambda", "ExternalSecretRotationMetadata", "ExternalSecretRotationRoleArn"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "SecretId"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "SecretId", "RotationLambdaARN", "ExternalSecretRotationRoleArn"); err != nil {
		return err
	}
	if p["HostedRotationLambda"] != nil {
		// The hosted function is created by the AWS::SecretsManager-2020-07-23
		// transform, which expands it into RotationLambdaARN before this resource.
		return fmt.Errorf("HostedRotationLambda requires the AWS::SecretsManager-2020-07-23 transform, which is not supported; specify RotationLambdaARN")
	}
	if _, _, err := cfnAppBoolean(p, "RotateImmediatelyOnUpdate"); err != nil {
		return err
	}
	_, err := cfnSecretRotationRules(p)
	return err
}
func (h cfnSecretRotation) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "SecretId"), h.Validate(b)
}

func cfnSecretRotationRules(p cloudformation.Properties) (map[string]any, error) {
	v, ok := p["RotationRules"]
	if !ok {
		return nil, nil
	}
	rules, ok := cfnComputeObject(v)
	if !ok {
		return nil, fmt.Errorf("RotationRules must be an object")
	}
	if err := cfnComputeProperties(rules, "AutomaticallyAfterDays", "Duration", "ScheduleExpression"); err != nil {
		return nil, err
	}
	if err := cfnComputeStrings(rules, "Duration", "ScheduleExpression"); err != nil {
		return nil, err
	}
	out := cfnComputeCopy(rules, "Duration", "ScheduleExpression")
	if err := cfnAppNumbers(out, rules, []string{"AutomaticallyAfterDays"}, nil); err != nil {
		return nil, err
	}
	return out, nil
}

func (h cfnSecretRotation) rotate(r cloudformation.ResourceRequest, immediately bool, token string) func(context.Context, string) error {
	return func(ctx context.Context, arn string) error {
		in := cfnComputeCopy(r.Properties, "RotationLambdaARN", "ExternalSecretRotationMetadata", "ExternalSecretRotationRoleArn")
		in["SecretId"], in["RotateImmediately"] = arn, immediately
		if rules, _ := cfnSecretRotationRules(r.Properties); rules != nil {
			in["RotationRules"] = rules
		}
		if token != "" {
			in["ClientRequestToken"] = token
		}
		return cfnComputeRun(ctx, h.commands, "secretsmanager", "RotateSecret", in)
	}
}

// Create rotates immediately, the RotateSecret default. Its version token is
// fixed per incarnation so a recovered create never starts a second rotation.
func (h cfnSecretRotation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.aspect().create(ctx, r, h.rotate(r, true, cfnSecretToken(r, "rotation")))
}

func (h cfnSecretRotation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	immediately, present, _ := cfnAppBoolean(r.Properties, "RotateImmediatelyOnUpdate")
	return h.aspect().update(ctx, r, h.rotate(r, immediately || !present, ""))
}

func (h cfnSecretRotation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return h.aspect().remove(ctx, r, func(ctx context.Context, arn string) error {
		return cfnComputeRun(ctx, h.commands, "secretsmanager", "CancelRotateSecret", map[string]any{"SecretId": arn})
	})
}

func cfnSecretRulesProperties(rules *api.RotationRulesType) map[string]any {
	out := map[string]any{}
	if rules == nil {
		return out
	}
	if rules.AutomaticallyAfterDays != nil {
		out["AutomaticallyAfterDays"] = int64(*rules.AutomaticallyAfterDays)
	}
	if rules.Duration != nil {
		out["Duration"] = cfnComputeValue(rules.Duration)
	}
	if rules.ScheduleExpression != nil {
		out["ScheduleExpression"] = cfnComputeValue(rules.ScheduleExpression)
	}
	return out
}

func (h cfnSecretRotation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	s, _, err := cfnSecretDescribe(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if s.RotationEnabled == nil || !bool(*s.RotationEnabled) {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Rotation is not enabled for the secret.", StatusCode: 400}
	}
	p := cloudformation.Properties{"Id": r.PhysicalID, "SecretId": r.PhysicalID, "RotationRules": cfnSecretRulesProperties(s.RotationRules)}
	if s.RotationLambdaARN != nil {
		p["RotationLambdaARN"] = cfnComputeValue(s.RotationLambdaARN)
	}
	return p, nil
}

func (h cfnSecretRotation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return cfnSecretAspectList(ctx, h.commands, func(s api.SecretListEntry) (bool, error) {
		return s.RotationEnabled != nil && bool(*s.RotationEnabled), nil
	})
}

// cfnSecretAttachment adds the target database's connection details to the
// secret's JSON value through PutSecretValue, and removes them on delete.
// Targets are read from the actual RDS and DocumentDB owners; Redshift,
// Redshift Serverless and DocumentDB Elastic owners are not installed.
type cfnSecretAttachment struct{ commands StepFunctionsCommands }

func (h cfnSecretAttachment) aspect() cfnSecretAspect {
	return cfnSecretAspect{h.commands, "attachment"}
}

func (h cfnSecretAttachment) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "SecretId", "TargetId", "TargetType"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "SecretId", "TargetId", "TargetType"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "SecretId", "TargetId", "TargetType"); err != nil {
		return err
	}
	switch kind := cfnComputeString(p, "TargetType"); kind {
	case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::DocDB::DBInstance", "AWS::DocDB::DBCluster":
		return nil
	case "AWS::Redshift::Cluster", "AWS::RedshiftServerless::Namespace", "AWS::DocDBElastic::Cluster":
		return fmt.Errorf("TargetType %s requires a service owner that is not available", kind)
	default:
		return fmt.Errorf("unsupported TargetType %q", kind)
	}
}
func (h cfnSecretAttachment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "SecretId"), h.Validate(b)
}

// connection reads the documented secret JSON keys from the target owner.
// https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_secret_json_structure.html
func (h cfnSecretAttachment) connection(ctx context.Context, p cloudformation.Properties) (map[string]any, error) {
	id := cfnComputeString(p, "TargetId")
	switch cfnComputeString(p, "TargetType") {
	case "AWS::RDS::DBInstance":
		out, err := cfnComputeCall[rdsapi.DescribeDBInstancesOutput](ctx, h.commands, "rds", "DescribeDBInstances", map[string]any{"DBInstanceIdentifier": id})
		if err != nil {
			return nil, err
		}
		if len(out.DBInstances) != 1 || out.DBInstances[0].Endpoint == nil {
			return nil, fmt.Errorf("RDS instance %s has no endpoint", id)
		}
		v := out.DBInstances[0]
		return map[string]any{"engine": cfnComputeValue(v.Engine), "host": cfnComputeValue(v.Endpoint.Address), "port": cfnACfgInt(v.Endpoint.Port), "dbInstanceIdentifier": cfnComputeValue(v.DBInstanceIdentifier)}, nil
	case "AWS::RDS::DBCluster":
		out, err := cfnComputeCall[rdsapi.DescribeDBClustersOutput](ctx, h.commands, "rds", "DescribeDBClusters", map[string]any{"DBClusterIdentifier": id})
		if err != nil {
			return nil, err
		}
		if len(out.DBClusters) != 1 || out.DBClusters[0].Endpoint == nil {
			return nil, fmt.Errorf("RDS cluster %s has no endpoint", id)
		}
		v := out.DBClusters[0]
		return map[string]any{"engine": cfnComputeValue(v.Engine), "host": cfnComputeValue(v.Endpoint), "port": cfnACfgInt(v.Port), "dbClusterIdentifier": cfnComputeValue(v.DBClusterIdentifier)}, nil
	case "AWS::DocDB::DBInstance":
		out, err := cfnComputeCall[docdbapi.DescribeDBInstancesOutput](ctx, h.commands, "docdb", "DescribeDBInstances", map[string]any{"DBInstanceIdentifier": id})
		if err != nil {
			return nil, err
		}
		if len(out.DBInstances) != 1 || out.DBInstances[0].Endpoint == nil {
			return nil, fmt.Errorf("DocumentDB instance %s has no endpoint", id)
		}
		v := out.DBInstances[0]
		return map[string]any{"engine": "mongo", "host": cfnComputeValue(v.Endpoint.Address), "port": cfnACfgInt(v.Endpoint.Port), "dbInstanceIdentifier": cfnComputeValue(v.DBInstanceIdentifier)}, nil
	case "AWS::DocDB::DBCluster":
		out, err := cfnComputeCall[docdbapi.DescribeDBClustersOutput](ctx, h.commands, "docdb", "DescribeDBClusters", map[string]any{"DBClusterIdentifier": id})
		if err != nil {
			return nil, err
		}
		if len(out.DBClusters) != 1 || out.DBClusters[0].Endpoint == nil {
			return nil, fmt.Errorf("DocumentDB cluster %s has no endpoint", id)
		}
		v := out.DBClusters[0]
		return map[string]any{"engine": "mongo", "host": cfnComputeValue(v.Endpoint), "port": cfnACfgInt(v.Port), "dbClusterIdentifier": cfnComputeValue(v.DBClusterIdentifier)}, nil
	}
	return nil, fmt.Errorf("unsupported TargetType %q", cfnComputeString(p, "TargetType"))
}

// document reads the current secret JSON object; a secret without a value
// starts from an empty object.
func (h cfnSecretAttachment) document(ctx context.Context, arn string) (map[string]any, error) {
	out, err := cfnComputeCall[api.GetSecretValueOutput](ctx, h.commands, "secretsmanager", "GetSecretValue", map[string]any{"SecretId": arn})
	if cfnSecretMissing(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if out.SecretString == nil {
		return nil, fmt.Errorf("secret %s holds a binary value, not a JSON object", arn)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(cfnComputeValue(out.SecretString)), &document); err != nil || document == nil {
		return nil, fmt.Errorf("secret %s value must be a JSON object to attach a target", arn)
	}
	return document, nil
}

func (h cfnSecretAttachment) attach(r cloudformation.ResourceRequest) func(context.Context, string) error {
	return func(ctx context.Context, arn string) error {
		connection, err := h.connection(ctx, r.Properties)
		if err != nil {
			return err
		}
		body, err := json.Marshal(connection)
		if err != nil {
			return err
		}
		return cfnComputeRun(ctx, h.commands, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": arn, "SecretString": string(body)})
	}
}

func (h cfnSecretAttachment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.aspect().create(ctx, r, h.attach(r))
}

func (h cfnSecretAttachment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.aspect().update(ctx, r, h.attach(r))
}

func (h cfnSecretAttachment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return h.aspect().remove(ctx, r, func(ctx context.Context, arn string) error {
		// The native owner removes only connection metadata from its current
		// value inside the fenced transaction, preserving concurrent credentials.
		return cfnComputeRun(ctx, h.commands, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": arn, "SecretString": "{}"})
	})
}

func (h cfnSecretAttachment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	document, err := h.document(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	engine, _ := document["engine"].(string)
	service := "RDS"
	if engine == "mongo" || engine == "docdb" {
		service = "DocDB"
	}
	p := cloudformation.Properties{"Id": r.PhysicalID, "SecretId": r.PhysicalID}
	if id, ok := document["dbClusterIdentifier"].(string); ok {
		p["TargetId"], p["TargetType"] = id, "AWS::"+service+"::DBCluster"
	} else if id, ok := document["dbInstanceIdentifier"].(string); ok {
		p["TargetId"], p["TargetType"] = id, "AWS::"+service+"::DBInstance"
	} else {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "The secret has no attached target.", StatusCode: 400}
	}
	return p, nil
}

func (h cfnSecretAttachment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return cfnSecretAspectList(ctx, h.commands, func(s api.SecretListEntry) (bool, error) {
		if s.OwningService != nil {
			return false, nil
		}
		document, err := h.document(ctx, cfnComputeValue(s.ARN))
		var wire *awswire.Error
		if errors.As(err, &wire) {
			return false, err
		}
		if err != nil {
			return false, nil // binary or non-object values carry no attachment
		}
		_, cluster := document["dbClusterIdentifier"].(string)
		_, instance := document["dbInstanceIdentifier"].(string)
		return cluster || instance, nil
	})
}
