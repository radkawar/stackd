package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	api "stackd/internal/awsapi/resourcegroups"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/resourcegroups"
)

// Resource Groups: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_ResourceGroups.html

func cfnRGroupMissing(err error) bool {
	return cfnMessagingMissing(err, "NotFoundException")
}

func cfnRGroupTagger(c StepFunctionsCommands, arn string) cfnAppTagged {
	return cfnAppTagged{
		list: func(ctx context.Context) (map[string]string, error) {
			out, err := cfnComputeCall[api.GetTagsOutput](ctx, c, "resourcegroups", "GetTags", map[string]any{"Arn": arn})
			if err != nil {
				return nil, err
			}
			tags := make(map[string]string, len(out.Tags))
			for k, v := range out.Tags {
				tags[string(k)] = string(v)
			}
			return tags, nil
		},
		tag: func(ctx context.Context, tags map[string]string) error {
			return cfnComputeRun(ctx, c, "resourcegroups", "Tag", map[string]any{"Arn": arn, "Tags": tags})
		},
		untag: func(ctx context.Context, keys []string) error {
			return cfnComputeRun(ctx, c, "resourcegroups", "Untag", map[string]any{"Arn": arn, "Keys": keys})
		},
	}
}

type cfnRGroup struct{ commands StepFunctionsCommands }

func (h cfnRGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "ResourceQuery", "Configuration", "Resources", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Description"); err != nil {
		return err
	}
	if p["ResourceQuery"] != nil && p["Configuration"] != nil {
		return fmt.Errorf("specify either ResourceQuery or Configuration, not both")
	}
	if p["Resources"] != nil && p["Configuration"] == nil {
		return fmt.Errorf("Resources requires Configuration")
	}
	if _, err := cfnComputeStringList(p, "Resources"); err != nil {
		return err
	}
	if _, err := cfnRGroupQuery(cloudformation.ResourceRequest{Properties: p, StackID: "stack"}); err != nil {
		return err
	}
	if _, err := cfnRGroupConfiguration(p); err != nil {
		return err
	}
	return cfnACfgTagProperties(p)
}
func (h cfnRGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}

// cfnRGroupQuery converts the template query object to the owner's JSON query
// document. A stack query without StackIdentifier selects the current stack.
func cfnRGroupQuery(r cloudformation.ResourceRequest) (map[string]any, error) {
	v, ok := r.Properties["ResourceQuery"]
	if !ok {
		return nil, nil
	}
	q, ok := cfnComputeObject(v)
	if !ok {
		return nil, fmt.Errorf("ResourceQuery must be an object")
	}
	if err := cfnComputeProperties(q, "Type", "Query"); err != nil {
		return nil, err
	}
	kind := cfnComputeString(q, "Type")
	if kind != "TAG_FILTERS_1_0" && kind != "CLOUDFORMATION_STACK_1_0" {
		return nil, fmt.Errorf("ResourceQuery.Type must be TAG_FILTERS_1_0 or CLOUDFORMATION_STACK_1_0")
	}
	query := map[string]any{}
	if raw, ok := q["Query"]; ok {
		body, ok := cfnComputeObject(raw)
		if !ok {
			return nil, fmt.Errorf("ResourceQuery.Query must be an object")
		}
		if err := cfnComputeProperties(body, "ResourceTypeFilters", "StackIdentifier", "TagFilters"); err != nil {
			return nil, err
		}
		query = cfnComputeCopy(body, "ResourceTypeFilters", "StackIdentifier", "TagFilters")
	}
	if _, ok := query["ResourceTypeFilters"]; !ok {
		query["ResourceTypeFilters"] = []any{"AWS::AllSupported"}
	}
	if kind == "CLOUDFORMATION_STACK_1_0" {
		if _, ok := query["TagFilters"]; ok {
			return nil, fmt.Errorf("TagFilters is valid only for TAG_FILTERS_1_0")
		}
		if _, ok := query["StackIdentifier"]; !ok {
			query["StackIdentifier"] = r.StackID
		}
	} else if _, ok := query["StackIdentifier"]; ok {
		return nil, fmt.Errorf("StackIdentifier is valid only for CLOUDFORMATION_STACK_1_0")
	}
	document, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	return map[string]any{"Type": kind, "Query": string(document)}, nil
}

func cfnRGroupConfiguration(p cloudformation.Properties) ([]any, error) {
	v, ok := p["Configuration"]
	if !ok {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok || len(items) == 0 || len(items) > 2 {
		return nil, fmt.Errorf("configuration must contain one or two items")
	}
	for _, item := range items {
		config, ok := cfnComputeObject(item)
		if !ok {
			return nil, fmt.Errorf("configuration entries must be objects")
		}
		if err := cfnComputeProperties(config, "Type", "Parameters"); err != nil {
			return nil, err
		}
		if params, ok := config["Parameters"].([]any); ok {
			for _, param := range params {
				object, ok := cfnComputeObject(param)
				if !ok {
					return nil, fmt.Errorf("configuration parameters must be objects")
				}
				if err := cfnComputeProperties(object, "Name", "Values"); err != nil {
					return nil, err
				}
			}
		}
	}
	return items, nil
}

func cfnRGroupResult(name, arn string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": arn}}
}

func (h cfnRGroup) get(ctx context.Context, name string) (*api.Group, error) {
	out, err := cfnComputeCall[api.GetGroupOutput](ctx, h.commands, "resourcegroups", "GetGroup", map[string]any{"Group": name})
	if err != nil {
		return nil, err
	}
	if out.Group == nil {
		return nil, fmt.Errorf("resource Groups returned no group")
	}
	return out.Group, nil
}

func cfnRGroupClaim(r cloudformation.ResourceRequest) string {
	if r.StackID == "" || r.LogicalID == "" || r.Token == "" {
		return ""
	}
	raw, _ := json.Marshal([]string{r.StackID, r.LogicalID, r.Token})
	return string(raw)
}

func cfnRGroupContext(ctx context.Context, r cloudformation.ResourceRequest, enforce bool, observed map[string]string) context.Context {
	if r.CloudControl && enforce {
		return ctx
	}
	return resourcegroups.WithCloudFormationGroupOwnership(ctx, cfnRGroupClaim(r), enforce, observed)
}

func cfnRGroupTags(r cloudformation.ResourceRequest) map[string]string {
	tags, _ := cfnComputeTags(r.Properties)
	for key, value := range r.Tags {
		if _, present := tags[key]; !present {
			tags[key] = value
		}
	}
	return tags
}

func (h cfnRGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	observed := map[string]string{}
	ctx = cfnRGroupContext(ctx, r, false, observed)
	name := cfnComputeString(r.Properties, "Name")
	g, err := h.get(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if claim := cfnRGroupClaim(r); claim == "" || observed[name] != claim {
		return cloudformation.ResourceResult{}, fmt.Errorf("group %s is not owned by this stack resource incarnation", name)
	}
	return cfnRGroupResult(cfnComputeValue(g.Name), cfnComputeValue(g.GroupArn)), nil
}

func (h cfnRGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if cfnRGroupClaim(r) == "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("group creation requires a stack resource incarnation")
	}
	name := cfnComputeString(r.Properties, "Name")
	recovered, err := h.RecoverCreation(ctx, r)
	if err == nil {
		ctx = resourcegroups.WithCloudFormationGroupOwnership(ctx, cfnRGroupClaim(r), true, nil)
		return recovered, h.members(ctx, r, recovered.PhysicalID, nil)
	}
	if !cfnRGroupMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "Name", "Description")
	if q, _ := cfnRGroupQuery(r); q != nil {
		in["ResourceQuery"] = q
	}
	if config, _ := cfnRGroupConfiguration(r.Properties); config != nil {
		in["Configuration"] = config
	}
	in["Tags"] = cfnRGroupTags(r)
	createCtx := cfnRGroupContext(ctx, r, false, nil)
	out, err := cfnComputeCall[api.CreateGroupOutput](createCtx, h.commands, "resourcegroups", "CreateGroup", in)
	if err != nil {
		recovered, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return recovered, err
		}
		if cfnRGroupMissing(recoveryErr) {
			return cloudformation.ResourceResult{}, err
		}
		return cloudformation.ResourceResult{}, errors.Join(err, recoveryErr)
	}
	g := out.Group
	ctx = resourcegroups.WithCloudFormationGroupOwnership(ctx, cfnRGroupClaim(r), true, nil)
	result := cfnRGroupResult(name, cfnComputeValue(g.GroupArn))
	return result, h.members(ctx, r, name, nil)
}

// members reconciles explicit members of a configured group with the owner.
func (h cfnRGroup) members(ctx context.Context, r cloudformation.ResourceRequest, name string, previous []string) error {
	desired, _ := cfnComputeStringList(r.Properties, "Resources")
	var add, remove []string
	for _, arn := range desired {
		if !slices.Contains(previous, arn) {
			add = append(add, arn)
		}
	}
	for _, arn := range previous {
		if !slices.Contains(desired, arn) {
			remove = append(remove, arn)
		}
	}
	in := map[string]any{"Group": name}
	if len(remove) > 0 {
		in["ResourceArns"] = remove
		out, err := cfnComputeCall[api.UngroupResourcesOutput](ctx, h.commands, "resourcegroups", "UngroupResources", in)
		if err != nil {
			return err
		}
		if err := cfnRGroupFailed("UngroupResources", out.Failed); err != nil {
			return err
		}
	}
	if len(add) > 0 {
		in["ResourceArns"] = add
		out, err := cfnComputeCall[api.GroupResourcesOutput](ctx, h.commands, "resourcegroups", "GroupResources", in)
		if err != nil {
			return err
		}
		return cfnRGroupFailed("GroupResources", out.Failed)
	}
	return nil
}

func cfnRGroupFailed(operation string, failed api.FailedResourceList) error {
	if len(failed) == 0 {
		return nil
	}
	return fmt.Errorf("%s failed for %s: %s", operation, cfnComputeValue(failed[0].ResourceArn), cfnComputeValue(failed[0].ErrorMessage))
}

// Stabilize waits for pending explicit memberships to reach the owner's
// terminal grouping status.
func (h cfnRGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRGroupContext(ctx, r, true, nil)
	desired, _ := cfnComputeStringList(r.Properties, "Resources")
	if len(desired) == 0 {
		return true, nil
	}
	out, err := cfnComputeCall[api.ListGroupingStatusesOutput](ctx, h.commands, "resourcegroups", "ListGroupingStatuses", map[string]any{"Group": r.PhysicalID})
	if err != nil {
		return false, err
	}
	done := 0
	for _, item := range out.GroupingStatuses {
		if cfnComputeValue(item.Action) != "GROUP" || !slices.Contains(desired, cfnComputeValue(item.ResourceArn)) {
			continue
		}
		switch cfnComputeValue(item.Status) {
		case "SUCCESS":
			done++
		case "FAILED":
			return false, fmt.Errorf("grouping %s failed: %s", cfnComputeValue(item.ResourceArn), cfnComputeValue(item.ErrorMessage))
		}
	}
	return done >= len(desired), nil
}

func (h cfnRGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnRGroupContext(ctx, r, true, nil)
	g, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnComputeValue(g.GroupArn)
	tagger := cfnRGroupTagger(h.commands, arn)
	tags, err := tagger.list(ctx)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnRGroupResult(r.PhysicalID, arn)
	if err := cfnComputeRun(ctx, h.commands, "resourcegroups", "UpdateGroup", map[string]any{"Group": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", "")}); err != nil {
		return result, err
	}
	if q, _ := cfnRGroupQuery(r); q != nil {
		if err := cfnComputeRun(ctx, h.commands, "resourcegroups", "UpdateGroupQuery", map[string]any{"Group": r.PhysicalID, "ResourceQuery": q}); err != nil {
			return result, err
		}
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Configuration") {
		config, _ := cfnRGroupConfiguration(r.Properties)
		if config == nil {
			config = []any{}
		}
		if err := cfnComputeRun(ctx, h.commands, "resourcegroups", "PutGroupConfiguration", map[string]any{"Group": r.PhysicalID, "Configuration": config}); err != nil {
			return result, err
		}
	}
	previous, _ := cfnComputeStringList(r.Previous, "Resources")
	if err := h.members(ctx, r, r.PhysicalID, previous); err != nil {
		return result, err
	}
	return result, cfnAppTagSync(ctx, tags, cfnRGroupTags(r), tagger.tag, tagger.untag)
}

func (h cfnRGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnRGroupContext(ctx, r, true, nil)
	_, err := h.get(ctx, r.PhysicalID)
	if cfnRGroupMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "resourcegroups", "DeleteGroup", map[string]any{"Group": r.PhysicalID})
	if cfnRGroupMissing(err) {
		return nil
	}
	return err
}

func (h cfnRGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	g, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	arn := cfnComputeValue(g.GroupArn)
	tags, err := cfnRGroupTagger(h.commands, arn).list(ctx)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"Name": cfnComputeValue(g.Name), "Arn": arn, "Tags": cfnAppUserTags(tags)}
	if g.Description != nil {
		p["Description"] = cfnComputeValue(g.Description)
	}
	query, err := cfnComputeCall[api.GetGroupQueryOutput](ctx, h.commands, "resourcegroups", "GetGroupQuery", map[string]any{"Group": r.PhysicalID})
	if err != nil && !cfnMessagingMissing(err, "BadRequestException") {
		return nil, err
	}
	if query != nil && query.GroupQuery != nil && query.GroupQuery.ResourceQuery != nil {
		var body map[string]any
		if err := json.Unmarshal([]byte(cfnComputeValue(query.GroupQuery.ResourceQuery.Query)), &body); err != nil {
			return nil, fmt.Errorf("invalid owner resource query: %w", err)
		}
		p["ResourceQuery"] = map[string]any{"Type": cfnComputeValue(query.GroupQuery.ResourceQuery.Type), "Query": body}
	}
	return p, nil
}

func (h cfnRGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var out []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		page, err := cfnComputeCall[api.ListGroupsOutput](ctx, h.commands, "resourcegroups", "ListGroups", in)
		if err != nil {
			return nil, err
		}
		for _, g := range page.GroupIdentifiers {
			name := cfnComputeValue(g.GroupName)
			out = append(out, cloudformation.ResourceDescription{Identifier: name, Properties: cloudformation.Properties{"Name": name, "Arn": cfnComputeValue(g.GroupArn)}})
		}
		next := cfnComputeValue(page.NextToken)
		if next == "" {
			return out, nil
		}
		if next == in["NextToken"] {
			return nil, fmt.Errorf("resource Groups pagination did not advance")
		}
		in["NextToken"] = next
	}
}

// cfnRGroupTagSync starts a tag-sync task in an application group. The owner
// derives the task identity from the stack incarnation, so an interrupted
// create recovers the same task instead of starting a second synchronization.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-resourcegroups-tagsynctask.html
type cfnRGroupTagSync struct{ commands StepFunctionsCommands }

func (h cfnRGroupTagSync) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Group", "TagKey", "TagValue", "RoleArn"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Group", "TagKey", "TagValue", "RoleArn"); err != nil {
		return err
	}
	return cfnComputeStrings(p, "Group", "TagKey", "TagValue", "RoleArn")
}
func (h cfnRGroupTagSync) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Group", "TagKey", "TagValue", "RoleArn"), h.Validate(b)
}

func cfnRGroupTaskResult(arn, groupARN, groupName, status string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"TaskArn": arn, "GroupArn": groupARN, "GroupName": groupName, "Status": status}}
}

func (h cfnRGroupTagSync) get(ctx context.Context, arn string) (*api.GetTagSyncTaskOutput, error) {
	return cfnComputeCall[api.GetTagSyncTaskOutput](ctx, h.commands, "resourcegroups", "GetTagSyncTask", map[string]any{"TaskArn": arn})
}

func (h cfnRGroupTagSync) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "Group", "TagKey", "TagValue", "RoleArn")
	out, err := cfnComputeCall[api.StartTagSyncTaskOutput](resourcegroups.WithCloudFormationOwner(ctx, cfnMessagingMarker(r)), h.commands, "resourcegroups", "StartTagSyncTask", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	task, err := h.get(ctx, cfnComputeValue(out.TaskArn))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnRGroupTaskResult(cfnComputeValue(task.TaskArn), cfnComputeValue(task.GroupArn), cfnComputeValue(task.GroupName), cfnComputeValue(task.Status)), nil
}

func (h cfnRGroupTagSync) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if changed, err := h.Replacement(r.Previous, r.Properties); err != nil || changed {
		if err == nil {
			err = fmt.Errorf("tag-sync task properties are create-only")
		}
		return cloudformation.ResourceResult{}, err
	}
	return h.Result(ctx, r)
}

func (h cfnRGroupTagSync) owned(ctx context.Context, r cloudformation.ResourceRequest) (*api.GetTagSyncTaskOutput, error) {
	task, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if !r.CloudControl && resourcegroups.CloudFormationTagSyncTaskARN(cfnComputeValue(task.GroupArn), cfnMessagingMarker(r)) != r.PhysicalID {
		return nil, fmt.Errorf("tag-sync task %s is not owned by this CloudFormation resource incarnation", r.PhysicalID)
	}
	return task, nil
}

func (h cfnRGroupTagSync) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	task, err := h.owned(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnRGroupTaskResult(r.PhysicalID, cfnComputeValue(task.GroupArn), cfnComputeValue(task.GroupName), cfnComputeValue(task.Status)), nil
}

func (h cfnRGroupTagSync) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	_, err := h.owned(ctx, r)
	if cfnRGroupMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "resourcegroups", "CancelTagSyncTask", map[string]any{"TaskArn": r.PhysicalID})
	if cfnRGroupMissing(err) {
		return nil
	}
	return err
}

func (h cfnRGroupTagSync) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	task, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return cloudformation.Properties{"TaskArn": cfnComputeValue(task.TaskArn), "Group": cfnComputeValue(task.GroupArn), "GroupArn": cfnComputeValue(task.GroupArn), "GroupName": cfnComputeValue(task.GroupName), "TagKey": cfnComputeValue(task.TagKey), "TagValue": cfnComputeValue(task.TagValue), "RoleArn": cfnComputeValue(task.RoleArn), "Status": cfnComputeValue(task.Status)}, nil
}

func (h cfnRGroupTagSync) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var out []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		page, err := cfnComputeCall[api.ListTagSyncTasksOutput](ctx, h.commands, "resourcegroups", "ListTagSyncTasks", in)
		if err != nil {
			return nil, err
		}
		for _, t := range page.TagSyncTasks {
			arn := cfnComputeValue(t.TaskArn)
			out = append(out, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"TaskArn": arn, "GroupArn": cfnComputeValue(t.GroupArn), "GroupName": cfnComputeValue(t.GroupName), "Status": cfnComputeValue(t.Status)}})
		}
		next := cfnComputeValue(page.NextToken)
		if next == "" {
			return out, nil
		}
		if next == in["NextToken"] {
			return nil, fmt.Errorf("resource Groups pagination did not advance")
		}
		in["NextToken"] = next
	}
}
