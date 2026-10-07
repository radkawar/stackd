package cloudformation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	api "stackd/internal/awsapi/cloudformation"
)

func (s *Service) registerReads() {
	register(s, "DescribeStacks", s.describeStacks)
	register(s, "ListStacks", s.listStacks)
	register(s, "DescribeStackEvents", s.describeEvents)
	register(s, "DescribeStackResources", s.describeResources)
	register(s, "DescribeStackResource", s.describeResource)
	register(s, "ListStackResources", s.listResources)
	register(s, "DescribeChangeSet", s.describeChangeSet)
	register(s, "ListChangeSets", s.listChangeSets)
	register(s, "ListExports", s.listExports)
	register(s, "ListImports", s.listImports)
	register(s, "GetTemplate", s.getTemplate)
	register(s, "ValidateTemplate", s.validateTemplate)
	register(s, "GetTemplateSummary", s.templateSummary)
}
func page[T any](r Reader, action, filter, token string, rows []T, key func(T) string) ([]T, *api.NextToken, error) {
	binding := requestHash([]any{scopeFor(r.Context()), action, filter})
	start := 0
	if token != "" {
		raw, e := base64.RawURLEncoding.DecodeString(token)
		var cursor []string
		if e != nil || json.Unmarshal(raw, &cursor) != nil || len(cursor) != 2 || cursor[0] != binding {
			return nil, nil, invalid("Invalid NextToken")
		}
		found := false
		for i, v := range rows {
			if key(v) == cursor[1] {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, nil, invalid("Invalid or expired NextToken")
		}
	}
	end := min(start+100, len(rows))
	if end == len(rows) {
		return rows[start:end], nil, nil
	}
	raw, _ := json.Marshal([]string{binding, key(rows[end-1])})
	return rows[start:end], new(api.NextToken(base64.RawURLEncoding.EncodeToString(raw))), nil
}
func parametersOutput(body string, values, resolved map[string]string) api.Parameters {
	out := api.Parameters{}
	t, _ := ParseTemplate(body)
	for _, key := range slices.Sorted(maps.Keys(values)) {
		v := values[key]
		if t != nil && t.Parameters[key].NoEcho {
			v = "****"
		}
		parameter := api.Parameter{ParameterKey: new(api.ParameterKey(key)), ParameterValue: new(api.ParameterValue(v))}
		if value, ok := resolved[key]; ok {
			if t != nil && t.Parameters[key].NoEcho {
				value = "****"
			}
			parameter.ResolvedValue = new(api.ParameterValue(value))
		}
		out = append(out, parameter)
	}
	return out
}
func tagsOutput(tags map[string]string) api.Tags {
	out := api.Tags{}
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, api.Tag{Key: new(api.TagKey(k)), Value: new(api.TagValue(tags[k]))})
	}
	return out
}
func capabilitiesOutput(values []string) api.Capabilities {
	out := api.Capabilities{}
	for _, v := range values {
		out = append(out, api.Capability(v))
	}
	return out
}
func stackOutput(v StackRecord) api.Stack {
	out := api.Stack{StackId: new(api.StackId(v.ID)), StackName: new(api.StackName(v.Name)), StackStatus: new(api.StackStatus(v.Status)), CreationTime: new(v.Created), DisableRollback: new(api.DisableRollback(v.DisableRollback)), EnableTerminationProtection: new(api.EnableTerminationProtection(v.TerminationProtection)), Capabilities: capabilitiesOutput(v.Capabilities), Parameters: parametersOutput(v.Template, v.Parameters, v.ResolvedParameters), Tags: tagsOutput(v.Tags), Outputs: api.Outputs{}}
	if !v.Updated.IsZero() {
		out.LastUpdatedTime = new(v.Updated)
	}
	if v.Deleted != nil {
		out.DeletionTime = v.Deleted
	}
	if v.Description != "" {
		out.Description = new(api.Description(v.Description))
	}
	if v.StatusReason != "" {
		out.StackStatusReason = new(api.StackStatusReason(v.StatusReason))
	}
	if v.RoleARN != "" {
		out.RoleARN = new(api.RoleARN(v.RoleARN))
	}
	if v.ParentID != "" {
		out.ParentId = new(api.StackId(v.ParentID))
		out.RootId = new(api.StackId(v.RootID))
	}
	for _, k := range slices.Sorted(maps.Keys(v.Outputs)) {
		v := v.Outputs[k]
		o := api.Output{OutputKey: new(api.OutputKey(k)), OutputValue: new(api.OutputValue(v.Value))}
		if v.Description != "" {
			o.Description = new(api.Description(v.Description))
		}
		if v.ExportName != "" {
			o.ExportName = new(api.ExportName(v.ExportName))
		}
		out.Outputs = append(out.Outputs, o)
	}
	return out
}
func (s *Service) describeStacks(tx Transaction, in *api.DescribeStacksInput) (*api.DescribeStacksOutput, error) {
	rows := []StackRecord{}
	if text(in.StackName) != "" {
		v, e := findStack(tx, text(in.StackName))
		if e != nil {
			return nil, e
		}
		if e = checkNestedStackOwner(tx, v); e != nil {
			return nil, e
		}
		if e = s.authorize(tx, "DescribeStacks", v); e != nil {
			return nil, e
		}
		if e = observeStackResource(tx, v); e != nil {
			return nil, e
		}
		rows = append(rows, v)
	} else {
		if e := s.authorize(tx, "DescribeStacks", StackRecord{}); e != nil {
			return nil, e
		}
		all, e := tx.Stacks(scopeFor(tx.Context()))
		if e != nil {
			return nil, e
		}
		for _, v := range all {
			if v.Deleted == nil && checkNestedStackOwner(tx, v) == nil {
				rows = append(rows, v)
			}
		}
	}
	rows, next, e := page(tx, "DescribeStacks", text(in.StackName), text(in.NextToken), rows, func(v StackRecord) string { return v.ID })
	if e != nil {
		return nil, e
	}
	out := &api.DescribeStacksOutput{Stacks: api.Stacks{}, NextToken: next}
	for _, v := range rows {
		if v.ParentID != "" {
			root, err := tx.Stack(v.RootID)
			if err != nil {
				return nil, err
			}
			v.TerminationProtection = root.TerminationProtection
		}
		out.Stacks = append(out.Stacks, stackOutput(v))
	}
	return out, nil
}
func (s *Service) listStacks(tx Transaction, in *api.ListStacksInput) (*api.ListStacksOutput, error) {
	if e := s.authorize(tx, "ListStacks", StackRecord{}); e != nil {
		return nil, e
	}
	rows, e := tx.Stacks(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	filtered := rows[:0]
	for _, v := range rows {
		if checkNestedStackOwner(tx, v) == nil && (len(in.StackStatusFilter) == 0 || slices.Contains(in.StackStatusFilter, api.StackStatus(v.Status))) {
			filtered = append(filtered, v)
		}
	}
	rows, next, e := page(tx, "ListStacks", requestHash(in.StackStatusFilter), text(in.NextToken), filtered, func(v StackRecord) string { return v.ID })
	if e != nil {
		return nil, e
	}
	out := &api.ListStacksOutput{StackSummaries: api.StackSummaries{}, NextToken: next}
	for _, v := range rows {
		o := api.StackSummary{StackId: new(api.StackId(v.ID)), StackName: new(api.StackName(v.Name)), StackStatus: new(api.StackStatus(v.Status)), CreationTime: new(v.Created)}
		if v.ParentID != "" {
			o.ParentId = new(api.StackId(v.ParentID))
			o.RootId = new(api.StackId(v.RootID))
		}
		if v.Description != "" {
			o.TemplateDescription = new(api.TemplateDescription(v.Description))
		}
		if !v.Updated.IsZero() {
			o.LastUpdatedTime = new(v.Updated)
		}
		if v.Deleted != nil {
			o.DeletionTime = v.Deleted
		}
		out.StackSummaries = append(out.StackSummaries, o)
	}
	return out, nil
}
func (s *Service) describeEvents(tx Transaction, in *api.DescribeStackEventsInput) (*api.DescribeStackEventsOutput, error) {
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "DescribeStackEvents", stack); e != nil {
		return nil, e
	}
	rows, e := tx.Events(stack.ID)
	if e != nil {
		return nil, e
	}
	rows, next, e := page(tx, "DescribeStackEvents", stack.ID, text(in.NextToken), rows, func(v EventRecord) string { return v.ID })
	if e != nil {
		return nil, e
	}
	out := &api.DescribeStackEventsOutput{NextToken: next, StackEvents: api.StackEvents{}}
	for _, v := range rows {
		o := api.StackEvent{StackId: new(api.StackId(stack.ID)), StackName: new(api.StackName(stack.Name)), EventId: new(api.EventId(v.ID)), LogicalResourceId: new(api.LogicalResourceId(v.LogicalID)), PhysicalResourceId: new(api.PhysicalResourceId(v.PhysicalID)), ResourceType: new(api.ResourceType(v.Type)), ResourceStatus: new(api.ResourceStatus(v.Status)), Timestamp: new(v.Timestamp)}
		if v.Token != "" {
			o.ClientRequestToken = new(api.ClientRequestToken(v.Token))
		}
		if v.Reason != "" {
			o.ResourceStatusReason = new(api.ResourceStatusReason(v.Reason))
		}
		if v.Properties != nil {
			raw, _ := json.Marshal(v.Properties)
			o.ResourceProperties = new(api.ResourceProperties(string(raw)))
		}
		out.StackEvents = append(out.StackEvents, o)
	}
	return out, nil
}
func visibleResources(r Reader, stack StackRecord) ([]ResourceRecord, error) {
	rows, e := r.Resources(stack.ID)
	if e != nil {
		return nil, e
	}
	latest := map[string]ResourceRecord{}
	for _, v := range rows {
		old, ok := latest[v.LogicalID]
		if !ok || v.Current || (!old.Current && v.Generation > old.Generation) {
			latest[v.LogicalID] = v
		}
	}
	out := []ResourceRecord{}
	var template *Template
	for _, id := range slices.Sorted(maps.Keys(latest)) {
		v := latest[id]
		if !v.Current {
			if stack.Status != "DELETE_COMPLETE" && stack.Status != "ROLLBACK_COMPLETE" {
				continue
			}
			if template == nil {
				template, e = ParseTemplate(stack.Template)
				if e != nil {
					return nil, e
				}
			}
			if _, retained := template.Resources[id]; !retained {
				continue
			}
		}
		out = append(out, v)
	}
	return out, nil
}
func resourceOutput(stack StackRecord, v ResourceRecord) api.StackResource {
	out := api.StackResource{StackId: new(api.StackId(stack.ID)), StackName: new(api.StackName(stack.Name)), LogicalResourceId: new(api.LogicalResourceId(v.LogicalID)), ResourceType: new(api.ResourceType(v.Type)), ResourceStatus: new(api.ResourceStatus(v.Status)), Timestamp: new(v.Updated)}
	if v.PhysicalID != "" {
		out.PhysicalResourceId = new(api.PhysicalResourceId(v.PhysicalID))
	}
	if v.StatusReason != "" {
		out.ResourceStatusReason = new(api.ResourceStatusReason(v.StatusReason))
	}
	return out
}
func (s *Service) describeResources(tx Transaction, in *api.DescribeStackResourcesInput) (*api.DescribeStackResourcesOutput, error) {
	if text(in.StackName) != "" && text(in.PhysicalResourceId) != "" {
		return nil, invalid("StackName and PhysicalResourceId cannot both be specified")
	}
	var stack StackRecord
	var e error
	if text(in.StackName) != "" {
		stack, e = findStack(tx, text(in.StackName))
		if e != nil {
			return nil, e
		}
	} else {
		if text(in.PhysicalResourceId) == "" {
			return nil, invalid("StackName or PhysicalResourceId is required")
		}
		all, e := tx.Stacks(scopeFor(tx.Context()))
		if e != nil {
			return nil, e
		}
		for _, v := range all {
			rows, e := tx.Resources(v.ID)
			if e != nil {
				return nil, e
			}
			for _, resource := range rows {
				if resource.PhysicalID == text(in.PhysicalResourceId) {
					stack = v
					break
				}
			}
			if stack.ID != "" {
				break
			}
		}
		if stack.ID == "" {
			return nil, invalid("Physical resource does not exist")
		}
	}
	if e = s.authorize(tx, "DescribeStackResources", stack); e != nil {
		return nil, e
	}
	rows, e := visibleResources(tx, stack)
	if e != nil {
		return nil, e
	}
	out := &api.DescribeStackResourcesOutput{StackResources: api.StackResources{}}
	for _, v := range rows {
		if text(in.LogicalResourceId) == "" || v.LogicalID == text(in.LogicalResourceId) {
			out.StackResources = append(out.StackResources, resourceOutput(stack, v))
		}
	}
	return out, nil
}
func (s *Service) describeResource(tx Transaction, in *api.DescribeStackResourceInput) (*api.DescribeStackResourceOutput, error) {
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "DescribeStackResource", stack); e != nil {
		return nil, e
	}
	rows, e := visibleResources(tx, stack)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if v.LogicalID == text(in.LogicalResourceId) {
			resource := resourceOutput(stack, v)
			return &api.DescribeStackResourceOutput{StackResourceDetail: &api.StackResourceDetail{StackId: resource.StackId, StackName: resource.StackName, LogicalResourceId: resource.LogicalResourceId, PhysicalResourceId: resource.PhysicalResourceId, ResourceType: resource.ResourceType, ResourceStatus: resource.ResourceStatus, ResourceStatusReason: resource.ResourceStatusReason, LastUpdatedTimestamp: resource.Timestamp}}, nil
		}
	}
	return nil, invalid("Resource does not exist for stack")
}
func (s *Service) listResources(tx Transaction, in *api.ListStackResourcesInput) (*api.ListStackResourcesOutput, error) {
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "ListStackResources", stack); e != nil {
		return nil, e
	}
	rows, e := visibleResources(tx, stack)
	if e != nil {
		return nil, e
	}
	rows, next, e := page(tx, "ListStackResources", stack.ID, text(in.NextToken), rows, func(v ResourceRecord) string { return v.LogicalID })
	if e != nil {
		return nil, e
	}
	out := &api.ListStackResourcesOutput{NextToken: next, StackResourceSummaries: api.StackResourceSummaries{}}
	for _, v := range rows {
		row := api.StackResourceSummary{LogicalResourceId: new(api.LogicalResourceId(v.LogicalID)), ResourceType: new(api.ResourceType(v.Type)), ResourceStatus: new(api.ResourceStatus(v.Status)), LastUpdatedTimestamp: new(v.Updated)}
		if v.PhysicalID != "" {
			row.PhysicalResourceId = new(api.PhysicalResourceId(v.PhysicalID))
		}
		if v.StatusReason != "" {
			row.ResourceStatusReason = new(api.ResourceStatusReason(v.StatusReason))
		}
		out.StackResourceSummaries = append(out.StackResourceSummaries, row)
	}
	return out, nil
}
func (s *Service) describeChangeSet(tx Transaction, in *api.DescribeChangeSetInput) (*api.DescribeChangeSetOutput, error) {
	v, e := findChangeSet(tx, text(in.ChangeSetName), text(in.StackName))
	if e != nil {
		return nil, e
	}
	stack, e := findStack(tx, v.StackID)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "DescribeChangeSet", stack); e != nil {
		return nil, e
	}
	rows, next, e := page(tx, "DescribeChangeSet", v.ID, text(in.NextToken), v.Changes, func(v ChangeRecord) string { return v.LogicalID })
	if e != nil {
		return nil, e
	}
	out := &api.DescribeChangeSetOutput{ChangeSetId: new(api.ChangeSetId(v.ID)), ChangeSetName: new(api.ChangeSetName(v.Name)), StackId: new(api.StackId(v.StackID)), StackName: new(api.StackName(v.StackName)), Status: new(api.ChangeSetStatus(v.Status)), ExecutionStatus: new(api.ExecutionStatus(v.ExecutionStatus)), CreationTime: new(v.Created), Capabilities: capabilitiesOutput(v.Capabilities), Parameters: parametersOutput(v.Template, v.Parameters, v.ResolvedParameters), Tags: tagsOutput(v.Tags), Changes: api.Changes{}, NextToken: next}
	if v.Reason != "" {
		out.StatusReason = new(api.ChangeSetStatusReason(v.Reason))
	}
	if v.Description != "" {
		out.Description = new(api.Description(v.Description))
	}
	template, e := ParseTemplate(v.Template)
	if e != nil {
		return nil, e
	}
	for _, c := range rows {
		resource := changeProperties(c, truth(in.IncludePropertyValues), s.handlers[c.Type], stack.Scope)
		if c.Replacement == "True" && template.Resources[c.LogicalID].UpdateReplacePolicy == "Retain" {
			resource.PolicyAction = new(api.PolicyAction("ReplaceAndRetain"))
		}
		out.Changes = append(out.Changes, api.Change{Type: new(api.ChangeType("Resource")), ResourceChange: resource})
	}
	return out, nil
}
func (s *Service) listChangeSets(tx Transaction, in *api.ListChangeSetsInput) (*api.ListChangeSetsOutput, error) {
	stack, e := findStack(tx, text(in.StackName))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "ListChangeSets", stack); e != nil {
		return nil, e
	}
	rows, e := tx.ChangeSets(stack.ID)
	if e != nil {
		return nil, e
	}
	rows = slices.DeleteFunc(rows, executedChangeSet)
	rows, next, e := page(tx, "ListChangeSets", stack.ID, text(in.NextToken), rows, func(v ChangeSetRecord) string { return v.ID })
	if e != nil {
		return nil, e
	}
	out := &api.ListChangeSetsOutput{NextToken: next, Summaries: api.ChangeSetSummaries{}}
	for _, v := range rows {
		out.Summaries = append(out.Summaries, api.ChangeSetSummary{ChangeSetId: new(api.ChangeSetId(v.ID)), ChangeSetName: new(api.ChangeSetName(v.Name)), StackId: new(api.StackId(v.StackID)), StackName: new(api.StackName(v.StackName)), Status: new(api.ChangeSetStatus(v.Status)), ExecutionStatus: new(api.ExecutionStatus(v.ExecutionStatus)), CreationTime: new(v.Created), Description: new(api.Description(v.Description)), StatusReason: new(api.ChangeSetStatusReason(v.Reason))})
	}
	return out, nil
}
func (s *Service) listExports(tx Transaction, in *api.ListExportsInput) (*api.ListExportsOutput, error) {
	if e := s.authorize(tx, "ListExports", StackRecord{}); e != nil {
		return nil, e
	}
	rows, e := tx.Exports(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	rows, next, e := page(tx, "ListExports", "", text(in.NextToken), rows, func(v ExportRecord) string { return v.Name })
	if e != nil {
		return nil, e
	}
	out := &api.ListExportsOutput{NextToken: next, Exports: api.Exports{}}
	for _, v := range rows {
		out.Exports = append(out.Exports, api.Export{Name: new(api.ExportName(v.Name)), Value: new(api.ExportValue(v.Value)), ExportingStackId: new(api.StackId(v.StackID))})
	}
	return out, nil
}
func (s *Service) listImports(tx Transaction, in *api.ListImportsInput) (*api.ListImportsOutput, error) {
	if e := s.authorize(tx, "ListImports", StackRecord{}); e != nil {
		return nil, e
	}
	exports, e := tx.Exports(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	found := false
	for _, v := range exports {
		if v.Name == text(in.ExportName) {
			found = true
		}
	}
	if !found {
		return nil, invalid("Export does not exist")
	}
	stacks, e := tx.Stacks(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	rows := []string{}
	for _, v := range stacks {
		if v.Deleted == nil && slices.Contains(v.Imports, text(in.ExportName)) {
			rows = append(rows, v.Name)
		}
	}
	slices.Sort(rows)
	rows, next, e := page(tx, "ListImports", text(in.ExportName), text(in.NextToken), rows, func(v string) string { return v })
	if e != nil {
		return nil, e
	}
	out := &api.ListImportsOutput{NextToken: next, Imports: api.Imports{}}
	for _, v := range rows {
		out.Imports = append(out.Imports, api.StackName(v))
	}
	return out, nil
}
func (s *Service) getTemplate(tx Transaction, in *api.GetTemplateInput) (*api.GetTemplateOutput, error) {
	if text(in.TemplateStage) != "" && text(in.TemplateStage) != "Original" {
		return nil, failure("NotImplementedException", "Processed template retrieval is not implemented.", 501)
	}
	var body string
	var stack StackRecord
	var e error
	if text(in.ChangeSetName) != "" {
		v, e := findChangeSet(tx, text(in.ChangeSetName), text(in.StackName))
		if e != nil {
			return nil, e
		}
		stack, e = findStack(tx, v.StackID)
		if e != nil {
			return nil, e
		}
		body = v.Template
	} else {
		stack, e = findStack(tx, text(in.StackName))
		if e != nil {
			return nil, e
		}
		body = stack.Template
		if body == "" && stack.OperationID != "" {
			op, e := tx.Operation(stack.OperationID)
			if e != nil {
				return nil, e
			}
			body = op.Template
		}
	}
	if e = checkNestedStackOwner(tx, stack); e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "GetTemplate", stack); e != nil {
		return nil, e
	}
	return &api.GetTemplateOutput{TemplateBody: new(api.TemplateBody(body)), StagesAvailable: api.StageList{api.TemplateStage("Original")}}, nil
}
func (s *Service) validateTemplate(tx Transaction, in *api.ValidateTemplateInput) (*api.ValidateTemplateOutput, error) {
	if e := s.authorize(tx, "ValidateTemplate", StackRecord{}); e != nil {
		return nil, e
	}
	body, e := s.templateBody(tx.Context(), text(in.TemplateBody), text(in.TemplateURL), false, "")
	if e != nil {
		return nil, e
	}
	t, e := ParseTemplate(body)
	if e != nil {
		return nil, e
	}
	if e = t.ValidateHandlers(s.handlers); e != nil {
		return nil, e
	}
	out := &api.ValidateTemplateOutput{Description: new(api.Description(t.Description)), Capabilities: capabilitiesOutput(t.Capabilities()), Parameters: api.TemplateParameters{}}
	for _, k := range slices.Sorted(maps.Keys(t.Parameters)) {
		p := t.Parameters[k]
		v := api.TemplateParameter{ParameterKey: new(api.ParameterKey(k)), NoEcho: new(api.NoEcho(p.NoEcho)), Description: new(api.Description(p.Description))}
		if p.Default != nil {
			v.DefaultValue = new(api.ParameterValue(fmt.Sprint(p.Default)))
		}
		out.Parameters = append(out.Parameters, v)
	}
	return out, nil
}
func (s *Service) templateSummary(tx Transaction, in *api.GetTemplateSummaryInput) (*api.GetTemplateSummaryOutput, error) {
	if e := supportedInput(in, "TemplateBody", "TemplateURL", "StackName"); e != nil {
		return nil, e
	}
	body := text(in.TemplateBody)
	stack := StackRecord{}
	if text(in.StackName) != "" {
		if body != "" || text(in.TemplateURL) != "" {
			return nil, invalid("Specify TemplateBody, TemplateURL or StackName, not more than one")
		}
		v, e := findStack(tx, text(in.StackName))
		if e != nil {
			return nil, e
		}
		stack = v
		body = v.Template
	}
	if e := s.authorize(tx, "GetTemplateSummary", stack); e != nil {
		return nil, e
	}
	if text(in.StackName) == "" {
		var err error
		body, err = s.templateBody(tx.Context(), body, text(in.TemplateURL), false, "")
		if err != nil {
			return nil, err
		}
	}
	t, e := ParseTemplate(body)
	if e != nil {
		return nil, e
	}
	if e = t.ValidateHandlers(s.handlers); e != nil {
		return nil, e
	}
	out := &api.GetTemplateSummaryOutput{Description: new(api.Description(t.Description)), Capabilities: capabilitiesOutput(t.Capabilities()), Parameters: api.ParameterDeclarations{}, ResourceTypes: api.ResourceTypes{}, Version: new(api.Version("2010-09-09"))}
	for _, k := range slices.Sorted(maps.Keys(t.Parameters)) {
		p := t.Parameters[k]
		v := api.ParameterDeclaration{ParameterKey: new(api.ParameterKey(k)), ParameterType: new(api.ParameterType(p.Type)), NoEcho: new(api.NoEcho(p.NoEcho)), Description: new(api.Description(p.Description))}
		if p.Default != nil {
			v.DefaultValue = new(api.ParameterValue(fmt.Sprint(p.Default)))
		}
		out.Parameters = append(out.Parameters, v)
	}
	types := map[string]bool{}
	for _, v := range t.Resources {
		types[v.Type] = true
	}
	for _, name := range slices.Sorted(maps.Keys(types)) {
		out.ResourceTypes = append(out.ResourceTypes, api.ResourceType(name))
	}
	return out, nil
}
