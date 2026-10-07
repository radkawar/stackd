package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	api "stackd/internal/awsapi/servicecatalogappregistry"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	appregistry "stackd/internal/services/servicecatalogappregistry"
)

// Service Catalog AppRegistry:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_ServiceCatalogAppRegistry.html

func cfnAppRegMissing(err error) bool {
	return cfnMessagingMissing(err, "ResourceNotFoundException")
}

// cfnAppRegTags validates the string-map Tags property of AppRegistry types.
func cfnAppRegTags(p cloudformation.Properties) (map[string]string, error) {
	out := map[string]string{}
	v, ok := p["Tags"]
	if !ok {
		return out, nil
	}
	raw, ok := cfnComputeObject(v)
	if !ok {
		return nil, fmt.Errorf("tags must be a string map")
	}
	for key, value := range raw {
		text, ok := value.(string)
		lower := strings.ToLower(key)
		if !ok || key == "" || strings.HasPrefix(lower, "aws:") {
			return nil, fmt.Errorf("invalid or reserved tag %q", key)
		}
		out[key] = text
	}
	return out, nil
}

// cfnAppRegDesiredTags is the customer tag set; ownership never rides on tags.
func cfnAppRegDesiredTags(r cloudformation.ResourceRequest) map[string]string {
	tags := make(map[string]string, len(r.Tags))
	for k, v := range r.Tags {
		tags[k] = v
	}
	own, _ := cfnAppRegTags(r.Properties)
	for k, v := range own {
		tags[k] = v
	}
	return tags
}

func cfnAppRegMapTags(tags map[string]string) map[string]any {
	out := map[string]any{}
	for key, value := range tags {
		lower := strings.ToLower(key)
		if !strings.HasPrefix(lower, "aws:") {
			out[key] = value
		}
	}
	return out
}

// cfnAppRegClaim names one stack resource incarnation. The owner retains it
// privately only from trusted creation context, alongside native ClientToken
// receipts or on association edges; never from public input or tags.
func cfnAppRegClaim(r cloudformation.ResourceRequest) string {
	return cfnMessagingHash(r.StackID + "\x00" + r.LogicalID + "\x00" + r.Token)
}

func cfnAppRegIncarnation(r cloudformation.ResourceRequest) error {
	if r.StackID == "" || r.LogicalID == "" || r.Token == "" {
		return fmt.Errorf("resource %s has no CloudFormation incarnation to verify ownership", r.LogicalID)
	}
	return nil
}

// cfnAppRegParent fences CloudFormation mutations of an application or
// attribute group inside each owner transaction to its private creation
// provenance. Cloud Control acts under current IAM authority alone.
func cfnAppRegParent(ctx context.Context, r cloudformation.ResourceRequest) (context.Context, error) {
	if r.CloudControl {
		return ctx, nil
	}
	if err := cfnAppRegIncarnation(r); err != nil {
		return nil, err
	}
	if r.PhysicalID == "" {
		return nil, fmt.Errorf("resource %s has no physical identity to verify ownership", r.LogicalID)
	}
	return appregistry.WithCloudFormationOwnership(ctx, appregistry.CloudFormationOwnership{Claim: cfnAppRegClaim(r), Target: r.PhysicalID}), nil
}

// cfnAppRegEdge claims a new association edge inside the owner transaction,
// requires that claim for disassociation and, with owned, observes the edges
// retained with it. It never borrows a parent's claim.
func cfnAppRegEdge(ctx context.Context, r cloudformation.ResourceRequest, owned map[string]bool) (context.Context, error) {
	if err := cfnAppRegIncarnation(r); err != nil {
		return nil, err
	}
	return appregistry.WithCloudFormationOwnership(ctx, appregistry.CloudFormationOwnership{Claim: cfnAppRegClaim(r), Edge: true, Owned: owned}), nil
}

// cfnAppRegObserved keeps dependency absence during recovery from being
// mistaken for proof that this incarnation was never admitted.
func cfnAppRegObserved(err error) error {
	if cfnAppRegMissing(err) {
		return fmt.Errorf("AppRegistry recovery observation is unavailable: %s", err.Error())
	}
	return err
}

func cfnAppRegNotAdmitted(kind string) error {
	return &awswire.Error{Code: "ResourceNotFoundException", Message: "This CloudFormation incarnation has no admitted " + kind + ".", StatusCode: 404}
}

// cfnAppRegOwnedIDs observes the identities a list operation retains with
// this incarnation's private claim. Observation covers every row, not a page.
func cfnAppRegOwnedIDs(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, edge bool, operation string, in map[string]any) ([]string, error) {
	owned := map[string]bool{}
	var observe context.Context
	if edge {
		var err error
		if observe, err = cfnAppRegEdge(ctx, r, owned); err != nil {
			return nil, err
		}
	} else {
		if err := cfnAppRegIncarnation(r); err != nil {
			return nil, err
		}
		observe = appregistry.WithCloudFormationOwnership(ctx, appregistry.CloudFormationOwnership{Claim: cfnAppRegClaim(r), Owned: owned})
	}
	in["MaxResults"] = 1
	if err := cfnComputeRun(observe, c, "servicecatalogappregistry", operation, in); err != nil {
		return nil, cfnAppRegObserved(err)
	}
	ids := make([]string, 0, len(owned))
	for id := range owned {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) > 1 {
		return nil, fmt.Errorf("CloudFormation incarnation %s claims %d AppRegistry resources", r.LogicalID, len(ids))
	}
	return ids, nil
}

// cfnAppRegCreateFailure returns this incarnation's authentic admitted
// identity with a failure observed after native admission.
func cfnAppRegCreateFailure(ctx context.Context, r cloudformation.ResourceRequest, h cloudformation.ResourceCreationRecoverer, cause error) (cloudformation.ResourceResult, error) {
	result, err := h.RecoverCreation(ctx, r)
	if result.PhysicalID != "" {
		if err == nil {
			return result, cause
		}
		return result, errors.Join(cause, err)
	}
	if cfnMessagingMissing(cause, "ConflictException") {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, cause)
	}
	return cloudformation.ResourceResult{}, cause
}

func cfnAppRegTagger(c StepFunctionsCommands, arn string) cfnAppTagged {
	return cfnAppTagged{
		list: func(ctx context.Context) (map[string]string, error) {
			out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, c, "servicecatalogappregistry", "ListTagsForResource", map[string]any{"ResourceArn": arn})
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
			return cfnComputeRun(ctx, c, "servicecatalogappregistry", "TagResource", map[string]any{"ResourceArn": arn, "Tags": tags})
		},
		untag: func(ctx context.Context, keys []string) error {
			return cfnComputeRun(ctx, c, "servicecatalogappregistry", "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": keys})
		},
	}
}

func cfnAppRegPages[O any, I any](ctx context.Context, c StepFunctionsCommands, operation string, in map[string]any, page func(*O) ([]I, *api.NextToken)) ([]I, error) {
	var rows []I
	for {
		out, err := cfnComputeCall[O](ctx, c, "servicecatalogappregistry", operation, in)
		if err != nil {
			return nil, err
		}
		items, next := page(out)
		rows = append(rows, items...)
		token := cfnComputeValue(next)
		if token == "" {
			return rows, nil
		}
		if token == in["NextToken"] {
			return nil, fmt.Errorf("AppRegistry %s pagination did not advance", operation)
		}
		in["NextToken"] = token
	}
}

type cfnAppRegApplication struct{ commands StepFunctionsCommands }

func (h cfnAppRegApplication) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Description"); err != nil {
		return err
	}
	_, err := cfnAppRegTags(p)
	return err
}
func (h cfnAppRegApplication) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}

func (h cfnAppRegApplication) get(ctx context.Context, id string) (*api.GetApplicationResponse, error) {
	return cfnComputeCall[api.GetApplicationOutput](ctx, h.commands, "servicecatalogappregistry", "GetApplication", map[string]any{"Application": id})
}

func cfnAppRegApplicationResult(id, arn, name string, tag api.ApplicationTagDefinition) cloudformation.ResourceResult {
	attributes := map[string]any{"Id": id, "Arn": arn, "ApplicationName": name}
	for key, value := range tag {
		attributes["ApplicationTagKey"], attributes["ApplicationTagValue"] = string(key), string(value)
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: attributes}
}

func (h cfnAppRegApplication) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnAppRegIncarnation(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "Name", "Description")
	in["Tags"], in["ClientToken"] = cfnAppRegDesiredTags(r), cfnAppRegClaim(r)
	claimed := appregistry.WithCloudFormationOwnership(ctx, appregistry.CloudFormationOwnership{Claim: cfnAppRegClaim(r)})
	out, err := cfnComputeCall[api.CreateApplicationOutput](claimed, h.commands, "servicecatalogappregistry", "CreateApplication", in)
	if err == nil && out.Application == nil {
		err = fmt.Errorf("AppRegistry returned no application")
	}
	if err != nil {
		return cfnAppRegCreateFailure(ctx, r, h, err)
	}
	a := out.Application
	return cfnAppRegApplicationResult(cfnComputeValue(a.Id), cfnComputeValue(a.Arn), cfnComputeValue(a.Name), a.ApplicationTag), nil
}

// RecoverCreation observes only the application whose private trusted creation
// provenance names this exact incarnation.
func (h cfnAppRegApplication) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ids, err := cfnAppRegOwnedIDs(ctx, h.commands, r, false, "ListApplications", map[string]any{})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if len(ids) == 0 {
		return cloudformation.ResourceResult{}, cfnAppRegNotAdmitted("application")
	}
	a, err := h.get(ctx, ids[0])
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: ids[0], Ref: ids[0]}, cfnAppRegObserved(err)
	}
	return cfnAppRegApplicationResult(ids[0], cfnComputeValue(a.Arn), cfnComputeValue(a.Name), a.ApplicationTag), nil
}

func (h cfnAppRegApplication) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	fenced, err := cfnAppRegParent(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	a, err := h.get(fenced, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags := map[string]string{}
	for k, v := range a.Tags {
		tags[string(k)] = string(v)
	}
	arn := cfnComputeValue(a.Arn)
	in := map[string]any{"Application": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", "")}
	if name := cfnComputeString(r.Properties, "Name"); name != cfnComputeValue(a.Name) {
		in["Name"] = name
	}
	result := cfnAppRegApplicationResult(r.PhysicalID, arn, cfnComputeValue(a.Name), a.ApplicationTag)
	updated, err := cfnComputeCall[api.UpdateApplicationOutput](fenced, h.commands, "servicecatalogappregistry", "UpdateApplication", in)
	if err != nil {
		return result, err
	}
	if updated.Application != nil {
		result = cfnAppRegApplicationResult(r.PhysicalID, arn, cfnComputeValue(updated.Application.Name), a.ApplicationTag)
	}
	t := cfnAppRegTagger(h.commands, arn)
	return result, cfnAppTagSync(fenced, tags, cfnAppRegDesiredTags(r), t.tag, t.untag)
}

// Delete is fenced inside the owner's DeleteApplication transaction; another
// incarnation's application is absent to this one and remains intact.
func (h cfnAppRegApplication) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	fenced, err := cfnAppRegParent(ctx, r)
	if err != nil {
		return err
	}
	err = cfnComputeRun(fenced, h.commands, "servicecatalogappregistry", "DeleteApplication", map[string]any{"Application": r.PhysicalID})
	if cfnAppRegMissing(err) {
		return nil
	}
	return err
}

func (h cfnAppRegApplication) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	a, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for k, v := range a.Tags {
		tags[string(k)] = string(v)
	}
	p := cloudformation.Properties(cfnAppRegApplicationResult(cfnComputeValue(a.Id), cfnComputeValue(a.Arn), cfnComputeValue(a.Name), a.ApplicationTag).Attributes)
	p["Name"], p["Tags"] = cfnComputeValue(a.Name), cfnAppRegMapTags(tags)
	if a.Description != nil {
		p["Description"] = cfnComputeValue(a.Description)
	}
	return p, nil
}

func (h cfnAppRegApplication) applications(ctx context.Context) ([]api.ApplicationSummary, error) {
	return cfnAppRegPages(ctx, h.commands, "ListApplications", map[string]any{}, func(o *api.ListApplicationsOutput) ([]api.ApplicationSummary, *api.NextToken) {
		return o.Applications, o.NextToken
	})
}

func (h cfnAppRegApplication) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := h.applications(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(rows))
	for _, row := range rows {
		id := cfnComputeValue(row.Id)
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Id": id, "Arn": cfnComputeValue(row.Arn), "Name": cfnComputeValue(row.Name)}})
	}
	return out, nil
}

type cfnAppRegAttributeGroup struct{ commands StepFunctionsCommands }

func (h cfnAppRegAttributeGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "Attributes", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Name", "Attributes"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "Description"); err != nil {
		return err
	}
	if _, err := cfnComputeDocument(p["Attributes"]); err != nil {
		return fmt.Errorf("attributes: %w", err)
	}
	_, err := cfnAppRegTags(p)
	return err
}
func (h cfnAppRegAttributeGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}

func cfnAppRegAttributeGroupResult(id, arn string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "Arn": arn}}
}

func (h cfnAppRegAttributeGroup) get(ctx context.Context, id string) (*api.GetAttributeGroupResponse, error) {
	return cfnComputeCall[api.GetAttributeGroupOutput](ctx, h.commands, "servicecatalogappregistry", "GetAttributeGroup", map[string]any{"AttributeGroup": id})
}

func (h cfnAppRegAttributeGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnAppRegIncarnation(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	attributes, _ := cfnComputeDocument(r.Properties["Attributes"])
	in := cfnComputeCopy(r.Properties, "Name", "Description")
	in["Attributes"], in["Tags"], in["ClientToken"] = attributes, cfnAppRegDesiredTags(r), cfnAppRegClaim(r)
	claimed := appregistry.WithCloudFormationOwnership(ctx, appregistry.CloudFormationOwnership{Claim: cfnAppRegClaim(r)})
	out, err := cfnComputeCall[api.CreateAttributeGroupOutput](claimed, h.commands, "servicecatalogappregistry", "CreateAttributeGroup", in)
	if err == nil && out.AttributeGroup == nil {
		err = fmt.Errorf("AppRegistry returned no attribute group")
	}
	if err != nil {
		return cfnAppRegCreateFailure(ctx, r, h, err)
	}
	return cfnAppRegAttributeGroupResult(cfnComputeValue(out.AttributeGroup.Id), cfnComputeValue(out.AttributeGroup.Arn)), nil
}

// RecoverCreation observes only the attribute group whose private trusted
// creation provenance names this exact incarnation.
func (h cfnAppRegAttributeGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ids, err := cfnAppRegOwnedIDs(ctx, h.commands, r, false, "ListAttributeGroups", map[string]any{})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if len(ids) == 0 {
		return cloudformation.ResourceResult{}, cfnAppRegNotAdmitted("attribute group")
	}
	g, err := h.get(ctx, ids[0])
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: ids[0], Ref: ids[0]}, cfnAppRegObserved(err)
	}
	return cfnAppRegAttributeGroupResult(ids[0], cfnComputeValue(g.Arn)), nil
}

func (h cfnAppRegAttributeGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	fenced, err := cfnAppRegParent(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	g, err := h.get(fenced, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags := map[string]string{}
	for k, v := range g.Tags {
		tags[string(k)] = string(v)
	}
	arn := cfnComputeValue(g.Arn)
	result := cfnAppRegAttributeGroupResult(r.PhysicalID, arn)
	attributes, _ := cfnComputeDocument(r.Properties["Attributes"])
	in := map[string]any{"AttributeGroup": r.PhysicalID, "Attributes": attributes, "Description": cfnComputeDefault(r.Properties, "Description", "")}
	if name := cfnComputeString(r.Properties, "Name"); name != cfnComputeValue(g.Name) {
		in["Name"] = name
	}
	if err := cfnComputeRun(fenced, h.commands, "servicecatalogappregistry", "UpdateAttributeGroup", in); err != nil {
		return result, err
	}
	t := cfnAppRegTagger(h.commands, arn)
	return result, cfnAppTagSync(fenced, tags, cfnAppRegDesiredTags(r), t.tag, t.untag)
}

// Delete is fenced inside the owner's DeleteAttributeGroup transaction.
func (h cfnAppRegAttributeGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	fenced, err := cfnAppRegParent(ctx, r)
	if err != nil {
		return err
	}
	err = cfnComputeRun(fenced, h.commands, "servicecatalogappregistry", "DeleteAttributeGroup", map[string]any{"AttributeGroup": r.PhysicalID})
	if cfnAppRegMissing(err) {
		return nil
	}
	return err
}

func (h cfnAppRegAttributeGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	g, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	var attributes any
	if err := json.Unmarshal([]byte(cfnComputeValue(g.Attributes)), &attributes); err != nil {
		return nil, fmt.Errorf("invalid owner attributes: %w", err)
	}
	tags := map[string]string{}
	for k, v := range g.Tags {
		tags[string(k)] = string(v)
	}
	p := cloudformation.Properties{"Id": cfnComputeValue(g.Id), "Arn": cfnComputeValue(g.Arn), "Name": cfnComputeValue(g.Name), "Attributes": attributes, "Tags": cfnAppRegMapTags(tags)}
	if g.Description != nil {
		p["Description"] = cfnComputeValue(g.Description)
	}
	return p, nil
}

func (h cfnAppRegAttributeGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := cfnAppRegPages(ctx, h.commands, "ListAttributeGroups", map[string]any{}, func(o *api.ListAttributeGroupsOutput) ([]api.AttributeGroupSummary, *api.NextToken) {
		return o.AttributeGroups, o.NextToken
	})
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(rows))
	for _, row := range rows {
		id := cfnComputeValue(row.Id)
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"Id": id, "Arn": cfnComputeValue(row.Arn), "Name": cfnComputeValue(row.Name)}})
	}
	return out, nil
}

// cfnAppRegAttributeAssociation associates an attribute group with an
// application. The owner retains this incarnation's private claim on the edge.
type cfnAppRegAttributeAssociation struct{ commands StepFunctionsCommands }

func (h cfnAppRegAttributeAssociation) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Application", "AttributeGroup"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Application", "AttributeGroup"); err != nil {
		return err
	}
	return cfnComputeStrings(p, "Application", "AttributeGroup")
}
func (h cfnAppRegAttributeAssociation) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Application", "AttributeGroup"), h.Validate(b)
}

func cfnAppRegPairResult(physical, applicationARN, otherKey, otherARN string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: physical, Ref: physical, Attributes: map[string]any{"ApplicationArn": applicationARN, otherKey: otherARN}}
}

// edge resolves both sides of the association through their owners.
func (h cfnAppRegAttributeAssociation) edge(ctx context.Context, application, group string) (*api.GetApplicationResponse, *api.GetAttributeGroupResponse, error) {
	a, err := (cfnAppRegApplication(h)).get(ctx, application)
	if err != nil {
		return nil, nil, err
	}
	g, err := (cfnAppRegAttributeGroup(h)).get(ctx, group)
	return a, g, err
}

func (h cfnAppRegAttributeAssociation) associated(ctx context.Context, application, group string) (bool, error) {
	ids, err := cfnAppRegPages(ctx, h.commands, "ListAssociatedAttributeGroups", map[string]any{"Application": application}, func(o *api.ListAssociatedAttributeGroupsOutput) ([]api.AttributeGroupId, *api.NextToken) {
		return o.AttributeGroups, o.NextToken
	})
	if err != nil {
		return false, err
	}
	return slices.Contains(ids, api.AttributeGroupId(group)), nil
}

func (h cfnAppRegAttributeAssociation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	claimed, err := cfnAppRegEdge(ctx, r, nil)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	a, g, err := h.edge(ctx, cfnComputeString(r.Properties, "Application"), cfnComputeString(r.Properties, "AttributeGroup"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	appARN, groupARN := cfnComputeValue(a.Arn), cfnComputeValue(g.Arn)
	// The owner claims a new edge, or replays one carrying this exact claim,
	// in the association transaction; any other existing edge is a conflict.
	if err := cfnComputeRun(claimed, h.commands, "servicecatalogappregistry", "AssociateAttributeGroup", map[string]any{"Application": appARN, "AttributeGroup": groupARN}); err != nil {
		return cfnAppRegCreateFailure(ctx, r, h, err)
	}
	return cfnAppRegPairResult(appARN+"|"+groupARN, appARN, "AttributeGroupArn", groupARN), nil
}

// RecoverCreation observes only an edge retained with this exact claim.
func (h cfnAppRegAttributeAssociation) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	a, g, err := h.edge(ctx, cfnComputeString(r.Properties, "Application"), cfnComputeString(r.Properties, "AttributeGroup"))
	if err != nil {
		return cloudformation.ResourceResult{}, cfnAppRegObserved(err)
	}
	appARN, groupARN := cfnComputeValue(a.Arn), cfnComputeValue(g.Arn)
	owned, err := cfnAppRegOwnedIDs(ctx, h.commands, r, true, "ListAssociatedAttributeGroups", map[string]any{"Application": appARN})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if !slices.Contains(owned, groupARN) {
		return cloudformation.ResourceResult{}, cfnAppRegNotAdmitted("attribute group association")
	}
	return cfnAppRegPairResult(appARN+"|"+groupARN, appARN, "AttributeGroupArn", groupARN), nil
}

func (h cfnAppRegAttributeAssociation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if changed, err := h.Replacement(r.Previous, r.Properties); err != nil || changed {
		if err == nil {
			err = fmt.Errorf("attribute group association properties are create-only")
		}
		return cloudformation.ResourceResult{}, err
	}
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if r.CloudControl {
		if _, err := h.Read(ctx, r); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	} else {
		owned, err := h.RecoverCreation(ctx, r)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if owned.PhysicalID != r.PhysicalID {
			return cloudformation.ResourceResult{}, fmt.Errorf("attribute association is not owned by this incarnation")
		}
	}
	return cfnAppRegPairResult(r.PhysicalID, parts[0], "AttributeGroupArn", parts[1]), nil
}

// Delete is fenced inside the owner's disassociation transaction. An edge
// another incarnation or a direct caller recreated is absent to this one.
// Cloud Control disassociates under current IAM authority alone.
func (h cfnAppRegAttributeAssociation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return err
	}
	fenced := ctx
	if !r.CloudControl {
		if fenced, err = cfnAppRegEdge(ctx, r, nil); err != nil {
			return err
		}
	}
	err = cfnComputeRun(fenced, h.commands, "servicecatalogappregistry", "DisassociateAttributeGroup", map[string]any{"Application": parts[0], "AttributeGroup": parts[1]})
	if err != nil && !cfnAppRegMissing(err) {
		return err
	}
	return nil
}

func (h cfnAppRegAttributeAssociation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	parts, err := cfnAppParts(r.PhysicalID, 2)
	if err != nil {
		return nil, err
	}
	a, g, err := h.edge(ctx, parts[0], parts[1])
	if err != nil {
		return nil, err
	}
	exists, err := h.associated(ctx, cfnComputeValue(a.Id), cfnComputeValue(g.Id))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "The attribute group is not associated with the application.", StatusCode: 404}
	}
	return cloudformation.Properties{"Application": cfnComputeValue(a.Id), "AttributeGroup": cfnComputeValue(g.Id), "ApplicationArn": parts[0], "AttributeGroupArn": parts[1]}, nil
}

func (h cfnAppRegAttributeAssociation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apps, err := (cfnAppRegApplication(h)).applications(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, app := range apps {
		appARN := cfnComputeValue(app.Arn)
		rows, err := cfnAppRegPages(ctx, h.commands, "ListAttributeGroupsForApplication", map[string]any{"Application": cfnComputeValue(app.Id)}, func(o *api.ListAttributeGroupsForApplicationOutput) ([]api.AttributeGroupDetails, *api.NextToken) {
			return o.AttributeGroupsDetails, o.NextToken
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			groupARN := cfnComputeValue(row.Arn)
			out = append(out, cloudformation.ResourceDescription{Identifier: appARN + "|" + groupARN, Properties: cloudformation.Properties{"ApplicationArn": appARN, "AttributeGroupArn": groupARN}})
		}
	}
	return out, nil
}

// cfnAppRegResourceAssociation associates a CloudFormation stack with an
// application. The owner retains this incarnation's private claim on the edge.
type cfnAppRegResourceAssociation struct{ commands StepFunctionsCommands }

func (h cfnAppRegResourceAssociation) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Application", "Resource", "ResourceType"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Application", "Resource", "ResourceType"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Application", "Resource", "ResourceType"); err != nil {
		return err
	}
	if cfnComputeString(p, "ResourceType") != "CFN_STACK" {
		return fmt.Errorf("ResourceType must be CFN_STACK")
	}
	return nil
}
func (h cfnAppRegResourceAssociation) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Application", "Resource", "ResourceType"), h.Validate(b)
}

func (h cfnAppRegResourceAssociation) association(ctx context.Context, application, resource, kind string) (*api.GetAssociatedResourceResponse, error) {
	return cfnComputeCall[api.GetAssociatedResourceOutput](ctx, h.commands, "servicecatalogappregistry", "GetAssociatedResource", map[string]any{"Application": application, "Resource": resource, "ResourceType": kind})
}

func (h cfnAppRegResourceAssociation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	claimed, err := cfnAppRegEdge(ctx, r, nil)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	a, err := (cfnAppRegApplication(h)).get(ctx, cfnComputeString(r.Properties, "Application"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	appARN := cfnComputeValue(a.Arn)
	resource, kind := cfnComputeString(r.Properties, "Resource"), cfnComputeString(r.Properties, "ResourceType")
	// The owner claims a new edge, or replays one carrying this exact claim,
	// in the association transaction; any other existing edge is a conflict.
	out, err := cfnComputeCall[api.AssociateResourceOutput](claimed, h.commands, "servicecatalogappregistry", "AssociateResource", map[string]any{"Application": appARN, "Resource": resource, "ResourceType": kind})
	if err == nil && cfnComputeValue(out.ResourceArn) == "" {
		err = fmt.Errorf("AppRegistry returned no associated resource")
	}
	if err != nil {
		return cfnAppRegCreateFailure(ctx, r, h, err)
	}
	arn := cfnComputeValue(out.ResourceArn)
	return cfnAppRegPairResult(appARN+"|"+arn+"|"+kind, appARN, "ResourceArn", arn), nil
}

// RecoverCreation observes only an edge retained with this exact claim.
func (h cfnAppRegResourceAssociation) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	a, err := (cfnAppRegApplication(h)).get(ctx, cfnComputeString(r.Properties, "Application"))
	if err != nil {
		return cloudformation.ResourceResult{}, cfnAppRegObserved(err)
	}
	appARN, kind := cfnComputeValue(a.Arn), cfnComputeString(r.Properties, "ResourceType")
	owned, err := cfnAppRegOwnedIDs(ctx, h.commands, r, true, "ListAssociatedResources", map[string]any{"Application": appARN})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if len(owned) == 0 {
		return cloudformation.ResourceResult{}, cfnAppRegNotAdmitted("resource association")
	}
	return cfnAppRegPairResult(appARN+"|"+owned[0]+"|"+kind, appARN, "ResourceArn", owned[0]), nil
}

func (h cfnAppRegResourceAssociation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if changed, err := h.Replacement(r.Previous, r.Properties); err != nil || changed {
		if err == nil {
			err = fmt.Errorf("resource association properties are create-only")
		}
		return cloudformation.ResourceResult{}, err
	}
	parts, err := cfnAppParts(r.PhysicalID, 3)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if r.CloudControl {
		if _, err := h.Read(ctx, r); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	} else {
		owned, err := h.RecoverCreation(ctx, r)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if owned.PhysicalID != r.PhysicalID {
			return cloudformation.ResourceResult{}, fmt.Errorf("resource association is not owned by this incarnation")
		}
	}
	return cfnAppRegPairResult(r.PhysicalID, parts[0], "ResourceArn", parts[1]), nil
}

// Delete is fenced inside the owner's disassociation transaction. An edge
// another incarnation or a direct caller recreated is absent to this one.
// Cloud Control disassociates under current IAM authority alone.
func (h cfnAppRegResourceAssociation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	parts, err := cfnAppParts(r.PhysicalID, 3)
	if err != nil {
		return err
	}
	fenced := ctx
	if !r.CloudControl {
		if fenced, err = cfnAppRegEdge(ctx, r, nil); err != nil {
			return err
		}
	}
	err = cfnComputeRun(fenced, h.commands, "servicecatalogappregistry", "DisassociateResource", map[string]any{"Application": parts[0], "Resource": parts[1], "ResourceType": parts[2]})
	if err != nil && !cfnAppRegMissing(err) {
		return err
	}
	return nil
}

func (h cfnAppRegResourceAssociation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	parts, err := cfnAppParts(r.PhysicalID, 3)
	if err != nil {
		return nil, err
	}
	out, err := h.association(ctx, parts[0], parts[1], parts[2])
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"Application": parts[0], "ApplicationArn": parts[0], "Resource": parts[1], "ResourceArn": parts[1], "ResourceType": parts[2]}
	if out.Resource != nil && out.Resource.Name != nil {
		p["Resource"] = cfnComputeValue(out.Resource.Name)
	}
	return p, nil
}

func (h cfnAppRegResourceAssociation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apps, err := (cfnAppRegApplication(h)).applications(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	for _, app := range apps {
		appARN := cfnComputeValue(app.Arn)
		rows, err := cfnAppRegPages(ctx, h.commands, "ListAssociatedResources", map[string]any{"Application": cfnComputeValue(app.Id)}, func(o *api.ListAssociatedResourcesOutput) ([]api.ResourceInfo, *api.NextToken) {
			return o.Resources, o.NextToken
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if kind := cfnComputeValue(row.ResourceType); kind == "CFN_STACK" {
				arn := cfnComputeValue(row.Arn)
				out = append(out, cloudformation.ResourceDescription{Identifier: appARN + "|" + arn + "|" + kind, Properties: cloudformation.Properties{"ApplicationArn": appARN, "ResourceArn": arn, "ResourceType": kind}})
			}
		}
	}
	return out, nil
}
