package appconfig

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/appconfig"
)

func registerExtensions(s *Service) {
	register(s, "CreateExtension", s.createExtension)
	register(s, "GetExtension", s.getExtension)
	register(s, "UpdateExtension", s.updateExtension)
	register(s, "DeleteExtension", s.deleteExtension)
	register(s, "ListExtensions", s.listExtensions)
	register(s, "CreateExtensionAssociation", s.createExtensionAssociation)
	register(s, "GetExtensionAssociation", s.getExtensionAssociation)
	register(s, "UpdateExtensionAssociation", s.updateExtensionAssociation)
	register(s, "DeleteExtensionAssociation", s.deleteExtensionAssociation)
	register(s, "ListExtensionAssociations", s.listExtensionAssociations)
}
func extensionARN(scope Scope, id string, version int32) string {
	return arn(scope, "extension/"+id+"/"+strconv.FormatInt(int64(version), 10))
}
func associationARN(scope Scope, id string) string { return arn(scope, "extensionassociation/"+id) }
func findExtension(r Reader, scope Scope, identifier string, version int32) (Extension, error) {
	if strings.HasPrefix(identifier, "arn:") {
		parsed, err := awsarn.Parse(identifier)
		if err != nil || parsed.Partition != scope.Partition || parsed.AccountID != scope.AccountID || parsed.Region != scope.Region || parsed.Service != "appconfig" {
			return Extension{}, failure("ResourceNotFoundException", "Extension not found: "+identifier)
		}
		parts := strings.Split(parsed.Resource, "/")
		if len(parts) == 3 {
			n, e := strconv.ParseInt(parts[2], 10, 32)
			if e != nil || n < 1 {
				return Extension{}, failure("BadRequestException", "Invalid extension version ARN.")
			}
			if version != 0 && version != int32(n) {
				return Extension{}, failure("BadRequestException", "Extension ARN and version number disagree.")
			}
			version = int32(n)
		}
	}
	rows, err := r.Extensions(scope)
	if err != nil {
		return Extension{}, err
	}
	var found Extension
	for _, row := range rows {
		match := identifier == row.ID || identifier == row.Name || identifier == row.ARN || identifier == arn(scope, "extension/"+row.ID)
		if match && (version == 0 || version == row.Version) && row.Version > found.Version {
			found = row
		}
	}
	if found.ID == "" {
		return found, failure("ResourceNotFoundException", "Extension not found: "+identifier)
	}
	return found, nil
}
func findAssociation(r Reader, scope Scope, id string) (Association, error) {
	rows, err := r.Associations(scope)
	if err != nil {
		return Association{}, err
	}
	for _, row := range rows {
		if row.ID == id {
			return row, nil
		}
	}
	return Association{}, failure("ResourceNotFoundException", "Extension association not found: "+id)
}
func extensionOutput(row Extension) *api.Extension {
	out := &api.Extension{Id: new(api.Id(row.ID)), Arn: new(api.Arn(row.ARN)), Name: new(api.Name(row.Name)), Description: new(api.Description(row.Description)), VersionNumber: new(api.Integer(row.Version)), Actions: api.ActionsMap{}, Parameters: api.ParameterMap{}}
	for _, action := range row.Actions {
		out.Actions[api.ActionPoint(action.Point)] = append(out.Actions[api.ActionPoint(action.Point)], api.Action{Name: new(api.Name(action.Name)), Description: new(api.Description(action.Description)), Uri: new(api.Uri(action.URI)), RoleArn: new(api.Arn(action.RoleARN))})
	}
	for _, p := range row.Parameters {
		out.Parameters[api.ExtensionOrParameterName(p.Name)] = api.Parameter{Description: new(api.Description(p.Description)), Required: new(api.Boolean(p.Required)), Dynamic: new(api.Boolean(p.Dynamic))}
	}
	return out
}
func associationOutput(row Association) *api.ExtensionAssociation {
	out := &api.ExtensionAssociation{Id: new(api.Identifier(row.ID)), Arn: new(api.Arn(row.ARN)), ExtensionArn: new(api.Arn(row.ExtensionARN)), ExtensionVersionNumber: new(api.Integer(row.ExtensionVersion)), ResourceArn: new(api.Arn(row.ResourceARN)), Parameters: api.ParameterValueMap{}}
	for k, v := range row.Parameters {
		out.Parameters[api.ExtensionOrParameterName(k)] = api.StringWithLengthBetween1And2048(v)
	}
	return out
}
func extensionActions(actions api.ActionsMap) ([]ExtensionAction, error) {
	if len(actions) == 0 {
		return nil, failure("BadRequestException", "At least one extension action is required.")
	}
	out := make([]ExtensionAction, 0, len(actions))
	for _, point := range slices.Sorted(maps.Keys(actions)) {
		switch point {
		case api.ActionPointPRE_CREATE_HOSTED_CONFIGURATION_VERSION, api.ActionPointPRE_START_DEPLOYMENT, api.ActionPointAT_DEPLOYMENT_TICK, api.ActionPointON_DEPLOYMENT_START, api.ActionPointON_DEPLOYMENT_STEP, api.ActionPointON_DEPLOYMENT_BAKING, api.ActionPointON_DEPLOYMENT_COMPLETE, api.ActionPointON_DEPLOYMENT_ROLLED_BACK:
		default:
			return nil, failure("BadRequestException", "Invalid extension action point.")
		}
		if len(actions[point]) != 1 {
			return nil, failure("BadRequestException", "Each extension action point must contain one action.")
		}
		for _, v := range actions[point] {
			target, err := awsarn.Parse(value(v.Uri))
			if err != nil {
				return nil, failure("BadRequestException", "Extension action URI must be an ARN.")
			}
			switch target.Service {
			case "lambda", "sns", "sqs", "events":
			default:
				return nil, failure("BadRequestException", "Unsupported extension destination.")
			}
			if !strings.HasPrefix(string(point), "ON_") && target.Service != "lambda" {
				return nil, failure("BadRequestException", "Synchronous extension actions require Lambda.")
			}
			if value(v.Name) == "" {
				return nil, failure("BadRequestException", "Extension action name is required.")
			}
			out = append(out, ExtensionAction{Point: string(point), Name: value(v.Name), Description: value(v.Description), URI: value(v.Uri), RoleARN: value(v.RoleArn)})
		}
	}
	return out, nil
}
func extensionParameters(in api.ParameterMap) ([]ExtensionParameter, error) {
	out := make([]ExtensionParameter, 0, len(in))
	for _, name := range slices.Sorted(maps.Keys(in)) {
		p := in[name]
		if boolean(p.Required) && boolean(p.Dynamic) {
			return nil, failure("BadRequestException", "Dynamic extension parameters cannot be required.")
		}
		out = append(out, ExtensionParameter{Name: string(name), Description: value(p.Description), Required: boolean(p.Required), Dynamic: boolean(p.Dynamic)})
	}
	return out, nil
}
func (s *Service) extensionAuthorize(r Reader, action, resource string) error {
	tags, err := r.Tags(scopeFor(r.Context()), resource)
	if err != nil {
		return err
	}
	return s.authorize(r.Context(), action, resource, tags)
}
func (s *Service) extensionPassRoles(ctx context.Context, actions []ExtensionAction) error {
	for _, action := range actions {
		if action.RoleARN != "" {
			if err := s.passRole(ctx, action.RoleARN); err != nil {
				return err
			}
		}
	}
	return nil
}
func extensionTags(in api.TagMap) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = string(v)
	}
	return out
}

func (s *Service) createExtension(tx Transaction, in *api.CreateExtensionInput) (*api.Extension, error) {
	scope := scopeFor(tx.Context())
	rows, err := tx.Extensions(scope)
	if err != nil {
		return nil, err
	}
	row := Extension{Scope: scope, ID: newID(), Name: value(in.Name), Description: value(in.Description), Version: 1}
	row.Parameters, err = extensionParameters(in.Parameters)
	if err != nil {
		return nil, err
	}
	row.Actions, err = extensionActions(in.Actions)
	if err != nil {
		return nil, err
	}
	var latest Extension
	for _, v := range rows {
		if v.Name == row.Name && v.Version > latest.Version {
			latest = v
		}
	}
	if latest.ID != "" {
		row.ID = latest.ID
		row.Version = latest.Version + 1
	}
	row.ARN = extensionARN(scope, row.ID, row.Version)
	tags := extensionTags(in.Tags)
	if err = s.authorize(tx.Context(), "CreateExtension", row.ARN, nil); err != nil {
		return nil, err
	}
	if err = s.extensionPassRoles(tx.Context(), row.Actions); err != nil {
		return nil, err
	}
	if latest.ID != "" && in.LatestVersionNumber == nil {
		if latest.Description == row.Description && slices.Equal(latest.Actions, row.Actions) && slices.Equal(latest.Parameters, row.Parameters) {
			if err = s.authorizeTagsOnCreate(tx.Context(), latest.ARN, tags); err != nil {
				return nil, err
			}
			return extensionOutput(latest), nil
		}
		return nil, failure("BadRequestException", "LatestVersionNumber is required when creating a new extension version.")
	}
	if in.LatestVersionNumber != nil && number(in.LatestVersionNumber) != row.Version-1 {
		return nil, failure("ConflictException", "LatestVersionNumber does not match the current extension version.")
	}
	if err = s.authorizeTagsOnCreate(tx.Context(), row.ARN, tags); err != nil {
		return nil, err
	}
	if err = tx.PutExtension(row); err != nil {
		return nil, err
	}
	if err = tx.PutTags(scope, row.ARN, tags); err != nil {
		return nil, err
	}
	return extensionOutput(row), nil
}
func (s *Service) getExtension(tx Transaction, in *api.GetExtensionInput) (*api.Extension, error) {
	row, err := findExtension(tx, scopeFor(tx.Context()), value(in.ExtensionIdentifier), number(in.VersionNumber))
	if err != nil {
		return nil, err
	}
	if err = s.extensionAuthorize(tx, "GetExtension", row.ARN); err != nil {
		return nil, err
	}
	return extensionOutput(row), nil
}
func (s *Service) updateExtension(tx Transaction, in *api.UpdateExtensionInput) (*api.Extension, error) {
	scope := scopeFor(tx.Context())
	row, err := findExtension(tx, scope, value(in.ExtensionIdentifier), number(in.VersionNumber))
	if err != nil {
		return nil, err
	}
	if err = s.extensionAuthorize(tx, "UpdateExtension", row.ARN); err != nil {
		return nil, err
	}
	if in.Description != nil {
		row.Description = value(in.Description)
	}
	if in.Actions != nil {
		row.Actions, err = extensionActions(in.Actions)
		if err != nil {
			return nil, err
		}
		if err = s.extensionPassRoles(tx.Context(), row.Actions); err != nil {
			return nil, err
		}
	}
	if in.Parameters != nil {
		row.Parameters, err = extensionParameters(in.Parameters)
		if err != nil {
			return nil, err
		}
	}
	if err = tx.PutExtension(row); err != nil {
		return nil, err
	}
	return extensionOutput(row), nil
}
func (s *Service) deleteExtension(tx Transaction, in *api.DeleteExtensionInput) (*api.Unit, error) {
	scope := scopeFor(tx.Context())
	row, err := findExtension(tx, scope, value(in.ExtensionIdentifier), number(in.VersionNumber))
	if err != nil {
		return nil, err
	}
	if err = s.extensionAuthorize(tx, "DeleteExtension", row.ARN); err != nil {
		return nil, err
	}
	associations, err := tx.Associations(scope)
	if err != nil {
		return nil, err
	}
	for _, association := range associations {
		if association.ExtensionID == row.ID && association.ExtensionVersion == row.Version {
			return nil, failure("BadRequestException", "The extension is associated with an AppConfig resource.")
		}
	}
	if err = tx.DeleteExtension(scope, row.ID, row.Version); err != nil {
		return nil, err
	}
	if err = tx.PutTags(scope, row.ARN, nil); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}
func (s *Service) listExtensions(tx Transaction, in *api.ListExtensionsInput) (*api.Extensions, error) {
	if err := s.authorize(tx.Context(), "ListExtensions", "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Extensions(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	latest := map[string]Extension{}
	for _, v := range rows {
		if (in.Name == nil || v.Name == value(in.Name)) && v.Version > latest[v.ID].Version {
			latest[v.ID] = v
		}
	}
	items := make([]api.ExtensionSummary, 0, len(latest))
	for _, id := range slices.Sorted(maps.Keys(latest)) {
		v := latest[id]
		items = append(items, api.ExtensionSummary{Id: new(api.Id(v.ID)), Arn: new(api.Arn(v.ARN)), Name: new(api.Name(v.Name)), Description: new(api.Description(v.Description)), VersionNumber: new(api.Integer(v.Version))})
	}
	items, next, err := page(items, in.NextToken, in.MaxResults, pageBinding(scopeFor(tx.Context()), "ListExtensions", value(in.Name)), func(i int) pageKey { return pageKey{ID: value(items[i].Id)} })
	return &api.Extensions{Items: items, NextToken: next}, err
}
