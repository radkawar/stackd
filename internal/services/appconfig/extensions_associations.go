package appconfig

import (
	api "stackd/internal/awsapi/appconfig"
	"strconv"
	"strings"
)

func associationResource(r Reader, scope Scope, identifier string) (string, error) {
	relative := identifier
	if strings.HasPrefix(identifier, "arn:") {
		prefix := arn(scope, "")
		if !strings.HasPrefix(identifier, prefix) {
			return "", failure("ResourceNotFoundException", "The extension resource is outside the current scope.")
		}
		relative = strings.TrimPrefix(identifier, prefix)
	}
	parts := strings.Split(relative, "/")
	if len(parts) != 2 && len(parts) != 4 {
		return "", failure("BadRequestException", "ResourceIdentifier must identify an application, environment or configuration profile.")
	}
	if parts[0] != "application" {
		return "", failure("BadRequestException", "Unsupported extension association resource.")
	}
	app, err := findApplication(r, scope, parts[1])
	if err != nil {
		return "", err
	}
	if len(parts) == 2 {
		return appARN(scope, app.ID), nil
	}
	switch parts[2] {
	case "environment":
		env, err := findEnvironment(r, scope, app.ID, parts[3])
		if err != nil {
			return "", err
		}
		return envARN(scope, app.ID, env.ID), nil
	case "configurationprofile":
		profile, err := findProfile(r, scope, app.ID, parts[3])
		if err != nil {
			return "", err
		}
		return profileARN(scope, app.ID, profile.ID), nil
	default:
		return "", failure("BadRequestException", "Unsupported extension association resource.")
	}
}
func associationParameters(extension Extension, in api.ParameterValueMap) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for name, v := range in {
		found := false
		for _, parameter := range extension.Parameters {
			if parameter.Name == string(name) {
				found = true
				break
			}
		}
		if !found {
			return nil, failure("BadRequestException", "Undefined extension parameter: "+string(name))
		}
		out[string(name)] = string(v)
	}
	for _, parameter := range extension.Parameters {
		if parameter.Required && !parameter.Dynamic && out[parameter.Name] == "" {
			return nil, failure("BadRequestException", "Missing required extension parameter: "+parameter.Name)
		}
	}
	return out, nil
}
func (s *Service) createExtensionAssociation(tx Transaction, in *api.CreateExtensionAssociationInput) (*api.ExtensionAssociation, error) {
	scope := scopeFor(tx.Context())
	extension, err := findExtension(tx, scope, value(in.ExtensionIdentifier), number(in.ExtensionVersionNumber))
	if err != nil {
		return nil, err
	}
	resource, err := associationResource(tx, scope, value(in.ResourceIdentifier))
	if err != nil {
		return nil, err
	}
	if err = s.extensionAuthorize(tx, "CreateExtensionAssociation", extension.ARN); err != nil {
		return nil, err
	}
	if err = s.extensionAuthorize(tx, "CreateExtensionAssociation", resource); err != nil {
		return nil, err
	}
	parameters, err := associationParameters(extension, in.Parameters)
	if err != nil {
		return nil, err
	}
	row := Association{Scope: scope, ID: newID(), ExtensionID: extension.ID, ExtensionARN: extension.ARN, ExtensionVersion: extension.Version, ResourceARN: resource, Parameters: parameters}
	row.ARN = associationARN(scope, row.ID)
	tags := extensionTags(in.Tags)
	if err = s.authorizeTagsOnCreate(tx.Context(), row.ARN, tags); err != nil {
		return nil, err
	}
	if err = tx.PutAssociation(row); err != nil {
		return nil, err
	}
	if err = tx.PutTags(scope, row.ARN, tags); err != nil {
		return nil, err
	}
	return associationOutput(row), nil
}
func (s *Service) getExtensionAssociation(tx Transaction, in *api.GetExtensionAssociationInput) (*api.ExtensionAssociation, error) {
	row, err := findAssociation(tx, scopeFor(tx.Context()), value(in.ExtensionAssociationId))
	if err != nil {
		return nil, err
	}
	if err = s.extensionAuthorize(tx, "GetExtensionAssociation", row.ARN); err != nil {
		return nil, err
	}
	return associationOutput(row), nil
}
func (s *Service) updateExtensionAssociation(tx Transaction, in *api.UpdateExtensionAssociationInput) (*api.ExtensionAssociation, error) {
	scope := scopeFor(tx.Context())
	row, err := findAssociation(tx, scope, value(in.ExtensionAssociationId))
	if err != nil {
		return nil, err
	}
	if err = s.extensionAuthorize(tx, "UpdateExtensionAssociation", row.ARN); err != nil {
		return nil, err
	}
	if in.Parameters != nil {
		extension, err := findExtension(tx, scope, row.ExtensionID, row.ExtensionVersion)
		if err != nil {
			return nil, err
		}
		row.Parameters, err = associationParameters(extension, in.Parameters)
		if err != nil {
			return nil, err
		}
	}
	if err = tx.PutAssociation(row); err != nil {
		return nil, err
	}
	return associationOutput(row), nil
}
func (s *Service) deleteExtensionAssociation(tx Transaction, in *api.DeleteExtensionAssociationInput) (*api.Unit, error) {
	scope := scopeFor(tx.Context())
	row, err := findAssociation(tx, scope, value(in.ExtensionAssociationId))
	if err != nil {
		return nil, err
	}
	if err = s.extensionAuthorize(tx, "DeleteExtensionAssociation", row.ARN); err != nil {
		return nil, err
	}
	if err = tx.DeleteAssociation(scope, row.ID); err != nil {
		return nil, err
	}
	if err = tx.PutTags(scope, row.ARN, nil); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}
func (s *Service) listExtensionAssociations(tx Transaction, in *api.ListExtensionAssociationsInput) (*api.ExtensionAssociations, error) {
	if err := s.authorize(tx.Context(), "ListExtensionAssociations", "*", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	rows, err := tx.Associations(scope)
	if err != nil {
		return nil, err
	}
	extensionID := ""
	if in.ExtensionIdentifier != nil {
		extension, err := findExtension(tx, scope, value(in.ExtensionIdentifier), number(in.ExtensionVersionNumber))
		if err != nil {
			return nil, err
		}
		extensionID = extension.ID
	}
	items := make([]api.ExtensionAssociationSummary, 0, len(rows))
	for _, row := range rows {
		if extensionID != "" && row.ExtensionID != extensionID {
			continue
		}
		if in.ExtensionVersionNumber != nil && row.ExtensionVersion != number(in.ExtensionVersionNumber) {
			continue
		}
		if in.ResourceIdentifier != nil && row.ResourceARN != value(in.ResourceIdentifier) {
			continue
		}
		items = append(items, api.ExtensionAssociationSummary{Id: new(api.Identifier(row.ID)), ExtensionArn: new(api.Arn(row.ExtensionARN)), ResourceArn: new(api.Arn(row.ResourceARN))})
	}
	items, next, err := page(items, in.NextToken, in.MaxResults, pageBinding(scope, "ListExtensionAssociations", extensionID, value(in.ResourceIdentifier), strconv.FormatInt(int64(number(in.ExtensionVersionNumber)), 10)), func(i int) pageKey { return pageKey{ID: value(items[i].Id)} })
	return &api.ExtensionAssociations{Items: items, NextToken: next}, err
}
