package cloudformation

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"stackd/internal/awswire"
)

// Automatic import only considers retained resources with static identifiers.
// Dynamic names are ordinary creates under the AWS auto-import contract:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/import-resources-automatically.html
func (s *Service) checkAutomaticImports(r Reader, stack StackRecord, t *Template, parameters, resolved map[string]string) error {
	evaluation, err := s.evaluation(r, stack, parameters, resolved)
	if err != nil {
		return err
	}
	order, err := t.Order(evaluation)
	if err != nil {
		return err
	}
	current, err := currentResources(r, stack.ID)
	if err != nil {
		return err
	}
	for _, logical := range order {
		resource := t.Resources[logical]
		if resource.DeletionPolicy != "Retain" && resource.DeletionPolicy != "RetainExceptOnCreate" {
			continue
		}
		if current[logical].PhysicalID != "" {
			continue
		}
		schema, ok := resourceSchemas[resource.Type]
		if !ok {
			return failure("NotImplementedException", "Automatic import requires captured identifier facts for "+resource.Type+".", 501)
		}
		identifiers := append([][]string{schema.PrimaryIdentifier}, schema.AdditionalIdentifiers...)
		identifier := ""
		for _, paths := range identifiers {
			parts := make([]string, 0, len(paths))
			for _, path := range paths {
				if slices.Contains(schema.ReadOnly, path) {
					break
				}
				values := resourcePathValues(resource.Properties, resourcePathParts(path))
				if len(values) != 1 {
					break
				}
				literal, ok := values[0].(string)
				if !ok || literal == "" {
					break
				}
				parts = append(parts, literal)
			}
			if len(parts) > 0 && len(parts) == len(paths) {
				identifier = strings.Join(parts, "|")
				break
			}
		}
		if identifier == "" {
			continue
		}
		owner, ok := s.handlers[resource.Type].(ResourceReader)
		if !ok {
			return failure("NotImplementedException", "Automatic import discovery is not implemented for "+resource.Type+".", 501)
		}
		_, err = owner.Read(r.Context(), ResourceRequest{Scope: stack.Scope, StackID: stack.ID, StackName: stack.Name, LogicalID: logical, Type: resource.Type, PhysicalID: identifier, Properties: resource.Properties})
		if err == nil {
			// TODO: Comeback adopt existing owner resources with durable ownership transfer
			// and import rollback before admitting a change set that would import them.
			return failure("NotImplementedException", fmt.Sprintf("Automatic import of existing resource %s (%s) is not implemented.", logical, identifier), 501)
		}
		var wire *awswire.Error
		if !errors.As(err, &wire) {
			return err
		}
		switch wire.Code {
		case "NoSuchBucket", "ParameterNotFound", "RepositoryNotFoundException", "ResourceNotFoundException", "AWS.SimpleQueueService.NonExistentQueue", "NoSuchEntity", "NotFoundException", "ResourceNotFound":
		default:
			return err
		}
	}
	return nil
}
