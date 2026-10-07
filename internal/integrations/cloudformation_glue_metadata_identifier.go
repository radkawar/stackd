package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"strings"
)

// Metadata keys and values can contain the compound identifier separator. Recover
// their boundaries from the owner's pairs rather than guessing or retaining a copy.
func cfnGlueMetadataIdentity(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest) (string, string, string, error) {
	version, key, value := cfnComputeString(r.Properties, "SchemaVersionId"), cfnComputeString(r.Properties, "Key"), cfnComputeString(r.Properties, "Value")
	if r.PhysicalID == "" || version+"|"+key+"|"+value == r.PhysicalID {
		return version, key, value, nil
	}
	version, _, ok := strings.Cut(r.PhysicalID, "|")
	if !ok || version == "" {
		return "", "", "", fmt.Errorf("invalid schema version metadata identifier")
	}
	input := map[string]any{"SchemaVersionId": version}
	found := false
	for {
		out, err := cfnComputeCall[api.QuerySchemaVersionMetadataOutput](ctx, c, "glue", "QuerySchemaVersionMetadata", input)
		if err != nil {
			return "", "", "", err
		}
		match := func(k, v string) error {
			if version+"|"+k+"|"+v != r.PhysicalID {
				return nil
			}
			if found && (key != k || value != v) {
				return fmt.Errorf("schema version metadata identifier is ambiguous")
			}
			key, value, found = k, v, true
			return nil
		}
		for k, v := range out.MetadataInfoMap {
			if err := match(string(k), cfnComputeValue(v.MetadataValue)); err != nil {
				return "", "", "", err
			}
			for _, other := range v.OtherMetadataValueList {
				if err := match(string(k), cfnComputeValue(other.MetadataValue)); err != nil {
					return "", "", "", err
				}
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			break
		}
		input["NextToken"] = out.NextToken
	}
	if !found {
		return "", "", "", &awswire.Error{Code: "EntityNotFoundException", Message: "Schema version metadata does not exist.", StatusCode: 400}
	}
	return version, key, value, nil
}
