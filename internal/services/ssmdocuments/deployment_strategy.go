package ssmdocuments

import (
	"encoding/json"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Native SSM validates this document independently of AppConfig's API bounds:
// durations have no 1440-minute maximum and description has no 1024-byte maximum.
// Optional fields remain absent in the stored source, rather than receiving API
// defaults. See deployment_strategy_documents.json for the retained boundaries.
const deploymentStrategySchema = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "additionalProperties": false,
  "required": ["schemaVersion", "deploymentDurationInMinutes", "growthFactor"],
  "properties": {
    "schemaVersion": {"type": "string", "enum": ["1.0"]},
    "description": {"type": "string"},
    "deploymentDurationInMinutes": {"type": "integer", "minimum": 0},
    "growthFactor": {"type": "number", "minimum": 1, "maximum": 100},
    "finalBakeTimeInMinutes": {"type": "integer", "minimum": 0},
    "growthType": {"type": "string", "enum": ["LINEAR", "EXPONENTIAL"]}
  }
}`

var compiledDeploymentStrategySchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	var document any
	if err := json.Unmarshal([]byte(deploymentStrategySchema), &document); err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft4)
	compiler.UseLoader(documentSchemaLoader{})
	const location = "urn:stackd:ssm:deployment-strategy-schema"
	if err := compiler.AddResource(location, document); err != nil {
		return nil, err
	}
	return compiler.Compile(location)
})

func validateDeploymentStrategy(document any) error {
	schema, err := compiledDeploymentStrategySchema()
	if err != nil {
		return failure("InternalServerError", "Unable to load the deployment strategy document schema.")
	}
	if err := schema.Validate(document); err != nil {
		return failure("InvalidDocumentContent", err.Error())
	}
	return nil
}
