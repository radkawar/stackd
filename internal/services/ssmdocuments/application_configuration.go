package ssmdocuments

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awswire"
)

// ApplicationConfiguration has exactly one immutable Requires entry. Selectors
// are resolved on creation; subsequent updates use that version and incarnation.
func (s *Service) bindSchema(r Reader, record *Record, requires api.DocumentRequiresList) error {
	if len(requires) != 1 {
		return failure("ValidationException", "ApplicationConfiguration requires exactly one ApplicationConfigurationSchema document.")
	}
	requirement := requires[0]
	if requirement.RequireType != nil || requirement.VersionName != nil {
		return failure("ValidationException", "RequireType and VersionName are not supported for ApplicationConfiguration dependencies.")
	}
	// Native CreateDocument requires current GetDocument authority on the schema.
	// UpdateDocument and GetDocument of the configuration do not require it.
	schema, err := s.load(r, "GetDocument", value(requirement.Name))
	if err != nil {
		return schemaDependencyError(err)
	}
	if schema.Type != "ApplicationConfigurationSchema" {
		return failure("ValidationException", "The required document must have type ApplicationConfigurationSchema.")
	}
	version, err := selectVersion(r, schema, value(requirement.Version), "")
	if err != nil {
		return schemaDependencyError(err)
	}
	record.SchemaName = schema.Key.Name
	if schema.Key.Scope != record.Key.Scope {
		record.SchemaName = documentARN(schema.Key)
	}
	record.SchemaDocumentID = schema.DocumentID
	record.SchemaVersion = version.Key.Version
	return nil
}

func schemaDependencyError(err error) error {
	var rejected *awswire.Error
	if errors.Is(err, ErrNotFound) || errors.As(err, &rejected) && (rejected.Code == "InvalidDocument" || rejected.Code == "InvalidDocumentVersion") {
		return failure("ValidationException", "The required schema document or version does not exist.")
	}
	return err
}

func documentRequires(record Record) api.DocumentRequiresList {
	if record.SchemaName == "" {
		return nil
	}
	return api.DocumentRequiresList{{Name: new(api.DocumentARN(record.SchemaName)), Version: new(api.DocumentVersion(strconv.FormatInt(record.SchemaVersion, 10)))}}
}

func decodeConfiguration(content, format string) (any, error) {
	data := []byte(content)
	if format == "YAML" {
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		var tree any
		if err := decoder.Decode(&tree); err != nil {
			return nil, failure("InvalidDocumentContent", err.Error())
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, failure("InvalidDocumentContent", "Document must contain exactly one value.")
		}
		var err error
		data, err = json.Marshal(tree)
		if err != nil {
			return nil, failure("InvalidDocumentContent", "YAML document keys and values must be JSON compatible.")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var tree any
	if err := decoder.Decode(&tree); err != nil {
		return nil, failure("InvalidDocumentContent", err.Error())
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, failure("InvalidDocumentContent", "Document must contain exactly one value.")
	}
	return tree, nil
}

// Schema evaluation is local to the selected owner bytes, never a host file or
// network fetch while the shared repository transaction is held.
type documentSchemaLoader struct{}

func (documentSchemaLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference is unavailable: %s", url)
}

func validateDocumentContent(r Reader, record Record, content, format string) error {
	if record.Type == "Command" {
		_, err := validateContent(content, format)
		return err
	}
	if len(content) > 64*1024 {
		return failure("MaxDocumentSizeExceeded", "Document content exceeds 64 KiB.")
	}
	if format != "JSON" && (format != "YAML" || record.Type == "ApplicationConfigurationSchema") {
		return failure("InvalidDocumentContent", "Configuration and deployment strategy documents require JSON or YAML; ApplicationConfigurationSchema requires JSON.")
	}
	tree, err := decodeConfiguration(content, format)
	if err != nil {
		return err
	}
	if record.Type == "DeploymentStrategy" {
		return validateDeploymentStrategy(tree)
	}
	if record.Type == "ApplicationConfigurationSchema" {
		object, ok := tree.(map[string]any)
		if !ok || object["additionalProperties"] != false {
			return failure("InvalidDocumentContent", "ApplicationConfigurationSchema must have field additionalProperties set to false.")
		}
		// Native stores the schema source here; compilation happens when a
		// configuration consumes it, not when the schema itself is admitted.
		return nil
	}
	schemaKey, err := documentKey(r.Context(), record.SchemaName)
	if err != nil {
		return schemaDependencyError(err)
	}
	schema, err := loadRecord(r, schemaKey)
	if err != nil {
		return schemaDependencyError(err)
	}
	if schema.DocumentID != record.SchemaDocumentID || schema.Type != "ApplicationConfigurationSchema" {
		return failure("ValidationException", "The required ApplicationConfigurationSchema document has been changed.")
	}
	version, err := selectVersion(r, schema, strconv.FormatInt(record.SchemaVersion, 10), "")
	if err != nil {
		return schemaDependencyError(err)
	}
	schemaTree, err := decodeConfiguration(version.Content, version.Format)
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft4)
	compiler.UseLoader(documentSchemaLoader{})
	const location = "urn:stackd:ssm:application-configuration-schema"
	if err := compiler.AddResource(location, schemaTree); err != nil {
		return failure("InvalidDocumentContent", err.Error())
	}
	compiled, err := compiler.Compile(location)
	if err != nil {
		return failure("InvalidDocumentContent", err.Error())
	}
	if err := compiled.Validate(tree); err != nil {
		return failure("InvalidDocumentContent", err.Error())
	}
	return nil
}
