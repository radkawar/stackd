package dynamodb

import (
	"regexp"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
)

var tableNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,255}$`)

func invalidTable(message string) error {
	return failure("ValidationException", "One or more parameter values were invalid: "+message)
}

func validateCapacity(mode string, capacity *api.ProvisionedThroughput, required bool) error {
	if mode != "PROVISIONED" && mode != "PAY_PER_REQUEST" {
		return invalidTable("Invalid BillingMode")
	}
	if mode == "PAY_PER_REQUEST" && capacity != nil {
		return invalidTable("Neither ReadCapacityUnits nor WriteCapacityUnits can be specified when BillingMode is PAY_PER_REQUEST")
	}
	if mode == "PROVISIONED" && capacity == nil && required {
		return invalidTable("ProvisionedThroughput must be specified when BillingMode is PROVISIONED")
	}
	if capacity != nil && (capacity.ReadCapacityUnits == nil || capacity.WriteCapacityUnits == nil || *capacity.ReadCapacityUnits < 1 || *capacity.WriteCapacityUnits < 1) {
		return invalidTable("ReadCapacityUnits and WriteCapacityUnits must be greater than zero")
	}
	if capacity != nil && (*capacity.ReadCapacityUnits > tableCapacityLimit || *capacity.WriteCapacityUnits > tableCapacityLimit) {
		return failure("LimitExceededException", "The provisioned throughput exceeds the maximum allowed capacity of 40000 units")
	}
	return nil
}

func validateOnDemand(mode string, capacity *api.OnDemandThroughput, allowRemoval bool) error {
	if capacity == nil {
		return nil
	}
	if mode != "PAY_PER_REQUEST" {
		return invalidTable("OnDemandThroughput can only be specified when BillingMode is PAY_PER_REQUEST")
	}
	for _, units := range []*api.LongObject{capacity.MaxReadRequestUnits, capacity.MaxWriteRequestUnits} {
		if units == nil {
			continue
		}
		if *units < 1 && !(allowRemoval && *units == -1) {
			return invalidTable("On-demand maximum request units must be positive, or -1 to remove an existing limit")
		}
		if *units > tableCapacityLimit {
			return failure("LimitExceededException", "The on-demand maximum exceeds the allowed table capacity of 40000 units")
		}
	}
	return nil
}

func validateStream(in *api.StreamSpecification) error {
	if in == nil {
		return nil
	}
	if in.StreamEnabled == nil {
		return invalidTable("StreamEnabled must be specified")
	}
	view := value(in.StreamViewType)
	if bool(*in.StreamEnabled) {
		switch view {
		case "KEYS_ONLY", "NEW_IMAGE", "OLD_IMAGE", "NEW_AND_OLD_IMAGES":
		default:
			return invalidTable("StreamViewType must be specified when StreamEnabled is true")
		}
	} else if view != "" {
		return invalidTable("StreamViewType must not be specified when StreamEnabled is false")
	}
	return nil
}

func validateSchema(schema api.KeySchema, definitions map[string]string, used map[string]bool) error {
	if len(schema) < 1 || len(schema) > 2 {
		return invalidTable("KeySchema must contain one HASH key and at most one RANGE key")
	}
	if value(schema[0].KeyType) != "HASH" {
		return failure("ValidationException", "Invalid KeySchema: The first KeySchemaElement is not a HASH key type")
	}
	if len(schema) == 2 && value(schema[1].KeyType) != "RANGE" {
		return failure("ValidationException", "Invalid KeySchema: The second KeySchemaElement is not a RANGE key type")
	}
	for i, key := range schema {
		name := value(key.AttributeName)
		if name == "" || len(name) > 255 {
			return invalidTable("Invalid key attribute name")
		}
		if _, ok := definitions[name]; !ok {
			return invalidTable("Some index key attributes are not defined in AttributeDefinitions. Keys: [" + name + "]")
		}
		if i > 0 && name == value(schema[0].AttributeName) {
			return invalidTable("Both the Hash Key and the Range Key cannot be the same attribute")
		}
		used[name] = true
	}
	return nil
}

func validateProjection(projection *api.Projection, keys api.KeySchema, tableKeys api.KeySchema) (int, error) {
	if projection == nil {
		return 0, invalidTable("Projection must be specified")
	}
	kind := value(projection.ProjectionType)
	switch kind {
	case "ALL", "KEYS_ONLY":
		if len(projection.NonKeyAttributes) > 0 {
			return 0, invalidTable("NonKeyAttributes can only be specified with ProjectionType INCLUDE")
		}
	case "INCLUDE":
		if len(projection.NonKeyAttributes) == 0 {
			return 0, invalidTable("ProjectionType is INCLUDE, but NonKeyAttributes is not specified")
		}
		if len(projection.NonKeyAttributes) > 20 {
			return 0, invalidTable("NonKeyAttributes must contain at most 20 attributes")
		}
		seen := map[string]bool{}
		for _, key := range keys {
			seen[value(key.AttributeName)] = true
		}
		for _, key := range tableKeys {
			seen[value(key.AttributeName)] = true
		}
		for _, name := range projection.NonKeyAttributes {
			if name == "" || len(name) > 255 || seen[string(name)] {
				return 0, invalidTable("NonKeyAttributes contains an invalid, duplicate, or key attribute")
			}
			seen[string(name)] = true
		}
	default:
		return 0, invalidTable("Invalid ProjectionType")
	}
	return len(projection.NonKeyAttributes), nil
}

func attributeMap(attributes api.AttributeDefinitions) (map[string]string, error) {
	definitions := make(map[string]string, len(attributes))
	for _, attribute := range attributes {
		name, kind := value(attribute.AttributeName), value(attribute.AttributeType)
		if name == "" || len(name) > 255 || kind != "S" && kind != "N" && kind != "B" {
			return nil, invalidTable("Invalid AttributeDefinition")
		}
		if _, ok := definitions[name]; ok {
			return nil, invalidTable("Duplicate AttributeDefinitions: " + name)
		}
		definitions[name] = kind
	}
	return definitions, nil
}

func validateCreate(in *api.CreateTableInput) error {
	if in.SSESpecification != nil {
		return unsupported("Explicit DynamoDB encryption configuration is not implemented.")
	}
	if in.GlobalTableSettingsReplicationMode != nil || in.GlobalTableSourceArn != nil {
		return unsupported("DynamoDB global table replication is not implemented.")
	}
	if in.VectorIndexes != nil {
		return unsupported("DynamoDB vector indexes are not implemented.")
	}
	if in.WarmThroughput != nil {
		return unsupported("Explicit DynamoDB warm-throughput configuration is not implemented.")
	}
	if in.TableClass != nil && value(in.TableClass) != "STANDARD" && value(in.TableClass) != "STANDARD_INFREQUENT_ACCESS" {
		return invalidTable("Invalid TableClass")
	}
	mode := value(in.BillingMode)
	if mode == "" {
		mode = "PROVISIONED"
	}
	if err := validateCapacity(mode, in.ProvisionedThroughput, true); err != nil {
		return err
	}
	if err := validateOnDemand(mode, in.OnDemandThroughput, false); err != nil {
		return err
	}
	if err := validateStream(in.StreamSpecification); err != nil {
		return err
	}
	definitions, err := attributeMap(in.AttributeDefinitions)
	if err != nil {
		return err
	}
	used := map[string]bool{}
	if err = validateSchema(in.KeySchema, definitions, used); err != nil {
		return err
	}
	if len(in.LocalSecondaryIndexes) > 5 || len(in.GlobalSecondaryIndexes) > 20 {
		return failure("LimitExceededException", "Number of secondary indexes exceeds the allowed limit")
	}
	names := map[string]bool{}
	projected := 0
	for _, index := range in.LocalSecondaryIndexes {
		name := value(index.IndexName)
		if !tableNamePattern.MatchString(name) || names[name] {
			return invalidTable("Invalid or duplicate index name: " + name)
		}
		names[name] = true
		if len(in.KeySchema) != 2 || len(index.KeySchema) != 2 {
			return invalidTable("Local secondary indexes require a table and index RANGE key")
		}
		if err = validateSchema(index.KeySchema, definitions, used); err != nil {
			return err
		}
		if value(index.KeySchema[0].AttributeName) != value(in.KeySchema[0].AttributeName) {
			return invalidTable("Index KeySchema does not have the same leading hash key as table KeySchema for index: " + name + ". index hash key: " + value(index.KeySchema[0].AttributeName) + ", table hash key: " + value(in.KeySchema[0].AttributeName))
		}
		n, e := validateProjection(index.Projection, index.KeySchema, in.KeySchema)
		if e != nil {
			return e
		}
		projected += n
	}
	for _, index := range in.GlobalSecondaryIndexes {
		name := value(index.IndexName)
		if !tableNamePattern.MatchString(name) || names[name] {
			return invalidTable("Invalid or duplicate index name: " + name)
		}
		names[name] = true
		if index.WarmThroughput != nil {
			return unsupported("Explicit index warm-throughput configuration is not implemented.")
		}
		if err = validateCapacity(mode, index.ProvisionedThroughput, true); err != nil {
			return err
		}
		if err = validateOnDemand(mode, index.OnDemandThroughput, false); err != nil {
			return err
		}
		if err = validateSchema(index.KeySchema, definitions, used); err != nil {
			return err
		}
		n, e := validateProjection(index.Projection, index.KeySchema, in.KeySchema)
		if e != nil {
			return e
		}
		projected += n
	}
	if projected > 100 {
		return invalidTable("The total number of attributes projected into all secondary indexes must not exceed 100")
	}
	if len(used) != len(definitions) {
		return invalidTable("Number of attributes in KeySchema does not exactly match number of attributes defined in AttributeDefinitions")
	}
	return nil
}

func validateTagKey(key string) error {
	if key == "" || len(key) > 128 {
		return failure("ValidationException", "Tag key must be between 1 and 128 bytes")
	}
	if strings.HasPrefix(strings.ToLower(key), "aws:") {
		return failure("ValidationException", "Tag Key cannot be prefixed with aws:, Key: "+key)
	}
	return nil
}
