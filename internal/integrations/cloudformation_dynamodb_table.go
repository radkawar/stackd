package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	ddbapi "stackd/internal/awsapi/dynamodb"
	"stackd/internal/services/cloudformation"
)

// cfnDynamoDBTable delegates every effect to the DynamoDB owner. Create admits
// the table; Stabilize waits for the native table to become ACTIVE and then
// converges post-create settings one owner transition at a time.
type cfnDynamoDBTable struct{ commands StepFunctionsCommands }

type cfnDDBAttribute struct{ AttributeName, AttributeType string }
type cfnDDBKey struct{ AttributeName, KeyType string }
type cfnDDBProjection struct {
	NonKeyAttributes []string `json:",omitempty"`
	ProjectionType   string   `json:",omitempty"`
}
type cfnDDBThroughput struct{ ReadCapacityUnits, WriteCapacityUnits cfnMessagingInt }
type cfnDDBOnDemand struct {
	MaxReadRequestUnits  *cfnMessagingInt `json:",omitempty"`
	MaxWriteRequestUnits *cfnMessagingInt `json:",omitempty"`
}
type cfnDDBGSI struct {
	IndexName                        string
	KeySchema                        []cfnDDBKey
	Projection                       cfnDDBProjection
	ProvisionedThroughput            *cfnDDBThroughput
	OnDemandThroughput               *cfnDDBOnDemand
	ContributorInsightsSpecification json.RawMessage
	WarmThroughput                   json.RawMessage
}
type cfnDDBLSI struct {
	IndexName  string
	KeySchema  []cfnDDBKey
	Projection cfnDDBProjection
}
type cfnDDBPolicy struct{ PolicyDocument map[string]any }
type cfnDDBStream struct {
	StreamViewType string
	ResourcePolicy *cfnDDBPolicy
	Tags           json.RawMessage
}
type cfnDDBTTL struct {
	Enabled       cfnMessagingBool
	AttributeName string
}
type cfnDDBPITR struct {
	PointInTimeRecoveryEnabled *cfnMessagingBool
	RecoveryPeriodInDays       *cfnMessagingInt
}
type cfnDDBKinesis struct {
	StreamArn                            string
	ApproximateCreationDateTimePrecision string
}
type cfnDDBSSE struct {
	SSEEnabled     cfnMessagingBool
	SSEType        string
	KMSMasterKeyId string
}

type cfnDDBTableProperties struct {
	TableName                        string
	AttributeDefinitions             []cfnDDBAttribute
	KeySchema                        json.RawMessage
	BillingMode                      string
	ProvisionedThroughput            *cfnDDBThroughput
	OnDemandThroughput               *cfnDDBOnDemand
	GlobalSecondaryIndexes           []cfnDDBGSI
	LocalSecondaryIndexes            []cfnDDBLSI
	StreamSpecification              *cfnDDBStream
	TimeToLiveSpecification          *cfnDDBTTL
	PointInTimeRecoverySpecification *cfnDDBPITR
	KinesisStreamSpecification       *cfnDDBKinesis
	DeletionProtectionEnabled        *cfnMessagingBool
	TableClass                       string
	ResourcePolicy                   *cfnDDBPolicy
	SSESpecification                 *cfnDDBSSE
	Tags                             []cfnMessagingTag
	ContributorInsightsSpecification json.RawMessage
	ImportSourceSpecification        json.RawMessage
	WarmThroughput                   json.RawMessage
	VectorIndexes                    json.RawMessage

	keys []cfnDDBKey
}

func cfnDDBTableDecode(raw cloudformation.Properties) (cfnDDBTableProperties, error) {
	var p cfnDDBTableProperties
	if raw == nil {
		raw = cloudformation.Properties{}
	}
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, err
	}
	if err := json.Unmarshal(p.KeySchema, &p.keys); err != nil || len(p.keys) == 0 {
		return p, fmt.Errorf("KeySchema must be a nonempty list of AttributeName/KeyType elements")
	}
	unsupported := map[string]bool{
		"ContributorInsightsSpecification": cfnDataRaw(p.ContributorInsightsSpecification),
		"ImportSourceSpecification":        cfnDataRaw(p.ImportSourceSpecification),
		"WarmThroughput":                   cfnDataRaw(p.WarmThroughput),
		"VectorIndexes":                    cfnDataRaw(p.VectorIndexes),
		// SSEEnabled=false selects the default AWS owned key and is the owner's
		// only encryption mode. KMS-managed encryption is not implemented.
		"SSESpecification (KMS)":   p.SSESpecification != nil && (bool(p.SSESpecification.SSEEnabled) || p.SSESpecification.SSEType != "" || p.SSESpecification.KMSMasterKeyId != ""),
		"StreamSpecification.Tags": p.StreamSpecification != nil && cfnDataRaw(p.StreamSpecification.Tags),
	}
	for _, index := range p.GlobalSecondaryIndexes {
		if cfnDataRaw(index.ContributorInsightsSpecification) {
			unsupported["GlobalSecondaryIndexes.ContributorInsightsSpecification"] = true
		}
		if cfnDataRaw(index.WarmThroughput) {
			unsupported["GlobalSecondaryIndexes.WarmThroughput"] = true
		}
	}
	if err := cfnDataUnsupported("The stackd DynamoDB owner", unsupported); err != nil {
		return p, err
	}
	if p.StreamSpecification != nil && p.StreamSpecification.StreamViewType == "" {
		return p, fmt.Errorf("StreamSpecification.StreamViewType is required")
	}
	if ttl := p.TimeToLiveSpecification; ttl != nil && bool(ttl.Enabled) && ttl.AttributeName == "" {
		return p, fmt.Errorf("TimeToLiveSpecification.AttributeName is required when TTL is enabled")
	}
	if pitr := p.PointInTimeRecoverySpecification; pitr != nil && pitr.RecoveryPeriodInDays != nil {
		if pitr.PointInTimeRecoveryEnabled == nil {
			return p, fmt.Errorf("PointInTimeRecoverySpecification.RecoveryPeriodInDays requires PointInTimeRecoveryEnabled")
		}
		if *pitr.RecoveryPeriodInDays < 1 || *pitr.RecoveryPeriodInDays > 35 {
			return p, fmt.Errorf("PointInTimeRecoverySpecification.RecoveryPeriodInDays must be between 1 and 35")
		}
	}
	if k := p.KinesisStreamSpecification; k != nil && k.StreamArn == "" {
		return p, fmt.Errorf("KinesisStreamSpecification.StreamArn is required")
	}
	for _, policy := range []*cfnDDBPolicy{p.ResourcePolicy, cfnDDBStreamPolicy(p)} {
		if policy != nil {
			if _, err := cfnDataPolicyDocument(policy.PolicyDocument); err != nil {
				return p, err
			}
		}
	}
	_, err := cfnComputeTags(raw)
	return p, err
}

func cfnDDBStreamPolicy(p cfnDDBTableProperties) *cfnDDBPolicy {
	if p.StreamSpecification == nil {
		return nil
	}
	return p.StreamSpecification.ResourcePolicy
}

func (h cfnDynamoDBTable) Validate(p cloudformation.Properties) error {
	_, err := cfnDDBTableDecode(p)
	return err
}

// Replacement follows the pinned schema: TableName and ImportSourceSpecification
// are create-only, KeySchema is conditionally create-only, and changing the type
// of an existing AttributeDefinition replaces the table.
func (h cfnDynamoDBTable) Replacement(a, b cloudformation.Properties) (bool, error) {
	before, err := cfnDDBTableDecode(a)
	if err != nil {
		return false, err
	}
	after, err := cfnDDBTableDecode(b)
	if err != nil {
		return false, err
	}
	replace := before.TableName != after.TableName || !reflect.DeepEqual(before.keys, after.keys)
	types := map[string]string{}
	for _, attribute := range before.AttributeDefinitions {
		types[attribute.AttributeName] = attribute.AttributeType
	}
	for _, attribute := range after.AttributeDefinitions {
		if kind, ok := types[attribute.AttributeName]; ok && kind != attribute.AttributeType {
			replace = true
		}
	}
	return cfnMessagingReplacement(after.TableName != "" && before.TableName == after.TableName, replace)
}

func cfnDDBKeys(keys []cfnDDBKey) []map[string]any {
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, map[string]any{"AttributeName": key.AttributeName, "KeyType": key.KeyType})
	}
	return out
}

func cfnDDBProjectionInput(p cfnDDBProjection) map[string]any {
	out := map[string]any{}
	if p.ProjectionType != "" {
		out["ProjectionType"] = p.ProjectionType
	}
	if len(p.NonKeyAttributes) > 0 {
		out["NonKeyAttributes"] = p.NonKeyAttributes
	}
	return out
}

func cfnDDBThroughputInput(p *cfnDDBThroughput) map[string]any {
	return map[string]any{"ReadCapacityUnits": int64(p.ReadCapacityUnits), "WriteCapacityUnits": int64(p.WriteCapacityUnits)}
}

func cfnDDBOnDemandInput(p *cfnDDBOnDemand) map[string]any {
	out := map[string]any{}
	if p.MaxReadRequestUnits != nil {
		out["MaxReadRequestUnits"] = int64(*p.MaxReadRequestUnits)
	}
	if p.MaxWriteRequestUnits != nil {
		out["MaxWriteRequestUnits"] = int64(*p.MaxWriteRequestUnits)
	}
	return out
}

func cfnDDBGSIInput(index cfnDDBGSI) map[string]any {
	out := map[string]any{"IndexName": index.IndexName, "KeySchema": cfnDDBKeys(index.KeySchema), "Projection": cfnDDBProjectionInput(index.Projection)}
	if index.ProvisionedThroughput != nil {
		out["ProvisionedThroughput"] = cfnDDBThroughputInput(index.ProvisionedThroughput)
	}
	if index.OnDemandThroughput != nil {
		out["OnDemandThroughput"] = cfnDDBOnDemandInput(index.OnDemandThroughput)
	}
	return out
}

func cfnDDBTagInput(tags map[string]string) []map[string]string {
	return cfnComputeTagList(tags)
}

// cfnDDBCreateInput projects the template into CreateTable. TTL, recovery,
// Kinesis destinations and stream policies need an ACTIVE table and are
// applied by Stabilize through their own owner operations.
func cfnDDBCreateInput(p cfnDDBTableProperties, name string, tags map[string]string) (map[string]any, error) {
	in := map[string]any{"TableName": name, "KeySchema": cfnDDBKeys(p.keys)}
	if len(tags) > 0 {
		in["Tags"] = cfnDDBTagInput(tags)
	}
	attributes := make([]map[string]any, 0, len(p.AttributeDefinitions))
	for _, attribute := range p.AttributeDefinitions {
		attributes = append(attributes, map[string]any{"AttributeName": attribute.AttributeName, "AttributeType": attribute.AttributeType})
	}
	in["AttributeDefinitions"] = attributes
	if p.BillingMode != "" {
		in["BillingMode"] = p.BillingMode
	}
	if p.ProvisionedThroughput != nil {
		in["ProvisionedThroughput"] = cfnDDBThroughputInput(p.ProvisionedThroughput)
	}
	if p.OnDemandThroughput != nil {
		in["OnDemandThroughput"] = cfnDDBOnDemandInput(p.OnDemandThroughput)
	}
	if len(p.GlobalSecondaryIndexes) > 0 {
		indexes := make([]map[string]any, 0, len(p.GlobalSecondaryIndexes))
		for _, index := range p.GlobalSecondaryIndexes {
			indexes = append(indexes, cfnDDBGSIInput(index))
		}
		in["GlobalSecondaryIndexes"] = indexes
	}
	if len(p.LocalSecondaryIndexes) > 0 {
		indexes := make([]map[string]any, 0, len(p.LocalSecondaryIndexes))
		for _, index := range p.LocalSecondaryIndexes {
			indexes = append(indexes, map[string]any{"IndexName": index.IndexName, "KeySchema": cfnDDBKeys(index.KeySchema), "Projection": cfnDDBProjectionInput(index.Projection)})
		}
		in["LocalSecondaryIndexes"] = indexes
	}
	if p.StreamSpecification != nil {
		in["StreamSpecification"] = map[string]any{"StreamEnabled": true, "StreamViewType": p.StreamSpecification.StreamViewType}
	}
	if p.DeletionProtectionEnabled != nil {
		in["DeletionProtectionEnabled"] = bool(*p.DeletionProtectionEnabled)
	}
	if p.TableClass != "" {
		in["TableClass"] = p.TableClass
	}
	if p.ResourcePolicy != nil {
		document, err := cfnDataPolicyDocument(p.ResourcePolicy.PolicyDocument)
		if err != nil {
			return nil, err
		}
		in["ResourcePolicy"] = document
	}
	return in, nil
}

func (h cfnDynamoDBTable) describe(ctx context.Context, name string) (*ddbapi.TableDescription, error) {
	out, err := cfnComputeCall[ddbapi.DescribeTableOutput](ctx, h.commands, "dynamodb", "DescribeTable", map[string]any{"TableName": name})
	if err != nil {
		return nil, err
	}
	if out.Table == nil {
		return nil, fmt.Errorf("DynamoDB returned no table description for %s", name)
	}
	return out.Table, nil
}

func cfnDDBTags(ctx context.Context, commands StepFunctionsCommands, arn string) (map[string]string, error) {
	tags := map[string]string{}
	in := map[string]any{"ResourceArn": arn}
	for {
		out, err := cfnComputeCall[ddbapi.ListTagsOfResourceOutput](ctx, commands, "dynamodb", "ListTagsOfResource", in)
		if err != nil {
			return nil, err
		}
		for _, tag := range out.Tags {
			tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
		}
		if cfnComputeValue(out.NextToken) == "" {
			return tags, nil
		}
		in["NextToken"] = cfnComputeValue(out.NextToken)
	}
}

func cfnDDBTableResult(table *ddbapi.TableDescription) cloudformation.ResourceResult {
	name := cfnComputeValue(table.TableName)
	attributes := map[string]any{"Arn": cfnComputeValue(table.TableArn)}
	if table.StreamSpecification != nil && cfnDataBool(table.StreamSpecification.StreamEnabled) && table.LatestStreamArn != nil {
		attributes["StreamArn"] = cfnComputeValue(table.LatestStreamArn)
	}
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: attributes}
}

// owned returns the current table only when it belongs to this resource
// incarnation. Cloud Control operations address existing owner resources.
func (h cfnDynamoDBTable) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (*ddbapi.TableDescription, error) {
	return h.describe(cfnDDBOwnerContext(ctx, r, false), name)
}

func (h cfnDynamoDBTable) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnDDBOwnerContext(ctx, r, true)
	p, err := cfnDDBTableDecode(r.Properties)
	if err != nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, err
	}
	name := cfnComputeName(r, "TableName", 255)
	if table, err := h.describe(ctx, name); err == nil {
		return cfnDDBTableResult(table), nil
	} else if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in, err := cfnDDBCreateInput(p, name, cfnDataCreateTags(r))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[ddbapi.CreateTableOutput](ctx, h.commands, "dynamodb", "CreateTable", in)
	if err != nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, err
	}
	if out.TableDescription == nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, fmt.Errorf("CreateTable returned no table description")
	}
	return cfnDDBTableResult(out.TableDescription), nil
}

func (h cfnDynamoDBTable) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	p, err := cfnDDBTableDecode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	table, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnDDBTableResult(table)
	if err := cfnDDBLocalIndexesUnchanged(p, table); err != nil {
		return result, err
	}
	if r.Previous != nil {
		previous, err := cfnDDBTableDecode(r.Previous)
		if err != nil {
			return result, err
		}
		if cfnDDBIndexChanges(previous.GlobalSecondaryIndexes, p.GlobalSecondaryIndexes) > 1 {
			return result, fmt.Errorf("a single DynamoDB table update can create or delete at most one global secondary index")
		}
	}
	if _, err := h.converge(ctx, r, p, table); err != nil {
		return result, err
	}
	return result, nil
}

func cfnDDBIndexChanges(before, after []cfnDDBGSI) int {
	names := map[string]bool{}
	for _, index := range before {
		names[index.IndexName] = true
	}
	changes := 0
	for _, index := range after {
		if !names[index.IndexName] {
			changes++
		}
		delete(names, index.IndexName)
	}
	return changes + len(names)
}

func cfnDDBLocalIndexesUnchanged(p cfnDDBTableProperties, table *ddbapi.TableDescription) error {
	if len(p.LocalSecondaryIndexes) != len(table.LocalSecondaryIndexes) {
		return fmt.Errorf("LocalSecondaryIndexes can only be defined when the table is created")
	}
	for _, want := range p.LocalSecondaryIndexes {
		index := slices.IndexFunc(table.LocalSecondaryIndexes, func(got ddbapi.LocalSecondaryIndexDescription) bool {
			return cfnComputeValue(got.IndexName) == want.IndexName
		})
		if index < 0 || !cfnDDBSameKeys(want.KeySchema, table.LocalSecondaryIndexes[index].KeySchema) || !cfnDDBSameProjection(want.Projection, table.LocalSecondaryIndexes[index].Projection) {
			return fmt.Errorf("LocalSecondaryIndexes can only be defined when the table is created")
		}
	}
	return nil
}

func cfnDDBSameKeys(want []cfnDDBKey, got ddbapi.KeySchema) bool {
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if want[i].AttributeName != cfnComputeValue(got[i].AttributeName) || want[i].KeyType != cfnComputeValue(got[i].KeyType) {
			return false
		}
	}
	return true
}

func cfnDDBSameProjection(want cfnDDBProjection, got *ddbapi.Projection) bool {
	if got == nil {
		return want.ProjectionType == "" && len(want.NonKeyAttributes) == 0
	}
	if want.ProjectionType != cfnComputeValue(got.ProjectionType) {
		return false
	}
	actual := make([]string, 0, len(got.NonKeyAttributes))
	for _, name := range got.NonKeyAttributes {
		actual = append(actual, string(name))
	}
	wanted := slices.Clone(want.NonKeyAttributes)
	slices.Sort(actual)
	slices.Sort(wanted)
	return slices.Equal(actual, wanted)
}

// Stabilize reports readiness only after the owner reports an ACTIVE table and
// every requested setting has been applied through its owner operation.
func (h cfnDynamoDBTable) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	p, err := cfnDDBTableDecode(r.Properties)
	if err != nil {
		return false, err
	}
	table, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	return h.converge(ctx, r, p, table)
}

func (h cfnDynamoDBTable) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	table, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnDDBTableResult(table), nil
}

// converge performs at most one asynchronous table transition per pass, in the
// order DynamoDB requires: capacity/settings, stream, index removal, index
// creation, then synchronous TTL, recovery, Kinesis, policies and tags.
func (h cfnDynamoDBTable) converge(ctx context.Context, r cloudformation.ResourceRequest, p cfnDDBTableProperties, table *ddbapi.TableDescription) (bool, error) {
	switch status := cfnComputeValue(table.TableStatus); status {
	case "ACTIVE":
	case "CREATING", "UPDATING":
		return false, nil
	default:
		return false, fmt.Errorf("DynamoDB table %s is %s", cfnComputeValue(table.TableName), status)
	}
	for _, index := range table.GlobalSecondaryIndexes {
		if cfnComputeValue(index.IndexStatus) != "ACTIVE" {
			return false, nil
		}
	}
	var previous *cfnDDBTableProperties
	if r.Previous != nil {
		decoded, err := cfnDDBTableDecode(r.Previous)
		if err != nil {
			return false, err
		}
		previous = &decoded
	}
	steps := []func() (bool, error){
		func() (bool, error) { return h.settings(ctx, p, table) },
		func() (bool, error) { return h.stream(ctx, p, table) },
		func() (bool, error) { return h.indexes(ctx, p, table) },
		func() (bool, error) { return h.ttl(ctx, p, previous, table) },
		func() (bool, error) { return h.recovery(ctx, p, previous, table) },
		func() (bool, error) { return h.kinesis(ctx, p, previous, table) },
		func() (bool, error) {
			return false, cfnDDBApplyPolicy(ctx, h.commands, cfnComputeValue(table.TableArn), p.ResourcePolicy, previous != nil && previous.ResourcePolicy != nil)
		},
		func() (bool, error) {
			if table.LatestStreamArn == nil || table.StreamSpecification == nil || !cfnDataBool(table.StreamSpecification.StreamEnabled) {
				return false, nil
			}
			return false, cfnDDBApplyPolicy(ctx, h.commands, cfnComputeValue(table.LatestStreamArn), cfnDDBStreamPolicy(p), previous != nil && cfnDDBStreamPolicy(*previous) != nil)
		},
		func() (bool, error) { return false, h.tags(ctx, r, cfnComputeValue(table.TableArn)) },
	}
	for _, step := range steps {
		waiting, err := step()
		if err != nil || waiting {
			return false, err
		}
	}
	return true, nil
}

func cfnDDBMode(table *ddbapi.TableDescription) string {
	if table.BillingModeSummary != nil && table.BillingModeSummary.BillingMode != nil {
		return cfnComputeValue(table.BillingModeSummary.BillingMode)
	}
	return "PROVISIONED"
}

func cfnDDBThroughputDiffers(want *cfnDDBThroughput, got *ddbapi.ProvisionedThroughputDescription) bool {
	if want == nil {
		return false
	}
	if got == nil {
		return true
	}
	return int64(want.ReadCapacityUnits) != cfnDataInt(got.ReadCapacityUnits) || int64(want.WriteCapacityUnits) != cfnDataInt(got.WriteCapacityUnits)
}

// cfnDDBOnDemandUpdate returns the owner update for configured maxima, using
// -1 to remove a maximum that the template no longer sets.
func cfnDDBOnDemandUpdate(want *cfnDDBOnDemand, got *ddbapi.OnDemandThroughput) map[string]any {
	var read, write int64 = -1, -1
	if want != nil && want.MaxReadRequestUnits != nil {
		read = int64(*want.MaxReadRequestUnits)
	}
	if want != nil && want.MaxWriteRequestUnits != nil {
		write = int64(*want.MaxWriteRequestUnits)
	}
	var currentRead, currentWrite int64 = -1, -1
	if got != nil {
		if v := cfnDataInt(got.MaxReadRequestUnits); v > 0 {
			currentRead = v
		}
		if v := cfnDataInt(got.MaxWriteRequestUnits); v > 0 {
			currentWrite = v
		}
	}
	out := map[string]any{}
	if read != currentRead {
		out["MaxReadRequestUnits"] = read
	}
	if write != currentWrite {
		out["MaxWriteRequestUnits"] = write
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (h cfnDynamoDBTable) settings(ctx context.Context, p cfnDDBTableProperties, table *ddbapi.TableDescription) (bool, error) {
	in := map[string]any{"TableName": cfnComputeValue(table.TableName)}
	mode := p.BillingMode
	if mode == "" {
		mode = "PROVISIONED"
	}
	current := cfnDDBMode(table)
	if mode != current {
		in["BillingMode"] = mode
	}
	if mode == "PROVISIONED" && (mode != current || cfnDDBThroughputDiffers(p.ProvisionedThroughput, table.ProvisionedThroughput)) && p.ProvisionedThroughput != nil {
		in["ProvisionedThroughput"] = cfnDDBThroughputInput(p.ProvisionedThroughput)
	}
	if mode == "PAY_PER_REQUEST" && mode == current {
		if update := cfnDDBOnDemandUpdate(p.OnDemandThroughput, table.OnDemandThroughput); update != nil {
			in["OnDemandThroughput"] = update
		}
	} else if mode == "PAY_PER_REQUEST" && p.OnDemandThroughput != nil {
		in["OnDemandThroughput"] = cfnDDBOnDemandInput(p.OnDemandThroughput)
	}
	class := p.TableClass
	if class == "" {
		class = "STANDARD"
	}
	currentClass := "STANDARD"
	if table.TableClassSummary != nil && table.TableClassSummary.TableClass != nil {
		currentClass = cfnComputeValue(table.TableClassSummary.TableClass)
	}
	if class != currentClass {
		in["TableClass"] = class
	}
	protection := p.DeletionProtectionEnabled != nil && bool(*p.DeletionProtectionEnabled)
	if protection != cfnDataBool(table.DeletionProtectionEnabled) {
		in["DeletionProtectionEnabled"] = protection
	}
	var updates []map[string]any
	for _, index := range p.GlobalSecondaryIndexes {
		position := slices.IndexFunc(table.GlobalSecondaryIndexes, func(got ddbapi.GlobalSecondaryIndexDescription) bool {
			return cfnComputeValue(got.IndexName) == index.IndexName
		})
		if position < 0 {
			continue
		}
		got := table.GlobalSecondaryIndexes[position]
		update := map[string]any{"IndexName": index.IndexName}
		switch {
		case mode == "PROVISIONED" && index.ProvisionedThroughput != nil && (mode != current || cfnDDBThroughputDiffers(index.ProvisionedThroughput, got.ProvisionedThroughput)):
			update["ProvisionedThroughput"] = cfnDDBThroughputInput(index.ProvisionedThroughput)
		case mode == "PAY_PER_REQUEST" && mode == current:
			if onDemand := cfnDDBOnDemandUpdate(index.OnDemandThroughput, got.OnDemandThroughput); onDemand != nil {
				update["OnDemandThroughput"] = onDemand
			}
		}
		if len(update) > 1 {
			updates = append(updates, map[string]any{"Update": update})
		}
	}
	if len(updates) > 0 {
		in["GlobalSecondaryIndexUpdates"] = updates
	}
	if len(in) == 1 {
		return false, nil
	}
	return true, cfnComputeRun(ctx, h.commands, "dynamodb", "UpdateTable", in)
}

// stream changes a view type by disabling the current stream before enabling
// the requested one, as DynamoDB does not change an enabled stream in place.
func (h cfnDynamoDBTable) stream(ctx context.Context, p cfnDDBTableProperties, table *ddbapi.TableDescription) (bool, error) {
	enabled := table.StreamSpecification != nil && cfnDataBool(table.StreamSpecification.StreamEnabled)
	view := ""
	if enabled {
		view = cfnComputeValue(table.StreamSpecification.StreamViewType)
	}
	want := ""
	if p.StreamSpecification != nil {
		want = p.StreamSpecification.StreamViewType
	}
	name := cfnComputeValue(table.TableName)
	switch {
	case enabled && view != want:
		return true, cfnComputeRun(ctx, h.commands, "dynamodb", "UpdateTable", map[string]any{"TableName": name, "StreamSpecification": map[string]any{"StreamEnabled": false}})
	case !enabled && want != "":
		return true, cfnComputeRun(ctx, h.commands, "dynamodb", "UpdateTable", map[string]any{"TableName": name, "StreamSpecification": map[string]any{"StreamEnabled": true, "StreamViewType": want}})
	}
	return false, nil
}

func (h cfnDynamoDBTable) indexes(ctx context.Context, p cfnDDBTableProperties, table *ddbapi.TableDescription) (bool, error) {
	name := cfnComputeValue(table.TableName)
	wanted := map[string]cfnDDBGSI{}
	for _, index := range p.GlobalSecondaryIndexes {
		wanted[index.IndexName] = index
	}
	for _, got := range table.GlobalSecondaryIndexes {
		index, ok := wanted[cfnComputeValue(got.IndexName)]
		if !ok {
			return true, cfnComputeRun(ctx, h.commands, "dynamodb", "UpdateTable", map[string]any{"TableName": name, "GlobalSecondaryIndexUpdates": []map[string]any{{"Delete": map[string]any{"IndexName": cfnComputeValue(got.IndexName)}}}})
		}
		if !cfnDDBSameKeys(index.KeySchema, got.KeySchema) || !cfnDDBSameProjection(index.Projection, got.Projection) {
			return false, fmt.Errorf("global secondary index %s key schema and projection cannot be updated; rename the index to replace it", index.IndexName)
		}
		delete(wanted, index.IndexName)
	}
	for _, index := range p.GlobalSecondaryIndexes {
		if _, missing := wanted[index.IndexName]; !missing {
			continue
		}
		attributes := []map[string]any{}
		for _, key := range index.KeySchema {
			for _, attribute := range p.AttributeDefinitions {
				if attribute.AttributeName == key.AttributeName {
					attributes = append(attributes, map[string]any{"AttributeName": attribute.AttributeName, "AttributeType": attribute.AttributeType})
				}
			}
		}
		return true, cfnComputeRun(ctx, h.commands, "dynamodb", "UpdateTable", map[string]any{"TableName": name, "AttributeDefinitions": attributes, "GlobalSecondaryIndexUpdates": []map[string]any{{"Create": cfnDDBGSIInput(index)}}})
	}
	return false, nil
}

func (h cfnDynamoDBTable) ttl(ctx context.Context, p cfnDDBTableProperties, previous *cfnDDBTableProperties, table *ddbapi.TableDescription) (bool, error) {
	if p.TimeToLiveSpecification == nil && (previous == nil || previous.TimeToLiveSpecification == nil) {
		return false, nil
	}
	return cfnDDBApplyTTL(ctx, h.commands, cfnComputeValue(table.TableName), p.TimeToLiveSpecification)
}

// cfnDDBApplyTTL drives the owner's TTL state toward the requested attribute.
// An attribute change disables first; the owner enforces its change interval.
func cfnDDBApplyTTL(ctx context.Context, commands StepFunctionsCommands, name string, want *cfnDDBTTL) (bool, error) {
	out, err := cfnComputeCall[ddbapi.DescribeTimeToLiveOutput](ctx, commands, "dynamodb", "DescribeTimeToLive", map[string]any{"TableName": name})
	if err != nil {
		return false, err
	}
	status, attribute := "DISABLED", ""
	if out.TimeToLiveDescription != nil {
		status = cfnComputeValue(out.TimeToLiveDescription.TimeToLiveStatus)
		attribute = cfnComputeValue(out.TimeToLiveDescription.AttributeName)
	}
	enabled := want != nil && bool(want.Enabled)
	active := status == "ENABLED" || status == "ENABLING"
	switch {
	case status == "ENABLING" || status == "DISABLING":
		if enabled && status == "ENABLING" && attribute == want.AttributeName {
			return false, nil
		}
		return true, nil
	case active && (!enabled || attribute != want.AttributeName):
		return true, cfnComputeRun(ctx, commands, "dynamodb", "UpdateTimeToLive", map[string]any{"TableName": name, "TimeToLiveSpecification": map[string]any{"Enabled": false, "AttributeName": attribute}})
	case !active && enabled:
		return false, cfnComputeRun(ctx, commands, "dynamodb", "UpdateTimeToLive", map[string]any{"TableName": name, "TimeToLiveSpecification": map[string]any{"Enabled": true, "AttributeName": want.AttributeName}})
	}
	return false, nil
}

func (h cfnDynamoDBTable) recovery(ctx context.Context, p cfnDDBTableProperties, previous *cfnDDBTableProperties, table *ddbapi.TableDescription) (bool, error) {
	if p.PointInTimeRecoverySpecification == nil && (previous == nil || previous.PointInTimeRecoverySpecification == nil) {
		return false, nil
	}
	return cfnDDBApplyRecovery(ctx, h.commands, cfnComputeValue(table.TableName), p.PointInTimeRecoverySpecification)
}

// cfnDDBApplyRecovery waits for continuous backups to become available after
// table creation, then applies point-in-time recovery through the owner.
func cfnDDBApplyRecovery(ctx context.Context, commands StepFunctionsCommands, name string, want *cfnDDBPITR) (bool, error) {
	out, err := cfnComputeCall[ddbapi.DescribeContinuousBackupsOutput](ctx, commands, "dynamodb", "DescribeContinuousBackups", map[string]any{"TableName": name})
	if cfnMessagingMissing(err, "TableNotFoundException", "ContinuousBackupsUnavailableException") {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	description := out.ContinuousBackupsDescription
	if description == nil || cfnComputeValue(description.ContinuousBackupsStatus) != "ENABLED" {
		return true, nil
	}
	enabled := want != nil && want.PointInTimeRecoveryEnabled != nil && bool(*want.PointInTimeRecoveryEnabled)
	period := int64(35)
	if want != nil && want.RecoveryPeriodInDays != nil {
		period = int64(*want.RecoveryPeriodInDays)
	}
	current := description.PointInTimeRecoveryDescription
	currentEnabled := current != nil && cfnComputeValue(current.PointInTimeRecoveryStatus) == "ENABLED"
	currentPeriod := int64(35)
	if current != nil && current.RecoveryPeriodInDays != nil {
		currentPeriod = cfnDataInt(current.RecoveryPeriodInDays)
	}
	if enabled == currentEnabled && (!enabled || period == currentPeriod) {
		return false, nil
	}
	spec := map[string]any{"PointInTimeRecoveryEnabled": enabled}
	if enabled && want.RecoveryPeriodInDays != nil {
		spec["RecoveryPeriodInDays"] = period
	}
	err = cfnComputeRun(ctx, commands, "dynamodb", "UpdateContinuousBackups", map[string]any{"TableName": name, "PointInTimeRecoverySpecification": spec})
	if cfnMessagingMissing(err, "ContinuousBackupsUnavailableException") {
		return true, nil
	}
	return false, err
}

func (h cfnDynamoDBTable) kinesis(ctx context.Context, p cfnDDBTableProperties, previous *cfnDDBTableProperties, table *ddbapi.TableDescription) (bool, error) {
	if p.KinesisStreamSpecification == nil && (previous == nil || previous.KinesisStreamSpecification == nil) {
		return false, nil
	}
	return cfnDDBApplyKinesis(ctx, h.commands, cfnComputeValue(table.TableName), p.KinesisStreamSpecification)
}

// cfnDDBApplyKinesis keeps at most the requested destination enabled. Other
// active destinations are disabled first; failed enablement is reported.
func cfnDDBApplyKinesis(ctx context.Context, commands StepFunctionsCommands, name string, want *cfnDDBKinesis) (bool, error) {
	out, err := cfnComputeCall[ddbapi.DescribeKinesisStreamingDestinationOutput](ctx, commands, "dynamodb", "DescribeKinesisStreamingDestination", map[string]any{"TableName": name})
	if err != nil {
		return false, err
	}
	precision := "MILLISECOND"
	if want != nil && want.ApproximateCreationDateTimePrecision != "" {
		precision = want.ApproximateCreationDateTimePrecision
	}
	var matched *ddbapi.KinesisDataStreamDestination
	for i, destination := range out.KinesisDataStreamDestinations {
		arn, status := cfnComputeValue(destination.StreamArn), cfnComputeValue(destination.DestinationStatus)
		if want != nil && arn == want.StreamArn {
			matched = &out.KinesisDataStreamDestinations[i]
			continue
		}
		switch status {
		case "ENABLING", "UPDATING", "DISABLING":
			return true, nil
		case "ACTIVE":
			return true, cfnComputeRun(ctx, commands, "dynamodb", "DisableKinesisStreamingDestination", map[string]any{"TableName": name, "StreamArn": arn})
		}
	}
	if want == nil {
		return false, nil
	}
	status := ""
	if matched != nil {
		status = cfnComputeValue(matched.DestinationStatus)
	}
	switch status {
	case "ENABLING", "UPDATING", "DISABLING":
		return true, nil
	case "ENABLE_FAILED":
		return false, fmt.Errorf("Kinesis streaming destination %s failed: %s", want.StreamArn, cfnComputeValue(matched.DestinationStatusDescription))
	case "ACTIVE":
		current := cfnComputeValue(matched.ApproximateCreationDateTimePrecision)
		if current == "" {
			current = "MILLISECOND"
		}
		if current == precision {
			return false, nil
		}
		return true, cfnComputeRun(ctx, commands, "dynamodb", "UpdateKinesisStreamingDestination", map[string]any{"TableName": name, "StreamArn": want.StreamArn, "UpdateKinesisStreamingConfiguration": map[string]any{"ApproximateCreationDateTimePrecision": precision}})
	}
	in := map[string]any{"TableName": name, "StreamArn": want.StreamArn}
	if want.ApproximateCreationDateTimePrecision != "" {
		in["EnableKinesisStreamingConfiguration"] = map[string]any{"ApproximateCreationDateTimePrecision": precision}
	}
	return true, cfnComputeRun(ctx, commands, "dynamodb", "EnableKinesisStreamingDestination", in)
}

// cfnDDBPolicy applies a declared table or stream policy. As documented for
// the resource type, a policy is removed only when this template previously
// declared it; an out-of-band policy is not adopted or deleted.
func cfnDDBApplyPolicy(ctx context.Context, commands StepFunctionsCommands, arn string, want *cfnDDBPolicy, previous bool) error {
	if want == nil && !previous {
		return nil
	}
	current, err := cfnComputeCall[ddbapi.GetResourcePolicyOutput](ctx, commands, "dynamodb", "GetResourcePolicy", map[string]any{"ResourceArn": arn})
	exists := err == nil
	if err != nil && !cfnMessagingMissing(err, "PolicyNotFoundException") {
		return err
	}
	if want == nil {
		if !exists {
			return nil
		}
		return cfnComputeRun(ctx, commands, "dynamodb", "DeleteResourcePolicy", map[string]any{"ResourceArn": arn})
	}
	document, err := cfnDataPolicyDocument(want.PolicyDocument)
	if err != nil {
		return err
	}
	if exists && cfnDataEqualJSON(cfnComputeValue(current.Policy), document) {
		return nil
	}
	return cfnComputeRun(ctx, commands, "dynamodb", "PutResourcePolicy", map[string]any{"ResourceArn": arn, "Policy": document})
}

func (h cfnDynamoDBTable) tags(ctx context.Context, r cloudformation.ResourceRequest, arn string) error {
	return cfnDDBReconcileTags(ctx, h.commands, r, arn, cfnDataCreateTags(r))
}

func cfnDDBReconcileTags(ctx context.Context, commands StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, owned map[string]string) error {
	current, err := cfnDDBTags(ctx, commands, arn)
	if err != nil {
		return err
	}
	desired := owned
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, commands, "dynamodb", "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if changed := cfnDataChangedTags(current, desired); len(changed) > 0 {
		return cfnComputeRun(ctx, commands, "dynamodb", "TagResource", map[string]any{"ResourceArn": arn, "Tags": cfnDDBTagInput(changed)})
	}
	return nil
}

// Delete admits deletion only for an ACTIVE owned table; a transitioning table
// is deleted by StabilizeDeletion as soon as the owner permits it.
func (h cfnDynamoDBTable) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	_, err := h.deleteOnce(ctx, r)
	return err
}

func (h cfnDynamoDBTable) deleteOnce(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	name := r.PhysicalID
	if name == "" {
		name = cfnComputeName(r, "TableName", 255)
	}
	table, err := h.owned(ctx, r, name)
	if cfnComputeMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if cfnComputeValue(table.TableStatus) != "ACTIVE" {
		return false, nil
	}
	err = cfnComputeRun(ctx, h.commands, "dynamodb", "DeleteTable", map[string]any{"TableName": name})
	if cfnComputeMissing(err) {
		return true, nil
	}
	return false, err
}

func (h cfnDynamoDBTable) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	return h.deleteOnce(ctx, r)
}

func (h cfnDynamoDBTable) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	table, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cfnDDBDescriptionProperties(table)
	name := cfnComputeValue(table.TableName)
	ttl, err := cfnComputeCall[ddbapi.DescribeTimeToLiveOutput](ctx, h.commands, "dynamodb", "DescribeTimeToLive", map[string]any{"TableName": name})
	if err != nil {
		return nil, err
	}
	if d := ttl.TimeToLiveDescription; d != nil && d.AttributeName != nil {
		p["TimeToLiveSpecification"] = map[string]any{"Enabled": cfnComputeValue(d.TimeToLiveStatus) == "ENABLED" || cfnComputeValue(d.TimeToLiveStatus) == "ENABLING", "AttributeName": cfnComputeValue(d.AttributeName)}
	}
	backups, err := cfnComputeCall[ddbapi.DescribeContinuousBackupsOutput](ctx, h.commands, "dynamodb", "DescribeContinuousBackups", map[string]any{"TableName": name})
	if err != nil && !cfnMessagingMissing(err, "TableNotFoundException", "ContinuousBackupsUnavailableException") {
		return nil, err
	}
	if err == nil && backups.ContinuousBackupsDescription != nil && backups.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
		d := backups.ContinuousBackupsDescription.PointInTimeRecoveryDescription
		spec := map[string]any{"PointInTimeRecoveryEnabled": cfnComputeValue(d.PointInTimeRecoveryStatus) == "ENABLED"}
		if d.RecoveryPeriodInDays != nil {
			spec["RecoveryPeriodInDays"] = cfnDataInt(d.RecoveryPeriodInDays)
		}
		p["PointInTimeRecoverySpecification"] = spec
	}
	destinations, err := cfnComputeCall[ddbapi.DescribeKinesisStreamingDestinationOutput](ctx, h.commands, "dynamodb", "DescribeKinesisStreamingDestination", map[string]any{"TableName": name})
	if err != nil {
		return nil, err
	}
	for _, d := range destinations.KinesisDataStreamDestinations {
		if status := cfnComputeValue(d.DestinationStatus); status == "ACTIVE" || status == "ENABLING" || status == "UPDATING" {
			spec := map[string]any{"StreamArn": cfnComputeValue(d.StreamArn)}
			if d.ApproximateCreationDateTimePrecision != nil {
				spec["ApproximateCreationDateTimePrecision"] = cfnComputeValue(d.ApproximateCreationDateTimePrecision)
			}
			p["KinesisStreamSpecification"] = spec
		}
	}
	policy, err := cfnComputeCall[ddbapi.GetResourcePolicyOutput](ctx, h.commands, "dynamodb", "GetResourcePolicy", map[string]any{"ResourceArn": cfnComputeValue(table.TableArn)})
	if err != nil && !cfnMessagingMissing(err, "PolicyNotFoundException") {
		return nil, err
	}
	if err == nil {
		var document map[string]any
		if err := json.Unmarshal([]byte(cfnComputeValue(policy.Policy)), &document); err != nil {
			return nil, err
		}
		p["ResourcePolicy"] = map[string]any{"PolicyDocument": document}
	}
	tags, err := cfnDDBTags(ctx, h.commands, cfnComputeValue(table.TableArn))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnDataUserTags(tags)
	return p, nil
}

// cfnDDBDescriptionProperties projects the owner's DescribeTable model into
// the pinned CloudFormation property names.
func cfnDDBDescriptionProperties(table *ddbapi.TableDescription) cloudformation.Properties {
	mode := cfnDDBMode(table)
	p := cloudformation.Properties{
		"TableName":                 cfnComputeValue(table.TableName),
		"Arn":                       cfnComputeValue(table.TableArn),
		"AttributeDefinitions":      cfnDataJSON(table.AttributeDefinitions),
		"KeySchema":                 cfnDataJSON(table.KeySchema),
		"BillingMode":               mode,
		"DeletionProtectionEnabled": cfnDataBool(table.DeletionProtectionEnabled),
	}
	if mode == "PROVISIONED" && table.ProvisionedThroughput != nil {
		p["ProvisionedThroughput"] = map[string]any{"ReadCapacityUnits": cfnDataInt(table.ProvisionedThroughput.ReadCapacityUnits), "WriteCapacityUnits": cfnDataInt(table.ProvisionedThroughput.WriteCapacityUnits)}
	}
	if mode == "PAY_PER_REQUEST" {
		if onDemand := cfnDDBOnDemandProperties(table.OnDemandThroughput); onDemand != nil {
			p["OnDemandThroughput"] = onDemand
		}
	}
	if table.TableClassSummary != nil && table.TableClassSummary.TableClass != nil {
		p["TableClass"] = cfnComputeValue(table.TableClassSummary.TableClass)
	}
	if table.StreamSpecification != nil && cfnDataBool(table.StreamSpecification.StreamEnabled) {
		p["StreamSpecification"] = map[string]any{"StreamViewType": cfnComputeValue(table.StreamSpecification.StreamViewType)}
		p["StreamArn"] = cfnComputeValue(table.LatestStreamArn)
	}
	if len(table.GlobalSecondaryIndexes) > 0 {
		indexes := make([]any, 0, len(table.GlobalSecondaryIndexes))
		for _, index := range table.GlobalSecondaryIndexes {
			item := map[string]any{"IndexName": cfnComputeValue(index.IndexName), "KeySchema": cfnDataJSON(index.KeySchema), "Projection": cfnDataJSON(index.Projection)}
			if mode == "PROVISIONED" && index.ProvisionedThroughput != nil {
				item["ProvisionedThroughput"] = map[string]any{"ReadCapacityUnits": cfnDataInt(index.ProvisionedThroughput.ReadCapacityUnits), "WriteCapacityUnits": cfnDataInt(index.ProvisionedThroughput.WriteCapacityUnits)}
			}
			if onDemand := cfnDDBOnDemandProperties(index.OnDemandThroughput); mode == "PAY_PER_REQUEST" && onDemand != nil {
				item["OnDemandThroughput"] = onDemand
			}
			indexes = append(indexes, item)
		}
		p["GlobalSecondaryIndexes"] = indexes
	}
	if len(table.LocalSecondaryIndexes) > 0 {
		indexes := make([]any, 0, len(table.LocalSecondaryIndexes))
		for _, index := range table.LocalSecondaryIndexes {
			indexes = append(indexes, map[string]any{"IndexName": cfnComputeValue(index.IndexName), "KeySchema": cfnDataJSON(index.KeySchema), "Projection": cfnDataJSON(index.Projection)})
		}
		p["LocalSecondaryIndexes"] = indexes
	}
	return p
}

func cfnDDBOnDemandProperties(v *ddbapi.OnDemandThroughput) map[string]any {
	if v == nil {
		return nil
	}
	out := map[string]any{}
	if n := cfnDataInt(v.MaxReadRequestUnits); n > 0 {
		out["MaxReadRequestUnits"] = n
	}
	if n := cfnDataInt(v.MaxWriteRequestUnits); n > 0 {
		out["MaxWriteRequestUnits"] = n
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (h cfnDynamoDBTable) List(ctx context.Context, _ cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[ddbapi.ListTablesOutput](ctx, h.commands, "dynamodb", "ListTables", in)
		if err != nil {
			return nil, err
		}
		for _, name := range out.TableNames {
			result = append(result, cloudformation.ResourceDescription{Identifier: string(name), Properties: cloudformation.Properties{"TableName": string(name)}})
		}
		if out.LastEvaluatedTableName == nil {
			return result, nil
		}
		in["ExclusiveStartTableName"] = cfnComputeValue(out.LastEvaluatedTableName)
	}
}
