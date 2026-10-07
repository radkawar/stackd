package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	ddbapi "stackd/internal/awsapi/dynamodb"
	"stackd/internal/services/cloudformation"
)

// cfnDynamoDBGlobalTable manages a version 2019.11.21 global table through the
// DynamoDB owner's regional table and ReplicaUpdates commands. The stack-Region
// table is the physical identity; other replicas are owner-created members.
type cfnDynamoDBGlobalTable struct{ commands StepFunctionsCommands }

type cfnDDBGlobalIndex struct {
	IndexName                          string
	KeySchema                          []cfnDDBKey
	Projection                         cfnDDBProjection
	WarmThroughput                     json.RawMessage
	ReadProvisionedThroughputSettings  json.RawMessage
	WriteProvisionedThroughputSettings json.RawMessage
	ReadOnDemandThroughputSettings     json.RawMessage
	WriteOnDemandThroughputSettings    json.RawMessage
}

type cfnDDBReplica struct {
	Region                             string
	Tags                               []cfnMessagingTag
	DeletionProtectionEnabled          *cfnMessagingBool
	TableClass                         string
	PointInTimeRecoverySpecification   *cfnDDBPITR
	SSESpecification                   json.RawMessage
	KinesisStreamSpecification         json.RawMessage
	ContributorInsightsSpecification   json.RawMessage
	GlobalTableSettingsReplicationMode string
	ReplicaStreamSpecification         json.RawMessage
	GlobalSecondaryIndexes             json.RawMessage
	ResourcePolicy                     json.RawMessage
	ReadProvisionedThroughputSettings  json.RawMessage
	ReadOnDemandThroughputSettings     json.RawMessage
}

type cfnDDBGlobalProperties struct {
	TableName                          string
	AttributeDefinitions               []cfnDDBAttribute
	KeySchema                          []cfnDDBKey
	BillingMode                        string
	GlobalSecondaryIndexes             []cfnDDBGlobalIndex
	LocalSecondaryIndexes              []cfnDDBLSI
	StreamSpecification                *cfnDDBStream
	TimeToLiveSpecification            *cfnDDBTTL
	Replicas                           []cfnDDBReplica
	SSESpecification                   *cfnDDBSSE
	MultiRegionConsistency             string
	GlobalTableWitnesses               json.RawMessage
	GlobalTableSourceArn               json.RawMessage
	WarmThroughput                     json.RawMessage
	VectorIndexes                      json.RawMessage
	ReadProvisionedThroughputSettings  json.RawMessage
	WriteProvisionedThroughputSettings json.RawMessage
	ReadOnDemandThroughputSettings     json.RawMessage
	WriteOnDemandThroughputSettings    json.RawMessage
}

func cfnDDBGlobalDecode(raw cloudformation.Properties) (cfnDDBGlobalProperties, error) {
	var p cfnDDBGlobalProperties
	if raw == nil {
		raw = cloudformation.Properties{}
	}
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, err
	}
	unsupported := map[string]bool{
		// Provisioned global tables require replica write auto scaling settings,
		// which this adapter does not drive through Application Auto Scaling.
		"BillingMode=PROVISIONED":            p.BillingMode != "PAY_PER_REQUEST",
		"SSESpecification (KMS)":             p.SSESpecification != nil && (bool(p.SSESpecification.SSEEnabled) || p.SSESpecification.SSEType != ""),
		"MultiRegionConsistency=STRONG":      p.MultiRegionConsistency != "" && p.MultiRegionConsistency != "EVENTUAL",
		"GlobalTableWitnesses":               cfnDataRaw(p.GlobalTableWitnesses),
		"GlobalTableSourceArn":               cfnDataRaw(p.GlobalTableSourceArn),
		"WarmThroughput":                     cfnDataRaw(p.WarmThroughput),
		"VectorIndexes":                      cfnDataRaw(p.VectorIndexes),
		"ReadProvisionedThroughputSettings":  cfnDataRaw(p.ReadProvisionedThroughputSettings),
		"WriteProvisionedThroughputSettings": cfnDataRaw(p.WriteProvisionedThroughputSettings),
		"ReadOnDemandThroughputSettings":     cfnDataRaw(p.ReadOnDemandThroughputSettings),
		"WriteOnDemandThroughputSettings":    cfnDataRaw(p.WriteOnDemandThroughputSettings),
		"StreamSpecification.ResourcePolicy": p.StreamSpecification != nil && p.StreamSpecification.ResourcePolicy != nil,
		"StreamSpecification.Tags":           p.StreamSpecification != nil && cfnDataRaw(p.StreamSpecification.Tags),
	}
	for _, index := range p.GlobalSecondaryIndexes {
		for name, present := range map[string]bool{"WarmThroughput": cfnDataRaw(index.WarmThroughput), "ReadProvisionedThroughputSettings": cfnDataRaw(index.ReadProvisionedThroughputSettings), "WriteProvisionedThroughputSettings": cfnDataRaw(index.WriteProvisionedThroughputSettings), "ReadOnDemandThroughputSettings": cfnDataRaw(index.ReadOnDemandThroughputSettings), "WriteOnDemandThroughputSettings": cfnDataRaw(index.WriteOnDemandThroughputSettings)} {
			if present {
				unsupported["GlobalSecondaryIndexes."+name] = true
			}
		}
	}
	regions := map[string]bool{}
	for _, replica := range p.Replicas {
		if replica.Region == "" || regions[replica.Region] {
			return p, fmt.Errorf("replicas must name distinct Regions")
		}
		regions[replica.Region] = true
		for name, present := range map[string]bool{"SSESpecification": cfnDataRaw(replica.SSESpecification), "KinesisStreamSpecification": cfnDataRaw(replica.KinesisStreamSpecification), "ContributorInsightsSpecification": cfnDataRaw(replica.ContributorInsightsSpecification), "ReplicaStreamSpecification": cfnDataRaw(replica.ReplicaStreamSpecification), "GlobalSecondaryIndexes": cfnDataRaw(replica.GlobalSecondaryIndexes), "ResourcePolicy": cfnDataRaw(replica.ResourcePolicy), "ReadProvisionedThroughputSettings": cfnDataRaw(replica.ReadProvisionedThroughputSettings), "ReadOnDemandThroughputSettings": cfnDataRaw(replica.ReadOnDemandThroughputSettings), "GlobalTableSettingsReplicationMode=DISABLED": replica.GlobalTableSettingsReplicationMode == "DISABLED"} {
			if present {
				unsupported["Replicas."+name] = true
			}
		}
		if pitr := replica.PointInTimeRecoverySpecification; pitr != nil && pitr.RecoveryPeriodInDays != nil && (pitr.PointInTimeRecoveryEnabled == nil || *pitr.RecoveryPeriodInDays < 1 || *pitr.RecoveryPeriodInDays > 35) {
			return p, fmt.Errorf("Replicas.PointInTimeRecoverySpecification.RecoveryPeriodInDays requires PointInTimeRecoveryEnabled and must be between 1 and 35")
		}
		if err := cfnDDBReplicaTagsValid(replica.Tags); err != nil {
			return p, err
		}
	}
	if err := cfnDataUnsupported("The stackd DynamoDB global table owner", unsupported); err != nil {
		return p, err
	}
	if len(p.Replicas) == 0 {
		return p, fmt.Errorf("replicas must contain the stack Region")
	}
	if len(p.KeySchema) == 0 || len(p.AttributeDefinitions) == 0 {
		return p, fmt.Errorf("KeySchema and AttributeDefinitions are required to create a global table")
	}
	if p.StreamSpecification == nil && len(p.Replicas) > 1 {
		return p, fmt.Errorf("StreamSpecification is required when a global table has more than one replica")
	}
	if p.StreamSpecification != nil && len(p.Replicas) > 1 && p.StreamSpecification.StreamViewType != "NEW_AND_OLD_IMAGES" {
		return p, fmt.Errorf("global table replication requires StreamViewType NEW_AND_OLD_IMAGES")
	}
	if ttl := p.TimeToLiveSpecification; ttl != nil && bool(ttl.Enabled) && ttl.AttributeName == "" {
		return p, fmt.Errorf("TimeToLiveSpecification.AttributeName is required when TTL is enabled")
	}
	return p, nil
}

func cfnDDBReplicaTagsValid(tags []cfnMessagingTag) error {
	list := make([]any, 0, len(tags))
	for _, tag := range tags {
		list = append(list, map[string]any{"Key": tag.Key, "Value": tag.Value})
	}
	_, err := cfnComputeTags(map[string]any{"Tags": list})
	return err
}

func (p cfnDDBGlobalProperties) replica(region string) (cfnDDBReplica, bool) {
	index := slices.IndexFunc(p.Replicas, func(r cfnDDBReplica) bool { return r.Region == region })
	if index < 0 {
		return cfnDDBReplica{}, false
	}
	return p.Replicas[index], true
}

// table projects the global table's stack-Region settings onto the regional
// table converger. Table-level settings propagate through the owner's group.
func (p cfnDDBGlobalProperties) table(region string) cfnDDBTableProperties {
	local, _ := p.replica(region)
	out := cfnDDBTableProperties{TableName: p.TableName, AttributeDefinitions: p.AttributeDefinitions, BillingMode: p.BillingMode, LocalSecondaryIndexes: p.LocalSecondaryIndexes, StreamSpecification: p.StreamSpecification, TimeToLiveSpecification: p.TimeToLiveSpecification, DeletionProtectionEnabled: local.DeletionProtectionEnabled, TableClass: local.TableClass, keys: p.KeySchema}
	for _, index := range p.GlobalSecondaryIndexes {
		out.GlobalSecondaryIndexes = append(out.GlobalSecondaryIndexes, cfnDDBGSI{IndexName: index.IndexName, KeySchema: index.KeySchema, Projection: index.Projection})
	}
	return out
}

func (h cfnDynamoDBGlobalTable) Validate(p cloudformation.Properties) error {
	_, err := cfnDDBGlobalDecode(p)
	return err
}

// TableName is create-only; KeySchema and LocalSecondaryIndexes are
// conditionally create-only in the pinned schema.
func (h cfnDynamoDBGlobalTable) Replacement(a, b cloudformation.Properties) (bool, error) {
	before, err := cfnDDBGlobalDecode(a)
	if err != nil {
		return false, err
	}
	after, err := cfnDDBGlobalDecode(b)
	if err != nil {
		return false, err
	}
	replace := before.TableName != after.TableName || !slices.Equal(before.KeySchema, after.KeySchema) || !cfnDDBSameLSIs(before.LocalSecondaryIndexes, after.LocalSecondaryIndexes)
	return cfnMessagingReplacement(after.TableName != "" && before.TableName == after.TableName, replace)
}

func cfnDDBSameLSIs(a, b []cfnDDBLSI) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func (h cfnDynamoDBGlobalTable) table() cfnDynamoDBTable { return cfnDynamoDBTable(h) }

func cfnDDBGlobalResult(table *ddbapi.TableDescription) cloudformation.ResourceResult {
	result := cfnDDBTableResult(table)
	result.Attributes["TableId"] = cfnComputeValue(table.TableId)
	return result
}

// cfnDDBReplicaTags combines stack tags, incarnation ownership and the
// replica's declared tags for one Region.
func cfnDDBReplicaTags(r cloudformation.ResourceRequest, replica cfnDDBReplica) map[string]string {
	tags := cfnDataCreateTags(r)
	for _, tag := range replica.Tags {
		tags[tag.Key] = tag.Value
	}
	return tags
}

func (h cfnDynamoDBGlobalTable) local(r cloudformation.ResourceRequest, p cfnDDBGlobalProperties) (cfnDDBReplica, error) {
	replica, ok := p.replica(r.Scope.Region)
	if !ok {
		return replica, fmt.Errorf("replicas must include the stack Region %s", r.Scope.Region)
	}
	return replica, nil
}

func (h cfnDynamoDBGlobalTable) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnDDBOwnerContext(ctx, r, true)
	p, err := cfnDDBGlobalDecode(r.Properties)
	if err != nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, err
	}
	local, err := h.local(r, p)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "TableName", 255)
	if table, err := h.table().describe(ctx, name); err == nil {
		return cfnDDBGlobalResult(table), nil
	} else if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in, err := cfnDDBCreateInput(p.table(r.Scope.Region), name, cfnDDBReplicaTags(r, local))
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
	return cfnDDBGlobalResult(out.TableDescription), nil
}

func (h cfnDynamoDBGlobalTable) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	p, err := cfnDDBGlobalDecode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if _, err := h.local(r, p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	table, err := h.table().owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnDDBGlobalResult(table)
	if r.Previous != nil {
		previous, err := cfnDDBGlobalDecode(r.Previous)
		if err != nil {
			return result, err
		}
		if cfnDDBIndexChanges(previous.table(r.Scope.Region).GlobalSecondaryIndexes, p.table(r.Scope.Region).GlobalSecondaryIndexes) > 1 {
			return result, fmt.Errorf("a single global table update can create or delete at most one global secondary index")
		}
		added, removed := 0, 0
		for _, replica := range p.Replicas {
			if _, ok := previous.replica(replica.Region); !ok {
				added++
			}
		}
		for _, replica := range previous.Replicas {
			if _, ok := p.replica(replica.Region); !ok {
				removed++
			}
		}
		if added+removed > 1 {
			return result, fmt.Errorf("a single global table update can add or remove at most one replica")
		}
	}
	_, err = h.converge(ctx, r, p, table)
	return result, err
}

func (h cfnDynamoDBGlobalTable) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	p, err := cfnDDBGlobalDecode(r.Properties)
	if err != nil {
		return false, err
	}
	table, err := h.table().describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	return h.converge(ctx, r, p, table)
}

func (h cfnDynamoDBGlobalTable) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	table, err := h.table().describe(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnDDBGlobalResult(table), nil
}

func cfnDDBReplicasSettled(table *ddbapi.TableDescription) bool {
	for _, replica := range table.Replicas {
		if cfnComputeValue(replica.ReplicaStatus) != "ACTIVE" {
			return false
		}
	}
	return true
}

func (h cfnDynamoDBGlobalTable) converge(ctx context.Context, r cloudformation.ResourceRequest, p cfnDDBGlobalProperties, table *ddbapi.TableDescription) (bool, error) {
	if status := cfnComputeValue(table.TableStatus); status != "ACTIVE" {
		if status == "CREATING" || status == "UPDATING" {
			return false, nil
		}
		return false, fmt.Errorf("DynamoDB global table %s is %s", cfnComputeValue(table.TableName), status)
	}
	for _, index := range table.GlobalSecondaryIndexes {
		if cfnComputeValue(index.IndexStatus) != "ACTIVE" {
			return false, nil
		}
	}
	for _, replica := range table.Replicas {
		switch status := cfnComputeValue(replica.ReplicaStatus); status {
		case "ACTIVE":
		case "CREATING", "UPDATING", "DELETING":
			return false, nil
		default:
			return false, fmt.Errorf("global table replica %s is %s: %s", cfnComputeValue(replica.RegionName), status, cfnComputeValue(replica.ReplicaStatusDescription))
		}
	}
	name := cfnComputeValue(table.TableName)
	local := p.table(r.Scope.Region)
	var previous *cfnDDBTableProperties
	if r.Previous != nil {
		old, err := cfnDDBGlobalDecode(r.Previous)
		if err != nil {
			return false, err
		}
		projected := old.table(r.Scope.Region)
		previous = &projected
	}
	regional := h.table()
	for _, step := range []func() (bool, error){
		func() (bool, error) { return regional.settings(ctx, local, table) },
		func() (bool, error) { return regional.stream(ctx, local, table) },
		func() (bool, error) { return regional.indexes(ctx, local, table) },
		func() (bool, error) {
			for _, replica := range table.Replicas {
				region := cfnComputeValue(replica.RegionName)
				if _, ok := p.replica(region); !ok {
					return true, cfnComputeRun(ctx, h.commands, "dynamodb", "UpdateTable", map[string]any{"TableName": name, "ReplicaUpdates": []map[string]any{{"Delete": map[string]any{"RegionName": region}}}})
				}
			}
			return false, nil
		},
		func() (bool, error) {
			for _, replica := range p.Replicas {
				if replica.Region == r.Scope.Region || slices.ContainsFunc(table.Replicas, func(d ddbapi.ReplicaDescription) bool { return cfnComputeValue(d.RegionName) == replica.Region }) {
					continue
				}
				create := map[string]any{"RegionName": replica.Region}
				if replica.TableClass != "" {
					create["TableClassOverride"] = replica.TableClass
				}
				return true, cfnComputeRun(ctx, h.commands, "dynamodb", "UpdateTable", map[string]any{"TableName": name, "ReplicaUpdates": []map[string]any{{"Create": create}}})
			}
			return false, nil
		},
		func() (bool, error) { return h.replicaClasses(ctx, p, r.Scope.Region, table) },
		func() (bool, error) { return regional.ttl(ctx, local, previous, table) },
		func() (bool, error) { return h.replicas(ctx, r, p) },
	} {
		waiting, err := step()
		if err != nil || waiting {
			return false, err
		}
	}
	return true, nil
}

// replicaClasses applies replica table-class overrides through the source
// table's ReplicaUpdates, which the owner propagates to the regional member.
func (h cfnDynamoDBGlobalTable) replicaClasses(ctx context.Context, p cfnDDBGlobalProperties, region string, table *ddbapi.TableDescription) (bool, error) {
	source := "STANDARD"
	if table.TableClassSummary != nil && table.TableClassSummary.TableClass != nil {
		source = cfnComputeValue(table.TableClassSummary.TableClass)
	}
	for _, described := range table.Replicas {
		replica, ok := p.replica(cfnComputeValue(described.RegionName))
		if !ok || replica.Region == region {
			continue
		}
		want := replica.TableClass
		if want == "" {
			want = source
		}
		current := source
		if described.ReplicaTableClassSummary != nil && described.ReplicaTableClassSummary.TableClass != nil {
			current = cfnComputeValue(described.ReplicaTableClassSummary.TableClass)
		}
		if want != current {
			return true, cfnComputeRun(ctx, h.commands, "dynamodb", "UpdateTable", map[string]any{"TableName": cfnComputeValue(table.TableName), "ReplicaUpdates": []map[string]any{{"Update": map[string]any{"RegionName": replica.Region, "TableClassOverride": want}}}})
		}
	}
	return false, nil
}

// replicas applies Region-owned settings (deletion protection, recovery and
// tags) with the owner commands of each replica Region.
func (h cfnDynamoDBGlobalTable) replicas(ctx context.Context, r cloudformation.ResourceRequest, p cfnDDBGlobalProperties) (bool, error) {
	var previous *cfnDDBGlobalProperties
	if r.Previous != nil {
		decoded, err := cfnDDBGlobalDecode(r.Previous)
		if err != nil {
			return false, err
		}
		previous = &decoded
	}
	for _, replica := range p.Replicas {
		regional := ctx
		if replica.Region != r.Scope.Region {
			regional = cfnDataRegion(ctx, replica.Region)
		}
		table, err := h.table().describe(regional, r.PhysicalID)
		if err != nil {
			return false, err
		}
		if cfnComputeValue(table.TableStatus) != "ACTIVE" {
			return true, nil
		}
		protection := replica.DeletionProtectionEnabled != nil && bool(*replica.DeletionProtectionEnabled)
		if protection != cfnDataBool(table.DeletionProtectionEnabled) {
			return true, cfnComputeRun(regional, h.commands, "dynamodb", "UpdateTable", map[string]any{"TableName": r.PhysicalID, "DeletionProtectionEnabled": protection})
		}
		hadRecovery := false
		if previous != nil {
			if old, ok := previous.replica(replica.Region); ok && old.PointInTimeRecoverySpecification != nil {
				hadRecovery = true
			}
		}
		if replica.PointInTimeRecoverySpecification != nil || hadRecovery {
			if waiting, err := cfnDDBApplyRecovery(regional, h.commands, r.PhysicalID, replica.PointInTimeRecoverySpecification); err != nil || waiting {
				return waiting, err
			}
		}
		if err := cfnDDBReconcileTags(regional, h.commands, r, cfnComputeValue(table.TableArn), cfnDDBReplicaTags(r, replica)); err != nil {
			return false, err
		}
	}
	return false, nil
}

// Delete removes non-stack replicas first, one owner transition at a time, and
// then deletes the stack-Region table. StabilizeDeletion continues the sequence.
func (h cfnDynamoDBGlobalTable) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	_, err := h.deleteOnce(ctx, r)
	return err
}

func (h cfnDynamoDBGlobalTable) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnDDBOwnerContext(ctx, r, false)
	return h.deleteOnce(ctx, r)
}

func (h cfnDynamoDBGlobalTable) deleteOnce(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	name := r.PhysicalID
	if name == "" {
		name = cfnComputeName(r, "TableName", 255)
	}
	table, err := h.table().owned(ctx, r, name)
	if cfnComputeMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if cfnComputeValue(table.TableStatus) != "ACTIVE" || !cfnDDBReplicasSettled(table) {
		return false, nil
	}
	if len(table.Replicas) > 0 {
		region := cfnComputeValue(table.Replicas[0].RegionName)
		return false, cfnComputeRun(ctx, h.commands, "dynamodb", "UpdateTable", map[string]any{"TableName": name, "ReplicaUpdates": []map[string]any{{"Delete": map[string]any{"RegionName": region}}}})
	}
	err = cfnComputeRun(ctx, h.commands, "dynamodb", "DeleteTable", map[string]any{"TableName": name})
	if cfnComputeMissing(err) {
		return true, nil
	}
	return false, err
}

func (h cfnDynamoDBGlobalTable) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	table, err := h.table().describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cfnDDBDescriptionProperties(table)
	delete(p, "DeletionProtectionEnabled")
	p["TableId"] = cfnComputeValue(table.TableId)
	regions := []string{r.Scope.Region}
	for _, replica := range table.Replicas {
		regions = append(regions, cfnComputeValue(replica.RegionName))
	}
	replicas := make([]any, 0, len(regions))
	for _, region := range regions {
		regional := ctx
		if region != r.Scope.Region {
			regional = cfnDataRegion(ctx, region)
		}
		member, err := h.table().describe(regional, r.PhysicalID)
		if err != nil {
			return nil, err
		}
		item := map[string]any{"Region": region, "DeletionProtectionEnabled": cfnDataBool(member.DeletionProtectionEnabled)}
		if member.TableClassSummary != nil && member.TableClassSummary.TableClass != nil {
			item["TableClass"] = cfnComputeValue(member.TableClassSummary.TableClass)
		}
		tags, err := cfnDDBTags(regional, h.commands, cfnComputeValue(member.TableArn))
		if err != nil {
			return nil, err
		}
		item["Tags"] = cfnDataUserTags(tags)
		replicas = append(replicas, item)
	}
	p["Replicas"] = replicas
	ttl, err := cfnComputeCall[ddbapi.DescribeTimeToLiveOutput](ctx, h.commands, "dynamodb", "DescribeTimeToLive", map[string]any{"TableName": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	if d := ttl.TimeToLiveDescription; d != nil && d.AttributeName != nil {
		p["TimeToLiveSpecification"] = map[string]any{"Enabled": cfnComputeValue(d.TimeToLiveStatus) == "ENABLED", "AttributeName": cfnComputeValue(d.AttributeName)}
	}
	return p, nil
}

// List reports stack-Region tables that are members of a replication group.
func (h cfnDynamoDBGlobalTable) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	tables, err := h.table().List(ctx, r)
	if err != nil {
		return nil, err
	}
	result := []cloudformation.ResourceDescription{}
	for _, item := range tables {
		table, err := h.table().describe(ctx, item.Identifier)
		if cfnComputeMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if cfnComputeValue(table.GlobalTableVersion) == "2019.11.21" {
			result = append(result, item)
		}
	}
	return result, nil
}
