package integrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	kafkaapi "stackd/internal/awsapi/kafka"
	mqapi "stackd/internal/awsapi/mq"
	searchapi "stackd/internal/awsapi/opensearch"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	msk "stackd/internal/services/kafka"
	mqowner "stackd/internal/services/mq"
	search "stackd/internal/services/opensearch"
	"stackd/storage/sqlite"
	kafkastore "stackd/storage/sqlite/kafka"
	mqstore "stackd/storage/sqlite/mq"
	searchstore "stackd/storage/sqlite/opensearch"
)

// These owners never start their lifecycle schedulers: admission, private
// ownership, SQLite persistence and IAM are real, while every native engine
// call reports unavailability, so no resource is ever presented as active.
var errCFNPrivateFenceEngine = errors.New("native engine is unavailable to this admission-only regression")

type cfnPrivateFenceSearchRuntime struct{}

func (cfnPrivateFenceSearchRuntime) Ensure(context.Context, search.NativeSpecification) (string, error) {
	return "", errCFNPrivateFenceEngine
}
func (cfnPrivateFenceSearchRuntime) Delete(context.Context, string) error {
	return errCFNPrivateFenceEngine
}
func (cfnPrivateFenceSearchRuntime) Statistics(context.Context, search.NativeSpecification) (search.NativeStatistics, error) {
	return search.NativeStatistics{}, errCFNPrivateFenceEngine
}
func (cfnPrivateFenceSearchRuntime) Close() error { return nil }

type cfnPrivateFenceKafkaRuntime struct{}

func (cfnPrivateFenceKafkaRuntime) Ensure(context.Context, msk.Specification) (msk.Endpoint, error) {
	return msk.Endpoint{}, errCFNPrivateFenceEngine
}
func (cfnPrivateFenceKafkaRuntime) Status(context.Context, msk.Specification) (msk.Endpoint, error) {
	return msk.Endpoint{}, errCFNPrivateFenceEngine
}
func (cfnPrivateFenceKafkaRuntime) Reboot(context.Context, msk.Specification, int32) (msk.Endpoint, error) {
	return msk.Endpoint{}, errCFNPrivateFenceEngine
}
func (cfnPrivateFenceKafkaRuntime) Delete(context.Context, msk.Specification) error {
	return errCFNPrivateFenceEngine
}
func (cfnPrivateFenceKafkaRuntime) Close() error { return nil }

type cfnPrivateFenceMQRuntime struct{}

func (cfnPrivateFenceMQRuntime) Ensure(context.Context, mqowner.BrokerRecord) (mqowner.Endpoint, error) {
	return mqowner.Endpoint{}, errCFNPrivateFenceEngine
}
func (cfnPrivateFenceMQRuntime) Reboot(context.Context, mqowner.BrokerRecord) (mqowner.Endpoint, error) {
	return mqowner.Endpoint{}, errCFNPrivateFenceEngine
}
func (cfnPrivateFenceMQRuntime) Delete(context.Context, mqowner.BrokerRecord) error {
	return errCFNPrivateFenceEngine
}
func (cfnPrivateFenceMQRuntime) Close() error { return nil }

type cfnPrivateFenceOwner interface {
	awscommands.CommandExecutor
	Close() error
}

// cfnPrivateFenceFixture reopens one SQLite file to prove claims are durable.
type cfnPrivateFenceFixture struct {
	t            *testing.T
	root, denied context.Context
	path         string
	db           *sql.DB
	owner        cfnPrivateFenceOwner
	commands     StepFunctionsCommands
	build        func(*sql.DB) (cfnPrivateFenceOwner, map[string]awscommands.CommandExecutor)
}

func newCFNPrivateFenceFixture(t *testing.T, build func(*sql.DB) (cfnPrivateFenceOwner, map[string]awscommands.CommandExecutor)) *cfnPrivateFenceFixture {
	metadata := awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"}
	f := &cfnPrivateFenceFixture{t: t, root: awsctx.WithMetadata(t.Context(), metadata), path: filepath.Join(t.TempDir(), "owner.sqlite"), build: build}
	metadata.PrincipalARN, metadata.PrincipalID = "arn:aws:iam::111111111111:user/restricted", "AIDARESTRICTED"
	f.denied = awsctx.WithMetadata(t.Context(), metadata)
	f.open()
	t.Cleanup(f.close)
	return f
}
func (f *cfnPrivateFenceFixture) open() {
	f.t.Helper()
	db, err := sqlite.Open(f.root, f.path)
	if err != nil {
		f.t.Fatal(err)
	}
	owner, executors := f.build(db)
	f.db, f.owner, f.commands = db, owner, NewStepFunctionsCommands(executors)
}
func (f *cfnPrivateFenceFixture) close() {
	if f.owner != nil {
		_ = f.owner.Close()
		f.owner = nil
	}
	if f.db != nil {
		_ = f.db.Close()
		f.db = nil
	}
}
func (f *cfnPrivateFenceFixture) reopen() { f.t.Helper(); f.close(); f.open() }
func (f *cfnPrivateFenceFixture) native(service, operation string, input map[string]any) {
	f.t.Helper()
	if err := cfnComputeRun(f.root, f.commands, service, operation, input); err != nil {
		f.t.Fatalf("%s %s: %v", service, operation, err)
	}
}

func cfnPrivateFenceRequest(kind, logical, token string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "arn:aws:cloudformation:us-east-1:111111111111:stack/private-fence/1", StackName: "private-fence", LogicalID: logical, Type: kind, Token: token, Scope: cloudformation.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Properties: p}
}

// cfnPrivateFenceForgedTags are every public marker a native caller can write
// for r: the old stack/logical/incarnation triple and the messaging hashes.
func cfnPrivateFenceForgedTags(r cloudformation.ResourceRequest) map[string]string {
	return map[string]string{cfnComputeTagPrefix + "stack-id": r.StackID, cfnComputeTagPrefix + "logical-id": r.LogicalID, cfnComputeTagPrefix + "incarnation": r.Token, cfnMessagingOwnerTag: cfnMessagingOwner(r), cfnMessagingTokenTag: cfnMessagingHash(r.Token)}
}
func cfnPrivateFenceTagKeys(tags map[string]string) []string {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	return keys
}
func cfnPrivateFenceAbsent(t *testing.T, operation string, result cloudformation.ResourceResult, err error) {
	t.Helper()
	var wire *awswire.Error
	if result.PhysicalID != "" || !errors.As(err, &wire) || wire.Code != "ResourceNotFoundException" {
		t.Fatalf("%s did not certify absence for this incarnation: %+v %v", operation, result, err)
	}
}
func cfnPrivateFenceRejected(t *testing.T, operation string, result cloudformation.ResourceResult, err error) {
	t.Helper()
	if err == nil || result.PhysicalID != "" {
		t.Fatalf("%s adopted a resource without its private claim: %+v %v", operation, result, err)
	}
}

func TestCloudFormationSearchDomainsUsePrivateIncarnationClaims(t *testing.T) {
	f := newCFNPrivateFenceFixture(t, func(db *sql.DB) (cfnPrivateFenceOwner, map[string]awscommands.CommandExecutor) {
		owner := search.New(search.Config{Repository: searchstore.New(db), Runtime: cfnPrivateFenceSearchRuntime{}, PublicEndpoint: "https://search.invalid"})
		return owner, map[string]awscommands.CommandExecutor{"opensearch": owner, "es": owner.Legacy()}
	})
	domain := func() cfnOpenSearchDomain { return cfnOpenSearchDomain{f.commands} }
	legacy := func() cfnElasticsearchDomain { return cfnElasticsearchDomain{f.commands} }
	deleted := func(name string) bool {
		t.Helper()
		out, err := cfnComputeCall[searchapi.DescribeDomainOutput](f.root, f.commands, "opensearch", "DescribeDomain", map[string]any{"DomainName": name})
		if err != nil || out.DomainStatus == nil {
			t.Fatalf("native describe %s: %+v %v", name, out, err)
		}
		return out.DomainStatus.Deleted != nil && bool(*out.DomainStatus.Deleted)
	}

	// An outsider domain carries every public marker of incarnation A.
	stale := cfnPrivateFenceRequest("AWS::OpenSearchService::Domain", "Search", "incarnation-a", cloudformation.Properties{"DomainName": "outsider-search"})
	f.native("opensearch", "CreateDomain", map[string]any{"DomainName": "outsider-search", "TagList": cfnComputeTagList(cfnPrivateFenceForgedTags(stale))})
	result, err := domain().Create(f.root, stale)
	cfnPrivateFenceRejected(t, "Create", result, err)
	result, err = domain().RecoverCreation(f.root, stale)
	cfnPrivateFenceAbsent(t, "RecoverCreation", result, err)
	esStale := stale
	esStale.Type = "AWS::Elasticsearch::Domain"
	result, err = legacy().RecoverCreation(f.root, esStale)
	cfnPrivateFenceAbsent(t, "legacy RecoverCreation", result, err)
	stale.PhysicalID, esStale.PhysicalID = "outsider-search", "111111111111/outsider-search"
	stale.Previous = stale.Properties
	if _, err = domain().Update(f.root, stale); err == nil {
		t.Fatal("stale incarnation updated a domain it never admitted")
	}
	if err = domain().Delete(f.root, stale); err != nil {
		t.Fatalf("stale deletion must treat a foreign domain as absent: %v", err)
	}
	if err = legacy().Delete(f.root, esStale); err != nil {
		t.Fatalf("stale legacy deletion must treat a foreign domain as absent: %v", err)
	}
	if deleted("outsider-search") {
		t.Fatal("stale CloudFormation deletion removed a foreign same-name domain")
	}
	// Cloud Control direct reads use current IAM, not request-token ownership.
	direct := stale
	direct.CloudControl, direct.Token = true, "unrelated-cloud-control-request"
	if _, err = domain().Read(f.root, direct); err != nil {
		t.Fatalf("authorized Cloud Control read failed: %v", err)
	}
	if _, err = domain().Read(f.denied, direct); err == nil {
		t.Fatal("Cloud Control read bypassed current IAM")
	}

	owned := cfnPrivateFenceRequest("AWS::OpenSearchService::Domain", "Search", "incarnation-b", cloudformation.Properties{"DomainName": "owned-search"})
	created, err := domain().Create(f.root, owned)
	if err != nil || created.PhysicalID != "owned-search" {
		t.Fatalf("exact incarnation create: %+v %v", created, err)
	}
	arn := "arn:aws:es:us-east-1:111111111111:domain/owned-search"
	foreign := owned
	foreign.Token = "incarnation-c"
	// Public tag removal and counterfeit markers neither revoke nor transfer the claim.
	f.native("opensearch", "RemoveTags", map[string]any{"ARN": arn, "TagKeys": cfnPrivateFenceTagKeys(cfnPrivateFenceForgedTags(owned))})
	f.native("opensearch", "AddTags", map[string]any{"ARN": arn, "TagList": cfnComputeTagList(cfnPrivateFenceForgedTags(foreign))})
	f.reopen()
	if recovered, err := domain().RecoverCreation(f.root, owned); err != nil || recovered.PhysicalID != created.PhysicalID {
		t.Fatalf("reopened exact recovery: %+v %v", recovered, err)
	}
	esOwned := owned
	esOwned.Type = "AWS::Elasticsearch::Domain"
	if recovered, err := legacy().RecoverCreation(f.root, esOwned); err != nil || recovered.PhysicalID != "111111111111/owned-search" || recovered.Ref != "owned-search" {
		t.Fatalf("legacy frontend lost the shared private claim: %+v %v", recovered, err)
	}
	if replay, err := domain().Create(f.root, owned); err != nil || replay.PhysicalID != created.PhysicalID {
		t.Fatalf("exact create replay: %+v %v", replay, err)
	}
	result, err = domain().Create(f.root, foreign)
	cfnPrivateFenceRejected(t, "foreign Create", result, err)
	result, err = domain().RecoverCreation(f.root, foreign)
	cfnPrivateFenceAbsent(t, "foreign RecoverCreation", result, err)
	foreign.PhysicalID = created.PhysicalID
	if err = domain().Delete(f.root, foreign); err != nil || deleted("owned-search") {
		t.Fatalf("counterfeit incarnation deleted the owned domain: %v", err)
	}
	owned.PhysicalID = created.PhysicalID
	if err = domain().Delete(f.root, owned); err != nil || !deleted("owned-search") {
		t.Fatalf("exact incarnation deletion: %v", err)
	}
}

func TestCloudFormationMSKClusterUsesPrivateIncarnationClaim(t *testing.T) {
	f := newCFNPrivateFenceFixture(t, func(db *sql.DB) (cfnPrivateFenceOwner, map[string]awscommands.CommandExecutor) {
		owner := msk.New(msk.Config{Repository: kafkastore.New(db), Runtime: cfnPrivateFenceKafkaRuntime{}})
		return owner, map[string]awscommands.CommandExecutor{"kafka": owner}
	})
	cluster := func() cfnMSKCluster { return cfnMSKCluster{f.commands} }
	properties := func(name string) cloudformation.Properties {
		return cloudformation.Properties{"ClusterName": name, "KafkaVersion": "3.7.1", "NumberOfBrokerNodes": 1, "BrokerNodeGroupInfo": map[string]any{"InstanceType": "kafka.local", "ClientSubnets": []any{}}}
	}
	state := func(arn string) string {
		t.Helper()
		out, err := cfnComputeCall[kafkaapi.DescribeClusterOutput](f.root, f.commands, "kafka", "DescribeCluster", map[string]any{"ClusterArn": arn})
		if err != nil || out.ClusterInfo == nil {
			t.Fatalf("native describe %s: %+v %v", arn, out, err)
		}
		return cfnComputeValue(out.ClusterInfo.State)
	}

	stale := cfnPrivateFenceRequest("AWS::MSK::Cluster", "Cluster", "incarnation-a", properties("outsider"))
	outsider, err := cfnComputeCall[kafkaapi.CreateClusterOutput](f.root, f.commands, "kafka", "CreateCluster", map[string]any{"clusterName": "outsider", "kafkaVersion": "3.7.1", "numberOfBrokerNodes": 1, "brokerNodeGroupInfo": map[string]any{"instanceType": "kafka.local", "clientSubnets": []any{}}, "tags": cfnPrivateFenceForgedTags(stale)})
	if err != nil {
		t.Fatal(err)
	}
	outsiderARN := cfnComputeValue(outsider.ClusterArn)
	result, err := cluster().Create(f.root, stale)
	cfnPrivateFenceRejected(t, "Create", result, err)
	result, err = cluster().RecoverCreation(f.root, stale)
	cfnPrivateFenceAbsent(t, "RecoverCreation", result, err)
	stale.PhysicalID, stale.Previous = outsiderARN, stale.Properties
	if _, err = cluster().Update(f.root, stale); err == nil {
		t.Fatal("stale incarnation updated a cluster it never admitted")
	}
	if err = cluster().Delete(f.root, stale); err != nil || state(outsiderARN) == "DELETING" {
		t.Fatalf("stale CloudFormation deletion touched a foreign cluster: %s %v", state(outsiderARN), err)
	}
	direct := stale
	direct.CloudControl, direct.Token = true, "unrelated-cloud-control-request"
	if _, err = cluster().Read(f.denied, direct); err == nil {
		t.Fatal("Cloud Control read bypassed current IAM")
	}

	owned := cfnPrivateFenceRequest("AWS::MSK::Cluster", "Cluster", "incarnation-b", properties("owned"))
	created, err := cluster().Create(f.root, owned)
	if err != nil || created.PhysicalID == "" || (state(created.PhysicalID) != "CREATING" && state(created.PhysicalID) != "FAILED") {
		t.Fatalf("exact incarnation create: %+v %v state=%s", created, err, state(created.PhysicalID))
	}
	foreign := owned
	foreign.Token = "incarnation-c"
	f.native("kafka", "UntagResource", map[string]any{"ResourceArn": created.PhysicalID, "tagKeys": cfnPrivateFenceTagKeys(cfnPrivateFenceForgedTags(owned))})
	f.native("kafka", "TagResource", map[string]any{"ResourceArn": created.PhysicalID, "tags": cfnPrivateFenceForgedTags(foreign)})
	f.reopen()
	if recovered, err := cluster().RecoverCreation(f.root, owned); err != nil || recovered.PhysicalID != created.PhysicalID {
		t.Fatalf("reopened exact recovery: %+v %v", recovered, err)
	}
	if replay, err := cluster().Create(f.root, owned); err != nil || replay.PhysicalID != created.PhysicalID {
		t.Fatalf("exact create replay: %+v %v", replay, err)
	}
	result, err = cluster().Create(f.root, foreign)
	cfnPrivateFenceRejected(t, "foreign Create", result, err)
	result, err = cluster().RecoverCreation(f.root, foreign)
	cfnPrivateFenceAbsent(t, "foreign RecoverCreation", result, err)
	foreign.PhysicalID = created.PhysicalID
	if err = cluster().Delete(f.root, foreign); err != nil || state(created.PhysicalID) == "DELETING" {
		t.Fatalf("counterfeit incarnation deleted the owned cluster: %s %v", state(created.PhysicalID), err)
	}
	owned.PhysicalID = created.PhysicalID
	if err = cluster().Delete(f.root, owned); err != nil || state(created.PhysicalID) != "DELETING" {
		t.Fatalf("exact incarnation deletion: %v", err)
	}
}

func TestCloudFormationMQResourcesUsePrivateIncarnationClaims(t *testing.T) {
	f := newCFNPrivateFenceFixture(t, func(db *sql.DB) (cfnPrivateFenceOwner, map[string]awscommands.CommandExecutor) {
		owner := mqowner.New(mqowner.Config{Repository: mqstore.New(db), Runtime: cfnPrivateFenceMQRuntime{}})
		return owner, map[string]awscommands.CommandExecutor{"mq": owner}
	})
	broker := func() cfnMQBroker { return cfnMQBroker{f.commands} }
	configuration := func() cfnMQConfiguration { return cfnMQConfiguration{f.commands} }
	properties := func(name string) cloudformation.Properties {
		return cloudformation.Properties{"BrokerName": name, "EngineType": "ACTIVEMQ", "DeploymentMode": "SINGLE_INSTANCE", "HostInstanceType": "mq.t3.micro", "PubliclyAccessible": true, "Users": []any{map[string]any{"Username": "admin", "Password": "private-fence-pass1"}}}
	}
	state := func(id string) string {
		t.Helper()
		out, err := cfnMQBrokerGet(f.root, f.commands, id)
		if err != nil {
			t.Fatalf("native describe %s: %v", id, err)
		}
		return cfnComputeValue(out.BrokerState)
	}

	// The outsider reuses A's name, public markers and request-derived creator
	// token, which previously made CreateBroker replay adopt it.
	stale := cfnPrivateFenceRequest("AWS::AmazonMQ::Broker", "Broker", "incarnation-a", properties("outsider-broker"))
	outsider, err := cfnComputeCall[mqapi.CreateBrokerOutput](f.root, f.commands, "mq", "CreateBroker", map[string]any{"brokerName": "outsider-broker", "engineType": "ACTIVEMQ", "deploymentMode": "SINGLE_INSTANCE", "hostInstanceType": "mq.t3.micro", "publiclyAccessible": true, "users": []any{map[string]any{"username": "admin", "password": "private-fence-pass1"}}, "creatorRequestId": stale.Token, "tags": cfnPrivateFenceForgedTags(stale)})
	if err != nil {
		t.Fatal(err)
	}
	outsiderID := cfnComputeValue(outsider.BrokerId)
	result, err := broker().Create(f.root, stale)
	cfnPrivateFenceRejected(t, "broker Create", result, err)
	result, err = broker().RecoverCreation(f.root, stale)
	cfnPrivateFenceAbsent(t, "broker RecoverCreation", result, err)
	stale.PhysicalID = outsiderID
	if err = broker().Delete(f.root, stale); err != nil || state(outsiderID) == "DELETION_IN_PROGRESS" {
		t.Fatalf("stale CloudFormation deletion touched a foreign broker: %s %v", state(outsiderID), err)
	}
	direct := stale
	direct.CloudControl, direct.Token = true, "unrelated-cloud-control-request"
	if _, err = broker().Read(f.denied, direct); err == nil {
		t.Fatal("Cloud Control read bypassed current IAM")
	}

	owned := cfnPrivateFenceRequest("AWS::AmazonMQ::Broker", "Broker", "incarnation-b", properties("owned-broker"))
	created, err := broker().Create(f.root, owned)
	if err != nil || created.PhysicalID == "" || (state(created.PhysicalID) != "CREATION_IN_PROGRESS" && state(created.PhysicalID) != "CREATION_FAILED") {
		t.Fatalf("exact incarnation create: %+v %v state=%s", created, err, state(created.PhysicalID))
	}
	brokerARN := "arn:aws:mq:us-east-1:111111111111:broker:owned-broker:" + created.PhysicalID
	foreign := owned
	foreign.Token = "incarnation-c"
	f.native("mq", "DeleteTags", map[string]any{"ResourceArn": brokerARN, "TagKeys": cfnPrivateFenceTagKeys(cfnPrivateFenceForgedTags(owned))})
	f.native("mq", "CreateTags", map[string]any{"ResourceArn": brokerARN, "tags": cfnPrivateFenceForgedTags(foreign)})

	// Configuration names are not unique: a same-name outsider is never adopted.
	sharedA := cfnPrivateFenceRequest("AWS::AmazonMQ::Configuration", "Configuration", "incarnation-a", cloudformation.Properties{"Name": "shared-config", "EngineType": "ACTIVEMQ"})
	outsiderConfiguration, err := cfnComputeCall[mqapi.CreateConfigurationOutput](f.root, f.commands, "mq", "CreateConfiguration", map[string]any{"name": "shared-config", "engineType": "ACTIVEMQ", "tags": cfnPrivateFenceForgedTags(sharedA)})
	if err != nil {
		t.Fatal(err)
	}
	outsiderConfigurationID := cfnComputeValue(outsiderConfiguration.Id)
	ownedConfiguration, err := configuration().Create(f.root, sharedA)
	if err != nil || ownedConfiguration.PhysicalID == "" || ownedConfiguration.PhysicalID == outsiderConfigurationID {
		t.Fatalf("configuration create adopted or failed: %+v %v", ownedConfiguration, err)
	}

	f.reopen()
	if recovered, err := broker().RecoverCreation(f.root, owned); err != nil || recovered.PhysicalID != created.PhysicalID {
		t.Fatalf("reopened exact broker recovery: %+v %v", recovered, err)
	}
	if replay, err := broker().Create(f.root, owned); err != nil || replay.PhysicalID != created.PhysicalID {
		t.Fatalf("exact broker create replay: %+v %v", replay, err)
	}
	result, err = broker().Create(f.root, foreign)
	cfnPrivateFenceRejected(t, "foreign broker Create", result, err)
	result, err = broker().RecoverCreation(f.root, foreign)
	cfnPrivateFenceAbsent(t, "foreign broker RecoverCreation", result, err)
	foreign.PhysicalID = created.PhysicalID
	if err = broker().Delete(f.root, foreign); err != nil || state(created.PhysicalID) == "DELETION_IN_PROGRESS" {
		t.Fatalf("counterfeit incarnation deleted the owned broker: %s %v", state(created.PhysicalID), err)
	}
	owned.PhysicalID = created.PhysicalID
	if err = broker().Delete(f.root, owned); err != nil || state(created.PhysicalID) != "DELETION_IN_PROGRESS" {
		t.Fatalf("exact incarnation broker deletion: %v", err)
	}

	if recovered, err := configuration().RecoverCreation(f.root, sharedA); err != nil || recovered.PhysicalID != ownedConfiguration.PhysicalID {
		t.Fatalf("reopened exact configuration recovery: %+v %v", recovered, err)
	}
	sharedC := sharedA
	sharedC.Token = "incarnation-c"
	result, err = configuration().RecoverCreation(f.root, sharedC)
	cfnPrivateFenceAbsent(t, "foreign configuration RecoverCreation", result, err)
	sharedC.PhysicalID = ownedConfiguration.PhysicalID
	if err = configuration().Delete(f.root, sharedC); err != nil {
		t.Fatalf("counterfeit configuration deletion must treat ours as absent: %v", err)
	}
	if _, err = configuration().get(f.root, ownedConfiguration.PhysicalID); err != nil {
		t.Fatalf("counterfeit incarnation deleted the owned configuration: %v", err)
	}
	sharedA.PhysicalID = ownedConfiguration.PhysicalID
	if err = configuration().Delete(f.root, sharedA); err != nil {
		t.Fatal(err)
	}
	if _, err = configuration().get(f.root, ownedConfiguration.PhysicalID); !cfnEngineMissing(err) {
		t.Fatalf("exact configuration deletion left the owned row: %v", err)
	}
	if _, err = configuration().get(f.root, outsiderConfigurationID); err != nil {
		t.Fatalf("exact deletion touched the same-name outsider configuration: %v", err)
	}
}
