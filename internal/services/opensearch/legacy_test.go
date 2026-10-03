package opensearch_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	legacysdk "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	legacytypes "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"
	modernsdk "github.com/aws/aws-sdk-go-v2/service/opensearch"
	moderntypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	es "stackd/internal/awsapi/es"
	api "stackd/internal/awsapi/opensearch"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/opensearch"
	"stackd/journal"
	"stackd/storage/memory"
)

const legacyTestName = "legacy-shared"
const legacyTestARN = "arn:aws:es:us-east-1:123456789012:domain/legacy-shared"

// These tests exercise retained control state only. Native provisioning and the
// signed gateway are exercised by the executable engine workflow, not this HTTP
// harness, which supplies an already authenticated root context.
func legacyClients(t *testing.T) (*legacysdk.Client, *modernsdk.Client, journal.Storage) {
	t.Helper()
	domain := memory.NewDomain()
	repo := service.NewMemoryRepository(domain)
	events := journal.NewMemory(domain)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := repo.Update(t.Context(), func(tx service.Transaction) error {
		return tx.PutDomain(service.Domain{
			Key:         service.Key{Scope: service.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: legacyTestName},
			Incarnation: "legacy-test-incarnation", EngineVersion: service.EngineVersion, Status: "active", InstanceCount: 1,
			AdvancedOptions: map[string]string{"indices.query.bool.max_clause_count": "1024"},
			Created:         now, Updated: now, Version: 1, ConfigVersion: 1,
		})
	}); err != nil {
		t.Fatal(err)
	}
	s := service.New(service.Config{Repository: repo, Recorder: apievents.New(events), Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = s.Close() })
	legacy := s.Legacy()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serviceID := "opensearch"
		var handler http.Handler = s
		if strings.HasPrefix(r.URL.Path, "/2015-01-01/") {
			serviceID, handler = "es", legacy
		}
		model, _ := awscatalog.LookupService(serviceID)
		op, labels, ok := model.MatchHTTPOperation(r.Method, r.URL.EscapedPath(), r.URL.Query(), r.Header)
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request := awsapi.Request{Body: body, Labels: labels, Query: r.URL.Query(), Header: r.Header}
		var decoded awsapi.DecodedRequest
		if serviceID == "es" {
			decoded, err = es.DecodeRequest(string(op.Name), request)
		} else {
			decoded, err = api.DecodeRequest(string(op.Name), request)
		}
		ctx := awsctx.WithMetadata(r.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
		if err != nil {
			awswire.RESTJSONError(w, r, &model, legacy.RequestError(string(op.Name), err))
			return
		}
		handler.ServeHTTP(w, r.WithContext(awsapi.WithDecodedRequest(ctx, decoded)))
	}))
	t.Cleanup(server.Close)
	config := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1, HTTPClient: server.Client()}
	return legacysdk.NewFromConfig(config, func(o *legacysdk.Options) { o.BaseEndpoint = aws.String(server.URL) }),
		modernsdk.NewFromConfig(config, func(o *modernsdk.Options) { o.BaseEndpoint = aws.String(server.URL) }), events
}

func TestLegacySDKSharedDomainControls(t *testing.T) {
	legacy, modern, events := legacyClients(t)
	ctx := t.Context()
	list, err := legacy.ListDomainNames(ctx, &legacysdk.ListDomainNamesInput{})
	if err != nil || len(list.DomainNames) != 1 || aws.ToString(list.DomainNames[0].DomainName) != legacyTestName || list.DomainNames[0].EngineType != legacytypes.EngineType("OpenSearch") {
		t.Fatalf("shared domain inventory: %#v, %v", list, err)
	}
	esOnly, err := legacy.ListDomainNames(ctx, &legacysdk.ListDomainNamesInput{EngineType: legacytypes.EngineType("Elasticsearch")})
	if err != nil || len(esOnly.DomainNames) != 0 {
		t.Fatalf("OpenSearch domain listed as Elasticsearch: %#v, %v", esOnly, err)
	}
	described, err := legacy.DescribeElasticsearchDomain(ctx, &legacysdk.DescribeElasticsearchDomainInput{DomainName: aws.String(legacyTestName)})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(described.DomainStatus.ARN) != legacyTestARN || aws.ToString(described.DomainStatus.ElasticsearchVersion) != service.EngineVersion {
		t.Fatalf("domain identity or native engine changed through legacy API: %#v", described.DomainStatus)
	}
	many, err := legacy.DescribeElasticsearchDomains(ctx, &legacysdk.DescribeElasticsearchDomainsInput{DomainNames: []string{legacyTestName, "missing-domain"}})
	if err != nil || len(many.DomainStatusList) != 1 || aws.ToString(many.DomainStatusList[0].ARN) != legacyTestARN {
		t.Fatalf("shared describe/missing-domain behavior: %#v, %v", many, err)
	}
	config, err := legacy.DescribeElasticsearchDomainConfig(ctx, &legacysdk.DescribeElasticsearchDomainConfigInput{DomainName: aws.String(legacyTestName)})
	if err != nil || aws.ToString(config.DomainConfig.ElasticsearchVersion.Options) != service.EngineVersion {
		t.Fatalf("legacy configuration engine: %#v, %v", config, err)
	}
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"es:*","Resource":"` + legacyTestARN + `/*"}]}`
	updated, err := legacy.UpdateElasticsearchDomainConfig(ctx, &legacysdk.UpdateElasticsearchDomainConfigInput{
		DomainName: aws.String(legacyTestName), AdvancedOptions: map[string]string{"indices.query.bool.max_clause_count": "2048"},
		AccessPolicies:             aws.String(policy),
		ElasticsearchClusterConfig: &legacytypes.ElasticsearchClusterConfig{InstanceCount: aws.Int32(1)},
	})
	if err != nil || updated.DomainConfig.AdvancedOptions.Status.UpdateVersion != 2 {
		t.Fatalf("legacy update: %#v, %v", updated, err)
	}
	current, err := modern.DescribeDomainConfig(ctx, &modernsdk.DescribeDomainConfigInput{DomainName: aws.String(legacyTestName)})
	if err != nil || current.DomainConfig.AdvancedOptions.Options["indices.query.bool.max_clause_count"] != "2048" {
		t.Fatalf("legacy update not visible through modern API: %#v, %v", current, err)
	}
	var actualPolicy, expectedPolicy any
	if err := json.Unmarshal([]byte(aws.ToString(current.DomainConfig.AccessPolicies.Options)), &actualPolicy); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(policy), &expectedPolicy); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actualPolicy, expectedPolicy) {
		t.Fatalf("legacy policy update not shared by modern controls: %#v", actualPolicy)
	}
	if _, err := legacy.AddTags(ctx, &legacysdk.AddTagsInput{ARN: aws.String(legacyTestARN), TagList: []legacytypes.Tag{{Key: aws.String("Legacy"), Value: aws.String("yes")}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := modern.AddTags(ctx, &modernsdk.AddTagsInput{ARN: aws.String(legacyTestARN), TagList: []moderntypes.Tag{{Key: aws.String("Modern"), Value: aws.String("yes")}}}); err != nil {
		t.Fatal(err)
	}
	tags, err := legacy.ListTags(ctx, &legacysdk.ListTagsInput{ARN: aws.String(legacyTestARN)})
	if err != nil {
		t.Fatal(err)
	}
	gotTags := map[string]string{}
	for _, tag := range tags.TagList {
		gotTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	if !reflect.DeepEqual(gotTags, map[string]string{"Legacy": "yes", "Modern": "yes"}) {
		t.Fatalf("separate tag stores: %#v", gotTags)
	}
	if _, err := legacy.RemoveTags(ctx, &legacysdk.RemoveTagsInput{ARN: aws.String(legacyTestARN), TagKeys: []string{"Legacy"}}); err != nil {
		t.Fatal(err)
	}
	modernTags, err := modern.ListTags(ctx, &modernsdk.ListTagsInput{ARN: aws.String(legacyTestARN)})
	if err != nil || len(modernTags.TagList) != 1 || aws.ToString(modernTags.TagList[0].Key) != "Modern" {
		t.Fatalf("legacy removal not visible through modern API: %#v, %v", modernTags, err)
	}
	deleted, err := legacy.DeleteElasticsearchDomain(ctx, &legacysdk.DeleteElasticsearchDomainInput{DomainName: aws.String(legacyTestName)})
	if err != nil || !aws.ToBool(deleted.DomainStatus.Deleted) {
		t.Fatalf("legacy deletion: %#v, %v", deleted, err)
	}
	modernDomain, err := modern.DescribeDomain(ctx, &modernsdk.DescribeDomainInput{DomainName: aws.String(legacyTestName)})
	if err != nil || !aws.ToBool(modernDomain.DomainStatus.Deleted) {
		t.Fatalf("legacy deletion not visible through modern API: %#v, %v", modernDomain, err)
	}
	calls, err := events.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	updates := 0
	for _, event := range calls {
		call := event.APICallCompleted
		if call.EventName == "UpdateDomainConfig" {
			t.Fatal("legacy update emitted an additional modern audit event")
		}
		if call.EventName == "UpdateElasticsearchDomainConfig" {
			updates++
			if call.EventSource != "es.amazonaws.com" || call.ReadOnly || call.ErrorCode != "" {
				t.Fatalf("legacy audit identity: %#v", call)
			}
		}
	}
	if updates != 1 {
		t.Fatalf("one legacy mutation must produce exactly one legacy outcome; got %d", updates)
	}
}

func TestLegacySDKRejectsUnsupportedControlsAtomically(t *testing.T) {
	legacy, modern, events := legacyClients(t)
	cases := map[string]func(*legacysdk.UpdateElasticsearchDomainConfigInput){
		"dry run": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) { v.DryRun = aws.Bool(false) },
		"vpc": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.VPCOptions = &legacytypes.VPCOptions{SubnetIds: []string{"subnet-123"}}
		},
		"snapshots": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.SnapshotOptions = &legacytypes.SnapshotOptions{AutomatedSnapshotStartHour: aws.Int32(1)}
		},
		"cluster type": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.ElasticsearchClusterConfig = &legacytypes.ElasticsearchClusterConfig{InstanceType: legacytypes.ESPartitionInstanceType("m5.large.elasticsearch")}
		},
		"cluster topology": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.ElasticsearchClusterConfig = &legacytypes.ElasticsearchClusterConfig{InstanceCount: aws.Int32(2)}
		},
		"zone details": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.ElasticsearchClusterConfig = &legacytypes.ElasticsearchClusterConfig{ZoneAwarenessConfig: &legacytypes.ZoneAwarenessConfig{AvailabilityZoneCount: aws.Int32(2)}}
		},
		"ebs size": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.EBSOptions = &legacytypes.EBSOptions{EBSEnabled: aws.Bool(false), VolumeSize: aws.Int32(10)}
		},
		"master credentials": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.AdvancedSecurityOptions = &legacytypes.AdvancedSecurityOptionsInput{MasterUserOptions: &legacytypes.MasterUserOptions{MasterUserName: aws.String("admin"), MasterUserPassword: aws.String("DoNotStoreMe1!")}}
		},
		"kms key": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.EncryptionAtRestOptions = &legacytypes.EncryptionAtRestOptions{Enabled: aws.Bool(false), KmsKeyId: aws.String("key-123")}
		},
		"node encryption": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.NodeToNodeEncryptionOptions = &legacytypes.NodeToNodeEncryptionOptions{Enabled: aws.Bool(true)}
		},
		"https": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.DomainEndpointOptions = &legacytypes.DomainEndpointOptions{EnforceHTTPS: aws.Bool(true)}
		},
		"tls policy": func(v *legacysdk.UpdateElasticsearchDomainConfigInput) {
			v.DomainEndpointOptions = &legacytypes.DomainEndpointOptions{TLSSecurityPolicy: legacytypes.TLSSecurityPolicy("Policy-Min-TLS-1-2-2019-07")}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := &legacysdk.UpdateElasticsearchDomainConfigInput{DomainName: aws.String(legacyTestName), AdvancedOptions: map[string]string{"indices.query.bool.max_clause_count": "999"}}
			mutate(in)
			_, err := legacy.UpdateElasticsearchDomainConfig(t.Context(), in)
			var invalid *legacytypes.ValidationException
			if !errors.As(err, &invalid) {
				t.Fatalf("unsupported field did not return a modeled validation error: %v", err)
			}
			current, err := modern.DescribeDomainConfig(t.Context(), &modernsdk.DescribeDomainConfigInput{DomainName: aws.String(legacyTestName)})
			if err != nil {
				t.Fatal(err)
			}
			if current.DomainConfig.AdvancedOptions.Options["indices.query.bool.max_clause_count"] != "1024" || current.DomainConfig.AdvancedOptions.Status.UpdateVersion != 1 {
				t.Fatalf("unsupported legacy field silently dropped or partial update committed: %#v", current.DomainConfig)
			}
		})
	}
	calls, err := events.Read(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range calls {
		if strings.Contains(string(event.APICallCompleted.RequestParameters), "DoNotStoreMe1!") {
			t.Fatal("rejected legacy security settings leaked a password into audit")
		}
	}
}

func TestLegacySDKUnsupportedCreationAndMissingDomain(t *testing.T) {
	legacy, _, _ := legacyClients(t)
	_, err := legacy.CreateElasticsearchDomain(t.Context(), &legacysdk.CreateElasticsearchDomainInput{DomainName: aws.String("unsupported-es"), ElasticsearchVersion: aws.String("7.10")})
	var invalid *legacytypes.ValidationException
	if !errors.As(err, &invalid) {
		t.Fatalf("unsupported Elasticsearch creation error: %v", err)
	}
	_, err = legacy.DescribeElasticsearchDomain(t.Context(), &legacysdk.DescribeElasticsearchDomainInput{DomainName: aws.String("unsupported-es")})
	var absent *legacytypes.ResourceNotFoundException
	if !errors.As(err, &absent) {
		t.Fatalf("rejected creation nevertheless retained a domain: %v", err)
	}
}

func TestLegacySDKTagScopeIsolation(t *testing.T) {
	legacy, modern, _ := legacyClients(t)
	for _, arn := range []string{
		"arn:aws:es:us-east-1:999999999999:domain/" + legacyTestName,
		"arn:aws:es:eu-west-1:123456789012:domain/" + legacyTestName,
	} {
		_, err := legacy.ListTags(t.Context(), &legacysdk.ListTagsInput{ARN: aws.String(arn)})
		var absent *legacytypes.ResourceNotFoundException
		if !errors.As(err, &absent) {
			t.Fatalf("foreign scope was readable: %s: %v", arn, err)
		}
		_, err = legacy.AddTags(t.Context(), &legacysdk.AddTagsInput{ARN: aws.String(arn), TagList: []legacytypes.Tag{{Key: aws.String("foreign"), Value: aws.String("changed")}}})
		var apiError smithy.APIError
		if !errors.As(err, &apiError) || apiError.ErrorCode() != "ResourceNotFoundException" {
			t.Fatalf("foreign scope was writable: %s: %v", arn, err)
		}
	}
	tags, err := modern.ListTags(t.Context(), &modernsdk.ListTagsInput{ARN: aws.String(legacyTestARN)})
	if err != nil || len(tags.TagList) != 0 {
		t.Fatalf("foreign-scope legacy call changed the local domain: %#v, %v", tags, err)
	}
}
