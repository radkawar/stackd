package opensearch_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	legacy "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	modern "github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/journal"
	"stackd/storage"
	"stackd/storage/sqlite"
	sqlbackends "stackd/storage/sqlite/backends"
)

type nativeCall struct {
	Label, Service, Operation, Code string
	Input                           json.RawMessage
	HTTPStatus                      int `json:"http_status"`
}
type nativeCapture struct {
	Account, Region, Prefix string
	Calls                   []nativeCall
	Matrix                  []struct {
		Label  string
		Policy json.RawMessage
		Rounds []struct{ Calls []nativeCall }
	} `json:"iam_matrix"`
	Audit struct {
		Events []struct {
			Label string `json:"call_label"`
			Event struct {
				EventSource, EventName, EventCategory, ErrorCode string
				ReadOnly                                         bool
				RequestParameters, ResponseElements              json.RawMessage
			}
		}
	} `json:"audit"`
}

func loadNativeCapture(t *testing.T) nativeCapture {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/aws/opensearch/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture nativeCapture
	if err = json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	return capture
}
func nativeClients(t *testing.T, backend string, capture nativeCapture) (aws.Config, string, journal.Storage) {
	t.Helper()
	var stores *storage.Backends
	if backend == "sqlite" {
		db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		stores, err = sqlbackends.New(t.Context(), db)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		stores = storage.NewMemory()
	}
	cloud, err := stackd.New(stackd.Config{AccountID: capture.Account, Storage: stores})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cloud.Close() })
	server := httptest.NewServer(cloud)
	t.Cleanup(server.Close)
	return aws.Config{Region: capture.Region, Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1, HTTPClient: server.Client()}, server.URL, stores.Journal
}
func matchNativeError(t *testing.T, err error, call nativeCall, events journal.Storage, capture nativeCapture) {
	t.Helper()
	var api smithy.APIError
	var response *smithyhttp.ResponseError
	if !errors.As(err, &api) || api.ErrorCode() != call.Code || !errors.As(err, &response) || response.HTTPStatusCode() != call.HTTPStatus {
		t.Fatalf("native %s code=%s status=%d; local=%v", call.Label, call.Code, call.HTTPStatus, err)
	}
	requestID := response.Response.Header.Get("X-Amzn-Requestid")
	records, e := events.Read(t.Context(), 0, 1000)
	if e != nil {
		t.Fatal(e)
	}
	var local *journal.APICallCompleted
	for _, event := range records {
		if event.RequestID == requestID && event.APICallCompleted != nil {
			local = event.APICallCompleted
			break
		}
	}
	if local == nil {
		t.Fatalf("no source audit for %s local request %s", call.Label, requestID)
	}
	document := func(raw json.RawMessage) any {
		if len(raw) == 0 {
			return nil
		}
		var v any
		if e := json.Unmarshal(raw, &v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	for _, native := range capture.Audit.Events {
		if native.Label != call.Label {
			continue
		}
		want := native.Event
		if local.EventSource != want.EventSource || local.EventName != want.EventName || string(local.Category) != want.EventCategory || local.ReadOnly != want.ReadOnly || local.ErrorCode != want.ErrorCode || !reflect.DeepEqual(document(local.RequestParameters), document(want.RequestParameters)) || !reflect.DeepEqual(document(local.ResponseElements), document(want.ResponseElements)) {
			t.Fatalf("%s native audit=%+v local=%+v", call.Label, want, *local)
		}
		return
	}
	t.Fatalf("missing exact-ID native audit fixture for %s", call.Label)
}
func TestNativeControlErrorsAndIAMRenameFixture(t *testing.T) {
	capture := loadNativeCapture(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			cfg, endpoint, events := nativeClients(t, backend, capture)
			m := modern.NewFromConfig(cfg, func(o *modern.Options) { o.BaseEndpoint = &endpoint })
			l := legacy.NewFromConfig(cfg, func(o *legacy.Options) { o.BaseEndpoint = &endpoint })
			for _, call := range capture.Calls {
				if strings.HasPrefix(call.Label, "iam-") || call.Code == "Success" {
					continue
				}
				var err error
				switch call.Operation {
				case "DescribeDomain":
					var in modern.DescribeDomainInput
					if err = json.Unmarshal(call.Input, &in); err != nil {
						t.Fatal(err)
					}
					_, err = m.DescribeDomain(t.Context(), &in)
				case "DescribeDomainConfig":
					var in modern.DescribeDomainConfigInput
					if err = json.Unmarshal(call.Input, &in); err != nil {
						t.Fatal(err)
					}
					_, err = m.DescribeDomainConfig(t.Context(), &in)
				case "DeleteDomain":
					var in modern.DeleteDomainInput
					if err = json.Unmarshal(call.Input, &in); err != nil {
						t.Fatal(err)
					}
					_, err = m.DeleteDomain(t.Context(), &in)
				case "DescribeElasticsearchDomain":
					var in legacy.DescribeElasticsearchDomainInput
					if err = json.Unmarshal(call.Input, &in); err != nil {
						t.Fatal(err)
					}
					_, err = l.DescribeElasticsearchDomain(t.Context(), &in)
				case "DescribeElasticsearchDomainConfig":
					var in legacy.DescribeElasticsearchDomainConfigInput
					if err = json.Unmarshal(call.Input, &in); err != nil {
						t.Fatal(err)
					}
					_, err = l.DescribeElasticsearchDomainConfig(t.Context(), &in)
				case "DeleteElasticsearchDomain":
					var in legacy.DeleteElasticsearchDomainInput
					if err = json.Unmarshal(call.Input, &in); err != nil {
						t.Fatal(err)
					}
					_, err = l.DeleteElasticsearchDomain(t.Context(), &in)
				default:
					continue
				}
				matchNativeError(t, err, call, events, capture)
			}
			identity := iam.NewFromConfig(cfg, func(o *iam.Options) { o.BaseEndpoint = &endpoint })
			tokens := sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = &endpoint })
			roleName := "fixture-rename"
			trust := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + capture.Account + `:root"},"Action":"sts:AssumeRole"}}`
			role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: &roleName, AssumeRolePolicyDocument: &trust})
			if err != nil {
				t.Fatal(err)
			}
			session, err := tokens.AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("fixture-session")})
			if err != nil {
				t.Fatal(err)
			}
			roleCfg := cfg
			roleCfg.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
			rm := modern.NewFromConfig(roleCfg, func(o *modern.Options) { o.BaseEndpoint = &endpoint })
			rl := legacy.NewFromConfig(roleCfg, func(o *legacy.Options) { o.BaseEndpoint = &endpoint })
			for _, row := range capture.Matrix {
				t.Run(row.Label, func(t *testing.T) {
					policy := string(row.Policy)
					if _, err = identity.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: &roleName, PolicyName: aws.String("matrix"), PolicyDocument: &policy}); err != nil {
						t.Fatal(err)
					}
					// Native repeated rounds calibrate propagation; local authority is current,
					// so replay one observed round rather than duplicate the same behavior.
					for _, observation := range row.Rounds[0].Calls {
						if strings.Contains(observation.Label, "-opensearch-") {
							_, err = rm.DescribeDomain(t.Context(), &modern.DescribeDomainInput{DomainName: &capture.Prefix})
						} else {
							_, err = rl.DescribeElasticsearchDomain(t.Context(), &legacy.DescribeElasticsearchDomainInput{DomainName: &capture.Prefix})
						}
						matchNativeError(t, err, observation, events, capture)
					}
				})
			}
		})
	}
}
