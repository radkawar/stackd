package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/journal"
	"stackd/storage"
)

func ec2AuditClient(c cloudClients) *ec2.Client {
	return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

// Replay retained API inputs, not reconstructed CloudTrail parameters. The latter
// deliberately omit DryRun, attribute selectors and empty tag values. The SDK
// response binds generated identities; it never supplies expected audit shapes.
func TestEC2NativeAPICallAudit(t *testing.T) {
	var captures struct {
		Capture struct {
			Calls []struct {
				Sequence int
				Label    string
				Input    json.RawMessage
				Output   any
				Code     string
			}
		}
	}
	var retained struct {
		Events []struct {
			Event       map[string]any
			Correlation *struct {
				Sequence    int
				CapturePath string `json:"capture_path"`
			} `json:"capture_correlation"`
		}
	}
	for path, target := range map[string]any{"../testdata/aws/ec2/networking.json": &captures, "../testdata/aws/ec2/audit.json": &retained} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, target); err != nil {
			t.Fatal(err)
		}
	}
	native := map[int]map[string]any{}
	for _, row := range retained.Events {
		if row.Correlation != nil && strings.HasSuffix(row.Correlation.CapturePath, "/capture.json") && row.Event["eventType"] == "AwsApiCall" {
			native[row.Correlation.Sequence] = row.Event
		}
	}
	// The second owned VPC supports the retained DryRun calls without substituting
	// different inputs. The first workflow keeps CIDR host bits and mutable tags.
	sequences := []int{26, 27, 28, 30, 32, 33, 34, 35, 36, 38, 39, 50, 52, 54, 60, 69, 70, 73, 76, 77, 78, 84, 91, 92, 95, 96, 97, 98, 99, 100, 101, 102, 149, 153, 175, 177, 178}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "ec2-audit.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 16, 9, 40, 0, 0, time.UTC))
			_, c, _ := startEventDeliveryCloud(t, backends, source)
			client, trails := ec2AuditClient(c), trailNativeClient(c)
			bindings := map[string]string{"000000000000": eventDeliveryAccount}
			completed := 0
			for _, capture := range captures.Capture.Calls {
				if !slices.Contains(sequences, capture.Sequence) {
					continue
				}
				want := native[capture.Sequence]
				if want == nil {
					t.Fatalf("missing native event for %s", capture.Label)
				}
				action := want["eventName"].(string)
				input := ec2AuditReplace(t, capture.Input, bindings)
				result, callErr := awstest.CallSDK(t.Context(), client, action, input)
				if capture.Code == "Success" {
					if callErr != nil {
						t.Fatalf("%s: %v", capture.Label, callErr)
					}
					if !strings.HasPrefix(action, "Describe") {
						encoded, err := json.Marshal(result)
						if err != nil {
							t.Fatal(err)
						}
						var actual any
						if err := json.Unmarshal(encoded, &actual); err != nil {
							t.Fatal(err)
						}
						ec2AuditBindIdentities(t, capture.Output, actual, bindings)
					}
				} else {
					assertAPIError(t, callErr, capture.Code)
				}
				requestID := nativeAuditRequestID(t, result, callErr)
				got := auditLookupRecord(t, trails, requestID, action)
				t.Run(capture.Label, func(t *testing.T) {
					assertEC2AuditCapture(t, source.Now(), want, got, requestID, callErr, bindings, nil)
				})
				completed++
			}
			if completed != len(sequences) {
				t.Fatalf("replayed %d captures, want %d", completed, len(sequences))
			}
			// DryRun must not have created its named security group.
			groups, err := client.DescribeSecurityGroups(t.Context(), &ec2.DescribeSecurityGroupsInput{Filters: []ec2types.Filter{{Name: aws.String("group-name"), Values: []string{"stackd-ec2-network-41b7e3-dryrun"}}}})
			if err != nil || len(groups.SecurityGroups) != 0 {
				t.Fatalf("DryRun mutated security groups: %+v %v", groups, err)
			}
		})
	}
}

func assertEC2AuditCapture(t *testing.T, now time.Time, want, got map[string]any, requestID string, callErr error, bindings map[string]string, normalize func(any)) {
	t.Helper()
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	if err := json.Unmarshal(ec2AuditReplace(t, encoded, bindings), &expected); err != nil {
		t.Fatal(err)
	}
	if normalize != nil {
		normalize(expected)
	}
	expected["eventTime"] = now.Format(time.RFC3339)
	// Bind the actual SDK request ID, including nested query envelopes and Unit
	// responses. Expected audit fields always come from the native capture.
	nativeID := expected["requestID"].(string)
	expectedBytes, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ec2AuditReplace(t, expectedBytes, map[string]string{nativeID: requestID}), &expected); err != nil {
		t.Fatal(err)
	}
	message := ""
	if callErr != nil {
		var apiError smithy.APIError
		if !errors.As(callErr, &apiError) {
			t.Fatal(callErr)
		}
		message = apiError.ErrorMessage()
	}
	ec2AuditSortSets(got)
	ec2AuditSortSets(expected)
	assertNativeAuditEvent(t, got, expected, message)
}

func ec2AuditReplace(t *testing.T, document []byte, bindings map[string]string) []byte {
	t.Helper()
	keys := make([]string, 0, len(bindings))
	for key := range bindings {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b string) int { return len(b) - len(a) })
	pairs := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		if _, err := netip.ParseAddr(key); err == nil {
			// An allocated host must not rewrite an unrelated address sharing its
			// textual prefix (for example .1 inside .15).
			pairs = append(pairs, strconv.Quote(key), strconv.Quote(bindings[key]))
		} else if len(key) == 12 && strings.Trim(key, "0123456789") == "" {
			// Account aliases must not rewrite digits inside opaque resource IDs,
			// especially the deliberately malformed all-zero snapshot fixtures.
			value := bindings[key]
			pairs = append(pairs, strconv.Quote(key), strconv.Quote(value),
				":"+key+":", ":"+value+":", "/"+key+"/", "/"+value+"/",
				`"`+key+"/", `"`+value+"/",
				key+".dkr.", value+".dkr.")
		} else {
			pairs = append(pairs, key, bindings[key])
		}
	}
	return []byte(strings.NewReplacer(pairs...).Replace(string(document)))
}

func ec2AuditBindIdentities(t *testing.T, native, actual any, bindings map[string]string) {
	t.Helper()
	switch expected := native.(type) {
	case map[string]any:
		got, _ := actual.(map[string]any)
		for key, value := range expected {
			switch key {
			case "VpcId", "SubnetId", "GroupId", "SecurityGroupRuleId", "AssociationId", "DhcpOptionsId", "AvailabilityZoneId", "SecurityGroupArn", "SecurityGroupRuleArn", "SubnetArn":
				before, beforeOK := value.(string)
				after, afterOK := got[key].(string)
				if !beforeOK || !afterOK || before == "" || after == "" {
					t.Fatalf("missing generated %s identity: native %#v, SDK %#v", key, value, got[key])
				}
				if prior, exists := bindings[before]; exists && prior != after {
					t.Fatalf("identity %s changed from %s to %s", before, prior, after)
				}
				bindings[before] = after
			default:
				ec2AuditBindIdentities(t, value, got[key], bindings)
			}
		}
	case []any:
		got, _ := actual.([]any)
		for i, value := range expected {
			if i < len(got) {
				ec2AuditBindIdentities(t, value, got[i], bindings)
			}
		}
	}
}

func ec2AuditSortSets(value any) {
	switch v := value.(type) {
	case map[string]any:
		for _, child := range v {
			ec2AuditSortSets(child)
		}
	case []any:
		for _, child := range v {
			ec2AuditSortSets(child)
		}
		if len(v) > 0 {
			if first, ok := v[0].(map[string]any); ok {
				for _, key := range []string{"key", "privateIpAddress", "groupId"} {
					if first[key] != nil {
						slices.SortFunc(v, func(a, b any) int {
							return strings.Compare(a.(map[string]any)[key].(string), b.(map[string]any)[key].(string))
						})
						break
					}
				}
			}
		}
	}
}

type ec2AuditAppendFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (f *ec2AuditAppendFailure) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := f.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "ec2.amazonaws.com" && call.EventName == "CreateTags" && call.ErrorCode == "" && f.fail.Swap(false) {
		return errors.New("injected EC2 audit append failure")
	}
	return nil
}

func TestEC2AuditAppendRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "ec2-rollback.sqlite"))
			}
			failure := &ec2AuditAppendFailure{Storage: backends.Journal}
			backends.Journal = failure
			_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 16, 9, 40, 0, 0, time.UTC)))
			client, trails := ec2AuditClient(c), trailNativeClient(c)
			vpc, err := client.CreateVpc(t.Context(), &ec2.CreateVpcInput{CidrBlock: aws.String("10.237.0.0/16")})
			if err != nil {
				t.Fatal(err)
			}
			input := &ec2.CreateTagsInput{Resources: []string{aws.ToString(vpc.Vpc.VpcId)}, Tags: []ec2types.Tag{{Key: aws.String("Stage"), Value: aws.String("committed")}}}
			if _, err := client.CreateTags(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			input.Tags[0].Value = aws.String("rejected")
			failure.fail.Store(true)
			result, callErr := client.CreateTags(t.Context(), input)
			if callErr == nil {
				t.Fatal("failed audit reported successful mutation")
			}
			record := auditLookupRecord(t, trails, nativeAuditRequestID(t, result, callErr), "CreateTags")
			if record["errorCode"] == nil || record["responseElements"] != nil {
				t.Fatalf("rollback did not retain one rejected completion: %#v", record)
			}
			state, err := client.DescribeTags(t.Context(), &ec2.DescribeTagsInput{Filters: []ec2types.Filter{{Name: aws.String("resource-id"), Values: input.Resources}}})
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]string{}
			for _, tag := range state.Tags {
				values[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			if !reflect.DeepEqual(values, map[string]string{"Stage": "committed"}) {
				t.Fatalf("failed audit committed resource mutation: %#v", values)
			}
		})
	}
}
