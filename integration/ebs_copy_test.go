package stackd_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	ebsdomain "stackd/internal/services/ebs"
)

type ebsCopyFixture struct {
	ebsNativeFixture
	Member string
	Wire   []struct {
		CapturedAt time.Time `json:"captured_at"`
		Presigned  struct {
			Host              string
			Action            []string
			SourceRegion      []string `json:"source_region"`
			SourceSnapshotID  []string `json:"source_snapshot_id"`
			DestinationRegion []string `json:"destination_region"`
			Algorithm         []string
			Expires           []string `json:"expires_seconds"`
			HasSignature      bool     `json:"has_signature"`
		} `json:"presigned"`
	} `json:"wire_requests"`
}

// These bounded captures exercise the public signed SDK, not service internals:
// sparse bytes, recipient ownership, lineage, tags, encryption and authorization.
// Every successful operation reconstructs the memory/SQLite owner before the next
// call, including between CopySnapshot, completion, token issuance and block reads.
func TestEBSNativeCopySnapshot(t *testing.T) {
	for _, names := range [][]string{
		{"copy_data"}, {"copy_data_authority"}, {"copy_data_source_authority"}, {"copy_data_failures"},
		{"copy_data_public"},
		{"copy_controls"}, {"copy_controls_iam"}, {"copy_controls_source_authority"},
		{"copy_controls_public", "copy_controls_contexts"},
	} {
		t.Run(names[0], func(t *testing.T) {
			var fixture ebsCopyFixture
			awsReadFixture(t, "ebs/"+names[0]+".json", &fixture)
			for _, name := range names[1:] {
				// Read-only supplements reuse the preceding capture's real source.
				// Compose native documents, never synthesize their setup or IDs.
				var supplement ebsCopyFixture
				awsReadFixture(t, "ebs/"+name+".json", &supplement)
				if supplement.Account != fixture.Account || supplement.Member != fixture.Member || supplement.Region != fixture.Region {
					t.Fatal("copy supplement has a different account or region")
				}
				fixture.Calls = append(fixture.Calls, supplement.Calls...)
				fixture.Wire = append(fixture.Wire, supplement.Wire...)
				if fixture.Sessions == nil {
					fixture.Sessions = map[string]json.RawMessage{}
				}
				for caller, policy := range supplement.Sessions {
					fixture.Sessions[caller] = policy
				}
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					r := newEBSCopyReplay(t, fixture, backend)
					for index, row := range fixture.Calls {
						if !ebsCopyReplayRow(t, r, fixture.Calls, index) {
							continue
						}
						if !t.Run(row.Label, func(t *testing.T) {
							row = ebsCopyPresignedInput(t, fixture, row)
							ebsCopyBindManagedKeys(t, r, row)
							ebsCopyCall(t, r, row)
							if row.Code == "Success" && (row.Operation == "ModifySnapshotAttribute" || row.Operation == "ResetSnapshotAttribute") {
								// The captures wait for published grants/revocations.
								// Advance service time, never their wall-clock latency.
								r.clock.Advance(ebsdomain.SharingDelay)
							}
						}) {
							return
						}
					}
				})
			}
		})
	}
}

func newEBSCopyReplay(t *testing.T, fixture ebsCopyFixture, backend string, start ...func(stackd.Config) (*stackd.Stack, *httptest.Server)) *ebsSnapshotReplay {
	t.Helper()
	const owner, member = "111111111111", "222222222222"
	if fixture.Account == "" || fixture.Member == "" || fixture.Account == fixture.Member {
		t.Fatal("copy capture must identify distinct source and recipient accounts")
	}
	native := fixture.ebsNativeFixture
	native.Account = owner
	r := newEBSSnapshotReplay(t, native, backend, start...)
	r.bind(t, fixture.Account, owner)
	r.bind(t, fixture.Member, member)
	r.sessionRoles = map[string]string{}
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}]}`, owner)
	root := r.clients.iam(member, "test", "")
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String("CopyRecipient"), AssumeRolePolicyDocument: aws.String(trust),
	})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "CopyRecipient", allow(`"*"`, "*"))
	session, err := r.clients.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: role.Role.Arn, RoleSessionName: aws.String("member"),
	})
	if err != nil {
		t.Fatal(err)
	}
	value := session.Credentials
	r.sessions["member"] = credentials.NewStaticCredentialsProvider(aws.ToString(value.AccessKeyId), aws.ToString(value.SecretAccessKey), aws.ToString(value.SessionToken))
	// The native session's identity identifies its account independently of the
	// case label. Preserve captured session policies and the owner's bounded role.
	for _, row := range fixture.Calls {
		if row.Service != "sts" || row.Operation != "GetCallerIdentity" || row.Code != "Success" {
			continue
		}
		var identity struct{ Account string }
		awsDecodeJSON(t, row.Output, &identity)
		if identity.Account == fixture.Member {
			r.sessionRoles[row.Caller] = aws.ToString(role.Role.Arn)
		} else if identity.Account != fixture.Account {
			t.Fatalf("unmodeled copy caller account %q", identity.Account)
		}
	}
	// Match the capture's explicitly observed account precondition. Do not rely
	// on whichever public-access default a fresh local account happens to use.
	publicScopes := map[string]bool{}
	for _, row := range fixture.Calls {
		if row.Operation != "GetSnapshotBlockPublicAccessState" || row.Code != "Success" {
			continue
		}
		scope := row.Caller + "/" + r.region(row)
		if publicScopes[scope] {
			continue
		}
		publicScopes[scope] = true
		var observed struct{ State string }
		awsDecodeJSON(t, row.Output, &observed)
		client := ec2.New(ec2.Options{Region: r.region(row), BaseEndpoint: aws.String(r.clients.server.URL), Credentials: r.provider(t, row.Caller), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
		if observed.State == "unblocked" {
			_, err = client.DisableSnapshotBlockPublicAccess(t.Context(), &ec2.DisableSnapshotBlockPublicAccessInput{})
		} else {
			_, err = client.EnableSnapshotBlockPublicAccess(t.Context(), &ec2.EnableSnapshotBlockPublicAccessInput{State: ec2types.SnapshotBlockPublicAccessState(observed.State)})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	r.clients = r.reopen()
	return r
}

func ebsCopyCall(t *testing.T, r *ebsSnapshotReplay, row ebsNativeCall) {
	t.Helper()
	if row.Operation != "CopySnapshot" || row.Code == "Success" {
		r.call(t, row)
		return
	}
	inventory := func() map[string]bool {
		account := r.fixture.Account
		if role := r.sessionRoles[row.Caller]; role != "" {
			account = strings.SplitN(role, ":", 6)[4]
		}
		client := ec2.New(ec2.Options{Region: r.region(row), BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
		output, err := client.DescribeSnapshots(t.Context(), &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}})
		if err != nil {
			t.Fatal(err)
		}
		ids := make(map[string]bool, len(output.Snapshots))
		for _, snapshot := range output.Snapshots {
			ids[aws.ToString(snapshot.SnapshotId)] = true
		}
		return ids
	}
	before := inventory()
	r.call(t, row)
	r.clients = r.reopen()
	if after := inventory(); !maps.Equal(before, after) {
		t.Fatalf("rejected or DryRun copy changed durable destination inventory: before %v, after %v", before, after)
	}
}

func ebsCopyReplayRow(t *testing.T, r *ebsSnapshotReplay, rows []ebsNativeCall, index int) bool {
	t.Helper()
	row := rows[index]
	if strings.HasPrefix(row.Label, "cleanup-") {
		return false // Native resource cleanup is not a CopySnapshot contract.
	}
	switch row.Service {
	case "ec2", "ebs":
	case "iam":
		return row.Operation == "CreateRole" || row.Operation == "PutRolePolicy"
	case "kms":
		return row.Operation == "CreateKey" || row.Operation == "PutKeyPolicy" || row.Operation == "DisableKey" || row.Operation == "EnableKey"
	default:
		// Standing role assumption is recreated above. Trail/EventBridge capture
		// setup is not substituted for a snapshot operation or an API assertion.
		return false
	}
	if row.Operation == "DescribeSnapshots" && row.Code == "Success" {
		var output struct {
			Snapshots []struct{ SnapshotID, State string }
		}
		awsDecodeJSON(t, row.Output, &output)
		for _, snapshot := range output.Snapshots {
			state := r.snapshots[snapshot.SnapshotID]
			if snapshot.State == "pending" && state != nil && !state.sealed.IsZero() && !r.clock.Now().Before(state.sealed.Add(ebsdomain.CompletionDelay)) {
				// Native workers complete independent copies out of creation order.
				// Replaying those polling races against a fixed local deadline would
				// invent a timing contract. Initial pending and terminal rows remain.
				return false
			}
		}
	}
	if row.Operation == "ListSnapshotBlocks" && row.Code == "ResourceNotFoundException" {
		var input struct{ SnapshotID string }
		awsDecodeJSON(t, row.Input, &input)
		if state := r.snapshots[input.SnapshotID]; state != nil && !state.readable {
			for _, later := range rows[index+1:] {
				if later.Service == row.Service && later.Operation == row.Operation && later.Caller == row.Caller && r.region(later) == r.region(row) && string(later.Input) == string(row.Input) && later.Code == "Success" {
					return false // Collapse readiness polling, not revoked/failed copies.
				}
			}
		}
	}
	return true
}

func ebsCopyBindManagedKeys(t *testing.T, r *ebsSnapshotReplay, row ebsNativeCall) {
	t.Helper()
	if row.Operation != "DescribeSnapshots" || row.Code != "Success" {
		return
	}
	var output struct{ Snapshots []struct{ KmsKeyID string } }
	awsDecodeJSON(t, row.Output, &output)
	for _, snapshot := range output.Snapshots {
		native := snapshot.KmsKeyID
		if native == "" || !strings.HasPrefix(native, "arn:") || r.bindings[native] != "" {
			continue
		}
		// Customer keys are bound only by their actual CreateKey response. A key
		// not created by the probe is the regional managed default; resolve that
		// alias independently, rather than blessing whatever ARN the copy chose.
		parts := strings.SplitN(native, ":", 6)
		if len(parts) != 6 || parts[2] != "kms" || r.bindings[parts[4]] == "" {
			t.Fatalf("unmodeled native copy key %q", native)
		}
		client := kms.New(kms.Options{Region: parts[3], BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(r.bindings[parts[4]], "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
		actual, err := client.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: aws.String("alias/aws/ebs")})
		if err != nil {
			t.Fatal(err)
		}
		r.bind(t, native, aws.ToString(actual.KeyMetadata.Arn))
	}
}

func ebsCopyPresignedInput(t *testing.T, fixture ebsCopyFixture, row ebsNativeCall) ebsNativeCall {
	t.Helper()
	if row.Operation != "CopySnapshot" {
		return row
	}
	var input map[string]json.RawMessage
	awsDecodeJSON(t, row.Input, &input)
	var raw string
	if json.Unmarshal(input["PresignedUrl"], &raw) != nil || raw != "<redacted>" {
		return row
	}
	var dry bool
	_ = json.Unmarshal(input["DryRun"], &dry)
	if dry {
		// DryRun never validates the URL. Its redacted placeholder is itself an
		// invalid URL; actual URL admission uses the preserved semantic facts.
		return row
	}
	for _, wire := range fixture.Wire {
		if wire.CapturedAt.Before(row.StartedAt) || wire.CapturedAt.After(row.FinishedAt) {
			continue
		}
		facts := wire.Presigned
		restored := "not-a-url"
		if facts.Host != "" {
			query := url.Values{
				"Action": facts.Action, "SourceRegion": facts.SourceRegion,
				"SourceSnapshotId": facts.SourceSnapshotID, "DestinationRegion": facts.DestinationRegion,
			}
			if facts.HasSignature {
				// The native tamper case deliberately used an invalid signature.
				// Preserve that property without retaining any AWS bearer material.
				query.Set("Version", "2016-11-15")
				query["X-Amz-Algorithm"] = facts.Algorithm
				query["X-Amz-Expires"] = facts.Expires
				query.Set("X-Amz-Date", row.StartedAt.UTC().Format("20060102T150405Z"))
				query.Set("X-Amz-Credential", "test/"+row.StartedAt.UTC().Format("20060102")+"/"+facts.SourceRegion[0]+"/ec2/aws4_request")
				query.Set("X-Amz-SignedHeaders", "host")
				query.Set("X-Amz-Signature", strings.Repeat("0", 64))
			}
			restored = (&url.URL{Scheme: "https", Host: facts.Host, Path: "/", RawQuery: query.Encode()}).String()
		}
		input["PresignedUrl"], _ = json.Marshal(restored)
		var err error
		row.Input, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	t.Fatalf("%s lacks safe presigned URL facts within its captured request interval", row.Label)
	return row
}
