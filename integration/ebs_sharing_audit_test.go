package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/clock"
	"stackd/internal/apievents"
	ebsdomain "stackd/internal/services/ebs"
	"stackd/journal"
	"stackd/storage"
)

func TestEBSSnapshotSharingNativeAuditAttribution(t *testing.T) {
	var native struct {
		Account, Member string
		Calls           []ebsNativeCall
		Sessions        map[string]json.RawMessage
		Owned           struct{ Key string }
		CloudTrail      struct {
			Events []struct {
				Label string `json:"call_label"`
				Event map[string]any
			}
		}
	}
	awsReadFixture(t, "ebs/sharing_data_settled.json", &native)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "sharing-audit.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC))
			_, clients, _ := startEventDeliveryCloud(t, backends, source)
			const member = "222222222222"
			trust := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + eventDeliveryAccount + `:root"},"Action":"sts:AssumeRole"}}`
			role, err := clients.iam(member, "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("snapshot-audit"), AssumeRolePolicyDocument: &trust})
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, clients.iam(member, "test", ""), "snapshot-audit", allow(`"*"`, "*"))
			assume := func(policy *string) aws.CredentialsProvider {
				issued, err := clients.sts(eventDeliveryAccount, "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("snapshot-audit"), Policy: policy})
				if err != nil {
					t.Fatal(err)
				}
				return credentials.NewStaticCredentialsProvider(aws.ToString(issued.Credentials.AccessKeyId), aws.ToString(issued.Credentials.SecretAccessKey), aws.ToString(issued.Credentials.SessionToken))
			}
			direct := func(provider aws.CredentialsProvider) *ebs.Client {
				return ebs.New(ebs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), HTTPClient: clients.server.Client(), Credentials: provider, RetryMaxAttempts: 1})
			}
			control := func(provider aws.CredentialsProvider) *ec2.Client {
				return ec2.New(ec2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), HTTPClient: clients.server.Client(), Credentials: provider, RetryMaxAttempts: 1})
			}
			owner := credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", "")
			caller := assume(nil)
			data := bytes.Repeat([]byte("stackd synthetic EBS encryption evidence\n"), 14000)[:ebsdomain.BlockSize]
			digest := sha256.Sum256(data)
			checksum := base64.StdEncoding.EncodeToString(digest[:])
			put := func(client *ebs.Client, id *string) error {
				_, err := client.PutSnapshotBlock(t.Context(), &ebs.PutSnapshotBlockInput{SnapshotId: id, BlockIndex: aws.Int32(0), BlockData: bytes.NewReader(data), DataLength: aws.Int32(ebsdomain.BlockSize), Checksum: &checksum, ChecksumAlgorithm: "SHA256"})
				return err
			}
			create := func(key *string) *string {
				input := &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1)}
				if key != nil {
					input.Encrypted, input.KmsKeyArn = aws.Bool(true), key
				}
				created, err := direct(owner).StartSnapshot(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				if err := put(direct(owner), created.SnapshotId); err != nil {
					t.Fatal(err)
				}
				if _, err := direct(owner).CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: created.SnapshotId, ChangedBlocksCount: aws.Int32(1)}); err != nil {
					t.Fatal(err)
				}
				source.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
				return created.SnapshotId
			}
			plain := create(nil)
			share := func(id *string, canonical bool) {
				input := &ec2.ModifySnapshotAttributeInput{SnapshotId: id}
				if canonical {
					input.CreateVolumePermission = &ec2types.CreateVolumePermissionModifications{Add: []ec2types.CreateVolumePermission{{UserId: aws.String(member)}}}
				} else {
					input.Attribute, input.OperationType, input.UserIds = ec2types.SnapshotAttributeNameCreateVolumePermission, ec2types.OperationTypeAdd, []string{member}
				}
				if _, err := control(owner).ModifySnapshotAttribute(t.Context(), input); err != nil {
					t.Fatal(err)
				}
				source.Advance(ebsdomain.SharingDelay)
			}
			share(plain, true)
			list, err := direct(caller).ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{SnapshotId: plain})
			if err != nil || len(list.Blocks) != 1 {
				t.Fatalf("shared block listing: %+v %v", list, err)
			}
			get := func(client *ebs.Client, id, token *string) error {
				out, err := client.GetSnapshotBlock(t.Context(), &ebs.GetSnapshotBlockInput{SnapshotId: id, BlockIndex: aws.Int32(0), BlockToken: token})
				if err == nil {
					defer out.BlockData.Close()
					_, err = io.Copy(io.Discard, out.BlockData)
				}
				return err
			}
			// Compare only positively captured recipient records. In particular, a
			// List capture does not establish absence from another account's trail.
			check := func(label string, id *string, invoke func() error) []journal.Event {
				t.Helper()
				var expected []map[string]any
				for _, row := range native.CloudTrail.Events {
					if row.Label == label && (row.Event["eventSource"] == "ebs.amazonaws.com" || row.Event["eventSource"] == "ec2.amazonaws.com") {
						expected = append(expected, row.Event)
					}
				}
				if len(expected) == 0 {
					t.Fatalf("missing native audit evidence for %s", label)
				}
				before, err := backends.Journal.Read(t.Context(), 0, 1000)
				if err != nil {
					t.Fatal(err)
				}
				sequence := before[len(before)-1].Sequence
				err = invoke()
				for _, row := range native.Calls {
					if row.Label != label {
						continue
					}
					if row.Code == "Success" {
						if err != nil {
							t.Fatal(err)
						}
					} else {
						assertAPIError(t, err, row.Code)
					}
					break
				}
				rows, err := backends.Journal.Read(t.Context(), sequence, 1000)
				if err != nil {
					t.Fatal(err)
				}
				var paired []map[string]any
				for _, want := range expected {
					account := member
					if want["recipientAccountId"] == native.Account {
						account = eventDeliveryAccount
					}
					var got map[string]any
					for _, row := range rows {
						if row.AccountID != account || row.APICallCompleted == nil || row.APICallCompleted.EventName != want["eventName"] || row.APICallCompleted.EventSource != want["eventSource"] {
							continue
						}
						if got != nil {
							t.Fatalf("duplicate %s recipient outcome for %s", label, account)
						}
						body, err := apievents.CloudTrailRecord(row)
						if err != nil {
							t.Fatal(err)
						}
						awsDecodeJSON(t, body, &got)
					}
					if got == nil {
						t.Fatalf("missing %s recipient outcome for %s", label, account)
					}
					for _, field := range []string{"eventName", "eventSource", "readOnly", "managementEvent", "eventCategory", "errorCode"} {
						if !reflect.DeepEqual(got[field], want[field]) {
							t.Fatalf("%s %s: got %#v, native %#v", label, field, got[field], want[field])
						}
					}
					wantIdentity := want["userIdentity"].(map[string]any)
					identity := got["userIdentity"].(map[string]any)
					if identity["type"] != wantIdentity["type"] || identity["accountId"] != member {
						t.Fatalf("%s lost public caller identity: %#v", label, identity)
					}
					if account == eventDeliveryAccount && (identity["arn"] != nil || identity["accessKeyId"] != nil || identity["sessionContext"] != nil) {
						t.Fatalf("owner received caller credentials: %#v", identity)
					}
					if got["responseElements"] != nil {
						t.Fatalf("%s retained unexpected response: %#v", label, got["responseElements"])
					}
					if want["requestParameters"] == nil {
						if got["requestParameters"] != nil {
							t.Fatalf("%s retained IAM-denied request", label)
						}
					} else if want["eventSource"] == "ec2.amazonaws.com" {
						body, _ := json.Marshal(want["requestParameters"])
						request := want["requestParameters"].(map[string]any)
						var normalized any
						awsDecodeJSON(t, ec2AuditReplace(t, body, map[string]string{request["snapshotId"].(string): *id, native.Member: member}), &normalized)
						if !reflect.DeepEqual(got["requestParameters"], normalized) {
							t.Fatalf("%s request = %#v, native %#v", label, got["requestParameters"], normalized)
						}
					}
					if resources, ok := want["resources"].([]any); ok {
						actual, ok := got["resources"].([]any)
						if !ok || len(actual) != len(resources) {
							t.Fatalf("%s lost snapshot resources: %#v", label, got["resources"])
						}
						for _, resource := range actual {
							r := resource.(map[string]any)
							if r["accountId"] != member || r["ARN"] != "arn:aws:ec2:us-east-1::snapshot/"+*id || r["type"] != "AWS::EC2::Snapshot" {
								t.Fatalf("%s changed requester resource scope: %#v", label, r)
							}
						}
					}
					if want["sharedEventID"] != nil {
						paired = append(paired, got)
					}
				}
				if len(paired) == 2 {
					if paired[0]["sharedEventID"] == nil || paired[0]["sharedEventID"] == "" || paired[0]["sharedEventID"] != paired[1]["sharedEventID"] || paired[0]["eventID"] == paired[1]["eventID"] || paired[0]["requestID"] != paired[1]["requestID"] {
						t.Fatalf("%s lost paired event correlation: %#v", label, paired)
					}
				}
				return rows
			}
			check("plain-shared-get", plain, func() error { return get(direct(caller), plain, list.Blocks[0].BlockToken) })
			check("plain-shared-list", plain, func() error {
				_, err := direct(caller).ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{SnapshotId: plain})
				return err
			})
			check("plain-shared-parent", plain, func() error {
				_, err := direct(caller).StartSnapshot(t.Context(), &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1), ParentSnapshotId: plain})
				return err
			})
			check("plain-member-source-put", plain, func() error { return put(direct(caller), plain) })
			check("plain-member-source-complete", plain, func() error {
				_, err := direct(caller).CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: plain, ChangedBlocksCount: aws.Int32(0)})
				return err
			})
			check("plain-member-permission-read", plain, func() error {
				_, err := control(caller).DescribeSnapshotAttribute(t.Context(), &ec2.DescribeSnapshotAttributeInput{SnapshotId: plain, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission})
				return err
			})
			for _, canonical := range []bool{false, true} {
				check("plain-member-permission-add", plain, func() error {
					input := &ec2.ModifySnapshotAttributeInput{SnapshotId: plain}
					if canonical {
						input.CreateVolumePermission = &ec2types.CreateVolumePermissionModifications{Add: []ec2types.CreateVolumePermission{{UserId: aws.String(member)}}}
					} else {
						input.Attribute, input.OperationType, input.UserIds = ec2types.SnapshotAttributeNameCreateVolumePermission, ec2types.OperationTypeAdd, []string{member}
					}
					_, err := control(caller).ModifySnapshotAttribute(t.Context(), input)
					return err
				})
			}
			check("plain-member-permission-reset", plain, func() error {
				_, err := control(caller).ResetSnapshotAttribute(t.Context(), &ec2.ResetSnapshotAttributeInput{SnapshotId: plain, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission})
				return err
			})
			denied := assume(aws.String(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":["ebs:GetSnapshotBlock","ebs:ListSnapshotBlocks"],"Resource":"*"}]}`))
			check("deny-list-list", plain, func() error {
				_, err := direct(denied).ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{SnapshotId: plain})
				return err
			})
			check("resource-account-member-get", plain, func() error { return get(direct(denied), plain, list.Blocks[0].BlockToken) })
			key, err := clients.kms(eventDeliveryAccount, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			encrypted := create(key.KeyMetadata.Arn)
			share(encrypted, false)
			blocks, err := direct(owner).ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{SnapshotId: encrypted})
			if err != nil || len(blocks.Blocks) != 1 {
				t.Fatalf("encrypted shared block listing: %+v %v", blocks, err)
			}
			check("encrypted-shared-get", encrypted, func() error { return get(direct(caller), encrypted, blocks.Blocks[0].BlockToken) })

			// An unshared key can reject DescribeKey before Decrypt. Use the
			// captured key trust and explicit Decrypt denial to exercise rollback
			// after a successful KMS dependency, not merely any failed KMS call.
			bindings := map[string]string{native.Account: eventDeliveryAccount, native.Member: member, native.Owned.Key: *key.KeyMetadata.Arn}
			var policy kms.PutKeyPolicyInput
			for _, call := range native.Calls {
				if call.Label == "allow-member-owned-key" {
					awsDecodeJSON(t, ec2AuditReplace(t, call.Input, bindings), &policy)
					break
				}
			}
			if policy.Policy == nil {
				t.Fatal("missing native shared-key policy")
			}
			if _, err := clients.kms(eventDeliveryAccount, "test", "").PutKeyPolicy(t.Context(), &policy); err != nil {
				t.Fatal(err)
			}
			denyDecrypt := assume(aws.String(string(ec2AuditReplace(t, native.Sessions["deny-kms-decrypt"], bindings))))
			rows := check("deny-kms-decrypt-get", encrypted, func() error { return get(direct(denyDecrypt), encrypted, blocks.Blocks[0].BlockToken) })
			var described map[string]any
			decryptDenied := false
			for _, row := range rows {
				call := row.APICallCompleted
				if row.AccountID != member || call == nil || call.EventSource != "kms.amazonaws.com" {
					continue
				}
				switch call.EventName {
				case "DescribeKey":
					if described != nil {
						t.Fatal("duplicate retained DescribeKey outcome")
					}
					body, err := apievents.CloudTrailRecord(row)
					if err != nil {
						t.Fatal(err)
					}
					awsDecodeJSON(t, body, &described)
				case "Decrypt":
					if decryptDenied || call.ErrorCode != "AccessDeniedException" {
						t.Fatalf("expected one Decrypt denial, got %+v", call)
					}
					decryptDenied = true
				}
			}
			if described == nil || !decryptDenied {
				t.Fatalf("snapshot rejection lost KMS dependency outcomes: DescribeKey=%#v, Decrypt denied=%v", described, decryptDenied)
			}
			// Only successful KMS child records were positively captured. Compare
			// the retained DescribeKey shape to that evidence; the Decrypt denial
			// above is a local transaction invariant, not a claimed native record.
			var expectedDescribe map[string]any
			for _, row := range native.CloudTrail.Events {
				want := row.Event
				if want["eventSource"] != "kms.amazonaws.com" || want["eventName"] != "DescribeKey" || want["recipientAccountId"] != native.Member || want["errorCode"] != nil {
					continue
				}
				body, err := json.Marshal(want)
				if err != nil {
					t.Fatal(err)
				}
				awsDecodeJSON(t, ec2AuditReplace(t, body, bindings), &expectedDescribe)
				break
			}
			if expectedDescribe == nil {
				t.Fatal("missing native successful cross-account DescribeKey outcome")
			}
			for _, field := range []string{"eventName", "eventSource", "readOnly", "managementEvent", "eventCategory", "errorCode", "requestParameters", "responseElements", "resources"} {
				if !reflect.DeepEqual(described[field], expectedDescribe[field]) {
					t.Fatalf("retained DescribeKey %s: got %#v, native %#v", field, described[field], expectedDescribe[field])
				}
			}
			gotIdentity := described["userIdentity"].(map[string]any)
			wantIdentity := expectedDescribe["userIdentity"].(map[string]any)
			for _, field := range []string{"type", "accountId", "invokedBy"} {
				if !reflect.DeepEqual(gotIdentity[field], wantIdentity[field]) {
					t.Fatalf("retained DescribeKey identity %s: got %#v, native %#v", field, gotIdentity[field], wantIdentity[field])
				}
			}
		})
	}
}
