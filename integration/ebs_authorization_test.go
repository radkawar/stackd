package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	ebstypes "github.com/aws/aws-sdk-go-v2/service/ebs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	ebsdomain "stackd/internal/services/ebs"
)

func TestEBSSnapshotAuthorization(t *testing.T) {
	var fixture struct {
		Account, Region string
		Policies        map[string]json.RawMessage
		Starts          []struct {
			Name, Policy, Code string
			Input              json.RawMessage
		}
		Tags []struct {
			Name, Policy, Operation, Code string
			Present                       bool
		}
	}
	body, err := os.ReadFile("../testdata/integration/ebs/authorization.json")
	if err != nil {
		t.Fatal(err)
	}
	awsDecodeJSON(t, body, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC))
			cloud, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source})
			root := credentials.NewStaticCredentialsProvider("test", "test", "")
			direct := func(provider aws.CredentialsProvider) *ebs.Client {
				return ebs.New(ebs.Options{Region: fixture.Region, BaseEndpoint: aws.String(cloud.server.URL), Credentials: provider, HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1})
			}
			control := func(provider aws.CredentialsProvider) *ec2.Client {
				return ec2.New(ec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(cloud.server.URL), Credentials: provider, HTTPClient: cloud.server.Client(), RetryMaxAttempts: 1})
			}
			organization, err := cloud.organizations("test", "test").CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll})
			if err != nil {
				t.Fatal(err)
			}
			roots, err := cloud.organizations("test", "test").ListRoots(t.Context(), &organizations.ListRootsInput{})
			if err != nil || len(roots.Roots) != 1 {
				t.Fatalf("organization roots: %+v, %v", roots, err)
			}
			bindings := map[string]string{"${org}": aws.ToString(organization.Organization.Id), "${org-path}": aws.ToString(organization.Organization.Id) + "/" + aws.ToString(roots.Roots[0].Id) + "/"}
			data := bytes.Repeat([]byte("parent authority\n"), ebsdomain.BlockSize/17+1)[:ebsdomain.BlockSize]
			digest := sha256.Sum256(data)
			checksum := base64.StdEncoding.EncodeToString(digest[:])
			for _, name := range []string{"${parent}", "${tagged-parent}"} {
				input := &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1)}
				if name == "${tagged-parent}" {
					input.Tags = []ebstypes.Tag{{Key: aws.String("team"), Value: aws.String("alice")}}
				}
				parent, err := direct(root).StartSnapshot(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				bindings[name] = aws.ToString(parent.SnapshotId)
				if _, err := direct(root).PutSnapshotBlock(t.Context(), &ebs.PutSnapshotBlockInput{SnapshotId: parent.SnapshotId, BlockIndex: aws.Int32(0), BlockData: bytes.NewReader(data), DataLength: aws.Int32(ebsdomain.BlockSize), Checksum: &checksum, ChecksumAlgorithm: "SHA256"}); err != nil {
					t.Fatal(err)
				}
				if _, err := direct(root).CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: parent.SnapshotId, ChangedBlocksCount: aws.Int32(1)}); err != nil {
					t.Fatal(err)
				}
			}
			source.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
			_, key, secret := cloud.user(t, "test", "snapshot-reader")
			caller := credentials.NewStaticCredentialsProvider(key, secret, "")
			if _, err := cloud.iam("test", "test", "").PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: aws.String("snapshot-reader"), PolicyName: aws.String("read-inherited-data"), PolicyDocument: aws.String(allow(`["ebs:CompleteSnapshot","ebs:ListSnapshotBlocks","ebs:GetSnapshotBlock"]`, "*"))}); err != nil {
				t.Fatal(err)
			}
			cloud = reopen()
			setPolicy := func(t *testing.T, name string) {
				t.Helper()
				policy, ok := fixture.Policies[name]
				if !ok {
					t.Fatalf("missing authorization policy %q", name)
				}
				putUserPolicy(t, cloud.iam("test", "test", ""), "snapshot-reader", string(ec2AuditReplace(t, policy, bindings)))
			}
			for _, row := range fixture.Starts {
				t.Run(row.Name, func(t *testing.T) {
					setPolicy(t, row.Policy)
					source.Advance(time.Second)
					var input ebs.StartSnapshotInput
					awsDecodeJSON(t, ec2AuditReplace(t, row.Input, bindings), &input)
					created, err := direct(caller).StartSnapshot(t.Context(), &input)
					if row.Code != "Success" {
						assertAPIError(t, err, row.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					stored, err := control(root).DescribeSnapshots(t.Context(), &ec2.DescribeSnapshotsInput{SnapshotIds: []string{aws.ToString(created.SnapshotId)}})
					if err != nil || len(stored.Snapshots) != 1 {
						t.Fatalf("created snapshot: %+v, %v", stored, err)
					}
					v := stored.Snapshots[0]
					if aws.ToString(v.OwnerId) != fixture.Account || int64(aws.ToInt32(v.VolumeSize)) != aws.ToInt64(input.VolumeSize) || aws.ToString(v.Description) != aws.ToString(input.Description) {
						t.Fatalf("authorized snapshot state: %+v", v)
					}
					if input.ParentSnapshotId == nil {
						return
					}
					if _, err := direct(caller).CompleteSnapshot(t.Context(), &ebs.CompleteSnapshotInput{SnapshotId: created.SnapshotId, ChangedBlocksCount: aws.Int32(0)}); err != nil {
						t.Fatal(err)
					}
					source.Advance(ebsdomain.CompletionDelay + ebsdomain.ReadinessDelay)
					cloud = reopen()
					blocks, err := direct(caller).ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{SnapshotId: created.SnapshotId})
					if err != nil || len(blocks.Blocks) != 1 || aws.ToInt32(blocks.Blocks[0].BlockIndex) != 0 {
						t.Fatalf("inherited block list: %+v, %v", blocks, err)
					}
					block, err := direct(caller).GetSnapshotBlock(t.Context(), &ebs.GetSnapshotBlockInput{SnapshotId: created.SnapshotId, BlockIndex: aws.Int32(0), BlockToken: blocks.Blocks[0].BlockToken})
					if err != nil {
						t.Fatal(err)
					}
					actual, err := io.ReadAll(block.BlockData)
					_ = block.BlockData.Close()
					if err != nil || !bytes.Equal(actual, data) {
						t.Fatalf("authorized inherited data differs: %v", err)
					}
				})
			}
			for _, row := range fixture.Tags {
				t.Run(row.Name, func(t *testing.T) {
					setPolicy(t, row.Policy)
					input, err := json.Marshal(ec2.CreateTagsInput{Resources: []string{bindings["${parent}"]}, Tags: []ec2types.Tag{{Key: aws.String("authority"), Value: aws.String("owner")}}})
					if err != nil {
						t.Fatal(err)
					}
					_, err = awstest.CallSDK(t.Context(), control(caller), row.Operation, input)
					if row.Code == "Success" {
						if err != nil {
							t.Fatal(err)
						}
					} else {
						assertAPIError(t, err, row.Code)
					}
					cloud = reopen()
					stored, err := control(root).DescribeSnapshots(t.Context(), &ec2.DescribeSnapshotsInput{SnapshotIds: []string{bindings["${parent}"]}})
					if err != nil || len(stored.Snapshots) != 1 {
						t.Fatalf("tagged snapshot: %+v, %v", stored, err)
					}
					got, want := map[string]string{}, map[string]string{}
					for _, tag := range stored.Snapshots[0].Tags {
						got[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
					}
					if row.Present {
						want["authority"] = "owner"
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("tag mutation authority: got %v, want %v", got, want)
					}
				})
			}
		})
	}
}
