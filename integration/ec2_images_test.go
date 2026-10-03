package stackd_test

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/internal/awstest"
	ebsdomain "stackd/internal/services/ebs"
)

var ec2ImageIDPattern = regexp.MustCompile(`^ami-[0-9a-f]{17}$`)

type ec2ImageReplay struct {
	*ebsSnapshotReplay
	created  map[string]time.Time
	accounts []string
}

// These captures use actual EBS StartSnapshot/CompleteSnapshot dependencies and
// signed SDK calls, including the bounded native RegisterImage session policies.
// Every accepted call reopens memory/SQLite before its consumers run. Native
// worker latency, creation instants, account IDs and allocated IDs are normalized;
// mappings, tags, launch permissions, visibility and modeled errors are not.
func TestEC2NativeImages(t *testing.T) {
	for _, name := range []string{"images_controls", "images_sharing", "images_snapshot_references"} {
		t.Run(name, func(t *testing.T) {
			var fixture ebsCopyFixture
			awsReadFixture(t, "ec2/"+name+".json", &fixture)
			// The member is identified by the captured STS result, not a case
			// label or a synthetic snapshot owner injected into the service.
			for _, row := range fixture.Calls {
				if row.Service == "sts" && row.Operation == "GetCallerIdentity" && row.Code == "Success" {
					var identity struct{ Account string }
					awsDecodeJSON(t, row.Output, &identity)
					if identity.Account != fixture.Account {
						fixture.Member = identity.Account
					}
				}
			}
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					r := newEC2ImageReplay(t, fixture, backend)
					for _, row := range fixture.Calls {
						if row.Service == "iam" && row.Operation != "CreateRole" && row.Operation != "PutRolePolicy" {
							continue // IAM role cleanup is not an AMI contract.
						}
						if !t.Run(row.Label, func(t *testing.T) {
							if name == "images_sharing" && row.Label == "describe-unknown-valid-id" {
								t.Skip("User-approved deferral: opaque AWS AMI ID validity cannot be derived from public hexadecimal syntax; immutable native capture retained.")
							}
							r.call(t, row)
							if name == "images_controls" && row.Label == "deregister-primary" {
								// Both captured images used this root. Removing one
								// reference must not release the other image's pin.
								client := ec2.New(ec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: r.provider(t, "owner"), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
								remaining, err := client.DescribeImages(t.Context(), &ec2.DescribeImagesInput{Owners: []string{"self"}})
								if err != nil || len(remaining.Images) != 1 || len(remaining.Images[0].BlockDeviceMappings) != 1 || remaining.Images[0].BlockDeviceMappings[0].Ebs == nil {
									t.Fatalf("remaining image after deregistration: %#v, %v", remaining, err)
								}
								_, err = client.DeleteSnapshot(t.Context(), &ec2.DeleteSnapshotInput{SnapshotId: remaining.Images[0].BlockDeviceMappings[0].Ebs.SnapshotId})
								assertAPIError(t, err, "InvalidSnapshot.InUse")
							}
						}) && row.Code == "Success" {
							return // A failed producer cannot supply later native identities.
						}
					}
				})
			}
		})
	}
}

func newEC2ImageReplay(t *testing.T, fixture ebsCopyFixture, backend string) *ec2ImageReplay {
	t.Helper()
	var snapshots *ebsSnapshotReplay
	if fixture.Member == "" {
		snapshots = newEBSSnapshotReplay(t, fixture.ebsNativeFixture, backend)
	} else {
		snapshots = newEBSCopyReplay(t, fixture, backend)
		if policy, ok := fixture.Sessions["member-snapshot-references-1"]; ok {
			// This fixture labels API calls "member" but retains its exact
			// inline session policy under the session-creation label. Assume it
			// only when used, after local snapshot IDs have been bound.
			snapshots.fixture.Sessions["member"] = policy
			delete(snapshots.sessions, "member")
		}
	}
	r := &ec2ImageReplay{ebsSnapshotReplay: snapshots, created: map[string]time.Time{}, accounts: []string{snapshots.fixture.Account}}
	if fixture.Member != "" {
		r.accounts = append(r.accounts, snapshots.bindings[fixture.Member])
	}
	return r
}

func (r *ec2ImageReplay) call(t *testing.T, row ebsNativeCall) {
	t.Helper()
	if row.Service == "sts" {
		// The original standing-role secret is unavailable. Verify the real
		// local assumed principal's account; native role IDs/ARNs are not an
		// AMI expectation and must not be replaced with fake identity output.
		client := sts.New(sts.Options{Region: r.region(row), BaseEndpoint: aws.String(r.clients.server.URL), Credentials: r.provider(t, row.Caller), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
		actual, err := client.GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
		if err != nil {
			t.Fatal(err)
		}
		var expected sts.GetCallerIdentityOutput
		awsDecodeJSON(t, row.Output, &expected)
		ec2NetworkCompare(t, "identity.Account", aws.ToString(expected.Account), aws.ToString(actual.Account), r.bindings)
		r.clients = r.reopen()
		return
	}
	if row.Service != "ec2" || !strings.Contains(row.Operation, "Image") {
		r.ebsSnapshotReplay.call(t, row)
		if row.Code == "Success" && row.Operation == "ModifySnapshotAttribute" {
			r.clock.Advance(ebsdomain.SharingDelay)
		}
		return
	}

	var before map[string]any
	if row.Code != "Success" && !strings.HasPrefix(row.Operation, "Describe") {
		before = r.inventory(t)
	}
	if row.Operation == "RegisterImage" {
		r.clock.Advance(time.Millisecond)
	}
	wire := &awstest.WireClient{Client: r.clients.server.Client()}
	client := ec2.New(ec2.Options{Region: r.region(row), BaseEndpoint: aws.String(r.clients.server.URL), Credentials: r.provider(t, row.Caller), HTTPClient: wire, RetryMaxAttempts: 1})
	if row.Label == "iam-no-describe-permission" {
		var request ec2.RegisterImageInput
		awsDecodeJSON(t, ec2AuditReplace(t, row.Input, r.bindings), &request)
		_, err := client.DescribeSnapshots(t.Context(), &ec2.DescribeSnapshotsInput{SnapshotIds: []string{aws.ToString(request.BlockDeviceMappings[0].Ebs.SnapshotId)}})
		assertAPIError(t, err, "UnauthorizedOperation")
	}
	actual, err := awstest.CallSDK(t.Context(), client, row.Operation, ec2AuditReplace(t, row.Input, r.bindings))
	if row.Code != "Success" {
		r.checkError(t, row, wire, err)
		if before != nil {
			r.clients = r.reopen()
			ec2NetworkCompare(t, "rejected mutation", before, r.inventory(t), map[string]string{})
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if wire.Status != row.HTTPStatus {
		t.Fatalf("HTTP %d, native %d", wire.Status, row.HTTPStatus)
	}
	expected := reflect.New(reflect.TypeOf(actual).Elem()).Interface()
	if err := awstest.DecodeSDK(row.Output, expected); err != nil {
		t.Fatal(err)
	}
	want, got := ec2NetworkDocument(t, expected), ec2NetworkDocument(t, actual)
	if row.Operation == "RegisterImage" {
		native, local := want["ImageId"].(string), got["ImageId"].(string)
		if !ec2ImageIDPattern.MatchString(local) {
			t.Fatalf("invalid allocated image ID %q", local)
		}
		for other, bound := range r.bindings {
			if other != native && strings.HasPrefix(other, "ami-") && bound == local {
				t.Fatalf("distinct images %s and %s collapsed to %s", other, native, local)
			}
		}
		r.bind(t, native, local)
		r.created[local] = r.clock.Now()
	}
	ec2NetworkSort(t, want, r.bindings, true)
	ec2NetworkSort(t, got, r.bindings, false)
	if row.Operation == "DescribeImages" {
		images, _ := want["Images"].([]any)
		actualImages, _ := got["Images"].([]any)
		if len(images) == len(actualImages) {
			for index, value := range images {
				native, local := value.(map[string]any), actualImages[index].(map[string]any)
				date, ok := local["CreationDate"].(string)
				when, err := time.Parse(time.RFC3339Nano, date)
				created := r.created[r.bindings[native["ImageId"].(string)]]
				if !ok || err != nil || created.IsZero() || !when.Equal(created.Truncate(time.Millisecond)) {
					t.Fatalf("creation date %v does not retain registration instant %v", local["CreationDate"], created)
				}
				native["CreationDate"] = date
			}
		}
	}
	ec2NetworkCompare(t, "response", want, got, r.bindings)
	r.clients = r.reopen()
}

// Rejected registration or attribute mutation must preserve the complete owner
// documents and permission sets, not merely return the expected error code.
func (r *ec2ImageReplay) inventory(t *testing.T) map[string]any {
	t.Helper()
	result := map[string]any{}
	for _, account := range r.accounts {
		client := ec2.New(ec2.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
		images, err := client.DescribeImages(t.Context(), &ec2.DescribeImagesInput{Owners: []string{"self"}})
		if err != nil {
			t.Fatal(err)
		}
		document := ec2NetworkDocument(t, images)
		permissions := map[string]any{}
		for _, image := range images.Images {
			attribute, err := client.DescribeImageAttribute(t.Context(), &ec2.DescribeImageAttributeInput{ImageId: image.ImageId, Attribute: ec2types.ImageAttributeNameLaunchPermission})
			if err != nil {
				t.Fatal(err)
			}
			permissions[aws.ToString(image.ImageId)] = ec2NetworkDocument(t, attribute)
		}
		document["Permissions"] = permissions
		ec2NetworkSort(t, document, r.bindings, false)
		result[account] = document
	}
	return result
}
