package stackd_test

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go/middleware"

	"stackd/internal/awstest"
	ebsdomain "stackd/internal/services/ebs"
)

const (
	ebsSharingControlOwner  = "123456789012"
	ebsSharingControlMember = "210987654321"
)

func ebsSharingControlRows(t *testing.T) (ebsNativeFixture, map[string]ebsNativeCall) {
	t.Helper()
	var fixture ebsNativeFixture
	awsReadFixture(t, "ebs/sharing_controls.json", &fixture)
	rows := make(map[string]ebsNativeCall)
	for _, row := range fixture.Calls {
		// Supplement captures repeat readonly defaults; retain the first observation.
		if _, exists := rows[row.Label]; !exists {
			rows[row.Label] = row
		}
	}
	return fixture, rows
}

func newEBSSharingControlReplay(t *testing.T, fixture ebsNativeFixture, backend string) *ebsSnapshotReplay {
	t.Helper()
	nativeOwner := fixture.Account
	fixture.Account = ebsSharingControlOwner
	r := newEBSSnapshotReplay(t, fixture, backend)
	r.bind(t, nativeOwner, ebsSharingControlOwner)
	r.bind(t, "917546008205", ebsSharingControlMember)
	r.sessions["member-owner"] = credentials.NewStaticCredentialsProvider(ebsSharingControlMember, "test", "")
	return r
}

// The native probe disabled client validation. Keep the Go SDK's real Query
// serializer, signing and response decoding, but let missing fields reach the
// service: authorized DryRun admission deliberately precedes some validation.
func ebsSharingControlCall(t *testing.T, r *ebsSnapshotReplay, row ebsNativeCall) {
	t.Helper()
	wire := &awstest.WireClient{Client: r.clients.server.Client()}
	var input map[string]any
	awsDecodeJSON(t, row.Input, &input)
	emptyFields := url.Values{}
	for name, value := range input {
		if text, ok := value.(string); ok && text == "" {
			emptyFields[name] = []string{""}
		}
	}
	client := ec2.New(ec2.Options{
		Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL),
		Credentials: r.provider(t, row.Caller), HTTPClient: wire, RetryMaxAttempts: 1,
		APIOptions: []func(*middleware.Stack) error{func(stack *middleware.Stack) error {
			if _, ok := stack.Initialize.Get("OperationInputValidation"); ok {
				if _, err := stack.Initialize.Remove("OperationInputValidation"); err != nil {
					return err
				}
			}
			// SDK enum serializers omit zero values; the capture distinguishes
			// an explicitly empty Query parameter from an absent one.
			if len(emptyFields) != 0 {
				return awstest.QueryValues(emptyFields)(stack)
			}
			return nil
		}},
	})
	actual, err := awstest.CallSDK(t.Context(), client, ebsSDKOperation(row.Operation), ec2AuditReplace(t, row.Input, r.bindings))
	if row.Code != "Success" {
		r.checkError(t, row, wire, err)
	} else {
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
		ec2NetworkSort(t, want, r.bindings, true)
		ec2NetworkSort(t, got, r.bindings, false)
		ec2NetworkCompare(t, "response", want, got, r.bindings)
	}
	// Both successful and rejected mutations are observed after reconstructing
	// the owner, so atomic rejection is not merely an in-memory response check.
	r.clients = r.reopen()
}

func TestEBSNativeSharingControls(t *testing.T) {
	fixture, rows := ebsSharingControlRows(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newEBSSharingControlReplay(t, fixture, backend)
			call := func(label string) {
				t.Helper()
				row, ok := rows[label]
				if !ok {
					t.Fatalf("missing native sharing observation %q", label)
				}
				if !t.Run(label, func(t *testing.T) {
					if row.Service == "ec2" && row.Operation != "DescribeSnapshots" {
						ebsSharingControlCall(t, r, row)
					} else {
						r.call(t, row)
					}
				}) {
					t.FailNow()
				}
			}
			transition := func(label string) {
				t.Helper()
				call(label)
				call(label + "-after")
			}

			call("default-key-before")
			call("plain")
			call("pending-permissions")
			transition("pending-add")
			transition("pending-remove")
			transition("pending-reset")
			call("plain-complete")
			// One completed observation replaces native readiness polling. The
			// existing replay advances the deterministic completion boundary.
			call("plain-state-1")
			call("completed-products")
			for _, label := range []string{
				"empty", "empty-canonical", "empty-add", "attribute-only",
				"canonical-add", "canonical-add-repeat", "canonical-duplicate", "self-add",
				"mixed-same-account", "mixed-accounts", "canonical-remove", "canonical-remove-absent", "self-remove",
				"legacy-add", "legacy-duplicate", "legacy-remove", "legacy-no-attribute", "legacy-no-operation", "legacy-invalid-operation",
				"canonical-with-attribute", "canonical-legacy-same", "canonical-legacy-conflict",
				"invalid-account-short", "invalid-account-text", "invalid-account-hyphens", "invalid-account-empty",
				"valid-invalid-atomicity", "invalid-group", "invalid-group-remove", "empty-item", "modify-products", "modify-invalid-attribute",
				"public-add", "public-remove", "legacy-public-add", "legacy-public-remove", "combined-user-group-item",
				"reset-permissions", "reset-empty-permissions",
			} {
				transition(label)
			}
			for _, action := range []string{"describe_snapshot_attribute", "reset_snapshot_attribute"} {
				for _, attribute := range []string{"productCodes", "invalid", "", "None"} {
					call(action + "-attribute-" + attribute)
				}
			}

			call("create-owned-key")
			// The native account already had its AWS-managed EBS key. Provision
			// that prerequisite through actual encrypted snapshot creation.
			direct := ebs.New(ebs.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: r.provider(t, "owner"), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
			if _, err := direct.StartSnapshot(t.Context(), &ebs.StartSnapshotInput{VolumeSize: aws.Int64(1), Encrypted: aws.Bool(true)}); err != nil {
				t.Fatal(err)
			}
			managed, err := r.clients.kms("test", "test", "").DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: aws.String("alias/aws/ebs")})
			if err != nil {
				t.Fatal(err)
			}
			var nativeManaged kms.DescribeKeyOutput
			if err := awstest.DecodeSDK(rows["aws-managed-key"].Output, &nativeManaged); err != nil {
				t.Fatal(err)
			}
			r.bind(t, aws.ToString(nativeManaged.KeyMetadata.Arn), aws.ToString(managed.KeyMetadata.Arn))
			r.bind(t, aws.ToString(nativeManaged.KeyMetadata.KeyId), aws.ToString(managed.KeyMetadata.KeyId))
			for _, encryption := range []string{"aws-managed", "customer-key"} {
				call(encryption)
				transition(encryption + "-pending-add")
				call(encryption + "-complete")
				call(encryption + "-state-1")
				for _, operation := range []string{"completed-add", "self-add", "public-add", "remove", "reset"} {
					transition(encryption + "-" + operation)
				}
			}
			// Creating the managed key and using it must not turn the unconfigured
			// regional default into an explicit canonical-ARN selection.
			call("default-key-after")

			for _, shared := range []string{"False", "True"} {
				if shared == "True" {
					call("share-for-unowned-probes")
					r.clock.Advance(ebsdomain.SharingDelay)
				}
				for _, action := range []string{"describe_snapshot_attribute", "modify_snapshot_attribute", "reset_snapshot_attribute"} {
					for _, dry := range []string{"False", "True"} {
						call("member-" + shared + "-" + action + "-dry-" + dry)
					}
				}
			}
			call("reset-after-unowned-probes")
			call("create-owned-role")
			call("bound-owned-role")
			// Replay the captured admission matrix in order, including the final
			// permission documents. Invalid Attribute precedes IAM for Describe/
			// Reset, while canonical Modify ignores the legacy Attribute selector.
			for _, row := range fixture.Calls {
				if (strings.HasPrefix(row.Label, "describe_snapshot_attribute-") || strings.HasPrefix(row.Label, "modify_snapshot_attribute-") || strings.HasPrefix(row.Label, "reset_snapshot_attribute-")) &&
					(strings.Contains(row.Label, "-owner-dry-") || strings.Contains(row.Label, "-explicit-deny-dry-") || strings.HasSuffix(row.Label, "-precedence-final-state")) {
					call(row.Label)
				}
			}
			for _, row := range fixture.Calls {
				selected := strings.HasPrefix(row.Label, "ec2-Owner-") || strings.HasPrefix(row.Label, "aws-ResourceAccount-") ||
					strings.HasPrefix(row.Label, "aws-ResourceTag-") || strings.HasPrefix(row.Label, "ec2-ResourceTag-") ||
					strings.HasPrefix(row.Label, "condition-") || row.Label == "empty-account-arn" || row.Label == "filled-account-arn"
				if selected && row.Service == "ec2" && !strings.HasSuffix(row.Label, "-before") {
					call(row.Label)
				}
			}
			transition("reset-after-iam-probes")

			call("isolated-permission-boundaries")
			call("isolated-permission-boundaries-complete")
			call("isolated-permission-boundaries-state-1")
			for _, label := range []string{
				"atomic-canonical", "atomic-legacy", "twelve-digit-zero-account", "legacy-empty-add", "legacy-invalid-attribute",
			} {
				call(label + "-reset")
				transition(label)
			}
			transition("combined-item-empty-state")
			for _, label := range []string{"canonical-invalid-operation", "dryrun-mixed", "dryrun-empty", "dryrun-invalid-group"} {
				call(label + "-reset")
				transition(label)
			}

			// Settings captures only use DryRun; their throttled rapid repeats do
			// not define a native refill SLA. Pace the distinct admission cases
			// against the explicit local 1-token/10-second policy instead.
			for _, row := range fixture.Calls {
				selected := strings.HasSuffix(row.Label, "-paced") ||
					strings.HasPrefix(row.Label, "settings-enable-block-all-sharing-") ||
					strings.HasPrefix(row.Label, "settings-disable_snapshot_block_public_access-") ||
					strings.HasPrefix(row.Label, "settings-get_snapshot_block_public_access_state-") ||
					row.Label == "settings-owner-final" || row.Label == "settings-member-final"
				if selected && row.Service == "ec2" {
					r.clock.Advance(10 * time.Second)
					call(row.Label)
				}
			}
		})
	}
}

func TestEBSNativeSharingModificationLimit(t *testing.T) {
	fixture, rows := ebsSharingControlRows(t)
	var limits ebsNativeFixture
	awsReadFixture(t, "ebs/sharing_data_limits.json", &limits)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newEBSSharingControlReplay(t, fixture, backend)
			r.call(t, rows["plain"])
			ebsSharingControlCall(t, r, rows["public-add"])
			var snapshot struct {
				SnapshotID string `json:"SnapshotId"`
			}
			awsDecodeJSON(t, rows["plain"].Output, &snapshot)
			for _, row := range limits.Calls {
				if row.Label == "self-limits-before" {
					var input struct {
						SnapshotID string `json:"SnapshotId"`
					}
					awsDecodeJSON(t, row.Input, &input)
					// The limit probe reused a previously public native snapshot.
					// Bind that prerequisite to the fresh local public snapshot.
					r.bindings[input.SnapshotID] = r.bindings[snapshot.SnapshotID]
				}
				if strings.HasPrefix(row.Label, "self-limits-") || strings.HasPrefix(row.Label, "canonical-self-add-") || strings.HasPrefix(row.Label, "legacy-self-add-") {
					if !t.Run(row.Label, func(t *testing.T) { ebsSharingControlCall(t, r, row) }) {
						return
					}
				}
			}
		})
	}
}

// This workflow is document-derived, not a native settings-mutation capture:
// https://docs.aws.amazon.com/ebs/latest/userguide/block-public-access-snapshots.html
func TestEBSSnapshotPublicBlockModes(t *testing.T) {
	fixture, rows := ebsSharingControlRows(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newEBSSharingControlReplay(t, fixture, backend)
			for _, label := range []string{"plain", "plain-complete", "plain-state-1", "isolated-permission-boundaries", "isolated-permission-boundaries-complete", "isolated-permission-boundaries-state-1"} {
				r.call(t, rows[label])
			}
			snapshotID := func(label string) string {
				t.Helper()
				var output struct {
					SnapshotID string `json:"SnapshotId"`
				}
				awsDecodeJSON(t, rows[label].Output, &output)
				return r.bindings[output.SnapshotID]
			}
			publicID, privateID := snapshotID("plain"), snapshotID("isolated-permission-boundaries")
			control := func(account, region string) *ec2.Client {
				return ec2.New(ec2.Options{
					Region: region, BaseEndpoint: aws.String(r.clients.server.URL),
					Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""),
					HTTPClient:  r.clients.server.Client(), RetryMaxAttempts: 1,
				})
			}
			owner := func() *ec2.Client { return control("test", fixture.Region) }
			share := func(id, account string, public bool) error {
				t.Helper()
				permission := ec2types.CreateVolumePermission{UserId: aws.String(account)}
				if public {
					permission = ec2types.CreateVolumePermission{Group: ec2types.PermissionGroup("all")}
				}
				_, err := owner().ModifySnapshotAttribute(t.Context(), &ec2.ModifySnapshotAttributeInput{
					SnapshotId:             aws.String(id),
					CreateVolumePermission: &ec2types.CreateVolumePermissionModifications{Add: []ec2types.CreateVolumePermission{permission}},
				})
				return err
			}
			permissions := func(id string, expected []ec2types.CreateVolumePermission) {
				t.Helper()
				output, err := owner().DescribeSnapshotAttribute(t.Context(), &ec2.DescribeSnapshotAttributeInput{
					SnapshotId: aws.String(id), Attribute: ec2types.SnapshotAttributeName("createVolumePermission"),
				})
				if err != nil {
					t.Fatal(err)
				}
				want := ec2NetworkDocument(t, &ec2.DescribeSnapshotAttributeOutput{SnapshotId: aws.String(id), CreateVolumePermissions: expected})
				got := ec2NetworkDocument(t, output)
				ec2NetworkSort(t, want, nil, false)
				ec2NetworkSort(t, got, nil, false)
				ec2NetworkCompare(t, "permissions", want, got, nil)
			}
			visible := func(account, id string, expected bool) {
				t.Helper()
				output, err := control(account, fixture.Region).DescribeSnapshots(t.Context(), &ec2.DescribeSnapshotsInput{SnapshotIds: []string{id}})
				if !expected {
					assertAPIError(t, err, "InvalidSnapshot.NotFound")
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(output.Snapshots) != 1 || aws.ToString(output.Snapshots[0].SnapshotId) != id || aws.ToString(output.Snapshots[0].OwnerId) != ebsSharingControlOwner {
					t.Fatalf("wrong shared snapshot identity: %+v", output.Snapshots)
				}
			}
			state := func(account, region, expected string) {
				t.Helper()
				output, err := control(account, region).GetSnapshotBlockPublicAccessState(t.Context(), &ec2.GetSnapshotBlockPublicAccessStateInput{})
				if err != nil || string(output.State) != expected || string(output.ManagedBy) != "account" {
					t.Fatalf("public block state in %s/%s: %+v, %v; want %s/account", account, region, output, err, expected)
				}
			}
			setState := func(mode string) {
				t.Helper()
				r.clock.Advance(10 * time.Second)
				if mode == "unblocked" {
					output, err := owner().DisableSnapshotBlockPublicAccess(t.Context(), &ec2.DisableSnapshotBlockPublicAccessInput{})
					if err != nil || string(output.State) != mode {
						t.Fatalf("disable public block: %+v, %v", output, err)
					}
				} else {
					output, err := owner().EnableSnapshotBlockPublicAccess(t.Context(), &ec2.EnableSnapshotBlockPublicAccessInput{State: ec2types.SnapshotBlockPublicAccessState(mode)})
					if err != nil || string(output.State) != mode {
						t.Fatalf("enable %s: %+v, %v", mode, output, err)
					}
				}
				r.clients = r.reopen()
				state("test", fixture.Region, mode)
			}
			if err := share(publicID, "", true); err != nil {
				t.Fatal(err)
			}
			if err := share(privateID, ebsSharingControlMember, false); err != nil {
				t.Fatal(err)
			}
			r.clock.Advance(ebsdomain.SharingDelay)
			r.clients = r.reopen()
			const outsider = "333333333333"
			publicGrant := []ec2types.CreateVolumePermission{{Group: ec2types.PermissionGroup("all")}}
			privateGrant := []ec2types.CreateVolumePermission{{UserId: aws.String(ebsSharingControlMember)}}
			visible(outsider, publicID, true)
			visible(outsider, privateID, false)
			visible(ebsSharingControlMember, privateID, true)

			for _, mode := range []string{"block-new-sharing", "block-all-sharing"} {
				setState(mode)
				state(ebsSharingControlMember, fixture.Region, "unblocked")
				state("test", "us-west-2", "unblocked")
				visible(outsider, publicID, mode == "block-new-sharing")
				visible(ebsSharingControlMember, privateID, true)
				permissions(publicID, publicGrant)
				if err := share(privateID, "", true); err == nil {
					t.Fatal("public blocking admitted a new public grant")
				}
				r.clients = r.reopen()
				permissions(privateID, privateGrant)
				visible(outsider, privateID, false)
			}
			// New private grants remain possible even while all public sharing is blocked.
			const additionalRecipient = "444444444444"
			if err := share(privateID, additionalRecipient, false); err != nil {
				t.Fatal(err)
			}
			privateGrant = append(privateGrant, ec2types.CreateVolumePermission{UserId: aws.String(additionalRecipient)})
			r.clock.Advance(ebsdomain.SharingDelay)
			r.clients = r.reopen()
			visible(additionalRecipient, privateID, true)
			permissions(privateID, privateGrant)
			// Block-all must not erase the old public grant; moving to block-new
			// restores its visibility while continuing to reject new grants.
			setState("block-new-sharing")
			visible(outsider, publicID, true)
			permissions(publicID, publicGrant)
			setState("block-all-sharing")
			visible(outsider, publicID, false)
			setState("unblocked")
			visible(outsider, publicID, true)
			visible(ebsSharingControlMember, privateID, true)
			if err := share(privateID, "", true); err != nil {
				t.Fatal(err)
			}
			r.clock.Advance(ebsdomain.SharingDelay)
			r.clients = r.reopen()
			visible(outsider, privateID, true)
			permissions(privateID, append(privateGrant, publicGrant...))
		})
	}
}

func TestEBSNativeSharingBatchAuthority(t *testing.T) {
	var fixture ebsNativeFixture
	awsReadFixture(t, "ebs/sharing_batch_authority.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newEBSSharingControlReplay(t, fixture, backend)
			for _, row := range fixture.Calls {
				if strings.HasPrefix(row.Label, "cleanup-") {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					if row.Service == "ec2" {
						ebsSharingControlCall(t, r, row)
					} else {
						r.call(t, row)
					}
				}) {
					return
				}
			}
		})
	}
}
