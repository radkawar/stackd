package stackd_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/internal/awstest"
	ebsdomain "stackd/internal/services/ebs"
)

// These are finite native workflows, not an EC2/EBS parity claim. Native polling
// latency is deliberately replaced with the owner's deterministic clock policy.
// The existing snapshot replay compares public SDK documents and real block bytes,
// and reconstructs both memory and SQLite owners after every successful request.
func TestEBSNativeSharingData(t *testing.T) {
	for _, name := range []string{
		"sharing_data_settled", "sharing_data_tags_settled", "sharing_data_pairs",
		"sharing_data_public_token", "sharing_tag_authority",
	} {
		t.Run(name, func(t *testing.T) {
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					r := newEBSSharingReplay(t, name, backend)
					sharedTokens := map[string]string{}
					pendingPublication := false
					for _, row := range r.fixture.Calls {
						if !ebsSharingDataRow(row) {
							continue
						}
						if !t.Run(row.Label, func(t *testing.T) {
							var input struct {
								SnapshotId string
								GroupNames []string
							}
							awsDecodeJSON(t, row.Input, &input)
							// Revocation and reset must invalidate an already-issued token;
							// re-sharing must revive that same token, not a freshly listed one.
							if row.Operation == "GetSnapshotBlock" && (strings.Contains(row.Label, "-revoked-") || strings.Contains(row.Label, "-reset-") || strings.Contains(row.Label, "-reshared-old-token-old-token-get")) {
								row = ebsSharingToken(t, row, sharedTokens[input.SnapshotId])
							}
							if pendingPublication && row.Service == "ebs" {
								r.clock.Advance(ebsdomain.SharingDelay)
								pendingPublication = false
							}
							ebsSharingCall(t, r, row)
							if row.Label == "plain-shared-list" || row.Label == "encrypted-key-shared-list" {
								sharedTokens[input.SnapshotId] = r.tokens[input.SnapshotId+"/0"]
							}
							// Public guards are immediate, including on a token minted
							// under the still-effective private grant. Only private
							// grant/revoke publication advances the local sharing clock.
							if row.Code == "Success" && len(input.GroupNames) == 0 && (row.Operation == "ModifySnapshotAttribute" || row.Operation == "ResetSnapshotAttribute") {
								if name == "sharing_data_settled" && (row.Label == "plain-share" || row.Label == "encrypted-share" || row.Label == "encrypted-revoke") {
									// Explicit-ID metadata precedes published discovery;
									// this revoke likewise retains metadata before EBS
									// rejects it. Preserve phases, not native latency.
									pendingPublication = true
								} else {
									r.clock.Advance(ebsdomain.SharingDelay)
								}
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

// Pin the local publication boundary using native before/after outcomes, never
// capture timestamps. Get does not advance replay phases or mint a replacement
// token, so these requests really exercise both sides of the exact deadline.
func TestEBSSnapshotSharingPublicationBoundaries(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newEBSSharingReplay(t, "sharing_data_settled", backend)
			rows := make(map[string]ebsNativeCall, len(r.fixture.Calls))
			for _, row := range r.fixture.Calls {
				rows[row.Label] = row
			}
			call := func(t *testing.T, label string) {
				t.Helper()
				row, ok := rows[label]
				if !ok {
					t.Fatalf("missing native sharing observation %q", label)
				}
				ebsSharingCall(t, r, row)
			}
			for _, label := range []string{"plain-source", "plain-put", "plain-complete", "plain-owner-list", "plain-owner-get", "plain-private-old-token-get"} {
				call(t, label)
			}
			for _, transition := range []struct{ mutation, before, after string }{
				{"plain-share", "plain-private-old-token-get", "plain-shared-old-token-get"},
				{"plain-revoke", "plain-shared-old-token-get", "plain-revoked-old-token-get"},
				{"plain-reshare", "plain-revoked-old-token-get", "plain-reshared-old-token-old-token-get"},
				{"plain-reset", "plain-shared-old-token-get", "plain-reset-old-token-get"},
			} {
				if !t.Run(transition.mutation, func(t *testing.T) {
					call(t, transition.mutation)
					call(t, transition.before)
					r.clock.Advance(ebsdomain.SharingDelay - time.Millisecond)
					call(t, transition.before)
					r.clients = r.reopen()
					r.clock.Advance(time.Millisecond)
					call(t, transition.after)
					call(t, "plain-owner-get")
				}) {
					return
				}
			}
		})
	}
}

func newEBSSharingReplay(t *testing.T, name, backend string) *ebsSnapshotReplay {
	t.Helper()
	var fixture struct {
		ebsNativeFixture
		Member        string
		MemberAccount string `json:"member_account"`
	}
	awsReadFixture(t, "ebs/"+name+".json", &fixture)
	owner, member := fixture.Account, fixture.Member
	if member == "" {
		member = fixture.MemberAccount
	}
	if owner == "" || member == "" || owner == member {
		t.Fatal("sharing capture must identify distinct owner and recipient accounts")
	}
	// The sharing probe imports the existing encryption probe's synthetic recipe.
	// Its upload metadata independently supplies the length/digest to that replay.
	for index := range fixture.Calls {
		row := &fixture.Calls[index]
		if row.Operation == "PutSnapshotBlock" {
			var input struct {
				BlockData struct {
					Length int
					SHA256 string
				}
			}
			awsDecodeJSON(t, row.Input, &input)
			if fixture.Payload.Length != 0 && fixture.Payload != input.BlockData {
				t.Fatal("sharing capture contains a different synthetic byte recipe")
			}
			fixture.Payload = input.BlockData
		}
		if name == "sharing_tag_authority" {
			switch {
			case strings.HasPrefix(row.Label, "member-"):
				row.Caller = "member"
			case strings.HasPrefix(row.Label, "immediate-"):
				row.Caller = strings.TrimPrefix(row.Label, "immediate-")
			case strings.HasPrefix(row.Label, "settled-"):
				row.Caller = strings.TrimPrefix(row.Label, "settled-")
			default:
				row.Caller = "owner"
			}
		}
	}
	const localOwner, localMember = "111111111111", "222222222222"
	fixture.Account = localOwner
	r := newEBSSnapshotReplay(t, fixture.ebsNativeFixture, backend)
	r.bind(t, owner, localOwner)
	r.bind(t, member, localMember)
	root := r.clients.iam(localMember, "test", "")
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}]}`, localOwner)
	for _, roleName := range []string{"SharingRecipient", "SharingNoIdentityAllow"} {
		role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{
			RoleName: aws.String(roleName), AssumeRolePolicyDocument: aws.String(trust),
		})
		if err != nil {
			t.Fatal(err)
		}
		caller := "no-identity-allow"
		if roleName == "SharingRecipient" {
			putRolePolicy(t, root, roleName, allow(`"*"`, "*"))
			r.roleARN = aws.ToString(role.Role.Arn)
			caller = "member"
		}
		session, err := r.clients.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{
			RoleArn: role.Role.Arn, RoleSessionName: aws.String(caller),
		})
		if err != nil {
			t.Fatal(err)
		}
		value := session.Credentials
		r.sessions[caller] = credentials.NewStaticCredentialsProvider(aws.ToString(value.AccessKeyId), aws.ToString(value.SecretAccessKey), aws.ToString(value.SessionToken))
	}
	if name == "sharing_data_pairs" || name == "sharing_data_public_token" {
		// The captures explicitly observed an unblocked owner account. Set that
		// precondition through the local SDK instead of borrowing an account default.
		client := ec2.New(ec2.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: r.provider(t, "owner"), HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
		if _, err := client.DisableSnapshotBlockPublicAccess(t.Context(), &ec2.DisableSnapshotBlockPublicAccessInput{}); err != nil {
			t.Fatal(err)
		}
	}
	r.clients = r.reopen()
	return r
}

func ebsSharingDataRow(row ebsNativeCall) bool {
	if strings.Contains(row.Label, "cleanup") {
		return false
	}
	if strings.Contains(row.Label, "readiness") && row.Code != "Success" {
		return false // Completion/readiness boundaries have a separate replay.
	}
	if strings.HasPrefix(row.Label, "immediate-") {
		return false // Use the settled resource-tag authority observations.
	}
	switch row.Service {
	case "ebs", "ec2":
		return true
	case "kms":
		return row.Operation == "CreateKey" || row.Operation == "PutKeyPolicy"
	default:
		// The original caller's standing organization role and the unprivileged
		// role are provisioned locally above; trail delivery belongs to audit tests.
		return false
	}
}

func ebsSharingToken(t *testing.T, row ebsNativeCall, token string) ebsNativeCall {
	t.Helper()
	if token == "" {
		t.Fatalf("%s has no previously issued recipient token", row.Label)
	}
	var input map[string]json.RawMessage
	awsDecodeJSON(t, row.Input, &input)
	input["BlockToken"], _ = json.Marshal(token)
	var err error
	row.Input, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func ebsSharingCall(t *testing.T, r *ebsSnapshotReplay, row ebsNativeCall) {
	t.Helper()
	if row.Service != "kms" || row.Operation != "PutKeyPolicy" {
		r.call(t, row)
		return
	}
	// Existing setup owns key creation/binding. This sharing-only trust transition
	// is a real KMS request; no grant or bypass is substituted for the native policy.
	wire := &awstest.WireClient{Client: r.clients.server.Client()}
	client := kms.New(kms.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: r.provider(t, row.Caller), HTTPClient: wire, RetryMaxAttempts: 1})
	_, err := awstest.CallSDK(t.Context(), client, row.Operation, ec2AuditReplace(t, row.Input, r.bindings))
	if row.Code != "Success" {
		r.checkError(t, row, wire, err)
		return
	}
	if err != nil || wire.Status != row.HTTPStatus {
		t.Fatalf("native KMS trust transition: HTTP %d, want %d: %v", wire.Status, row.HTTPStatus, err)
	}
	r.clients = r.reopen()
}
