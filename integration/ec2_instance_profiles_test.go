package stackd_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
)

// The seeded row supplies control-plane preconditions, not guest execution.
// Actual IMDS/guest transitions are exercised by the QEMU workflow. This replay
// proves signed command semantics, atomic relationship/projection replacement,
// obsolete association isolation, and recovery of in-flight transitions.
func TestEC2NativeInstanceProfileAssociations(t *testing.T) {
	var fixture struct {
		Account, Region string
		Calls           []struct{ Label, Code string }
	}
	awsReadFixture(t, "ec2/instance_profiles_transitions.json", &fixture)
	codes := make(map[string]string, len(fixture.Calls))
	for _, row := range fixture.Calls {
		codes[row.Label] = row.Code
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			manual := clock.NewManual(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
			var cloud *stackd.Stack
			var repository domain.Repository
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: manual}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				repository = config.Storage.EC2
				var err error
				cloud, err = stackd.New(config)
				if err != nil {
					t.Fatal(err)
				}
				return cloud, httptest.NewServer(cloud)
			})
			client := func() *sdkec2.Client {
				return sdkec2.New(sdkec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			identity := clients.iam(fixture.Account, "test", "")
			profiles := make([]*iam.CreateInstanceProfileOutput, 0, 2)
			for _, name := range []string{"profile-first", "profile-second"} {
				_, err := identity.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
				if err != nil {
					t.Fatal(err)
				}
				profile, err := identity.CreateInstanceProfile(ctx, &iam.CreateInstanceProfileInput{InstanceProfileName: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := identity.AddRoleToInstanceProfile(ctx, &iam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String(name), RoleName: aws.String(name)}); err != nil {
					t.Fatal(err)
				}
				profiles = append(profiles, profile)
			}
			key := domain.ResourceKey{Scope: domain.Scope{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region}, ID: "i-0123456789abcdef0"}
			if err := repository.Update(ctx, func(tx domain.Transaction) error {
				return tx.PutInstance(domain.InstanceRecord{Key: key, Data: api.Instance{InstanceId: new(api.String(key.ID)), State: &api.InstanceState{Name: new(api.InstanceStateName("running")), Code: new(api.Integer(16))}}})
			}); err != nil {
				t.Fatal(err)
			}
			operator, err := identity.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("profile-operator"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + fixture.Account + `:root"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identity.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: operator.Role.RoleName, PolicyName: aws.String("profiles"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":["ec2:*IamInstanceProfile*","iam:PassRole"],"Resource":"*"}}`)}); err != nil {
				t.Fatal(err)
			}
			restricted := func(policy string) *sdkec2.Client {
				t.Helper()
				session, err := clients.sts(fixture.Account, "test", "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: operator.Role.Arn, RoleSessionName: aws.String("profile-caller"), Policy: aws.String(policy)})
				if err != nil {
					t.Fatal(err)
				}
				return sdkec2.New(sdkec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken)), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			instanceARN := "arn:aws:ec2:" + fixture.Region + ":" + fixture.Account + ":instance/" + key.ID
			roleARN := "arn:aws:iam::" + fixture.Account + ":role/profile-first"
			input := &sdkec2.AssociateIamInstanceProfileInput{InstanceId: aws.String(key.ID), IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: profiles[0].InstanceProfile.InstanceProfileName}}
			_, err = restricted(`{"Statement":{"Effect":"Allow","Action":"ec2:AssociateIamInstanceProfile","Resource":"*"}}`).AssociateIamInstanceProfile(ctx, input)
			assertAPIError(t, err, codes["iam-no-pass-dry"])
			passPolicy := func(associated string) string {
				return fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"ec2:AssociateIamInstanceProfile","Resource":%q,"Condition":{"ArnEquals":{"ec2:NewInstanceProfile":%q}}},{"Effect":"Allow","Action":"iam:PassRole","Resource":%q,"Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"},"ArnLike":{"iam:AssociatedResourceArn":%q}}}]}`, instanceARN, aws.ToString(profiles[0].InstanceProfile.Arn), roleARN, associated)
			}
			_, err = restricted(passPolicy(instanceARN)).AssociateIamInstanceProfile(ctx, input)
			assertAPIError(t, err, codes["iam-pass-associated-dry"])
			permitted := restricted(passPolicy("arn:aws:ec2:" + fixture.Region + ":" + fixture.Account + ":instance/*"))
			advance := func(d time.Duration) {
				t.Helper()
				manual.Advance(d)
				if _, err := cloud.RunDueJobs(ctx, 100); err != nil {
					t.Fatal(err)
				}
			}
			projection := func(want *iam.CreateInstanceProfileOutput) {
				t.Helper()
				if err := repository.View(ctx, func(tx domain.Reader) error {
					instance, err := tx.Instance(key)
					if err != nil {
						return err
					}
					if want == nil {
						if instance.Data.IamInstanceProfile != nil {
							t.Fatalf("disassociated instance retained profile: %+v", instance.Data.IamInstanceProfile)
						}
						return nil
					}
					if instance.Data.IamInstanceProfile == nil || string(*instance.Data.IamInstanceProfile.Id) != aws.ToString(want.InstanceProfile.InstanceProfileId) {
						t.Fatalf("instance projection = %+v, expected profile %s", instance.Data.IamInstanceProfile, aws.ToString(want.InstanceProfile.InstanceProfileId))
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			// These four APIs accept native Query DryRun even though current
			// AWS SDK models omit it. Sign the real wire request, not a DTO echo.
			dry := func(action, label string, values url.Values) {
				t.Helper()
				values.Set("Action", action)
				values.Set("Version", "2016-11-15")
				values.Set("DryRun", "true")
				body := values.Encode()
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, clients.server.URL, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				digest := sha256.Sum256([]byte(body))
				if err := v4.NewSigner().SignHTTP(ctx, aws.Credentials{AccessKeyID: fixture.Account, SecretAccessKey: "test"}, request, hex.EncodeToString(digest[:]), "ec2", fixture.Region, time.Now()); err != nil {
					t.Fatal(err)
				}
				response, err := clients.server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				var rejected struct {
					Errors struct{ Error struct{ Code string } }
				}
				if err := xml.NewDecoder(response.Body).Decode(&rejected); err != nil {
					t.Fatal(err)
				}
				if rejected.Errors.Error.Code != codes[label] {
					t.Fatalf("%s DryRun code %q; native %q", action, rejected.Errors.Error.Code, codes[label])
				}
			}
			dry("AssociateIamInstanceProfile", "associate-both-profile-fields-dry", url.Values{"InstanceId": {key.ID}, "IamInstanceProfile.Name": {aws.ToString(profiles[0].InstanceProfile.InstanceProfileName)}})
			dry("DescribeIamInstanceProfileAssociations", "describe-negative-63", url.Values{})
			unassociated, err := client().DescribeIamInstanceProfileAssociations(ctx, &sdkec2.DescribeIamInstanceProfileAssociationsInput{})
			if err != nil {
				t.Fatal(err)
			}
			if len(unassociated.IamInstanceProfileAssociations) != 0 {
				t.Fatal("DryRun created an association")
			}
			first, err := permitted.AssociateIamInstanceProfile(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			oldID := aws.ToString(first.IamInstanceProfileAssociation.AssociationId)
			if first.IamInstanceProfileAssociation.State != ec2types.IamInstanceProfileAssociationStateAssociating || first.IamInstanceProfileAssociation.Timestamp != nil {
				t.Fatalf("native association envelope: %+v", first.IamInstanceProfileAssociation)
			}
			_, err = client().AssociateIamInstanceProfile(ctx, &sdkec2.AssociateIamInstanceProfileInput{InstanceId: aws.String(key.ID), IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: profiles[0].InstanceProfile.InstanceProfileName}})
			assertAPIError(t, err, codes["associate-duplicate-immediate"])
			clients = reopen()
			advance(time.Second)
			projection(profiles[0])
			dry("ReplaceIamInstanceProfileAssociation", "replace-owner-dry", url.Values{"AssociationId": {oldID}, "IamInstanceProfile.Name": {aws.ToString(profiles[1].InstanceProfile.InstanceProfileName)}})
			same, err := client().ReplaceIamInstanceProfileAssociation(ctx, &sdkec2.ReplaceIamInstanceProfileAssociationInput{AssociationId: aws.String(oldID), IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: profiles[0].InstanceProfile.InstanceProfileName}})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(same.IamInstanceProfileAssociation.AssociationId) != oldID || same.IamInstanceProfileAssociation.State != ec2types.IamInstanceProfileAssociationStateAssociated {
				t.Fatalf("same-profile replacement changed relationship: %+v", same.IamInstanceProfileAssociation)
			}
			replaced, err := client().ReplaceIamInstanceProfileAssociation(ctx, &sdkec2.ReplaceIamInstanceProfileAssociationInput{AssociationId: aws.String(oldID), IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: profiles[1].InstanceProfile.InstanceProfileName}})
			if err != nil {
				t.Fatal(err)
			}
			newID := aws.ToString(replaced.IamInstanceProfileAssociation.AssociationId)
			if newID == oldID || replaced.IamInstanceProfileAssociation.State != ec2types.IamInstanceProfileAssociationStateAssociating {
				t.Fatalf("replacement must allocate associating relationship: %+v", replaced.IamInstanceProfileAssociation)
			}
			clients = reopen()
			projection(profiles[0]) // Replacement admission preserves delivered profile.
			transitions, err := client().DescribeIamInstanceProfileAssociations(ctx, &sdkec2.DescribeIamInstanceProfileAssociationsInput{Filters: []ec2types.Filter{{Name: aws.String("instance-id"), Values: []string{key.ID}}}})
			if err != nil {
				t.Fatal(err)
			}
			states := make(map[string]ec2types.IamInstanceProfileAssociationState)
			for _, row := range transitions.IamInstanceProfileAssociations {
				states[aws.ToString(row.AssociationId)] = row.State
			}
			if len(states) != 2 || states[oldID] != ec2types.IamInstanceProfileAssociationStateDisassociating || states[newID] != ec2types.IamInstanceProfileAssociationStateAssociating {
				t.Fatalf("replacement transitions = %+v", states)
			}
			page, err := client().DescribeIamInstanceProfileAssociations(ctx, &sdkec2.DescribeIamInstanceProfileAssociationsInput{MaxResults: aws.Int32(1)})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.IamInstanceProfileAssociations) != 1 || page.NextToken == nil {
				t.Fatalf("first association page: %+v", page)
			}
			clients = reopen()
			last, err := client().DescribeIamInstanceProfileAssociations(ctx, &sdkec2.DescribeIamInstanceProfileAssociationsInput{NextToken: page.NextToken, MaxResults: aws.Int32(1)})
			if err != nil {
				t.Fatal(err)
			}
			if len(last.IamInstanceProfileAssociations) != 1 || last.NextToken != nil || aws.ToString(page.IamInstanceProfileAssociations[0].AssociationId) == aws.ToString(last.IamInstanceProfileAssociations[0].AssociationId) {
				t.Fatalf("continued association page repeated or lost a relationship: %+v", last)
			}
			advance(time.Second)
			projection(profiles[1]) // Retiring old work must not clear the replacement.
			_, err = client().DescribeIamInstanceProfileAssociations(ctx, &sdkec2.DescribeIamInstanceProfileAssociationsInput{NextToken: aws.String("invalid")})
			assertAPIError(t, err, "InvalidNextToken")
			_, err = client().DescribeIamInstanceProfileAssociations(ctx, &sdkec2.DescribeIamInstanceProfileAssociationsInput{Filters: []ec2types.Filter{{Name: aws.String("iam-instance-profile.arn"), Values: []string{aws.ToString(profiles[1].InstanceProfile.Arn)}}}})
			assertAPIError(t, err, codes["describe-filter-profile"])
			dry("DisassociateIamInstanceProfile", "disassociate-no-pass-dry", url.Values{"AssociationId": {newID}})
			stillAssociated, err := client().DescribeIamInstanceProfileAssociations(ctx, &sdkec2.DescribeIamInstanceProfileAssociationsInput{AssociationIds: []string{newID}})
			if err != nil {
				t.Fatal(err)
			}
			if len(stillAssociated.IamInstanceProfileAssociations) != 1 || stillAssociated.IamInstanceProfileAssociations[0].State != ec2types.IamInstanceProfileAssociationStateAssociated {
				t.Fatal("DryRun disassociated the active profile")
			}
			if _, err := client().DisassociateIamInstanceProfile(ctx, &sdkec2.DisassociateIamInstanceProfileInput{AssociationId: aws.String(newID)}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			advance(time.Second)
			projection(nil)
			advance(time.Minute)
			_, err = client().DisassociateIamInstanceProfile(ctx, &sdkec2.DisassociateIamInstanceProfileInput{AssociationId: aws.String(oldID)})
			assertAPIError(t, err, codes["replace-disassociated"])
			identity = clients.iam(fixture.Account, "test", "")
			for _, name := range []string{"empty-delivery", "denied-delivery"} {
				profile, err := identity.CreateInstanceProfile(ctx, &iam.CreateInstanceProfileInput{InstanceProfileName: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				if name == "denied-delivery" {
					if _, err := identity.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`)}); err != nil {
						t.Fatal(err)
					}
					if _, err := identity.AddRoleToInstanceProfile(ctx, &iam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String(name), RoleName: aws.String(name)}); err != nil {
						t.Fatal(err)
					}
				}
				attached, err := client().AssociateIamInstanceProfile(ctx, &sdkec2.AssociateIamInstanceProfileInput{InstanceId: aws.String(key.ID), IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: profile.InstanceProfile.InstanceProfileName}})
				if err != nil {
					t.Fatal(err)
				}
				advance(time.Second)
				observed, err := client().DescribeIamInstanceProfileAssociations(ctx, &sdkec2.DescribeIamInstanceProfileAssociationsInput{AssociationIds: []string{aws.ToString(attached.IamInstanceProfileAssociation.AssociationId)}})
				if err != nil {
					t.Fatal(err)
				}
				want := ec2types.IamInstanceProfileAssociationStateAssociated
				if name == "denied-delivery" {
					want = ec2types.IamInstanceProfileAssociationStateAssociating
				}
				if len(observed.IamInstanceProfileAssociations) != 1 || observed.IamInstanceProfileAssociations[0].State != want {
					t.Fatalf("%s delivery state = %+v, want %s", name, observed.IamInstanceProfileAssociations, want)
				}
				if name == "denied-delivery" {
					if _, err := identity.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: aws.String(name), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`)}); err != nil {
						t.Fatal(err)
					}
					advance(time.Minute)
				}
				projection(profile)
				if _, err := client().DisassociateIamInstanceProfile(ctx, &sdkec2.DisassociateIamInstanceProfileInput{AssociationId: attached.IamInstanceProfileAssociation.AssociationId}); err != nil {
					t.Fatal(err)
				}
				advance(time.Second)
				projection(nil)
			}
			if err := repository.Update(ctx, func(tx domain.Transaction) error {
				instance, err := tx.Instance(key)
				if err != nil {
					return err
				}
				instance.Data.State = &api.InstanceState{Name: new(api.InstanceStateName("stopped")), Code: new(api.Integer(80))}
				return tx.PutInstance(instance)
			}); err != nil {
				t.Fatal(err)
			}
			stopped, err := client().AssociateIamInstanceProfile(ctx, &sdkec2.AssociateIamInstanceProfileInput{InstanceId: aws.String(key.ID), IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: profiles[0].InstanceProfile.InstanceProfileName}})
			if err != nil {
				t.Fatal(err)
			}
			advance(time.Second)
			_, err = client().ReplaceIamInstanceProfileAssociation(ctx, &sdkec2.ReplaceIamInstanceProfileAssociationInput{AssociationId: stopped.IamInstanceProfileAssociation.AssociationId, IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: profiles[1].InstanceProfile.InstanceProfileName}})
			assertAPIError(t, err, "IncorrectState")
			projection(profiles[0])
		})
	}
}
