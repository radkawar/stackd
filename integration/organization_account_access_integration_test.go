package stackd_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/storage"
	iamstore "stackd/storage/iam"
	orgstore "stackd/storage/organizations"
)

func TestOrganizationAccountAccessRoleAWSReplaySDK(t *testing.T) {
	for _, roleName := range []string{"OrganizationAccountAccessRole", "CustomAccess"} {
		t.Run(roleName, func(t *testing.T) {
			f := newOrganizationReportFixture(t, nil)
			in := &organizations.CreateAccountInput{AccountName: aws.String("access-member"), Email: aws.String("access-member@example.test")}
			if roleName != "OrganizationAccountAccessRole" {
				in.RoleName = &roleName
			}
			created, err := f.org.CreateAccount(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			created.CreateAccountStatus = waitAccountCreation(t, f.org, created.CreateAccountStatus, f.clock)
			member := aws.ToString(created.CreateAccountStatus.AccountId)
			want := loadOrganizationRoleCapture(t, member, roleName).AccessRole
			owner := f.cloud.iam(member, "test", "")
			_, err = f.iam.GetRole(t.Context(), &iam.GetRoleInput{RoleName: &roleName})
			assertAPIError(t, err, "NoSuchEntity")
			r := assertOrganizationRoleCapture(t, owner, want)
			if !r.CreateDate.Equal(f.clock.Now()) {
				t.Fatalf("role creation time = %v", r.CreateDate)
			}
			// An ordinary management-account principal still needs AssumeRole;
			// account-root trust does not give all its users permission by itself.
			_, key, secret := f.cloud.user(t, "test", "operator")
			caller := f.cloud.sts(key, secret, "")
			assume := &sts.AssumeRoleInput{RoleArn: r.Arn, RoleSessionName: aws.String("stackd-read-access-role")}
			_, err = caller.AssumeRole(t.Context(), assume)
			assertAPIError(t, err, "AccessDenied")
			putUserPolicy(t, f.iam, "operator", allow(`"sts:AssumeRole"`, *r.Arn))
			session, err := caller.AssumeRole(t.Context(), assume)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := f.cloud.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
			if err != nil || aws.ToString(identity.Arn) != want.SessionArn || aws.ToString(identity.Account) != member {
				t.Fatalf("assumed identity = %+v, err=%v", identity, err)
			}
			_, err = f.cloud.sts("333333333333", "test", "").AssumeRole(t.Context(), assume)
			assertAPIError(t, err, "AccessDenied")
			c := session.Credentials
			admin := f.cloud.iam(*c.AccessKeyId, *c.SecretAccessKey, *c.SessionToken)
			if _, err := admin.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("admin-created")}); err != nil {
				t.Fatal("initial role cannot administer member IAM", err)
			}
			// The ordinary role remains subject to current member SCPs and IAM
			// attachments, including for already-issued credentials.
			f.policy(t, "deny-create", `{"Statement":{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*"}}`, member)
			_, err = admin.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("denied")})
			assertAPIError(t, err, "AccessDenied")
			if _, err := owner.DetachRolePolicy(t.Context(), &iam.DetachRolePolicyInput{RoleName: &roleName, PolicyArn: want.AttachedPolicies[0].PolicyArn}); err != nil {
				t.Fatal(err)
			}
			_, err = admin.ListUsers(t.Context(), &iam.ListUsersInput{})
			assertAPIError(t, err, "AccessDenied")
			if _, err := owner.DeleteRole(t.Context(), &iam.DeleteRoleInput{RoleName: &roleName}); err != nil {
				t.Fatal("access role must be customer-manageable", err)
			}
		})
	}
}

func TestOrganizationAccountCreationUsesOrganizationsPermissionsSDK(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	_, key, secret := f.cloud.user(t, "test", "account-creator")
	putUserPolicy(t, f.iam, "account-creator", `{"Statement":[{"Effect":"Allow","Action":"organizations:CreateAccount","Resource":"*"},{"Effect":"Deny","Action":["iam:CreateRole","iam:AttachRolePolicy"],"Resource":"*"}]}`)
	client := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(f.cloud.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: f.cloud.server.Client(), RetryMaxAttempts: 1})
	in := &organizations.CreateAccountInput{AccountName: aws.String("permission-member"), Email: aws.String("permission-member@example.test"), Tags: []orgtypes.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}}
	_, err := client.CreateAccount(t.Context(), in)
	assertAPIError(t, err, "AccessDeniedException")
	in.Tags = nil
	out, err := client.CreateAccount(t.Context(), in)
	if err != nil {
		t.Fatal("Organizations creation must not require the caller's IAM role-write permissions", err)
	}
	out.CreateAccountStatus = waitAccountCreation(t, f.org, out.CreateAccountStatus, f.clock)
	member := aws.ToString(out.CreateAccountStatus.AccountId)
	if _, err := f.cloud.iam(member, "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("OrganizationAccountAccessRole")}); err != nil {
		t.Fatal("creation did not provision access", err)
	}
	statuses, err := f.org.ListCreateAccountStatus(t.Context(), &organizations.ListCreateAccountStatusInput{})
	if err != nil || len(statuses.CreateAccountStatuses) != 1 {
		t.Fatalf("unauthorized tagged creation left state: %+v, %v", statuses, err)
	}
}

func TestOrganizationCreationMissingPartitionTemplateRollsBackSDK(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	client := organizations.New(organizations.Options{Region: "us-gov-west-1", BaseEndpoint: aws.String(f.cloud.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: f.cloud.server.Client(), RetryMaxAttempts: 1})
	_, err := client.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
	assertAPIError(t, err, "NotImplemented")
	_, err = client.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	assertAPIError(t, err, "AWSOrganizationsNotInUseException")
	_, err = client.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetConsolidatedBilling})
	assertAPIError(t, err, "ConstraintViolationException")
	// The rejected GovCloud operation does not reserve commercial identities.
	member := f.account(t, f.rootID, "missing-template")
	if member != "100000000001" {
		t.Fatalf("commercial member = %s", member)
	}
}

type accountRoleRepository struct {
	iamstore.Repository
	mode      atomic.Int32
	attempted chan error
}

func (r *accountRoleRepository) Update(ctx context.Context, fn func(iamstore.WriteTx) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wrote := false
	err := r.Repository.Update(ctx, func(tx iamstore.WriteTx) error {
		if err := fn(accountRoleTx{WriteTx: tx, wrote: &wrote}); err != nil {
			return err
		}
		if wrote {
			switch r.mode.Load() {
			case 1:
				return errors.New("injected IAM publication failure")
			case 2:
				cancel()
			}
		}
		return nil
	})
	if wrote && err != nil && r.attempted != nil {
		select {
		case r.attempted <- err:
		default:
		}
	}
	return err
}

type accountRoleTx struct {
	iamstore.WriteTx
	wrote *bool
}

func (tx accountRoleTx) PutRole(scope iamstore.Scope, role iamstore.Role) error {
	*tx.wrote = true
	return tx.WriteTx.PutRole(scope, role)
}

type accountCreationStorage struct {
	orgstore.Storage
	fail      atomic.Bool
	attempted chan error
}

func (s *accountCreationStorage) CompareAndSwap(ctx context.Context, partition string, revision uint64, record orgstore.PartitionRecord, commit func(context.Context) error) (bool, error) {
	if s.fail.Load() {
		err := errors.New("injected Organizations publication failure")
		if s.attempted != nil {
			select {
			case s.attempted <- err:
			default:
			}
		}
		return false, err
	}
	return s.Storage.CompareAndSwap(ctx, partition, revision, record, commit)
}

func TestOrganizationAccountAndRoleRollbackTogetherSDK(t *testing.T) {
	for _, mode := range []string{"IAM commit", "IAM cancellation", "Organizations commit"} {
		t.Run(mode, func(t *testing.T) {
			backends := storage.NewMemory()
			attempted := make(chan error, 1)
			repository := &accountRoleRepository{Repository: backends.IAM, attempted: attempted}
			orgs := &accountCreationStorage{Storage: backends.Organizations, attempted: attempted}
			backends.IAM, backends.Organizations = repository, orgs
			f := newOrganizationReportFixture(t, backends)
			in := &organizations.CreateAccountInput{AccountName: aws.String("rollback"), Email: aws.String("rollback@example.test")}
			created, err := f.org.CreateAccount(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "IAM commit":
				repository.mode.Store(1)
			case "IAM cancellation":
				repository.mode.Store(2)
			case "Organizations commit":
				orgs.fail.Store(true)
			}
			advanceClock(t, f.clock, time.Second)
			select {
			case <-attempted:
			case <-time.After(5 * time.Second):
				t.Fatal("provisioning did not reach injected failure")
			}

			accounts, err := f.org.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
			if err != nil || len(accounts.Accounts) != 1 {
				t.Fatalf("failed publication retained member: %+v, %v", accounts, err)
			}
			statuses, err := f.org.ListCreateAccountStatus(t.Context(), &organizations.ListCreateAccountStatusInput{})
			if err != nil || len(statuses.CreateAccountStatuses) != 1 || statuses.CreateAccountStatuses[0].State != orgtypes.CreateAccountStateInProgress {
				t.Fatalf("failed publication retained status: %+v, %v", statuses, err)
			}
			// Read the typed repository so checking the absent account does not
			// itself initialize that account through an IAM API request.
			if err := backends.IAM.View(t.Context(), func(tx iamstore.ReadTx) error {
				roles, err := tx.Roles(iamstore.Scope{Partition: "aws", AccountID: "100000000001"})
				if err == nil && len(roles) != 0 {
					t.Fatalf("failed publication retained IAM roles: %+v", roles)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			repository.mode.Store(0)
			orgs.fail.Store(false)
			status := waitAccountCreation(t, f.org, created.CreateAccountStatus, f.clock)
			if status.State != orgtypes.CreateAccountStateSucceeded || aws.ToString(status.AccountId) != "100000000001" {
				t.Fatalf("retry did not recover account allocation: %+v", status)
			}

			if _, err := f.cloud.iam("100000000001", "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("OrganizationAccountAccessRole")}); err != nil {
				t.Fatal("retry did not provision access role", err)
			}
		})
	}
}

func TestConcurrentOrganizationAccountCreationPublishesOneAccessRoleSDK(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	const count = 8
	var wg sync.WaitGroup
	results := make(chan *organizations.CreateAccountOutput, count)
	for range count {
		wg.Go(func() {
			out, err := f.org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("concurrent"), Email: aws.String("concurrent@example.test")})
			if err != nil {
				assertAPIError(t, err, "ConcurrentModificationException")
				return
			}
			results <- out
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for result := range results {
		status := waitAccountCreation(t, f.org, result.CreateAccountStatus, f.clock)
		if status.State == orgtypes.CreateAccountStateSucceeded {
			successes++
			roles, err := f.cloud.iam(*status.AccountId, "test", "").ListRoles(t.Context(), &iam.ListRolesInput{})
			if err != nil || len(roles.Roles) != 2 || aws.ToString(roles.Roles[1].RoleName) != "OrganizationAccountAccessRole" {
				t.Fatalf("provisioned roles: %+v, %v", roles, err)
			}
		} else if status.State != orgtypes.CreateAccountStateFailed || status.FailureReason != orgtypes.CreateAccountFailureReasonEmailAlreadyExists {
			t.Errorf("unexpected concurrent creation result: %+v", status)
		}
	}
	if successes != 1 {
		t.Fatalf("successful account creations = %d", successes)
	}
}
