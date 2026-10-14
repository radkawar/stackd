package stackd_test

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/storage"
	"stackd/storage/sqlite"
	sqlbackends "stackd/storage/sqlite/backends"
)

func reservedOrganizationAccount(t *testing.T, backends *storage.Backends, requestID string) string {
	t.Helper()
	record, _, err := backends.Organizations.Load(t.Context(), "aws")
	if err != nil {
		t.Fatal(err)
	}
	for _, organization := range record.Organizations {
		for _, job := range organization.Creations {
			if job.ID == requestID {
				return job.AccountID
			}
		}
	}
	t.Fatalf("missing account reservation %s", requestID)
	return ""
}

func organizationAccountSequence(t *testing.T, backends *storage.Backends) uint64 {
	t.Helper()
	record, _, err := backends.Organizations.Load(t.Context(), "aws")
	if err != nil {
		t.Fatal(err)
	}
	return record.AccountSequence
}

func TestDefaultAccountIdentitySDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, explicit := range []string{"", "820493716052", "000000000000"} {
			t.Run(backend+"/override="+explicit, func(t *testing.T) {
				backends := storage.NewMemory()
				var db *sql.DB
				var cloud *stackd.Stack
				var server *httptest.Server
				path := filepath.Join(t.TempDir(), "identity.sqlite")
				source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
				closeState := func() {
					if server != nil {
						server.Close()
					}
					if cloud != nil {
						if err := cloud.Close(); err != nil {
							t.Error(err)
						}
					}
					if db != nil {
						if err := db.Close(); err != nil {
							t.Error(err)
						}
					}
					server, cloud, db = nil, nil, nil
				}
				t.Cleanup(closeState)
				start := func(account string) cloudClients {
					t.Helper()
					var err error
					if backend == "sqlite" {
						db, err = sqlite.Open(t.Context(), path)
						if err != nil {
							t.Fatal(err)
						}
						backends, err = sqlbackends.New(t.Context(), db)
						if err != nil {
							t.Fatal(err)
						}
					}
					cloud, err = stackd.New(stackd.Config{AccountID: account, Storage: backends, Clock: source})
					if err != nil {
						t.Fatal(err)
					}
					server = httptest.NewServer(cloud)
					return cloudClients{server}
				}
				want := explicit
				assertCaller := func(c cloudClients, key, account string) {
					t.Helper()
					out, err := c.sts(key, "test", "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
					if err != nil || aws.ToString(out.Account) != account || aws.ToString(out.UserId) != account || aws.ToString(out.Arn) != "arn:aws:iam::"+account+":root" {
						t.Fatalf("caller = %+v, %v; want account %s", out, err, account)
					}
				}
				c := start(explicit)
				if want == "" {
					caller, err := c.sts("test", "test", "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
					if err != nil {
						t.Fatal(err)
					}
					want = aws.ToString(caller.Account)
					if _, err := strconv.ParseUint(want, 10, 64); err != nil || len(want) != 12 || strings.HasPrefix(want, "0") {
						t.Fatalf("fresh account is not a generated 12-digit ID: %q", want)
					}
				}
				assertCaller(c, "test", want)
				assertCaller(c, "609274183506", "609274183506")
				if _, err := c.iam("test", "test", "").CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("retained-owner")}); err != nil {
					t.Fatal(err)
				}
				other, err := c.iam("609274183506", "test", "").ListUsers(t.Context(), &iam.ListUsersInput{})
				if err != nil || len(other.Users) != 0 {
					t.Fatalf("account isolation: %+v, %v", other, err)
				}
				org := c.organizations("test", "test")
				createdOrg, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
				if err != nil || aws.ToString(createdOrg.Organization.MasterAccountId) != want {
					t.Fatalf("management identity: %+v, %v", createdOrg, err)
				}
				created, err := org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("first"), Email: aws.String("first@example.test")})
				if err != nil {
					t.Fatal(err)
				}
				reserved := reservedOrganizationAccount(t, backends, aws.ToString(created.CreateAccountStatus.Id))
				closeState()
				c = start("")
				assertCaller(c, "test", want)
				org = c.organizations("test", "test")
				first := waitAccountCreation(t, org, created.CreateAccountStatus, source)
				if aws.ToString(first.AccountId) != reserved || string(first.State) != "SUCCEEDED" {
					t.Fatalf("recovered reservation: %+v; want %s", first, reserved)
				}
				second, err := org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("second"), Email: aws.String("second@example.test")})
				if err != nil {
					t.Fatal(err)
				}
				finished := waitAccountCreation(t, org, second.CreateAccountStatus, source)
				id := aws.ToString(finished.AccountId)
				a, errA := strconv.ParseInt(reserved, 10, 64)
				b, errB := strconv.ParseInt(id, 10, 64)
				if string(finished.State) != "SUCCEEDED" || errA != nil || errB != nil || len(reserved) != 12 || len(id) != 12 || strings.HasPrefix(reserved, "0") || strings.HasPrefix(id, "0") || id == want || reserved == want || a == b || a == b+1 || a == b-1 {
					t.Fatalf("allocated accounts are not distinct opaque 12-digit IDs: %q, %q", reserved, id)
				}
				assertCaller(c, reserved, reserved)
				if _, err := c.iam(reserved, "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("OrganizationAccountAccessRole")}); err != nil {
					t.Fatal("account lacks provisioned access role", err)
				}
				if _, err := c.iam("test", "test", "").GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("retained-owner")}); err != nil {
					t.Fatal("restart lost original account resources", err)
				}
			})
		}
	}
}

func TestCustomStorageRequiresAccountSelection(t *testing.T) {
	backends := storage.NewMemory()
	backends.ResolveAccountID = nil
	if cloud, err := stackd.New(stackd.Config{Storage: backends}); err == nil {
		_ = cloud.Close()
		t.Fatal("custom storage silently selected an unretained account")
	}
	const account = "820493716052"
	cloud, err := stackd.New(stackd.Config{AccountID: account, Storage: backends})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cloud.Close() })
	server := httptest.NewServer(cloud)
	t.Cleanup(server.Close)
	caller, err := (cloudClients{server}).sts("test", "test", "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(caller.Account) != account || aws.ToString(caller.Arn) != "arn:aws:iam::"+account+":root" {
		t.Fatalf("explicit custom storage identity = %+v, %v", caller, err)
	}
}
