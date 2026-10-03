package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	elbapi "stackd/internal/awsapi/elbv2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/elbv2"
	"stackd/internal/services/iam"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	elbdb "stackd/storage/sqlite/elbv2"
	iamdb "stackd/storage/sqlite/iam"
	journaldb "stackd/storage/sqlite/journal"
)

func certificateUsageContext(ctx context.Context, account, region string) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: "aws", AccountID: account, Region: region, PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account})
}

func certificateUsageIAMCall(t *testing.T, service *iam.Service, ctx context.Context, action string, q url.Values) (any, *awswire.Error) {
	t.Helper()
	request, err := iamapi.DecodeRequest(action, awsapi.Request{Query: q})
	if err != nil {
		t.Fatal(err)
	}
	return service.ExecuteCommand(ctx, request)
}

func TestELBV2CertificateDeleteNativeDependency(t *testing.T) {
	data, err := os.ReadFile("../../testdata/aws/elbv2/alb_native_success.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Service, Action, Stderr string
			ExitCode                int
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var nativeConflict string
	var nativeReleased bool
	for _, observation := range fixture.Cases {
		if observation.Service != "iam" || observation.Action != "delete-server-certificate" {
			continue
		}
		if observation.ExitCode == 0 {
			nativeReleased = true
		} else if match := regexp.MustCompile(`\(([^)]*)\) when calling the DeleteServerCertificate`).FindStringSubmatch(observation.Stderr); len(match) == 2 {
			nativeConflict = match[1]
		}
	}
	if nativeConflict == "" || !nativeReleased {
		t.Fatal("native fixture lacks both bound and released certificate outcomes")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var ir iam.Repository
			var er elbv2.Repository
			var events journal.Storage
			if backend == "memory" {
				domain := memory.NewDomain()
				ir, er, events = iam.NewMemoryRepository(domain), elbv2.NewMemoryRepository(domain), journal.NewMemory(domain)
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "certificate.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				})
				ir, er, events = iamdb.New(db), elbdb.New(db), journaldb.New(db)
			}
			ctx := certificateUsageContext(t.Context(), "123456789012", "us-west-2")
			account := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			certificateARN := "arn:aws:iam::123456789012:server-certificate/bound"
			foreignARN := "arn:aws:iam::987654321098:server-certificate/bound"
			if err := ir.Update(ctx, func(tx iam.WriteTx) error {
				if err := tx.PutServerCertificate(account, iam.ServerCertificateRecord{ID: "ASCAOWNED", Name: "bound", Path: "/", ARN: certificateARN}); err != nil {
					return err
				}
				return tx.PutServerCertificate(iam.Scope{Partition: "aws", AccountID: "987654321098"}, iam.ServerCertificateRecord{ID: "ASCAFOREIGN", Name: "bound", Path: "/", ARN: foreignARN})
			}); err != nil {
				t.Fatal(err)
			}
			var bindings []elbv2.ListenerRecord
			for _, location := range []struct{ account, region, certificate, id string }{{account.AccountID, "eu-west-1", certificateARN, "ASCAOWNED"}, {account.AccountID, "ap-south-1", certificateARN, "ASCAOWNED"}, {"987654321098", "eu-west-1", foreignARN, "ASCAFOREIGN"}} {
				prefix := "arn:aws:elasticloadbalancing:" + location.region + ":" + location.account + ":"
				bindings = append(bindings, elbv2.ListenerRecord{Scope: elbv2.Scope{Partition: "aws", AccountID: location.account, Region: location.region}, CertificateID: location.id, Data: elbapi.Listener{ListenerArn: new(elbapi.ListenerArn(prefix + "listener/app/fixture/one/listener")), LoadBalancerArn: new(elbapi.LoadBalancerArn(prefix + "loadbalancer/app/fixture/one")), Protocol: new(elbapi.ProtocolEnumHTTPS), Certificates: elbapi.CertificateList{{CertificateArn: new(elbapi.CertificateArn(location.certificate))}}}})
			}
			if err := er.Update(ctx, func(tx elbv2.Transaction) error {
				for _, binding := range bindings {
					if err := tx.PutLoadBalancer(elbv2.LoadBalancerRecord{Scope: binding.Scope, Data: elbapi.LoadBalancer{LoadBalancerArn: binding.Data.LoadBalancerArn}, Version: 1}); err != nil {
						return err
					}
					if err := tx.PutListener(binding); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			is := iam.NewWithConfig(iam.Config{Repository: ir, APICallEvents: apievents.New(events)})
			es := elbv2.New(elbv2.Config{Repository: er})
			t.Cleanup(func() {
				if err := es.Close(); err != nil {
					t.Error(err)
				}
			})
			is.SetServerCertificateUsage(ELBV2CertificateUsage{ELBV2: es})
			deleteCertificate := func(ctx context.Context, expected string) {
				t.Helper()
				_, got := certificateUsageIAMCall(t, is, ctx, "DeleteServerCertificate", url.Values{"ServerCertificateName": {"bound"}})
				code := ""
				if got != nil {
					code = got.Code
				}
				if code != expected {
					t.Fatalf("certificate deletion: got %v, expected %s", got, expected)
				}
			}
			deleteCertificate(ctx, nativeConflict)
			created, apiErr := certificateUsageIAMCall(t, is, ctx, "CreateUser", url.Values{"UserName": {"certificate-manager"}})
			if apiErr != nil {
				t.Fatal(apiErr)
			}
			user := created.(*iamapi.CreateUserOutput).User
			metadata := awsctx.FromContext(ctx)
			metadata.PrincipalARN, metadata.PrincipalID = string(*user.Arn), string(*user.UserId)
			userContext := awsctx.WithMetadata(ctx, metadata)
			setPolicy := func(effect string) {
				t.Helper()
				_, err := certificateUsageIAMCall(t, is, ctx, "PutUserPolicy", url.Values{"UserName": {"certificate-manager"}, "PolicyName": {"certificate-delete"}, "PolicyDocument": {`{"Statement":{"Effect":"` + effect + `","Action":"iam:DeleteServerCertificate","Resource":"` + certificateARN + `"}}`}})
				if err != nil {
					t.Fatal(err)
				}
			}
			setPolicy("Allow")
			deleteCertificate(userContext, nativeConflict)
			setPolicy("Deny")
			deleteCertificate(userContext, "AccessDenied")
			deleteListener := func(binding elbv2.ListenerRecord) {
				t.Helper()
				request, err := elbapi.DecodeRequest("DeleteListener", awsapi.Request{Query: url.Values{"ListenerArn": {string(*binding.Data.ListenerArn)}}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := es.ExecuteCommand(certificateUsageContext(ctx, binding.AccountID, binding.Region), request); err != nil {
					t.Fatal(err)
				}
			}
			deleteListener(bindings[0])
			deleteCertificate(ctx, nativeConflict)
			deleteListener(bindings[1])
			deleteCertificate(ctx, "")
			if err := ir.View(ctx, func(tx iam.ReadTx) error {
				if _, err := tx.ServerCertificate(account, "bound"); !errors.Is(err, iam.ErrRecordNotFound) {
					t.Fatalf("released certificate remains: %v", err)
				}
				_, err := tx.ServerCertificate(iam.Scope{Partition: "aws", AccountID: "987654321098"}, "bound")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := er.View(ctx, func(tx elbv2.Reader) error {
				_, err := tx.Listener(bindings[2].Scope, string(*bindings[2].Data.ListenerArn))
				return err
			}); err != nil {
				t.Fatalf("other account dependency changed: %v", err)
			}
			recorded, err := events.Read(ctx, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			var outcomes []string
			for _, event := range recorded {
				if event.APICallCompleted != nil && event.APICallCompleted.EventName == "DeleteServerCertificate" {
					outcomes = append(outcomes, event.APICallCompleted.ErrorCode)
				}
			}
			if expected := []string{"DeleteConflictException", "DeleteConflictException", "AccessDenied", "DeleteConflictException", ""}; !reflect.DeepEqual(outcomes, expected) {
				t.Fatalf("rejected mutations lost audit or leaked success: got %v, want %v", outcomes, expected)
			}
		})
	}
}
