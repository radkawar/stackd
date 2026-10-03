package integrations

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"stackd/internal/awsapi"
	elbapi "stackd/internal/awsapi/elbv2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/services/elbv2"
	"stackd/internal/services/iam"
	"stackd/storage/sqlite"
	elbdb "stackd/storage/sqlite/elbv2"
	iamdb "stackd/storage/sqlite/iam"
)

func certificateUsageMaterial(t *testing.T, serial int64) (string, string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "certificate.stackd.test"}, DNSNames: []string{"certificate.stackd.test"}, NotBefore: time.Unix(0, 0), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), der
}

func TestELBV2CertificateRenameRetainsDeploymentIdentity(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/aws/elbv2/alb_native_tls_identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		Cases []struct {
			Action string
			Output json.RawMessage
		}
	}
	if err := json.Unmarshal(fixture, &native); err != nil {
		t.Fatal(err)
	}
	var uploaded iamapi.UploadServerCertificateOutput
	var renamed iamapi.GetServerCertificateOutput
	var described elbapi.DescribeListenersOutput
	for _, row := range native.Cases {
		var target any
		switch row.Action {
		case "upload-server-certificate":
			target = &uploaded
		case "get-server-certificate":
			target = &renamed
		case "describe-listeners":
			target = &described
		}
		if target != nil {
			if err := json.Unmarshal(row.Output, target); err != nil {
				t.Fatal(err)
			}
		}
	}
	if uploaded.ServerCertificateMetadata == nil || renamed.ServerCertificate == nil || len(described.Listeners) != 1 {
		t.Fatal("native fixture lacks rename deployment observations")
	}
	oldNative := uploaded.ServerCertificateMetadata
	newNative := renamed.ServerCertificate.ServerCertificateMetadata
	if string(*oldNative.ServerCertificateId) != string(*newNative.ServerCertificateId) || string(*oldNative.Arn) == string(*newNative.Arn) || string(*described.Listeners[0].Certificates[0].CertificateArn) != string(*oldNative.Arn) {
		t.Fatal("native deployment identity relation changed")
	}

	ctx := certificateUsageContext(t.Context(), "123456789012", "us-east-1")
	path := filepath.Join(t.TempDir(), "identity.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ir, er := iamdb.New(db), elbdb.New(db)
	is := iam.NewWithConfig(iam.Config{Repository: ir})
	source := ELBV2Certificates{IAM: is}
	es := elbv2.New(elbv2.Config{Repository: er, Certificates: source})
	t.Cleanup(func() { _ = es.Close() })
	is.SetServerCertificateUsage(ELBV2CertificateUsage{ELBV2: es})
	iamCall := func(action string, input url.Values) any {
		t.Helper()
		out, err := certificateUsageIAMCall(t, is, ctx, action, input)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	elbCall := func(action string, input url.Values) any {
		t.Helper()
		request, err := elbapi.DecodeRequest(action, awsapi.Request{Query: input})
		if err != nil {
			t.Fatal(err)
		}
		out, failure := es.ExecuteCommand(ctx, request)
		if failure != nil {
			t.Fatal(failure)
		}
		return out
	}
	body, private, originalDER := certificateUsageMaterial(t, 1)
	created := iamCall("UploadServerCertificate", url.Values{"ServerCertificateName": {"bound"}, "CertificateBody": {body}, "PrivateKey": {private}}).(*iamapi.UploadServerCertificateOutput).ServerCertificateMetadata
	certificateARN, certificateID := string(*created.Arn), string(*created.ServerCertificateId)
	scope := elbv2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	lbARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/fixture/one"
	if err := er.Update(ctx, func(tx elbv2.Transaction) error {
		return tx.PutLoadBalancer(elbv2.LoadBalancerRecord{Scope: scope, Data: elbapi.LoadBalancer{LoadBalancerArn: new(elbapi.LoadBalancerArn(lbARN))}, Version: 1})
	}); err != nil {
		t.Fatal(err)
	}
	listener := elbCall("CreateListener", url.Values{"LoadBalancerArn": {lbARN}, "Port": {"443"}, "Protocol": {"HTTPS"}, "SslPolicy": {"ELBSecurityPolicy-TLS13-1-2-Res-2021-06"}, "Certificates.member.1.CertificateArn": {certificateARN}, "DefaultActions.member.1.Type": {"fixed-response"}, "DefaultActions.member.1.FixedResponseConfig.StatusCode": {"200"}}).(*elbapi.CreateListenerOutput).Listeners[0]
	listenerARN := string(*listener.ListenerArn)
	iamCall("UpdateServerCertificate", url.Values{"ServerCertificateName": {"bound"}, "NewServerCertificateName": {"renamed"}, "NewPath": {"/renamed/"}})
	if _, err := source.CertificateID(ctx, scope, certificateARN); !errors.Is(err, iam.ErrInvalidServerCertificate) {
		t.Fatalf("renamed ARN remained available for new admission: %v", err)
	}
	retained := elbCall("ModifyListener", url.Values{"ListenerArn": {listenerARN}, "Port": {"8443"}}).(*elbapi.ModifyListenerOutput).Listeners[0]
	if string(*retained.Certificates[0].CertificateArn) != certificateARN {
		t.Fatal("unrelated mutation rewrote native-observed certificate ARN")
	}
	if _, err := certificateUsageIAMCall(t, is, ctx, "DeleteServerCertificate", url.Values{"ServerCertificateName": {"renamed"}}); err == nil || err.Code != "DeleteConflict" {
		t.Fatalf("renamed bound certificate deleted: %v", err)
	}
	body, private, replacementDER := certificateUsageMaterial(t, 2)
	replacement := iamCall("UploadServerCertificate", url.Values{"ServerCertificateName": {"bound"}, "CertificateBody": {body}, "PrivateKey": {private}}).(*iamapi.UploadServerCertificateOutput).ServerCertificateMetadata
	if string(*replacement.Arn) != certificateARN || string(*replacement.ServerCertificateId) == certificateID {
		t.Fatal("replacement did not receive its own immutable identity")
	}
	if err := es.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	ir, er = iamdb.New(db), elbdb.New(db)
	is = iam.NewWithConfig(iam.Config{Repository: ir})
	source = ELBV2Certificates{IAM: is}
	es = elbv2.New(elbv2.Config{Repository: er, Certificates: source})
	is.SetServerCertificateUsage(ELBV2CertificateUsage{ELBV2: es})
	pair, err := source.Certificate(ctx, scope, certificateARN, certificateID)
	if err != nil || !bytes.Equal(pair.Certificate[0], originalDER) {
		t.Fatalf("restarted deployment adopted replacement at old ARN: %v", err)
	}
	if err := er.View(ctx, func(tx elbv2.Reader) error {
		binding, err := tx.Listener(scope, listenerARN)
		if err != nil {
			return err
		}
		if binding.CertificateID != certificateID {
			t.Fatal("restart lost immutable listener binding")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := certificateUsageIAMCall(t, is, ctx, "DeleteServerCertificate", url.Values{"ServerCertificateName": {"renamed"}}); err == nil || err.Code != "DeleteConflict" {
		t.Fatalf("restart released live certificate dependency: %v", err)
	}
	elbCall("ModifyListener", url.Values{"ListenerArn": {listenerARN}, "Certificates.member.1.CertificateArn": {certificateARN}})
	iamCall("DeleteServerCertificate", url.Values{"ServerCertificateName": {"renamed"}})
	if _, err := certificateUsageIAMCall(t, is, ctx, "DeleteServerCertificate", url.Values{"ServerCertificateName": {"bound"}}); err == nil || err.Code != "DeleteConflict" {
		t.Fatalf("explicit replacement did not acquire deletion dependency: %v", err)
	}
	pair, err = source.Certificate(ctx, scope, certificateARN, string(*replacement.ServerCertificateId))
	if err != nil || !bytes.Equal(pair.Certificate[0], replacementDER) {
		t.Fatalf("explicit replacement did not change TLS material: %v", err)
	}
	elbCall("DeleteListener", url.Values{"ListenerArn": {listenerARN}})
	iamCall("DeleteServerCertificate", url.Values{"ServerCertificateName": {"bound"}})
}
