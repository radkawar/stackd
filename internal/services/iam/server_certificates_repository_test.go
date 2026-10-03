package iam_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"stackd/internal/services/iam"
)

func TestIAMCertificateRepositoryDetachmentAndRollback(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	ctx := context.Background()
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	failure := errors.New("rollback")
	err := repository.Update(ctx, func(tx iam.WriteTx) error {
		if err := tx.PutSigningCertificate(scope, iam.SigningCertificateRecord{ID: "signing", UserID: "user", DER: []byte{1, 2}}); err != nil {
			return err
		}
		if err := tx.PutSSHPublicKey(scope, iam.SSHPublicKeyRecord{ID: "ssh", UserID: "user", Wire: []byte{3, 4}}); err != nil {
			return err
		}
		return tx.PutServerCertificate(scope, iam.ServerCertificateRecord{ID: "server", Name: "Server", PrivateKey: []byte{5, 6}, Tags: []iam.Tag{{Key: "team", Value: "one"}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	var retained iam.ReadTx
	err = repository.View(ctx, func(tx iam.ReadTx) error {
		retained = tx
		s, e := tx.SigningCertificate(scope, "signing")
		if e != nil {
			return e
		}
		s.DER[0] = 8
		k, e := tx.SSHPublicKey(scope, "ssh")
		if e != nil {
			return e
		}
		k.Wire[0] = 8
		c, e := tx.ServerCertificate(scope, "SERVER")
		if e != nil {
			return e
		}
		c.PrivateKey[0] = 8
		c.Tags[0].Value = "mutated"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retained.SigningCertificate(scope, "signing"); !errors.Is(err, iam.ErrClosedTransaction) {
		t.Fatal("expired transaction allowed access")
	}
	err = repository.Update(ctx, func(tx iam.WriteTx) error {
		if err := tx.DeleteSigningCertificate(scope, "signing"); err != nil {
			return err
		}
		if err := tx.DeleteSSHPublicKey(scope, "ssh"); err != nil {
			return err
		}
		if err := tx.DeleteServerCertificate(scope, "server"); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	err = repository.View(ctx, func(tx iam.ReadTx) error {
		s, e := tx.SigningCertificate(scope, "signing")
		if e != nil {
			return e
		}
		k, e := tx.SSHPublicKey(scope, "ssh")
		if e != nil {
			return e
		}
		c, e := tx.ServerCertificate(scope, "server")
		if e != nil {
			return e
		}
		if !bytes.Equal(s.DER, []byte{1, 2}) || !bytes.Equal(k.Wire, []byte{3, 4}) || !bytes.Equal(c.PrivateKey, []byte{5, 6}) || c.Tags[0].Value != "one" {
			t.Fatal("detached records or rollback changed storage")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIAMCertificateUploadRepositoryFailure(t *testing.T) {
	repository := &failingIAMRepository{Repository: iam.NewMemoryRepository(nil)}
	s := iam.NewWithRepository(nil, repository)
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	key := certificateTestECKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	for _, canceled := range []bool{false, true} {
		repository.fail, repository.cancel = !canceled, canceled
		_, err := root.UploadServerCertificate(ctx, &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String("atomic"), CertificateBody: aws.String(body), PrivateKey: aws.String(certificateTestPrivate(t, key))})
		requireCode(t, err, "ServiceFailure")
		repository.fail, repository.cancel = false, false
		out, err := root.ListServerCertificates(ctx, &sdkiam.ListServerCertificatesInput{})
		if err != nil || len(out.ServerCertificateMetadataList) != 0 {
			t.Fatal("failed/canceled transaction committed private material")
		}
	}
}
