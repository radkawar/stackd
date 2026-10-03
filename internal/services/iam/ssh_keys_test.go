package iam_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"golang.org/x/crypto/ssh"
	"stackd/internal/services/iam"
)

func TestIAMSSHKeysLifecycle(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	name := "ssh-owner"
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String(name)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("other")})
	if err != nil {
		t.Fatal(err)
	}
	key := certificateTestKey(t)
	public, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))) + " original-comment"
	created, err := root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyBody: aws.String(body)})
	if err != nil {
		t.Fatal(err)
	}
	id := created.SSHPublicKey.SSHPublicKeyId
	if len(aws.ToString(id)) != 20 || aws.ToString(created.SSHPublicKey.SSHPublicKeyBody) != body || aws.ToString(created.SSHPublicKey.Fingerprint) != strings.TrimPrefix(ssh.FingerprintLegacyMD5(public), "MD5:") {
		t.Fatal("incorrect SSH wire metadata")
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBody := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	_, err = root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyBody: aws.String(pemBody)})
	requireCode(t, err, "DuplicateSSHPublicKey")
	if _, err := root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String("other"), SSHPublicKeyBody: aws.String(body)}); err != nil {
		t.Fatal("different users can upload the same SSH key", err)
	}
	for _, encoding := range []types.EncodingType{types.EncodingTypeSsh, types.EncodingTypePem} {
		out, err := root.GetSSHPublicKey(ctx, &sdkiam.GetSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyId: id, Encoding: encoding})
		if err != nil {
			t.Fatal(err)
		}
		expected := pemBody
		if encoding == types.EncodingTypeSsh {
			expected = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
		}
		if aws.ToString(out.SSHPublicKey.SSHPublicKeyBody) != expected {
			t.Fatalf("wrong %s representation", encoding)
		}
	}
	_, err = root.GetSSHPublicKey(ctx, &sdkiam.GetSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyId: id, Encoding: "ssh"})
	requireCode(t, err, "ValidationError")
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("SSH authentication transcript")
	signature, err := signer.Sign(rand.Reader, message)
	if err != nil {
		t.Fatal(err)
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	verify := func(valid bool) {
		t.Helper()
		p, e := s.VerifySSHPublicKey(ctx, scope, aws.ToString(id), message, ssh.Marshal(signature))
		if valid && (e != nil || p.ID != aws.ToString(u.User.UserId)) {
			t.Fatalf("SSH signature rejected: %v", e)
		}
		if !valid && !errors.Is(e, iam.ErrInvalidSSHPublicKey) {
			t.Fatalf("inactive key accepted: %v", e)
		}
	}
	verify(true)
	if _, err := s.VerifySSHPublicKey(ctx, scope, aws.ToString(id), []byte("tampered"), ssh.Marshal(signature)); !errors.Is(err, iam.ErrInvalidSSHPublicKey) {
		t.Fatal("tampering accepted")
	}
	_, err = root.UpdateSSHPublicKey(ctx, &sdkiam.UpdateSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyId: id, Status: types.StatusTypeInactive})
	if err != nil {
		t.Fatal(err)
	}
	verify(false)
	_, err = root.UpdateSSHPublicKey(ctx, &sdkiam.UpdateSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyId: id, Status: types.StatusTypeExpired})
	requireCode(t, err, "InvalidInput")
	_, err = root.UpdateSSHPublicKey(ctx, &sdkiam.UpdateSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyId: id, Status: types.StatusTypeActive})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: aws.String(name), NewUserName: aws.String("renamed-ssh"), NewPath: aws.String("/new/")})
	if err != nil {
		t.Fatal(err)
	}
	name = "renamed-ssh"
	verify(true)
	listed, err := root.ListSSHPublicKeys(ctx, &sdkiam.ListSSHPublicKeysInput{UserName: aws.String(name)})
	if err != nil || len(listed.SSHPublicKeys) != 1 || aws.ToString(listed.SSHPublicKeys[0].UserName) != name {
		t.Fatalf("renamed SSH listing: %+v %v", listed, err)
	}
	_, err = root.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String(name)})
	requireCode(t, err, "DeleteConflict")
	_, err = root.DeleteSSHPublicKey(ctx, &sdkiam.DeleteSSHPublicKeyInput{UserName: aws.String("other"), SSHPublicKeyId: id})
	requireCode(t, err, "NoSuchEntity")
	_, err = root.DeleteSSHPublicKey(ctx, &sdkiam.DeleteSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyId: id})
	if err != nil {
		t.Fatal(err)
	}
	verify(false)
}

func TestIAMSSHKeysValidationQuotaPagination(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	name := "ssh-quota"
	if _, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String(name)}); err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallPublic, err := ssh.NewPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPublic, err := ssh.NewPublicKey(certificateTestECKey(t).Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ body, code string }{{"not a key", "UnrecognizedPublicKeyEncoding"}, {"ssh-rsa broken", "InvalidPublicKey"}, {string(ssh.MarshalAuthorizedKey(smallPublic)), "InvalidPublicKey"}, {string(ssh.MarshalAuthorizedKey(ecPublic)), "InvalidPublicKey"}} {
		_, err := root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyBody: aws.String(test.body)})
		requireCode(t, err, test.code)
	}
	for i := 0; i < 6; i++ {
		key := certificateTestKey(t)
		pub, e := ssh.NewPublicKey(&key.PublicKey)
		if e != nil {
			t.Fatal(e)
		}
		_, e = root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String(name), SSHPublicKeyBody: aws.String(string(ssh.MarshalAuthorizedKey(pub)))})
		if i == 5 {
			requireCode(t, e, "LimitExceeded")
		} else if e != nil {
			t.Fatal(e)
		}
	}
	page, err := root.ListSSHPublicKeys(ctx, &sdkiam.ListSSHPublicKeysInput{UserName: aws.String(name), MaxItems: aws.Int32(2)})
	if err != nil || len(page.SSHPublicKeys) != 2 || !page.IsTruncated {
		t.Fatalf("SSH page: %+v %v", page, err)
	}
	next, err := root.ListSSHPublicKeys(ctx, &sdkiam.ListSSHPublicKeysInput{UserName: aws.String(name), MaxItems: aws.Int32(3), Marker: page.Marker})
	if err != nil || len(next.SSHPublicKeys) != 3 || next.IsTruncated {
		t.Fatalf("SSH next page: %+v %v", next, err)
	}
}
