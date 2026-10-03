package iam_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	"golang.org/x/crypto/ssh"
	"stackd/internal/services/iam"
)

func TestIAMCertificateAWSObservationReplay(t *testing.T) {
	data, err := os.ReadFile("testdata/certificates_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		CleanupVerified bool `json:"cleanup_verified"`
		Observations    []struct {
			Case, Code string
			IDLength   int `json:"id_length"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.CleanupVerified {
		t.Fatal("unverified AWS cleanup")
	}
	codes := map[string]string{}
	lengths := map[string]int{}
	for _, row := range fixture.Observations {
		codes[row.Case] = row.Code
		lengths[row.Case] = row.IDLength
	}
	expect := func(name string, err error) {
		t.Helper()
		actual := "Success"
		if err != nil {
			var api smithy.APIError
			if !errors.As(err, &api) {
				t.Fatalf("%s transport failure: %v", name, err)
			}
			actual = api.ErrorCode()
		}
		if expected, ok := codes[name]; !ok || actual != expected {
			t.Fatalf("AWS %s: got %s, expected %s", name, actual, expected)
		}
	}
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	for _, name := range []string{"owner", "other"} {
		if _, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	key := certificateTestKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	private := certificateTestPrivate(t, key)
	expired, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	for _, row := range []struct{ name, body string }{{"signing:malformed", "bad certificate"}, {"signing:expired", expired}} {
		_, err := root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String("owner"), CertificateBody: aws.String(row.body)})
		expect(row.name, err)
	}
	created, err := root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String("owner"), CertificateBody: aws.String(body)})
	expect("signing:create", err)
	if len(aws.ToString(created.Certificate.CertificateId)) != lengths["signing:create"] {
		t.Fatal("signing ID length differs from AWS")
	}
	_, err = root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String("owner"), CertificateBody: aws.String(body)})
	expect("signing:duplicate", err)
	_, err = root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String("other"), CertificateBody: aws.String(body)})
	expect("signing:duplicate-other-user", err)
	_, err = root.DeleteSigningCertificate(ctx, &sdkiam.DeleteSigningCertificateInput{UserName: aws.String("other"), CertificateId: created.Certificate.CertificateId})
	expect("signing:wrong-owner", err)
	for _, status := range []types.StatusType{types.StatusTypeInactive, types.StatusTypeExpired, types.StatusTypeActive} {
		_, err := root.UpdateSigningCertificate(ctx, &sdkiam.UpdateSigningCertificateInput{UserName: aws.String("owner"), CertificateId: created.Certificate.CertificateId, Status: status})
		expect("signing:status-"+string(status), err)
	}
	_, err = root.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("owner")})
	expect("signing:user-delete-blocked", err)
	_, err = root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String("owner"), SSHPublicKeyBody: aws.String("not a key")})
	expect("ssh:malformed", err)
	_, err = root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String("owner"), SSHPublicKeyBody: aws.String(body)})
	expect("ssh:certificate", err)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallPublic, err := ssh.NewPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String("owner"), SSHPublicKeyBody: aws.String(string(ssh.MarshalAuthorizedKey(smallPublic)))})
	expect("ssh:rsa1024", err)
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sshBody := string(ssh.MarshalAuthorizedKey(pub))
	uploaded, err := root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String("owner"), SSHPublicKeyBody: aws.String(sshBody)})
	expect("ssh:create", err)
	if len(aws.ToString(uploaded.SSHPublicKey.SSHPublicKeyId)) != lengths["ssh:create"] {
		t.Fatal("SSH ID differs from AWS")
	}
	_, err = root.UploadSSHPublicKey(ctx, &sdkiam.UploadSSHPublicKeyInput{UserName: aws.String("other"), SSHPublicKeyBody: aws.String(sshBody)})
	expect("ssh:duplicate-other-user", err)
	for _, status := range []types.StatusType{types.StatusTypeInactive, types.StatusTypeExpired, types.StatusTypeActive} {
		_, err := root.UpdateSSHPublicKey(ctx, &sdkiam.UpdateSSHPublicKeyInput{UserName: aws.String("owner"), SSHPublicKeyId: uploaded.SSHPublicKey.SSHPublicKeyId, Status: status})
		expect("ssh:status-"+string(status), err)
	}
	for _, row := range []struct{ name, body, private, chain string }{{"malformed", "bad", private, ""}, {"expired", expired, private, ""}, {"mismatch", body, certificateTestPrivate(t, certificateTestECKey(t)), ""}, {"invalid-chain", body, private, "bad"}} {
		in := &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String(row.name), CertificateBody: aws.String(row.body), PrivateKey: aws.String(row.private)}
		if row.chain != "" {
			in.CertificateChain = aws.String(row.chain)
		}
		_, err := root.UploadServerCertificate(ctx, in)
		expect("server:"+row.name, err)
	}
	server, err := root.UploadServerCertificate(ctx, &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String("server"), CertificateBody: aws.String(body), PrivateKey: aws.String(private)})
	expect("server:create", err)
	if len(aws.ToString(server.ServerCertificateMetadata.ServerCertificateId)) != lengths["server:create"] {
		t.Fatal("server ID differs from AWS")
	}
	_, err = root.UploadServerCertificate(ctx, &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String("SERVER"), CertificateBody: aws.String(body), PrivateKey: aws.String(private)})
	expect("server:duplicate-name-case", err)
	_, err = root.TagServerCertificate(ctx, &sdkiam.TagServerCertificateInput{ServerCertificateName: aws.String("server"), Tags: []types.Tag{}})
	expect("server:empty-tags", err)
	_, err = root.UntagServerCertificate(ctx, &sdkiam.UntagServerCertificateInput{ServerCertificateName: aws.String("server"), TagKeys: []string{}})
	expect("server:empty-untag", err)
}

func TestIAMServerCertificateUpdateAWSReplay(t *testing.T) {
	data, err := os.ReadFile("testdata/server_certificate_transitions_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case, Code string
			Tags       []types.Tag
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	expectedTags := map[string][]types.Tag{}
	expectedCodes := map[string]string{}
	for _, r := range fixture.Observations {
		expectedTags[r.Case] = r.Tags
		expectedCodes[r.Case] = r.Code
	}
	for _, kind := range []string{"empty", "rename", "path"} {
		t.Run(kind, func(t *testing.T) {
			s := iam.New()
			root := clientFor(t, s, "123456789012", "us-east-1")
			ctx := context.Background()
			name := "server"
			key := certificateTestECKey(t)
			body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			_, err := root.UploadServerCertificate(ctx, &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String(name), Path: aws.String("/before/"), CertificateBody: aws.String(body), PrivateKey: aws.String(certificateTestPrivate(t, key)), Tags: expectedTags[kind+":before"]})
			if err != nil {
				t.Fatal(err)
			}
			update := &sdkiam.UpdateServerCertificateInput{ServerCertificateName: aws.String(name)}
			if kind == "rename" {
				name = "renamed"
				update.NewServerCertificateName = aws.String(name)
			}
			if kind == "path" {
				update.NewPath = aws.String("/after/")
			}
			if _, err := root.UpdateServerCertificate(ctx, update); err != nil {
				t.Fatal(err)
			}
			get, err := root.GetServerCertificate(ctx, &sdkiam.GetServerCertificateInput{ServerCertificateName: aws.String(name)})
			if err != nil {
				t.Fatal(err)
			}
			normalize := func(tags []types.Tag) map[string]string {
				out := map[string]string{}
				for _, tag := range tags {
					out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
				}
				return out
			}
			if !reflect.DeepEqual(normalize(get.ServerCertificate.Tags), normalize(expectedTags[kind+":immediate"])) {
				t.Fatal("tag visibility differs from AWS after update")
			}
			_, err = root.TagServerCertificate(ctx, &sdkiam.TagServerCertificateInput{ServerCertificateName: aws.String(name), Tags: []types.Tag{{Key: aws.String("Team"), Value: aws.String("retagged")}}})
			result := "Success"
			if err != nil {
				var api smithy.APIError
				if !errors.As(err, &api) {
					t.Fatal(err)
				}
				result = api.ErrorCode()
			}
			caseName := kind
			if kind == "rename" {
				caseName = "rename-new"
			}
			if result != expectedCodes[caseName+":retag-delayed"] {
				t.Fatalf("post-update tag write: got %s, want %s", result, expectedCodes[caseName+":retag-delayed"])
			}
		})
	}
}

func TestIAMSigningCertificateDuplicateAWSReadback(t *testing.T) {
	data, err := os.ReadFile("testdata/certificate_edges_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case           string
			Status         string
			ListedStatus   string `json:"listed_status"`
			SameID         bool   `json:"same_id"`
			SameUploadDate bool   `json:"same_upload_date"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Observations {
		if row.Case != "signing:duplicate-inactive" {
			continue
		}
		s := iam.New()
		root := clientFor(t, s, "123456789012", "us-east-1")
		ctx := context.Background()
		if _, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("owner")}); err != nil {
			t.Fatal(err)
		}
		key := certificateTestECKey(t)
		body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		input := &sdkiam.UploadSigningCertificateInput{UserName: aws.String("owner"), CertificateBody: aws.String(body)}
		first, err := root.UploadSigningCertificate(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		_, err = root.UpdateSigningCertificate(ctx, &sdkiam.UpdateSigningCertificateInput{UserName: input.UserName, CertificateId: first.Certificate.CertificateId, Status: types.StatusTypeInactive})
		if err != nil {
			t.Fatal(err)
		}
		duplicate, err := root.UploadSigningCertificate(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		listed, err := root.ListSigningCertificates(ctx, &sdkiam.ListSigningCertificatesInput{UserName: input.UserName})
		if err != nil {
			t.Fatal(err)
		}
		if string(duplicate.Certificate.Status) != row.Status || string(listed.Certificates[0].Status) != row.ListedStatus || (aws.ToString(first.Certificate.CertificateId) == aws.ToString(duplicate.Certificate.CertificateId)) != row.SameID || first.Certificate.UploadDate.Equal(*duplicate.Certificate.UploadDate) != row.SameUploadDate {
			t.Fatal("duplicate response/state differs from observed AWS")
		}
		return
	}
	t.Fatal("missing AWS duplicate observation")
}
