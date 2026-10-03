package iam

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func parseIAMSSHKey(body string) (ssh.PublicKey, *awswire.Error) {
	var key ssh.PublicKey
	var err error
	if strings.HasPrefix(strings.TrimSpace(body), "ssh-") || strings.HasPrefix(strings.TrimSpace(body), "ecdsa-") {
		var rest []byte
		var options []string
		key, _, options, rest, err = ssh.ParseAuthorizedKey([]byte(body))
		if err != nil || len(bytes.TrimSpace(rest)) != 0 || len(options) != 0 {
			return nil, certificateError("InvalidPublicKey", "The SSH public key is invalid.")
		}
	} else {
		block, rest := pem.Decode([]byte(body))
		if block == nil || (block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY") || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, certificateError("UnrecognizedPublicKeyEncoding", "The public key encoding is not recognized.")
		}
		var public any
		if block.Type == "PUBLIC KEY" {
			public, err = x509.ParsePKIXPublicKey(block.Bytes)
		} else {
			public, err = x509.ParsePKCS1PublicKey(block.Bytes)
		}
		if err == nil {
			key, err = ssh.NewPublicKey(public)
		}
		if err != nil {
			return nil, certificateError("InvalidPublicKey", "The public key is invalid.")
		}
	}
	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return nil, certificateError("InvalidPublicKey", "Only RSA SSH keys are supported.")
	}
	rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
	if !ok || rsaKey.N.BitLen() < 2048 || rsaKey.N.BitLen() > 16384 || rsaKey.E < 3 || rsaKey.E%2 == 0 {
		return nil, certificateError("InvalidPublicKey", "The public key must be RSA with a bit length from 2048 to 16384.")
	}
	return key, nil
}

func uploadSSHPublicKey(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UploadSSHPublicKeyInput](ctx)
	if err != nil {
		return nil, err
	}
	u, err := loginUser(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	key, err := parseIAMSSHKey(inputString(in.SSHPublicKeyBody))
	if err != nil {
		return nil, err
	}
	count := 0
	for _, r := range a.sshKeys {
		if r.UserID == u.UserId {
			if bytes.Equal(r.Wire, key.Marshal()) {
				return nil, certificateError("DuplicateSSHPublicKey", "The SSH public key is already associated with this user.")
			}
			count++
		}
	}
	if count >= 5 {
		return nil, limit("Cannot exceed quota for SSHPublicKeysPerUser: 5")
	}
	body := inputString(in.SSHPublicKeyBody)
	r := &SSHPublicKeyRecord{ID: newID("APKA")[:20], UserID: u.UserId, Body: body, Wire: key.Marshal(), Fingerprint: strings.TrimPrefix(ssh.FingerprintLegacyMD5(key), "MD5:"), Status: "Active", UploadDate: a.currentTime.Truncate(time.Millisecond)}
	a.sshKeys[r.ID] = r
	return &iamapi.UploadSSHPublicKeyOutput{SSHPublicKey: wireSSHKey(*r, u.UserName, r.Body)}, nil
}

func getSSHPublicKey(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.GetSSHPublicKeyInput](ctx)
	if err != nil {
		return nil, err
	}
	u, err := loginUser(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	r := a.sshKeys[inputString(in.SSHPublicKeyId)]
	if r == nil || r.UserID != u.UserId {
		return nil, missing("SSH public key", inputString(in.SSHPublicKeyId))
	}
	key, e := ssh.ParsePublicKey(r.Wire)
	if e != nil {
		return nil, certificateError("ServiceFailure", "Stored SSH key is invalid.")
	}
	body := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if inputString(in.Encoding) == "PEM" {
		cryptoKey, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return nil, certificateError("ServiceFailure", "Stored SSH key is invalid.")
		}
		der, marshalErr := x509.MarshalPKIXPublicKey(cryptoKey.CryptoPublicKey())
		if marshalErr != nil {
			return nil, certificateError("ServiceFailure", "Stored SSH key is invalid.")
		}
		body = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	return &iamapi.GetSSHPublicKeyOutput{SSHPublicKey: wireSSHKey(*r, u.UserName, body)}, nil
}

func listSSHPublicKeys(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.ListSSHPublicKeysInput](ctx)
	if err != nil {
		return nil, err
	}
	u, err := loginUser(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	items := make([]SSHPublicKeyRecord, 0)
	for _, r := range a.sshKeys {
		if r.UserID == u.UserId {
			items = append(items, *r)
		}
	}
	items, p, err := page(ctx, items, func(r SSHPublicKeyRecord) string { return r.ID }, m, in)
	if err != nil {
		return nil, err
	}
	out := make(iamapi.SSHPublicKeyListType, 0, len(items))
	for _, r := range items {
		out = append(out, iamapi.SSHPublicKeyMetadata{SSHPublicKeyId: wirePointer(iamapi.PublicKeyIdType(r.ID)), UserName: wirePointer(iamapi.UserNameType(u.UserName)), Status: wirePointer(iamapi.StatusType(r.Status)), UploadDate: wirePointer(r.UploadDate)})
	}
	return &iamapi.ListSSHPublicKeysOutput{SSHPublicKeys: out, IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, nil
}

func updateSSHPublicKey(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UpdateSSHPublicKeyInput](ctx)
	if err != nil {
		return nil, err
	}
	u, err := loginUser(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	r := a.sshKeys[inputString(in.SSHPublicKeyId)]
	if r == nil || r.UserID != u.UserId {
		return nil, missing("SSH public key", inputString(in.SSHPublicKeyId))
	}
	status := inputString(in.Status)
	if status != "Active" && status != "Inactive" {
		return nil, invalidInput("Invalid status. Status must be Active or Inactive.")
	}
	r.Status = status
	return &iamapi.Unit{}, nil
}

func deleteSSHPublicKey(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.DeleteSSHPublicKeyInput](ctx)
	if err != nil {
		return nil, err
	}
	u, err := loginUser(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	id := inputString(in.SSHPublicKeyId)
	r := a.sshKeys[id]
	if r == nil || r.UserID != u.UserId {
		return nil, missing("SSH public key", id)
	}
	delete(a.sshKeys, id)
	return &iamapi.Unit{}, nil
}

func wireSSHKey(r SSHPublicKeyRecord, name, body string) *iamapi.SSHPublicKey {
	return &iamapi.SSHPublicKey{UserName: wirePointer(iamapi.UserNameType(name)), SSHPublicKeyId: wirePointer(iamapi.PublicKeyIdType(r.ID)), SSHPublicKeyBody: wirePointer(iamapi.PublicKeyMaterialType(body)), Fingerprint: wirePointer(iamapi.PublicKeyFingerprintType(r.Fingerprint)), Status: wirePointer(iamapi.StatusType(r.Status)), UploadDate: wirePointer(r.UploadDate)}
}
