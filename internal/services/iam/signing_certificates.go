package iam

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func certificateError(code, message string) *awswire.Error {
	status := 400
	if code == "DuplicateCertificate" {
		status = 409
	}
	if code == "ServiceFailure" {
		status = 500
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}

func signingOwner(a *account, m awsctx.Metadata, name string) (id, username string, err *awswire.Error) {
	root := "arn:" + m.Partition + ":iam::" + m.AccountID + ":root"
	if name == "" && m.PrincipalARN == root {
		return root, m.AccountID, nil
	}
	u, err := loginUser(a, m, name)
	if err != nil {
		return "", "", err
	}
	return u.UserId, u.UserName, nil
}

func parseSigningCertificate(body string, now time.Time) (*x509.Certificate, *awswire.Error) {
	block, rest := pem.Decode([]byte(body))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, certificateError("MalformedCertificate", "Unable to parse certificate. Please ensure the certificate is in PEM format.")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, certificateError("MalformedCertificate", "The certificate is malformed.")
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, certificateError("MalformedCertificate", "The certificate is not currently valid.")
	}
	return cert, nil
}

func uploadSigningCertificate(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UploadSigningCertificateInput](ctx)
	if err != nil {
		return nil, err
	}
	owner, name, err := signingOwner(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	body := inputString(in.CertificateBody)
	cert, err := parseSigningCertificate(body, a.currentTime)
	if err != nil {
		return nil, err
	}
	count := 0
	for _, existing := range a.signingCertificates {
		if bytes.Equal(existing.DER, cert.Raw) {
			if existing.UserID != owner {
				return nil, certificateError("DuplicateCertificate", "The same certificate is already associated with another user in this account.")
			}
			// AWS's idempotent upload response says Active, while an existing
			// Inactive certificate remains inactive when listed and used.
			response := *existing
			response.Status = "Active"
			return &iamapi.UploadSigningCertificateOutput{Certificate: wireSigningCertificate(response, name)}, nil
		}
		if existing.UserID == owner {
			count++
		}
	}
	if count >= maxSigningCertificatesPerUser {
		return nil, limit("Cannot exceed quota for CertificatesPerUser: 2")
	}
	digest := sha1.Sum(cert.Raw) // IAM certificate identifiers are public fingerprints, not authentication secrets.
	id := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])
	record := &SigningCertificateRecord{ID: id, UserID: owner, Body: body, Status: "Active", DER: cert.Raw, UploadDate: a.currentTime.Truncate(time.Millisecond)}
	a.signingCertificates[id] = record
	return &iamapi.UploadSigningCertificateOutput{Certificate: wireSigningCertificate(*record, name)}, nil
}

func listSigningCertificates(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.ListSigningCertificatesInput](ctx)
	if err != nil {
		return nil, err
	}
	owner, name, err := signingOwner(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	items := make([]SigningCertificateRecord, 0)
	for _, record := range a.signingCertificates {
		if record.UserID == owner {
			items = append(items, *record)
		}
	}
	items, p, err := page(ctx, items, func(r SigningCertificateRecord) string { return r.ID }, m, in)
	if err != nil {
		return nil, err
	}
	out := make(iamapi.CertificateListType, 0, len(items))
	for _, record := range items {
		out = append(out, *wireSigningCertificate(record, name))
	}
	return &iamapi.ListSigningCertificatesOutput{Certificates: out, IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, nil
}

func updateSigningCertificate(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UpdateSigningCertificateInput](ctx)
	if err != nil {
		return nil, err
	}
	owner, _, err := signingOwner(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	r := a.signingCertificates[inputString(in.CertificateId)]
	if r == nil || r.UserID != owner {
		return nil, missing("certificate", inputString(in.CertificateId))
	}
	status := inputString(in.Status)
	if status != "Active" && status != "Inactive" {
		return nil, invalidInput("Invalid status. Status must be Active or Inactive.")
	}
	r.Status = status
	return &iamapi.Unit{}, nil
}

func deleteSigningCertificate(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.DeleteSigningCertificateInput](ctx)
	if err != nil {
		return nil, err
	}
	owner, _, err := signingOwner(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	id := inputString(in.CertificateId)
	r := a.signingCertificates[id]
	if r == nil || r.UserID != owner {
		return nil, missing("certificate", id)
	}
	delete(a.signingCertificates, id)
	return &iamapi.Unit{}, nil
}

func wireSigningCertificate(r SigningCertificateRecord, name string) *iamapi.SigningCertificate {
	return &iamapi.SigningCertificate{CertificateBody: wirePointer(iamapi.CertificateBodyType(r.Body)), CertificateId: wirePointer(iamapi.CertificateIdType(r.ID)), Status: wirePointer(iamapi.StatusType(r.Status)), UploadDate: wirePointer(r.UploadDate), UserName: wirePointer(iamapi.UserNameType(name))}
}
