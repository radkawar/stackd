package iam

import (
	"context"
	"strings"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func findServerCertificate(a *account, name string) (*ServerCertificateRecord, *awswire.Error) {
	r := a.serverCertificates[strings.ToLower(name)]
	if r == nil {
		return nil, missing("server certificate", name)
	}
	return r, nil
}

func uploadServerCertificate(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UploadServerCertificateInput](ctx)
	if err != nil {
		return nil, err
	}
	name := inputString(in.ServerCertificateName)
	if a.serverCertificates[strings.ToLower(name)] != nil {
		return nil, duplicate("server certificate", name)
	}
	if len(a.serverCertificates) >= maxServerCertificates {
		return nil, limit("Cannot exceed quota for ServerCertificates: 20")
	}
	path, err := validPath(inputString(in.Path))
	if err != nil {
		return nil, err
	}
	body, key, chain := inputString(in.CertificateBody), inputString(in.PrivateKey), inputString(in.CertificateChain)
	expiration, err := validateServerCertificate(body, key, chain, a.currentTime)
	if err != nil {
		return nil, err
	}
	tags, err := inputTags(in.Tags, "FederationProvider")
	if err != nil {
		return nil, err
	}
	r := &ServerCertificateRecord{ID: newID("ASCA"), Name: name, Path: path, ARN: resourceARN(m, "server-certificate", path, name), Body: strings.TrimSpace(body), Chain: strings.TrimSpace(chain), PrivateKey: []byte(key), UploadDate: a.currentTime.Truncate(time.Millisecond), Expiration: expiration, Tags: tags}
	a.serverCertificates[strings.ToLower(name)] = r
	return &iamapi.UploadServerCertificateOutput{ServerCertificateMetadata: wireServerCertificateMetadata(*r), Tags: wireTags(tags)}, nil
}

func getServerCertificate(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.GetServerCertificateInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findServerCertificate(a, inputString(in.ServerCertificateName))
	if err != nil {
		return nil, err
	}
	out := &iamapi.ServerCertificate{ServerCertificateMetadata: wireServerCertificateMetadata(*r), CertificateBody: wirePointer(iamapi.CertificateBodyType(r.Body)), Tags: federationWireTags(r.Tags)}
	if r.Chain != "" {
		out.CertificateChain = wirePointer(iamapi.CertificateChainType(r.Chain))
	}
	return &iamapi.GetServerCertificateOutput{ServerCertificate: out}, nil
}

func listServerCertificates(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.ListServerCertificatesInput](ctx)
	if err != nil {
		return nil, err
	}
	items := make([]ServerCertificateRecord, 0)
	for _, r := range a.serverCertificates {
		if strings.HasPrefix(r.Path, inputString(in.PathPrefix)) {
			items = append(items, *r)
		}
	}
	items, p, err := page(ctx, items, func(r ServerCertificateRecord) string { return strings.ToLower(r.Name) }, m, in)
	if err != nil {
		return nil, err
	}
	out := make(iamapi.ServerCertificateMetadataListType, 0, len(items))
	for _, r := range items {
		out = append(out, *wireServerCertificateMetadata(r))
	}
	return &iamapi.ListServerCertificatesOutput{ServerCertificateMetadataList: out, IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, nil
}

func updateServerCertificate(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UpdateServerCertificateInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findServerCertificate(a, inputString(in.ServerCertificateName))
	if err != nil {
		return nil, err
	}
	name, path := r.Name, r.Path
	if in.NewServerCertificateName != nil {
		name = inputString(in.NewServerCertificateName)
	}
	if in.NewPath != nil {
		path, err = validPath(inputString(in.NewPath))
		if err != nil {
			return nil, err
		}
	}
	if other := a.serverCertificates[strings.ToLower(name)]; other != nil && other.ID != r.ID {
		return nil, duplicate("server certificate", name)
	}
	delete(a.serverCertificates, strings.ToLower(r.Name))
	r.Name, r.Path = name, path
	r.ARN = resourceARN(m, "server-certificate", path, name)
	// Name/path updates preserve tags. The empty-update edge is covered by
	// a separate AWS observation because it changes tag visibility.
	if in.NewPath == nil && in.NewServerCertificateName == nil {
		r.Tags = nil
		r.TaggingInvalid = true
	}
	a.serverCertificates[strings.ToLower(name)] = r
	return &iamapi.Unit{}, nil
}

func (s *Service) deleteServerCertificate(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.DeleteServerCertificateInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findServerCertificate(a, inputString(in.ServerCertificateName))
	if err != nil {
		return nil, err
	}
	if err := s.checkServerCertificateUnused(ctx, Scope{Partition: m.Partition, AccountID: m.AccountID}, r); err != nil {
		return nil, err
	}
	delete(a.serverCertificates, strings.ToLower(r.Name))
	return &iamapi.Unit{}, nil
}

func wireServerCertificateMetadata(r ServerCertificateRecord) *iamapi.ServerCertificateMetadata {
	return &iamapi.ServerCertificateMetadata{Arn: wirePointer(iamapi.ArnType(r.ARN)), Path: wirePointer(iamapi.PathType(r.Path)), ServerCertificateName: wirePointer(iamapi.ServerCertificateNameType(r.Name)), ServerCertificateId: wirePointer(iamapi.IdType(r.ID)), UploadDate: wirePointer(r.UploadDate), Expiration: wirePointer(r.Expiration)}
}

func (s *Service) certificateHandlers() map[string]handler {
	return map[string]handler{"UploadSigningCertificate": uploadSigningCertificate, "ListSigningCertificates": listSigningCertificates, "UpdateSigningCertificate": updateSigningCertificate, "DeleteSigningCertificate": deleteSigningCertificate, "UploadSSHPublicKey": uploadSSHPublicKey, "GetSSHPublicKey": getSSHPublicKey, "ListSSHPublicKeys": listSSHPublicKeys, "UpdateSSHPublicKey": updateSSHPublicKey, "DeleteSSHPublicKey": deleteSSHPublicKey, "UploadServerCertificate": uploadServerCertificate, "GetServerCertificate": getServerCertificate, "ListServerCertificates": listServerCertificates, "UpdateServerCertificate": updateServerCertificate, "DeleteServerCertificate": s.deleteServerCertificate, "TagServerCertificate": tagServerCertificate, "UntagServerCertificate": untagServerCertificate, "ListServerCertificateTags": listServerCertificateTags}
}
