package iam

import (
	"context"
	"slices"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func tagServerCertificate(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.TagServerCertificateInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findServerCertificate(a, inputString(in.ServerCertificateName))
	if err != nil {
		return nil, err
	}
	if r.TaggingInvalid {
		return nil, invalidInput("Input tag parameters does not meet the acceptance criteria.")
	}
	tags, err := inputTags(in.Tags, "FederationProvider")
	if err != nil {
		return nil, err
	}
	if len(tags) == 0 {
		return nil, invalidInput("The provided tag map must not be null/empty.")
	}
	if err := mergeTags(&r.Tags, tags, "ServerCertificate"); err != nil {
		return nil, err
	}
	return &iamapi.Unit{}, nil
}

func untagServerCertificate(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UntagServerCertificateInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findServerCertificate(a, inputString(in.ServerCertificateName))
	if err != nil {
		return nil, err
	}
	if len(in.TagKeys) == 0 {
		return nil, invalidInput("The provided tag keys must not be null/empty.")
	}
	if r.TaggingInvalid {
		return nil, invalidInput("Input tag parameters does not meet the acceptance criteria.")
	}
	removeTags(&r.Tags, in.TagKeys, "ServerCertificate")
	return &iamapi.Unit{}, nil
}

func listServerCertificateTags(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.ListServerCertificateTagsInput](ctx)
	if err != nil {
		return nil, err
	}
	r, err := findServerCertificate(a, inputString(in.ServerCertificateName))
	if err != nil {
		return nil, err
	}
	items, p, err := page(ctx, slices.Clone(r.Tags), func(t Tag) string { return t.Key }, m, in)
	if err != nil {
		return nil, err
	}
	return &iamapi.ListServerCertificateTagsOutput{Tags: federationWireTags(items), IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: wireMarker(p)}, nil
}
