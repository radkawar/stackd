package iam

import (
	"context"
	"strconv"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func createPolicyVersion(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.CreatePolicyVersionInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if err := managedPolicyMutationError(inputString(in.PolicyArn), "CreatePolicyVersion"); err != nil {
		return nil, err
	}
	p, err := findPolicyARN(a, inputString(in.PolicyArn))
	if err != nil {
		return nil, err
	}
	doc := inputString(in.PolicyDocument)
	if err := validateDocument(doc, false); err != nil {
		return nil, err
	}
	if policySize(doc) > maxManagedPolicyCharacters {
		return nil, limit("Managed policy exceeds 6144 characters.")
	}
	setDefault := in.SetAsDefault != nil && bool(*in.SetAsDefault)
	if len(p.Versions) >= maxVersionsPerPolicy {
		return nil, limit("A managed policy may have at most five versions.")
	}
	id := "v" + strconv.Itoa(p.NextVersion)
	v := &policyVersion{Document: doc, VersionId: id, IsDefaultVersion: setDefault, CreateDate: a.currentTime}
	p.NextVersion++
	p.Versions[id] = v
	p.UpdateDate = a.currentTime
	if setDefault {
		changeDefault(p, id, a.currentTime)
	}
	return &iamapi.CreatePolicyVersionOutput{PolicyVersion: wirePolicyVersion(v, false)}, nil
}

func getPolicyVersion(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.GetPolicyVersionInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	p, err := findPolicyARN(a, inputString(in.PolicyArn))
	if err != nil {
		return nil, err
	}
	v, err := findVersion(p, inputString(in.VersionId))
	if err != nil {
		return nil, err
	}
	return &iamapi.GetPolicyVersionOutput{PolicyVersion: wirePolicyVersion(v, true)}, nil
}

func listPolicyVersions(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ListPolicyVersionsInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	p, err := findPolicyARN(a, inputString(in.PolicyArn))
	if err != nil {
		return nil, err
	}
	items := make([]*policyVersion, 0, len(p.Versions))
	for _, v := range p.Versions {
		items = append(items, v)
	}
	items, paging, err := page(ctx, items, func(v *policyVersion) string { return v.VersionId }, m, in)
	versions := make(iamapi.PolicyDocumentVersionListType, 0, len(items))
	for _, item := range items {
		versions = append(versions, *wirePolicyVersion(item, false))
	}
	return &iamapi.ListPolicyVersionsOutput{Versions: versions, IsTruncated: wirePointer(iamapi.BooleanType(paging.IsTruncated)), Marker: wireMarker(paging)}, err
}

func setDefaultPolicyVersion(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.SetDefaultPolicyVersionInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if err := managedPolicyMutationError(inputString(in.PolicyArn), "SetDefaultPolicyVersion"); err != nil {
		return nil, err
	}
	p, err := findPolicyARN(a, inputString(in.PolicyArn))
	if err != nil {
		return nil, err
	}
	v, err := findVersion(p, inputString(in.VersionId))
	if err != nil {
		return nil, err
	}
	changeDefault(p, v.VersionId, a.currentTime)
	return &iamapi.SetDefaultPolicyVersionOutput{}, nil
}

func deletePolicyVersion(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.DeletePolicyVersionInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if err := managedPolicyMutationError(inputString(in.PolicyArn), "DeletePolicyVersion"); err != nil {
		return nil, err
	}
	p, err := findPolicyARN(a, inputString(in.PolicyArn))
	if err != nil {
		return nil, err
	}
	v, err := findVersion(p, inputString(in.VersionId))
	if err != nil {
		return nil, err
	}
	if v.IsDefaultVersion {
		return nil, conflict("Cannot delete the default policy version.")
	}
	delete(p.Versions, v.VersionId)
	return &iamapi.DeletePolicyVersionOutput{}, nil
}

func findVersion(p *policy, id string) (*policyVersion, *awswire.Error) {
	v := p.Versions[id]
	if v == nil {
		return nil, missing("policy version", id)
	}
	return v, nil
}

func changeDefault(p *policy, id string, now time.Time) {
	for _, v := range p.Versions {
		v.IsDefaultVersion = v.VersionId == id
	}
	p.DefaultVersionId = id
	p.UpdateDate = now
}
