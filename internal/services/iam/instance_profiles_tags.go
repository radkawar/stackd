package iam

import (
	"context"
	"slices"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func wireInstanceProfileTags(tags []Tag) iamapi.TagListType {
	result := make(iamapi.TagListType, 0, len(tags))
	for _, tag := range tags {
		result = append(result, iamapi.Tag{Key: wirePointer(iamapi.TagKeyType(tag.Key)), Value: wirePointer(iamapi.TagValueType(tag.Value))})
	}
	return result
}

func tagInstanceProfile(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.TagInstanceProfileInput](ctx)
	if err != nil {
		return nil, err
	}
	profile, err := findInstanceProfile(a, inputString(input.InstanceProfileName))
	if err != nil {
		return nil, err
	}
	tags, err := inputTags(input.Tags, "InstanceProfile")
	if err != nil {
		return nil, err
	}
	if len(tags) == 0 {
		return nil, invalidInput("Tags must contain at least one tag.")
	}
	if err := mergeTags(&profile.Tags, tags, "InstanceProfile"); err != nil {
		return nil, err
	}
	return &iamapi.TagInstanceProfileOutput{}, nil
}

func untagInstanceProfile(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.UntagInstanceProfileInput](ctx)
	if err != nil {
		return nil, err
	}
	profile, err := findInstanceProfile(a, inputString(input.InstanceProfileName))
	if err != nil {
		return nil, err
	}
	removeTags(&profile.Tags, input.TagKeys, "InstanceProfile")
	return &iamapi.UntagInstanceProfileOutput{}, nil
}

func listInstanceProfileTags(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.ListInstanceProfileTagsInput](ctx)
	if err != nil {
		return nil, err
	}
	profile, err := findInstanceProfile(a, inputString(input.InstanceProfileName))
	if err != nil {
		return nil, err
	}
	selection := *input
	selection.InstanceProfileName = wirePointer(iamapi.InstanceProfileNameType(profile.InstanceProfileName))
	tags, p, err := page(ctx, slices.Clone(profile.Tags), func(tag Tag) string { return tag.Key }, m, &selection)
	return &iamapi.ListInstanceProfileTagsOutput{Tags: wireInstanceProfileTags(tags), IsTruncated: wirePointer(iamapi.BooleanType(p.IsTruncated)), Marker: instanceProfileMarker(p)}, err
}
