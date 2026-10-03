package iam

import iamapi "stackd/internal/awsapi/iam"

func federationWireTags(tags []Tag) iamapi.TagListType {
	result := wireTags(tags)
	if result == nil {
		result = make(iamapi.TagListType, 0)
	}
	return result
}
func cloneFederationWireTags(input iamapi.TagListType) iamapi.TagListType {
	if input == nil {
		return nil
	}
	result := make(iamapi.TagListType, len(input))
	for i, t := range input {
		result[i] = iamapi.Tag{Key: wirePointer(iamapi.TagKeyType(inputString(t.Key))), Value: wirePointer(iamapi.TagValueType(inputString(t.Value)))}
	}
	return result
}
