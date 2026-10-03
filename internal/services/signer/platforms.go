package signer

import (
	"context"
	api "stackd/internal/awsapi/signer"
)

func lambdaPlatform() *api.GetSigningPlatformOutput {
	return &api.GetSigningPlatformOutput{PlatformId: new(api.PlatformId(LambdaPlatform)), DisplayName: new(api.DisplayName("AWS Lambda")), Partner: new(api.String("AWSLambda")), Target: new(api.String("SHA384-ECDSA")), Category: new(api.Category("AWS")), MaxSizeInMB: new(api.MaxSizeInMB(250)), RevocationSupported: new(api.Bool(true)), SigningConfiguration: &api.SigningConfiguration{EncryptionAlgorithmOptions: &api.EncryptionAlgorithmOptions{AllowedValues: api.EncryptionAlgorithms{"ECDSA"}, DefaultValue: new(api.EncryptionAlgorithm("ECDSA"))}, HashAlgorithmOptions: &api.HashAlgorithmOptions{AllowedValues: api.HashAlgorithms{"SHA384"}, DefaultValue: new(api.HashAlgorithm("SHA384"))}}, SigningImageFormat: &api.SigningImageFormat{SupportedFormats: api.ImageFormats{"JSONDetached"}, DefaultFormat: new(api.ImageFormat("JSONDetached"))}}
}
func (s *Service) getPlatform(ctx context.Context, _ Transaction, in *api.GetSigningPlatformInput) (*api.GetSigningPlatformOutput, error) {
	if e := s.authorize(ctx, "GetSigningPlatform", "", nil, nil); e != nil {
		return nil, e
	}
	if value(in.PlatformId) != LambdaPlatform {
		return nil, invalid("This signing platform is not implemented")
	}
	return lambdaPlatform(), nil
}
func (s *Service) listPlatforms(ctx context.Context, _ Transaction, in *api.ListSigningPlatformsInput) (*api.ListSigningPlatformsOutput, error) {
	if e := s.authorize(ctx, "ListSigningPlatforms", "", nil, nil); e != nil {
		return nil, e
	}
	if _, _, e := page(in.MaxResults, value(in.NextToken)); e != nil {
		return nil, e
	}
	o := &api.ListSigningPlatformsOutput{Platforms: api.SigningPlatforms{}}
	if value(in.NextToken) != "" {
		return nil, invalid("Invalid nextToken")
	}
	if value(in.Category) != "" && value(in.Category) != "AWS" || value(in.Partner) != "" && value(in.Partner) != "AWSLambda" || value(in.Target) != "" && value(in.Target) != "SHA384-ECDSA" {
		return o, nil
	}
	p := lambdaPlatform()
	o.Platforms = append(o.Platforms, api.SigningPlatform{PlatformId: new(api.String(LambdaPlatform)), DisplayName: new(api.String("AWS Lambda")), Partner: p.Partner, Target: p.Target, Category: p.Category, MaxSizeInMB: p.MaxSizeInMB, RevocationSupported: p.RevocationSupported, SigningConfiguration: p.SigningConfiguration, SigningImageFormat: p.SigningImageFormat})
	return o, nil
}
