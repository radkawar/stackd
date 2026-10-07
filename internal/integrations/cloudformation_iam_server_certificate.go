package integrations

import (
	"context"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-servercertificate.html
// Body, chain and private key are schema write-only and never enter CFN reads.
type cfnIAMServerCertificate struct{ commands StepFunctionsCommands }

func (h cfnIAMServerCertificate) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ServerCertificateName", "Path", "CertificateBody", "CertificateChain", "PrivateKey", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ServerCertificateName", "Path", "CertificateBody", "CertificateChain", "PrivateKey"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnIAMServerCertificate) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ServerCertificateName", "CertificateBody", "CertificateChain", "PrivateKey"), h.Validate(b)
}
func (h cfnIAMServerCertificate) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (*api.ServerCertificate, error) {
	ctx = cfnIAMContext(ctx, r)
	out, err := cfnComputeCall[api.GetServerCertificateOutput](ctx, h.commands, "iam", "GetServerCertificate", map[string]any{"ServerCertificateName": name})
	if err != nil {
		return nil, err
	}
	if out.ServerCertificate == nil || out.ServerCertificate.ServerCertificateMetadata == nil {
		return nil, cfnIAMNotFound()
	}
	return out.ServerCertificate, nil
}
func cfnIAMServerCertificateResult(certificate *api.ServerCertificate) cloudformation.ResourceResult {
	metadata := certificate.ServerCertificateMetadata
	return cfnIAMNamedResult(cfnComputeValue(metadata.ServerCertificateName), cfnComputeValue(metadata.Arn))
}
func (h cfnIAMServerCertificate) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnComputeRequired(r.Properties, "CertificateBody", "PrivateKey"); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "ServerCertificateName", 128)
	existing, err := h.owned(ctx, r, name)
	if err == nil {
		return cfnIAMServerCertificateResult(existing), nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "Path", "CertificateBody", "CertificateChain", "PrivateKey")
	in["ServerCertificateName"] = name
	in["Tags"] = cfnComputeTagList(cfnIAMCustomerTags(r))
	out, err := cfnComputeCall[api.UploadServerCertificateOutput](ctx, h.commands, "iam", "UploadServerCertificate", in)
	if err != nil {
		return cfnIAMCreationFailure(ctx, r, h, err)
	}
	if out.ServerCertificateMetadata == nil {
		return cloudformation.ResourceResult{}, cfnIAMNotFound()
	}
	return cfnIAMNamedResult(cfnComputeValue(out.ServerCertificateMetadata.ServerCertificateName), cfnComputeValue(out.ServerCertificateMetadata.Arn)), nil
}
func (h cfnIAMServerCertificate) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnIAMContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	certificate, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnIAMServerCertificateResult(certificate)
	if err := cfnComputeRun(ctx, h.commands, "iam", "UpdateServerCertificate", map[string]any{"ServerCertificateName": r.PhysicalID, "NewPath": cfnComputeDefault(r.Properties, "Path", "/")}); err != nil {
		return result, err
	}
	if err := cfnIAMUpdateTags(ctx, h.commands, r, "ServerCertificate", "ServerCertificateName", r.PhysicalID, cfnIAMTags(certificate.Tags)); err != nil {
		return result, err
	}
	certificate, err = h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return result, err
	}
	return cfnIAMServerCertificateResult(certificate), nil
}
func (h cfnIAMServerCertificate) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnIAMContext(ctx, r)
	name := cfnComputeName(r, "ServerCertificateName", 128)
	if _, err := h.owned(ctx, r, name); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "iam", "DeleteServerCertificate", map[string]any{"ServerCertificateName": name}))
}
func (h cfnIAMServerCertificate) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	certificate, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	metadata := certificate.ServerCertificateMetadata
	return cloudformation.Properties{"ServerCertificateName": cfnComputeValue(metadata.ServerCertificateName), "Path": cfnComputeValue(metadata.Path), "Arn": cfnComputeValue(metadata.Arn), "Tags": cfnIAMUserTags(certificate.Tags)}, nil
}
func (h cfnIAMServerCertificate) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListServerCertificatesOutput](ctx, h.commands, "iam", "ListServerCertificates", in)
		if err != nil {
			return nil, err
		}
		for _, certificate := range out.ServerCertificateMetadataList {
			rr := r
			rr.PhysicalID = cfnComputeValue(certificate.ServerCertificateName)
			p, e := h.Read(ctx, rr)
			if e != nil {
				if !r.CloudControl {
					continue
				}
				return nil, e
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
		}
		marker := cfnComputeValue(out.Marker)
		if marker == "" {
			return result, nil
		}
		in["Marker"] = marker
	}
}
