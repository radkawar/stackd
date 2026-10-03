These fixtures record AWS IAM responses from uniquely owned providers in the
commercial partition, captured on 2026-09-11 through AWS CLI 2.36.28. Each request
records its exact input, output/error and UTC observation time. Source account
numbers are replaced with `<source-account>`; private key inputs reference files
in this directory. All PEM keys are generated public test material, not account
credentials. All created AWS providers were deleted. The OIDC file includes a
separate cleanup read for its trailing-slash variant.

`TestFederationAWSReplay` sends these inputs through the actual Go v2 IAM SDK to
an offline stackd provider and compares decoded response fields and error codes.
It maps generated identifiers and validates timestamp shape; dedicated SDK tests
verify timestamp transitions, rollback and immutable snapshots.

The SAML validation fixture's resource named `expired-certificate` is a repeated
control using the normal certificate. It does not establish certificate-expiry
behavior. AWS explicitly documents that certificate expiry and metadata
`validUntil` are ignored during SAML authentication; assertion expiry still
applies. Metadata updates reset IAM's returned `ValidUntil` to update time plus
100 years while preserving `CreateDate` and the provider UUID.

Repeat an owned-resource capture explicitly with configured real AWS credentials:

```
python scripts/aws/iam_federation_probe.py oidc
python scripts/aws/iam_federation_probe.py saml
python scripts/aws/iam_federation_probe.py saml-validation
```

The script uses the real commercial IAM endpoint, unique resource names, and a
`finally` cleanup. It records cleanup failure and names any resource needing
manual deletion. Normal tests never run these probes or contact an IdP.

Authoritative references:

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html
- https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateSAMLProvider.html
- https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml.html

Observed behavior sometimes differs from descriptive prose: `:443` is accepted
and stripped from an OIDC URL, 40-character nonhex thumbprints are accepted, and
SAML decryption key registration accepts EC and 1024-bit RSA PKCS#8 keys as well
as RSA PKCS#1. The fixture replays retain these observations.
