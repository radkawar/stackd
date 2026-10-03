AWS-managed IAM policy catalogue
===============================

`data/aws.json.gz` is a complete commercial-partition capture of the policies
returned by AWS IAM `ListPolicies(Scope=AWS)`, including metadata from `GetPolicy`
and **every retained version** enumerated by `ListPolicyVersions` and fetched by
`GetPolicyVersion`. Normal builds, tests and authorization are entirely offline.

The commercial capture on 2026-09-11 contains **1,575 policies and 7,006 versions**.
Its compressed SHA256 is
`d094ba82c31bf144cdc1ff1f2403470cc355720e3d724016c211afc3d3f902db`.

Each snapshot records the authoritative endpoint, signing region, partition,
capture start/end, SDK version and request IDs for every enumeration/metadata
read. Each version records its retrieval time, AWS request ID and SHA256 of the
exact URL-decoded JSON document. Source-account attachment and permissions-
boundary counts are deliberately excluded: the emulator derives those counts
from its own account's identity records. No credentials are included.

Refresh from the repository root using credentials with the four read actions:

```
go run ./cmd/awspolicies -cache-dir /tmp/stackd-managed-policy-cache
go run ./cmd/awspolicies -check
go test ./internal/iam/managed ./cmd/awspolicies ./internal/services/iam
```

The refresh command performs no AWS mutations. It traverses every page, retries
throttling through the AWS SDK and limits concurrent initial request rates.
Immutable version documents are cached by partition, policy ARN and version.
Rerunning resumes these completed reads and obtains fresh membership, metadata
and default-version flags. A partial or inconsistent capture never replaces the
checked-in snapshot. JSON key/order formatting, policy/version order and gzip
headers are deterministic for the same captured input. Inspect the full public
source with `gzip -dc internal/iam/managed/data/aws.json.gz | python3 -m json.tool`.

The commercial snapshot provides no evidence about the contents of China or
GovCloud policies. They use separate IAM domains and credentials; no ARN or
document is silently rewritten to create another partition's catalogue. The
refresh command supports independent captures, for example:

```
AWS_PROFILE=govcloud go run ./cmd/awspolicies -partition aws-us-gov -region us-gov-west-1 -endpoint https://iam.us-gov.amazonaws.com -output internal/iam/managed/data/aws-us-gov.json.gz
AWS_PROFILE=china go run ./cmd/awspolicies -partition aws-cn -region cn-north-1 -endpoint https://iam.cn-north-1.amazonaws.com.cn -output internal/iam/managed/data/aws-cn.json.gz
```

The current environment has no verified credentials for those separate domains.
Requests requiring an uncaptured partition's AWS catalogue return an explicit
`NotImplemented` error. Customer-managed policies remain available there.

Compatibility evidence
----------------------

`testdata/immutability.json` preserves real AWS CLI results for attempted changes
to the AWS-owned `AdministratorAccess` policy. These requests cannot mutate
customer resources. SDK tests replay each result locally:

| Operation | Observed result |
| --- | --- |
| DeletePolicy | AccessDenied: cannot delete outside own account |
| CreatePolicyVersion | AccessDenied: cannot create versions outside own account |
| SetDefaultPolicyVersion | AccessDenied: cannot update outside own account |
| DeletePolicyVersion | AccessDenied: cannot delete versions outside own account |
| TagPolicy / UntagPolicy | InvalidInput: tags unsupported in this domain |
| ListPolicyTags | Success with an empty tag list |

`testdata/attachment_domains.json` records that customer APIs reject reserved
`/aws-service-role/` and `/root-task/` policies for user attachments and boundaries,
even though their public `IsAttachable` metadata is true. Ordinary `/service-role/`
policies accept both operations. Successful probe attachments were removed and
the temporary user was deleted.

`testdata/arn_component_variables.json` records real `SimulateCustomPolicy`
decisions for variables in the partition, service, region, account and entire ARN.
IAM evaluates those variables, including the account-component expression used
by the current AmazonTimestreamInfluxDBServiceRolePolicy. Short dynamic ARNs are
not completed with wildcard components. This evidence supersedes the narrower
resource-component guidance in the user guide.

`testdata/resource_account*.json` records that AWS-managed policy reads evaluate
`aws:ResourceAccount` as **639982225848** in the commercial partition. It is
neither the public ARN alias `aws` nor the caller's account. Conditional requests
derived the 12 digits and confirmed the complete value, then verified it across
ordinary, job-function, service-role, service-linked-role and root-task policies.
Fresh user-agent conditions checked policy propagation before each round; all
temporary users, groups, policies and access keys were removed. The runtime
exports this observed value independently from cross-account permission rules.

AWS retains historical documents containing misspelled actions and whitespace in
action names (for example, old ReadOnlyAccess versions). Those bytes are preserved
for retrieval; the effective default versions are the ones compiled and used by
authorization. All retained documents are validated as JSON and against their
recorded digests.

Authoritative references:

- [ListPolicies API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html)
- [GetPolicyVersion API and URL encoding](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html)
- [Managed policy versioning](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html)
- [AWS retains full AWS-managed policy histories](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html)
- [TagPolicy only accepts customer-managed policies](https://docs.aws.amazon.com/IAM/latest/APIReference/API_TagPolicy.html)
- [GovCloud credentials and partition isolation](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/govcloud-differences.html)
