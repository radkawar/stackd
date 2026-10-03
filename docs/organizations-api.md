# Organizations API behavior

Every implemented Organizations operation consumes a generated Smithy input and
returns a generated output. Direct provider and signed gateway requests share the
same decoder and service-owned validation error mapping. Generated accessors expose
only modeled resource selectors, request tags, policy types and pagination controls
to the common authorization and pagination code. State is still service-owned:
response encoding completes before the existing revision-checked transaction
publishes mutations. Account provisioning and IAM authorization retain their
existing transaction boundaries.

Generation uses SDK revision `113bc91bf12edc3af1d3aba1c70be28494d54c2a`.
This completes the adapter migration, not Organizations semantic parity.
[Invitations](organizations-invitations.md) and
[standard feature migration](organizations-features.md) now have behavioral
implementations and explicit remaining audits. Effective policies, account
closure and other gaps remain in [TODO.md](../TODO.md).

Resource control policies use the same retained hierarchy and typed policy
attachments as SCPs, but select the resource owner's ancestry independently of
the caller. The current [RCP contract](iam-resource-controls.md) records the
2026-09-27 AWS service list, action/resource-type eligibility, exemptions and
source-version discrepancies. Owner-policy mutation replay includes actual S3
and Secrets Manager access across memory and reopened SQLite, without a second
policy store or service-specific RCP evaluator.

RAM organization sharing also requires the management account's protected
`AWSServiceRoleForResourceAccessManager`, not only Organizations trusted access.
RAM's [EnableSharingWithAwsOrganization](https://docs.aws.amazon.com/ram/latest/APIReference/API_EnableSharingWithAwsOrganization.html)
owns that setup. The actual CLI
[`ram_org_enablement.json`](../testdata/integration/ram_org_enablement.json)
records rejected OU sharing before enablement, continued rejection with trusted
access alone, then successful sharing after RAM enablement. These are local
signed-SDK observations, not a new native Organizations configuration change.

## Native evidence

[The capture](../testdata/aws/iam/organizations_inputs.json) records signed native
AWS requests from September 13, 2026. [The probe](../scripts/aws/organizations_inputs_probe.py)
creates owned OUs and unattached SCPs, reads management-account path fields, and
deletes its resources. It does not move accounts, attach SCPs or change trusted
access. Credentials stay in memory. Reproducing the capture requires an authorized
management-account session; ordinary tests use only the committed fixture.

[Input replay](../internal/services/organizations/inputs_aws_test.go) runs the
39 captured mutation/list cases through standalone and gateway endpoints using
SDK signing and modeled error decoding. Subsequent SDK reads check retained names,
descriptions and tags after both accepted and rejected mutations:

- OU updates accept omission/null without changing the name. An empty name fails;
  a whitespace-only name succeeds without changing stored state. Unicode names
  use character bounds. These observations refine the modeled
  [OU update contract](https://docs.aws.amazon.com/organizations/latest/APIReference/API_UpdateOrganizationalUnit.html).
- Policy descriptions accept 512 Unicode characters and reject 513. An empty
  description succeeds but retains its stored value. `UpdatePolicy` returns only
  supplied name/description fields, alongside policy identity, type, ownership and
  current content. A separate capture records response presence, and delayed reads
  confirm the retained values. AWS describes the response as showing the
  [requested changes](https://docs.aws.amazon.com/organizations/latest/APIReference/API_UpdatePolicy.html).
- Empty tag and tag-key lists succeed. Missing/null required lists or tag values
  fail. Duplicate keys and invalid members reject the whole mutation. Generated
  validation supplies constraint/path information for native `Reason` values;
  domain logic retains cumulative quotas, reserved prefixes and duplicate checks.
  See [TagResource](https://docs.aws.amazon.com/organizations/latest/APIReference/API_TagResource.html)
  and [UntagResource](https://docs.aws.amazon.com/organizations/latest/APIReference/API_UntagResource.html).
- An omitted/null page size selects the default. Zero and 21 fail the modeled
  bounds. A present empty continuation token fails with `INVALID_NEXT_TOKEN`;
  token presence survives generated binding. ListTagsForResource has no modeled
  page-size member. See [OU listing](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListOrganizationalUnitsForParent.html)
  and [tag listing](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListTagsForResource.html).

[Projection replay](../internal/services/organizations/projections_aws_test.go)
checks the six captured update responses and seven hierarchy projections through
both endpoints. OU `Path` and account `Paths` include the entity's own ID and a
trailing slash. Create, describe and list projections derive these fields from the
current hierarchy. IAM principal paths select the account's parent; access reports
use the same ancestry without a trailing slash. Native reads still returned both
`State` and `Status` on the capture date. See the
[OU shape](https://docs.aws.amazon.com/organizations/latest/APIReference/API_OrganizationalUnit.html)
and [account shape](https://docs.aws.amazon.com/organizations/latest/APIReference/API_Account.html).

These observations establish the captured cases, not complete timing, policy or
service behavior. Existing integration tests cover IAM/SCP enforcement, member
access-role provisioning and memory/SQLite recovery; those remain separate from
wire-model compatibility.
