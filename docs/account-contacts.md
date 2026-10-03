# Account contacts

Account Management has generated REST JSON bindings and typed behavior for
`GetContactInformation`, `PutContactInformation`, `GetAlternateContact`,
`PutAlternateContact` and `DeleteAlternateContact`. The service remains partial;
these operations do not establish complete address-validation or partition parity.
Region behavior and shared Account authorization modes are documented in
[account regions](account-regions.md).

## State and permissions

Primary contacts are keyed by partition and account. Alternate contacts add the
modeled `BILLING`, `OPERATIONS` or `SECURITY` type to that key. The Account-owned
repository exposes typed records and uses the shared memory transaction domain.
It has no separate locks or opaque resource blobs. Replacing a backend must
preserve the borrowed-transaction contract with IAM and Organizations.

Reads and writes authorize inside their repository callback. Omitting `AccountId`
uses the caller's standalone Account resource. Supplying it uses Organizations
mode with its trusted-access, membership and delegated-administration gates.
Identity policies, boundaries, session policies and SCPs continue to apply.
Alternate-contact requests supply `account:AlternateContactTypes` to the IAM
evaluator, including on deletion; a grant for one contact type grants no access
to the others or to primary contacts.

Primary and alternate updates replace the stored contact. Omitted optional
primary fields are removed. A missing alternate contact returns
`ResourceNotFoundException` on both reads and deletes, including a repeated
delete. Invalid alternate types return `AccessDeniedException`, even when the
caller otherwise has access. The allowed values are generated from Smithy's
legacy enum trait; they are not a separately maintained service catalogue.

Alternate updates trim surrounding email whitespace while preserving email case
and the supplied name, title and phone whitespace. Primary updates trim full name,
address line 1, city, state/region, postal code and phone whitespace, and uppercase
country codes. Generated shape validation still applies to the supplied input:
leading phone whitespace fails its pattern before a replacement can commit.
Supplied full name, address line 1, city, state/region and postal code must also
remain nonempty after trimming. Rejected updates preserve the previous contact.
Normalization of the remaining optional primary fields requires further capture.

When Organizations completes `CreateAccount`, it copies the management account's
current primary contact and replaces `FullName` with the requested account name.
Alternate contacts are not copied. Membership, initial IAM roles and the primary
contact commit together; a failed completion leaves none of them published.
Subsequent contact changes in either account do not affect the other. A local
management account without a primary contact supplies no inherited contact;
initializing bootstrap accounts remains open.

## AWS evidence

The captures were taken on 2026-09-12 in a commercial AWS organization:

- [`contacts.json`](../testdata/aws/account/contacts.json) captures an absent
  alternate slot, creation, replacement, reads, deletion, repeated deletion and
  session-policy restrictions. It also records unchanged-value primary-contact
  and account-name writes; these do not establish name-change propagation.
- [`primary_contact.json`](../testdata/aws/account/primary_contact.json) records
  primary normalization, optional-field replacement and rejected updates. Private
  values are represented by equality comparisons and response field names.
- [`validation.json`](../testdata/aws/account/validation.json) captures the exact
  invalid-type error and the separate invalid-region-filter validation envelope.
  Native schema errors omit optional `reason` and `fieldList`; domain errors may
  populate them as described in the region guide.
- [`contact_origin.json`](../testdata/aws/account/contact_origin.json) compares an
  existing Organizations-created member with management. Their address and phone
  fields matched, and the member's full name matched its account name. This is a
  read-only observation of existing data, not a measurement of fresh creation or
  post-success initialization timing.

`scripts/aws/account_contacts_probe.py` uses an existing member and an absent
alternate slot, then verifies that the slot is absent again. Its synthetic email
uses `.invalid`; no primary-email verification is invoked. The primary-contact
probe restores the exact original contact and verifies restoration before
removing its private recovery file. `scripts/aws/account_validation_probe.py`
performs reads only. Fixtures omit credentials and private contact values.

Offline AWS SDK tests replay the alternate lifecycle, primary normalization
comparisons and native validation errors, and exercise primary replacement, IAM restrictions, account isolation and
Organizations inheritance. The storage test rejects account publication after
copying the contact and checks that the shared transaction rolls it back.

Primary references:

- [Primary contact management](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-primary.html)
  and [PutContactInformation](https://docs.aws.amazon.com/accounts/latest/APIReference/API_PutContactInformation.html).
- [Alternate contact management](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-alternate.html)
  and [PutAlternateContact](https://docs.aws.amazon.com/accounts/latest/APIReference/API_PutAlternateContact.html).
- [Organizations account initialization](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_create.html)
  and [CreateAccount](https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateAccount.html).
- [Account IAM actions, resources and conditions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_account.html).

## Remaining completion work

Primary-contact country/address rules, remaining optional-field normalization,
bootstrap initialization, partition behavior and full authorization/error
precedence still require conformance work. The current captures do not prove
international address acceptance, propagation timing or throttling.
[Account information/name](account-information.md) uses separate identity state;
[primary-email verification/delivery](account-primary-email.md) has its own
conformance audit. GovCloud association remains unsupported.
Organizations still needs its other account
initialization consumers, including billing and communication preferences.
