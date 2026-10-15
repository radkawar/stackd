"""Run the pinned identity lifecycle with signed consumers and owned cleanup."""

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (ACCOUNT, REGION, arguments, client, controller, environment,
                   expect_missing, local_endpoint, require, workspace)


BASE_CONTACT = {
    "FullName": "Local Before Image", "AddressLine1": "99 Local Street",
    "City": "Seattle", "CountryCode": "US", "PhoneNumber": "+12065550199",
    "PostalCode": "98101", "StateOrRegion": "WA",
}


def signed(service, endpoint, key, secret, token=None, region=REGION):
    return boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret,
                         aws_session_token=token, region_name=region).client(
        service, endpoint_url=local_endpoint(endpoint),
        config=Config(connect_timeout=3, read_timeout=60, proxies={},
                      retries={"max_attempts": 0}))


def rejected(call, codes, **kwargs):
    try:
        call(**kwargs)
    except ClientError as error:
        code = error.response["Error"]["Code"]
        require(code in codes, f"Expected {sorted(codes)}, got {code}")
    else:
        raise RuntimeError(f"Unauthorized or invalid operation succeeded: {call.__name__}")


def verify_consumers(endpoint, out, revision, contacts, previous=None):
    iam, kms, secrets, directory, account = (
        client(name, endpoint) for name in
        ("iam", "kms", "secretsmanager", "identitystore", "account"))
    reader = signed("secretsmanager", endpoint, out["reader_key"], out["reader_secret"])
    reader_kms = signed("kms", endpoint, out["reader_key"], out["reader_secret"])
    denied = signed("secretsmanager", endpoint, out["denied_key"], out["denied_secret"])
    denied_kms = signed("kms", endpoint, out["denied_key"], out["denied_secret"])

    def secret_value(consumer=reader):
        result = consumer.get_secret_value(SecretId=out["secret_arn"])
        require(result["VersionId"] == out["secret_version"], "AWSCURRENT version changed")
        require(json.loads(result["SecretString"]) == {
            "revision": revision, "payload": f"local-only-identity-{revision}"},
            "The live consumer received different secret bytes")
        require({"AWSCURRENT", f"fixture-{revision}"}.issubset(result["VersionStages"]),
                "Secret staging labels changed")

    secret_value()
    rejected(denied.get_secret_value, {"AccessDeniedException"}, SecretId=out["secret_arn"])
    rejected(signed("identitystore", endpoint, out["denied_key"], out["denied_secret"]).describe_user,
             {"AccessDeniedException"}, IdentityStoreId=out["identity_store_id"], UserId=out["directory_user"])
    rejected(signed("account", endpoint, out["denied_key"], out["denied_secret"]).get_contact_information,
             {"AccessDeniedException"})

    ciphertext = base64.b64decode(out["ciphertext"], validate=True)
    context = {"Fixture": out["name"], "Revision": revision}
    expected = f"stackd symmetric plaintext {revision}".encode()
    require(reader_kms.decrypt(CiphertextBlob=ciphertext, EncryptionContext=context)["Plaintext"] == expected,
            "The provider ciphertext did not decrypt to its actual plaintext")
    require(denied_kms.decrypt(CiphertextBlob=ciphertext, EncryptionContext=context)["Plaintext"] == expected,
            "The constrained KMS grant did not authorize a real consumer")
    rejected(reader_kms.decrypt, {"InvalidCiphertextException"}, CiphertextBlob=ciphertext,
             EncryptionContext={"Fixture": out["name"], "Revision": "wrong"})
    rejected(denied_kms.decrypt, {"AccessDeniedException"}, CiphertextBlob=ciphertext,
             EncryptionContext={"Fixture": out["name"], "Revision": "wrong"})
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    rejected(reader_kms.decrypt, {"InvalidCiphertextException"}, CiphertextBlob=tampered,
             EncryptionContext=context)

    # Current key authority must affect already-stored secrets, not just key metadata.
    kms.disable_key(KeyId=out["key_id"])
    try:
        rejected(reader.get_secret_value, {"DecryptionFailure"}, SecretId=out["secret_arn"])
        rejected(reader_kms.decrypt, {"DisabledException"}, CiphertextBlob=ciphertext,
                 EncryptionContext=context)
    finally:
        kms.enable_key(KeyId=out["key_id"])
    secret_value()
    iam.update_access_key(UserName=out["user"], AccessKeyId=out["reader_key"], Status="Inactive")
    try:
        rejected(reader.get_secret_value, {"InvalidClientTokenId", "UnrecognizedClientException"},
                 SecretId=out["secret_arn"])
    finally:
        iam.update_access_key(UserName=out["user"], AccessKeyId=out["reader_key"], Status="Active")
    secret_value()

    # Explicit current IAM denies must defeat an existing secret resource grant.
    deny_name = "fixture-current-deny"
    iam.put_user_policy(UserName=out["user"], PolicyName=deny_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Deny",
            "Action": "secretsmanager:GetSecretValue", "Resource": out["secret_arn"]}]}))
    try:
        rejected(reader.get_secret_value, {"AccessDeniedException"}, SecretId=out["secret_arn"])
    finally:
        iam.delete_user_policy(UserName=out["user"], PolicyName=deny_name)
    secret_value()

    # Consume real STS session credentials. Existing sessions use current role policies.
    session = signed("sts", endpoint, out["reader_key"], out["reader_secret"]).assume_role(
        RoleArn=out["role_arn"], RoleSessionName="fixture-consumer")["Credentials"]
    role_reader = signed("secretsmanager", endpoint, session["AccessKeyId"],
                         session["SecretAccessKey"], session["SessionToken"])
    secret_value(role_reader)
    iam.detach_role_policy(RoleName=out["role"], PolicyArn=out["policy_arn"])
    try:
        rejected(role_reader.get_secret_value, {"AccessDeniedException"}, SecretId=out["secret_arn"])
    finally:
        iam.attach_role_policy(RoleName=out["role"], PolicyArn=out["policy_arn"])
    secret_value(role_reader)
    rejected(signed("sts", endpoint, out["denied_key"], out["denied_secret"]).assume_role,
             {"AccessDenied"}, RoleArn=out["role_arn"], RoleSessionName="wrong-principal")

    role = iam.get_role(RoleName=out["role"])["Role"]
    require(role["Description"] == f"Consumer {revision}", "Role update was not retained")
    require(role["MaxSessionDuration"] == (3600 if revision == "v1" else 7200), "Role session limit changed")
    require(iam.get_instance_profile(InstanceProfileName=out["profile"])["InstanceProfile"]["Roles"][0]["Arn"] == out["role_arn"],
            "Instance profile does not point to its owned role")
    members = {user["UserName"] for user in iam.get_group(GroupName=out["group"])["Users"]}
    require(members == ({out["user"]} if revision == "v1" else set()), "Group membership update failed")
    groups = {group["GroupName"] for group in iam.list_groups_for_user(UserName=out["user"])["Groups"]}
    require(groups == ({out["group"], out["secondary_group"]} if revision == "v1" else set()),
            "User-scoped membership update failed")
    for kind, entity in (("user", out["user"]), ("group", out["group"]), ("role", out["role"])):
        key = kind.capitalize() + "Name"
        policies = getattr(iam, f"list_{kind}_policies")(**{key: entity})["PolicyNames"]
        attached = getattr(iam, f"list_attached_{kind}_policies")(**{key: entity})["AttachedPolicies"]
        require(set(policies) == {out["inline_name"]}, f"{kind} inline ownership changed")
        require({p["PolicyArn"] for p in attached} == {out["policy_arn"]}, f"{kind} managed bindings changed")
    rotation = kms.get_key_rotation_status(KeyId=out["key_id"])
    require(rotation["KeyRotationEnabled"] and rotation["RotationPeriodInDays"] == (365 if revision == "v1" else 180),
            "Rotation settings did not survive refresh")
    aliases = {a["AliasName"]: a["TargetKeyId"] for a in kms.list_aliases()["Aliases"] if "TargetKeyId" in a}
    require(aliases.get(out["alias"]) == out["alias_resolved_key"], "Alias retarget did not reach its owner")
    alias_bytes = b"consumer follows the current alias target"
    alias_blob = kms.encrypt(KeyId=out["alias"], Plaintext=alias_bytes, EncryptionContext=context)
    alias_plain = kms.decrypt(CiphertextBlob=alias_blob["CiphertextBlob"], EncryptionContext=context)
    require(alias_plain["Plaintext"] == alias_bytes and alias_plain["KeyId"].endswith("/" + out["alias_resolved_key"]),
            "Alias encryption used stale key authority")
    metadata = secrets.describe_secret(SecretId=out["secret_arn"])
    require(metadata["KmsKeyId"] == out["key_arn"] and metadata["Description"] == f"Identity secret {revision}",
            "Secret ownership or update changed")
    require({t["Key"]: t["Value"] for t in metadata["Tags"]}["ConsumerRevision"] == revision,
            "Standalone secret tag update failed")
    if previous is not None and previous["secret_version"] != out["secret_version"]:
        value = reader.get_secret_value(SecretId=out["secret_arn"], VersionId=previous["secret_version"])
        require(json.loads(value["SecretString"])["revision"] == "v1", "Historical encrypted secret bytes changed")

    user = directory.describe_user(IdentityStoreId=out["identity_store_id"], UserId=out["directory_user"])
    require(user["DisplayName"] == f"Directory {revision}" and user["Emails"][0]["Value"] == f"{revision}@example.invalid",
            "Directory user update did not reach its signed consumer")
    if contacts:
        require(user["Addresses"][0]["StreetAddress"] == ("1 Local Street" if revision == "v1" else "2 Local Street"),
                "Directory address update failed")
        require(user["PhoneNumbers"][0]["Value"] == ("+12065550101" if revision == "v1" else "+12065550102"),
                "Directory phone update failed")
    else:
        require(not user.get("Addresses") and not user.get("PhoneNumbers"), "Removed directory contacts reappeared")
    membership = directory.describe_group_membership(IdentityStoreId=out["identity_store_id"], MembershipId=out["membership"])
    require(membership["GroupId"] == out["directory_group"] and membership["MemberId"]["UserId"] == out["directory_user"],
            "Directory membership does not bind the current user and group")
    require(directory.is_member_in_groups(IdentityStoreId=out["identity_store_id"],
            MemberId={"UserId": out["directory_user"]}, GroupIds=[out["directory_group"]])["Results"][0]["MembershipExists"],
            "The live directory did not resolve the membership")
    expect_missing(directory.create_user, {"ResourceNotFoundException"}, IdentityStoreId="d-0000000000",
                   UserName="invalid-prerequisite", DisplayName="Invalid prerequisite")
    expect_missing(signed("identitystore", endpoint, "test", "test", region="us-west-2").describe_user,
                   {"ResourceNotFoundException"}, IdentityStoreId=out["identity_store_id"], UserId=out["directory_user"])
    expect_missing(signed("secretsmanager", endpoint, "test", "test", region="us-west-2").get_secret_value,
                   {"ResourceNotFoundException"}, SecretId=out["secret_arn"])
    expect_missing(signed("kms", endpoint, "test", "test", region="us-west-2").describe_key,
                   {"NotFoundException"}, KeyId=out["key_id"])
    foreign = "104857639201"
    # Cross-account secret access needs both identity and resource permission:
    # https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples_cross.html
    rejected(secrets.get_secret_value, {"AccessDeniedException"}, SecretId=out["secret_arn"].replace(ACCOUNT, foreign))
    rejected(kms.describe_key, {"NotFoundException", "AccessDeniedException"}, KeyId=out["key_arn"].replace(ACCOUNT, foreign))
    rejected(iam.get_policy, {"AccessDenied"}, PolicyArn=out["policy_arn"].replace(ACCOUNT, foreign))
    require(account.get_contact_information()["ContactInformation"]["FullName"] == f"Local Fixture {revision}",
            "Primary account contact update failed")
    require(account.get_alternate_contact(AlternateContactType="SECURITY")["AlternateContact"]["EmailAddress"] == f"{revision}@example.invalid",
            "Alternate account contact update failed")
    print(f"Consumers complete: {revision}, contacts={contacts}; secret bytes, symmetric decrypt, grants, STS, current IAM, directory and scope rejection", flush=True)


def verify_deleted(endpoint, out):
    iam, kms, secrets, directory, account = (
        client(name, endpoint) for name in
        ("iam", "kms", "secretsmanager", "identitystore", "account"))
    for user in (out["user"], out["denied_user"]):
        expect_missing(iam.get_user, {"NoSuchEntity"}, UserName=user)
    for group in (out["group"], out["secondary_group"]):
        expect_missing(iam.get_group, {"NoSuchEntity"}, GroupName=group)
    expect_missing(iam.get_role, {"NoSuchEntity"}, RoleName=out["role"])
    expect_missing(iam.get_instance_profile, {"NoSuchEntity"}, InstanceProfileName=out["profile"])
    expect_missing(iam.get_policy, {"NoSuchEntity"}, PolicyArn=out["policy_arn"])
    expect_missing(secrets.get_secret_value, {"ResourceNotFoundException"}, SecretId=out["secret_arn"])
    expect_missing(directory.describe_user, {"ResourceNotFoundException"}, IdentityStoreId=out["identity_store_id"], UserId=out["directory_user"])
    expect_missing(directory.describe_group, {"ResourceNotFoundException"}, IdentityStoreId=out["identity_store_id"], GroupId=out["directory_group"])
    expect_missing(directory.describe_group_membership, {"ResourceNotFoundException"}, IdentityStoreId=out["identity_store_id"], MembershipId=out["membership"])
    expect_missing(account.get_alternate_contact, {"ResourceNotFoundException"}, AlternateContactType="SECURITY")
    for identifier in (out["key_id"], out["alias_target_key"]):
        key = kms.describe_key(KeyId=identifier)["KeyMetadata"]
        require(key["KeyState"] == "PendingDeletion" and key["DeletionDate"], "Key deletion was not scheduled")
    require(out["alias"] not in {alias["AliasName"] for alias in kms.list_aliases()["Aliases"]}, "Alias still exists")
    require(not kms.list_grants(KeyId=out["key_id"])["Grants"], "Grant survived destroy")
    rejected(kms.decrypt, {"KMSInvalidStateException"}, CiphertextBlob=base64.b64decode(out["ciphertext"]),
             EncryptionContext={"Fixture": out["name"], "Revision": "v2"})
    rejected(signed("secretsmanager", endpoint, out["reader_key"], out["reader_secret"]).get_secret_value,
             {"InvalidClientTokenId", "UnrecognizedClientException"}, SecretId=out["secret_arn"])
    print("Deletion consumers complete; the KMS key is legally PendingDeletion, not physically deleted", flush=True)


def imports(resources):
    """Return provider-native IDs, never Terraform's generated attachment IDs."""
    for resource in resources:
        kind, out = resource["type"], resource["values"]
        if kind in {"aws_iam_access_key", "aws_iam_group_membership", "aws_kms_ciphertext"}:
            continue
        if kind == "aws_iam_group_policy_attachment":
            identifier = out["group"] + "/" + out["policy_arn"]
        elif kind.endswith("_policies_exclusive") or kind.endswith("_policy_attachments_exclusive"):
            identifier = next(out[key] for key in ("user_name", "group_name", "role_name") if key in out)
        elif kind == "aws_iam_user_group_membership":
            identifier = out["user"] + "/" + "/".join(sorted(out["groups"]))
        else:
            identifier = out["id"]
        yield resource["address"], identifier


def main():
    os.umask(0o077)
    parser = arguments(__doc__, 14701)
    parser.add_argument("--provider-mirror", type=Path,
                        help="Prepared filesystem mirror for the pinned provider; no direct download fallback")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install Terraform 1.15.9 first")
    env = environment()
    version = json.loads(subprocess.run(["terraform", "version", "-json"], env=env,
                         check=True, capture_output=True, text=True).stdout)
    require(version["terraform_version"] == "1.15.9", "This fixture requires Terraform 1.15.9")
    root = workspace(args, "terraform-identity")
    root.chmod(0o700)
    source = Path(__file__).resolve().parent
    for name in ("main.tf", ".terraform.lock.hcl"):
        shutil.copyfile(source / name, root / name)
    configuration = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror directory does not exist")
        configuration += ("provider_installation {\n filesystem_mirror {\n path = "
                          + json.dumps(str(args.provider_mirror.resolve()))
                          + '\n include = ["registry.terraform.io/hashicorp/aws"]\n }\n}\n')
    (root / "terraform.rc").write_text(configuration)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")
    stages = []

    def stage(name):
        stages.append(name)
        (root / "lifecycle.json").write_text(json.dumps({"terraform": "1.15.9", "provider": "6.68.0",
            "completed_stages": stages}, indent=2) + "\n")
        print(f"Stage complete: {name}", flush=True)

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        return subprocess.run(["terraform", command[0], "-no-color", *command[1:]]
                              if command[0] not in {"output", "show", "state"} else ["terraform", *command], cwd=root, env=env,
                              check=check, capture_output=capture, text=True)

    def output():
        value = json.loads(terraform("output", "-json", "identity", capture=True).stdout)
        (root / "outputs.json").write_text(json.dumps(value, indent=2) + "\n")
        return value

    def nochange(name):
        plan = terraform("plan", "-input=false", "-detailed-exitcode", f"-out={name}.tfplan", check=False)
        require(plan.returncode == 0, f"{name} plan is not empty: exit {plan.returncode}")
        terraform("apply", "-input=false", "-auto-approve", f"{name}.tfplan")
        stage(name)

    variables = {"name": "stackd-identity-" + uuid.uuid4().hex[:12], "account_id": ACCOUNT,
                 "revision": "v1", "contacts": True}

    def save_variables():
        (root / "local.auto.tfvars.json").write_text(json.dumps(variables))

    out = first = None
    instance = None
    terraform("init", "-input=false", "-lockfile=readonly")
    with controller(args, root) as endpoint:
        variables["endpoint"] = endpoint
        account = client("account", endpoint)
        account.put_contact_information(ContactInformation=BASE_CONTACT)
        before = account.get_contact_information()["ContactInformation"]
        sso = client("sso-admin", endpoint)
        try:
            instance = sso.create_instance(Name=variables["name"], ClientToken=uuid.uuid4().hex)["InstanceArn"]
            variables["identity_store_id"] = sso.describe_instance(InstanceArn=instance)["IdentityStoreId"]
            save_variables()
            stage("owned-identity-center-prerequisite")
            terraform("apply", "-input=false", "-auto-approve")
            out = first = output()
            verify_consumers(endpoint, out, "v1", True)
            stage("create-read-consumers")
            nochange("create-nochange")
            snapshot = json.loads(terraform("show", "-json", capture=True).stdout)
            for address, identifier in imports(snapshot["values"]["root_module"]["resources"]):
                backup = root / "before-import.tfstate"
                backup.write_text(terraform("state", "pull", capture=True).stdout)
                terraform("state", "rm", address)
                try:
                    terraform("import", "-input=false", address, identifier)
                except BaseException:
                    # Keep this owned resource in state so cleanup can delete it.
                    terraform("state", "push", "-force", str(backup))
                    raise
            # Import cannot recover provider-local deletion windows. Reconcile
            # those non-API settings once, then demand a normal empty plan.
            terraform("apply", "-input=false", "-auto-approve")
            out = output()
            verify_consumers(endpoint, out, "v1", True)
            stage("all-recoverable-resource-imports")
            nochange("import-nochange")
            variables["revision"] = "v2"
            save_variables()
            terraform("apply", "-input=false", "-auto-approve")
            out = output()
            verify_consumers(endpoint, out, "v2", True, previous=first)
            stage("update-read-consumers")
            nochange("update-nochange")
        except BaseException:
            try:
                terraform("destroy", "-input=false", "-auto-approve")
            finally:
                account.put_contact_information(ContactInformation=before)
                if instance is not None:
                    sso.delete_instance(InstanceArn=instance)
            raise
    # A new owned controller process opens the same SQLite store. No shared
    # endpoint and no test-process restart stand in for real persistence.
    with controller(args, root) as endpoint:
        account, sso = client("account", endpoint), client("sso-admin", endpoint)
        try:
            require(sso.describe_instance(InstanceArn=instance)["IdentityStoreId"] == variables["identity_store_id"],
                    "Directory prerequisite changed after reopen")
            verify_consumers(endpoint, out, "v2", True, previous=first)
            terraform("apply", "-refresh-only", "-input=false", "-auto-approve")
            nochange("retained-contact-reopen-nochange")
            variables["contacts"] = False
            save_variables()
            terraform("apply", "-input=false", "-auto-approve")
            out = output()
            verify_consumers(endpoint, out, "v2", False, previous=first)
            stage("contact-clearing")
            nochange("cleared-nochange")
        except BaseException:
            try:
                terraform("destroy", "-input=false", "-auto-approve")
            finally:
                account.put_contact_information(ContactInformation=before)
                sso.delete_instance(InstanceArn=instance)
            raise
    with controller(args, root) as endpoint:
        account, sso = client("account", endpoint), client("sso-admin", endpoint)
        try:
            require(sso.describe_instance(InstanceArn=instance)["IdentityStoreId"] == variables["identity_store_id"],
                    "Directory prerequisite changed after reopen")
            verify_consumers(endpoint, out, "v2", False, previous=first)
            terraform("apply", "-refresh-only", "-input=false", "-auto-approve")
            nochange("reopen-refresh-nochange")
        finally:
            try:
                terraform("destroy", "-input=false", "-auto-approve")
                verify_deleted(endpoint, out)
                state = json.loads(terraform("show", "-json", capture=True).stdout)
                require(not state.get("values", {}).get("root_module", {}).get("resources"),
                        "Terraform state still contains resources")
                stage("destroy-consumer-absence")
            finally:
                account.put_contact_information(ContactInformation=before)
                require(account.get_contact_information()["ContactInformation"] == before,
                        "Primary account contact before-image was not restored")
                sso.delete_instance(InstanceArn=instance)
                expect_missing(sso.describe_instance, {"ResourceNotFoundException"}, InstanceArn=instance)
                stage("restore-settings-delete-prerequisite")
    print(f"Identity lifecycle complete; controller stopped. Private local state retained: {root}", flush=True)


if __name__ == "__main__":
    main()
