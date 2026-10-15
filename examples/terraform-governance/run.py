"""Exercise pinned Terraform governance controls and their real local consumers."""

import html
from contextlib import ExitStack
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPCookieProcessor, ProxyHandler, Request
import uuid

import boto3

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (ACCOUNT, REGION, arguments, client, controller, environment,
                   expect_missing, local_endpoint, require, verify_application,
                   verify_deleted, workspace)


def credential_client(service, endpoint, credentials):
    """Use issued IAM credentials with the same local transport configuration."""
    return boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
                         aws_secret_access_key=credentials["SecretAccessKey"],
                         aws_session_token=credentials["SessionToken"],
                         region_name=REGION).client(
        service, endpoint_url=local_endpoint(endpoint),
        config=client(service, endpoint).meta.config)


class NoDifferencePlanError(RuntimeError):
    """Strict refresh-only exit2 with a saved, semantically unchanged plan."""


class Terraform:
    def __init__(self, root, env, *, revoke_ram=False):
        self.root, self.env, self.revoke_ram = root, env, revoke_ram
        self.plan_sequence = 0

    def run(self, *command, capture=False, check=True):
        print(self.root.name + ": terraform " + " ".join(command), flush=True)
        return subprocess.run(["terraform", *command], cwd=self.root, env=self.env,
                              text=True, capture_output=capture, check=check)

    def variables(self, values):
        path = self.root / "local.auto.tfvars.json"
        path.write_text(json.dumps(values) + "\n")
        path.chmod(0o600)

    def output(self):
        return json.loads(self.run("output", "-json", "governance", capture=True).stdout)

    def apply(self):
        self.run("apply", "-input=false", "-auto-approve", "-parallelism=4")
        return self.output()

    def refresh(self):
        # Aggregate computed fields change when dependent member resources are
        # created or renamed. Record that real owner read before no-change plans.
        self.run("apply", "-refresh-only", "-input=false", "-auto-approve")

    def stable(self):
        self.plan_sequence += 1
        failures = []
        for mode in ("-refresh-only", None):
            plan = self.root / f"strict-{self.plan_sequence}-{'refresh' if mode else 'normal'}.tfplan"
            command = ["plan", "-input=false", "-detailed-exitcode", "-out=" + str(plan)]
            if mode:
                command.append(mode)
            result = self.run(*command, check=False)
            if result.returncode != 0:
                require(mode == "-refresh-only" and result.returncode == 2,
                        f"{self.root.name} {mode or 'normal'} plan failed or changed: {result.returncode}")
                document = json.loads(self.run("show", "-json", str(plan), capture=True).stdout)
                changes = [row["change"] for key in ("resource_changes", "resource_drift")
                           for row in document.get(key, [])]
                changes.extend(document.get("output_changes", {}).values())
                require(not document.get("errored") and all(
                    change.get("actions") == ["no-op"] and change.get("before") == change.get("after")
                    for change in changes),
                    f"{self.root.name} refresh-only exit2 contains actual resource/output drift: {plan}")
                failures.append(f"{self.root.name} refresh-only plan exited2 without semantic changes: {plan}")
        if failures:
            raise NoDifferencePlanError("; ".join(failures))
        print(self.root.name + ": refresh and normal plans have no changes", flush=True)

    def imports(self, entries):
        for address, identity in entries:
            # Remove only this owned state entry. Import must recover the native
            # identity; no replacement or ignore_changes hides a refresh gap.
            backup = self.root / "before-import.tfstate"
            backup.write_text(self.run("state", "pull", capture=True).stdout)
            self.run("state", "rm", address)
            try:
                self.run("import", "-input=false", address, identity)
            except BaseException:
                # Keep this owned resource in state so cleanup can delete it.
                self.run("state", "push", "-force", str(backup))
                raise
        print(self.root.name + ": selected resource imports complete", flush=True)

    def destroy(self):
        if self.revoke_ram:
            # AWS does not let recipients withdraw from shares containing SSM
            # parameters. Revoke the owner's resource grant before the provider
            # deletes the recipient accepter; do not weaken that service rule.
            state = json.loads(self.run("show", "-json", capture=True).stdout)
            resources = state.get("values", {}).get("root_module", {}).get("resources", [])
            share = next((row["values"]["arn"] for row in resources
                          if row["address"] == "aws_ram_resource_share.external"), None)
            if share:
                endpoint = json.loads((self.root / "local.auto.tfvars.json").read_text())["endpoint"]
                ram = client("ram", endpoint)
                associations = ram.get_resource_share_associations(
                    associationType="RESOURCE", resourceShareArns=[share])["resourceShareAssociations"]
                arns = [row["associatedEntity"] for row in associations if row["status"] == "ASSOCIATED"]
                if arns:
                    ram.disassociate_resource_share(resourceShareArn=share, resourceArns=arns)
                remaining = ram.get_resource_share_associations(
                    associationType="RESOURCE", resourceShareArns=[share])["resourceShareAssociations"]
                require(not any(row["status"] == "ASSOCIATED" for row in remaining),
                        "Owner RAM resource revocation did not complete before accepter cleanup")
        self.run("destroy", "-input=false", "-auto-approve", "-parallelism=4")
        state = json.loads(self.run("show", "-json", capture=True).stdout)
        require(not state.get("values", {}).get("root_module", {}).get("resources"),
                self.root.name + ": state still contains resources after destroy")


def assume_member(endpoint, account, role="OrganizationAccountAccessRole"):
    credentials = client("sts", endpoint).assume_role(
        RoleArn=f"arn:aws:iam::{account}:role/{role}",
        RoleSessionName="terraform-governance", DurationSeconds=3600)["Credentials"]
    identity = credential_client("sts", endpoint, credentials).get_caller_identity()
    require(identity["Account"] == account and f":assumed-role/{role}/" in identity["Arn"],
            "Organizations did not provision a real usable member access role")
    return credentials


def external_account(endpoint, name):
    organizations = client("organizations", endpoint)
    request = organizations.create_account(AccountName=name + "-external",
        Email=name + "-external@example.invalid", RoleName="GovernanceAccess")["CreateAccountStatus"]
    deadline = time.monotonic() + 60
    while request["State"] == "IN_PROGRESS":
        require(time.monotonic() < deadline, "External account provisioning did not complete")
        time.sleep(0.25)
        request = organizations.describe_create_account_status(
            CreateAccountRequestId=request["Id"])["CreateAccountStatus"]
    require(request["State"] == "SUCCEEDED", "External account real provisioning failed: " + str(request))
    account = request["AccountId"]
    try:
        credentials = assume_member(endpoint, account, "GovernanceAccess")
    finally:
        # This native seed is not in Terraform state. Remove membership even if
        # the real access-role consumer fails before returning credentials.
        organizations.remove_account_from_organization(AccountId=account)
    expect_missing(organizations.describe_account, {"AccountNotFoundException"}, AccountId=account)
    require(credential_client("sts", endpoint, credentials).get_caller_identity()["Account"] == account,
            "Removing organization membership incorrectly removed the real standalone account")
    print("Seeded an independent external recipient through real IAM account provisioning", flush=True)
    return account, credentials


def wait_effective_tag_policy(endpoint):
    organizations = client("organizations", endpoint)
    deadline = time.monotonic() + 60
    while True:
        try:
            response = organizations.describe_effective_policy(PolicyType="TAG_POLICY")
            policy = json.loads(response["EffectivePolicy"]["PolicyContent"])
            if "fixture" in policy.get("tags", {}):
                return
        except organizations.exceptions.EffectivePolicyNotFoundException:
            pass
        require(time.monotonic() < deadline, "Required tag policy publication did not reach the actual policy reader")
        time.sleep(0.25)


def directory(endpoint, name, seeds):
    ssoadmin, store, cognito = (client(service, endpoint) for service in
                              ("sso-admin", "identitystore", "cognito-idp"))
    instance = ssoadmin.create_instance(Name=name)["InstanceArn"]
    seeds.callback(ssoadmin.delete_instance, InstanceArn=instance)
    instances = ssoadmin.list_instances()["Instances"]
    store_id = next(value["IdentityStoreId"] for value in instances if value["InstanceArn"] == instance)
    username = name + "-user"
    user = store.create_user(IdentityStoreId=store_id, UserName=username,
        DisplayName="Governance consumer", Name={"GivenName": "Governance", "FamilyName": "Consumer"})["UserId"]
    seeds.callback(store.delete_user, IdentityStoreId=store_id, UserId=user)
    group = store.create_group(IdentityStoreId=store_id, DisplayName=name + "-group")["GroupId"]
    seeds.callback(store.delete_group, IdentityStoreId=store_id, GroupId=group)
    membership = store.create_group_membership(IdentityStoreId=store_id,
        GroupId=group, MemberId={"UserId": user})["MembershipId"]
    seeded = {"membership": membership}
    seeds.callback(lambda: store.delete_group_membership(
        IdentityStoreId=store_id, MembershipId=seeded["membership"]))
    pool = cognito.create_user_pool(PoolName=name)["UserPool"]["Id"]
    seeds.callback(cognito.delete_user_pool, UserPoolId=pool)
    app = cognito.create_user_pool_client(UserPoolId=pool, ClientName=name,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])["UserPoolClient"]["ClientId"]
    password = "Governance-" + uuid.uuid4().hex + "!2"
    cognito.admin_create_user(UserPoolId=pool, Username=username, MessageAction="SUPPRESS")
    cognito.admin_set_user_password(UserPoolId=pool, Username=username, Password=password, Permanent=True)
    seeded.update({"instance": instance, "store": store_id, "user": user, "group": group,
                   "pool": pool, "client": app, "username": username, "password": password})
    return seeded


def portal_session(endpoint, seeded):
    oidc = client("sso-oidc", endpoint)
    registered = oidc.register_client(clientName="Terraform governance consumer",
        clientType="public", scopes=["sso:account:access"],
        grantTypes=["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"])
    instance_id = seeded["instance"].rsplit("/", 1)[-1]
    device = oidc.start_device_authorization(clientId=registered["clientId"],
        clientSecret=registered["clientSecret"],
        startUrl="https://identitycenter.amazonaws.com/" + instance_id)
    url = device["verificationUriComplete"]
    require(url.startswith(endpoint + "/_stackd/sso/"), "OIDC verification left the owned listener")
    browser = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
    with browser.open(url, timeout=20) as response:
        page = response.read().decode()
    hidden = dict((key, html.unescape(value)) for key, value in
                  re.findall(r'type="hidden" name="([^"]+)" value="([^"]*)"', page))
    require(hidden.get("csrf") and hidden.get("user_code") == device["userCode"],
            "Device form did not bind the real request and CSRF token")
    hidden.update(username=seeded["username"], password=seeded["password"], decision="approve")
    request = Request(endpoint + "/_stackd/sso/device", data=urlencode(hidden).encode(),
                      headers={"Origin": endpoint, "Content-Type": "application/x-www-form-urlencoded"})
    with browser.open(request, timeout=20) as response:
        require(response.status == 200, "Cognito-backed authorization form did not succeed")
    time.sleep(device.get("interval", 5))
    token = oidc.create_token(clientId=registered["clientId"], clientSecret=registered["clientSecret"],
        grantType="urn:ietf:params:oauth:grant-type:device_code", deviceCode=device["deviceCode"])
    # Bearer values are held only in memory, never in evidence or a CLI cache.
    return token["accessToken"]


def verify_organization(endpoint, name, output, revision, credentials):
    organizations = client("organizations", endpoint)
    parent = output["parent"] if revision == "one" else output["child"]
    for account, expected_name in zip(output["members"], output["member_names"]):
        current = organizations.describe_account(AccountId=account)["Account"]
        require(current["Name"] == expected_name and current["State"] == "ACTIVE", "Account name/state is not current")
        require(organizations.list_parents(ChildId=account)["Parents"][0]["Id"] == parent,
                "Terraform account move did not reach live Organizations state")
    require(set(output["descendant_accounts"]) == set(output["members"]), "Descendant discovery missed members")
    require(set(output["child_accounts"]) == (set() if revision == "one" else set(output["members"])),
            "Child-account discovery did not follow the move")
    require(parent in output["entity_path"] and output["policy"] in output["policy_targets"],
            "Terraform policy/path data sources did not read the native owner")
    s3 = credential_client("s3", endpoint, credentials[0])
    bucket = name + "-member"
    if revision == "one":
        expect_missing(s3.put_object, {"AccessDenied"}, Bucket=bucket, Key="scp", Body=b"denied")
    else:
        s3.put_object(Bucket=bucket, Key="scp", Body=b"current policy")
        expect_missing(s3.delete_object, {"AccessDenied"}, Bucket=bucket, Key="scp")
    first = {row["Name"] for row in s3.list_buckets()["Buckets"]}
    second = {row["Name"] for row in credential_client("s3", endpoint, credentials[1]).list_buckets()["Buckets"]}
    require(bucket in first and name + "-other" not in first and name + "-other" in second and bucket not in second,
            "Member account resource discovery is not isolated")
    delegated = credential_client("organizations", endpoint, credentials[1]).list_accounts()["Accounts"]
    require({row["Id"] for row in delegated} == {ACCOUNT, *output["members"]},
            "Organizations resource policy did not authorize the actual delegated reader")
    print("Verified " + revision + ": account names/moves, two real isolated identities, current SCP and delegation", flush=True)


def verify_controls(endpoint, name, output, revision, member, external, token):
    verify_application(endpoint, output, revision)
    ssm = client("ssm", endpoint)
    schema = json.loads(output["registry_schema"])
    require(schema["typeName"] == "AWS::SSM::Parameter" and schema["primaryIdentifier"] == ["/properties/Name"],
            "Default Cloud Control schema discovery did not return the actual registry contract")
    native_type = client("cloudformation", endpoint).describe_type(Arn=output["registry_type_arn"])
    require(json.loads(native_type["Schema"]) == schema and "DefaultVersionId" not in native_type,
            "DescribeType changed the schema or fabricated a public private-registration version")
    require(ssm.get_parameter(Name="/" + name + "/reference")["Parameter"]["Value"] == output["parameter_name"],
            "CloudFormation ImportValue did not reach a native parameter")
    require(output["exported_parameter"] == output["parameter_name"], "Terraform export lookup disagrees with the owner")
    require(ssm.get_parameter(Name=output["cloudcontrol_parameter"])["Parameter"]["Value"] == revision,
            "Cloud Control did not update its native SSM resource")
    for credentials, parameter in ((member, output["parameter_name"]), (external, output["cloudcontrol_parameter"])):
        arn = f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter" + parameter
        actual = credential_client("ssm", endpoint, credentials).get_parameter(Name=arn)["Parameter"]
        require(actual["Value"] == revision, "Accepted RAM share did not authorize real cross-account parameter bytes")
    expect_missing(credential_client("ssm", endpoint, member).get_parameter, {"AccessDeniedException"},
                   Name=f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter" + output["cloudcontrol_parameter"])
    groups = client("resource-groups", endpoint)
    stack_group = groups.get_group(Group=output["stack_group"])["Group"]
    require(stack_group["Description"] == "Current owner " + revision,
            "SDK stack-query description update/reopen did not reach the actual group")
    stack_query = groups.get_group_query(Group=output["stack_group"])["GroupQuery"]["ResourceQuery"]
    require(stack_query["Type"] == "CLOUDFORMATION_STACK_1_0" and
            json.loads(stack_query["Query"]) == {"ResourceTypeFilters": ["AWS::AllSupported"],
                                                "StackIdentifier": output["stack"]},
            "SDK stack-query group did not retain the live CloudFormation owner query")
    expected = {"arn:aws:s3:::" + output["bucket"], output["queue_arn"],
                f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter" + output["parameter_name"]}
    for group in (output["tag_group"], output["stack_group"]):
        resources = groups.list_group_resources(Group=group)["Resources"]
        require(expected <= {row["Identifier"]["ResourceArn"] for row in resources}, "Group missed real live owner resources")
    tagged = {row["resource_arn"] for row in output["tagged_resources"]}
    require(expected <= tagged, "Terraform Tagging API data source missed real tagged native resources")
    app_members = groups.list_group_resources(Group=output["application_group"])["Resources"]
    require(output["queue_arn"] in {row["Identifier"]["ResourceArn"] for row in app_members},
            "Terraform application membership was metadata only")
    queue_tags = client("sqs", endpoint).list_queue_tags(QueueUrl=output["queue_url"])["Tags"]
    require(queue_tags["awsApplication"] == output["application_group"], "Grouping did not reach the actual SQS tag owner")
    registry = client("servicecatalog-appregistry", endpoint)
    attributes = registry.get_attribute_group(attributeGroup=output["attribute_group"])["attributes"]
    require(json.loads(attributes)["revision"] == revision, "Attribute group updates are not current")
    required = {row["resource_type"]: row["reporting_tag_keys"] for row in output["required_tags"]}
    require("Fixture" in required.get("s3:bucket", []) and "Fixture" in required.get("sqs:queue", []),
            "Terraform required-tags data source did not consume the actual published Organizations tag policy")
    portal = client("sso", endpoint)
    accounts = portal.list_accounts(accessToken=token)["accountList"]
    require({row["accountId"] for row in accounts} == {ACCOUNT, member["Account"]}, "SSO portal ignored real assignments")
    for account in (ACCOUNT, member["Account"]):
        roles = portal.list_account_roles(accessToken=token, accountId=account)["roleList"]
        require(output["permission_name"] in {row["roleName"] for row in roles}, "SSO role discovery missed provisioning")
        role = portal.get_role_credentials(accessToken=token, accountId=account,
                                           roleName=output["permission_name"])["roleCredentials"]
        credentials = {"AccessKeyId": role["accessKeyId"], "SecretAccessKey": role["secretAccessKey"], "SessionToken": role["sessionToken"]}
        identity = credential_client("sts", endpoint, credentials).get_caller_identity()
        require(identity["Account"] == account and ":assumed-role/AWSReservedSSO_" in identity["Arn"],
                "SSO portal did not issue real protected IAM-role credentials")
        iam = client("iam", endpoint) if account == ACCOUNT else credential_client("iam", endpoint, member)
        role_name = identity["Arn"].split("/")[-2]
        native_role = iam.get_role(RoleName=role_name)["Role"]
        require(native_role["MaxSessionDuration"] == (3600 if revision == "one" else 7200),
                "Permission-set duration update did not reach the real provisioned IAM role")
        expect_missing(iam.update_assume_role_policy, {"UnmodifiableEntity"}, RoleName=role_name,
                       PolicyDocument=json.dumps(native_role["AssumeRolePolicyDocument"]))
        if account == ACCOUNT:
            s3 = credential_client("s3", endpoint, credentials)
            key = "sso/" + revision + "/bytes"
            try:
                s3.put_object(Bucket=output["bucket"], Key=key, Body=b"real Identity Center consumer")
                stream = client("s3", endpoint).get_object(Bucket=output["bucket"], Key=key)["Body"]
                try:
                    require(stream.read() == b"real Identity Center consumer", "SSO identity did not write actual object bytes")
                finally:
                    stream.close()
                previous = "two" if revision == "one" else "one"
                expect_missing(s3.put_object, {"AccessDenied"}, Bucket=output["bucket"],
                               Key="sso/" + previous + "/denied", Body=b"denied")
            finally:
                client("s3", endpoint).delete_object(Bucket=output["bucket"], Key=key)
    print("Verified " + revision + ": native CFN/Cloud Control effects, RAM bytes, owner discovery, AppRegistry and SSO IAM consumers", flush=True)

def native_stack_group(endpoint, name, output, seeds):
    """Supplement the provider's TAG_FILTERS_1_0-only query schema through SDK."""
    groups = client("resource-groups", endpoint)
    query = {"Type": "CLOUDFORMATION_STACK_1_0", "Query": json.dumps({
        "ResourceTypeFilters": ["AWS::AllSupported"], "StackIdentifier": output["stack"]})}
    group = groups.create_group(Name=name + "-stack", Description="Current owner one",
                                ResourceQuery=query)["Group"]["GroupArn"]
    seeds.callback(groups.delete_group, Group=group)
    require(groups.get_group_query(Group=group)["GroupQuery"]["ResourceQuery"] == query,
            "SDK stack-query group did not retain the actual CloudFormation owner query")
    return group


def record_stability(evidence, *cohorts):
    failures = []
    for cohort in cohorts:
        try:
            cohort.stable()
        except NoDifferencePlanError as error:
            failures.append(str(error))
    evidence.setdefault("strict_plan_failures", []).extend(failures)
    return not failures



def cleanup_failed_create(error, organization, seeds, controls=None):
    # Keep the original failure. Never remove organization membership or native
    # identity seeds while dependent SSO/RAM controls still need them to delete.
    actions = ([("controls destroy", controls.destroy)] if controls else []) + [
        ("organization destroy", organization.destroy), ("native seed cleanup", seeds.close)]
    for label, cleanup in actions:
        try:
            cleanup()
        except BaseException as cleanup_error:
            message = f"{label} failed: {cleanup_error}"
            error.add_note(message)
            print(message, file=sys.stderr, flush=True)
            if label == "controls destroy":
                message = "Preserving organization and native seeds until dependent controls can be destroyed"
                error.add_note(message)
                print(message, file=sys.stderr, flush=True)
                return


def delete_seed_bucket(endpoint, credentials, bucket):
    s3 = credential_client("s3", endpoint, credentials)
    s3.delete_object(Bucket=bucket, Key="scp")
    s3.delete_bucket(Bucket=bucket)


def main():
    os.umask(0o077)
    parser = arguments(__doc__, 14708)
    parser.add_argument("--provider-mirror", type=Path, help="Prepared filesystem mirror for hashicorp/aws 6.68.0")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install Terraform >= 1.5, < 2 first")
    root = workspace(args, "terraform-governance")
    root.chmod(0o700)
    env = environment()
    config = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror directory does not exist")
        config += ("provider_installation {\n  filesystem_mirror {\n    path = "
                   + json.dumps(str(args.provider_mirror.resolve()))
                   + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
    (root / "terraform.rc").write_text(config)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")
    fixtures = Path(__file__).resolve().parent
    for cohort in ("organization", "controls"):
        shutil.copytree(fixtures / cohort, root / cohort)
        (root / cohort).chmod(0o700)
    organization = Terraform(root / "organization", env)
    controls = Terraform(root / "controls", env, revoke_ram=True)
    name = "gov-" + uuid.uuid4().hex[:12]
    evidence = {"provider": "6.68.0", "terraform": subprocess.run(["terraform", "version", "-json"],
        env=env, capture_output=True, check=True, text=True).stdout, "stages": [],
        "native_aws_mutations": False, "browser": "HTTP form with real Cognito authentication; not AWS CLI/browser parity"}
    org_values, control_values = None, None
    org_output, output, seeded, credentials, external_credentials = None, None, None, [], None
    seeds = ExitStack()
    completed = False
    with controller(args, root) as endpoint:
        try:
            org_values = {"endpoint": endpoint, "name": name, "revision": "one", "bootstrap": True}
            organization.variables(org_values)
            organization.run("init", "-input=false")
            # The pinned provider's create path redundantly enables configured
            # SCP. Create the native default, then manage policies by update from
            # the actual read state. No error suppression or drift masking.
            organization.run("apply", "-input=false", "-auto-approve",
                             "-target=aws_organizations_organization.proof")
            org_values["bootstrap"] = False
            organization.variables(org_values)
            org_output = organization.apply()
            wait_effective_tag_policy(endpoint)
            credentials = [assume_member(endpoint, account) for account in org_output["members"]]
            for index, suffix in enumerate(("member", "other")):
                bucket = name + "-" + suffix
                credential_client("s3", endpoint, credentials[index]).create_bucket(Bucket=bucket)
                seeds.callback(delete_seed_bucket, endpoint, credentials[index], bucket)
            external, external_credentials = external_account(endpoint, name)
            seeded = directory(endpoint, name, seeds)
            read_policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}]})
            for credentials_for_policy in (None, credentials[1]):
                iam = client("iam", endpoint) if credentials_for_policy is None else credential_client("iam", endpoint, credentials_for_policy)
                policy = iam.create_policy(PolicyName=name + "-customer", PolicyDocument=read_policy)["Policy"]["Arn"]
                seeds.callback(iam.delete_policy, PolicyArn=policy)
            seed_parameter = "/" + name + "/seed"
            ssm = client("ssm", endpoint)
            ssm.put_parameter(Name=seed_parameter, Type="String", Value="one")
            seeds.callback(ssm.delete_parameter, Name=seed_parameter)
            ssm.put_parameter(Name=seed_parameter, Type="String", Value="two", Overwrite=True)
            control_values = {"endpoint": endpoint, "name": name, "revision": "one", "owner_account": ACCOUNT,
                "member_account": org_output["members"][1], "external_account": external,
                "instance_arn": seeded["instance"], "group_id": seeded["group"], "seed_parameter": seed_parameter,
                "external_credentials": {"access_key": external_credentials["AccessKeyId"],
                    "secret_key": external_credentials["SecretAccessKey"], "token": external_credentials["SessionToken"]}}
            controls.variables(control_values)
            controls.run("init", "-input=false")
            evidence["stages"].append("organization-default-create-policy-update-and-real-IAM-seeds")
        except BaseException as error:
            cleanup_failed_create(error, organization, seeds)
            raise
    # Reopen the same SQLite state with the explicit Cognito login dependency.
    with controller(args, root, extra=("-sso-user-pool-client-id", seeded["client"])) as endpoint:
        try:
            output = controls.apply()
            stack_group = native_stack_group(endpoint, name, output, seeds)
            output["stack_group"] = stack_group
            token = portal_session(endpoint, seeded)
            member = dict(credentials[1], Account=org_output["members"][1])
            verify_organization(endpoint, name, org_output, "one", credentials)
            verify_controls(endpoint, name, output, "one", member, external_credentials, token)
            store = client("identitystore", endpoint)
            store.delete_group_membership(IdentityStoreId=seeded["store"], MembershipId=seeded["membership"])
            try:
                require(not client("sso", endpoint).list_accounts(accessToken=token)["accountList"],
                        "SSO portal retained access after actual group membership removal")
                expect_missing(client("sso", endpoint).get_role_credentials, {"UnauthorizedException"},
                               accessToken=token, accountId=ACCOUNT, roleName=output["permission_name"])
            finally:
                seeded["membership"] = store.create_group_membership(IdentityStoreId=seeded["store"],
                    GroupId=seeded["group"], MemberId={"UserId": seeded["user"]})["MembershipId"]
            evidence["stages"].append("current-directory-membership-revocation")
            organization.refresh()
            controls.refresh()
            stable = record_stability(evidence, organization, controls)
            evidence["stages"].append("create-consumers-refresh-noop" if stable else "create-consumers-strict-plan-failure")
            organization.imports([
                ("aws_organizations_organization.proof", org_output["organization"]),
                ("aws_organizations_organizational_unit.parent", org_output["parent"]),
                ("aws_organizations_account.member[0]", org_output["members"][0]),
                ("aws_organizations_policy.deny", org_output["policy"])])
            controls.imports([
                ("aws_cloudformation_stack.native", output["stack"]),
                ("aws_ram_resource_share.member", output["member_share"]),
                ("aws_ram_resource_share_accepter.external", output["external_share"]),
                ("aws_ssoadmin_permission_set.proof", output["permission_set"] + "," + seeded["instance"]),
                ("aws_resourcegroups_group.tags", output["tag_group"]),
                ("aws_servicecatalogappregistry_application.proof", output["application"]),
                ("aws_servicecatalogappregistry_attribute_group.proof", output["attribute_group"])])
            stable = record_stability(evidence, organization, controls)
            evidence["stages"].append("selected-imports-refresh-noop" if stable else "selected-imports-strict-plan-failure")
            org_values["revision"] = control_values["revision"] = "two"
            organization.variables(org_values)
            controls.variables(control_values)
            org_output = organization.apply()
            wait_effective_tag_policy(endpoint)
            output = controls.apply()
            output["stack_group"] = stack_group
            client("resource-groups", endpoint).update_group(Group=stack_group, Description="Current owner two")
            verify_organization(endpoint, name, org_output, "two", credentials)
            verify_controls(endpoint, name, output, "two", member, external_credentials, token)
            organization.refresh()
            controls.refresh()
            stable = record_stability(evidence, organization, controls)
            evidence["stages"].append("update-consumers-refresh-noop" if stable else "update-consumers-strict-plan-failure")
        except BaseException as error:
            cleanup_failed_create(error, organization, seeds, controls)
            raise
    with controller(args, root, extra=("-sso-user-pool-client-id", seeded["client"])) as endpoint:
        try:
            token = portal_session(endpoint, seeded)
            member = dict(credentials[1], Account=org_output["members"][1])
            verify_organization(endpoint, name, org_output, "two", credentials)
            verify_controls(endpoint, name, output, "two", member, external_credentials, token)
            stable = record_stability(evidence, organization, controls)
            evidence["stages"].append("SQLite-controller-restart-consumers-refresh-noop" if stable else
                                      "SQLite-controller-restart-consumers-strict-plan-failure")
        finally:
            controls.destroy()
            try:
                organization.destroy()
            finally:
                seeds.close()
        verify_deleted(endpoint, output)
        expect_missing(client("ssm", endpoint).get_parameter, {"ParameterNotFound"}, Name=output["cloudcontrol_parameter"])
        expect_missing(client("ssm", endpoint).get_parameter, {"ParameterNotFound"}, Name="/" + name + "/reference")
        expect_missing(client("sso-admin", endpoint).describe_permission_set, {"ResourceNotFoundException"},
                       InstanceArn=seeded["instance"], PermissionSetArn=output["permission_set"])
        expect_missing(client("servicecatalog-appregistry", endpoint).get_application, {"ResourceNotFoundException"}, application=output["application"])
        expect_missing(client("resource-groups", endpoint).get_group, {"NotFoundException"}, Group=output["application_group"])
        expect_missing(client("resource-groups", endpoint).get_group, {"NotFoundException"}, Group=stack_group)
        shares = client("ram", endpoint).get_resource_shares(resourceOwner="SELF")["resourceShares"]
        require({row["resourceShareArn"] for row in shares} ==
                {output["member_share"], output["external_share"]} and
                all(row["status"] == "DELETED" for row in shares),
                "Owned RAM shares did not reach deleted tombstones after destroy")
        expect_missing(client("organizations", endpoint).describe_organization, {"AWSOrganizationsNotInUseException"})
        evidence["stages"].append("destroy-native-absence-and-seed-cleanup")
        completed = True
    require(completed, "Governance lifecycle did not complete")
    (root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    require(not evidence.get("strict_plan_failures"),
            "Governance consumers and cleanup completed, but strict Terraform plans failed: "
            + "; ".join(evidence.get("strict_plan_failures", [])))
    print("Governance lifecycle complete. Private owned state: " + str(root), flush=True)


if __name__ == "__main__":
    main()
