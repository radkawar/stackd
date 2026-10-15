"""Run AWS 6.68.0 messaging lifecycles and consume real events and configuration."""

from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from queue import Empty, Queue
import shutil
import ssl
import subprocess
import sys
import threading
import time
from urllib.request import Request, urlopen
import uuid

from botocore.exceptions import ClientError
from botocore.session import get_session
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (arguments, client, controller, environment, expect_missing,
                   require, workspace)


@contextmanager
def receiver(root):
    """Trust one owned TLS consumer only in this fixture's child processes."""
    certificate, key = root / "receiver.pem", root / "receiver.key"
    require(shutil.which("openssl"), "Install OpenSSL for the owned HTTPS receiver")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        "-keyout", str(key), "-out", str(certificate)], check=True, capture_output=True)
    token, deliveries = uuid.uuid4().hex, Queue()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path != "/delivery" or self.headers.get("X-Fixture-Token") != token:
                self.send_response(403)
                self.end_headers()
                return
            deliveries.put((body, self.headers.get("X-Revision")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"accepted":true}')

        def log_message(self, *unused):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    previous = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = str(certificate)
    try:
        yield {"endpoint": f"https://127.0.0.1:{server.server_port}", "token": token, "deliveries": deliveries}
    finally:
        if previous is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = previous
        server.shutdown()
        worker.join()
        server.server_close()


def next_delivery(https):
    try:
        return https["deliveries"].get_nowait()
    except Empty:
        return None


def clock(endpoint, advance=None):
    data = None if advance is None else json.dumps({"advance": advance}).encode()
    request = Request(endpoint + "/_stackd/clock", data=data,
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def await_value(endpoint, description, read, accept, timeout=45):
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if accept(value):
            return value
        require(time.monotonic() < deadline, f"Timed out: {description}: {value}")
        clock(endpoint, "200ms")
        time.sleep(0.1)


def receive(endpoint, queue, expected):
    sqs = client("sqs", endpoint)
    messages = await_value(endpoint, f"queue payload {expected}",
                           lambda: sqs.receive_message(QueueUrl=queue, MaxNumberOfMessages=10,
                                                       MessageAttributeNames=["All"]).get("Messages", []),
                           lambda rows: bool(rows))
    require(len(messages) == 1, f"Expected one actual message: {messages}")
    message = messages[0]
    require(json.loads(message["Body"]) == expected, f"Queue payload changed: {message}")
    sqs.delete_message(QueueUrl=queue, ReceiptHandle=message["ReceiptHandle"])
    return message


def absent_message(endpoint, queue):
    messages = client("sqs", endpoint).receive_message(QueueUrl=queue).get("Messages", [])
    require(not messages, f"Unexpected queue delivery: {messages}")


def queue_identity(endpoint, queue):
    """Use the owner's ARN and AWS endpoint metadata, never the public URL as transport."""
    arn = client("sqs", endpoint).get_queue_attributes(
        QueueUrl=queue, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    prefix, partition, service, region, account, name = arn.split(":", 5)
    require(prefix == "arn" and service == "sqs" and len(account) == 12 and account.isdigit(),
            f"Unexpected queue owner identity: {arn}")
    resolved = get_session().get_component("endpoint_resolver").construct_endpoint("sqs", region)
    require(resolved and resolved["partition"] == partition and "https" in resolved["protocols"],
            f"No authoritative HTTPS SQS endpoint for {arn}")
    return f"https://{resolved['hostname']}/{account}/{name}"


def verify(endpoint, outputs, https, *, reopened=False):
    revision = outputs["revision"]
    queues = outputs["queues"]
    sqs, sns, events, iam, appconfig, data = (
        client(service, endpoint) for service in ("sqs", "sns", "events", "iam", "appconfig", "appconfigdata"))
    require(outputs["discovered_topic"] == outputs["topic_arn"], "SNS discovery changed identity")
    require(queue_identity(endpoint, outputs["discovered_queue"]) == queue_identity(endpoint, queues["sns"]["url"]),
            "SQS discovery changed identity")
    require({queue_identity(endpoint, queue) for queue in outputs["discovered_queues"]}
            == {queue_identity(endpoint, queue["url"]) for queue in queues.values()},
            "SQS list data source did not find every owned queue")
    require(outputs["discovered_app"] == outputs["application_id"], "AppConfig discovery changed identity")
    require(outputs["discovered_env"] == outputs["environment_id"]
            and outputs["discovered_envs"] == [outputs["environment_id"]], "Environment discovery differs")
    require(outputs["discovered_profile"] == outputs["profile_id"]
            and outputs["discovered_profiles"] == [outputs["profile_id"]], "Profile discovery differs")
    require({bus["name"] for bus in outputs["discovered_buses"]}
            == {outputs["bus_name"], outputs["permission_bus_name"]}, "Event bus discovery differs")

    # The subscription filter must reject another revision, not just echo it.
    sns.publish(TopicArn=outputs["topic_arn"], Message=json.dumps({"rejected": True}),
                MessageAttributes={"revision": {"DataType": "String", "StringValue": "not-this-revision"}})
    clock(endpoint, "2s")
    absent_message(endpoint, queues["sns"]["url"])
    payload = {"kind": "sns", "revision": revision, "marker": uuid.uuid4().hex}
    sns.publish(TopicArn=outputs["topic_arn"], Message=json.dumps(payload),
                MessageAttributes={"revision": {"DataType": "String", "StringValue": revision}})
    receive(endpoint, queues["sns"]["url"], payload)
    print(f"{revision}: consumed SNS to SQS with topic/queue policies and a subscription filter", flush=True)

    payload = {"kind": "events", "revision": revision, "marker": uuid.uuid4().hex}
    rejected = events.put_events(Entries=[{"EventBusName": outputs["bus_name"],
        "Source": "stackd.terraform.messaging", "DetailType": "FixtureMessage",
        "Detail": json.dumps({"revision": "not-this-revision"})}])
    require(rejected["FailedEntryCount"] == 0, f"Event admission failed: {rejected}")
    clock(endpoint, "2s")
    absent_message(endpoint, queues["events"]["url"])
    accepted = events.put_events(Entries=[{"EventBusName": outputs["bus_name"],
        "Source": "stackd.terraform.messaging", "DetailType": "FixtureMessage", "Detail": json.dumps(payload)}])
    require(accepted["FailedEntryCount"] == 0, f"Event admission failed: {accepted}")
    receive(endpoint, queues["events"]["url"], payload)
    delivered = await_value(endpoint, "authenticated HTTPS API destination",
        lambda: next_delivery(https), lambda value: value is not None)
    require(json.loads(delivered[0]) == payload and delivered[1] == revision,
            f"HTTPS destination payload/header differs: {delivered}")
    archive = await_value(endpoint, "actual event archive", lambda: events.describe_archive(
        ArchiveName=outputs["archive_name"]), lambda value: value.get("EventCount", 0) >= 1)
    require(archive["EventCount"] >= 1, "Archive did not retain an accepted matching event")
    print(f"{revision}: consumed EventBridge queue and authenticated HTTPS targets; archive retained the event", flush=True)

    payload = {"kind": "pipe", "revision": revision, "marker": uuid.uuid4().hex}
    sqs.send_message(QueueUrl=queues["source"]["url"], MessageBody=json.dumps(payload))
    receive(endpoint, queues["pipe"]["url"], payload)
    await_value(endpoint, "Pipes source acknowledgment", lambda: sqs.get_queue_attributes(
        QueueUrl=queues["source"]["url"], AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"],
        lambda attributes: all(int(value) == 0 for value in attributes.values()))
    print(f"{revision}: consumed genuine SQS Pipes source/target bytes and source acknowledgment", flush=True)

    number = outputs["deployment_number"]
    deployment = await_value(endpoint, "AppConfig rollout completion", lambda: appconfig.get_deployment(
        ApplicationId=outputs["application_id"], EnvironmentId=outputs["environment_id"], DeploymentNumber=number),
        lambda value: value["State"] == "COMPLETE")
    require(deployment["ConfigurationVersion"] == str(outputs["version_number"]), "Deployment version differs")
    token = data.start_configuration_session(ApplicationIdentifier=outputs["application_id"],
        EnvironmentIdentifier=outputs["environment_id"], ConfigurationProfileIdentifier=outputs["profile_id"],
        RequiredMinimumPollIntervalInSeconds=15)["InitialConfigurationToken"]
    current = data.get_latest_configuration(ConfigurationToken=token)
    with current["Configuration"] as stream:
        content = stream.read()
    require(json.loads(content) == {"revision": revision, "message": "Real AppConfig value", "enabled": True},
            f"Deployed AppConfig bytes differ: {content!r}")
    require(current["ContentType"] == "application/json", f"AppConfig content type differs: {current}")
    expect_missing(data.get_latest_configuration, {"BadRequestException"}, ConfigurationToken=token)
    clock(endpoint, "15s")
    unchanged = data.get_latest_configuration(ConfigurationToken=current["NextPollConfigurationToken"])
    with unchanged["Configuration"] as stream:
        require(stream.read() == b"", "AppConfig no-change poll returned configuration bytes")
    if reopened:
        absent_message(endpoint, queues["extensions"]["url"])
    else:
        notification = await_value(endpoint, "AppConfig extension delivery", lambda: sqs.receive_message(
            QueueUrl=queues["extensions"]["url"]).get("Messages", []), lambda rows: bool(rows))
        require(len(notification) == 1, f"Expected one extension delivery: {notification}")
        body = json.loads(notification[0]["Body"])
        require(body["Type"] == "OnDeploymentComplete" and body["Application"]["Id"] == outputs["application_id"]
                and body["DeploymentNumber"] == number, f"Extension payload differs: {body}")
        sqs.delete_message(QueueUrl=queues["extensions"]["url"], ReceiptHandle=notification[0]["ReceiptHandle"])
    print(f"{revision}: consumed real AppConfig bytes and one-use/no-change polling; "
          + ("reopen did not replay extension delivery" if reopened else "consumed extension delivery"), flush=True)

    # Each advance crosses only one retained occurrence. Current role authority
    # is changed after schedule admission and restored before Terraform refresh.
    clock(endpoint, "1m")
    receive(endpoint, queues["scheduler"]["url"], {"kind": "scheduler", "stage": "allowed", "revision": revision})
    original = iam.get_role_policy(RoleName=outputs["scheduler_role"], PolicyName="delivery")["PolicyDocument"]
    revoked = dict(original)
    revoked["Statement"] = [*original["Statement"], {"Effect": "Deny", "Action": "sqs:SendMessage",
                                                    "Resource": queues["scheduler"]["arn"]}]
    try:
        iam.put_role_policy(RoleName=outputs["scheduler_role"], PolicyName="delivery", PolicyDocument=json.dumps(revoked))
        clock(endpoint, "1m")
        failure = receive(endpoint, queues["dlq"]["url"], {"kind": "scheduler", "stage": "denied", "revision": revision})
        require("AccessDenied" in failure.get("MessageAttributes", {}).get("ERROR_CODE", {}).get("StringValue", ""),
                f"Scheduler DLQ omitted actual authority failure: {failure}")
        absent_message(endpoint, queues["scheduler"]["url"])
    finally:
        iam.put_role_policy(RoleName=outputs["scheduler_role"], PolicyName="delivery", PolicyDocument=json.dumps(original))
    clock(endpoint, "1m")
    receive(endpoint, queues["scheduler"]["url"], {"kind": "scheduler", "stage": "recovered", "revision": revision})
    print(f"{revision}: Scheduler timing, current-role denial, real DLQ and authority recovery", flush=True)

    pipes = client("pipes", endpoint)
    pipes.stop_pipe(Name=outputs["pipe_name"])
    await_value(endpoint, "Pipes stopped source consumer", lambda: pipes.describe_pipe(Name=outputs["pipe_name"]),
                lambda value: value["CurrentState"] == "STOPPED")
    try:
        payload = {"kind": "redrive", "revision": revision, "marker": uuid.uuid4().hex}
        sqs.send_message(QueueUrl=queues["source"]["url"], MessageBody=json.dumps(payload))
        for attempt in range(3):
            message = sqs.receive_message(QueueUrl=queues["source"]["url"],
                MessageSystemAttributeNames=["ApproximateReceiveCount"]).get("Messages", [])
            require(len(message) == 1 and json.loads(message[0]["Body"]) == payload,
                    f"Redrive source receipt {attempt + 1} differs: {message}")
            require(int(message[0]["Attributes"]["ApproximateReceiveCount"]) == attempt + 1,
                    f"Redrive source receive count differs: {message}")
            clock(endpoint, "31s")
        absent_message(endpoint, queues["source"]["url"])
        receive(endpoint, queues["dlq"]["url"], payload)
    finally:
        pipes.start_pipe(Name=outputs["pipe_name"])
        await_value(endpoint, "Pipes restarted source consumer", lambda: pipes.describe_pipe(Name=outputs["pipe_name"]),
                    lambda value: value["CurrentState"] == "RUNNING")
    print(f"{revision}: consumed actual SQS redrive after three visibility receipts; Pipes stopped and restarted", flush=True)


def verify_deleted(endpoint, outputs):
    for queue in outputs["queues"].values():
        expect_missing(client("sqs", endpoint).get_queue_attributes,
            {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}, QueueUrl=queue["url"], AttributeNames=["QueueArn"])
    expect_missing(client("sns", endpoint).get_topic_attributes, {"NotFound", "NotFoundException"}, TopicArn=outputs["topic_arn"])
    expect_missing(client("sns", endpoint).get_subscription_attributes, {"NotFound", "NotFoundException"}, SubscriptionArn=outputs["subscription_arn"])
    events = client("events", endpoint)
    for name in (outputs["bus_name"], outputs["permission_bus_name"]):
        expect_missing(events.describe_event_bus, {"ResourceNotFoundException"}, Name=name)
    expect_missing(events.describe_archive, {"ResourceNotFoundException"}, ArchiveName=outputs["archive_name"])
    expect_missing(events.describe_connection, {"ResourceNotFoundException"}, Name=outputs["connection_name"])
    expect_missing(events.describe_api_destination, {"ResourceNotFoundException"}, Name=outputs["destination_name"])
    expect_missing(client("secretsmanager", endpoint).describe_secret, {"ResourceNotFoundException"},
                   SecretId=outputs["connection_secret_arn"])
    expect_missing(client("pipes", endpoint).describe_pipe, {"NotFoundException"}, Name=outputs["pipe_name"])
    expect_missing(client("scheduler", endpoint).get_schedule_group, {"ResourceNotFoundException"}, Name=outputs["scheduler_group"])
    appconfig = client("appconfig", endpoint)
    expect_missing(appconfig.get_application, {"ResourceNotFoundException"}, ApplicationId=outputs["application_id"])
    expect_missing(appconfig.get_deployment_strategy, {"ResourceNotFoundException"}, DeploymentStrategyId=outputs["strategy_id"])
    expect_missing(appconfig.get_extension, {"ResourceNotFoundException"}, ExtensionIdentifier=outputs["extension_id"])
    expect_missing(appconfig.get_extension_association, {"ResourceNotFoundException"}, ExtensionAssociationId=outputs["association_id"])
    for suffix in ("pipes", "scheduler", "appconfig", "events"):
        expect_missing(client("iam", endpoint).get_role, {"NoSuchEntity"}, RoleName=outputs["name"] + "-" + suffix)
    expect_missing(client("iam", endpoint).get_role, {"NoSuchEntity"}, RoleName=outputs["linked_role_name"])
    print("Destroy: signed owner reads confirm queues, topics, buses, archive, pipe, group, AppConfig and roles are absent", flush=True)


def main():
    parser = arguments(__doc__, 14702)
    parser.add_argument("--provider-mirror", type=Path, help="Prepared filesystem mirror for the signed AWS 6.68.0 package")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install Terraform 1.15.9 or newer, below 2.0.0")
    root = workspace(args, "terraform-messaging")
    root.chmod(0o700)
    source = Path(__file__).resolve().parent
    for name in ("main.tf", ".terraform.lock.hcl"):
        shutil.copyfile(source / name, root / name)
    env = environment()
    configuration = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror directory does not exist")
        configuration += ("provider_installation {\n  filesystem_mirror {\n    path = "
            + json.dumps(str(args.provider_mirror.resolve()))
            + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
    cli_config = root / "terraform.rc"
    cli_config.write_text(configuration)
    env["TF_CLI_CONFIG_FILE"] = str(cli_config)

    def terraform(*command, capture=False, check=True, advance_endpoint=None):
        print("terraform", *command, flush=True)
        stop, failures = threading.Event(), []

        def advance_connection():
            events = client("events", advance_endpoint)
            while not stop.wait(0.2):
                try:
                    connection = events.describe_connection(Name=variables["name"] + "-connection")
                    if connection["ConnectionState"] not in {"CREATING", "UPDATING", "DELETING", "DEAUTHORIZING"}:
                        continue
                    now = datetime.fromisoformat(clock(advance_endpoint)["time"].replace("Z", "+00:00"))
                    # Advance only an actual asynchronous Connection transition.
                    # Never let this helper cross an untested Scheduler occurrence.
                    future = [datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
                              for value in variables.get("schedule_times", {}).values()]
                    require(not any(now < due <= now + timedelta(seconds=1) for due in future),
                            "Connection transition would cross a controlled Scheduler deadline")
                    clock(advance_endpoint, "1s")
                except ClientError as error:
                    if error.response["Error"]["Code"] == "ResourceNotFoundException":
                        continue
                    failures.append(error)
                    return
                except Exception as error:
                    failures.append(error)
                    return

        worker = None
        if advance_endpoint is not None:
            worker = threading.Thread(target=advance_connection)
            worker.start()
        command_env = env
        if command[0] == "import":
            command_env = {**env, "TF_LOG_PROVIDER": "DEBUG", "TF_LOG_PATH": str(root / "import-provider.log")}
        try:
            result = subprocess.run(["terraform", *command], cwd=root, env=command_env,
                                    check=check, text=True, capture_output=capture)
        finally:
            stop.set()
            if worker is not None:
                worker.join()
        require(not failures, f"Asynchronous Connection service-time advancement failed: {failures}")
        return result

    def outputs():
        return json.loads(terraform("output", "-json", "application", capture=True).stdout)

    strict_failures = []

    def nochange(stage):
        terraform("apply", "-refresh-only", "-input=false", "-auto-approve")
        result = terraform("plan", "-input=false", "-detailed-exitcode", "-out=nochange.tfplan", check=False)
        plan = json.loads(terraform("show", "-json", "nochange.tfplan", capture=True).stdout)
        require(result.returncode in (0, 2), f"{stage}: plan failed with exit {result.returncode}")
        require(all(change["change"]["actions"] == ["no-op"] for change in plan.get("resource_changes", []))
                and all(change["actions"] == ["no-op"] for change in plan.get("output_changes", {}).values()),
                f"{stage}: semantic changes remain in {root / 'nochange.tfplan'}")
        if result.returncode != 0:
            strict_failures.append(f"{stage}: expected a no-change plan, got exit {result.returncode}")
        terraform("apply", "-input=false", "-auto-approve", "nochange.tfplan")
        print(f"{stage}: saved-plan apply complete; detailed exit {result.returncode}", flush=True)

    def destroy(endpoint):
        state = json.loads(terraform("show", "-json", capture=True).stdout)
        managed = [resource for resource in state.get("values", {}).get("root_module", {}).get("resources", [])
                   if resource["mode"] == "managed"]
        ordinary = [resource for resource in managed if resource["type"] != "aws_iam_service_linked_role"]
        if ordinary:
            terraform("plan", "-destroy", "-input=false", "-out=ordinary-destroy.tfplan",
                      *("-target=" + resource["address"] for resource in ordinary))
            plan = json.loads(terraform("show", "-json", "ordinary-destroy.tfplan", capture=True).stdout)
            require(all(change["change"]["actions"] in (["delete"], ["no-op"])
                        and (change["type"] != "aws_iam_service_linked_role" or change["change"]["actions"] == ["no-op"])
                        for change in plan.get("resource_changes", [])),
                    "Ordinary destroy would mutate or delete the guarded service-linked role")
            terraform("apply", "-input=false", "-auto-approve", "ordinary-destroy.tfplan", advance_endpoint=endpoint)
        state = json.loads(terraform("show", "-json", capture=True).stdout)
        remaining = [resource for resource in state.get("values", {}).get("root_module", {}).get("resources", [])
                     if resource["mode"] == "managed"]
        require(all(resource["type"] == "aws_iam_service_linked_role" for resource in remaining),
                f"Ordinary destroy retained resources: {remaining}")
        # Consumers are gone: no new sessions can be issued. Respect each
        # remaining role's configured AWS maximum session duration plus one second.
        durations = [client("iam", endpoint).get_role(RoleName=resource["values"]["name"])["Role"]["MaxSessionDuration"]
                     for resource in remaining]
        if durations:
            seconds = max(durations) + 1
            print(f"Destroy: advancing owned service time {seconds}s beyond retained role session bounds", flush=True)
            clock(endpoint, f"{seconds}s")
        terraform("plan", "-destroy", "-input=false", "-out=final-destroy.tfplan")
        plan = json.loads(terraform("show", "-json", "final-destroy.tfplan", capture=True).stdout)
        require(all(change["change"]["actions"] in (["delete"], ["no-op"])
                    for change in plan.get("resource_changes", [])), "Final destroy contains non-deletion changes")
        terraform("apply", "-input=false", "-auto-approve", "final-destroy.tfplan", advance_endpoint=endpoint)

    start = datetime.now(timezone.utc).replace(microsecond=0)
    variables = {"name": "stackd-msg-" + uuid.uuid4().hex[:10]}
    # Use shared deterministic service time, not wall-clock sleeps. Customer
    # payloads still traverse the native owners and current IAM at execution.
    def phase_variables(endpoint, revision, base):
        variables.update(endpoint=endpoint, revision=revision, schedule_times={
            stage: (base + timedelta(minutes=index)).strftime("%Y-%m-%dT%H:%M:%S")
            for index, stage in enumerate(("allowed", "denied", "recovered"), 1)})
        (root / "local.auto.tfvars.json").write_text(json.dumps(variables))

    final = None
    with receiver(root) as https, ExitStack() as owned:
        endpoint = owned.enter_context(controller(args, root, extra=("-clock-start", start.isoformat())))
        variables.update(receiver_endpoint=https["endpoint"], receiver_token=https["token"])
        phase_variables(endpoint, "v1", start)
        terraform("init", "-input=false", "-lockfile=readonly")
        try:
            terraform("apply", "-input=false", "-auto-approve", advance_endpoint=endpoint)
            final = outputs()
            verify(endpoint, final, https)
            nochange("Create")
            # Import all cohort resources back into the same private state. The
            # corresponding native resources are not deleted by state rm.
            state = json.loads(terraform("show", "-json", capture=True).stdout)
            resources = [resource for resource in state["values"]["root_module"]["resources"]
                         if resource["mode"] == "managed" and not resource["type"].startswith("aws_iam_")]
            for resource in resources:
                address, identity = resource["address"], resource["values"]["id"]
                if resource["type"] == "aws_cloudwatch_event_target":
                    identity = "/".join((final["bus_name"], final["rule_name"], resource["values"]["target_id"]))
                if resource["type"].startswith("aws_sqs_queue"):
                    identity = queue_identity(endpoint, resource["values"].get("queue_url", identity))
                backup = root / "before-import.tfstate"
                backup.write_text(terraform("state", "pull", capture=True).stdout)
                terraform("state", "rm", address)
                try:
                    terraform("import", "-input=false", address, str(identity))
                except BaseException:
                    # Keep this owned resource in state so cleanup can delete it.
                    terraform("state", "push", "-force", str(backup))
                    raise
            # DescribeConnection does not expose the API-key value. Reapply that
            # write-only credential from the private configuration after import.
            terraform("apply", "-input=false", "-auto-approve", advance_endpoint=endpoint)
            nochange("Import")
            # Read the current shared clock instead of assuming the job polling
            # loops advanced it by a fixed duration.
            now = datetime.fromisoformat(clock(endpoint)["time"].replace("Z", "+00:00"))
            phase_variables(endpoint, "v2", now)
            terraform("apply", "-input=false", "-auto-approve", advance_endpoint=endpoint)
            final = outputs()
            verify(endpoint, final, https)
            nochange("Update")
            before = clock(endpoint)["time"]
            owned.close()
            endpoint = owned.enter_context(controller(args, root, extra=("-clock-start", start.isoformat())))
            require(clock(endpoint)["time"] == before, "Reopen changed the retained service timeline")
            now = datetime.fromisoformat(before.replace("Z", "+00:00"))
            phase_variables(endpoint, "v2", now)
            terraform("apply", "-input=false", "-auto-approve", advance_endpoint=endpoint)
            final = outputs()
            verify(endpoint, final, https, reopened=True)
            nochange("Reopen")
        finally:
            destroy(endpoint)
        if final is not None:
            verify_deleted(endpoint, final)
        state = json.loads(terraform("show", "-json", capture=True).stdout)
        require(not state.get("values", {}).get("root_module", {}).get("resources"),
                "Terraform state retains resources after destroy")
    require(not strict_failures, "; ".join(strict_failures))
    print(f"Messaging lifecycle complete; owned controller stopped. Private artifacts: {root}", flush=True)


if __name__ == "__main__":
    main()
