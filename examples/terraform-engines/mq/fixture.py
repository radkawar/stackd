"""Real standalone ActiveMQ5.18.7 TLS/OpenWire lifecycle for provider6.68.0.

RabbitMQ is intentionally not emulated through ActiveMQ-only MQ user APIs.
Native client libraries come only from the already installed digest-pinned image.
"""

import base64
import json
import os
from pathlib import Path
import shutil
import socket
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from common import (client, command, delete_unprivileged, denied, inspect_image,
                    password, require, tls, unprivileged)

RABBIT_IMAGE = "rabbitmq@sha256:87178a0ee3e2f52980ba356d38646ed1056705ff2d5ff281f8965456eaa0c1e3"
ACTIVE_IMAGE = "apache/activemq-classic@sha256:65814d0a18a16bef9096ce7829fcb27e501e281e0ef1064857b9eded4927508c"
USERNAME = "writer"
AUTHORITY_POLICY = "mq-native-authority"


def prepare(args, root):
    # The current MQ runtime admits both engines together and requires both
    # installed images plus the matching JDK, even for an ActiveMQ-only broker.
    inspect_image(args, RABBIT_IMAGE)
    inspect_image(args, ACTIVE_IMAGE)
    executable = str(args.java) if args.java is not None else shutil.which("java")
    require(executable is not None, "Install a Java11+ JDK or pass --java /installed/jdk/bin/java")
    java = Path(executable).resolve()
    javac = java.with_name("javac")
    require(java.is_file() and os.access(java, os.X_OK)
            and javac.is_file() and os.access(javac, os.X_OK),
            "MQ requires installed java and matching javac executables")
    cert, key = tls(root)
    native = root / "mq-native"
    native.mkdir(mode=0o700, exist_ok=True)
    libraries = root / "mq-client"
    libraries.mkdir(mode=0o700, exist_ok=True)
    temporary = command(["docker", "--host", args.docker_host, "create", "--pull=never", ACTIVE_IMAGE]).stdout.strip()
    require(temporary, "Docker did not return an owned stopped image-extraction container")
    try:
        command(["docker", "--host", args.docker_host, "cp",
                 temporary + ":/opt/apache-activemq/lib/.", libraries])
    finally:
        command(["docker", "--host", args.docker_host, "rm", "--volumes", temporary])
    source = libraries / "NativeMQ.java"
    shutil.copyfile(Path(__file__).with_name("NativeMQ.java"), source)
    command([javac, "-cp", str(libraries / "*"), "-d", libraries, source])
    (root / "mq-client.json").write_text(json.dumps({"java": str(java), "docker_host": args.docker_host}))
    return ["-docker-host", args.docker_host, "-mq-runtime",
            "-mq-state-directory", str(native), "-mq-tls-certificate", str(cert),
            "-mq-tls-key", str(key), "-mq-java", str(java)]


def _native(outputs, root, action, key="retained", payload=b"", credential=None):
    address = urlsplit(outputs["native_endpoint"])
    require(address.scheme == "ssl" and address.hostname == "127.0.0.1"
            and address.port is not None and not address.username and not address.password
            and not address.query and not address.fragment and address.path in ("", "/"),
            "Refusing a native MQ endpoint outside explicit local TLS")
    require(outputs["queue"] == outputs["broker_name"] + "-payload",
            "Refusing a queue outside this Terraform broker's exact owned name")
    configuration = json.loads((root / "mq-client.json").read_text())
    libraries = root / "mq-client"
    fields = [outputs["native_endpoint"].encode(), USERNAME.encode(),
              (password(root) if credential is None else credential).encode(),
              outputs["queue"].encode(), (root / "local.crt").read_bytes(), key.encode(), payload]
    result = command([configuration["java"], "-Xms16m", "-Xmx96m", "-cp",
                      str(libraries) + os.pathsep + str(libraries / "*"), "NativeMQ", action],
                     input="\t".join(base64.b64encode(field).decode("ascii") for field in fields) + "\n",
                     timeout=30)
    return json.loads(result.stdout)


def _payload(outputs):
    return b"stackd Terraform native MQ persistent bytes\x00\xff\n" + outputs["queue"].encode()


def _check_delivery(delivery, key, body, message_id):
    require(delivery["message_id"] == message_id and delivery["correlation_id"] == key,
            "The native broker changed the owned message identity")
    require(delivery["persistent"] and base64.b64decode(delivery["data"]) == body,
            "The native broker did not retain the exact persistent binary payload")


def _current_authority(endpoint, outputs, root):
    limited, owned = unprivileged("mq", endpoint, root)
    iam, username, _ = owned
    read = lambda: limited.describe_broker(BrokerId=outputs["broker_id"])
    installed = False
    try:
        denied(read)
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "mq:DescribeBroker", "Resource": outputs["broker_arn"]}]}
        iam.put_user_policy(UserName=username, PolicyName=AUTHORITY_POLICY,
                            PolicyDocument=json.dumps(policy))
        installed = True
        require(read()["BrokerId"] == outputs["broker_id"], "Exact broker authority did not allow its signed reader")
        policy["Statement"].append({"Effect": "Deny", "Action": "mq:DescribeBroker", "Resource": outputs["broker_arn"]})
        iam.put_user_policy(UserName=username, PolicyName=AUTHORITY_POLICY,
                            PolicyDocument=json.dumps(policy))
        # Reuse the very same signed client/key: this proves current authority,
        # not a cached creation-time permission or merely an unknown credential.
        denied(read)
    finally:
        try:
            if installed:
                iam.delete_user_policy(UserName=username, PolicyName=AUTHORITY_POLICY)
        finally:
            delete_unprivileged(owned)


def consume(endpoint, outputs, root, revision, persisted):
    require(outputs["revision"] == revision and revision in {"v1", "v2"}, "Terraform revision changed")
    require(outputs["discovered_by_id"] == outputs["broker_id"] == outputs["discovered_by_name"],
            "MQ broker data sources did not discover the Terraform-owned broker")
    require(outputs["engine_type"] == "ActiveMQ" and outputs["engine_version"] == "5.18",
            "Terraform did not select the supported pinned ActiveMQ API release")
    engines = outputs["catalogue_engine_types"]
    require(len(engines) == 1 and engines[0]["engine_type"] == "ACTIVEMQ"
            and [version["name"] for version in engines[0]["engine_versions"]] == ["5.18"],
            "MQ engine catalogue advertised unsupported releases")
    offerings = outputs["catalogue_instances"]
    require(len(offerings) == 1 and offerings[0]["host_instance_type"] == "mq.t3.micro"
            and set(offerings[0]["supported_deployment_modes"]) == {"SINGLE_INSTANCE"}
            and offerings[0]["supported_engine_versions"] == ["5.18"],
            "MQ instance catalogue advertised unsupported native topology")
    mq = client("mq", endpoint)
    described = mq.describe_broker(BrokerId=outputs["broker_id"])
    require(described["BrokerState"] == "RUNNING" and described["BrokerArn"] == outputs["broker_arn"],
            "The typed MQ owner did not expose the running Terraform broker")
    require(described["BrokerInstances"][0]["Endpoints"] == [outputs["native_endpoint"]],
            "The native endpoint changed outside the Terraform broker identity")
    current = described["Configurations"]["Current"]
    require(current["Id"] == outputs["configuration_id"]
            and current["Revision"] == outputs["configuration_revision"]
            and not described["Configurations"].get("Pending"),
            "Terraform's configuration revision was not applied by a real native reboot")
    require(described["Tags"].get("Revision") == revision, "The broker's Terraform tag update was not retained")
    configuration = mq.describe_configuration(ConfigurationId=outputs["configuration_id"])
    require(configuration["Tags"].get("Revision") == revision, "The configuration's Terraform tags were not retained")
    require(not described["AutoMinorVersionUpgrade"] and not described["Logs"]["General"]
            and not described["Logs"]["Audit"], "Default-disabled controls unexpectedly became enabled")
    negative = _native(outputs, root, "authenticate-negative", credential="wrong-" + password(root))
    require(negative.get("authentication_denied") is True, "The real TLS broker did not reject the wrong password")
    _current_authority(endpoint, outputs, root)

    marker = root / "mq-retained-message.json"
    body = _payload(outputs)
    if persisted:
        require(marker.is_file(), "Missing prior native publication; persistence must not seed a replacement payload")
        retained = json.loads(marker.read_text())
        require(retained["broker_id"] == outputs["broker_id"] and retained["queue"] == outputs["queue"]
                and retained["native_endpoint"] == outputs["native_endpoint"],
                "Reopen or update replaced the broker, destination or TLS endpoint")
        message_id = retained["message_id"]
    else:
        require(not marker.exists(), "Refusing to overwrite a prior owned native payload")
        message_id = _native(outputs, root, "publish", payload=body)["message_id"]
    delivery = _native(outputs, root, "retain")
    _check_delivery(delivery, "retained", body, message_id)
    require(delivery["user_id"] == "", "The v1 retained message gained a synthetic user-identity property")
    if not persisted:
        marker.write_text(json.dumps({"broker_id": outputs["broker_id"], "queue": outputs["queue"],
                                      "native_endpoint": outputs["native_endpoint"], "message_id": message_id}))

    # The v1 payload remains unacknowledged in the engine. A separate exact-key
    # publication proves v2's populateJMSXUserID setting is effective, not just
    # stored configuration metadata. Consume and commit only that probe payload.
    probe_key = "probe-" + revision
    probe_body = b"native configuration revision " + revision.encode()
    probe_id = _native(outputs, root, "publish", key=probe_key, payload=probe_body)["message_id"]
    probe = _native(outputs, root, "consume", key=probe_key)
    _check_delivery(probe, probe_key, probe_body, probe_id)
    require(probe["user_id"] == (USERNAME if revision == "v2" else ""),
            "The configuration update did not change the broker's real JMSXUserID stamping")
    print(f"Verified MQ {revision}: TLS/OpenWire binary publication and transactional consumption, "
          f"native wrong-password rejection, current signed authority, retained message {message_id}, "
          f"JMSXUserID={probe['user_id']!r}", flush=True)


def cleanup(endpoint, outputs, root):
    described = client("mq", endpoint).describe_broker(BrokerId=outputs["broker_id"])
    require(described["BrokerArn"] == outputs["broker_arn"]
            and described["BrokerName"] == outputs["broker_name"], "Refusing cleanup of a foreign MQ broker")
    # Delete only this exact Terraform configuration's queue. Broker/container,
    # journal volume and API configuration deletion remain Terraform-owned.
    require(_native(outputs, root, "delete").get("deleted") is True,
            "The native broker did not delete the exact owned queue")


def deleted(endpoint, outputs, root):
    mq = client("mq", endpoint)
    for operation, arguments in ((mq.describe_broker, {"BrokerId": outputs["broker_id"]}),
                                 (mq.describe_configuration, {"ConfigurationId": outputs["configuration_id"]})):
        try:
            operation(**arguments)
        except ClientError as error:
            require(error.response["Error"]["Code"] == "NotFoundException", str(error))
        else:
            raise RuntimeError("Terraform-owned MQ resource remains after destroy")
    configuration = json.loads((root / "mq-client.json").read_text())
    docker = ["docker", "--host", configuration["docker_host"]]
    label = "label=stackd.mq.arn=" + outputs["broker_arn"]
    require(not command([*docker, "container", "ls", "--all", "--quiet", "--filter", label]).stdout.strip(),
            "The exact owned native MQ container remains after destroy")
    require(not command([*docker, "volume", "ls", "--quiet", "--filter", label]).stdout.strip(),
            "The exact owned native MQ journal volume remains after destroy")
    for native in (outputs["native_endpoint"], outputs["console_url"]):
        address = urlsplit(native)
        require(address.hostname == "127.0.0.1" and address.port is not None,
                "Refusing a deletion check outside native loopback")
        with socket.socket() as connection:
            connection.settimeout(3)
            require(connection.connect_ex((address.hostname, address.port)) != 0,
                    "The deleted broker's native listener is still reachable")
    print("Verified exact broker/configuration and native container/journal/listener deletion", flush=True)
