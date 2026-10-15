"""Use Terraform-owned real Kafka brokers, SCRAM, EC2 policy and native records."""

from datetime import datetime
import errno
import hashlib
import ipaddress
import json
import socket
import ssl
import time
import uuid
from urllib.request import Request, urlopen

from botocore.exceptions import ClientError
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer, TopicPartition
from confluent_kafka.admin import AdminClient, ConfigResource, ResourceType

from common import (KAFKA_IMAGE, client, command, delete_unprivileged, denied,
                    inspect_image, password, require, unprivileged)

TOOLKIT_IMAGE = "nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61"


def prepare(args, root):
    inspect_image(args, KAFKA_IMAGE)
    inspect_image(args, TOOLKIT_IMAGE)
    (root / "docker-host").write_text(args.docker_host)
    return ["-docker-host", args.docker_host, "-msk-runtime"]


def before_apply(endpoint, root, terraform, variables):
    """Use real Terraform network prerequisites to exercise denied automatic IAM."""
    terraform("apply", "-input=false", "-auto-approve", "-target=aws_vpc.native",
              "-target=aws_subnet.native", "-target=aws_security_group.native")
    state = json.loads(terraform("show", "-json", capture=True).stdout)
    resources = state["values"]["root_module"]["resources"]
    subnets = [row["values"]["id"] for row in resources if row["type"] == "aws_subnet"]
    group = next(row["values"]["id"] for row in resources if row["address"] == "aws_security_group.native")
    iam, kafka = client("iam", endpoint), client("kafka", endpoint)
    try:
        iam.get_role(RoleName="AWSServiceRoleForKafka")
    except ClientError as error:
        require(error.response["Error"]["Code"] == "NoSuchEntity", str(error))
    else:
        raise RuntimeError("Isolated fixture unexpectedly has a Kafka service-linked role before creation")
    unauthorized, owned = unprivileged("kafka", endpoint, root)
    iam, user, access_key = owned
    name = variables["name"]+"-denied"
    account = client("sts", endpoint).get_caller_identity()["Account"]
    try:
        iam.put_user_policy(UserName=user, PolicyName="owned-create", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "kafka:CreateCluster",
            "Resource": f"arn:aws:kafka:us-east-1:{account}:cluster/{name}/*"}]}))
        try:
            created = unauthorized.create_cluster(ClusterName=name, KafkaVersion="3.7.1", NumberOfBrokerNodes=2,
                BrokerNodeGroupInfo={"InstanceType": "kafka.local", "ClientSubnets": subnets,
                    "SecurityGroups": [group], "BrokerAZDistribution": "DEFAULT"}, EnhancedMonitoring="DEFAULT")
        except ClientError as error:
            rejection = error.response["Error"]["Code"]
            require("AccessDenied" in rejection or rejection == "ForbiddenException", str(error))
        else:
            kafka.delete_cluster(ClusterArn=created["ClusterArn"])
            deadline = time.monotonic()+180
            while True:
                try:
                    kafka.describe_cluster(ClusterArn=created["ClusterArn"])
                except ClientError as error:
                    require(error.response["Error"]["Code"] == "NotFoundException", str(error))
                    break
                require(time.monotonic() < deadline, "Unexpectedly admitted negative-test cluster did not clean up")
                time.sleep(0.25)
            role_deletion(endpoint, "SUCCEEDED")
            raise RuntimeError("Kafka caller without iam:CreateServiceLinkedRole created a managed cluster")
        events = client("cloudtrail", endpoint).lookup_events(LookupAttributes=[
            {"AttributeKey": "AccessKeyId", "AttributeValue": access_key}])["Events"]
        documents = [json.loads(event["CloudTrailEvent"]) for event in events]
        iam_rejection = next((index for index, event in enumerate(documents)
            if event["eventSource"] == "iam.amazonaws.com" and event["eventName"] == "CreateServiceLinkedRole"
            and event.get("errorCode") == "AccessDenied"), None)
        kafka_rejection = next((index for index, event in enumerate(documents)
            if event["eventSource"] == "kafka.amazonaws.com" and event["eventName"] == "CreateCluster"
            and event.get("errorCode") == rejection), None)
        require(iam_rejection is not None and kafka_rejection is not None and kafka_rejection < iam_rejection,
                "Rolled-back automatic IAM rejection was not retained before the parent Kafka rejection")
        require(not kafka.list_clusters(ClusterNameFilter=name).get("ClusterInfoList", []),
                "Denied automatic role creation committed a Kafka cluster")
        try:
            iam.get_role(RoleName="AWSServiceRoleForKafka")
        except ClientError as error:
            require(error.response["Error"]["Code"] == "NoSuchEntity", str(error))
        else:
            raise RuntimeError("Denied automatic role creation committed its IAM role")
    finally:
        try:
            iam.delete_user_policy(UserName=user, PolicyName="owned-create")
        finally:
            delete_unprivileged(owned)
    print("Verified denied automatic service-linked-role creation: child IAM and parent Kafka CloudTrail records survive rollback; no cluster or role committed", flush=True)


def native_identity(outputs):
    arn = outputs["arn"]
    fields = arn.split(":", 5)
    require(len(fields) == 6 and fields[0] == "arn" and fields[2] == "kafka", "Invalid owned Kafka ARN")
    resource = fields[5].split("/")
    require(len(resource) == 3 and resource[0] == "cluster" and resource[1] == outputs["name"], "Kafka ARN/name differ")
    incarnation = resource[2]
    material = "\x00".join((fields[1], fields[4], fields[3], arn, incarnation)).encode()
    return "stackd-msk-" + hashlib.sha256(material).hexdigest()[:32], fields, incarnation


def export_ca(outputs, root):
    prefix, fields, incarnation = native_identity(outputs)
    host = (root / "docker-host").read_text()
    volume = prefix + "-config"
    record = json.loads(command(["docker", "--host", host, "volume", "inspect", volume]).stdout)[0]
    labels = record["Labels"]
    require(labels.get("stackd.msk.arn") == outputs["arn"] and labels.get("stackd.msk.id") == incarnation
            and labels.get("stackd.msk.role") == "config" and labels.get("stackd.msk.account") == fields[4],
            "Refusing a native CA volume outside exact resource ownership")
    name = "stackd-tf-ca-" + uuid.uuid4().hex
    try:
        certificate = command(["docker", "--host", host, "run", "--rm", "--pull=never", "--name", name,
                               "--network", "none", "--read-only", "--mount", f"type=volume,src={volume},dst=/source,readonly",
                               "--entrypoint", "/bin/cat", KAFKA_IMAGE, "/source/ca.pem"]).stdout
    finally:
        # The exact one-shot name is ours even if Docker client cancellation left it behind.
        command(["docker", "--host", host, "container", "rm", "--force", "--volumes", name], check=False)
    require(certificate.startswith("-----BEGIN CERTIFICATE-----"), "Native CA export returned no certificate")
    path = root / "kafka-ca.pem"
    if path.exists():
        require(path.read_text() == certificate, "Native Kafka CA changed across retained resource lifecycle")
    else:
        path.write_text(certificate)
    return path


def settings(outputs, root, wrong=False, credential=None):
    network = ipaddress.ip_network(outputs["cidr"])
    brokers = outputs["brokers"].split(",")
    require(len(brokers) == 2, "Terraform did not return both native brokers")
    for broker in brokers:
        host, port = broker.rsplit(":", 1)
        require(ipaddress.ip_address(host) in network and port == "9092", "Native broker bypassed its EC2 reservation")
    return {"bootstrap.servers": outputs["brokers"], "security.protocol": "SASL_SSL",
            "ssl.ca.location": str(root / "kafka-ca.pem"), "ssl.endpoint.identification.algorithm": "https",
            "sasl.mechanism": "SCRAM-SHA-512", "sasl.username": "consumer",
            "sasl.password": "incorrect-local-password" if wrong else (password(root) if credential is None else credential),
            "socket.timeout.ms": 10000}


def read_record(outputs, root, record, credential=None):
    consumer = Consumer({**settings(outputs, root, credential=credential), "group.id": outputs["name"]+"-native-reader",
                         "enable.auto.commit": False, "enable.auto.offset.store": False})
    try:
        consumer.assign([TopicPartition(outputs["topic"], record["partition"], record["offset"])])
        message = consumer.poll(15)
        require(message is not None, "Native Kafka did not return the retained record")
        if message.error():
            raise KafkaException(message.error())
        require(message.offset() == record["offset"] and message.value().hex() == record["value"],
                "Native Kafka record identity/bytes changed or disappeared")
    finally:
        consumer.close()


def authentication_denial(outputs, root, incorrect=True):
    authentication_errors = []
    wrong = Producer({**settings(outputs, root, wrong=incorrect), "error_cb": authentication_errors.append})
    try:
        try:
            wrong.list_topics(timeout=10)
        except KafkaException:
            # A metadata transport failure is not authentication evidence.
            # Require librdkafka's explicit broker/SASL authentication error.
            pass
        else:
            raise RuntimeError("Native Kafka accepted credentials expected to be rejected")
        deadline = time.monotonic()+5
        while not any(error.code() in {KafkaError._AUTHENTICATION, KafkaError.SASL_AUTHENTICATION_FAILED}
                      for error in authentication_errors):
            require(time.monotonic() < deadline, "Password denial returned no explicit native authentication failure")
            wrong.poll(0.1)
        return {"authentication_error_codes": sorted({error.code() for error in authentication_errors
                if error.code() in {KafkaError._AUTHENTICATION, KafkaError.SASL_AUTHENTICATION_FAILED}})}
    finally:
        wrong.flush(1)
        wrong = None


def role_deletion(endpoint, expected):
    iam = client("iam", endpoint)
    task = iam.delete_service_linked_role(RoleName="AWSServiceRoleForKafka")["DeletionTaskId"]
    deadline = time.monotonic() + 30
    while True:
        response = iam.get_service_linked_role_deletion_status(DeletionTaskId=task)
        if response["Status"] in {"SUCCEEDED", "FAILED"}:
            require(response["Status"] == expected, f"Kafka role deletion did not respect broker ownership: {response}")
            return response
        require(time.monotonic() < deadline, f"Kafka role deletion did not finish: {response}")
        time.sleep(0.25)


def policy_denial(endpoint, outputs, root):
    ec2, kafka = client("ec2", endpoint), client("kafka", endpoint)
    permission = {"IpProtocol": "tcp", "FromPort": 9092, "ToPort": 9092, "IpRanges": [{"CidrIp": outputs["cidr"]}]}

    def wait_for_sockets(expected_open):
        deadline = time.monotonic() + 90
        while True:
            observed = []
            for broker in outputs["brokers"].split(","):
                host, port = broker.rsplit(":", 1)
                remaining = deadline-time.monotonic()
                require(remaining > 0, "Background Kafka reconciliation did not apply the current EC2 SG rule within 90 seconds")
                try:
                    connection = socket.create_connection((host, int(port)), timeout=min(1, remaining))
                except (TimeoutError, ConnectionRefusedError):
                    observed.append(False)
                else:
                    connection.close()
                    observed.append(True)
            if all(value == expected_open for value in observed):
                return
            require(time.monotonic() < deadline, "Background Kafka packet-policy reconciliation exceeded 90 seconds")
            time.sleep(min(0.5, max(0, deadline-time.monotonic())))

    ec2.revoke_security_group_ingress(GroupId=outputs["group"], IpPermissions=[permission])
    try:
        # Do not force reconciliation with a Kafka control-plane read. Only the
        # natural health pass may make these fresh native connections fail.
        wait_for_sockets(False)
        admin_denial(outputs, root, public_check=False)
        state = kafka.describe_cluster(ClusterArn=outputs["arn"])["ClusterInfo"]["State"]
        require(state == "ACTIVE", "SG revocation changed native broker health instead of packet authority")
    finally:
        ec2.authorize_security_group_ingress(GroupId=outputs["group"], IpPermissions=[permission])
    wait_for_sockets(True)
    require(kafka.describe_cluster(ClusterArn=outputs["arn"])["ClusterInfo"]["State"] == "ACTIVE",
            "Restored packet policy did not preserve healthy native brokers")


def wait_scram(outputs, root, credential=None):
    # Association accepts credentials before asynchronous native propagation.
    # Only an authenticated TLS/SCRAM Kafka metadata response establishes readiness.
    deadline = time.monotonic() + 180
    failures = []
    incomplete = []
    last_metadata = {}
    def require_ready(condition, message):
        if not condition:
            (root / "kafka-scram-readiness-failure.json").write_text(json.dumps({
                "status": "FAILED", "security_protocol": "SASL_SSL", "mechanism": "SCRAM-SHA-512",
                "bootstrap_endpoints": outputs["brokers"].split(","),
                "credential_override": credential is not None,
                "classified_failures": failures, "incomplete_membership": incomplete,
                "last_metadata": last_metadata,
            }, indent=2))
        require(condition, message)
    def record_error(error, bootstrap, source):
        code = error.code()
        failures.append({"bootstrap": bootstrap, "code": code, "source": source,
            "kind": "authentication" if code in {KafkaError._AUTHENTICATION, KafkaError.SASL_AUTHENTICATION_FAILED}
                    else "timeout" if code == KafkaError._TIMED_OUT
                    else "transport" if code in {KafkaError._TRANSPORT, KafkaError._ALL_BROKERS_DOWN} else "other"})

    while True:
        try:
            probe = None
            complete = True
            for broker in outputs["brokers"].split(","):
                probe = Producer({**settings(outputs, root, credential=credential),
                                  "bootstrap.servers": broker, "socket.timeout.ms": 3000,
                                  "error_cb": lambda error, address=broker: record_error(error, address, "callback")})
                metadata = probe.list_topics(timeout=3)
                probe.poll(0)
                last_metadata.update(bootstrap=broker, broker_count=len(metadata.brokers))
                require_ready(len(metadata.brokers) <= 2, "Authenticated native Kafka metadata exposed unexpected extra brokers")
                if len(metadata.brokers) < 2:
                    incomplete.append({"bootstrap": broker, "broker_count": len(metadata.brokers)})
                    complete = False
                    break
                probe = None
            if complete:
                receipt = {
                    "brokers": {identifier: {"host": broker.host, "port": broker.port}
                                for identifier, broker in metadata.brokers.items()},
                    "security_protocol": "SASL_SSL", "mechanism": "SCRAM-SHA-512",
                    "authenticated_bootstrap_endpoints": outputs["brokers"].split(","),
                    "classified_failures": failures, "incomplete_membership": incomplete,
                }
                (root / "kafka-scram-readiness.json").write_text(json.dumps(receipt, indent=2))
                return receipt
            require_ready(time.monotonic() < deadline, "Authenticated Kafka membership did not converge to both actual brokers")
        except KafkaException as error:
            code = error.args[0].code()
            record_error(error.args[0], broker, "metadata")
            if probe is not None:
                probe.poll(0)
            require_ready(code in {KafkaError._AUTHENTICATION, KafkaError.SASL_AUTHENTICATION_FAILED, KafkaError._TRANSPORT,
                    KafkaError._ALL_BROKERS_DOWN, KafkaError._TIMED_OUT},
                    f"Unexpected native credential-propagation failure: {error}")
            require_ready(time.monotonic() < deadline, f"Actual SCRAM authentication did not converge: {error}")
        finally:
            probe = None
        time.sleep(0.5)


def ready(endpoint, outputs, root):
    deadline = time.monotonic() + 180
    while True:
        info = client("kafka", endpoint).describe_cluster(ClusterArn=outputs["arn"])["ClusterInfo"]
        if info["State"] == "ACTIVE":
            return
        require(time.monotonic() < deadline, f"Retained native Kafka reconciliation did not finish: {info}")
        time.sleep(0.5)


def scram_authority(endpoint, outputs, root, info):
    """Retain the local least-privilege grant contract, not native AWS SCRAM evidence."""
    secrets = client("kafka", endpoint).list_scram_secrets(ClusterArn=outputs["arn"])["SecretArnList"]
    require(len(secrets) == 1, "Owned Kafka fixture lost its exact SCRAM secret association")
    kms = client("kms", endpoint)
    key = kms.describe_key(KeyId=outputs["key_id"])["KeyMetadata"]
    grants = kms.list_grants(KeyId=key["Arn"])["Grants"]
    owned = [grant for grant in grants
             if grant.get("GranteePrincipal") == "kafka.amazonaws.com"
             and grant.get("RetiringPrincipal") == "kafka.amazonaws.com"
             and grant.get("Constraints", {}).get("EncryptionContextSubset") == {"SecretARN": secrets[0]}]
    require(len(owned) == 1 and set(owned[0]["Operations"]) == {"Decrypt", "DescribeKey"},
            "SCRAM association did not create its bounded current-secret KMS grant")
    policy = json.loads(kms.get_key_policy(KeyId=key["Arn"], PolicyName="default")["Policy"])
    root_arn = "arn:aws:iam::"+outputs["arn"].split(":")[4]+":root"
    statements = policy["Statement"]
    require(len(statements) == 1 and statements[0]["Principal"] == {"AWS": root_arn}
            and statements[0]["Effect"] == "Allow" and statements[0]["Action"] == "kms:*",
            "Owned fixture's default root-only CMK policy was broadened for Kafka")
    secret_policy = json.loads(client("secretsmanager", endpoint).get_resource_policy(SecretId=secrets[0])["ResourcePolicy"])
    access = [statement for statement in secret_policy["Statement"]
              if statement.get("Principal") == {"Service": "kafka.amazonaws.com"}]
    require(len(access) == 1 and access[0]["Effect"] == "Allow" and access[0]["Resource"] == secrets[0]
            and set(access[0]["Action"]) == {"secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"}
            and access[0]["Condition"] == {"StringEquals": {"aws:SourceAccount": outputs["arn"].split(":")[4]},
                                         "ArnEquals": {"aws:SourceArn": outputs["arn"]}},
            "SCRAM secret authority lost its exact cluster/source-account resource-policy boundary")
    evidence = {"cluster_arn": outputs["arn"], "configuration_arn": info["CurrentBrokerSoftwareInfo"]["ConfigurationArn"],
                "secret_arn": secrets[0], "key_arn": key["Arn"], "grant_ids": [grant["GrantId"] for grant in owned],
                "key_policy": policy, "secret_policy": secret_policy,
                "contract": "Local least-privilege SCRAM implementation, not captured AWS SCRAM output"}
    path = root / "kafka-scram-authority.json"
    if path.exists():
        previous = json.loads(path.read_text())
        require(previous["cluster_arn"] == evidence["cluster_arn"]
                and previous["key_policy"] == policy and previous["secret_policy"] == secret_policy,
                "Retained SCRAM cluster or original authorization policy changed")
    path.write_text(json.dumps(evidence, indent=2))


def rotate_scram_version(endpoint, outputs, root, record):
    secrets = client("secretsmanager", endpoint)
    secret = client("kafka", endpoint).list_scram_secrets(ClusterArn=outputs["arn"])["SecretArnList"][0]
    original = secrets.get_secret_value(SecretId=secret)
    credentials = json.loads(original["SecretString"])
    require(credentials["username"] == "consumer" and credentials["password"] == password(root),
            "Native rotation fixture does not own the Terraform-current credentials")
    authority = json.loads((root / "kafka-scram-authority.json").read_text())
    credential = uuid.uuid4().hex + uuid.uuid4().hex
    rotated = secrets.put_secret_value(SecretId=secret, ClientRequestToken=uuid.uuid4().hex,
        SecretString=json.dumps({**credentials, "password": credential}))["VersionId"]
    try:
        # No Kafka API read triggers this propagation: the managed owner must
        # observe AWSCURRENT and install real SCRAM credentials on its own.
        new_readiness = wait_scram(outputs, root, credential=credential)
        read_record(outputs, root, record, credential=credential)
        old_denial = authentication_denial(outputs, root, incorrect=False)
    finally:
        secrets.update_secret_version_stage(SecretId=secret, VersionStage="AWSCURRENT",
            MoveToVersionId=original["VersionId"], RemoveFromVersionId=rotated)
    restored_readiness = wait_scram(outputs, root)
    read_record(outputs, root, record)
    scram_authority(endpoint, outputs, root, client("kafka", endpoint).describe_cluster(ClusterArn=outputs["arn"])["ClusterInfo"])
    restored = json.loads((root / "kafka-scram-authority.json").read_text())
    require(authority == restored, "Same-CMK version rotation changed the retained grant or authorization policies")
    restored_version = secrets.get_secret_value(SecretId=secret)["VersionId"]
    require(restored_version == original["VersionId"], "Rotation did not restore Terraform's exact AWSCURRENT version")
    (root / "kafka-same-key-version-rotation.json").write_text(json.dumps({
        "secret_arn": secret, "key_arn": authority["key_arn"], "grant_ids": authority["grant_ids"],
        "original_version": original["VersionId"], "rotated_version": rotated,
        "restored_version": restored_version,
        "new_credentials_authenticated": True, "old_credentials_rejected_by_broker": True,
        "original_credentials_recovered": True, "retained_record": record,
        "new_readiness": new_readiness, "old_password_denial": old_denial,
        "restored_readiness": restored_readiness,
    }, indent=2))
    print("Verified actual same-CMK AWSCURRENT rotation: new SCRAM password, explicit old-password denial, retained bytes/offset, original-version recovery and unchanged grant/policies", flush=True)


def consume(endpoint, outputs, root, revision, persisted):
    export_ca(outputs, root)
    wait_scram(outputs, root)
    kafka = client("kafka", endpoint)
    info = kafka.describe_cluster(ClusterArn=outputs["arn"])["ClusterInfo"]
    require(info["State"] == "ACTIVE" and set(info["BrokerNodeGroupInfo"]["ClientSubnets"]) == set(outputs["subnets"]),
            "Native Kafka placement does not match Terraform subnets")
    scram_authority(endpoint, outputs, root, info)
    nodes = kafka.list_nodes(ClusterArn=outputs["arn"])["NodeInfoList"]
    require(len(nodes) == 2 and {node["BrokerNodeInfo"]["ClientSubnet"] for node in nodes} == set(outputs["subnets"])
            and all(node["BrokerNodeInfo"].get("AttachedENIId") for node in nodes), "Kafka broker ENI ownership is incomplete")
    (root / "kafka-interfaces.json").write_text(json.dumps([node["BrokerNodeInfo"]["AttachedENIId"] for node in nodes]))
    interfaces = client("ec2", endpoint).describe_network_interfaces(NetworkInterfaceIds=[node["BrokerNodeInfo"]["AttachedENIId"] for node in nodes])["NetworkInterfaces"]
    by_interface = {interface["NetworkInterfaceId"]: interface for interface in interfaces}
    for node in nodes:
        broker = node["BrokerNodeInfo"]
        interface = by_interface[broker["AttachedENIId"]]
        address = broker["ClientVpcIpAddress"]
        require(address == interface["PrivateIpAddress"] and interface["SubnetId"] == broker["ClientSubnet"]
                and f"{address}:9092" in broker["Endpoints"] and f"{address}:9092" in outputs["brokers"].split(","),
                "Advertised Kafka socket bypassed its exact live EC2 interface/subnet")
    retained_file = root / "kafka-record.json"
    # Recovery must prove prior bytes/offset before any fresh publish can mask them.
    if persisted or retained_file.exists():
        read_record(outputs, root, json.loads(retained_file.read_text()))
    producer = Producer({**settings(outputs, root), "acks": "all"})
    delivered = []
    try:
        payload = b"Terraform native Kafka\x00\xff:" + revision.encode() + uuid.uuid4().bytes
        producer.produce(outputs["topic"], key=b"fixture", value=payload,
                         on_delivery=lambda error, message: delivered.append((error, message)))
        require(producer.flush(20) == 0 and len(delivered) == 1, "Native Kafka did not acknowledge the actual publish")
        error, sent = delivered[0]
        if error:
            raise KafkaException(error)
        retained = {"partition": sent.partition(), "offset": sent.offset(), "value": payload.hex()}
        read_record(outputs, root, retained)
        retained_file.write_text(json.dumps(retained))
    finally:
        producer.flush(5)
        producer = None
    admin = AdminClient(settings(outputs, root))
    try:
        expected = "86400000" if revision == "v1" else "172800000"
        for index in (1, 2):
            # librdkafka routes a BROKER resource to that exact broker and
            # accepts only one such resource in each describe-configs call.
            broker = ConfigResource(ResourceType.BROKER, str(index))
            configurations = admin.describe_configs([broker], request_timeout=15)
            require(set(configurations) == {broker}, "Native broker configuration response omitted its exact broker")
            values = configurations[broker].result(timeout=20)
            require(values["log.retention.ms"].value == expected,
                    "Terraform configuration update did not reach the real Kafka broker")
    finally:
        admin = None
    if revision == "v1" and not persisted:
        rotate_scram_version(endpoint, outputs, root, retained)
    authentication_denial(outputs, root)
    role_deletion(endpoint, "FAILED")
    admin_denial(outputs, root)
    policy_denial(endpoint, outputs, root)
    # After restoring the exact ingress permission, a new authenticated native
    # connection must read the retained record again.
    read_record(outputs, root, json.loads(retained_file.read_text()))
    if not persisted:
        observation_quarantine(endpoint, outputs, root)
    unauthorized, owned = unprivileged("kafka", endpoint, root)
    iam, name, _ = owned
    try:
        denied(lambda: unauthorized.describe_cluster(ClusterArn=outputs["arn"]))
        iam.put_user_policy(UserName=name, PolicyName="owned-describe", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "kafka:DescribeCluster", "Resource": outputs["arn"]}]}))
        require(unauthorized.describe_cluster(ClusterArn=outputs["arn"])["ClusterInfo"]["ClusterArn"] == outputs["arn"], "Current IAM grant did not affect the same consumer")
        iam.delete_user_policy(UserName=name, PolicyName="owned-describe")
        denied(lambda: unauthorized.describe_cluster(ClusterArn=outputs["arn"]))
    finally:
        try:
            iam.delete_user_policy(UserName=name, PolicyName="owned-describe")
        except ClientError as error:
            require(error.response["Error"]["Code"] == "NoSuchEntity", str(error))
        delete_unprivileged(owned)
    deadline = time.monotonic() + 100
    while True:
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        metrics = client("cloudwatch", endpoint).get_metric_statistics(Namespace="AWS/Kafka", MetricName="PartitionCount",
            Dimensions=[{"Name": "Cluster Name", "Value": outputs["name"]}, {"Name": "Broker ID", "Value": "1"}],
            StartTime=now-timedelta(minutes=5), EndTime=now+timedelta(seconds=1), Period=60, Statistics=["Maximum"])["Datapoints"]
        if metrics and max(point["Maximum"] for point in metrics) > 0:
            break
        require(time.monotonic() < deadline, "Native Kafka PartitionCount was not published from real broker JMX")
        time.sleep(1)
    print(f"Verified {revision}: actual SCRAM/TLS Kafka records and retained offsets, broker configuration, EC2 SG revocation, live IAM, SLR ownership and native JMX gauge", flush=True)


def cleanup(endpoint, outputs, root):
    admin = AdminClient(settings(outputs, root))
    try:
        admin.delete_topics([outputs["topic"]], request_timeout=15)[outputs["topic"]].result(timeout=20)
    finally:
        admin = None


def deleted(endpoint, outputs, root):
    try:
        client("kafka", endpoint).describe_cluster(ClusterArn=outputs["arn"])
    except ClientError as error:
        require(error.response["Error"]["Code"] == "NotFoundException", str(error))
    else:
        raise RuntimeError("Kafka cluster remains after Terraform destroy")
    key = client("kms", endpoint).describe_key(KeyId=outputs["key_id"])["KeyMetadata"]
    require(key["KeyState"] == "PendingDeletion", "Terraform did not schedule owned SCRAM KMS key deletion")
    authority = json.loads((root / "kafka-scram-authority.json").read_text())
    for service, method, parameters, code in (
            ("kafka", "describe_configuration", {"Arn": authority["configuration_arn"]}, "BadRequestException"),
            # This fixture explicitly sets recovery_window_in_days=0. A fixture
            # retaining a recovery window must instead assert scheduled deletion.
            ("secretsmanager", "describe_secret", {"SecretId": authority["secret_arn"]}, "ResourceNotFoundException")):
        try:
            getattr(client(service, endpoint), method)(**parameters)
        except ClientError as error:
            require(error.response["Error"]["Code"] == code, str(error))
        else:
            raise RuntimeError(f"Owned {service} resource remains after ordinary destroy: {parameters}")
    grants = client("kms", endpoint).list_grants(KeyId=authority["key_arn"])["Grants"]
    require(not any(grant["GrantId"] in authority["grant_ids"] for grant in grants),
            "Owned SCRAM grant remains on the pending-deletion CMK")
    require(not any(grant.get("GranteePrincipal") == "kafka.amazonaws.com"
                    and grant.get("Constraints", {}).get("EncryptionContextSubset") == {"SecretARN": authority["secret_arn"]}
                    for grant in grants), "Ordinary destroy orphaned a replacement SCRAM grant")
    (root / "kafka-signed-secret-configuration-grant-absence.json").write_text(json.dumps({
        "configuration_arn": authority["configuration_arn"], "secret_arn": authority["secret_arn"],
        "retired_grant_ids": authority["grant_ids"], "key_arn": authority["key_arn"],
        "key_state": key["KeyState"], "before_session_expiry_acceleration": True}, indent=2))
    ec2 = client("ec2", endpoint)
    for interface in json.loads((root / "kafka-interfaces.json").read_text()):
        try:
            ec2.describe_network_interfaces(NetworkInterfaceIds=[interface])
        except ClientError as error:
            require(error.response["Error"]["Code"] == "InvalidNetworkInterfaceID.NotFound", str(error))
        else:
            raise RuntimeError(f"Owned Kafka interface remains after destroy: {interface}")
    host = (root / "docker-host").read_text()
    for kind in ("container", "volume", "network"):
        listing = ["docker", "--host", host, kind, "ls"]
        if kind == "container":
            listing.append("--all")
        listed = command([*listing, "--filter", "label=stackd.msk.arn="+outputs["arn"], "--quiet"]).stdout
        require(not listed.strip(), f"Exactly owned Kafka {kind} objects remain after destroy: {listed}")
    print("Verified signed cluster/configuration/secret/ENI absence and SCRAM grant retirement; KMS key has the AWS-required seven-day pending deletion", flush=True)


def retire_roles(endpoint, outputs, root):
    # deleted() already proved native/ENI absence before this owned clock starts.
    # IAM correctly retains issued sessions for up to one hour after consumers
    # disappear. Accelerate expiration, never revoke live service credentials.
    with urlopen(endpoint + "/_stackd/clock", timeout=30) as response:
        initial = json.load(response)
    retained = json.loads((root / "cleanup-service-time.json").read_text())
    initial_time = datetime.fromisoformat(initial["time"].replace("Z", "+00:00"))
    retained_time = datetime.fromisoformat(retained["time"].replace("Z", "+00:00"))
    require(initial_time >= retained_time, "Role retirement moved retained service time backward")
    request = Request(endpoint + "/_stackd/clock", data=json.dumps({"advance": "1h1s"}).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=30) as response:
        advanced = json.load(response)
    result = role_deletion(endpoint, "SUCCEEDED")
    (root / "kafka-role-retirement.json").write_text(json.dumps({
        "initial_clock": initial, "advanced_clock": advanced, "deletion": result,
        "expiration_accelerated": "1h1s",
    }, indent=2))
    print("Verified normal signed SLR release after manual-time session expiration, not immediate AWS deletion", flush=True)


def owned_brokers(outputs, root):
    prefix, fields, incarnation = native_identity(outputs)
    host = (root / "docker-host").read_text()
    brokers = []
    for broker in (1, 2):
        role = f"broker-{broker}"
        record = json.loads(command(["docker", "--host", host, "container", "inspect", prefix+"-"+role]).stdout)[0]
        labels = record["Config"]["Labels"]
        expected = {"arn": outputs["arn"], "id": incarnation, "role": role, "partition": fields[1],
                    "account": fields[4], "region": fields[3], "image": KAFKA_IMAGE}
        require(all(labels.get("stackd.msk."+key) == value for key, value in expected.items()),
                "Refusing a broker outside exact native ownership")
        brokers.append(record)
    return brokers


def admin_denial(outputs, root, public_check=True):
    # TLS1.2 makes missing-client-certificate rejection synchronous. Prove the
    # same TLS context works on CLIENT before requiring its rejection on ADMIN.
    context = ssl.create_default_context(cafile=str(root / "kafka-ca.pem"))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    if public_check:
        host, port = outputs["brokers"].split(",")[0].rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=3) as connection:
            with context.wrap_socket(connection, server_hostname=host):
                pass
    for broker in owned_brokers(outputs, root):
        bindings = broker["HostConfig"]["PortBindings"]["9095/tcp"]
        require(len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1", "ADMIN is not private daemon loopback")
        try:
            with socket.create_connection(("127.0.0.1", int(bindings[0]["HostPort"])), timeout=3) as connection:
                with context.wrap_socket(connection, server_hostname="127.0.0.1"):
                    raise RuntimeError("Customer without the runtime private TLS identity can reach ADMIN authentication")
        except ssl.SSLError as error:
            require("CERTIFICATE_REQUIRED" in error.reason or error.reason == "SSLV3_ALERT_HANDSHAKE_FAILURE",
                    f"ADMIN failed for a reason other than its required native client certificate: {error}")


def observation_quarantine(endpoint, outputs, root):
    ec2, kafka = client("ec2", endpoint), client("kafka", endpoint)
    original = ec2.describe_vpcs(VpcIds=[outputs["vpc"]])["Vpcs"][0]["DhcpOptionsId"]
    interfaces = [broker["Id"] for broker in owned_brokers(outputs, root)]
    options = ec2.create_dhcp_options(DhcpConfigurations=[{"Key": "domain-name-servers", "Values": ["fd00::53"]}])["DhcpOptions"]["DhcpOptionsId"]
    permission = {"IpProtocol": "tcp", "FromPort": 9092, "ToPort": 9092, "IpRanges": [{"CidrIp": outputs["cidr"]}]}
    associated, revoked = False, False
    try:
        ec2.associate_dhcp_options(DhcpOptionsId=options, VpcId=outputs["vpc"])
        associated = True
        ec2.revoke_security_group_ingress(GroupId=outputs["group"], IpPermissions=[permission])
        revoked = True
        deadline = time.monotonic()+90
        while True:
            denied_connections = []
            for broker in outputs["brokers"].split(","):
                host, port = broker.rsplit(":", 1)
                try:
                    connection = socket.create_connection((host, int(port)), timeout=1)
                except (ConnectionRefusedError, TimeoutError):
                    denied_connections.append(True)
                except OSError as error:
                    if error.errno not in {errno.EHOSTUNREACH, errno.ENETUNREACH}:
                        raise
                    denied_connections.append(True)
                else:
                    connection.close()
                    denied_connections.append(False)
            # A stopped bridge endpoint can time out instead of sending a TCP reset.
            # Packet failure alone is not evidence: require both owned processes stopped.
            stopped = all(not broker["State"]["Running"] for broker in owned_brokers(outputs, root))
            if all(denied_connections) and stopped:
                break
            require(time.monotonic() < deadline, "Failed EC2 observation left an old native listener serving beyond background reconciliation")
            time.sleep(0.25)
        require(kafka.describe_cluster(ClusterArn=outputs["arn"])["ClusterInfo"]["State"] == "FAILED",
                "Quarantined native cluster falsely reports ACTIVE")
    finally:
        try:
            if associated:
                ec2.associate_dhcp_options(DhcpOptionsId=original, VpcId=outputs["vpc"])
        finally:
            try:
                if revoked:
                    ec2.authorize_security_group_ingress(GroupId=outputs["group"], IpPermissions=[permission])
            finally:
                ec2.delete_dhcp_options(DhcpOptionsId=options)
    deadline = time.monotonic()+180
    while kafka.describe_cluster(ClusterArn=outputs["arn"])["ClusterInfo"]["State"] != "ACTIVE":
        require(time.monotonic() < deadline, "Restored EC2 prerequisites did not recover retained native brokers")
        time.sleep(0.5)
    require([broker["Id"] for broker in owned_brokers(outputs, root)] == interfaces,
            "Quarantine replaced owned broker identity instead of retaining it")
    read_record(outputs, root, json.loads((root / "kafka-record.json").read_text()))
    print("Verified failed EC2/DHCP observation quarantines both owned brokers without Describe-triggered denial; restored prerequisites retain actual native records", flush=True)
