"""Native single-node OpenSearch 2.19.4 proof, not AWS capacity/security emulation.

Terraform owns domain/policy/tags; this consumer owns one explicitly marked index,
one deterministic document, and one IAM denial identity. No runtime image pulls.
Legacy ES is description-only here: creating an Elasticsearch engine is unsupported.
"""

import hashlib
import http.client
import json
import os
import time
from urllib.parse import urlsplit

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from common import client, inspect_image, require

IMAGE = "opensearchproject/opensearch@sha256:9e0b3b3b6805811bd63d9b9503ffe34a58ba33d03cc346000e318c6ff5c05bd9"
REGION = "us-east-1"
STATE = "search-consumer.json"
DOCUMENT = "owned-document"
POLICY = "fixture-current-describe"
ROOT_CREDENTIALS = Credentials("test", "test")


def prepare(args, root) -> list[str]:
    inspect_image(args, IMAGE)
    return ["-docker-host", args.docker_host, "-opensearch-runtime"]


def _application(endpoint, outputs):
    application = outputs
    origin = urlsplit(endpoint)
    native = urlsplit("http://" + application["endpoint"])
    require(origin.scheme == "http" and origin.hostname == "127.0.0.1"
            and origin.port is not None and not origin.username and not origin.password,
            "Search fixture requires an owned loopback endpoint")
    require(native.scheme == origin.scheme and native.netloc == origin.netloc
            and native.path.startswith("/_stackd/opensearch/")
            and not native.query and not native.fragment and not native.username,
            f"Refusing search endpoint outside the owned gateway: {native.geturl()}")
    require(application["arn"] == application["modern_data_id"] == application["legacy_data_id"],
            "Modern and legacy Terraform data sources disagree on domain identity")
    require(application["engine_version"] == application["legacy_version"] == "OpenSearch_2.19",
            "Search fixture refuses a substituted legacy Elasticsearch version")
    return application, native.geturl().rstrip("/")


def _request(base, method, path, body=None, credentials=ROOT_CREDENTIALS,
             expected=(200,), content_type="application/json"):
    payload = b"" if body is None else (body.encode() if isinstance(body, str)
                                      else json.dumps(body, sort_keys=True).encode())
    request = AWSRequest(method=method, url=base + path, data=payload,
                         headers={"Content-Type": content_type})
    if credentials is not None:
        SigV4Auth(credentials, "es", REGION).add_auth(request)
    prepared = request.prepare()
    parsed = urlsplit(prepared.url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=60)
    try:
        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        connection.request(method, target, body=prepared.body, headers=dict(prepared.headers))
        response = connection.getresponse()
        raw = response.read()
        require(response.status in expected,
                f"Search {method} {path}: HTTP {response.status}: {raw.decode(errors='replace')}")
        return json.loads(raw) if raw else {}
    finally:
        connection.close()


def _save(root, state):
    path = root / STATE
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(state, stream, sort_keys=True)


def _load(root):
    path = root / STATE
    return json.loads(path.read_text()) if path.exists() else None


def _denied(call, **kwargs):
    try:
        call(**kwargs)
    except ClientError as error:
        require(error.response["ResponseMetadata"]["HTTPStatusCode"] == 403
                and error.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"),
                f"Expected current IAM authority denial: {error}")
    else:
        raise RuntimeError("Consumer without current IAM authority unexpectedly succeeded")


def _verify_identity(iam, state):
    user = iam.get_user(UserName=state["username"])["User"]
    require(user["UserId"] == state["user_id"], "Denial identity was replaced")
    tags = {entry["Key"]: entry["Value"] for entry in iam.list_user_tags(
        UserName=state["username"])["Tags"]}
    require(tags.get("StackdSearchFixture") == state["owner"], "Denial identity is not owned")


def _mapping(base, state):
    mapping = _request(base, "GET", f"/{state['index']}/_mapping")
    require(mapping[state["index"]]["mappings"].get("_meta") == {"owner": state["owner"]},
            "Search index ownership metadata changed")


def _document(base, state):
    document = _request(base, "GET", f"/{state['index']}/_doc/{DOCUMENT}")
    require(document["found"] and document["_source"] == state["payload"],
            "Native document did not persist unchanged; refusing to replace missing/corrupt data")


def consume(endpoint, outputs, root, revision, persisted) -> None:
    application, base = _application(endpoint, outputs)
    require(revision in ("v1", "v2") and application["revision"] == revision,
            "Terraform output revision does not match the consumer")
    native = _request(base, "GET", "/")
    require(native["version"]["number"] == "2.19.4"
            and native["version"]["distribution"] == "opensearch", "Wrong native runtime")
    control = client("opensearch", endpoint)
    domain = control.describe_domain(DomainName=application["domain_name"])["DomainStatus"]
    require(domain["ARN"] == application["arn"] and not domain["Processing"]
            and domain["ClusterConfig"]["InstanceCount"] == 1, "Domain is not one ready native node")
    options = {"indices.query.bool.max_clause_count": "8" if revision == "v1" else "16",
               "rest.action.multi.allow_explicit_index": "true" if revision == "v1" else "false"}
    require(domain["AdvancedOptions"] == options, "Terraform advanced-options update is missing")
    policy = json.loads(domain["AccessPolicies"])
    require(policy["Statement"][0]["Sid"] == ("FixtureInitial" if revision == "v1" else "FixtureUpdated"),
            "Terraform domain-policy update is missing")
    tags = {tag["Key"]: tag["Value"] for tag in control.list_tags(ARN=application["arn"])["TagList"]}
    require(tags.get("Revision") == revision and tags.get("Fixture") == application["domain_name"],
            "Terraform domain tags did not update")
    nodes = _request(base, "GET", "/_nodes/settings?flat_settings=true")["nodes"]
    require(len(nodes) == 1, "Native engine did not report exactly one node")
    for node in nodes.values():
        for key, value in options.items():
            require(str(node["settings"].get(key)).lower() == value,
                    f"Native option {key} was not applied: {node['settings']}")
    iam = client("iam", endpoint)
    state = _load(root)
    require(not persisted or state is not None, "Persisted consume requires prior native payload metadata")
    if state is None:
        owner = hashlib.sha256((str(root.resolve()) + application["arn"]).encode()).hexdigest()
        state = {"owner": owner, "arn": application["arn"], "index": "stackd-fixture-" + owner[:20],
                 "username": application["domain_name"] + "-denied"}
        _request(base, "PUT", f"/{state['index']}", {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {"dynamic": "strict", "_meta": {"owner": owner}, "properties": {
                "owner": {"type": "keyword"}, "revision": {"type": "keyword"},
                "message": {"type": "text"}, "ordinal": {"type": "integer"}}}}, expected=(200,))
        user = iam.create_user(UserName=state["username"], Tags=[
            {"Key": "StackdSearchFixture", "Value": owner}])["User"]
        state["user_id"] = user["UserId"]
        try:
            key = iam.create_access_key(UserName=state["username"])["AccessKey"]
        except BaseException:
            iam.delete_user(UserName=state["username"])
            raise
        state["access_key"] = key["AccessKeyId"]
        state["secret_key"] = key["SecretAccessKey"]
        state["payload"] = None
        _save(root, state)
    else:
        require(state["arn"] == application["arn"], "Consumer state belongs to another domain")
        _mapping(base, state)
        require(state["payload"] is not None, "Prior native payload was never committed")
        _document(base, state)
    _verify_identity(iam, state)
    credentials = Credentials(state["access_key"], state["secret_key"])
    _request(base, "GET", f"/{state['index']}/_search", credentials=credentials, expected=(403,))
    _request(base, "GET", f"/{state['index']}/_search", credentials=None, expected=(401, 403))
    consumer = boto3.Session(aws_access_key_id=state["access_key"],
                            aws_secret_access_key=state["secret_key"], region_name=REGION).client(
        "opensearch", endpoint_url=endpoint, config=Config(proxies={}, retries={"max_attempts": 0}))
    _denied(consumer.describe_domain, DomainName=application["domain_name"])
    iam.put_user_policy(UserName=state["username"], PolicyName=POLICY, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "es:DescribeDomain",
                                                "Resource": application["arn"]}]}))
    try:
        described = consumer.describe_domain(DomainName=application["domain_name"])["DomainStatus"]
        require(described["ARN"] == application["arn"], "Granted SDK consumer read a different domain")
    finally:
        iam.delete_user_policy(UserName=state["username"], PolicyName=POLICY)
    _denied(consumer.describe_domain, DomainName=application["domain_name"])
    _request(base, "GET", f"/{state['index']}/_search", credentials=credentials, expected=(403,))
    payload = {"owner": state["owner"], "revision": revision,
               "message": "persistent signed native search payload", "ordinal": 19}
    _request(base, "PUT", f"/{state['index']}/_doc/{DOCUMENT}?refresh=wait_for", payload,
             expected=(200, 201))
    state["payload"] = payload
    _save(root, state)
    bulk = json.dumps({"index": {"_index": state["index"], "_id": DOCUMENT}}) + "\n" + json.dumps(payload) + "\n"
    result = _request(base, "POST", "/_bulk?refresh=wait_for", bulk,
                      expected=(200,) if revision == "v1" else (400,), content_type="application/x-ndjson")
    if revision == "v1":
        require(not result["errors"] and result["items"][0]["index"]["_id"] == DOCUMENT,
                "Native explicit-index bulk did not write the owned document")
    else:
        require("explicit index" in json.dumps(result).lower(), "Native bulk failed for an unrelated reason")
    _document(base, state)
    result = _request(base, "POST", f"/{state['index']}/_search", {
        "query": {"bool": {"filter": [{"term": {"owner": state["owner"]}},
                                         {"term": {"revision": revision}},
                                         {"range": {"ordinal": {"gte": 19}}}]}},
        "aggs": {"ordinal_sum": {"sum": {"field": "ordinal"}}}})
    require(result["hits"]["total"]["value"] == 1
            and result["hits"]["hits"][0]["_id"] == DOCUMENT
            and result["hits"]["hits"][0]["_source"] == payload
            and result["aggregations"]["ordinal_sum"]["value"] == 19,
            f"Native query/aggregation returned unexpected data: {result}")


def cleanup(endpoint, outputs, root) -> None:
    application, base = _application(endpoint, outputs)
    state = _load(root)
    if state is None:
        return
    require(state["arn"] == application["arn"], "Cleanup state belongs to another domain")
    # A new controller has recovered intent, not yet joined native startup.
    # Wait for the actual signed owner transition before touching engine bytes.
    control = client("opensearch", endpoint)
    deadline = time.monotonic() + 90
    while True:
        domain = control.describe_domain(DomainName=application["domain_name"])["DomainStatus"]
        require(domain["ARN"] == application["arn"], "Cleanup observed a foreign domain")
        if not domain["Processing"]:
            break
        require(time.monotonic() < deadline, "Owned search domain did not recover before native cleanup")
        time.sleep(0.25)
    _mapping(base, state)
    if state["payload"] is not None:
        _document(base, state)
        _request(base, "DELETE", f"/{state['index']}/_doc/{DOCUMENT}?refresh=wait_for")
    remaining = _request(base, "GET", f"/{state['index']}/_count")["count"]
    require(remaining == 0, "Refusing to delete an index containing foreign documents")
    _request(base, "DELETE", f"/{state['index']}")
    iam = client("iam", endpoint)
    _verify_identity(iam, state)
    iam.delete_access_key(UserName=state["username"], AccessKeyId=state["access_key"])
    iam.delete_user(UserName=state["username"])
    (root / STATE).unlink()


def deleted(endpoint, outputs, root) -> None:
    application, base = _application(endpoint, outputs)
    for service, operation in (("opensearch", "describe_domain"),
                               ("es", "describe_elasticsearch_domain")):
        try:
            getattr(client(service, endpoint), operation)(DomainName=application["domain_name"])
        except ClientError as error:
            require(error.response["Error"]["Code"] == "ResourceNotFoundException"
                    and error.response["ResponseMetadata"]["HTTPStatusCode"] == 404,
                    f"Unexpected post-destroy search error: {error}")
        else:
            raise RuntimeError(f"Destroyed search domain remains in {service}")
    _request(base, "GET", "/", expected=(404,))
