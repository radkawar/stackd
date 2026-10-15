"""Use actual MemoryDB-compatible Valkey bytes, ACLs and physical restore."""

import time

import redis
from botocore.exceptions import ClientError

from cache.fixture import prepare
from common import client, closed, delete_unprivileged, denied, password, require, unprivileged


def connection(outputs, root, wrong=False):
    require(outputs["address"] == "127.0.0.1" and 1024 <= int(outputs["port"]) <= 65535,
            "Standalone native MemoryDB endpoint is not the owned loopback listener")
    return redis.Redis(host=outputs["address"], port=int(outputs["port"]), username=outputs["username"],
                       password="incorrect-local-password" if wrong else password(root), ssl=True,
                       ssl_ca_certs=str(root / "local.crt"), ssl_cert_reqs="required", ssl_check_hostname=True,
                       socket_connect_timeout=5, socket_timeout=5)


def consume(endpoint, outputs, root, revision, persisted):
    memorydb = client("memorydb", endpoint)
    deadline = time.monotonic() + 180
    while True:
        cluster = memorydb.describe_clusters(ClusterName=outputs["name"], ShowShardDetails=True)["Clusters"][0]
        if cluster["Status"] == "available" and cluster["ParameterGroupStatus"] == "in-sync":
            break
        require(time.monotonic() < deadline, f"MemoryDB native update did not finish: {cluster}")
        time.sleep(0.5)
    require(cluster["TLSEnabled"] and cluster["NumberOfShards"] == 1, "Unexpected native MemoryDB topology/security")
    native = connection(outputs, root)
    try:
        require(native.ping(), "Native MemoryDB-compatible Valkey PING failed")
        key = "fixture:retained"
        file = root / "memorydb-value"
        if persisted:
            require(native.get(key) == file.read_bytes(), "Native MemoryDB bytes did not survive update/reopen")
        value = b"Terraform native MemoryDB\x00\xff:" + revision.encode()
        native.set(key, value)
        require(native.get(key) == value, "Native MemoryDB binary bytes changed")
        file.write_bytes(value)
        require(native.info("memory")["maxmemory_policy"] == ("noeviction" if revision == "v1" else "allkeys-lru"),
                "Terraform MemoryDB parameter did not affect native memory policy")
        try:
            native.get("outside-fixture")
        except redis.exceptions.NoPermissionError:
            pass
        else:
            raise RuntimeError("MemoryDB key ACL did not deny the native consumer")
    finally:
        native.close()
    wrong = connection(outputs, root, wrong=True)
    try:
        try:
            wrong.ping()
        except redis.exceptions.AuthenticationError:
            pass
        else:
            raise RuntimeError("MemoryDB native listener accepted the wrong password")
    finally:
        wrong.close()
    if outputs["restored"] is not None:
        restored_outputs = dict(outputs, **outputs["restored"])
        restored = connection(restored_outputs, root)
        try:
            require(restored.get("fixture:retained") == b"Terraform native MemoryDB\x00\xff:v1",
                    "Physical snapshot restore did not retain the original independent bytes")
            require(restored.get("fixture:retained") != value, "Restore shared mutable bytes with the source")
        finally:
            restored.close()
    unauthorized, owned = unprivileged("memorydb", endpoint, root)
    try:
        denied(lambda: unauthorized.describe_clusters(ClusterName=outputs["name"]))
    finally:
        delete_unprivileged(owned)
    print(f"Verified {revision}: native TLS binary values, ACL/password/IAM denial, effective parameter and physical snapshot restore", flush=True)


def cleanup(endpoint, outputs, root):
    for item in (outputs, outputs["restored"]):
        if item is None:
            continue
        native = connection(dict(outputs, **item), root)
        try:
            native.delete("fixture:retained")
        finally:
            native.close()


def deleted(endpoint, outputs, root):
    for name in (outputs["name"], (outputs["restored"] or {}).get("name")):
        if name is None:
            continue
        try:
            client("memorydb", endpoint).describe_clusters(ClusterName=name)
        except ClientError as error:
            require(error.response["Error"]["Code"] == "ClusterNotFoundFault", str(error))
        else:
            raise RuntimeError("MemoryDB resource remains after Terraform destroy")
    for item in (outputs, outputs["restored"]):
        if item is not None:
            closed(item["address"], item["port"])
