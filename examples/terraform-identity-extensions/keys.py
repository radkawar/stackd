"""Consume real imported/generated KMS material through signed regional APIs.

AWS contracts: https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html
https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html#deleting-multi-region-keys
The independent AES-GCM decoder deliberately checks stackd's local ciphertext
format (internal/services/kms/crypto.go), not AWS ciphertext-format parity.
"""

import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import struct
from urllib.request import ProxyHandler, Request, build_opener

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from local import client, local_endpoint, require


GROUPS = (("external_primary", "external_replica"), ("primary", "replica"))


def prepare(root):
    """Create private, true random AES-256 material; Terraform performs wrapping."""
    directory = Path(root) / "keys"
    directory.mkdir(mode=0o700)
    for filename in ("single.bin", "multi.bin", "rotation.bin", "wrong.bin"):
        with os.fdopen(os.open(directory / filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                               0o600), "wb") as stream:
            stream.write(os.urandom(32))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {"keys_valid_to_v1": _iso(now + timedelta(days=30)),
            "keys_valid_to_v2": _iso(now + timedelta(days=31))}


def _iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _date(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _client(endpoint, region, key="test", secret="test"):
    return boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret,
                         region_name=region).client(
        "kms", endpoint_url=local_endpoint(endpoint),
        config=Config(signature_version="v4", connect_timeout=3, read_timeout=60,
                      proxies={}, retries={"max_attempts": 0}))


def _rejected(call, codes, **kwargs):
    try:
        call(**kwargs)
    except ClientError as error:
        require(error.response["Error"]["Code"] in codes, str(error))
    else:
        raise RuntimeError(f"KMS negative unexpectedly succeeded: {call.__name__}")


def _clock(endpoint, advance=None):
    endpoint = local_endpoint(endpoint)
    payload = None if advance is None else json.dumps({"advance": advance}).encode()
    http = build_opener(ProxyHandler({}))
    request = Request(endpoint + "/_stackd/clock", data=payload,
                      headers={"Content-Type": "application/json"})
    with http.open(request, timeout=30) as response:
        result = json.load(response)
    if advance is not None:
        with http.open(Request(endpoint + "/_stackd/jobs/drain?limit=4096", data=b""),
                       timeout=60) as response:
            json.load(response)
    return _date(result["time"])


def _save(root, evidence):
    path = Path(root) / "keys" / "evidence.json"
    with os.fdopen(os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600), "w") as stream:
        json.dump(evidence, stream, sort_keys=True, indent=2)
        stream.write("\n")


def _wrapped_import(kms, resource, material, valid_to="", **extra):
    parameters = kms.get_parameters_for_import(
        KeyId=resource["id"], WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048")
    public = serialization.load_der_public_key(parameters["PublicKey"])
    require(isinstance(public, rsa.RSAPublicKey) and public.key_size == 2048,
            "KMS import did not return a real RSA-2048 wrapping public key")
    arguments = dict(KeyId=resource["id"], ImportToken=parameters["ImportToken"],
                     EncryptedKeyMaterial=public.encrypt(material, padding.OAEP(
                         mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"")),
                     ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE", **extra)
    if valid_to:
        arguments.update(ExpirationModel="KEY_MATERIAL_EXPIRES", ValidTo=_date(valid_to))
    return kms.import_key_material(**arguments)


def _independent_decrypt(root, filename, blob, context, plaintext):
    magic = b"STACKDKMS\x02"
    require(blob.startswith(magic) and len(blob) >= len(magic) + 2,
            "Unexpected local KMS ciphertext format")
    arn_size = struct.unpack_from(">H", blob, len(magic))[0]
    end = len(magic) + 2 + arn_size + 64
    require(arn_size > 0 and len(blob) >= end + 12 + 16 + 1,
            "Truncated local KMS ciphertext")
    # Go's encoding/json emits sorted UTF-8 object keys. Fixture context contains
    # only safe ASCII names/values, so this is exactly the owner's authenticated data.
    associated = blob[:end] + json.dumps(context, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=False).encode()
    actual = AESGCM((Path(root) / "keys" / filename).read_bytes()).decrypt(
        blob[end:end + 12], blob[end + 12:], associated)
    require(actual == plaintext, "The imported raw AES bytes did not decrypt actual ciphertext")
    return blob[end - 64:end].decode("ascii")


def _metadata(kms, resource):
    return kms.describe_key(KeyId=resource["id"])["KeyMetadata"]


def _decrypt_record(record, resources, admins, root):
    blob = base64.b64decode(record["ciphertext"], validate=True)
    plain = base64.b64decode(record["plaintext"], validate=True)
    for name in record["targets"]:
        resource = resources[name]
        result = admins[resource["region"]].decrypt(
            KeyId=resource["arn"], CiphertextBlob=blob, EncryptionContext=record["context"])
        require(result["Plaintext"] == plain and result["KeyId"] == resource["arn"],
                "Retained ciphertext lost bytes, local key authority, or regional interoperability")
    if record.get("material_file"):
        material_id = _independent_decrypt(root, record["material_file"], blob, record["context"], plain)
        require(material_id == record["material_id"], "Retained imported material identity changed")


def _round_trip(names, resources, consumers, admins, root, context, material_file=None):
    source = resources[names[0]]
    consumer = consumers[source["region"]]
    plain = b"real imported/regional binary consumer\x00\xff\n" + os.urandom(32)
    encrypted = consumer.encrypt(KeyId=source["alias"], Plaintext=plain, EncryptionContext=context)
    blob = encrypted["CiphertextBlob"]
    require(encrypted["KeyId"] == source["arn"], "Alias encrypt did not resolve current regional authority")
    for name in names:
        resource = resources[name]
        reader = consumers[resource["region"]]
        for reference in (resource["arn"], resource["id"], resource["alias"], None):
            arguments = dict(CiphertextBlob=blob, EncryptionContext=context)
            if reference is not None:
                arguments["KeyId"] = reference
            decrypted = reader.decrypt(**arguments)
            require(decrypted["Plaintext"] == plain and decrypted["KeyId"] == resource["arn"],
                    "Linked Region did not decrypt actual source bytes with its local authority")
        admin = admins[resource["region"]]
        wrong_name = "primary" if name.startswith("external") or name == "single" else "external_primary"
        wrong_id = resources[wrong_name]["id"]
        _rejected(admin.decrypt, {"IncorrectKeyException"}, KeyId=wrong_id,
                  CiphertextBlob=blob, EncryptionContext=context)
        _rejected(admin.decrypt, {"InvalidCiphertextException"}, CiphertextBlob=blob,
                  EncryptionContext={**context, "Revision": "wrong"})
        _rejected(admin.decrypt, {"InvalidCiphertextException"}, CiphertextBlob=blob[:-1] + bytes([blob[-1] ^ 1]),
                  EncryptionContext=context)
    if len(names) == 2:
        destination = resources[names[1]]
        _rejected(admins[destination["region"]].decrypt, {"IncorrectKeyException"},
                  KeyId=source["arn"], CiphertextBlob=blob, EncryptionContext=context)
    record = {"targets": list(names), "ciphertext": base64.b64encode(blob).decode(),
              "plaintext": base64.b64encode(plain).decode(), "context": context}
    if material_file:
        record["material_file"] = material_file
        record["material_id"] = _independent_decrypt(root, material_file, blob, context, plain)
    return record


def _expiry(endpoint, out, admins, root, context):
    resource = out["resources"]["single"]
    kms = admins[resource["region"]]
    material = (Path(root) / "keys" / "single.bin").read_bytes()
    before = kms.encrypt(KeyId=resource["id"], Plaintext=b"expiry retains ciphertext", EncryptionContext=context)
    short_deadline = _iso(_clock(endpoint) + timedelta(seconds=60))
    _wrapped_import(kms, resource, material, short_deadline)
    try:
        require(_metadata(kms, resource)["ValidTo"] == _date(short_deadline), "Short material expiry was not retained")
        _clock(endpoint, "61s")
        require(_metadata(kms, resource)["KeyState"] == "PendingImport", "Expired real material remained usable")
        _rejected(kms.decrypt, {"KMSInvalidStateException"}, CiphertextBlob=before["CiphertextBlob"],
                  EncryptionContext=context)
        _rejected(kms.encrypt, {"KMSInvalidStateException"}, KeyId=resource["id"], Plaintext=b"must fail")
        _rejected(_wrapped_import, {"IncorrectKeyMaterialException"}, kms=kms, resource=resource,
                  material=(Path(root) / "keys" / "wrong.bin").read_bytes(), valid_to=resource["valid_to"])
    finally:
        _wrapped_import(kms, resource, material, resource["valid_to"])
    require(kms.decrypt(CiphertextBlob=before["CiphertextBlob"], EncryptionContext=context)["Plaintext"]
            == b"expiry retains ciphertext", "Reimport did not recover previous real ciphertext")


def _regional_material_recovery(out, admins, root, context):
    primary, replica = (out["resources"][name] for name in GROUPS[0])
    east, west = admins[primary["region"]], admins[replica["region"]]
    ciphertext = east.encrypt(KeyId=primary["id"], Plaintext=b"regional import presence", EncryptionContext=context)["CiphertextBlob"]
    west.delete_imported_key_material(KeyId=replica["id"])
    try:
        require(_metadata(west, replica)["KeyState"] == "PendingImport", "Deleted replica material stayed usable")
        require(east.decrypt(CiphertextBlob=ciphertext, EncryptionContext=context)["Plaintext"]
                == b"regional import presence", "Replica deletion damaged primary material")
        _rejected(west.decrypt, {"KMSInvalidStateException"}, CiphertextBlob=ciphertext, EncryptionContext=context)
        _rejected(_wrapped_import, {"IncorrectKeyMaterialException"}, kms=west, resource=replica,
                  material=(Path(root) / "keys" / "wrong.bin").read_bytes(), valid_to=replica["valid_to"])
    finally:
        _wrapped_import(west, replica, (Path(root) / "keys" / "multi.bin").read_bytes(), replica["valid_to"])
    require(west.decrypt(CiphertextBlob=ciphertext, EncryptionContext=context)["Plaintext"]
            == b"regional import presence", "Same-material replica reimport did not recover ciphertext")


def _rotate(endpoint, out, admins, root, evidence):
    resources = out["resources"]
    primary, replica = resources["external_primary"], resources["external_replica"]
    east, west = admins[primary["region"]], admins[replica["region"]]
    old_external = _metadata(east, primary)["CurrentKeyMaterialId"]
    material = (Path(root) / "keys" / "rotation.bin").read_bytes()
    imported = _wrapped_import(east, primary, material, ImportType="NEW_KEY_MATERIAL",
                               KeyMaterialDescription=f"{out['name']} actual rotation v2")
    pending_id = imported["KeyMaterialId"]
    require(pending_id != old_external, "New imported bytes did not stage a distinct material")
    pending = east.list_key_rotations(KeyId=primary["id"], IncludeKeyMaterial="ALL_KEY_MATERIAL")["Rotations"]
    require(any(row["KeyMaterialId"] == pending_id and row["KeyMaterialState"]
                == "PENDING_MULTI_REGION_IMPORT_AND_ROTATION" for row in pending),
            "Imported rotation ignored the replica's missing material")
    _rejected(east.rotate_key_on_demand, {"KMSInvalidStateException"}, KeyId=primary["id"])
    _rejected(_wrapped_import, {"IncorrectKeyMaterialException"}, kms=west, resource=replica,
              material=(Path(root) / "keys" / "wrong.bin").read_bytes(), valid_to=replica["valid_to"],
              KeyMaterialId=pending_id)
    _wrapped_import(west, replica, material, replica["valid_to"], KeyMaterialId=pending_id)
    east.rotate_key_on_demand(KeyId=primary["id"])
    generated = resources["primary"]
    old_generated = _metadata(east, generated)["CurrentKeyMaterialId"]
    east.rotate_key_on_demand(KeyId=generated["id"])
    require(east.get_key_rotation_status(KeyId=generated["id"]).get("OnDemandRotationStartDate"),
            "Generated key did not retain its accepted rotation")
    require(east.get_key_rotation_status(KeyId=primary["id"]).get("OnDemandRotationStartDate"),
            "Imported key did not retain its accepted rotation")
    _clock(endpoint, "121s")
    for name in GROUPS[0]:
        resource = resources[name]
        kms = admins[resource["region"]]
        require(_metadata(kms, resource)["CurrentKeyMaterialId"] == pending_id,
                "Imported rotation did not commit the same new material in both Regions")
        rotations = kms.list_key_rotations(KeyId=resource["id"])["Rotations"]
        require(any(row["KeyMaterialId"] == pending_id and row["RotationType"] == "ON_DEMAND"
                    and row["KeyMaterialState"] == "CURRENT" for row in rotations),
                "Actual imported rotation history was not shared")
    generated_id = _metadata(east, generated)["CurrentKeyMaterialId"]
    require(generated_id != old_generated and generated_id == _metadata(west, resources["replica"])["CurrentKeyMaterialId"],
            "Generated rotation did not change shared actual material")
    require(not east.get_key_rotation_status(KeyId=generated["id"]).get("OnDemandRotationStartDate")
            and not east.get_key_rotation_status(KeyId=primary["id"]).get("OnDemandRotationStartDate"),
            "Completed rotation retained an in-progress request")
    evidence["rotated_external_material"] = pending_id
    evidence["rotated_generated_material"] = generated_id
    _save(root, evidence)


def _current_authority(endpoint, out, consumers, admins, context):
    resources = out["resources"]
    primary, replica = resources["external_primary"], resources["external_replica"]
    east, west = admins[primary["region"]], admins[replica["region"]]
    blob = east.encrypt(KeyId=primary["id"], Plaintext=b"current authority", EncryptionContext=context)["CiphertextBlob"]
    consumer_east, consumer_west = consumers[primary["region"]], consumers[replica["region"]]
    policy = json.loads(out["policy"])
    revoked = {**policy, "Statement": [row for row in policy["Statement"] if row["Sid"] == "AccountAdministration"]}
    west.put_key_policy(KeyId=replica["id"], PolicyName="default", Policy=json.dumps(revoked))
    try:
        _rejected(consumer_west.decrypt, {"AccessDeniedException"}, KeyId=replica["id"],
                  CiphertextBlob=blob, EncryptionContext=context)
        require(consumer_east.decrypt(CiphertextBlob=blob, EncryptionContext=context)["Plaintext"] == b"current authority",
                "Independent replica policy incorrectly changed primary authority")
    finally:
        west.put_key_policy(KeyId=replica["id"], PolicyName="default", Policy=out["policy"])
    east.disable_key(KeyId=primary["id"])
    try:
        _rejected(consumer_east.decrypt, {"DisabledException"}, CiphertextBlob=blob, EncryptionContext=context)
        require(consumer_west.decrypt(CiphertextBlob=blob, EncryptionContext=context)["Plaintext"] == b"current authority",
                "Disabling primary incorrectly disabled the related replica")
    finally:
        east.enable_key(KeyId=primary["id"])
    # Current explicit IAM denies defeat the existing resource-policy allow.
    iam = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1").client(
        "iam", endpoint_url=local_endpoint(endpoint), config=Config(signature_version="v4", proxies={},
        connect_timeout=3, read_timeout=60, retries={"max_attempts": 0}))
    deny_name = "keys-current-authority-deny"
    iam.put_user_policy(UserName=out["consumer_user"], PolicyName=deny_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "*"}]}))
    try:
        _rejected(consumer_east.decrypt, {"AccessDeniedException"}, CiphertextBlob=blob, EncryptionContext=context)
        _rejected(consumer_west.decrypt, {"AccessDeniedException"}, CiphertextBlob=blob, EncryptionContext=context)
    finally:
        iam.delete_user_policy(UserName=out["consumer_user"], PolicyName=deny_name)
    iam.update_access_key(UserName=out["consumer_user"], AccessKeyId=out["consumer_key"], Status="Inactive")
    try:
        _rejected(consumer_east.decrypt, {"InvalidClientTokenId", "UnrecognizedClientException"},
                  CiphertextBlob=blob, EncryptionContext=context)
    finally:
        iam.update_access_key(UserName=out["consumer_user"], AccessKeyId=out["consumer_key"], Status="Active")
    require(consumer_west.decrypt(CiphertextBlob=blob, EncryptionContext=context)["Plaintext"] == b"current authority",
            "Current credential/policy recovery did not restore actual bytes")


def verify(endpoint, out, revision, root):
    account = client("sts", endpoint).get_caller_identity()["Account"]
    require(revision in ("v1", "v2") and out["revision"] == revision and out["account_id"] == account,
            "Unexpected key fixture revision/account")
    resources = out["resources"]
    regions = ("us-east-1", "us-west-2")
    admins = {region: _client(endpoint, region) for region in regions}
    consumers = {region: _client(endpoint, region, out["consumer_key"], out["consumer_secret"]) for region in regions}
    denied = {region: _client(endpoint, region, out["denied_key"], out["denied_secret"]) for region in regions}
    path = Path(root) / "keys" / "evidence.json"
    evidence = json.loads(path.read_text()) if path.exists() else {"identities": {}, "records": [], "completed": []}
    identities = {name: row["arn"] for name, row in resources.items()}
    require(not evidence["identities"] or evidence["identities"] == identities,
            "Revision/import/reopen unexpectedly replaced a cryptographic key")
    evidence["identities"] = identities
    descriptions = {"single": "imported single", "external_primary": "imported primary",
                    "external_replica": "imported replica", "primary": "generated primary", "replica": "generated replica"}
    context = {"Fixture": out["name"], "Revision": revision}
    temporarily_enabled = []
    try:
        for name, resource in resources.items():
            kms = admins[resource["region"]]
            metadata = _metadata(kms, resource)
            require(metadata["KeySpec"] == "SYMMETRIC_DEFAULT" and metadata["KeyUsage"] == "ENCRYPT_DECRYPT",
                    f"Native AES key spec/usage changed across import or reopen for {name}")
            expected_enabled = revision == "v1" or name not in ("external_replica", "replica")
            require(metadata["KeyState"] == ("Enabled" if expected_enabled else "Disabled")
                    and metadata["Enabled"] == expected_enabled,
                    f"Terraform/current enabled state differs for {name}")
            require(metadata["Description"] == f"{out['name']} {descriptions[name]} {revision}"
                    and metadata["Origin"] == resource["origin"] and metadata["MultiRegion"] == resource["multi_region"],
                    f"Description/origin/topology update differs for {name}")
            tags = {row["TagKey"]: row["TagValue"] for row in kms.list_resource_tags(KeyId=resource["id"])["Tags"]}
            require(tags["Fixture"] == out["name"] and tags["ConsumerRevision"] == revision
                    and tags["MaterialOwner"] == "keys", f"Current tags differ for {name}")
            require(json.loads(kms.get_key_policy(KeyId=resource["id"], PolicyName="default")["Policy"])
                    == json.loads(out["policy"]), f"Current key policy differs for {name}")
            if resource["origin"] == "EXTERNAL":
                require(metadata["ExpirationModel"] == ("KEY_MATERIAL_EXPIRES" if resource["valid_to"] else "KEY_MATERIAL_DOES_NOT_EXPIRE"),
                        f"Import expiry model differs for {name}")
                require(metadata.get("ValidTo") == (_date(resource["valid_to"]) if resource["valid_to"] else None),
                        f"Imported expiry update differs for {name}")
                _rejected(kms.enable_key_rotation, {"UnsupportedOperationException"}, KeyId=resource["id"])
            if not expected_enabled:
                _rejected(consumers[resource["region"]].encrypt, {"DisabledException"}, KeyId=resource["id"],
                          Plaintext=b"current disabled key", EncryptionContext=context)
                disabled_blob = admins["us-east-1"].encrypt(
                    KeyId=resource["id"], Plaintext=b"linked ciphertext under current disable",
                    EncryptionContext=context)["CiphertextBlob"]
                _rejected(consumers[resource["region"]].decrypt, {"DisabledException"},
                          KeyId=resource["id"], CiphertextBlob=disabled_blob, EncryptionContext=context)
                kms.enable_key(KeyId=resource["id"])
                temporarily_enabled.append(resource)
            _rejected(denied[resource["region"]].encrypt, {"AccessDeniedException"}, KeyId=resource["id"],
                      Plaintext=b"no principal authority", EncryptionContext=context)
        for primary_name, replica_name in GROUPS:
            primary, replica = resources[primary_name], resources[replica_name]
            east, west = admins[primary["region"]], admins[replica["region"]]
            primary_metadata, replica_metadata = _metadata(east, primary), _metadata(west, replica)
            require(primary["id"] == replica["id"] and primary["arn"] != replica["arn"]
                    and primary_metadata["CurrentKeyMaterialId"] == replica_metadata["CurrentKeyMaterialId"],
                    "Related Regions did not share one key/material identity")
            require(primary_metadata["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY"
                    and replica_metadata["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA"
                    and replica_metadata["MultiRegionConfiguration"]["PrimaryKey"]["Arn"] == primary["arn"]
                    and {row["Arn"] for row in primary_metadata["MultiRegionConfiguration"]["ReplicaKeys"]} == {replica["arn"]},
                    "Current primary/replica topology was not retained")
            _rejected(west.rotate_key_on_demand, {"UnsupportedOperationException"}, KeyId=replica["id"])
        for name in GROUPS[1]:
            resource = resources[name]
            status = admins[resource["region"]].get_key_rotation_status(KeyId=resource["id"])
            require(status["KeyRotationEnabled"] and status["RotationPeriodInDays"] == (365 if revision == "v1" else 180),
                    "Primary rotation update did not reach both Regions")
        for names, field in ((GROUPS[0], "rotated_external_material"), (GROUPS[1], "rotated_generated_material")):
            if field in evidence:
                for name in names:
                    resource = resources[name]
                    require(_metadata(admins[resource["region"]], resource)["CurrentKeyMaterialId"] == evidence[field],
                            "Import/reopen changed the completed rotation's current material")
        # These records predate this invocation and survive actual controller reopen
        # and native Terraform import. They must decrypt before any new encryption.
        for record in evidence["records"]:
            _decrypt_record(record, resources, admins, root)
            if record["context"]["Revision"] != revision:
                target = resources[record["targets"][0]]
                _rejected(consumers[target["region"]].decrypt, {"AccessDeniedException"}, KeyId=target["id"],
                          CiphertextBlob=base64.b64decode(record["ciphertext"]), EncryptionContext=record["context"])
        if revision == "v1" and "regional-material-recovery" not in evidence["completed"]:
            _regional_material_recovery(out, admins, root, context)
            evidence["completed"].append("regional-material-recovery")
        if f"expiry-{revision}" not in evidence["completed"]:
            _expiry(endpoint, out, admins, root, context)
            evidence["completed"].append(f"expiry-{revision}")
        if revision == "v2" and not evidence.get("rotated_external_material"):
            _rotate(endpoint, out, admins, root, evidence)
        _current_authority(endpoint, out, consumers, admins, context)
        material_file = "rotation.bin" if evidence.get("rotated_external_material") else "multi.bin"
        new_records = [_round_trip(("single",), resources, consumers, admins, root, context, "single.bin")]
        for names in GROUPS:
            for order in (names, tuple(reversed(names))):
                new_records.append(_round_trip(order, resources, consumers, admins, root, context,
                                               material_file if names == GROUPS[0] else None))
        for record in evidence["records"]:
            _decrypt_record(record, resources, admins, root)
        if f"bytes-{revision}" not in evidence["completed"]:
            evidence["records"].extend(new_records)
            evidence["completed"].append(f"bytes-{revision}")
        _save(root, evidence)
    finally:
        for resource in temporarily_enabled:
            admins[resource["region"]].disable_key(KeyId=resource["id"])
    print(f"Verified keys {revision}: true imported AES bytes, two-way linked-Region crypto, expiry/reimport, "
          "retained ciphertext and current regional/IAM/credential authority", flush=True)


def imports(resources):
    """Native provider IDs for this slice; never import nonrecoverable access-key secrets."""
    owned = {"aws_kms_external_key.keys_single", "aws_kms_external_key.keys_external_primary",
             "aws_kms_replica_external_key.keys_external_replica", "aws_kms_key.keys_primary",
             "aws_kms_replica_key.keys_replica", "aws_kms_alias.keys_single",
             "aws_kms_alias.keys_external_primary", "aws_kms_alias.keys_external_replica",
             "aws_kms_alias.keys_primary", "aws_kms_alias.keys_replica",
             "aws_iam_user.keys_consumer", "aws_iam_user.keys_denied"}
    return {resource["address"]: resource["values"]["id"] for resource in resources
            if resource["address"] in owned}


def verify_deleted(endpoint, out, root):
    """Terraform destroys aliases/users, but KMS destruction schedules real deletion."""
    resources = out["resources"]
    for name, resource in resources.items():
        kms = _client(endpoint, resource["region"])
        metadata = _metadata(kms, resource)
        primary = name in ("external_primary", "primary")
        require(metadata["KeyState"] == ("PendingReplicaDeletion" if primary else "PendingDeletion"),
                f"Scheduled KMS deletion semantics differ for {name}")
        if primary:
            require("DeletionDate" not in metadata and metadata["PendingDeletionWindowInDays"] == 7,
                    "Primary deletion window started before its replica was physically removed")
        else:
            require(metadata.get("DeletionDate") and metadata["DeletionDate"] > _clock(endpoint),
                    "Scheduled deletion did not retain a future physical deletion date")
        _rejected(kms.encrypt, {"KMSInvalidStateException"}, KeyId=resource["id"], Plaintext=b"pending deletion")
        aliases = {row["AliasName"] for row in kms.list_aliases()["Aliases"]}
        require(resource["alias"] not in aliases, "Destroyed Terraform alias remains live")
    evidence = json.loads((Path(root) / "keys" / "evidence.json").read_text())
    for record in evidence["records"]:
        for name in record["targets"]:
            resource = resources[name]
            _rejected(_client(endpoint, resource["region"]).decrypt, {"KMSInvalidStateException"},
                      KeyId=resource["id"], CiphertextBlob=base64.b64decode(record["ciphertext"]),
                      EncryptionContext=record["context"])
    _rejected(_client(endpoint, "us-east-1", out["consumer_key"], out["consumer_secret"]).encrypt,
              {"InvalidClientTokenId", "UnrecognizedClientException"}, KeyId=resources["single"]["id"], Plaintext=b"deleted consumer")
    print("Verified KMS pending deletion (not immediate physical removal), alias removal and revoked consumer credentials", flush=True)
