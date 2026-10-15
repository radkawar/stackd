"""Independent signed Lambda consumer and real ECR OCI HTTP byte consumer.

The OCI artifact carries actual gzipped tar content, not an executable container
or Lambda RIC image. No Docker pull/execution claim follows from these checks.
"""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, Request

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from local import client, local_endpoint, require


def get_bytes(endpoint, url, headers=None, data=None):
    require(urlsplit(url).netloc == urlsplit(endpoint).netloc,
            f"Refusing content outside the owned endpoint: {url}")
    with build_opener(ProxyHandler({})).open(Request(url, data=data, headers=headers or {}), timeout=60) as response:
        return response.read()


def check_result(result, revision, message, version):
    require(result == {"revision": revision, "code_revision": revision,
                       "layer": "native-layer-bytes", "message": message,
                       "version": str(version)}, f"Unexpected actual handler output: {result}")


def consume(endpoint, output, image, previous=None):
    lambdas, ecr = client("lambda", endpoint), client("ecr", endpoint)
    revision = output["revision"]
    for qualifier in (output["alias"], output["version"]):
        response = lambdas.invoke(FunctionName=output["function_name"], Qualifier=qualifier,
                                  Payload=json.dumps({"message": "signed-independent"}).encode())
        stream = response["Payload"]
        try:
            payload = stream.read()
        finally:
            stream.close()
        require(response["StatusCode"] == 200 and not response.get("FunctionError"),
                f"Runtime failure: {response.get('FunctionError')} {payload!r}")
        check_result(json.loads(payload), revision, "signed-independent", output["version"])
    for key, message in (("invocation_result", "terraform-resource"), ("data_result", "terraform-data")):
        check_result(output[key], revision, message, output["version"])
    # URL updates intentionally retain propagation. Actual responses, not API
    # configuration, establish when the URL's selected alias executes new code.
    deadline = time.monotonic() + 90
    while True:
        result = json.loads(get_bytes(endpoint, output["function_url"],
                                      {"Content-Type": "application/json"},
                                      json.dumps({"message": "independent-url"}).encode()))
        if result.get("revision") == revision:
            check_result(result, revision, "independent-url", output["version"])
            break
        require(time.monotonic() < deadline, f"Function URL propagation did not converge: {result}")
        time.sleep(1)
    configuration = lambdas.get_function_configuration(FunctionName=output["function_name"])
    require(configuration["MemorySize"] == (256 if revision == "first" else 384), "Memory update was not applied")
    require(configuration["Environment"]["Variables"]["FIXTURE_REVISION"] == revision, "Environment update was not applied")
    require(lambdas.get_function_recursion_config(FunctionName=output["function_name"])["RecursiveLoop"] ==
            ("Terminate" if revision == "first" else "Allow"), "Recursion update was not retained")
    require(lambdas.get_runtime_management_config(FunctionName=output["function_name"])["UpdateRuntimeOn"] ==
            ("Auto" if revision == "first" else "FunctionUpdate"), "Runtime policy update was not retained")
    if previous is not None:
        response = lambdas.invoke(FunctionName=output["function_name"], Qualifier=previous["version"],
                                  Payload=json.dumps({"message": "old-version"}).encode())
        stream = response["Payload"]
        try:
            payload = stream.read()
        finally:
            stream.close()
        require(not response.get("FunctionError"), f"Published version failed: {payload!r}")
        check_result(json.loads(payload), previous["revision"], "old-version", previous["version"])

    authorization = output["authorization"]
    require(urlsplit(authorization["proxy_endpoint"]).netloc == urlsplit(endpoint).netloc,
            "Registry token endpoint left local origin")
    headers = {"Authorization": "Basic " + authorization["authorization_token"],
               "Accept": "application/vnd.oci.image.manifest.v1+json"}
    base = endpoint + "/v2/" + output["repository_url"].split("/", 1)[1]
    manifest_bytes = get_bytes(endpoint, base + "/manifests/dev-current", headers)
    require("sha256:" + hashlib.sha256(manifest_bytes).hexdigest() == image["digest"], "Manifest digest mismatch")
    require(output["image_digest"] == image["digest"], "Terraform image discovery differs from real manifest")
    manifest = json.loads(manifest_bytes)
    config_bytes = get_bytes(endpoint, base + "/blobs/" + manifest["config"]["digest"], headers)
    layer_bytes = get_bytes(endpoint, base + "/blobs/" + manifest["layers"][0]["digest"], headers)
    for descriptor, data in ((manifest["config"], config_bytes), (manifest["layers"][0], layer_bytes)):
        require(len(data) == descriptor["size"] and "sha256:" + hashlib.sha256(data).hexdigest() == descriptor["digest"],
                "OCI descriptor does not match independently downloaded bytes")
    config = json.loads(config_bytes)
    uncompressed = gzip.decompress(layer_bytes)
    require(config["rootfs"]["diff_ids"] == ["sha256:" + hashlib.sha256(uncompressed).hexdigest()], "OCI diff ID mismatch")
    with tarfile.open(fileobj=io.BytesIO(uncompressed), mode="r:") as archive:
        stream = archive.extractfile("payload.bin")
        require(stream is not None, "OCI tar lacks payload.bin")
        require(stream.read() == base64.b64decode(image["payload_base64"]), "OCI tar payload bytes changed")
    url = ecr.get_download_url_for_layer(repositoryName=output["repository"],
                                         layerDigest=manifest["layers"][0]["digest"])["downloadUrl"]
    require(get_bytes(endpoint, url) == layer_bytes, "Signed SDK download URL changed OCI bytes")
    print(f"Consumer verified {revision}: real ZIP, immutable version, alias, layer import, URL and OCI tar/config/manifest bytes", flush=True)


if __name__ == "__main__":
    require(len(sys.argv) in (4, 5), "Usage: consumer.py ENDPOINT OUTPUTS.json IMAGE.json [PREVIOUS.json]")
    consume(local_endpoint(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text()),
            json.loads(Path(sys.argv[3]).read_text()),
            json.loads(Path(sys.argv[4]).read_text()) if len(sys.argv) == 5 else None)
