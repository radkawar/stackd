"""Signed AWS requests for behavior probes that bypass CLI shape validation."""
import datetime
import hashlib
import hmac
import json
import subprocess
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aws_cli import ProbeResult

_RAW_CREDENTIALS: dict[str, Any] | None = None


@dataclass(frozen=True)
class SignedResponse:
    status: int
    body: bytes
    request_id: str | None


def signed_post(endpoint: str, service: str, body: bytes, headers: Mapping[str, str],
                environment: Mapping[str, str] | None = None) -> SignedResponse:
    global _RAW_CREDENTIALS
    credentials = _RAW_CREDENTIALS if environment is None else None
    if credentials is None:
        process = subprocess.run(["aws", "configure", "export-credentials", "--format", "process"],
                                 capture_output=True, text=True, timeout=30, env=environment)
        if process.returncode:
            raise RuntimeError("Unable to load AWS credentials for signed requests; diagnostics discarded")
        credentials = json.loads(process.stdout)
        if environment is None:
            _RAW_CREDENTIALS = credentials
    now = datetime.datetime.now(datetime.timezone.utc)
    date, instant = now.strftime("%Y%m%d"), now.strftime("%Y%m%dT%H%M%SZ")
    headers = dict(headers, host=endpoint)
    headers["x-amz-date"] = instant
    if credentials.get("SessionToken"):
        headers["x-amz-security-token"] = credentials["SessionToken"]
    names = ";".join(sorted(headers))
    canonical = "POST\n/\n\n" + "".join(name + ":" + headers[name] + "\n" for name in sorted(headers)) + "\n" + names + "\n" + hashlib.sha256(body).hexdigest()
    scope = date + "/us-east-1/" + service + "/aws4_request"
    signing_key = ("AWS4" + credentials["SecretAccessKey"]).encode()
    for item in (date, "us-east-1", service, "aws4_request"):
        signing_key = hmac.new(signing_key, item.encode(), hashlib.sha256).digest()
    signature = hmac.new(signing_key, ("AWS4-HMAC-SHA256\n" + instant + "\n" + scope + "\n" + hashlib.sha256(canonical.encode()).hexdigest()).encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + credentials["AccessKeyId"] + "/" + scope + ", SignedHeaders=" + names + ", Signature=" + signature
    request = urllib.request.Request("https://" + endpoint + "/", data=body, headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return SignedResponse(response.status, response.read(),
                              response.headers.get("x-amzn-requestid") or response.headers.get("x-amz-request-id"))


def observe_json(endpoint: str, service: str, target: str,
                 parameters: Mapping[str, Any], environment: Mapping[str, str] | None = None) -> ProbeResult:
    """Observe one AWS JSON call, retaining native error fields and HTTP status.

    Like signed_post, this signs for us-east-1 without retrying. Non-JSON or
    unmodeled errors raise rather than becoming invented AWS observations.
    """
    response = signed_post(endpoint, service, json.dumps(parameters).encode(),
                           {"content-type": "application/x-amz-json-1.0", "x-amz-target": target},
                           environment)
    output = json.loads(response.body)
    if 200 <= response.status < 300:
        return {"code": "Success", "output": output, "http_status": response.status, "request_id": response.request_id}
    return {"code": output["__type"].split("#")[-1], "error": output, "http_status": response.status, "request_id": response.request_id}
