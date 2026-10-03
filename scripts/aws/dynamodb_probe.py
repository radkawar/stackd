"""Shared recording and real-table lifecycle for DynamoDB behavior probes."""
import datetime
import json
import pathlib
import time
from typing import Any, Literal, NotRequired, cast

from aws_cli import ProbeResult, observe
from signed_requests import observe_json


class Observation(ProbeResult):
    sequence: int
    label: str
    service: str
    region: str
    operation: str
    input: dict[str, Any]
    startedAt: str
    startedOffsetSeconds: float
    finishedAt: str
    durationSeconds: float
    transport: str
    transportErrorType: NotRequired[str]

def timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class DynamoDBProbe:
    def __init__(self, output: pathlib.Path, capture: dict[str, Any], environment: dict[str, str]):
        self.output = output
        self.capture = capture
        self.environment = environment
        self.origin = time.monotonic()

    def save(self) -> None:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(json.dumps(self.capture, indent=2) + "\n")

    def call(self, label: str, operation: str, parameters: dict[str, Any],
             service: Literal["dynamodb", "sts"] = "dynamodb", *, region: str | None = None) -> Observation:
        region = region or self.capture["region"]
        start = time.monotonic()
        row = {"sequence": len(self.capture["calls"]) + 1, "label": label, "service": service,
               "operation": operation, "region": region, "input": parameters, "startedAt": timestamp(),
               "startedOffsetSeconds": round(start - self.origin, 6)}
        self.capture["calls"].append(row)
        self.save()
        try:
            if service == "dynamodb" and region == "us-east-1":
                row["transport"] = "signed_requests.observe_json"
                target = "DynamoDB_20120810." + "".join(part.capitalize() for part in operation.split("-"))
                row.update(observe_json("dynamodb.us-east-1.amazonaws.com", service, target, parameters, self.environment))
            else:
                row["transport"] = "aws_cli.observe"
                # The raw signer is east-only; the CLI owns other regional signing.
                environment = dict(self.environment, AWS_REGION=region, AWS_DEFAULT_REGION=region)
                environment["AWS_ENDPOINT_URL_" + service.upper()] = f"https://{service}.{region}.amazonaws.com"
                row.update(observe(service, operation, parameters, environment, paginate=False))
        except Exception as error:
            row.update(code="ClientTransportError", transportErrorType=type(error).__name__)
            raise RuntimeError(label + ": transport " + type(error).__name__) from error
        finally:
            row.update(finishedAt=timestamp(), durationSeconds=round(time.monotonic() - start, 6))
            self.save()
        return cast(Observation, row)

    def ready(self, table: str, label: str) -> Observation:
        """Wait for the table AND every GSI; ACTIVE on the table alone is insufficient."""
        for attempt in range(180):
            row = self.call(label + "-describe-" + str(attempt), "describe-table", {"TableName": table})
            if row["code"] != "Success":
                raise RuntimeError(label + ": describe " + row["code"])
            result = row["output"]["Table"]
            if result["TableArn"].split(":")[3:5] != [self.capture["region"], self.capture["account"]]:
                raise RuntimeError("unexpected table account/region")
            if result["TableStatus"] == "ACTIVE" and all(index["IndexStatus"] == "ACTIVE" for index in result.get("GlobalSecondaryIndexes", [])):
                return row
            time.sleep(2)
        raise RuntimeError(label + ": table failed to settle")

    def delete(self, table: str) -> None:
        """Delete one caller-owned table and retain the actual absence observation."""
        cleanup = self.capture["cleanup"].setdefault(table, {"verifiedAbsent": False})
        row = self.call("delete-owned", "delete-table", {"TableName": table})
        if row["code"] not in ("Success", "ResourceNotFoundException"):
            raise RuntimeError("delete rejected: " + row["code"])
        for attempt in range(180):
            row = self.call("verify-absent-" + str(attempt), "describe-table", {"TableName": table})
            if row["code"] == "ResourceNotFoundException":
                cleanup.update(verifiedAbsent=True, verificationSequence=row["sequence"], verifiedAt=row["finishedAt"])
                return
            if row["code"] != "Success":
                raise RuntimeError("absence verification rejected: " + row["code"])
            time.sleep(2)
        raise RuntimeError("owned table absence not observed")
