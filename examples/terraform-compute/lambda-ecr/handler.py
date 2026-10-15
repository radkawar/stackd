"""Runs inside the official Python RIC, importing the uploaded Lambda layer."""
import json
import os

from fixture_layer import LAYER_VALUE

CODE_REVISION = "first"


def invoke(event, context):
    is_url = "requestContext" in event and "http" in event["requestContext"]
    request = json.loads(event.get("body") or "{}") if is_url else event
    result = {
        "revision": os.environ["FIXTURE_REVISION"],
        "code_revision": CODE_REVISION,
        "layer": LAYER_VALUE,
        "message": request.get("message"),
        "version": context.function_version,
    }
    if is_url:
        return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
                "body": json.dumps(result)}
    return result
