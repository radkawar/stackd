"""Actually executed by the Docker Python runtime, never imported by the driver."""

from pathlib import Path
import uuid

MESSAGE = "first"
BOOT_ID = str(uuid.uuid4())


def invoke(event, context):
    marker = Path("/tmp/stackd-example-marker")
    if not marker.exists():
        marker.write_text(str(uuid.uuid4()))
    return {
        "message": MESSAGE,
        "echo": event["message"],
        "boot_id": BOOT_ID,
        "tmp_id": marker.read_text(),
        "function_arn": context.invoked_function_arn,
        "function_version": context.function_version,
    }
