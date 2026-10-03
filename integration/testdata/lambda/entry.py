"""Real RIC entry points for native-AWS replay and execution-role SDK calls."""
import os

import handler as native_handler


def invoke(event, context):
    result = native_handler.handler(event, context)
    result["runtime_owner"] = os.environ["AWS_LAMBDA_LOG_STREAM_NAME"]
    return result


def send(event, context):
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError

    client = boto3.client("sqs", config=Config(retries={"max_attempts": 0}))
    result = {"runtime_owner": os.environ["AWS_LAMBDA_LOG_STREAM_NAME"]}
    try:
        sent = client.send_message(QueueUrl=event["queue_url"], MessageBody=event["body"])
        result["message_id"] = sent["MessageId"]
    except ClientError as error:
        result["error_code"] = error.response["Error"]["Code"]
    return result
