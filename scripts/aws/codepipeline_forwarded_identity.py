"""Discover a native forwarding condition value through an owned role policy.

Session-tag substitutions vary the query without repeatedly changing IAM policies.
Only the assumed-role ARN and request ID are retained, never credentials.
"""

import string
import time


CANDIDATES = 40
ALPHABET = string.ascii_letters + string.digits + "-_.:/=+@ "


def conditions():
    return {
        "StringEquals": {"aws:PrincipalTag/probe-mode": "prefix"},
        "StringLike": {
            "aws:CalledViaLast": ["${aws:PrincipalTag/probe-" + str(i) + "}*" for i in range(CANDIDATES)]
        },
    }


def exact_statement(resource):
    return {
        "Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"], "Resource": resource,
        "Condition": {"StringEquals": {
            "aws:PrincipalTag/probe-mode": "exact",
            "aws:CalledViaLast": "${aws:PrincipalTag/probe-0}",
        }},
    }


def discover(session, clients, config, role_arn, deployment, call, evidence, save):
    queries = evidence["forwarded_identity_queries"] = []

    def accepts(prefixes, exact=False):
        if not prefixes or len(prefixes) > CANDIDATES or len(queries) >= 768:
            raise RuntimeError("Forwarding discovery query bound exceeded")
        tags = [{"Key": "probe-mode", "Value": "exact" if exact else "prefix"}]
        tags.extend({"Key": "probe-" + str(i), "Value": prefixes[min(i, len(prefixes) - 1)]}
                    for i in range(CANDIDATES))
        assumed = clients["sts"].assume_role(
            RoleArn=role_arn, RoleSessionName="called-via-" + str(len(queries)),
            DurationSeconds=900, Tags=tags)
        credentials = assumed["Credentials"]
        consumer = session.client("appconfig", config=config,
                                  aws_access_key_id=credentials["AccessKeyId"],
                                  aws_secret_access_key=credentials["SecretAccessKey"],
                                  aws_session_token=credentials["SessionToken"])
        try:
            call("appconfig", "start_deployment", deployment,
                 label="ForwardedIdentityQuery" + str(len(queries)), api_client=consumer,
                 allowed=("Success", "BadRequestException"))
        finally:
            consumer.close()
        code = evidence["calls"][-1]["code"]
        queries.append({"prefixes": prefixes, "exact": exact, "code": code,
                        "session_arn": assumed["AssumedRoleUser"]["Arn"],
                        "assume_request_id": assumed["ResponseMetadata"]["RequestId"]})
        save()
        time.sleep(0.25)
        return code == "Success"

    if not accepts([""]):
        raise RuntimeError("Native forwarding did not authorize the tagged wildcard control")
    prefix = ""
    for _ in range(96):
        if accepts([prefix], exact=True):
            evidence["forwarded_called_via_last"] = prefix
            save()
            return prefix
        remaining = ALPHABET
        while len(remaining) > 1:
            split = (len(remaining) + 1) // 2
            candidates = remaining[:split]
            if accepts([prefix + c for c in candidates]):
                remaining = candidates
            else:
                remaining = remaining[split:]
        prefix += remaining
        if not accepts([prefix]):
            raise RuntimeError("Native forwarding value is outside the bounded tag alphabet")
        evidence["forwarded_identity_prefix"] = prefix
        save()
    raise RuntimeError("Native forwarding value exceeded the length bound")
