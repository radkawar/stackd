#!/usr/bin/env python3
"""Compare repeated-query SigV4 value ordering against native AWS STS.

Uses only GetCallerIdentity. Captures status/error codes, never identities,
credentials, request headers or response bodies. Requires boto3.
"""

import argparse
import datetime
import json
import pathlib
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, quote, urlsplit

import boto3
import botocore
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


class DecodedValueSort(SigV4Auth):
    """Reproduce the Go v2 signer's pre-encoding repeated-value sort."""

    def canonical_query_string(self, request):
        pairs = sorted(parse_qsl(urlsplit(request.url).query, keep_blank_values=True))
        return "&".join(
            quote(key, safe="-_.~") + "=" + quote(value, safe="-_.~")
            for key, value in pairs
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not exist")
    credentials = boto3.Session(profile_name=args.profile).get_credentials()
    if credentials is None:
        parser.error("profile has no AWS credentials")
    credentials = credentials.get_frozen_credentials()
    url = (
        "https://sts.us-east-1.amazonaws.com/"
        "?Action=GetCallerIdentity&Version=2011-06-15&tagKeys=~&tagKeys=%E7%95%8C"
    )
    observations = []
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for name, signer in [
        ("encoded_value_sort", SigV4Auth),
        ("decoded_value_sort", DecodedValueSort),
    ]:
        request = AWSRequest(method="GET", url=url)
        signer(credentials, "sts", "us-east-1").add_auth(request)
        prepared = request.prepare()
        wire = urllib.request.Request(
            prepared.url, headers=dict(prepared.headers), method="GET"
        )
        try:
            response = opener.open(wire, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = ET.fromstring(response.read())
            code = next(
                (node.text for node in payload.iter() if node.tag.rsplit("}", 1)[-1] == "Code"),
                None,
            )
            observations.append(
                {"variant": name, "status": response.status, "error_code": code}
            )
    capture = {
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": "native AWS STS GetCallerIdentity, us-east-1, read-only",
        "probe": "scripts/aws/sigv4_query_order_probe.py",
        "botocore_version": botocore.__version__,
        "query": urlsplit(url).query,
        "observations": observations,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as output:
        output.write(json.dumps(capture, indent=2) + "\n")
    print(json.dumps(observations, indent=2))


if __name__ == "__main__":
    main()
