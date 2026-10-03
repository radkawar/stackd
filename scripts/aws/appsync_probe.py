#!/usr/bin/env python3
"""Capture exact-owned AppSync JS, GraphQL and real-time behavior; always clean up."""
import argparse
import base64
import datetime
import json
import os
import time
import uuid

import boto3
import requests
import websocket
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

SCHEMA = '''
type Thing @aws_api_key @aws_iam { id: ID!, title: String!, optional: String, json: AWSJSON }
input ThingInput { id: ID!, title: String!, json: AWSJSON }
type Query { item(id: ID!): Thing @aws_api_key @aws_iam, fail: String, missing: String }
type Mutation { put(input: ThingInput!): Thing @aws_api_key @aws_iam }
type Subscription { changed(id: ID): Thing @aws_subscribe(mutations: ["put"]) @aws_api_key @aws_iam }
schema { query: Query, mutation: Mutation, subscription: Subscription }
'''
UNIT = '''export function request(ctx) {return {payload:{id:ctx.args.id,title:'loaded',json:{nested:1}}};}
export function response(ctx) {return ctx.result;}'''
BEFORE = '''export function request(ctx) {ctx.stash.title = ctx.args.input.title + '!'; return ctx.args.input;}
export function response(ctx) {return ctx.prev.result;}'''
FUNCTION = '''export function request(ctx) {return {payload:{id:ctx.prev.result.id,title:ctx.stash.title,json:ctx.prev.result.json}};}
export function response(ctx) {return ctx.result;}'''
FAIL = '''import { util } from '@aws-appsync/utils';
export function request(ctx) { util.error('owned failure','OwnedError'); }
export function response(ctx) { return ctx.result; }'''
RUNTIME = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    session = boto3.Session(region_name="us-east-1")
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Native probe requires the authorized account")
    client, iam = session.client("appsync"), session.client("iam")
    name = "stackd-next-appsync-" + uuid.uuid4().hex[:12]
    api_id, role_name = None, None
    result = {"capturedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "account": identity["Account"], "region": "us-east-1", "name": name, "cases": {}, "cleanup": {}}
    conn = None
    try:
        created = client.create_graphql_api(name=name, authenticationType="API_KEY", additionalAuthenticationProviders=[{"authenticationType": "AWS_IAM"}], tags={"stackd-probe": name})["graphqlApi"]
        api_id = created["apiId"]
        result["apiId"] = api_id
        result["cases"]["create"] = {k: created.get(k) for k in ("authenticationType", "apiType", "visibility", "introspectionConfig", "queryDepthLimit", "resolverCountLimit")}
        client.start_schema_creation(apiId=api_id, definition=SCHEMA.encode())
        for _ in range(90):
            status = client.get_schema_creation_status(apiId=api_id)
            if status["status"] in ("SUCCESS", "FAILED"):
                break
            time.sleep(1)
        if status["status"] != "SUCCESS":
            raise RuntimeError(str(status))
        key = client.create_api_key(apiId=api_id)["apiKey"]
        result["cases"]["keyLifetime"] = {"expires": key["expires"], "deletes": key.get("deletes"), "expiresHourAligned": key["expires"] % 3600 == 0}
        zero_key = client.create_api_key(apiId=api_id, expires=0)["apiKey"]
        result["cases"]["zeroKeyLifetime"] = {"expires": zero_key["expires"], "deletes": zero_key.get("deletes"), "defaultSevenDays": 7 * 86400 - 3600 <= zero_key["expires"] - time.time() <= 7 * 86400}
        ten_day_key = client.create_api_key(apiId=api_id, expires=int(time.time()) + 10 * 86400)["apiKey"]
        updated_key = client.update_api_key(apiId=api_id, id=ten_day_key["id"], expires=0)["apiKey"]
        result["cases"]["updateZeroKeepsExpiration"] = updated_key["expires"] == ten_day_key["expires"]
        client.create_data_source(apiId=api_id, name="none", type="NONE")
        client.create_resolver(apiId=api_id, typeName="Query", fieldName="item", dataSourceName="none", runtime=RUNTIME, code=UNIT)
        client.create_resolver(apiId=api_id, typeName="Query", fieldName="fail", dataSourceName="none", runtime=RUNTIME, code=FAIL)
        function = client.create_function(apiId=api_id, name="transform", dataSourceName="none", runtime=RUNTIME, code=FUNCTION)["functionConfiguration"]
        client.create_resolver(apiId=api_id, typeName="Mutation", fieldName="put", kind="PIPELINE", pipelineConfig={"functions": [function["functionId"]]}, runtime=RUNTIME, code=BEFORE)
        endpoint = created["uris"]["GRAPHQL"]
        headers = {"x-api-key": key["id"], "content-type": "application/json"}

        def query(label, document, variables=None, extra=None):
            response = requests.post(endpoint, json={"query": document, "variables": variables or {}}, headers=extra or headers, timeout=30)
            result["cases"][label] = {"status": response.status_code, "body": response.json()}
            return response

        # Native resources become visible to the serving fleet independently of
        # control acceptance. Only the first propagation query is retried.
        for _ in range(60):
            response = query("query", 'query($id: ID!) { alias:item(id:$id){...F json} missing } fragment F on Thing {id title}', {"id": "one"})
            if response.status_code == 200 and response.json().get("data", {}).get("alias"):
                break
            time.sleep(1)
        query("invalidKey", '{ item(id:"one"){id} }', extra={"x-api-key": "da2-invalid", "content-type": "application/json"})
        query("mappingError", '{ fail missing }')
        query("unknownField", '{ absent }')
        query("jsonInput", 'mutation($i: ThingInput!){put(input:$i){id title json}}', {"i": {"id": "one", "title": "input", "json": '{"value":42}'}})
        query("invalidJSON", 'mutation($i: ThingInput!){put(input:$i){id}}', {"i": {"id": "one", "title": "input", "json": "invalid"}})
        query("missingVariable", 'query($id:ID!){item(id:$id){id}}')
        ws_url = created["uris"]["REALTIME"].replace("https://", "wss://")
        host = requests.utils.urlparse(endpoint).netloc
        auth = {"host": host, "x-api-key": key["id"]}
        url = ws_url + "?header=" + base64.b64encode(json.dumps(auth).encode()).decode() + "&payload=e30="
        conn = websocket.create_connection(url, subprotocols=["graphql-ws"], timeout=20)
        conn.send(json.dumps({"type": "connection_init"}))

        def receive(kind, wanted=None):
            while True:
                message = json.loads(conn.recv())
                if message["type"] == kind and (wanted is None or message.get("id") == wanted):
                    return message
                if message["type"] in ("error", "connection_error"):
                    raise RuntimeError(str(message))

        result["cases"]["connectionAck"] = receive("connection_ack")
        subscription = 'subscription {changed(id:"one"){id title optional}}'
        conn.send(json.dumps({"id": "owned", "type": "start", "payload": {"data": json.dumps({"query": subscription, "variables": {}}), "extensions": {"authorization": auth}}}))
        result["cases"]["startAck"] = receive("start_ack", "owned")
        query("mutationSubscription", 'mutation {put(input:{id:"one",title:"notify"}){id title}}')
        result["cases"]["subscriptionData"] = receive("data", "owned")
        conn.send(json.dumps({"id": "owned", "type": "stop"}))
        result["cases"]["stop"] = receive("complete", "owned")
        conn.close()
        conn = None

        # Isolated role distinguishes root-field grants from nested-field grants.
        role_name = name
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": identity["Arn"]}, "Action": "sts:AssumeRole"}]}), Tags=[{"Key": "stackd-probe", "Value": name}])
        field_arn = created["arn"] + "/types/Query/fields/item"
        iam.put_role_policy(RoleName=role_name, PolicyName="owned", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "appsync:GraphQL", "Resource": field_arn}]}))
        time.sleep(10)
        temporary = sts.assume_role(RoleArn=f'arn:aws:iam::{identity["Account"]}:role/{role_name}', RoleSessionName="owned")["Credentials"]
        from botocore.credentials import Credentials
        credentials = Credentials(temporary["AccessKeyId"], temporary["SecretAccessKey"], temporary["SessionToken"])
        payload = json.dumps({"query": '{item(id:"one"){id title}}'})
        request = AWSRequest(method="POST", url=endpoint, data=payload, headers={"content-type": "application/json"})
        SigV4Auth(credentials, "appsync", "us-east-1").add_auth(request)
        response = requests.post(endpoint, data=payload, headers=dict(request.headers), timeout=30)
        result["cases"]["iamRootFieldOnly"] = {"status": response.status_code, "body": response.json()}
    finally:
        if conn is not None:
            conn.close()
        if role_name is not None:
            iam.delete_role_policy(RoleName=role_name, PolicyName="owned")
            iam.delete_role(RoleName=role_name)
            result["cleanup"]["roleDeleted"] = True
        if api_id is not None:
            client.delete_graphql_api(apiId=api_id)
            result["cleanup"]["apiDeleted"] = True
        with open(args.output, "w", encoding="utf-8") as target:
            json.dump(result, target, indent=2)
            target.write("\n")
        print(json.dumps({"capture": args.output, "cases": sorted(result["cases"]), "cleanup": result["cleanup"]}))


if __name__ == "__main__":
    main()
