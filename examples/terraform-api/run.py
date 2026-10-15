"""Run Terraform 1.15.9 / AWS 6.68.0 API, GraphQL and DNS consumers in owned state."""

import http.client
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (ACCOUNT, REGION, arguments, client, controller, environment,
                   expect_missing, require, workspace)

STORAGE = "ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc"
RUNTIME = "public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3"


def main():
    parser = arguments(__doc__, 14703)
    parser.add_argument("--dns-port", type=int, default=15703)
    parser.add_argument("--provider-mirror", type=Path)
    parser.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"))
    args = parser.parse_args()
    for binary in ("terraform", "openssl", "docker", "dig"):
        require(shutil.which(binary), f"Install {binary} first")
    require(args.docker_host.startswith("unix:///"), "Use an explicit local Docker Unix socket")
    require(1024 <= args.dns_port <= 65535 and args.dns_port != args.port, "Choose a distinct unprivileged DNS port")
    for network in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(type=network) as probe:
            probe.bind(("127.0.0.1", args.dns_port))
    for image in (STORAGE, RUNTIME):
        subprocess.run(["docker", "--host", args.docker_host, "image", "inspect", image],
                       check=True, stdout=subprocess.DEVNULL)
    helper = args.stackd.resolve().parent / "lambda-telemetry-amd64"
    require(helper.is_file(), f"Prepare the Linux helper: {helper}")
    root = workspace(args, "terraform-api")
    root.chmod(0o700)  # Contains API keys, TLS keys and sensitive Terraform state.
    name = "stackd-api-" + uuid.uuid4().hex[:12]
    domain = name + ".test"
    source = Path(__file__).resolve().parent
    shutil.copyfile(source / "main.tf", root / "main.tf")
    ca, cert, key = root / "ca.pem", root / "server.pem", root / "server.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=stackd-api-fixture", "-keyout", str(root / "ca.key"), "-out", str(ca),
                    "-addext", "basicConstraints=critical,CA:TRUE"], check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1",
                    "-keyout", str(key), "-out", str(root / "server.csr")], check=True, capture_output=True)
    (root / "server.ext").write_text("subjectAltName=IP:127.0.0.1\n"
                                    "basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                                    "extendedKeyUsage=serverAuth\n")
    subprocess.run(["openssl", "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(ca),
                    "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "2",
                    "-extfile", str(root / "server.ext"), "-out", str(cert)], check=True, capture_output=True)
    domain_cert, domain_key = root / "domain.pem", root / "domain.key"
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={domain}",
                    "-keyout", str(domain_key), "-out", str(root / "domain.csr")], check=True, capture_output=True)
    (root / "domain.ext").write_text(f"subjectAltName=DNS:{domain}\n"
                                    "basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                                    "extendedKeyUsage=serverAuth\n")
    subprocess.run(["openssl", "x509", "-req", "-in", str(root / "domain.csr"), "-CA", str(ca),
                    "-CAkey", str(root / "ca.key"), "-CAserial", str(root / "ca.srl"), "-days", "2",
                    "-extfile", str(root / "domain.ext"), "-out", str(domain_cert)], check=True, capture_output=True)
    env = environment()
    configuration = "disable_checkpoint = true\n"
    if args.provider_mirror is not None:
        require(args.provider_mirror.is_dir(), "Provider mirror does not exist")
        configuration += ("provider_installation {\n filesystem_mirror {\n path = "
                          + json.dumps(str(args.provider_mirror.resolve()))
                          + '\n include = ["registry.terraform.io/hashicorp/aws"]\n }\n}\n')
    (root / "terraform.rc").write_text(configuration)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        return subprocess.run(["terraform", *command], cwd=root, env=env, check=check,
                              text=True, capture_output=capture)

    tls = ssl.create_default_context(cafile=str(ca))

    def request(endpoint, path, body=None, headers=None, sni=None):
        parsed = urlsplit(endpoint)
        require(parsed.hostname == "127.0.0.1", "Refusing non-owned HTTP consumer")
        connection = http.client.HTTPSConnection("127.0.0.1", parsed.port, context=tls, timeout=45)
        if sni is not None:
            address = dns(sni, "A", "127.0.0.1")
            connection.sock = tls.wrap_socket(socket.create_connection((address, parsed.port), timeout=45),
                                              server_hostname=sni)
        try:
            connection.request("POST" if body is not None else "GET", path, body=body,
                               headers={"Host": sni or parsed.netloc, **(headers or {})})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def dns(name, kind, expected, tcp=False):
        result = subprocess.check_output(["dig", "@127.0.0.1", "-p", str(args.dns_port), name, kind,
                                          "+time=2", "+tries=1", "+short", *( ["+tcp"] if tcp else [])], text=True)
        require(result.strip().splitlines() == [expected], f"Unexpected real DNS answer for {name}: {result!r}")
        return result.strip()

    extra = ["-dns-listen", f"127.0.0.1:{args.dns_port}", "-docker-host", args.docker_host,
             "-lambda-runtime", "-lambda-telemetry-directory", str(helper.parent)]
    with controller(args, root, extra, containers=True, tls_certificate=cert, tls_key=key, tls_ca=ca) as endpoint:
        sdk = {service: client(service, endpoint, ca_file=ca) for service in
               ("iam", "lambda", "acm", "apigateway", "apigatewayv2", "appsync", "route53")}
        role = function = certificate = None
        outputs = None
        try:
            role = sdk["iam"].create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                                        "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
                package.writestr("handler.py", "import json\ndef invoke(event, context):\n"
                                 "    data = json.loads(event.get('body') or '{}')\n"
                                 "    return {'statusCode': 200, 'headers': {'content-type': 'application/json'}, "
                                 "'body': json.dumps({'nonce': data['nonce'], 'revision': event['stageVariables']['revision']})}\n")
            function = sdk["lambda"].create_function(FunctionName=name, Role=role, Runtime="python3.12",
                                                     Handler="handler.invoke", Code={"ZipFile": archive.getvalue()},
                                                     Timeout=15, MemorySize=256)["FunctionArn"]
            sdk["lambda"].add_permission(FunctionName=name, StatementId="apigateway", Action="lambda:InvokeFunction",
                                         Principal="apigateway.amazonaws.com",
                                         SourceArn=f"arn:aws:execute-api:{REGION}:{ACCOUNT}:*")
            deadline = time.monotonic() + 120
            while True:
                state = sdk["lambda"].get_function_configuration(FunctionName=name)["State"]
                require(state != "Failed", "Lambda runtime preparation failed")
                if state == "Active":
                    break
                require(time.monotonic() < deadline, "Lambda runtime preparation timed out")
                time.sleep(0.5)
            certificate = sdk["acm"].import_certificate(Certificate=domain_cert.read_bytes(), PrivateKey=domain_key.read_bytes(),
                                                       CertificateChain=ca.read_bytes())["CertificateArn"]
            variables = {"endpoint": endpoint, "name": name, "revision": "first", "function_arn": function,
                         "ca_file": str(ca), "certificate_arn": certificate}
            variable_file = root / "local.auto.tfvars.json"
            variable_file.write_text(json.dumps(variables))
            terraform("init", "-input=false")
            terraform("apply", "-input=false", "-auto-approve")
            outputs = json.loads(terraform("output", "-json", "proof", capture=True).stdout)

            def consume(revision):
                nonce = uuid.uuid4().hex
                api_key = sdk["apigateway"].get_api_key(apiKey=outputs["rest_key_id"], includeValue=True)["value"]
                rest = f"/_stackd/execute-api/{outputs['rest_id']}/live/proof"
                denied_status, _, denied_body = request(endpoint, rest)
                require(denied_status == 418 and json.loads(denied_body) == {"denied": revision},
                        f"Usage-plan admission did not enforce API key: {denied_status} {denied_body!r}")
                status, headers, body = request(endpoint, rest, headers={"x-api-key": api_key})
                require(status == 200 and json.loads(body) == {"revision": revision}
                        and headers.get("X-Revision") == revision, f"REST snapshot response: {status} {headers} {body!r}")
                missing = f"/_stackd/execute-api/{outputs['rest_id']}/live/missing"
                status, _, body = request(endpoint, missing)
                require(status == 404 and json.loads(body) == {"missing": revision}, f"Gateway response: {status} {body!r}")
                payload = json.dumps({"nonce": nonce})
                for path, sni in ((f"/_stackd/execute-api/{outputs['http_id']}/live/proof", None),
                                  (f"/{revision}/proof", domain)):
                    status, _, body = request(endpoint, path, payload, {"Content-Type": "application/json"}, sni)
                    require(status == 200 and json.loads(body) == {"nonce": nonce, "revision": revision},
                            f"Actual Lambda HTTP response: {status} {body!r}")
                keys = sdk["appsync"].list_api_keys(apiId=outputs["graphql_id"])["apiKeys"]
                require(len(keys) == 1, "Expected one current AppSync API key")
                query = json.dumps({"query": "query Proof($input: String!) { proof(input: $input) }", "variables": {"input": nonce}})
                status, _, body = request(endpoint, urlsplit(outputs["graphql_url"]).path, query,
                                          {"Content-Type": "application/json", "x-api-key": keys[0]["id"]})
                require(status == 200 and json.loads(body) == {"data": {"proof": revision + ":" + nonce}},
                        f"Actual GraphQL resolver output: {status} {body!r}")
                for tcp in (False, True):
                    dns(outputs["dns_name"], "TXT", json.dumps(revision), tcp)
                    address = "192.0.2.1" if revision == "first" else "192.0.2.2"
                    dns(outputs["address_name"], "A", address, tcp)
                    dns(outputs["alias_name"], "A", address, tcp)
                    dns(domain, "A", "127.0.0.1", tcp)
                tags = sdk["route53"].list_tags_for_resource(ResourceType="hostedzone", ResourceId=outputs["zone_id"])["ResourceTagSet"]["Tags"]
                require(tags == [{"Key": "Revision", "Value": revision}], f"Retained DNS tags: {tags}")
                print(f"Consumed {revision}: deployed REST headers/body, live gateway response, Lambda HTTP and trusted SNI, GraphQL input, UDP/TCP DNS", flush=True)

            consume("first")
            sdk["apigateway"].update_integration_response(restApiId=outputs["rest_id"], resourceId=outputs["rest_resource_id"],
                                                        httpMethod="GET", statusCode="200", patchOperations=[{
                                                            "op": "replace", "path": "/responseTemplates/application~1json",
                                                            "value": json.dumps({"revision": "not-deployed"})}])
            api_key = sdk["apigateway"].get_api_key(apiKey=outputs["rest_key_id"], includeValue=True)["value"]
            status, _, body = request(endpoint, f"/_stackd/execute-api/{outputs['rest_id']}/live/proof",
                                      headers={"x-api-key": api_key})
            require(status == 200 and json.loads(body) == {"revision": "first"}, "Undeployed REST response leaked into live stage")
            sdk["apigateway"].update_gateway_response(restApiId=outputs["rest_id"], responseType="MISSING_AUTHENTICATION_TOKEN",
                                                       patchOperations=[{"op": "replace",
                                                                         "path": "/responseTemplates/application~1json",
                                                                         "value": json.dumps({"missing": "live-first"})}])
            status, _, body = request(endpoint, f"/_stackd/execute-api/{outputs['rest_id']}/live/missing")
            require(status == 404 and json.loads(body) == {"missing": "live-first"},
                    "Gateway response edit incorrectly waited for deployment")
            terraform("apply", "-input=false", "-auto-approve")  # Repair observed draft drift, not ignored changes.
            for address, identifier in (("aws_api_gateway_rest_api.proof", outputs["rest_id"]),
                                        ("aws_apigatewayv2_api.proof", outputs["http_id"]),
                                        ("aws_apigatewayv2_domain_name.proof", domain),
                                        ("aws_appsync_graphql_api.proof", outputs["graphql_id"]),
                                        ("aws_appsync_resolver.proof", outputs["graphql_id"] + "-Query-proof"),
                                        ("aws_route53_zone.proof", outputs["zone_id"])):
                backup = root / "before-import.tfstate"
                backup.write_text(terraform("state", "pull", capture=True).stdout)
                terraform("state", "rm", address)
                try:
                    terraform("import", "-input=false", address, identifier)
                except BaseException:
                    # Keep this owned resource in state so cleanup can delete it.
                    terraform("state", "push", "-force", str(backup))
                    raise
            print("Imported six retained native resources", flush=True)
            refresh = terraform("plan", "-refresh-only", "-input=false", "-detailed-exitcode", "-out=refresh.tfplan", check=False)
            require(refresh.returncode in (0, 2), "Refresh failed")
            terraform("apply", "-input=false", "-auto-approve", "refresh.tfplan")
            plan = terraform("plan", "-input=false", "-detailed-exitcode", "-out=import-schema.tfplan", check=False)
            require(plan.returncode in (0, 2), f"Imported plan failed: {plan.returncode}")
            if plan.returncode == 2:
                saved = json.loads(terraform("show", "-json", "import-schema.tfplan", capture=True).stdout)
                changes = [row for row in saved.get("resource_changes", [])
                           if row["change"]["actions"] != ["no-op"]]
                require(len(changes) == 1 and changes[0]["address"] == "aws_appsync_graphql_api.proof"
                        and changes[0]["change"]["actions"] == ["update"],
                        "Import proposed a change outside the known provider schema reconciliation")
                change = changes[0]["change"]
                before, after = change["before"], change["after"]
                changed = {key for key in set(before) | set(after) if before.get(key) != after.get(key)}

                def unknown(value):
                    if isinstance(value, dict):
                        return any(unknown(child) for child in value.values())
                    if isinstance(value, list):
                        return any(unknown(child) for child in value)
                    return value is True

                expected_schema = "type Query { proof(input: String!): String! }\nschema { query: Query }"
                require(changed == {"schema"} and before.get("schema") is None
                        and after["schema"] == expected_schema and not unknown(change.get("after_unknown", {}))
                        and not change.get("replace_paths"),
                        "Import reconciliation differs from the exact unset-to-configured SDL transition")
                terraform("apply", "-input=false", "-auto-approve", "import-schema.tfplan")
                print("Reconciled only imported write-only GraphQL schema through a guarded saved plan", flush=True)
            strict_refresh = terraform("plan", "-refresh-only", "-input=false", "-detailed-exitcode", check=False)
            require(strict_refresh.returncode == 0, "Reconciled import refresh has unexpected changes")
            strict_plan = terraform("plan", "-input=false", "-detailed-exitcode", check=False)
            require(strict_plan.returncode == 0, "Reconciled import is not a strict no-op")
            consume("first")
            previous = outputs.copy()
            variables["revision"] = "second"
            variable_file.write_text(json.dumps(variables))
            terraform("apply", "-input=false", "-auto-approve")
            outputs = json.loads(terraform("output", "-json", "proof", capture=True).stdout)
            for field in ("rest_id", "http_id", "graphql_id", "zone_id"):
                require(outputs[field] == previous[field], f"Update replaced stable resource: {field}")
            for field in ("rest_deployment_id", "http_deployment_id"):
                require(outputs[field] != previous[field], f"Update did not publish a new deployment: {field}")
            consume("second")
            status, _, _ = request(endpoint, "/first/proof", json.dumps({"nonce": "old-mapping"}), {"Content-Type": "application/json"}, domain)
            require(status == 404, f"Old custom-domain mapping still routed: {status}")
            plan = terraform("plan", "-input=false", "-detailed-exitcode", check=False)
            require(plan.returncode == 0, "Repeated current-provider update plan has drift")
        finally:
            try:
                if (root / ".terraform").exists():
                    terraform("destroy", "-input=false", "-auto-approve")
            finally:
                if function is not None:
                    sdk["lambda"].delete_function(FunctionName=name)
                if role is not None:
                    sdk["iam"].delete_role(RoleName=name)
                if certificate is not None:
                    sdk["acm"].delete_certificate(CertificateArn=certificate)
        if outputs is not None:
            expect_missing(sdk["apigateway"].get_rest_api, {"NotFoundException"}, restApiId=outputs["rest_id"])
            expect_missing(sdk["apigatewayv2"].get_api, {"NotFoundException"}, ApiId=outputs["http_id"])
            expect_missing(sdk["apigatewayv2"].get_domain_name, {"NotFoundException"}, DomainName=domain)
            expect_missing(sdk["appsync"].get_graphql_api, {"NotFoundException"}, apiId=outputs["graphql_id"])
            expect_missing(sdk["route53"].get_hosted_zone, {"NoSuchHostedZone"}, Id=outputs["zone_id"])
            for name_to_check in (outputs["dns_name"], outputs["address_name"], outputs["alias_name"]):
                packet = subprocess.check_output(["dig", "@127.0.0.1", "-p", str(args.dns_port), name_to_check,
                                                  "+time=2", "+tries=1", "+noall", "+comments", "+answer"], text=True)
                require("status: REFUSED" in packet and "ANSWER: 0" in packet, f"Deleted DNS authority survived: {packet}")
            status, _, _ = request(endpoint, f"/_stackd/execute-api/{outputs['http_id']}/live/proof")
            require(status in (403, 404), f"Deleted HTTP API still accepts requests: {status}")
            state = json.loads(terraform("show", "-json", capture=True).stdout)
            require(not state.get("values", {}).get("root_module", {}).get("resources"), "Terraform resources remain after destroy")
            (root / "evidence.json").write_text(json.dumps({"provider": "6.68.0", "terraform": "1.15.9", "outputs": outputs,
                                                         "completed": ["create", "consumer", "draft-isolation", "import", "refresh", "update", "destroy"]}, indent=2) + "\n")
            print("Destroyed native API owners and real DNS publication", flush=True)
    print(f"Current-provider API lifecycle complete. Private owned artifacts: {root}")


if __name__ == "__main__":
    main()
