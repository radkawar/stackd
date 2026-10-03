"""Normal HTTP/TLS clients using an explicit local UDP/TCP DNS endpoint.

Requires the installed BIND dig client. Never changes resolver configuration,
uses hosts overrides, or falls back to public/system DNS for hostnames.
"""
import http.client
from functools import partial
import ipaddress
import re
import socket
import ssl
import subprocess
import urllib.request


def query(endpoint, name, record_type="A", tcp=False):
    host, port = endpoint.rsplit(":", 1)
    ipaddress.IPv4Address(host)
    command = ["dig", "@" + host, "-p", port, name + ("" if name.endswith(".") else "."), record_type,
               "+noall", "+comments", "+answer", "+time=3", "+tries=1", "+norecurse"]
    if tcp:
        command.append("+tcp")
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=5)
    status = re.search(r"status: ([A-Z]+)", result.stdout)
    if status is None:
        raise OSError("DNS query did not return a response: " + result.stdout + result.stderr)
    records = []
    for line in result.stdout.splitlines():
        if not line or line.startswith(";"):
            continue
        owner, ttl, record_class, kind, value = line.split(None, 4)
        records.append({"name": owner, "ttl": int(ttl), "class": record_class, "type": kind, "value": value})
    return {"status": status.group(1), "records": records}


def create_connection(endpoint, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    """Connect through the explicit resolver, never through system DNS."""
    host, port = address
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        answer = query(endpoint, host)
        if answer["status"] != "NOERROR":
            raise socket.gaierror(socket.EAI_NONAME, answer["status"] + ": " + host)
        addresses = [row["value"] for row in answer["records"] if row["type"] == "A"]
    error = socket.gaierror(socket.EAI_NONAME, "No IPv4 DNS answer: " + host)
    for ip in addresses:
        try:
            return socket.create_connection((ip, port), timeout, source_address)
        except OSError as failure:
            error = failure
    raise error


def opener(endpoint, context=None):
    connect = partial(create_connection, endpoint)

    class HTTPConnection(http.client.HTTPConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._create_connection = connect

    class HTTPSConnection(http.client.HTTPSConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # Only socket address selection changes. HTTPSConnection still
            # verifies the original hostname and sends it as TLS SNI.
            self._create_connection = connect

    class HTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, request):
            return self.do_open(HTTPConnection, request)

    class HTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, request):
            return self.do_open(HTTPSConnection, request, context=self._context)

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPHandler(),
                                      HTTPSHandler(context=context or ssl.create_default_context()))
