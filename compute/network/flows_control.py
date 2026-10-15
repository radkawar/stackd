# Docker exec is the only external control transport; no host socket or port.
import base64
import json
import socket
import sys

request = base64.b64decode(sys.argv[1], validate=True)
if len(request) > 65536:
    raise ValueError('control request exceeds 64 KiB')
json.loads(request)
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.settimeout(5)
try:
    connection.connect('/flows/control.sock')
    connection.sendall(request + b'\n')
    data = bytearray()
    while b'\n' not in data:
        block = connection.recv(min(65536, 2 * 1024 * 1024 + 1 - len(data)))
        if not block:
            raise ValueError('incomplete native control response')
        data.extend(block)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError('native control response exceeds 2 MiB')
    json.loads(data)
    sys.stdout.buffer.write(data)
finally:
    connection.close()
