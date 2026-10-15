# Executed with fd 9 holding the existing daemon-host native network lock.
import base64
import http.client
import json
import os
import socket
import urllib.parse
import time


class Engine(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect('/var/run/docker.sock')


def request(method, path, body=None, missing=False):
    engine = Engine('localhost', timeout=10)
    try:
        engine.request(method, path, None if body is None else json.dumps(body), {'Content-Type': 'application/json'})
        response = engine.getresponse()
        data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise ValueError('Engine ownership response exceeds bound')
        if missing and response.status == 404:
            return None
        if response.status < 200 or response.status >= 300:
            raise ValueError('Engine flow admission HTTP %d: %s' % (response.status, data[:1024]))
        return json.loads(data) if data else {}
    finally:
        engine.close()


def control_operation(operation, fields=None):
    message = dict(fields or {}, op=operation)
    control = r'''import base64,json,socket,sys,time
deadline=time.monotonic()+8
while True:
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect('/flows/control.sock')
        break
    except OSError:
        s.close()
        if time.monotonic()>=deadline: raise
        time.sleep(0.05)
s.sendall(base64.b64decode(sys.argv[1])+b'\n')
data=bytearray()
while b'\n' not in data:
    block=s.recv(4096)
    if not block or len(data)>65536: raise ValueError('invalid control response')
    data.extend(block)
s.close()
response=json.loads(data)
if response.get('error'): raise ValueError(response['error'])
if sys.argv[2]=='prepare-cleanup' and response.get('result',{}).get('quiesced') is not True:
    raise ValueError('receiver did not quiesce')
'''
    payload = base64.b64encode(json.dumps(message).encode()).decode()
    execution = request('POST', path + '/exec', {'Cmd': ['python3', '-c', control, payload, operation]})
    exec_path = '/exec/' + execution['Id']
    request('POST', exec_path + '/start', {'Detach': True, 'Tty': False})
    deadline = time.monotonic() + 14
    while True:
        status = request('GET', exec_path + '/json')
        if not status.get('Running'):
            if status.get('ExitCode') != 0:
                raise ValueError('receiver refused locked ' + operation)
            return
        if time.monotonic() >= deadline:
            raise ValueError('locked receiver control timed out')
        time.sleep(0.05)


name = os.environ['FLOW_NAME']
volume = os.environ['FLOW_VOLUME']
config = json.loads(base64.b64decode(os.environ['FLOW_CONFIG']))
config['HostConfig']['LogConfig'].setdefault('Config', {})
config['HostConfig']['RestartPolicy'] = {'Name': 'unless-stopped'}
labels = config['Labels']
engine = request('GET', '/info')
if engine.get('ID') != os.environ['NATIVE_ENGINE_ID'] or engine.get('OSType') != 'linux':
    raise ValueError('flow admission selected Engine mismatch')
image = request('GET', '/images/' + urllib.parse.quote(config['Image'], safe='') + '/json')
image_config = image.get('Config', {})
expected_env = dict(item.split('=', 1) for item in (image_config.get('Env') or []))
expected_env.update(item.split('=', 1) for item in config['Env'])
expected_labels = dict(image_config.get('Labels') or {})
expected_labels.update(labels)
vol = request('GET', '/volumes/' + urllib.parse.quote(volume, safe=''), missing=True)
cleanup = os.environ.get('FLOW_CLEANUP') == '1'
if cleanup and vol is None:
    if request('GET', '/containers/' + urllib.parse.quote(name, safe='') + '/json', missing=True) is not None:
        raise ValueError('collector exists without owned journal')
    print('STACKD_FLOW_COLLECTOR_ALREADY_ABSENT')
    raise SystemExit(0)
if vol is None:
    vol = request('POST', '/volumes/create', {'Name': volume, 'Driver': 'local', 'Labels': labels})
if vol.get('Name') != volume or vol.get('Labels') != labels or vol.get('Driver') != 'local' or vol.get('Options'):
    raise ValueError('refusing unowned or externally mounted flow journal volume')
path = '/containers/' + urllib.parse.quote(name, safe='')
existing = request('GET', path + '/json', missing=True)
if existing is None:
    if cleanup:
        raise ValueError('retained journal has no live receiver; adopt and acknowledge before cleanup')
    request('POST', '/containers/create?name=' + urllib.parse.quote(name, safe=''), config)
    existing = request('GET', path + '/json')
observed = existing['Config']
host = existing['HostConfig']
if existing.get('Image') != image['Id']:
    raise ValueError('retained flow collector pinned image ID mismatch')
for field in ('Image', 'Entrypoint', 'Cmd', 'User'):
    if observed.get(field) != config.get(field):
        raise ValueError('retained flow collector immutable %s mismatch' % field)
if dict(item.split('=', 1) for item in observed.get('Env', [])) != expected_env or observed.get('Labels') != expected_labels:
    raise ValueError('retained flow collector environment or labels mismatch')
if observed.get('OpenStdin') or observed.get('Tty'):
    raise ValueError('retained flow collector process ownership mismatch')
for field in ('NetworkMode', 'ReadonlyRootfs', 'Memory', 'MemorySwap', 'PidsLimit', 'CapDrop', 'CapAdd', 'SecurityOpt', 'LogConfig'):
    if host.get(field) != config['HostConfig'].get(field):
        raise ValueError('retained flow collector immutable host %s mismatch' % field)
if host.get('Privileged') or host.get('AutoRemove') or host.get('Binds') or host.get('Devices') or host.get('PidMode') or host.get('VolumesFrom'):
    raise ValueError('retained flow collector has unexpected host authority')
if host.get('RestartPolicy', {}).get('Name') != 'unless-stopped':
    raise ValueError('retained flow collector restart policy mismatch')
mounts = existing.get('Mounts', [])
if len(mounts) != 1 or mounts[0].get('Type') != 'volume' or mounts[0].get('Name') != volume or mounts[0].get('Destination') != '/flows' or not mounts[0].get('RW'):
    raise ValueError('retained flow collector private journal mount mismatch')
path = '/containers/' + existing['Id']
if cleanup:
    if not existing.get('State', {}).get('Running'):
        raise ValueError('receiver stopped; adopt and acknowledge before cleanup')
    control_operation('prepare-cleanup')
    request('POST', path + '/stop?t=2')
    request('DELETE', path)
    request('DELETE', '/volumes/' + urllib.parse.quote(volume, safe=''))
    print('STACKD_FLOW_COLLECTOR_IDLE_REMOVED')
    raise SystemExit(0)
if not existing.get('State', {}).get('Running'):
    request('POST', path + '/start')
# Resume is serialized with the whole quiesce/stop/remove transaction. Never
# revoke a cleanup proof from a controller-side readiness loop outside this lock.
control_operation('resume')
if os.environ.get('FLOW_RECONCILE'):
    control_operation('reconcile', {'reconciliation': json.loads(base64.b64decode(os.environ['FLOW_RECONCILE']))})
print(json.dumps({'marker': 'STACKD_FLOW_COLLECTOR_ADMITTED', 'boot_id': os.environ['NATIVE_LOCK_IDENTITY'].split()[0]}))
