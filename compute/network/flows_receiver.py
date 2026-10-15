# Embedded trusted toolkit helper. Python standard library only. No packet body
# is written to disk, stdout, Docker logs, or the private control socket.
import datetime
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import time
import uuid

ROOT = '/flows'
MAX_RECORDS = 32768
MAX_BYTES = 60 * 1024 * 1024
MAX_REGISTRATIONS = 4096
MAX_CONTROL = 2 * 1024 * 1024


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def encoded(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, value):
    data = encoded(value)
    temporary = path + '.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        syncdir(os.path.dirname(path))
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def load(path, default):
    try:
        with open(path, 'rb') as stream:
            data = stream.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError('retained metadata exceeds bound')
        return json.loads(data)
    except FileNotFoundError:
        return default


class Journal:
    def __init__(self, root, owner):
        self.root = root
        self.records_dir = root + '/records'
        os.makedirs(self.records_dir, mode=0o700, exist_ok=True)
        self.state_path = root + '/state.json'
        self.state = load(self.state_path, {'owner': owner, 'head': 0, 'acked': 0, 'bindings': {}, 'group': 0})
        if self.state['owner'] != owner:
            raise ValueError('retained collector namespace/Engine ownership mismatch')
        self.files = {}
        self.bytes = 0
        for entry in os.scandir(self.records_dir):
            if re.fullmatch(r'[0-9]{20}\.json', entry.name):
                cursor = int(entry.name[:20])
                if cursor <= self.state['acked']:
                    os.unlink(entry.path)
                    continue
                size = entry.stat(follow_symlinks=False).st_size
                if not entry.is_file(follow_symlinks=False) or size > 65536:
                    raise ValueError('invalid retained record')
                self.files[cursor] = size
                self.bytes += size
                self.state['head'] = max(self.state['head'], cursor)
        self.loss_path = root + '/loss.json'
        self.loss = load(self.loss_path, None)
        self.save()

    def save(self):
        atomic(self.state_path, self.state)

    def loss_gap(self, reason, generation, token='', start=None):
        stamp = now()
        if self.loss is None:
            self.loss = {'generation': generation, 'token': token, 'start': start or self.state.get('watermark', stamp), 'end': stamp, 'reason': reason}
        else:
            self.loss['end'] = stamp
            if start and datetime.datetime.fromisoformat(start.replace('Z', '+00:00')) < datetime.datetime.fromisoformat(self.loss['start'].replace('Z', '+00:00')):
                self.loss['start'] = start
            # A bounded summary loses precision, never evidence of loss.
            if self.loss.get('token') != token:
                self.loss['token'] = ''
            if reason not in self.loss['reason'].split(','):
                self.loss['reason'] = (self.loss['reason'] + ',' + reason)[:1024]
        atomic(self.loss_path, self.loss)

    def append(self, body, reserve=False):
        if not reserve and self.loss is not None:
            self.flush_loss()
        data_size = len(encoded(body)) + 64
        if len(self.files) >= MAX_RECORDS or self.bytes + data_size > MAX_BYTES + (65536 if reserve else 0):
            return False
        cursor = self.state['head'] + 1
        # Reserve the ID durably first. A crash before frame commit is covered
        # by receiver-restart and never reuses an advertised observation ID.
        self.state['head'] = cursor
        self.save()
        record = dict(body, cursor=cursor)
        path = self.records_dir + '/%020d.json' % cursor
        atomic(path, record)
        self.files[cursor] = os.stat(path).st_size
        self.bytes += self.files[cursor]
        return True

    def flush_loss(self):
        if self.loss is not None and self.append({'gap': self.loss}, reserve=True):
            self.loss = None
            os.unlink(self.loss_path)
            syncdir(self.root)

    def gap(self, reason, generation, token='', start=None):
        stamp = now()
        gap = {'reason': reason, 'generation': generation, 'token': token, 'start': start or self.state.get('watermark', stamp), 'end': stamp}
        if not self.append({'gap': gap}):
            self.loss_gap(reason, generation, token, start)

    def observation(self, observation, generation):
        if not self.append({'observation': observation}):
            self.loss_gap('spool-full', generation)

    def read(self, after, records, size):
        if after < self.state['acked']:
            raise ValueError('cursor precedes durable acknowledgement')
        if after > self.state['head']:
            raise ValueError('cursor exceeds retained head')
        self.flush_loss()
        result = []
        used = 0
        cursor = after
        for identifier in sorted(self.files):
            if identifier <= after:
                continue
            if len(result) >= records or used + self.files[identifier] > size:
                break
            record = load(self.records_dir + '/%020d.json' % identifier, None)
            if record is None or record.get('cursor') != identifier:
                raise ValueError('retained record corruption')
            result.append(record)
            used += self.files[identifier]
            cursor = identifier
        return result, cursor

    def ack(self, through):
        if through < self.state['acked'] or through > self.state['head']:
            raise ValueError('ack outside durable journal range')
        self.state['acked'] = through
        self.save()
        for identifier in list(self.files):
            if identifier <= through:
                os.unlink(self.records_dir + '/%020d.json' % identifier)
                self.bytes -= self.files.pop(identifier)
        syncdir(self.records_dir)
        self.flush_loss()
        self.prune()

    def prune(self):
        # Retired tokens remain until every queued observation and the retirement
        # uncertainty barrier is durably acknowledged. Tokens are never reused.
        for token, entry in list(self.state['bindings'].items()):
            if entry.get('retired') and entry.get('retire_cursor', self.state['head'] + 1) <= self.state['acked'] and self.loss is None:
                del self.state['bindings'][token]
        self.save()


def attributes(data):
    result = {}
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            if any(data[offset:]):
                raise ValueError('short netlink attribute')
            break
        length, kind = struct.unpack_from('=HH', data, offset)
        if length < 4 or offset + length > len(data):
            raise ValueError('invalid netlink attribute length')
        result[kind & 0x3fff] = data[offset + 4:offset + length]
        offset += (length + 3) & ~3
    return result


def packet_header(payload):
    # NFULA_PAYLOAD on bridge/netdev can begin with L2; only accept an explicit
    # IPv4 EtherType, never search arbitrary packet bytes for a plausible header.
    if not payload:
        raise ValueError('missing-ip-header')
    if payload[0] >> 4 != 4:
        if len(payload) < 14:
            raise ValueError('short-ethernet-header')
        offset = 14
        ethertype = struct.unpack_from('!H', payload, 12)[0]
        for _ in range(2):
            if ethertype not in (0x8100, 0x88a8):
                break
            if len(payload) < offset + 4:
                raise ValueError('short-vlan-header')
            ethertype = struct.unpack_from('!H', payload, offset + 2)[0]
            offset += 4
        if ethertype != 0x0800:
            raise ValueError('non-ipv4-observation')
        payload = payload[offset:]
    if len(payload) < 20 or payload[0] >> 4 != 4:
        raise ValueError('short-ipv4-header')
    ihl = (payload[0] & 15) * 4
    total = struct.unpack_from('!H', payload, 2)[0]
    fragment = struct.unpack_from('!H', payload, 6)[0]
    if ihl < 20 or len(payload) < ihl or total < ihl:
        raise ValueError('invalid-ipv4-length')
    if fragment & 0x3fff:
        raise ValueError('fragment-count-ambiguity')
    protocol = payload[9]
    source = str(ipaddress.IPv4Address(bytes(payload[12:16])))
    destination = str(ipaddress.IPv4Address(bytes(payload[16:20])))
    source_port = destination_port = flags = 0
    if protocol in (6, 17):
        minimum = 20 if protocol == 6 else 8
        if len(payload) < ihl + minimum or total < ihl + minimum:
            raise ValueError('truncated-transport-header')
        source_port, destination_port = struct.unpack_from('!HH', payload, ihl)
        if protocol == 6:
            tcp_length = (payload[ihl + 12] >> 4) * 4
            if tcp_length < 20 or total < ihl + tcp_length:
                raise ValueError('invalid-tcp-header')
            flags = payload[ihl + 13]
            # NFLOG exposes skbs, not GSO segment counts. TCP data may be GSO/GRO;
            # without a segment witness it is incomplete, not invented packets.
            if total > ihl + tcp_length:
                raise ValueError('tcp-segmentation-ambiguity')
        elif struct.unpack_from('!H', payload, ihl + 4)[0] != total - ihl:
            raise ValueError('udp-segmentation-ambiguity')
    # Provider traffic must remain excluded even if an old renderer logs it.
    excluded = {'169.254.169.254', '169.254.169.123', '169.254.169.253'}
    if source in excluded or destination in excluded or (protocol == 17 and {source_port, destination_port} == {67, 68}):
        return None
    return {'source_address': source, 'destination_address': destination, 'protocol': protocol,
            'source_port': source_port, 'destination_port': destination_port,
            'ip_bytes': total, 'packets': 1, 'tcp_flags': flags}


def run_native(arguments):
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    data = bytearray()
    deadline = time.monotonic() + 3
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('native inspection timed out')
            readable, _, _ = select.select([process.stdout], [], [], remaining)
            if not readable:
                raise ValueError('native inspection timed out')
            block = os.read(process.stdout.fileno(), 65536)
            if not block:
                break
            data.extend(block)
            if len(data) > 2 * 1024 * 1024:
                raise ValueError('native inspection exceeds bound')
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return subprocess.CompletedProcess(arguments, code, bytes(data) if code == 0 else b'', bytes(data) if code else b'')
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def command_json(arguments):
    result = run_native(arguments)
    if result.returncode:
        raise ValueError('native inspection failed')
    return json.loads(result.stdout)


class Receiver:
    def __init__(self):
        os.umask(0o077)
        os.makedirs(ROOT, mode=0o700, exist_ok=True)
        self.lock = os.open(ROOT + '/receiver.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.boot = open('/proc/sys/kernel/random/boot_id').read().strip()
        self.engine = os.environ['FLOW_ENGINE_ID']
        self.namespace = os.environ['FLOW_NAMESPACE']
        self.generation = uuid.uuid4().hex
        self.journal = Journal(ROOT, {'namespace': self.namespace, 'engine_id': self.engine, 'version': 1})
        previous_boot = self.journal.state.get('boot_id')
        restart_gap = {'generation': self.generation, 'start': self.journal.state.get('watermark', now()), 'end': now(),
                       'reason': 'daemon-boot-change' if previous_boot and previous_boot != self.boot else 'receiver-start-uncertain-coverage'}
        if not self.journal.append({'gap': restart_gap}):
            self.journal.loss_gap(restart_gap['reason'], self.generation)
        self.journal.state['generation_started_at'] = restart_gap['start']
        if previous_boot and previous_boot != self.boot:
            for entry in self.journal.state['bindings'].values():
                entry['retired'] = True
                entry['retire_cursor'] = self.journal.state['head']
        self.journal.state['boot_id'] = self.boot
        self.journal.state['generation'] = self.generation
        self.journal.save()
        self.netlink = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
        self.netlink.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.netlink.bind((0, 0))
        self.netlink.settimeout(3)
        self.request_sequence = 0
        self.last_sequence = None
        self.last_counters = {}
        self.received = {}
        self.counter_time = time.monotonic()
        self.watermark = now()
        self.last_empty = 0
        self.coverages = []
        group = self.journal.state['group']
        if group:
            self.configure(group, 1, b'\x01')
        else:
            start = int(hashlib.sha256((self.namespace + self.engine).encode()).hexdigest()[:8], 16)
            for attempt in range(1024):
                group = 1024 + (start + attempt) % (65535 - 1024)
                try:
                    self.configure(group, 1, b'\x01')
                    break
                except OSError as error:
                    if error.errno not in (errno.EBUSY, errno.EEXIST):
                        raise
            else:
                raise ValueError('no free NFLOG group in bounded collision search')
        self.group = group
        self.journal.state['group'] = group
        self.journal.save()
        # Group bind only: never issue PF_UNBIND or replace a host logger.
        self.configure(group, 2, struct.pack('!IBB', 128, 2, 0))
        self.configure(group, 3, struct.pack('!I', 65536))
        self.configure(group, 4, struct.pack('!I', 1))
        self.configure(group, 5, struct.pack('!I', 1))
        self.configure(group, 6, struct.pack('!H', 1 | 4))
        command_json(['ip', '-j', 'link', 'show'])
        command_json(['nft', '-j', 'list', 'tables'])
        self.netlink.setblocking(False)
        self.control_path = ROOT + '/control.sock'
        try:
            os.unlink(self.control_path)
        except FileNotFoundError:
            pass
        self.control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.control.bind(self.control_path)
        os.chmod(self.control_path, 0o600)
        self.control.listen(8)

    def configure(self, group, kind, value):
        self.request_sequence += 1
        attribute = struct.pack('=HH', len(value) + 4, kind) + value
        attribute += b'\0' * ((-len(attribute)) % 4)
        body = struct.pack('!BBH', 0, 0, group) + attribute
        message = struct.pack('=IHHII', 16 + len(body), 0x0401, 1 | 4, self.request_sequence, 0) + body
        self.netlink.sendto(message, (0, 0))
        while True:
            data, _, flags, address = self.netlink.recvmsg(262144)
            if flags & socket.MSG_TRUNC or address[0] != 0:
                raise ValueError('invalid NFLOG bind acknowledgement')
            offset = 0
            while offset + 16 <= len(data):
                length, kind, _, sequence, _ = struct.unpack_from('=IHHII', data, offset)
                if length < 16 or offset + length > len(data):
                    raise ValueError('invalid NFLOG acknowledgement length')
                if kind == 2 and sequence == self.request_sequence:
                    code = struct.unpack_from('=i', data, offset + 16)[0]
                    if code:
                        raise OSError(-code, os.strerror(-code))
                    return
                # A retained group can already have installed native rules.
                if kind == 0x0400:
                    self.decode(data[offset + 16:offset + length])
                offset += (length + 3) & ~3

    def health(self):
        return {'ready': not getattr(self, 'quiescing', False), 'engine_id': self.engine, 'boot_id': self.boot, 'group': self.group,
                'generation': self.generation, 'acked': self.journal.state['acked'], 'head': self.journal.state['head'],
                'watermark': self.watermark, 'incomplete': self.journal.loss is not None or not self.coverages or any(not item['ready'] for item in self.coverages)}

    def decode(self, body):
        token = ''
        try:
            if len(body) < 4 or struct.unpack_from('!H', body, 2)[0] != self.journal.state['group']:
                raise ValueError('group-identity-mismatch')
            attrs = attributes(body[4:])
            if 12 not in attrs or len(attrs[12]) != 4:
                raise ValueError('missing-sequence')
            sequence = struct.unpack('!I', attrs[12])[0]
            if self.last_sequence is not None and sequence != (self.last_sequence + 1) & 0xffffffff:
                self.journal.gap('netlink-sequence-loss', self.generation)
            self.last_sequence = sequence
            prefix = attrs.get(10, b'').rstrip(b'\0').decode('ascii')
            match = re.fullmatch(r'sf:([a-f0-9]{32}):(ingress|egress):(ACCEPT|REJECT)', prefix)
            if not match:
                raise ValueError('unknown-verdict-prefix')
            token, direction, action = match.groups()
            entry = self.journal.state['bindings'].get(token)
            if entry is None or entry['binding']['boot_id'] != self.boot:
                raise ValueError('unknown-or-stale-binding')
            binding = entry['binding']
            interfaces = [struct.unpack('!I', attrs[key])[0] for key in (4, 5, 6, 7) if key in attrs and len(attrs[key]) == 4]
            if binding['peer_ifindex'] not in interfaces:
                raise ValueError('peer-identity-mismatch')
            key = (token, direction, action)
            self.received[key] = self.received.get(key, 0) + 1
            observation = packet_header(attrs.get(9, b''))
            if observation is None:
                return
            if observation['ip_bytes'] > binding.get('mtu', 1500):
                raise ValueError('skb-segmentation-mtu-ambiguity')
            timestamp = now()
            source = 'daemon-receipt'
            if 3 in attrs:
                if len(attrs[3]) != 16:
                    raise ValueError('invalid-kernel-timestamp')
                seconds, micros = struct.unpack('!QQ', attrs[3])
                if micros >= 1000000:
                    raise ValueError('invalid-kernel-timestamp')
                timestamp = datetime.datetime.fromtimestamp(seconds + micros / 1000000, datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
                source = 'kernel'
            observation.update(binding=binding, token=token, generation=binding['generation'], direction=direction, action=action,
                               observed_at=timestamp, timestamp_source=source)
            self.journal.observation(observation, self.generation)
        except (ValueError, UnicodeError, struct.error, OverflowError) as error:
            self.journal.gap(str(error)[:256], self.generation, token)

    def drain(self):
        # Bound each turn so control/ack cannot be starved by customer traffic.
        for _ in range(128):
            try:
                data, _, flags, address = self.netlink.recvmsg(262144)
            except BlockingIOError:
                self.last_empty = time.monotonic()
                break
            except OSError as error:
                if error.errno == errno.ENOBUFS:
                    self.journal.gap('netlink-receive-overflow', self.generation)
                    continue
                raise
            if flags & socket.MSG_TRUNC:
                self.journal.gap('netlink-datagram-truncated', self.generation)
                continue
            if address[0] != 0:
                self.journal.gap('netlink-sender-identity', self.generation)
                continue
            offset = 0
            while offset < len(data):
                if offset + 16 > len(data):
                    self.journal.gap('netlink-header-truncated', self.generation)
                    break
                length, kind, _, _, _ = struct.unpack_from('=IHHII', data, offset)
                if length < 16 or offset + length > len(data):
                    self.journal.gap('netlink-message-truncated', self.generation)
                    break
                if kind == 0x0400:
                    self.decode(data[offset + 16:offset + length])
                elif kind not in (2, 3):
                    self.journal.gap('netlink-unexpected-message', self.generation)
                offset += (length + 3) & ~3
        # Watermark is advanced only by a completed native counter snapshot.

    def register(self, binding):
        identity = binding['identity']
        values = [identity[key] for key in ('partition', 'account_id', 'region', 'vpc_id', 'subnet_id', 'interface_id')]
        if any(not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', value) for value in values):
            raise ValueError('invalid attachment identity')
        vpc_owner = identity.get('vpc_owner_account_id') or values[1]
        if not re.fullmatch(r'[A-Za-z0-9-]{1,128}', vpc_owner):
            raise ValueError('invalid VPC owner identity')
        arn = 'arn:%s:ec2:%s:%s:vpc/%s' % (values[0], values[2], vpc_owner, values[3])
        if binding['network_id'] != arn:
            raise ValueError('attachment full VPC ARN mismatch')
        if not re.fullmatch(r'stackd_(ec2|ecs|elbv2|lambda|msk|elasticache)_[a-f0-9]+', binding['policy_table']):
            raise ValueError('invalid owned policy table')
        if not binding['public_owner'] or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', binding['generation']) or len(encoded(binding)) > 8192:
            raise ValueError('missing or excessive immutable binding metadata')
        if not ipaddress.ip_address(binding['address']).version == 4:
            raise ValueError('attachment address must be IPv4')
        if binding.get('engine_id') and binding['engine_id'] != self.engine:
            raise ValueError('binding Engine mismatch')
        if binding.get('boot_id') and binding['boot_id'] != self.boot:
            raise ValueError('binding boot mismatch')
        peer = command_json(['ip', '-j', 'link', 'show', 'dev', binding['peer_name']])[0]
        bridge = command_json(['ip', '-j', 'link', 'show', 'dev', binding['bridge']])[0]
        if peer.get('master') not in (binding['bridge'], bridge['ifindex']):
            raise ValueError('peer is not enslaved to owned bridge')
        if binding.get('peer_ifindex') and binding['peer_ifindex'] != peer['ifindex']:
            raise ValueError('peer ifindex changed')
        mtu = min(int(peer['mtu']), int(bridge['mtu']))
        if binding.get('mtu') and binding['mtu'] != mtu:
            raise ValueError('binding MTU changed')
        binding.update(peer_ifindex=peer['ifindex'], engine_id=self.engine, boot_id=self.boot, mtu=mtu)
        # Reject a foreign controller's existing table without preventing the
        # first policy installation (which legitimately has no table yet).
        result = run_native(['nft', '-j', 'list', 'table', 'bridge', binding['policy_table']])
        if result.returncode == 0:
            state = json.loads(result.stdout)
            tables = [row['table'] for row in state.get('nftables', []) if 'table' in row]
            capture_chains = [row['chain'] for row in state.get('nftables', []) if row.get('chain', {}).get('name') in ('flow_controller', 'flow_identity')]
            if len(tables) != 1 or (tables[0].get('comment') != 'stackd:' + binding['policy_table'] and (tables[0].get('comment') or capture_chains)):
                raise ValueError('policy table ownership mismatch')
            controllers = [row['chain']['comment'] for row in state.get('nftables', []) if row.get('chain', {}).get('name') == 'flow_controller']
            if controllers and controllers != [hashlib.sha256(binding['public_owner'].encode()).hexdigest()]:
                raise ValueError('policy controller ownership mismatch')
        elif b'No such file' not in result.stderr:
            raise ValueError('cannot verify policy ownership')
        for entry in self.journal.state['bindings'].values():
            if entry['binding'] == binding and not entry.get('retired'):
                return entry['registration']
        if len(self.journal.state['bindings']) >= MAX_REGISTRATIONS:
            raise ValueError('retained binding registry full; acknowledge retired evidence')
        token = uuid.uuid4().hex
        registration = {'group': self.group, 'token': token, 'generation': binding['generation']}
        self.journal.state['registration_order'] = self.journal.state.get('registration_order', 0) + 1
        self.journal.state['bindings'][token] = {'binding': binding, 'registration': registration, 'registered_at': now(),
                                                  'order': self.journal.state['registration_order']}
        if len(encoded(self.journal.state)) > 7 * 1024 * 1024:
            del self.journal.state['bindings'][token]
            raise ValueError('retained binding metadata exceeds bound')
        self.journal.save()
        self.journal.gap('policy-generation-registration-coverage', self.generation, token)
        return registration

    def retire(self, registration):
        token = registration['token']
        entry = self.journal.state['bindings'].get(token)
        if entry is None:
            return
        if registration.get('generation') != entry['registration']['generation'] or registration.get('group', 0) not in (0, entry['registration']['group']):
            raise ValueError('retirement identity mismatch')
        if entry.get('retired'):
            return
        # Inspect all owned families: retirement is forbidden while any rule
        # still references the token, including a quarantined public generation.
        for family in ('bridge', 'netdev', 'ip'):
            result = run_native(['nft', '-j', 'list', 'table', family, entry['binding']['policy_table']])
            if result.returncode and b'No such file' not in result.stderr:
                raise ValueError('cannot verify retired native references')
            if token.encode() in result.stdout:
                raise ValueError('native rules still reference registration')
        self.drain()
        self.journal.gap('policy-generation-retirement-uncertain-coverage', self.generation, token)
        entry['retired'] = True
        entry['retired_at'] = now()
        self.journal.save()

    def reconcile(self, scope):
        # Invoked by the daemon-flock bootstrap only after its caller observed a
        # serialized native policy success. Never guess from elapsed absence.
        table = scope['policy_table']
        owner = scope['public_owner']
        through = scope.get('through') or {}
        token = through.get('token')
        committed = self.journal.state['bindings'].get(token) if token else None
        if token:
            if committed is None or committed['binding']['policy_table'] != table or committed['binding']['public_owner'] != owner:
                raise ValueError('reconciliation committed ownership mismatch')
            if through != committed['registration'] or not committed.get('order'):
                raise ValueError('reconciliation committed registration mismatch')
            cutoff = committed['order']
        else:
            cutoff = self.journal.state.get('registration_order', 0)
        native = command_json(['nft', '-j', 'list', 'ruleset'])
        for family in ('bridge', 'netdev'):
            tables = [row['table'] for row in native.get('nftables', [])
                      if row.get('table', {}).get('family') == family and row['table']['name'] == table]
            chains = {row['chain']['name']: row['chain'] for row in native.get('nftables', [])
                      if row.get('chain', {}).get('family') == family and row['chain']['table'] == table}
            if not token:
                if tables or chains:
                    raise ValueError('reconciliation removal requires absent native tables')
            else:
                witness = 'sf:' + hashlib.sha256(self.namespace.encode()).hexdigest()[:32] + ':' + token + ':' + committed['binding']['generation']
                if len(tables) != 1 or tables[0].get('comment') != 'stackd:' + table or chains.get('flow_identity', {}).get('comment') != witness or chains.get('flow_controller', {}).get('comment') != hashlib.sha256(owner.encode()).hexdigest():
                    raise ValueError('reconciliation committed native generation unverified')
        references = encoded(native)
        self.drain()
        retired = 0
        for candidate, entry in self.journal.state['bindings'].items():
            binding = entry['binding']
            if entry.get('retired') or candidate == token or binding['policy_table'] != table or binding['public_owner'] != owner or binding['boot_id'] != self.boot:
                continue
            # Unordered retained entries precede every newly ordered commit.
            if entry.get('order', 0) > cutoff or candidate.encode() in references:
                continue
            self.journal.gap('resolved-unreferenced-policy-generation', self.generation, candidate, entry.get('registered_at'))
            entry['retired'] = True
            entry['retired_at'] = now()
            retired += 1
        self.journal.save()
        return {'retired': retired}

    def coverage(self):
        # Counters witness logger allocation losses that need not advance seq.
        try:
            snapshot_stamp = now()
            state = command_json(['nft', '-j', 'list', 'ruleset'])
            self.drain()
            self.coverages = []
            tables = {}
            for row in state.get('nftables', []):
                for kind in ('table', 'chain', 'counter'):
                    if kind in row:
                        item = row[kind]
                        key = (item.get('family'), item.get('table', item.get('name')))
                        tables.setdefault(key, []).append((kind, item))
            for token, entry in list(self.journal.state['bindings'].items()):
                binding = entry['binding']
                if entry.get('retired'):
                    retired_at = datetime.datetime.fromisoformat(entry.get('retired_at', now()).replace('Z', '+00:00')).timestamp()
                    if 'retire_cursor' not in entry and time.time() - retired_at >= 1 and self.last_empty >= time.monotonic() - 0.5 and self.journal.loss is None:
                        self.journal.gap('retired-queue-drained-barrier', self.generation, token)
                        if self.journal.loss is None:
                            entry['retire_cursor'] = self.journal.state['head']
                    continue
                if binding['boot_id'] != self.boot:
                    continue
                counters = {}
                complete = self.journal.loss is None and self.last_empty >= time.monotonic() - 0.5
                for family in ('bridge', 'netdev'):
                    rows = tables.get((family, binding['policy_table']), [])
                    chains = {item['name']: item for kind, item in rows if kind == 'chain'}
                    expected = 'sf:' + hashlib.sha256(self.namespace.encode()).hexdigest()[:32] + ':' + token + ':' + binding['generation']
                    if chains.get('flow_identity', {}).get('comment') != expected:
                        self.journal.gap('native-policy-generation-unverified', self.generation, token)
                        complete = False
                        continue
                    if 'flow_uncertain' in chains:
                        self.journal.gap('public-address-quarantine', self.generation, token)
                        complete = False
                    if chains.get('flow_controller', {}).get('comment') != hashlib.sha256(binding['public_owner'].encode()).hexdigest():
                        complete = False
                        self.journal.gap('native-controller-unverified', self.generation, token)
                    required = {'flow_from_reject', 'flow_to_reject'}
                    if family == 'bridge':
                        required.update(('flow_from_accept', 'flow_to_accept'))
                    found = {item['name'] for kind, item in rows if kind == 'counter'}
                    if not required.issubset(found):
                        complete = False
                        self.journal.gap('native-terminal-counters-unverified', self.generation, token)
                    for kind, item in rows:
                        if kind == 'counter':
                            match = re.fullmatch(r'flow_(from|to)_(accept|reject)', item['name'])
                            if match:
                                direction = 'egress' if match[1] == 'from' else 'ingress'
                                key = (token, direction, match[2].upper())
                                counters[key] = counters.get(key, 0) + int(item.get('packets', 0))
                for key, count in counters.items():
                    received = self.received.get(key, 0)
                    previous = self.last_counters.get(key)
                    if previous is None or count < previous[0] or received < previous[1]:
                        self.journal.gap('counter-generation-baseline-uncertain', self.generation, token)
                        complete = False
                        credit = max(0, received - count)
                    else:
                        # Receipts drained after a snapshot can already belong
                        # to the next native counter value. Carry that surplus.
                        available = previous[2] + received - previous[1]
                        expected = count - previous[0]
                        if expected > available:
                            self.journal.gap('counter-observation-deficit', self.generation, token,
                                             entry.get('registered_at', self.journal.state.get('generation_started_at')))
                            complete = False
                        credit = max(0, available - expected)
                    self.last_counters[key] = (count, received, credit)
                self.coverages.append({'binding': binding, 'token': token, 'generation': binding['generation'], 'ready': complete, 'watermark': snapshot_stamp})
            self.watermark = snapshot_stamp
            self.journal.state['watermark'] = self.watermark
            self.journal.save()
            self.journal.prune()
        except (ValueError, OSError, subprocess.SubprocessError):
            self.coverages = []
            self.journal.gap('native-coverage-inspection-failed', self.generation)

    def request(self, request):
        operation = request.get('op')
        if operation == 'health':
            return self.health()
        if operation == 'resume':
            self.quiescing = False
            return {}
        if operation == 'prepare-cleanup':
            self.drain()
            self.journal.prune()
            if self.journal.state['bindings'] or self.journal.files or self.journal.loss is not None or self.journal.state['head'] != self.journal.state['acked']:
                raise ValueError('collector has active bindings or unacknowledged evidence')
            native = command_json(['nft', '-j', 'list', 'ruleset'])
            for row in native.get('nftables', []):
                for expression in row.get('rule', {}).get('expr', []):
                    if expression.get('log', {}).get('group') == self.group:
                        raise ValueError('native rules still reference collector NFLOG group')
            self.quiescing = True
            return {'quiesced': True}
        if getattr(self, 'quiescing', False):
            raise ValueError('collector is quiesced for exact-owned idle cleanup')
        if operation == 'reconcile':
            return self.reconcile(request['reconciliation'])
        if operation == 'register':
            return self.register(request['binding'])
        if operation == 'read':
            self.coverage()
            limits = request['limits']
            count = max(1, min(1024, int(limits.get('max_records') or 256)))
            size = max(1, min(1024 * 1024, int(limits.get('max_bytes') or 1024 * 1024)))
            records, cursor = self.journal.read(int(request['cursor']), count, size)
            coverage = []
            coverage_bytes = 0
            for item in self.coverages:
                coverage_bytes += len(encoded(item))
                if coverage_bytes > 512 * 1024:
                    self.journal.gap('coverage-index-truncated', self.generation)
                    break
                coverage.append(item)
            return {'records': records, 'cursor': cursor, 'health': self.health(), 'coverage': coverage}
        if operation == 'ack':
            self.journal.ack(int(request['cursor']))
            return {}
        if operation == 'retire':
            self.retire(request['registration'])
            return {}
        if operation == 'gap':
            gap = request['gap']
            if not gap.get('start') or gap['start'].startswith('0001-01-01'):
                gap['start'] = self.journal.state.get('watermark', now())
            if not gap.get('end') or gap['end'].startswith('0001-01-01'):
                gap['end'] = now()
            if not gap.get('generation'):
                gap['generation'] = self.generation
            if len(encoded(gap)) > 4096:
                raise ValueError('gap exceeds bound')
            if not self.journal.append({'gap': gap}):
                self.journal.loss_gap(gap['reason'], self.generation, gap.get('token', ''), gap['start'])
            return {}
        raise ValueError('unknown control operation')

    def serve(self):
        self.counter_time = time.monotonic()
        while True:
            ready, _, _ = select.select([self.netlink, self.control], [], [], 0.1)
            if time.monotonic() - self.counter_time >= 1:
                self.drain()
                self.coverage()
                self.counter_time = time.monotonic()
            if self.netlink in ready:
                self.drain()
            if self.control in ready:
                connection, _ = self.control.accept()
                try:
                    connection.settimeout(2)
                    data = bytearray()
                    while b'\n' not in data:
                        block = connection.recv(min(65536, MAX_CONTROL + 1 - len(data)))
                        if not block:
                            raise ValueError('incomplete control frame')
                        data.extend(block)
                        if len(data) > MAX_CONTROL:
                            raise ValueError('control frame exceeds bound')
                    response = {'result': self.request(json.loads(data))}
                except Exception as error:
                    response = {'error': str(error)[:1024]}
                try:
                    reply = encoded(response) + b'\n'
                    if len(reply) > MAX_CONTROL:
                        reply = encoded({'error': 'control reply exceeds bound'}) + b'\n'
                    connection.sendall(reply)
                except (OSError, TimeoutError):
                    pass
                finally:
                    connection.close()


if __name__ == '__main__':
    Receiver().serve()
