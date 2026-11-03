"""Independent, bounded header-only witness for the native TCP-control consumer."""
import itertools
import json
import sqlite3

from local import ACCOUNT, require

TCP_PORT = 33003
TCP_SEND = '''import json,socket,sys,time
address,sport,dport=sys.argv[1:]
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(8)
s.bind(('0.0.0.0',int(sport)));started=time.time()
s.connect((address,int(dport)));local=s.getsockname();peer=s.getpeername()
s.shutdown(socket.SHUT_WR)
assert s.recv(1)==b'', 'TCP peer sent application payload'
s.close()
print(json.dumps(dict(started=started,finished=time.time(),local=local,peer=peer,application_bytes=0,orderly_eof=True)))
'''

# SOCK_DGRAM removes the Ethernet header. The exact-tuple classic BPF filter
# returns only IHL+TCP data offset, so packet bodies never enter Python or logs.
WITNESS = r'''import ctypes,fcntl,json,os,signal,socket,struct,sys,time
source,destination,sport,dport,namespace,iflink=sys.argv[1:]
sport,dport,iflink=int(sport),int(dport),int(iflink)
assert os.readlink('/proc/self/ns/net')==namespace
assert int(open('/sys/class/net/eth0/iflink').read())==iflink
# ETH_P_ALL is required for Linux's outgoing tap; ETH_P_IP sees only ingress.
# The socket filter below still admits only this exact IPv4 TCP tuple.
s=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0003))
s.bind(('eth0',0));s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1<<20)
address=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s',b'eth0'))[20:24])
assert address==source
class Filter(ctypes.Structure):
 _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
 _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
# Symbolic jumps keep the exact-owned bidirectional tuple filter auditable.
code=[];labels={}
def label(name): labels[name]=len(code)
def ins(op,k=0,jt=None,jf=None): code.append([op,k,jt,jf])
def eq(k,yes,no): ins(0x15,k,yes,no)
ip=lambda value: struct.unpack('!I',socket.inet_aton(value))[0]
ins(0x20,0xfffff000);eq(0x0800,'ipv4','reject')  # SKF_AD_PROTOCOL
label('ipv4');ins(0x30,9);eq(6,'addresses','reject')
label('addresses');ins(0x20,12);eq(ip(source),'forward','reverse')
label('forward');ins(0x20,16);eq(ip(destination),'forward_ports','reject')
label('forward_ports');ins(0xb1,0);ins(0x48,0);eq(sport,'forward_destination','reject')
label('forward_destination');ins(0x48,2);eq(dport,'headers','reject')
label('reverse');eq(ip(destination),'reverse_address','reject')
label('reverse_address');ins(0x20,16);eq(ip(source),'reverse_ports','reject')
label('reverse_ports');ins(0xb1,0);ins(0x48,0);eq(dport,'reverse_destination','reject')
label('reverse_destination');ins(0x48,2);eq(sport,'headers','reject')
label('headers');ins(0x50,12);ins(0x54,0xf0);ins(0x74,2);ins(0x0c);ins(0x16)
label('reject');ins(0x06,0)
filters=(Filter*len(code))(*(Filter(op,0 if jt is None else labels[jt]-i-1,
 0 if jf is None else labels[jf]-i-1,k) for i,(op,k,jt,jf) in enumerate(code)))
program=Program(len(code),filters)
s.setsockopt(socket.SOL_SOCKET,26,bytes(program))  # SO_ATTACH_FILTER
s.setsockopt(socket.SOL_SOCKET,35,1)  # SO_TIMESTAMPNS, Linux x86_64
s.setsockopt(socket.SOL_SOCKET,40,1)  # SO_RXQ_OVFL
# Discard any traffic queued before the filter/readiness boundary.
s.setblocking(False)
while True:
 try: s.recv(134)
 except BlockingIOError: break
s.getsockopt(263,6,8)  # reset PACKET_STATISTICS before explicit readiness
stopping=False
def stop(*unused):
 global stopping
 stopping=True
signal.signal(signal.SIGUSR1,stop)
s.settimeout(.1);packets=[];overflow=0;deadline=time.monotonic()+25
print(json.dumps(dict(event='READY',namespace=namespace,address=address,interface='eth0',
 ifindex=socket.if_nametoindex('eth0'),iflink=iflink,snaplen='IPv4 header + TCP header only')),flush=True)
quiet=None
while True:
 if time.monotonic()>=deadline: raise RuntimeError('Witness deadline exceeded')
 if stopping and quiet is None: quiet=time.monotonic()+1
 if quiet is not None and time.monotonic()>=quiet: break
 try: data,ancillary,flags,peer=s.recvmsg(120,256)
 except socket.timeout: continue
 assert flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)==0, 'Truncated witness headers/ancillary'
 assert len(packets)<128, 'Witness packet bound exceeded'
 assert data[0]>>4==4 and data[9]==6
 ihl=(data[0]&15)*4;total=struct.unpack_from('!H',data,2)[0]
 assert struct.unpack_from('!H',data,6)[0]&0x3fff==0, 'Fragmented TCP witness'
 thl=(data[ihl+12]>>4)*4
 assert ihl>=20 and thl>=20 and total==ihl+thl==len(data), 'TCP payload/invalid header witness'
 stamp=None
 for level,kind,value in ancillary:
  if level==socket.SOL_SOCKET and kind==35:
   sec,nsec=struct.unpack('ll',value);stamp=sec*1000000000+nsec
  if level==socket.SOL_SOCKET and kind==40: overflow=max(overflow,struct.unpack('I',value)[0])
 assert stamp is not None, 'No kernel packet timestamp'
 src,dst=socket.inet_ntoa(data[12:16]),socket.inet_ntoa(data[16:20])
 sp,dp=struct.unpack_from('!HH',data,ihl)
 forward=(src,dst,sp,dp)==(source,destination,sport,dport)
 assert forward or (src,dst,sp,dp)==(destination,source,dport,sport)
 assert peer[2]==(socket.PACKET_OUTGOING if forward else socket.PACKET_HOST), 'Unexpected packet direction'
 packets.append(dict(timestamp_ns=stamp,srcaddr=src,dstaddr=dst,srcport=sp,dstport=dp,
  ip_bytes=total,ip_header_bytes=ihl,tcp_header_bytes=thl,tcp_flags=data[ihl+13],
  direction='forward' if forward else 'reverse'))
 if quiet is not None: quiet=time.monotonic()+1
received,dropped=struct.unpack('II',s.getsockopt(263,6,8))
assert stopping, 'Witness was not explicitly completed'
assert dropped==overflow==0 and received==len(packets), 'Witness loss/overflow/count mismatch'
print(json.dumps(dict(event='RESULT',packets=packets,received=received,dropped=dropped,
 overflow=overflow,completed=True)),flush=True)
'''


def normalized_flags(packets):
    flags = 0
    for packet in packets:
        raw = packet['tcp_flags']
        flags |= (raw & 7) | (16 if raw & 18 == 18 else 0)
    return flags


def validate_partition(rows, packets, label):
    """Allocate every witnessed packet exactly once, including late sealed batches."""
    remaining = tuple(range(len(packets)))
    ordered = sorted(rows, key=lambda row: (int(row['start']), int(row['end']), -int(row['packets'])))
    budget = 50000

    def allocate(index, available):
        nonlocal budget
        if index == len(ordered):
            return not available
        row = ordered[index]
        # Independent hooks can fall on opposite sides of a second/window
        # boundary. Permit only that bounded timestamp uncertainty; allocation
        # remains one-to-one across all real window/late-batch splits.
        candidates = [i for i in available if int(row['start']) - 1 <= packets[i]['timestamp_ns'] // 1000000000
                      <= int(row['end']) + 1]
        for selected in itertools.combinations(candidates, int(row['packets'])):
            budget -= 1
            require(budget >= 0, f'TCP exact packet partition complexity bound exceeded: {label}')
            observations = [packets[i] for i in selected]
            if (sum(p['ip_bytes'] for p in observations) != int(row['bytes'])
                    or normalized_flags(observations) != int(row['tcp-flags'])):
                continue
            times = [p['timestamp_ns'] // 1000000000 for p in observations]
            if not times or abs(min(times) - int(row['start'])) > 1 or abs(max(times) - int(row['end'])) > 1:
                continue
            used = set(selected)
            if allocate(index + 1, tuple(i for i in available if i not in used)):
                return True
        return False

    require(allocate(0, remaining), f'TCP rows do not partition the independent header witness: {label}: {rows}')


class TCPProof:
    def __init__(self, consumer, fields):
        self.c = consumer
        self.fields = fields
        self.helpers = []
        consumer.report['tcp'] = []
        consumer.report['tcp_helpers'] = self.helpers

    def connect(self, phase):
        c = self.c
        source, destination = c.source, c.destination
        sport = 32100 + phase
        name = c.name + f'-tcp-witness-{phase}'
        helper = {'name': name, 'phase': phase, 'removed': False, 'create_attempted': True}
        self.helpers.append(helper)
        c.save()
        try:
            identifier = c.docker('run', '-d', '--pull', 'never', '--name', name,
                '--label', 'stackd.flow.consumer=' + c.name, '--network', 'container:' + source['anchor'],
                '--read-only', '--cap-drop', 'ALL', '--cap-add', 'NET_RAW',
                '--security-opt', 'no-new-privileges:true', '--memory', '64m', '--memory-swap', '64m',
                '--pids-limit', '16', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1',
                '--entrypoint', 'python3', c.toolkit, '-u', '-c', WITNESS, source['address'],
                destination['address'], str(sport), str(TCP_PORT), source['native']['namespace'],
                str(source['native']['iflink']))
            helper['id'] = identifier
            inspected = json.loads(c.docker('inspect', identifier))[0]
            helper['host_config'] = inspected['HostConfig']
            c.save()
            require(inspected['HostConfig']['NetworkMode'] == 'container:' + source['anchor']
                    and [cap.removeprefix('CAP_') for cap in inspected['HostConfig']['CapAdd']] == ['NET_RAW']
                    and inspected['HostConfig']['CapDrop'] == ['ALL']
                    and not inspected['HostConfig']['Privileged'], 'Witness isolation/capabilities differ')
            def ready():
                logs = c.docker('logs', identifier)
                state = json.loads(c.docker('inspect', identifier))[0]['State']
                require(state['Running'], f'TCP witness exited before readiness: {logs}: {state}')
                return next((json.loads(line) for line in logs.splitlines()
                             if line.startswith('{') and json.loads(line).get('event') == 'READY'), None)
            helper['ready'] = c.wait('explicit header-only TCP witness readiness', ready, timeout=15)
            c.save()
            socket_result = json.loads(c.docker('exec', source['container'], 'python3', '-c', TCP_SEND,
                                               destination['address'], str(sport), str(TCP_PORT), timeout=15))
            require(socket_result['local'] == [source['address'], sport]
                    and socket_result['peer'] == [destination['address'], TCP_PORT]
                    and socket_result['orderly_eof'] and socket_result['application_bytes'] == 0,
                    f'TCP socket connection/close proof differs: {socket_result}')
            c.docker('kill', '--signal', 'USR1', identifier)
            require(c.docker('wait', identifier, timeout=10) == '0', 'Header-only TCP witness failed')
            logs = c.docker('logs', identifier)
            helper['log'] = logs
            result = next((json.loads(line) for line in logs.splitlines()
                           if line.startswith('{') and json.loads(line).get('event') == 'RESULT'), None)
            require(result and result['completed'] and result['dropped'] == result['overflow'] == 0
                    and result['received'] == len(result['packets']), 'Missing/lossy TCP witness result')
            packets = result['packets']
            require(all(int(socket_result['started']) - 1 <= p['timestamp_ns'] // 1000000000
                        <= int(socket_result['finished']) + 2 for p in packets),
                    'TCP witness timestamps lie outside the real socket lifecycle')
            for direction in ('forward', 'reverse'):
                controls = [p for p in packets if p['direction'] == direction]
                require(controls and any(p['tcp_flags'] & 2 for p in controls)
                        and any(p['tcp_flags'] & 1 for p in controls)
                        and not any(p['tcp_flags'] & 4 for p in controls),
                        f'TCP witness did not observe handshake and orderly FIN close: {direction}: {controls}')
            require(any(p['tcp_flags'] & 18 == 18 for p in packets if p['direction'] == 'reverse')
                    and any(p['tcp_flags'] & 0x3f == 16 for p in packets),
                    'TCP witness lacks SYN+ACK or countable pure ACK')
            def receipt():
                listener = c.docker('logs', destination['container'])
                receipts = [json.loads(line) for line in listener.splitlines() if line.startswith('{')]
                return next((row for row in receipts if row.get('event') == 'TCP_CLOSED'
                             and row.get('peer') == [source['address'], sport]), None)
            accepted = c.wait('actual TCP accept and orderly close receipt', receipt, timeout=10)
            require(accepted['local'] == [destination['address'], TCP_PORT]
                    and accepted['application_bytes'] == 0 and accepted['orderly_eof'],
                    f'TCP listener proof differs: {accepted}')
            c.report['tcp'].append({'phase': phase, 'socket': socket_result, 'listener': accepted,
                                    'witness': result, 'helper': name})
            c.report['listener_log'] = c.docker('logs', destination['container'])
            c.save()
        finally:
            self.remove(helper)

    def remove(self, helper):
        c = self.c
        ids = c.docker('ps', '-aq', '--filter', 'name=^/' + helper['name'] + '$').split()
        if ids:
            require(len(ids) == 1, 'Ambiguous exact TCP helper identity')
            row = json.loads(c.docker('inspect', ids[0]))[0]
            require(row['Name'] == '/' + helper['name']
                    and row['Config']['Labels'].get('stackd.flow.consumer') == c.name
                    and ('id' not in helper or row['Id'] == helper['id']), 'TCP helper ownership differs')
            helper['log'] = c.docker('logs', row['Id'])
            c.docker('rm', '-f', row['Id'])
        require(not c.docker('ps', '-aq', '--filter', 'name=^/' + helper['name'] + '$'),
                'Exact-owned TCP helper survived cleanup')
        helper['removed'] = True
        c.save()

    def expectations(self):
        c = self.c
        for connection in c.report['tcp']:
            for forward in (True, False):
                direction = 'forward' if forward else 'reverse'
                packets = [p for p in connection['witness']['packets'] if p['direction'] == direction]
                first = packets[0]
                for endpoint, flow_direction in ((c.source, 'egress' if forward else 'ingress'),
                                                  (c.destination, 'ingress' if forward else 'egress')):
                    yield connection, packets, {
                        'interface-id': endpoint['eni'], 'srcaddr': first['srcaddr'], 'dstaddr': first['dstaddr'],
                        'srcport': first['srcport'], 'dstport': first['dstport'], 'protocol': 6,
                        'flow-direction': flow_direction, 'subnet-id': endpoint['subnet']}

    def verify(self, rows):
        c = self.c
        evidence = []
        for connection, packets, expected in self.expectations():
            kinds = ('all', 'accept', 'parquet') if expected['interface-id'] == c.destination['eni'] else ('all',)
            matches = lambda row: all(str(row.get(key)) == str(value) for key, value in expected.items()
                                      if key != 'subnet-id')
            require(not any(matches(row) for row in rows['reject']), 'ACCEPT TCP control leaked into REJECT')
            for kind in kinds:
                found = [row for row in rows[kind] if matches(row)]
                if not self.complete(found, packets, expected, kind):
                    return False
                evidence.append({'phase': connection['phase'], 'destination': kind, 'selector': expected,
                                 'rows': found, 'packets': len(packets),
                                 'bytes': sum(p['ip_bytes'] for p in packets), 'tcp_flags': normalized_flags(packets)})
        c.report['tcp_publication_proof'] = evidence
        c.save()
        return True

    def complete(self, rows, packets, expected, label, pending=False):
        counts = sum(int(row['packets']) for row in rows)
        size = sum(int(row['bytes']) for row in rows)
        expected_size = sum(p['ip_bytes'] for p in packets)
        for row in rows:
            path = row.get('traffic-path')
            expected_path = '1' if expected['flow-direction'] == 'egress' else '-'
            actual_path = '-' if path is None or (pending and path == 0) else str(path)
            require(actual_path == expected_path, f'TCP native traffic path differs in {label}: {expected}: {row}')
        if pending:
            return counts == len(packets) and size == expected_size and all(
                row.get('action') == 'ACCEPT' and row.get('log-status') == 'OK' for row in rows)
        require(counts <= len(packets) and size <= expected_size,
                f'TCP duplicate/replayed control counts in {label}: {expected}: {rows}')
        if counts < len(packets) or size < expected_size:
            return False
        for row in rows:
            require(str(row['version']) == '5' and row['log-status'] == 'OK' and row['action'] == 'ACCEPT'
                    and row['account-id'] == ACCOUNT and row['vpc-id'] == self.c.outputs['vpc_id']
                    and row['subnet-id'] == expected['subnet-id'], f'TCP scope/status differs in {label}: {row}')
            require(int(row['packets']) > 0 and int(row['start']) <= int(row['end'])
                    and int(row['start']) // 60 == int(row['end']) // 60,
                    f'TCP record crosses its aggregation window: {row}')
        validate_partition(rows, packets, label)
        return True

    def checkpoint(self):
        """Demand both ENIs' complete controls in durable ALL state before restart."""
        c = self.c
        flow_ids = [row['FlowLogId'] for row in c.report['flow_logs']
                    if row['TrafficType'] == 'ALL']
        require(len(flow_ids) == 1, 'TCP checkpoint requires the exact ALL subscription')
        # Published lines can be retired from SQLite; fetch them before the
        # consistent DB snapshot. A concurrent delivery is retried, not summed
        # away or treated as proof of missing packets.
        rows = c.read_records()['all']
        with sqlite3.connect(f'file:{c.database}?mode=ro', uri=True) as db:
            db.row_factory = sqlite3.Row
            db.execute('BEGIN')
            # Repository uint64 counters use fixed-width big-endian SQLite BLOBs.
            rows.extend(dict(row, packets=int.from_bytes(row['packets'], 'big'),
                             bytes=int.from_bytes(row['bytes'], 'big')) for row in db.execute(
                'SELECT interface_id AS \"interface-id\", source_address AS srcaddr, '
                'destination_address AS dstaddr, source_port AS srcport, destination_port AS dstport, '
                'protocol, direction AS \"flow-direction\", packets, bytes, tcp_flags AS \"tcp-flags\", traffic_path AS \"traffic-path\", '
                "action, 'OK' AS \"log-status\" FROM ec2_flow_log_aggregates "
                'WHERE flow_log_id=? AND protocol=6 AND lost=0', (flow_ids[0],)))
            rows.extend(dict(zip(self.fields, row['message'].split())) for row in db.execute(
                'SELECT l.message FROM ec2_flow_log_delivery_lines l '
                'JOIN ec2_flow_log_deliveries d USING (partition,account_id,region,resource_id) '
                'WHERE d.flow_log_id=?', (flow_ids[0],)))
        proof = []
        for connection, packets, expected in self.expectations():
            found = [row for row in rows if all(str(row.get(key)) == str(value)
                     for key, value in expected.items() if key != 'subnet-id')]
            if not self.complete(found, packets, expected, 'durable ALL checkpoint', pending=True):
                return False
            require(normalized_flags(packets) == self.flags(found), 'TCP checkpoint flags differ from witness')
            proof.append({'phase': connection['phase'], 'selector': expected, 'rows': found,
                          'packets': len(packets), 'bytes': sum(p['ip_bytes'] for p in packets),
                          'tcp_flags': normalized_flags(packets)})
        c.report['tcp_checkpoint_proof'] = proof
        return True

    @staticmethod
    def flags(rows):
        flags = 0
        for row in rows:
            flags |= int(row['tcp-flags'])
        return flags

