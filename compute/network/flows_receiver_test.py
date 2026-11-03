import base64
import copy
import os
import struct
import tempfile
import types
import unittest

receiver = types.ModuleType('stackd_flow_receiver_test')
exec(compile(base64.b64decode(os.environ['FLOW_TEST_SOURCE']), 'flows_receiver.py', 'exec'), receiver.__dict__)


def ipv4_udp(payload=b'customer-body-must-never-be-retained', options=b'', fragment=0):
    ihl = 20 + len(options)
    udp = struct.pack('!HHHH', 40001, 40002, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x40 | (ihl // 4), 0, ihl + len(udp), 1, fragment, 64, 17, 0,
                     b'\x0a\x01\x00\x0a', b'\x0a\x01\x00\x0b')
    return ip + options + udp


def ipv4_tcp(flags, ip_options=b'', tcp_options=b'', payload=b'', fragment=0):
    ihl = 20 + len(ip_options)
    tcp_length = 20 + len(tcp_options)
    tcp = struct.pack('!HHIIBBHHH', 40001, 40002, 1, 2, (tcp_length // 4) << 4, flags, 65535, 0, 0)
    tcp += tcp_options + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x40 | (ihl // 4), 0, ihl + len(tcp), 1, fragment, 64, 6, 0,
                     b'\x0a\x01\x00\x0a', b'\x0a\x01\x00\x0b')
    return ip + ip_options + tcp


def attr(kind, value):
    data = struct.pack('=HH', len(value) + 4, kind) + value
    return data + b'\0' * ((-len(data)) % 4)


class DecoderTests(unittest.TestCase):
    def test_ipv4_options_exact_ip_bytes_no_payload(self):
        packet = ipv4_udp(options=b'\x01\x01\x00\x00')
        decoded = receiver.packet_header(packet[:128])
        self.assertEqual(decoded['ip_bytes'], len(packet))
        self.assertEqual(decoded['source_port'], 40001)
        self.assertEqual(decoded['destination_port'], 40002)
        self.assertEqual(decoded['packets'], 1)
        self.assertNotIn(b'customer-body', receiver.encoded(decoded))
        ethernet = b'\x02' + b'\x00' * 11 + b'\x08\x00' + packet
        self.assertEqual(receiver.packet_header(ethernet), decoded)

    def test_tcp_controls_options_raw_flags_and_exact_ip_bytes(self):
        # Normalization belongs to the consumer: retain raw ACK/ECN/PSH bits here.
        cases = ((0x02, b'', b''), (0xd2, b'\x01\x01\x00\x00', b'\x01' * 12),
                 (0x10, b'\x01' * 40, b'\x01' * 40))
        for flags, ip_options, tcp_options in cases:
            with self.subTest(flags=flags, ihl=20 + len(ip_options), tcp_length=20 + len(tcp_options)):
                packet = ipv4_tcp(flags, ip_options, tcp_options)
                decoded = receiver.packet_header(packet)
                self.assertEqual(decoded, {
                    'source_address': '10.1.0.10', 'destination_address': '10.1.0.11',
                    'protocol': 6, 'source_port': 40001, 'destination_port': 40002,
                    'ip_bytes': len(packet), 'packets': 1, 'tcp_flags': flags})
                ethernet = b'\x02' + b'\x00' * 11 + b'\x08\x00' + packet
                self.assertEqual(receiver.packet_header(ethernet), decoded)

    def test_tcp_real_headers_preserve_ambiguity_and_length_failures(self):
        with self.assertRaisesRegex(ValueError, 'tcp-segmentation-ambiguity'):
            receiver.packet_header(ipv4_tcp(0x18, tcp_options=b'\x01' * 12, payload=b'customer-body'))
        for fragment in (0x2000, 1):
            with self.assertRaisesRegex(ValueError, 'fragment-count-ambiguity'):
                receiver.packet_header(ipv4_tcp(0x02, fragment=fragment))
        with self.assertRaisesRegex(ValueError, 'truncated-transport-header'):
            receiver.packet_header(ipv4_tcp(0x02)[:39])
        for offset in (0x40, 0xf0):
            packet = bytearray(ipv4_tcp(0x02))
            packet[32] = offset
            with self.assertRaisesRegex(ValueError, 'invalid-tcp-header'):
                receiver.packet_header(packet)

    def test_tcp_native_attributes_journal_replay_and_mtu_gap(self):
        with tempfile.TemporaryDirectory() as root:
            owner = {'test': 'tcp-control-owner'}
            instance = receiver.Receiver.__new__(receiver.Receiver)
            instance.journal = receiver.Journal(root, owner)
            instance.journal.state['group'] = 12123
            instance.generation = 'tcp-generation'
            instance.boot = 'tcp-boot'
            instance.last_sequence = None
            instance.received = {}
            token = '2' * 32
            binding = {'peer_ifindex': 321, 'boot_id': instance.boot, 'generation': 'tcp-policy',
                       'mtu': 60, 'identity': {'interface_id': 'eni-tcp'}}
            instance.journal.state['bindings'][token] = {'binding': binding}
            instance.journal.save()
            controls = (0x02, 0x12, 0x10, 0x01, 0x11, 0x04, 0x14, 0xd2)
            packets = [ipv4_tcp(flags, b'\x01' * 4, b'\x01' * 12) for flags in controls]
            packets += [ipv4_tcp(0x10, payload=b'customer-body-must-never-be-retained'),
                        ipv4_tcp(0x02, fragment=0x2000), ipv4_tcp(0x02, tcp_options=b'\x01' * 24)]
            for sequence, packet in enumerate(packets, 1):
                frame = (struct.pack('!BBH', 7, 0, 12123) + attr(12, struct.pack('!I', sequence))
                         + attr(6, struct.pack('!I', 321))
                         + attr(10, ('sf:' + token + ':egress:ACCEPT').encode() + b'\0')
                         + attr(9, packet))
                instance.decode(frame)
            records, cursor = instance.journal.read(0, 100, 65536)
            observations = [row['observation'] for row in records if 'observation' in row]
            self.assertEqual([row['tcp_flags'] for row in observations], list(controls))
            self.assertEqual(sum(row['packets'] for row in observations), len(controls))
            self.assertEqual(sum(row['ip_bytes'] for row in observations), 56 * len(controls))
            self.assertTrue(all(row['binding']['identity']['interface_id'] == 'eni-tcp' for row in observations))
            reasons = [row['gap']['reason'] for row in records if 'gap' in row]
            for reason in ('tcp-segmentation-ambiguity', 'fragment-count-ambiguity', 'skb-segmentation-mtu-ambiguity'):
                self.assertIn(reason, reasons)
            successor = receiver.Journal(root, owner)
            self.assertEqual(successor.read(0, 100, 65536), (records, cursor))
            for directory, _, files in os.walk(root):
                for filename in files:
                    with open(os.path.join(directory, filename), 'rb') as stream:
                        self.assertNotIn(b'customer-body', stream.read())
            successor.ack(cursor)
            self.assertEqual(receiver.Journal(root, owner).read(cursor, 100, 65536), ([], cursor))

    def test_fragments_truncation_and_segmentation_are_gaps(self):
        for packet in (ipv4_udp(fragment=0x2000), ipv4_udp(fragment=1), ipv4_udp()[:24]):
            with self.assertRaises(ValueError):
                receiver.packet_header(packet)
        packet = bytearray(ipv4_udp())
        packet[24:26] = b'\x00\x08'
        with self.assertRaisesRegex(ValueError, 'udp-segmentation'):
            receiver.packet_header(packet)
        tcp = bytearray(ipv4_udp())
        tcp[9] = 6
        tcp[32] = 0x50
        with self.assertRaisesRegex(ValueError, 'tcp-segmentation'):
            receiver.packet_header(tcp)

    def test_custom_dns_not_excluded(self):
        packet = bytearray(ipv4_udp())
        packet[22:24] = struct.pack('!H', 53)
        self.assertIsNotNone(receiver.packet_header(packet))
        packet[16:20] = b'\xa9\xfe\xa9\xfe'
        self.assertIsNone(receiver.packet_header(packet))

    def test_native_attributes_sequence_identity_and_discard(self):
        with tempfile.TemporaryDirectory() as root:
            instance = receiver.Receiver.__new__(receiver.Receiver)
            instance.journal = receiver.Journal(root, {'test': 'owner'})
            instance.journal.state['group'] = 12123
            instance.generation = 'native-test-generation'
            instance.boot = 'native-test-boot'
            instance.last_sequence = None
            instance.received = {}
            token = '1' * 32
            binding = {'peer_ifindex': 321, 'boot_id': instance.boot, 'generation': 'policy-test-generation', 'identity': {'interface_id': 'eni-authoritative'}}
            instance.journal.state['bindings'][token] = {'binding': binding}
            instance.journal.save()
            def frame(sequence, peer=321, packet=None):
                return struct.pack('!BBH', 7, 0, 12123) + attr(12, struct.pack('!I', sequence)) + attr(6, struct.pack('!I', peer)) + attr(10, ('sf:' + token + ':egress:REJECT').encode() + b'\0') + attr(9, packet or ipv4_udp()) + attr(3, struct.pack('!QQ', 1700000000, 123456))
            instance.decode(frame(1))
            instance.decode(frame(3))
            instance.decode(frame(4, peer=999))
            records, _ = instance.journal.read(0, 100, 65536)
            observations = [record['observation'] for record in records if 'observation' in record]
            self.assertEqual(len(observations), 2)
            self.assertEqual(observations[0]['action'], 'REJECT')
            self.assertEqual(observations[0]['binding']['identity']['interface_id'], 'eni-authoritative')
            self.assertEqual(observations[0]['observed_at'], '2023-11-14T22:13:20.123456Z')
            reasons = [record['gap']['reason'] for record in records if 'gap' in record]
            self.assertIn('netlink-sequence-loss', reasons)
            self.assertIn('peer-identity-mismatch', reasons)
            for directory, _, files in os.walk(root):
                for filename in files:
                    with open(os.path.join(directory, filename), 'rb') as stream:
                        self.assertNotIn(b'customer-body', stream.read())

    def test_forward_peer_witness_is_optional_frozen_and_lifetime_fenced(self):
        with tempfile.TemporaryDirectory() as root:
            instance = receiver.Receiver.__new__(receiver.Receiver)
            owner = {'test': 'peer-witness'}
            instance.journal = receiver.Journal(root, owner)
            instance.journal.state['group'] = 12123
            instance.generation, instance.boot = 'receiver', 'boot'
            instance.last_sequence, instance.received = None, {}
            instance.link_revision = 0
            class LinkSocket:
                messages = []
                def recvmsg(self, size):
                    if not self.messages:
                        raise BlockingIOError()
                    return self.messages.pop(0)
            instance.links = LinkSocket()
            source_token, target_token = 'a' * 32, 'b' * 32
            identity = {'partition': 'aws', 'account_id': '111111111111', 'region': 'us-east-1',
                        'vpc_id': 'vpc-one', 'subnet_id': 'subnet-one', 'interface_id': 'eni-source'}
            source = {'identity': identity, 'network_id': 'arn:aws:ec2:us-east-1:111111111111:vpc/vpc-one',
                      'peer_ifindex': 321, 'peer_name': 'source', 'bridge': 'bridge', 'bridge_ifindex': 300,
                      'boot_id': 'boot', 'engine_id': 'engine', 'generation': 'source-policy', 'mtu': 1500,
                      'address': '10.1.0.10', 'mac': '02:00:00:00:00:0a'}
            target = copy.deepcopy(source)
            target.update(peer_ifindex=322, peer_name='target', address='10.1.0.11',
                          mac='02:00:00:00:00:0b', generation='target-policy')
            target['identity']['interface_id'] = 'eni-target'
            baseline = {
                source_token: {'binding': source, 'registered_at': '2023-11-14T22:13:20.123455Z'},
                target_token: {'binding': target, 'registered_at': '2023-11-14T22:13:20.123455Z'}}
            layer2 = bytes.fromhex('02000000000b02000000000a0800')
            actual = {1: struct.pack('!HBB', 0x0800, 2, 0), 4: struct.pack('!I', 321), 6: struct.pack('!I', 321),
                      7: struct.pack('!I', 322), 21: layer2, 3: struct.pack('!QQ', 1700000000, 123456)}
            observations = []
            def capture(change=None, attrs_change=None, direction='egress', action='ACCEPT', family=7):
                instance.journal.state['bindings'] = copy.deepcopy(baseline)
                instance.peer_lifetimes = {token: entry['registered_at'] for token, entry in baseline.items()}
                if change:
                    change()
                attrs = dict(actual)
                if attrs_change:
                    attrs_change(attrs)
                frame = (struct.pack('!BBH', family, 0, 12123)
                         + attr(12, struct.pack('!I', len(observations) + 1))
                         + attr(10, ('sf:' + source_token + ':' + direction + ':' + action).encode() + b'\0')
                         + attr(9, ipv4_udp()))
                frame += b''.join(attr(kind, value) for kind, value in attrs.items())
                instance.decode(frame)
                rows, _ = instance.journal.read(0, 100, 1024 * 1024)
                self.assertFalse(any('gap' in row for row in rows))
                observation = rows[-1]['observation']
                observations.append(observation)
                self.assertEqual((observation['packets'], observation['ip_bytes']), (1, len(ipv4_udp())))
                return observation.get('peer_witness')
            first = capture()
            self.assertEqual(first['target']['identity']['interface_id'], 'eni-target')
            self.assertEqual(first['physical_output'], 322)
            for options in ({'direction': 'ingress'}, {'action': 'REJECT'}, {'family': 2},
                            {'attrs_change': lambda attrs: attrs.pop(1)},
                            {'attrs_change': lambda attrs: attrs.update({1: struct.pack('!HBB', 0x0800, 1, 0)})},
                            {'attrs_change': lambda attrs: attrs.pop(6)},
                            {'attrs_change': lambda attrs: attrs.update({7: struct.pack('!I', 321)})},
                            {'attrs_change': lambda attrs: attrs.pop(3)},
                            {'attrs_change': lambda attrs: attrs.pop(21)},
                            {'attrs_change': lambda attrs: attrs.update({21: b'\0' * 12 + b'\x08\x00'})},
                            {'attrs_change': lambda attrs: attrs.update({20: b''})},
                            {'change': lambda: instance.peer_lifetimes.update({target_token: '2023-11-14T22:13:20.123457Z'})},
                            {'change': lambda: instance.peer_lifetimes.update({source_token: '2023-11-14T22:13:20.123457Z'})},
                            {'change': lambda: instance.journal.state['bindings'][target_token].update(retired=True)},
                            {'change': lambda: instance.journal.state['bindings'][source_token].update(retired=True)},
                            {'change': lambda: instance.journal.state['bindings'][target_token]['binding'].update(network_id='foreign-vpc')},
                            {'change': lambda: instance.journal.state['bindings'][target_token]['binding'].update(engine_id='foreign-engine')},
                            {'change': lambda: instance.journal.state['bindings'][target_token]['binding'].update(boot_id='foreign-boot')},
                            {'change': lambda: instance.journal.state['bindings'][target_token]['binding'].update(bridge_ifindex=999)},
                            {'change': lambda: instance.journal.state['bindings'][target_token]['binding'].update(address='10.1.0.12')},
                            {'change': lambda: instance.journal.state['bindings'][source_token]['binding'].update(address='10.1.0.12')}):
                with self.subTest(options=options):
                    self.assertIsNone(capture(**options))
            def overlapping_epoch():
                duplicate = copy.deepcopy(baseline[target_token])
                duplicate['binding']['generation'] = 'next-policy'
                instance.journal.state['bindings']['c' * 32] = duplicate
                instance.peer_lifetimes['c' * 32] = duplicate['registered_at']
            self.assertIsNotNone(capture(change=overlapping_epoch))
            def ambiguous_attachment():
                overlapping_epoch()
                instance.journal.state['bindings']['c' * 32]['binding']['identity']['interface_id'] = 'eni-other'
            self.assertIsNone(capture(change=ambiguous_attachment))
            def link_event():
                info = struct.pack('=BBHiII', 0, 0, 1, 322, 0, 0)
                event = struct.pack('=IHHII', 32, 17, 0, 0, 0) + info
                instance.links.messages.append((event, [], 0, (0, 1)))
            self.assertIsNone(capture(change=link_event))
            def new_link(index=322, name=b'target', master=300, flags=1):
                info = struct.pack('=BBHiII', 0, 0, 1, index, flags, 0)
                info += attr(3, name + b'\0') + attr(20, b'updated alias\0')
                if master:
                    info += attr(10, struct.pack('=I', master))
                event = struct.pack('=IHHII', 16 + len(info), 16, 0, 0, 0) + info
                instance.links.messages.append((event, [], 0, (0, 1)))
            self.assertEqual(capture(change=new_link), first)
            self.assertEqual(capture(change=lambda: new_link(300, b'bridge', 0)), first)
            for change in (lambda: new_link(name=b'renamed'),
                           lambda: new_link(master=999),
                           lambda: new_link(master=0),
                           lambda: new_link(flags=0)):
                self.assertIsNone(capture(change=change))
            def deleted_then_reused():
                link_event()
                new_link()
            self.assertIsNone(capture(change=deleted_then_reused))
            def overflow():
                instance.links.messages.append((b'', [], receiver.socket.MSG_TRUNC, (0, 1)))
            self.assertIsNone(capture(change=overflow))
            self.assertIsNone(capture(change=lambda: instance.peer_lifetimes.clear()))
            self.assertEqual(first['target']['address'], '10.1.0.11')
            rows, cursor = instance.journal.read(0, 100, 1024 * 1024)
            self.assertEqual(sum(row['observation']['packets'] for row in rows), len(observations))
            self.assertEqual(receiver.Journal(root, owner).read(0, 100, 1024 * 1024), (rows, cursor))

    def test_conntrack_translation_evidence_rejects_nat_and_mismatched_tuples(self):
        observation = receiver.packet_header(ipv4_udp())
        def tuple_attrs(source, destination):
            return attr(1, attr(1, receiver.ipaddress.IPv4Address(source).packed)
                        + attr(2, receiver.ipaddress.IPv4Address(destination).packed))
        original = tuple_attrs('10.1.0.10', '10.1.0.11')
        reply = tuple_attrs('10.1.0.11', '10.1.0.10')
        metadata = attr(1, original) + attr(2, reply) + attr(3, struct.pack('!I', 2))
        self.assertEqual(receiver.peer_conntrack(metadata, observation)['status'], 2)
        for status in (1 << 4, 1 << 5):
            with self.assertRaisesRegex(ValueError, 'translated'):
                receiver.peer_conntrack(attr(1, original) + attr(2, reply) + attr(3, struct.pack('!I', status)), observation)
        # NAT_DONE also describes a null (untranslated) NAT binding.
        for status in (1 << 7, 1 << 8):
            self.assertEqual(receiver.peer_conntrack(attr(1, original) + attr(2, reply)
                             + attr(3, struct.pack('!I', status)), observation)['status'], status)
        with self.assertRaisesRegex(ValueError, 'translated'):
            receiver.peer_conntrack(attr(1, original) + attr(2, tuple_attrs('10.1.0.12', '10.1.0.10'))
                                    + attr(3, struct.pack('!I', 2)), observation)

    def test_registration_reverifies_and_fences_reused_peers_without_dropping_capture(self):
        with tempfile.TemporaryDirectory() as root:
            instance = receiver.Receiver.__new__(receiver.Receiver)
            instance.journal = receiver.Journal(root, {'test': 'registration-lifetimes'})
            instance.generation, instance.boot, instance.engine = 'receiver', 'boot', 'engine'
            instance.group = 12123
            instance.peer_lifetimes, instance.link_revision = {}, 0
            instance.drain = lambda: None
            instance.drain_links = lambda: True
            identity = {'partition': 'aws', 'account_id': '111111111111', 'region': 'us-east-1',
                        'vpc_id': 'vpc-one', 'subnet_id': 'subnet-one', 'interface_id': 'eni-target'}
            binding = {'identity': identity, 'network_id': 'arn:aws:ec2:us-east-1:111111111111:vpc/vpc-one',
                       'policy_table': 'stackd_ec2_abcd', 'public_owner': 'controller', 'generation': 'epoch-one',
                       'peer_name': 'target', 'bridge': 'bridge', 'address': '10.1.0.11', 'mac': '02:00:00:00:00:0b'}
            original_json, original_native = receiver.command_json, receiver.run_native
            changed_during_inspection = False
            def inspect(arguments):
                if arguments[-1] == 'target':
                    if changed_during_inspection:
                        instance.invalidate_links({322})
                    return [{'ifindex': 322, 'master': 'bridge', 'mtu': 1500}]
                return [{'ifindex': 300, 'mtu': 1500}]
            receiver.command_json = inspect
            receiver.run_native = lambda arguments: types.SimpleNamespace(returncode=1, stderr=b'No such file', stdout=b'')
            try:
                registration = instance.register(copy.deepcopy(binding))
                token = registration['token']
                self.assertIn(token, instance.peer_lifetimes)
                self.assertEqual(instance.journal.state['bindings'][token]['binding']['bridge_ifindex'], 300)
                instance.peer_lifetimes[token] = '2020-01-01T00:00:00Z'
                self.assertEqual(instance.register(copy.deepcopy(binding)), registration)
                self.assertNotEqual(instance.peer_lifetimes[token], '2020-01-01T00:00:00Z')
                overlap = copy.deepcopy(binding)
                overlap['generation'] = 'epoch-two'
                second = instance.register(overlap)
                self.assertIn(token, instance.peer_lifetimes)
                self.assertIn(second['token'], instance.peer_lifetimes)
                reused = copy.deepcopy(binding)
                reused['identity']['interface_id'] = 'eni-reused'
                third = instance.register(reused)
                self.assertNotIn(token, instance.peer_lifetimes)
                self.assertNotIn(second['token'], instance.peer_lifetimes)
                self.assertIn(third['token'], instance.peer_lifetimes)
                changed_during_inspection = True
                uncertain = copy.deepcopy(binding)
                uncertain['identity']['interface_id'] = 'eni-racing'
                fourth = instance.register(uncertain)
                self.assertIn(fourth['token'], instance.journal.state['bindings'])
                self.assertNotIn(fourth['token'], instance.peer_lifetimes)
                self.assertNotIn(third['token'], instance.peer_lifetimes)
                # Retirement invalidates enrichment before draining old frames.
                changed_during_inspection = False
                instance.register(copy.deepcopy(uncertain))
                during_drain = []
                instance.drain = lambda: during_drain.append(fourth['token'] in instance.peer_lifetimes)
                instance.retire(fourth)
                self.assertEqual(during_drain, [False])
            finally:
                receiver.command_json, receiver.run_native = original_json, original_native


class JournalTests(unittest.TestCase):
    def test_replay_restart_durable_ack_and_owner_rejection(self):
        with tempfile.TemporaryDirectory() as root:
            owner = {'namespace': 'owner-a', 'engine_id': 'engine-a'}
            first = receiver.Journal(root, owner)
            first.gap('explicit-test-loss', 'generation-a')
            records, cursor = first.read(0, 10, 65536)
            self.assertEqual((records, cursor), first.read(0, 10, 65536))
            successor = receiver.Journal(root, owner)
            self.assertEqual((records, cursor), successor.read(0, 10, 65536))
            successor.ack(cursor)
            final = receiver.Journal(root, owner)
            self.assertEqual(final.read(cursor, 10, 65536), ([], cursor))
            with self.assertRaises(ValueError):
                final.read(0, 10, 65536)
            with self.assertRaises(ValueError):
                final.ack(cursor + 1)
            with self.assertRaises(ValueError):
                receiver.Journal(root, {'namespace': 'foreign'})

    def test_full_spool_retains_loss_then_replays_after_ack(self):
        saved = receiver.MAX_RECORDS
        receiver.MAX_RECORDS = 2
        try:
            with tempfile.TemporaryDirectory() as root:
                journal = receiver.Journal(root, {'namespace': 'full-test'})
                journal.gap('first', 'generation')
                journal.gap('second', 'generation')
                journal.observation({'packets': 1, 'test': 'header-only'}, 'generation')
                self.assertEqual(len(journal.files), 2)
                self.assertIsNotNone(journal.loss)
                successor = receiver.Journal(root, {'namespace': 'full-test'})
                self.assertIn('spool-full', successor.loss['reason'])
                records, cursor = successor.read(0, 100, 65536)
                self.assertEqual(len(records), 2)
                successor.ack(cursor)
                loss, end = successor.read(cursor, 100, 65536)
                self.assertEqual(loss[0]['gap']['reason'], 'spool-full')
                self.assertGreater(end, cursor)
                self.assertIsNone(successor.loss)
        finally:
            receiver.MAX_RECORDS = saved

    def test_explicit_gap_keeps_original_start_when_full_and_restarted(self):
        saved = receiver.MAX_RECORDS
        receiver.MAX_RECORDS = 1
        try:
            with tempfile.TemporaryDirectory() as root:
                instance = receiver.Receiver.__new__(receiver.Receiver)
                instance.journal = receiver.Journal(root, {'namespace': 'gap-start-test'})
                instance.generation = 'generation'
                instance.journal.state['watermark'] = '2026-10-15T12:00:20Z'
                instance.journal.gap('fill', 'generation')
                instance.request({'op': 'gap', 'gap': {'reason': 'earlier-native-operation',
                    'start': '2026-10-15T12:00:10Z', 'end': '2026-10-15T12:00:20Z'}})
                self.assertEqual(instance.journal.loss['start'], '2026-10-15T12:00:10Z')
                successor = receiver.Journal(root, {'namespace': 'gap-start-test'})
                self.assertEqual(successor.loss['start'], '2026-10-15T12:00:10Z')
                _, cursor = successor.read(0, 10, 65536)
                successor.ack(cursor)
                records, _ = successor.read(cursor, 10, 65536)
                self.assertEqual(records[0]['gap']['start'], '2026-10-15T12:00:10Z')
        finally:
            receiver.MAX_RECORDS = saved

    def test_retire_mapping_prunes_only_after_barrier_ack(self):
        with tempfile.TemporaryDirectory() as root:
            journal = receiver.Journal(root, {'namespace': 'retire-test'})
            journal.state['bindings']['token'] = {'retired': True}
            journal.prune()
            self.assertIn('token', journal.state['bindings'])
            journal.gap('retirement-drain-barrier', 'generation', 'token')
            journal.state['bindings']['token']['retire_cursor'] = journal.state['head']
            journal.prune()
            self.assertIn('token', journal.state['bindings'])
            journal.ack(journal.state['head'])
            self.assertNotIn('token', journal.state['bindings'])


class CoverageAndCleanupTests(unittest.TestCase):
    def test_verified_generation_counters_and_deficits(self):
        with tempfile.TemporaryDirectory() as root:
            instance = receiver.Receiver.__new__(receiver.Receiver)
            instance.journal = receiver.Journal(root, {'namespace': 'coverage-test'})
            instance.generation = 'receiver-generation'
            instance.boot = 'boot'
            instance.namespace = 'coverage-test'
            instance.received = {}
            instance.last_counters = {}
            instance.last_empty = receiver.time.monotonic()
            instance.drain = lambda: setattr(instance, 'last_empty', receiver.time.monotonic())
            token = 'a' * 32
            binding = {'boot_id': 'boot', 'generation': 'policy-generation', 'policy_table': 'stackd_ec2_1234', 'public_owner': 'owned-controller'}
            instance.journal.state['bindings'][token] = {'binding': binding}
            rows = []
            for family in ('bridge', 'netdev'):
                common = {'family': family, 'table': binding['policy_table']}
                rows.append({'chain': dict(common, name='flow_identity', comment='sf:' + receiver.hashlib.sha256(instance.namespace.encode()).hexdigest()[:32] + ':' + token + ':' + binding['generation'])})
                rows.append({'chain': dict(common, name='flow_controller', comment=receiver.hashlib.sha256(binding['public_owner'].encode()).hexdigest())})
                names = ['flow_from_reject', 'flow_to_reject']
                if family == 'bridge':
                    names += ['flow_from_accept', 'flow_to_accept']
                for name in names:
                    rows.append({'counter': dict(common, name=name, packets=0)})
            original = receiver.command_json
            receiver.command_json = lambda arguments: {'nftables': rows}
            try:
                instance.coverage()
                self.assertFalse(instance.coverages[0]['ready'])
                instance.coverage()
                self.assertTrue(instance.coverages[0]['ready'])
                self.assertEqual(instance.coverages[0]['watermark'], instance.watermark)
                # Receipt after the counter read is credit for the next poll,
                # not a loss when the native counter catches up while idle.
                key = (token, 'egress', 'ACCEPT')
                instance.received[key] = 1
                instance.coverage()
                self.assertEqual(instance.last_counters[key][2], 1)
                for row in rows:
                    if row.get('counter', {}).get('name') == 'flow_from_accept':
                        row['counter']['packets'] = 1
                instance.coverage()
                self.assertTrue(instance.coverages[0]['ready'])
                self.assertEqual(instance.last_counters[key][2], 0)
                receipts, _ = instance.journal.read(0, 100, 65536)
                self.assertFalse(any(row.get('gap', {}).get('reason') == 'counter-observation-deficit' for row in receipts))
                rows[-1]['counter']['packets'] = 1
                instance.coverage()
                self.assertFalse(instance.coverages[0]['ready'])
                records, _ = instance.journal.read(0, 100, 65536)
                self.assertTrue(any(row.get('gap', {}).get('reason') == 'counter-observation-deficit' for row in records))
                rows.append({'chain': {'family': 'bridge', 'table': binding['policy_table'], 'name': 'flow_uncertain'}})
                instance.coverage()
                self.assertFalse(instance.coverages[0]['ready'])
            finally:
                receiver.command_json = original

    def test_cleanup_requires_ack_no_bindings_no_native_references(self):
        with tempfile.TemporaryDirectory() as root:
            instance = receiver.Receiver.__new__(receiver.Receiver)
            instance.journal = receiver.Journal(root, {'namespace': 'cleanup-test'})
            instance.group = 12345
            instance.drain = lambda: None
            instance.journal.gap('unacknowledged-test-gap', 'generation')
            with self.assertRaisesRegex(ValueError, 'unacknowledged'):
                instance.request({'op': 'prepare-cleanup'})
            instance.journal.ack(instance.journal.state['head'])
            original = receiver.command_json
            receiver.command_json = lambda arguments: {'nftables': [{'rule': {'expr': [{'log': {'group': 12345}}]}}]}
            try:
                with self.assertRaisesRegex(ValueError, 'native rules'):
                    instance.request({'op': 'prepare-cleanup'})
                receiver.command_json = lambda arguments: {'nftables': []}
                self.assertEqual(instance.request({'op': 'prepare-cleanup'}), {'quiesced': True})
                with self.assertRaisesRegex(ValueError, 'quiesced'):
                    instance.request({'op': 'register'})
                instance.request({'op': 'resume'})
                self.assertFalse(instance.quiescing)
            finally:
                receiver.command_json = original


class ReconciliationTests(unittest.TestCase):
    def test_only_resolved_unreferenced_generations_retire(self):
        with tempfile.TemporaryDirectory() as root:
            instance = receiver.Receiver.__new__(receiver.Receiver)
            instance.journal = receiver.Journal(root, {'namespace': 'reconcile-test'})
            instance.generation = 'receiver-generation'
            instance.namespace = 'reconcile-test'
            instance.boot = 'boot'
            instance.drain = lambda: None
            table, owner = 'stackd_ec2_abcd', 'persistent-controller'
            tokens = [str(number) * 32 for number in range(1, 6)]
            for order, token in enumerate(tokens, 1):
                binding = {'policy_table': table, 'public_owner': owner, 'boot_id': 'boot', 'generation': 'generation-' + token[0]}
                registration = {'token': token, 'group': 12345, 'generation': binding['generation']}
                instance.journal.state['bindings'][token] = {'binding': binding, 'registration': registration, 'order': order,
                    'registered_at': '2026-10-15T12:00:00Z'}
            instance.journal.state['registration_order'] = 5
            instance.journal.state['bindings'][tokens[4]]['binding']['public_owner'] = 'foreign-controller'
            current = instance.journal.state['bindings'][tokens[2]]
            rows = []
            for family in ('bridge', 'netdev'):
                rows.append({'table': {'family': family, 'name': table, 'comment': 'stackd:' + table}})
                common = {'family': family, 'table': table}
                witness = 'sf:' + receiver.hashlib.sha256(instance.namespace.encode()).hexdigest()[:32] + ':' + tokens[2] + ':' + current['binding']['generation']
                rows.append({'chain': dict(common, name='flow_identity', comment=witness)})
                rows.append({'chain': dict(common, name='flow_controller', comment=receiver.hashlib.sha256(owner.encode()).hexdigest())})
            rows.append({'rule': {'expr': [{'log': {'prefix': 'sf:' + tokens[1] + ':egress:REJECT', 'group': 12345}}]}})
            original = receiver.command_json
            receiver.command_json = lambda arguments: {'nftables': rows}
            try:
                scope = {'policy_table': table, 'public_owner': owner, 'through': current['registration']}
                self.assertEqual(instance.reconcile(scope), {'retired': 1})
                self.assertTrue(instance.journal.state['bindings'][tokens[0]]['retired'])
                for token in tokens[1:]:
                    self.assertFalse(instance.journal.state['bindings'][token].get('retired', False))
                # Acknowledgement cannot prune a mapping before its queue-drain
                # barrier, and the resolution survives a controller restart.
                instance.journal.ack(instance.journal.state['head'])
                self.assertIn(tokens[0], instance.journal.state['bindings'])
                recovered = receiver.Journal(root, {'namespace': 'reconcile-test'})
                self.assertTrue(recovered.state['bindings'][tokens[0]]['retired'])
                with self.assertRaisesRegex(ValueError, 'absent native tables'):
                    instance.reconcile(dict(scope, through={}))
                rows.clear()
                self.assertEqual(instance.reconcile(dict(scope, through={})), {'retired': 3})
                self.assertFalse(instance.journal.state['bindings'][tokens[4]].get('retired', False))
            finally:
                receiver.command_json = original


suite = unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
result = unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful():
    raise SystemExit(1)
