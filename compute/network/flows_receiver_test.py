import base64
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
