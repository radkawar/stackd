"""Public-safe native binding diagnostics; requires the smoke fixture dependencies."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("eks_lbc_smoke", Path(__file__).with_name("eks_lbc_smoke.py"))
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class NativeAPIBindingWitnessTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {"WorkerAdvertiseHost": "192.0.2.37", "NativePort": 18443}
        self.exact = {"HostIp": "192.0.2.37", "HostPort": "18443"}

    def witness(self, configured, effective=None):
        node = {"HostConfig": {"PortBindings": configured},
                "NetworkSettings": {"Ports": effective}}
        return smoke.Smoke.native_api_bindings(node, self.receipt)

    def test_retained_bare_request_and_normalized_effective_port(self):
        report = self.witness({"6443": [self.exact]}, {"6443/tcp": [self.exact]})
        self.assertTrue(report["configured"]["matches"])
        self.assertTrue(report["effective"]["matches"])

    def test_multiple_aliases_and_drift_are_distinguished(self):
        report = self.witness({"6443": [self.exact], "6443/tcp": [self.exact]},
                              {"6443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18444"}]})
        self.assertFalse(report["configured"]["matches"])
        self.assertEqual(report["configured"]["binding_count"], 2)
        self.assertFalse(report["effective"]["matches"])
        binding = report["effective"]["aliases"][1]["bindings"][0]
        self.assertEqual(binding["host_class"], "ipv4_unspecified")
        self.assertFalse(binding["host_matches"])
        self.assertFalse(binding["port_matches"])

    def test_only_closed_vocabulary_is_published(self):
        private_host = "private-host-token.example"
        private_port = "private-port-token"
        private_key = "private-port-map-key"
        report = self.witness({"6443/tcp": [{"HostIp": private_host, "HostPort": private_port}],
                               private_key: [self.exact]})
        serialized = json.dumps(report)
        for private_value in (private_host, private_port, private_key, self.exact["HostIp"], self.exact["HostPort"]):
            self.assertNotIn(private_value, serialized)
        self.assertEqual(report["configured"]["other_port_key_count"], 1)
        self.assertEqual(report["configured"]["aliases"][1]["bindings"][0]["host_class"], "invalid")
        self.assertEqual(report["effective"]["binding_count"], 0)
        self.assertFalse(report["effective"]["matches"])

    def test_address_classes_and_missing_values(self):
        for host, expected in ((None, "missing"), ("", "empty"), ("127.0.0.1", "ipv4_loopback"),
                               ("::", "ipv6_unspecified"), ("::1", "ipv6_loopback"),
                               ("2001:db8::1", "ipv6_specified")):
            with self.subTest(expected=expected):
                report = self.witness({"6443/tcp": [{"HostIp": host}]})
                binding = report["configured"]["aliases"][1]["bindings"][0]
                self.assertEqual(binding["host_class"], expected)
                self.assertTrue(binding["port_empty"])
                self.assertFalse(binding["port_matches"])

    def test_missing_inspect_fields(self):
        report = smoke.Smoke.native_api_bindings({}, {"NativePort": 18443})
        for source in ("configured", "effective"):
            self.assertFalse(report[source]["field_present"])
            self.assertFalse(report[source]["matches"])
            self.assertEqual(report[source]["binding_count"], 0)

    def test_ingress_failure_keeps_raw_diagnostics_private(self):
        sentinel = "independent-private-diagnostic-sentinel"
        reason = 'File "<stdin>", line 173, in witness\nAssertionError: ' + sentinel
        with tempfile.TemporaryDirectory() as directory:
            fixture = smoke.Smoke.__new__(smoke.Smoke)
            fixture.state = Path(directory)
            fixture.result = {}
            fixture.diagnostics = io.StringIO()
            fixture.lb = {"LoadBalancerArn": sentinel}
            fixture.tg = sentinel
            fixture.pod_ip = "192.0.2.75"
            fixture.api = lambda *_args, **_kwargs: {"LoadBalancers": [
                {"LoadBalancerArn": sentinel, "State": {"Code": "active_impaired", "Reason": reason}}]}
            fixture.health = lambda: [{"Target": {"Id": fixture.pod_ip, "Port": 8080},
                "TargetHealth": {"State": "unused", "Reason": "Target.NotInUse", "Description": sentinel}}]
            fixture.capture_ingress_failure()
            report = fixture.result["native_ingress_failure"]
            self.assertNotIn(sentinel, json.dumps(report))
            self.assertNotIn(fixture.pod_ip, json.dumps(report))
            self.assertIn("native_assertion_failed", report["native_error_classes"])
            self.assertEqual(report["native_trace_lines"], [173])
            self.assertTrue(report["targets"][0]["expected_pod_and_port"])
            self.assertIn(sentinel, (fixture.state / "failed-ingress.json").read_text())


if __name__ == "__main__":
    unittest.main()
