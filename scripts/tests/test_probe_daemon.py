from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import probe_daemon as m


class ProbeTests(unittest.TestCase):
    def test_readiness_rejects_reference_capacity_and_partial_health(self):
        health = dict(kind="health", status="healthy", ipc_listening=True,
                      policy_intact=True, hmac_ready=True, idempotency="ready",
                      worker_occupied=0, worker_capacity=32)
        self.assertTrue(m.readiness(health))
        for field, value in (("idempotency", "local"), ("worker_occupied", 32),
                             ("worker_occupied", False), ("policy_intact", False),
                             ("hmac_ready", False), ("status", "degraded")):
            self.assertFalse(m.readiness({**health, field: value}))

    def test_metrics_never_pass_through_unregistered_fields_or_booleans(self):
        values = {k: 0 for k in m.METRICS}
        self.assertEqual(len(m.numeric_metrics(values).splitlines()), 5)
        with self.assertRaises(ValueError):
            m.numeric_metrics({**values, "api_key": "secret"})
        with self.assertRaises(ValueError):
            m.numeric_metrics({**values, m.METRICS[0]: True})
