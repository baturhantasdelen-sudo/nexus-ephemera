import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pilot_gate as m

class PilotGateTests(unittest.TestCase):
    def bundle(self,root):
        proof=root/"review.txt"; proof.write_bytes(b"public fixture only")
        digest=hashlib.sha256(proof.read_bytes()).hexdigest()
        data={"schema":"nexus-pilot-v1","commit":"a"*40,"gates":{name:{"status":"reviewed_pass","evidence":"review.txt","sha256":digest} for name in m.GATES}}
        path=root/"pilot.json"; path.write_text(json.dumps(data))
        return path,data

    def test_pending_blocks_and_changed_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); p,data=self.bundle(r)
            self.assertEqual(m.evaluate(p,"a"*40),[])
            data["gates"]["customer_acceptance"]["status"]="failed"
            p.write_text(json.dumps(data))
            self.assertEqual(m.evaluate(p,"a"*40),["customer_acceptance"])
            data["gates"]["customer_acceptance"]={"status":"pending","evidence":None,"sha256":None}
            p.write_text(json.dumps(data))
            self.assertEqual(m.evaluate(p,"a"*40),["customer_acceptance"])
            (r/"review.txt").write_bytes(b"changed")
            with self.assertRaises(ValueError): m.evaluate(p,"a"*40)

    def test_wrong_commit_omitted_gate_extra_secret_and_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); p,data=self.bundle(r)
            with self.assertRaises(ValueError): m.evaluate(p,"b"*40)
            for mutation in ("omit","secret","traversal"):
                bad=copy.deepcopy(data)
                if mutation=="omit": del bad["gates"]["customer_acceptance"]
                elif mutation=="secret": bad["api_key"]="must never be accepted"
                else: bad["gates"]["customer_acceptance"]["evidence"]="../review.txt"
                p.write_text(json.dumps(bad))
                with self.assertRaises(ValueError): m.evaluate(p,"a"*40)
