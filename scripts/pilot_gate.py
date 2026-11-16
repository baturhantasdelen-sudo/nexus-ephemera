"""Check a design-partner evidence bundle. This is NOT a security certification.

Evidence files must be secret-free and independently reviewed. Hash validation
detects changed/missing attachments; it cannot prove that an assertion is true.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

GATES = ('same_commit_ci', 'release_provenance', 'clean_install', 'agent_secret_isolation', 'agent_egress_isolation', 'policy_denials', 'lost_ack', 'same_key_concurrency', 'restart_recovery', 'redis_failover_topology', 'audit_before_dispatch', 'audit_after_dispatch', 'external_audit_anchor', 'audit_rotation', 'credential_rotation_revocation', 'graceful_shutdown', 'load_capacity', 'backup_restore', 'upgrade_rollback', 'operator_reconciliation', 'independent_review', 'customer_acceptance')
MAX_MANIFEST=65536
MAX_EVIDENCE=16*1024*1024

def read_bounded(path: Path, limit: int) -> bytes:
    if path.is_symlink() or getattr(path,"is_junction",lambda:False)() or not path.is_file():
        raise ValueError("invalid evidence file")
    with path.open("rb") as f:
        data=f.read(limit+1)
    if len(data)>limit:
        raise ValueError("oversize evidence")
    return data

def unique(pairs):
    result={}
    for k,v in pairs:
        if k in result:
            raise ValueError("duplicate field")
        result[k]=v
    return result

def evaluate(manifest: Path, expected_commit: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{40}",expected_commit):
        raise ValueError("full source commit required")
    data=json.loads(read_bounded(manifest,MAX_MANIFEST),object_pairs_hook=unique)
    if not isinstance(data,dict) or set(data)!={"schema","commit","gates"} or data["schema"]!="nexus-pilot-v1" or data["commit"]!=expected_commit:
        raise ValueError("invalid pilot identity")
    gates=data["gates"]
    if not isinstance(gates,dict) or set(gates)!=set(GATES):
        raise ValueError("incomplete gate set")
    root=manifest.absolute().parent
    for part in (root,*root.parents):
        if part.is_symlink() or getattr(part,"is_junction",lambda:False)():
            raise ValueError("indirect evidence root")
    blocked=[]
    for name in GATES:
        g=gates[name]
        if not isinstance(g,dict) or set(g)!={"status","evidence","sha256"}:
            raise ValueError("invalid gate fields")
        if g["status"] in ("pending","failed"):
            blocked.append(name)
            if g["evidence"] is None and g["sha256"] is None:
                continue
        elif g["status"]!="reviewed_pass":
            raise ValueError("invalid gate decision")
        if not isinstance(g["evidence"],str) or not isinstance(g["sha256"],str):
            raise ValueError("invalid gate decision")
        # Single safe attachment name: no nested paths, URLs, tokens or IDs.
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}\.(?:json|txt|log|md|pdf)",g["evidence"]) or not re.fullmatch(r"[0-9a-f]{64}",g["sha256"]):
            raise ValueError("invalid evidence reference")
        raw=read_bounded(root/g["evidence"],MAX_EVIDENCE)
        if hashlib.sha256(raw).hexdigest()!=g["sha256"]:
            raise ValueError("evidence integrity mismatch")
    return blocked

def main() -> None:
    p=argparse.ArgumentParser(__doc__)
    p.add_argument("manifest",type=Path)
    p.add_argument("--expected-commit",required=True)
    a=p.parse_args()
    try:
        blocked=evaluate(a.manifest,a.expected_commit)
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        p.exit(2,"evidence bundle rejected; no approval issued\n")
    print(json.dumps({"evidence_complete":not blocked,"blocked_gates":blocked,"certification":False}))
    sys.exit(1 if blocked else 0)

if __name__=="__main__":
    main()
