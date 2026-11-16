"""Exercise the installed archive, not Cargo's source-tree executable."""
from pathlib import Path
import argparse
import hashlib
import subprocess
import tempfile
from install_prebuilt import install

def main() -> None:
    p=argparse.ArgumentParser(__doc__)
    p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--target",required=True)
    a=p.parse_args()
    # macOS SUN_LEN requires a short socket path even when TMPDIR is long.
    with tempfile.TemporaryDirectory(prefix="nx-", dir="/tmp" if "apple" in a.target else None) as tmp:
        # Canonicalize only the temporary directory we just created. macOS
        # exposes /tmp and /var through aliases; user-supplied installer paths
        # must still pass the strict no-indirection policy unchanged.
        root=Path(tmp).resolve(strict=True)
        binary=root/"bin"
        install(a.archive,hashlib.sha256(a.archive.read_bytes()).hexdigest(),a.target,binary)
        daemon=binary/("nexus-daemon.exe" if "windows" in a.target else "nexus-daemon")
        package=root/"p"
        listen=r"\\.\pipe\nx-release-smoke" if "windows" in a.target else str(package/"b.sock")
        subprocess.run([str(daemon),"--listen",listen,"--package",str(package),"--init-package"],check=True,timeout=30)
        subprocess.run([str(daemon),"--package",str(package),"--check"],check=True,timeout=30)
        # Negative gate: mutation of a sealed policy must never pass --check.
        policy=package/"pilot_support_agent.json"
        if not policy.exists():
            policy=next(package.glob("*.json"))
        policy.write_bytes(b"{}")
        denied=subprocess.run([str(daemon),"--package",str(package),"--check"],capture_output=True,timeout=30)
        if denied.returncode==0:
            raise RuntimeError("tampered package was accepted")
    print("installed archive: native check and tamper rejection passed")

if __name__=="__main__":
    main()
