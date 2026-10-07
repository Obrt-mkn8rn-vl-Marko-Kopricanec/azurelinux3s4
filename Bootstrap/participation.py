import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

try:
    with tempfile.TemporaryDirectory(prefix="verifier.", dir=sys.argv[1]) as directory:
        root = Path(directory)
        for name in ("repos", "sample/repodata", "control-cache", "check-cache", "persist", "gnupg"):
            (root / name).mkdir(parents=True, mode=0o700)
        # The repair service hides home directories. Use a private keyring with
        # no agent/keyserver startup, independent of the administrator's home.
        (root / "gnupg/gpg.conf").write_text(
            "no-autostart\ndisable-dirmngr\nno-auto-key-retrieve\nno-auto-key-import\n")
        environment = dict(os.environ, GNUPGHOME=str(root / "gnupg"), LC_ALL="C")
        metadata = b'<?xml version="1.0"?><metadata xmlns="http://linux.duke.edu/metadata/common" packages="0"/>'
        primary = gzip.compress(metadata, mtime=0)
        (root / "sample/repodata/primary.xml.gz").write_bytes(primary)
        repomd = ('<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo">'
                  '<revision>0</revision><data type="primary"><checksum type="sha256">'
                  + hashlib.sha256(primary).hexdigest() + '</checksum><open-checksum type="sha256">'
                  + hashlib.sha256(metadata).hexdigest() + '</open-checksum>'
                  '<location href="repodata/primary.xml.gz"/><timestamp>0</timestamp><size>'
                  + str(len(primary)) + '</size><open-size>' + str(len(metadata))
                  + '</open-size></data></repomd>')
        (root / "sample/repodata/repomd.xml").write_text(repomd)
        (root / "sample/repodata/repomd.xml.asc").write_text("intentionally invalid signature\n")
        (root / "repos/probe.repo").write_text(
            "[azurelinux3s4-verifier-probe]\nname=Offline verifier probe\nbaseurl="
            + (root / "sample").as_uri()
            + "\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nsslverify=1\nskip_if_unavailable=0\n")
        for name in ("control", "check"):
            (root / (name + ".conf")).write_text(
                "[main]\nplugins=1\ngpgcheck=1\nrepodir=" + str(root / "repos")
                + "\ncachedir=" + str(root / (name + "-cache"))
                + "\npersistdir=" + str(root / "persist")
                + "\npluginpath=" + str(Path(sys.argv[2]).parent)
                + "\npluginconfpath=" + str(Path(sys.argv[3]).parent) + "\n")
        def run(name, *options):
            return subprocess.run(["tdnf", "-v", "-c", str(root / (name + ".conf")),
                                   "--releasever=3.0", "--refresh", "-y", *options, "makecache"],
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=25, env=environment)
        control = run("control", "--noplugins")
        check = run("check", "--disableplugin=*", "--enableplugin=tdnfrepogpgcheck")
        output = check.stdout + check.stderr
        if (control.returncode != 0 or check.returncode == 0
                or "Loaded plugin: tdnfrepogpgcheck" not in output
                or "gpg verify failed: No data" not in output
                or "Error: TDNFVerifySignature " not in output):
            print("azurelinux3s4: native metadata verifier did not prove fail-closed participation.",
                  file=sys.stderr)
            sys.exit(1)
except (ValueError, OSError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: bounded verifier probe failed: " + str(error), file=sys.stderr)
    sys.exit(1)
