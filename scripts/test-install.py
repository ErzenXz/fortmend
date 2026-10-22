#!/usr/bin/env python3
"""Exercise the production shell installers with isolated command/download fixtures.

No root, network, APT, systemd, host installation directories or login required.
The test copy maps privileged absolute paths into a temporary root and substitutes
only OS commands and upstream Codex archive hashes. There are no test bypasses in
shipped installers. Run: python3 scripts/test-install.py
"""
import hashlib
import io
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fortmend-installer-test-")
        self.root = Path(self.tmp.name).resolve()
        self.bin = self.root / "commands"
        self.assets = self.root / "assets"
        self.bin.mkdir()
        self.assets.mkdir()
        for d in ["etc/systemd/system", "usr/local/bin", "var/lib", "run/systemd/system", "tmp", "dev"]:
            (self.root / d).mkdir(parents=True, exist_ok=True)
        (self.root / "etc/os-release").write_text("ID=debian\n")
        (self.root / "dev/tty").touch()
        self.env = dict(os.environ, FIXTURE_ROOT=str(self.root), FIXTURE_ASSETS=str(self.assets), FIXTURE_ARCH="x86_64", FIXTURE_AUTH="ready", FIXTURE_LOGIN="success")
        self.env["PATH"] = str(self.bin) + os.pathsep + os.environ["PATH"]
        self.command("uname", '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo "$FIXTURE_ARCH";; esac\n')
        self.command("id", "#!/bin/sh\necho 0\n")
        self.command("stat", '#!/bin/sh\ncase "$2" in %u) echo 0;; %a) if [ -d "${4:-$3}" ]; then echo 755; else echo 640; fi;; esac\n')
        self.command("systemctl", '''#!/bin/sh
printf '%s\n' "$*" >> "$FIXTURE_ROOT/systemctl.log"
if [ "$1" = is-active ]; then
  case "$*" in *fortmend-protect.service) test -f "$FIXTURE_ROOT/active";; *ssh.service) exit 0;; *) exit 1;; esac
elif [ "$1" = enable ]; then
  touch "$FIXTURE_ROOT/active"
elif [ "$1" = stop ]; then
  rm -f "$FIXTURE_ROOT/active"
fi
''')
        self.command("apt-get", '#!/bin/sh\necho "$*" >> "$FIXTURE_ROOT/apt.log"\n')
        self.command("unattended-upgrade", "#!/bin/sh\nexit 0\n")
        self.command("dpkg", "#!/bin/sh\nexit 0\n")
        self.command("journalctl", "#!/bin/sh\nexit 0\n")
        self.command("curl", '''#!/bin/sh
url= destination=
while [ "$#" -gt 0 ]; do
 case "$1" in
   -o) destination=$2; shift 2;;
   --proto|--retry|--connect-timeout|--max-time) shift 2;;
   https://*) url=$1; shift;;
   *) shift;;
 esac
done
name=${url##*/}
printf '%s\n' "$url" >> "$FIXTURE_ROOT/downloads.log"
cp "$FIXTURE_ASSETS/$name" "$destination"
''')
        # Preserve the install utility's behavior, replacing owner/group changes
        # only because these fixtures deliberately run without root.
        self.command("install", '''#!/usr/bin/env python3
import pathlib,sys,shutil,os
args=sys.argv[1:]; mode=0o755; dirs=False; paths=[]
while args:
 a=args.pop(0)
 if a in ('-o','-g'): args.pop(0)
 elif a=='-m': mode=int(args.pop(0),8)
 elif a=='-d': dirs=True
 elif a=='--': pass
 else: paths.append(a)
if dirs:
 for p in paths: pathlib.Path(p).mkdir(parents=True,exist_ok=True); os.chmod(p,mode)
else:
 shutil.copyfile(paths[0],paths[1]); os.chmod(paths[1],mode)
''')
        cli = '''#!/bin/sh
if [ "$1" = protect ]; then
 shift
 while [ "$#" -gt 0 ]; do
  if [ "$1" = --config ]; then jq -e '.schemaVersion == "fortmend.linux/v1"' "$2" >/dev/null || exit 1; shift; fi
  shift
 done
 exit 0
fi
if [ "$1 $2" = 'ai status' ]; then
 if [ "$FIXTURE_AUTH" = ready ] || [ -f "$FIXTURE_ROOT/logged-in" ]; then echo '{"account":{"type":"chatgpt"}}'; else echo '{"account":null}'; fi
elif [ "$1 $2" = 'ai login' ]; then
 echo login >> "$FIXTURE_ROOT/login.log"
 [ "$FIXTURE_LOGIN" != failed ] || exit 1
 [ "$FIXTURE_LOGIN" != unconfirmed ] || exit 0
 touch "$FIXTURE_ROOT/logged-in"
fi
'''
        self.write(self.assets / "fortmend-linux-amd64", cli)
        self.write(self.assets / "fortmend-linux-arm64", cli)
        for arch in ["x86_64", "aarch64"]:
            target = f"{arch}-unknown-linux-musl"
            with tarfile.open(self.assets / f"codex-{target}.tar.gz", "w:gz") as archive:
                content = b"#!/bin/sh\nexit 0\n"
                entry = tarfile.TarInfo(f"codex-{target}")
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        self.write(self.assets / "install.sh", self.render((REPO / "packaging/linux/install.sh").read_text()))
        self.write(self.assets / "fortmend-protect.service", (REPO / "packaging/linux/fortmend-protect.service").read_text())
        self.write(self.assets / "linux.example.json", self.render((REPO / "packaging/linux/linux.example.json").read_text()))
        self.manifest()
        self.script = self.root / "bootstrap.sh"
        text = self.render((REPO / "site/install.sh").read_text())
        for original, arch in [("beb339e8ecd9ba057a6bb2dc81ad8ca474812edfbf0fc5056ca818797648dde4", "x86_64"), ("a7261e65f4a96d8f4ca65a069c6cf2dc2c33defc341e48078acefda9461fffe4", "aarch64")]:
            text = text.replace(original, self.hash(self.assets / f"codex-{arch}-unknown-linux-musl.tar.gz"))
        self.write(self.script, text)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, path, text):
        path.write_text(text)
        path.chmod(0o755)

    def command(self, name, content):
        self.write(self.bin / name, content)

    def render(self, text):
        # A single pass prevents an inserted /tmp fixture prefix from being
        # rewritten again on Linux (macOS temp paths usually start /private).
        text = re.sub(r"/usr/local/|/var/lib/|/etc/|/run/|/tmp/|/dev/tty",
                      lambda match: str(self.root) + match.group(0), text)
        # Insert the fixture command directory only after path rewriting.
        return text.replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", 'PATH="' + str(self.bin) + ':$PATH"')

    def hash(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def manifest(self):
        names = ["fortmend-linux-amd64", "fortmend-linux-arm64", "install.sh", "fortmend-protect.service", "linux.example.json"]
        (self.assets / "SHA256SUMS").write_text("".join(f"{self.hash(self.assets / n)}  {n}\n" for n in names))

    def run_install(self, *args, success=True, pipeline=False):
        result = subprocess.run(["sh", "-s", "--", *args] if pipeline else ["sh", str(self.script), *args], input=self.script.read_text() if pipeline else None, env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def installed(self):
        return self.root / "usr/local/bin/fortmend"

    def test_complete_install_from_pipeline(self):
        self.env["FIXTURE_AUTH"] = "none"
        self.run_install(pipeline=True)
        self.assertTrue(self.installed().is_file())
        self.assertTrue((self.root / "active").exists())
        self.assertEqual((self.root / "login.log").read_text().strip(), "login")
        policy = json.loads((self.root / "etc/fortmend/linux.json").read_text())
        self.assertEqual(policy["healthServices"], ["ssh.service"])
        self.assertFalse(policy["automaticReboot"])

    def test_no_start_does_not_login_or_enable(self):
        self.run_install("--no-start")
        self.assertTrue(self.installed().exists())
        self.assertFalse((self.root / "active").exists())
        self.assertFalse((self.root / "login.log").exists())

    def test_custom_policy_preserved_on_upgrade(self):
        self.run_install("--no-start")
        path = self.root / "etc/fortmend/linux.json"
        policy = json.loads(path.read_text()); policy["webRoots"] = ["/srv/my-app"]; policy["ai"]["enabled"] = False
        path.write_text(json.dumps(policy))
        original = path.read_bytes()
        self.run_install()
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse((self.root / "login.log").exists())

    def test_bad_release_checksum_prevents_install_and_apt(self):
        (self.assets / "fortmend-linux-amd64").write_text("modified download")
        self.assertIn("checksum mismatch", self.run_install(success=False))
        self.assertFalse(self.installed().exists())
        self.assertFalse((self.root / "apt.log").exists())

    def test_duplicate_checksum_rejected(self):
        path = self.assets / "SHA256SUMS"
        path.write_text(path.read_text() + f"{'0' * 64}  fortmend-linux-amd64\n")
        self.assertIn("duplicate checksum", self.run_install(success=False))
        self.assertFalse(self.installed().exists())

    def test_bad_codex_checksum_prevents_service_start(self):
        (self.assets / "codex-x86_64-unknown-linux-musl.tar.gz").write_bytes(b"bad archive")
        self.assertIn("Codex checksum mismatch", self.run_install(success=False))
        self.assertFalse(self.installed().exists())
        self.assertFalse((self.root / "active").exists())

    def test_login_failure_does_not_start(self):
        self.env.update(FIXTURE_AUTH="none", FIXTURE_LOGIN="failed")
        self.assertIn("sign-in did not complete", self.run_install(success=False))
        self.assertFalse((self.root / "active").exists())

    def test_unconfirmed_login_does_not_start(self):
        self.env.update(FIXTURE_AUTH="none", FIXTURE_LOGIN="unconfirmed")
        self.assertIn("authentication was not confirmed", self.run_install(success=False))
        self.assertFalse((self.root / "active").exists())

    def test_missing_terminal_leaves_install_stopped(self):
        self.env["FIXTURE_AUTH"] = "none"
        (self.root / "dev/tty").unlink()
        self.assertIn("no terminal", self.run_install(success=False))
        self.assertFalse((self.root / "active").exists())
        self.assertFalse((self.root / "login.log").exists())

    def test_symlinked_privileged_directory_refused(self):
        directory = self.root / "usr/local/lib"
        directory.mkdir()
        (directory / "fortmend").symlink_to(self.root / "tmp", target_is_directory=True)
        self.assertIn("symlinked installation path", self.run_install(success=False))
        self.assertFalse((self.root / "downloads.log").exists())

    def test_unknown_architecture_fails_before_network(self):
        self.env["FIXTURE_ARCH"] = "riscv64"
        self.assertIn("supported architectures", self.run_install(success=False))
        self.assertFalse((self.root / "downloads.log").exists())

    def test_legacy_install_refused_without_modification(self):
        (self.root / "var/lib/aegis").mkdir()
        self.assertIn("legacy Aegis", self.run_install(success=False))
        self.assertFalse((self.root / "downloads.log").exists())

    def test_legacy_state_requires_explicit_flag_and_existing_policy(self):
        self.run_install("--no-start")
        legacy = self.root / "var/lib/aegis/protection"
        legacy.mkdir(parents=True)
        evidence = legacy / "receipt.json"
        evidence.write_text('{"payloadPath":"/var/lib/aegis/protection/quarantine/example/payload"}')
        policy_path = self.root / "etc/fortmend/linux.json"
        policy = json.loads(policy_path.read_text())
        policy["stateDir"] = str(legacy)
        policy_path.write_text(json.dumps(policy))
        original = evidence.read_bytes()
        self.run_install("--no-start", success=False)
        self.run_install("--no-start", "--retain-legacy-state")
        self.assertEqual(evidence.read_bytes(), original)
        self.assertEqual(json.loads(policy_path.read_text())["stateDir"], str(legacy))

    def test_legacy_state_flag_without_existing_policy_refused(self):
        (self.root / "var/lib/aegis").mkdir()
        self.run_install("--no-start", "--retain-legacy-state", success=False)
        self.assertFalse((self.root / "downloads.log").exists())

    def test_arm64_selects_matching_assets(self):
        self.env["FIXTURE_ARCH"] = "aarch64"
        self.run_install("--no-start")
        downloads = (self.root / "downloads.log").read_text()
        self.assertIn("fortmend-linux-arm64", downloads)
        self.assertIn("codex-aarch64-unknown-linux-musl.tar.gz", downloads)


if __name__ == "__main__":
    unittest.main(verbosity=2)
