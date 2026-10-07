import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("azurelinux3s4_pack", ROOT / "Bootstrap/pack.py")
PACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACK)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="azurelinux3s4-bundle-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "checkout"
        self.root.mkdir()
        for name in (*PACK.INPUTS, "Bootstrap/pack.py", "Bootstrap/test.py"):
            target = self.root / name
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.script = self.root / PACK.TARGET
        self.script.write_bytes((ROOT / PACK.TARGET).read_bytes())
        self.script.chmod(0o755)

    def command(self, *arguments, expected=0, **options):
        result = subprocess.run([sys.executable, "-B", str(self.root / "Bootstrap/pack.py"), *arguments],
                                capture_output=True, text=True, timeout=10, **options)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_current_assembly_and_executable_mode_match_delivery(self):
        self.assertEqual(PACK.assemble(), (ROOT / PACK.TARGET).read_bytes())
        self.assertEqual(stat.S_IMODE((ROOT / PACK.TARGET).stat().st_mode), 0o755)
        self.command("--check")

    def test_rebuild_is_deterministic_across_cwd_environment_and_umask(self):
        expected = self.script.read_bytes()
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        self.script.unlink()
        self.command(cwd=self.root.parent, env=dict(os.environ, PYTHONHASHSEED="9", TZ="UTC", LC_ALL="C"))
        self.assertEqual(self.script.read_bytes(), expected)
        self.assertEqual(stat.S_IMODE(self.script.stat().st_mode), 0o755)
        self.command(cwd="/", env=dict(os.environ, PYTHONHASHSEED="17", TZ="Asia/Tokyo"))
        self.assertEqual(self.script.read_bytes(), expected)
        self.assertFalse(list(self.root.glob(".azurelinux3s4-*.tmp")))

    def test_single_file_help_works_without_checkout_or_payload_files(self):
        delivered = self.root.parent / "delivery" / PACK.TARGET
        delivered.parent.mkdir()
        shutil.copyfile(self.script, delivered)
        delivered.chmod(0o755)
        shutil.rmtree(self.root)
        result = subprocess.run([str(delivered), "--help"], cwd="/", capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sudo ./azurelinux3s4.sh", result.stdout)
        self.assertIn("incomplete", result.stdout)
        self.assertEqual(list(delivered.parent.iterdir()), [delivered])

    def test_checker_refuses_source_drift_without_replacing_installer(self):
        original = self.script.read_bytes()
        source = self.root / "Recovery/worker.sh"
        source.write_bytes(source.read_bytes() + b"# changed source\n")
        self.command("--check", expected=1)
        self.assertEqual(self.script.read_bytes(), original)
        self.command()
        self.assertNotEqual(self.script.read_bytes(), original)
        self.command("--check")

    def test_checker_refuses_missing_or_nonexecutable_installer(self):
        self.script.chmod(0o644)
        self.command("--check", expected=1)
        self.script.unlink()
        self.command("--check", expected=1)
        self.command()
        self.command("--check")

    def test_missing_payload_keeps_existing_delivery_unchanged(self):
        original = self.script.read_bytes()
        (self.root / "Updates/capacity.py").unlink()
        self.command(expected=1)
        self.assertEqual(self.script.read_bytes(), original)

    def test_syntax_error_in_python_payload_refuses_publication(self):
        original = self.script.read_bytes()
        (self.root / "Packages/admission.py").write_text("def broken(\n")
        self.command(expected=1)
        self.assertEqual(self.script.read_bytes(), original)

    def test_unsafe_encoding_or_missing_newline_refuses_publication(self):
        original = self.script.read_bytes()
        path = self.root / "Updates/effects.py"
        for data in (b"\xff\n", b"pass\r\n", b"pass\0\n", b"pass"):
            with self.subTest(data=data):
                path.write_bytes(data)
                self.command(expected=1)
                self.assertEqual(self.script.read_bytes(), original)

    def test_payload_cannot_close_heredoc_or_request_other_inputs(self):
        original = self.script.read_bytes()
        path = self.root / "Packages/admission.py"
        for data in (b"PY\n", b"# @s4-include .env\n"):
            with self.subTest(data=data):
                path.write_bytes(data)
                self.command(expected=1)
                self.assertEqual(self.script.read_bytes(), original)

    def test_unknown_duplicate_or_missing_include_refuses_publication(self):
        original = self.script.read_bytes()
        path = self.root / "Updates/diagnostics.sh.in"
        source = path.read_bytes()
        marker = b"# @s4-include Updates/effects.py\n"
        for replacement in (b"# @s4-include .env\n", marker + marker, b"# missing payload\n",
                            b" # @s4-include Updates/effects.py\n"):
            with self.subTest(replacement=replacement):
                path.write_bytes(source.replace(marker, replacement))
                self.command(expected=1)
                self.assertEqual(self.script.read_bytes(), original)

    def test_symlink_and_wrong_kind_inputs_are_not_opened_or_changed(self):
        original = self.script.read_bytes()
        path = self.root / "Updates/effects.py"
        external = self.root.parent / "operator.py"
        external.write_bytes(path.read_bytes())
        digest = hashlib.sha256(external.read_bytes()).hexdigest()
        path.unlink()
        for kind in ("symlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    path.symlink_to(external)
                elif kind == "fifo":
                    os.mkfifo(path)
                else:
                    path.mkdir()
                identity = path.lstat()
                self.command(expected=1)
                self.assertEqual(path.lstat(), identity)
                self.assertEqual(hashlib.sha256(external.read_bytes()).hexdigest(), digest)
                self.assertEqual(self.script.read_bytes(), original)
                if kind == "directory":
                    path.rmdir()
                else:
                    path.unlink()

    def test_symlink_and_wrong_kind_delivery_targets_are_preserved(self):
        self.script.unlink()
        external = self.root.parent / "operator.sh"
        external.write_bytes(b"operator content\n")
        for kind in ("symlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.script.symlink_to(external)
                elif kind == "fifo":
                    os.mkfifo(self.script)
                else:
                    self.script.mkdir()
                identity = self.script.lstat()
                self.command(expected=1)
                self.command("--check", expected=1)
                self.assertEqual(self.script.lstat(), identity)
                self.assertEqual(external.read_bytes(), b"operator content\n")
                if kind == "directory":
                    self.script.rmdir()
                else:
                    self.script.unlink()

    def test_damaged_installer_is_rebuilt_from_sources(self):
        expected = self.script.read_bytes()
        self.script.write_bytes(b"damaged installer\n")
        self.command("--check", expected=1)
        self.command()
        self.assertEqual(self.script.read_bytes(), expected)

    def test_test_runner_refuses_stale_delivery_before_loading_tests(self):
        source = self.root / "Recovery/worker.sh"
        source.write_bytes(source.read_bytes() + b"# changed source\n")
        result = subprocess.run([sys.executable, "-B", str(self.root / "Bootstrap/test.py"), "test_bootstrap"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("differs from its sources", result.stderr)
        self.assertNotIn("ModuleNotFoundError", result.stderr)
        self.assertNotIn("Ran ", result.stderr)


if __name__ == "__main__":
    unittest.main()
