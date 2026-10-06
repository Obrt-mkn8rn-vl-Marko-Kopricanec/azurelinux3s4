import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "azurelinux3s4.sh"


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        original_umask = os.umask(0o077)
        self.addCleanup(os.umask, original_umask)
        # Use a private, non-writable ancestry rather than a shared /tmp tree.
        cache = Path.home() / ".cache"
        cache.mkdir(mode=0o700, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="azurelinux3s4-test-", dir=cache)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("state", "state/components", "state/repos", "run", "runner", "units", "systemd"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "rpm-key").write_text("fixture key; no real transactions are performed\n")
        bundle = next(path for path in (Path('/etc/ssl/certs/ca-certificates.crt'),
            Path('/etc/pki/tls/certs/ca-bundle.crt')) if path.exists())
        (self.root / 'ca-bundle').write_bytes(bundle.read_bytes())
        (self.root / 'plugin-library').write_text('fixture; no dynamic library is executed\n')
        (self.root / 'plugin-config').write_text('[main]\nenabled=1\n')
        self.header = f"""
source {shlex.quote(str(SCRIPT))}
S4_STATE={shlex.quote(str(self.root / 'state'))}
S4_RUN={shlex.quote(str(self.root / 'run'))}
S4_INSTALL_DIR={shlex.quote(str(self.root / 'runner'))}
S4_SYSTEMD_DIR={shlex.quote(str(self.root / 'units'))}
S4_OS_RELEASE={shlex.quote(str(self.root / 'os-release'))}
S4_SYSTEMD_RUNTIME={shlex.quote(str(self.root / 'systemd'))}
S4_GPG_KEY={shlex.quote(str(self.root / 'rpm-key'))}
S4_CA_BUNDLE={shlex.quote(str(self.root / 'ca-bundle'))}
S4_PLUGIN_LIBRARY={shlex.quote(str(self.root / 'plugin-library'))}
S4_PLUGIN_CONFIG={shlex.quote(str(self.root / 'plugin-config'))}
S4_ARCH=x86_64
S4_NOW=1000000
update-ca-trust() {{ return 0; }}
systemctl() {{
    printf '%s\\n' "$*" >> {shlex.quote(str(self.root / 'events'))}
    case $1 in
        enable) touch "$S4_RUN/timer-enabled" ;;
        disable) rm -f "$S4_RUN/timer-enabled" ;;
        is-enabled|is-active) [[ -f $S4_RUN/timer-enabled ]] ;;
        *) return 0 ;;
    esac
}}
"""

    def shell(self, body, expected=0):
        result = subprocess.run(
            ["bash", "-c", self.header + "\n" + body],
            text=True,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def state(self):
        return dict(line.split("=", 1) for line in (self.root / "state/components/bootstrap").read_text().splitlines())

    def test_nonroot_main_refuses_before_mutating(self):
        if os.geteuid() == 0:
            self.skipTest("Requires an unprivileged test process")
        result = subprocess.run([str(SCRIPT)], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 77)
        self.assertIn("administrator privileges", result.stderr)

    def test_help_is_available_without_privilege(self):
        result = subprocess.run([str(SCRIPT), "--help"], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn("hardening is incomplete", result.stdout)

    def test_unknown_action_is_rejected(self):
        result = subprocess.run([str(SCRIPT), "--unknown"], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 64)

    def test_wrong_distribution_and_version_are_rejected(self):
        for distro, version in (("debian", "13"), ("azurelinux", "4.0"), ("mariner", "2.0")):
            with self.subTest(distro=distro, version=version):
                (self.root / "os-release").write_text(f'ID="{distro}"\nVERSION_ID="{version}"\n')
                self.shell("s4_platform", expected=78)

    def test_supported_azure_linux_platform(self):
        (self.root / "os-release").write_text('ID="azurelinux"\nVERSION_ID="3.0"\n')
        self.shell("s4_platform; [[ $S4_ARCH == x86_64 || $S4_ARCH == aarch64 ]]")

    def test_os_release_is_not_executed(self):
        (self.root / "os-release").write_text(f'ID="$(touch {self.root}/executed)"\nVERSION_ID="3.0"\n')
        self.shell("s4_platform", expected=78)
        self.assertFalse((self.root / "executed").exists())

    def test_container_and_unsupported_architecture_refused(self):
        (self.root / "os-release").write_text("ID=azurelinux\nVERSION_ID=3.0\n")
        self.shell("S4_SYSTEMD_RUNTIME=$S4_RUN/not-systemd; s4_platform", expected=78)
        self.shell("uname() { printf 'armv7l\\n'; }; s4_platform", expected=78)

    def test_atomic_write_is_private_and_idempotent(self):
        self.shell("printf 'content\\n' | s4_atomic_write \"$S4_STATE/record\" 0600")
        path = self.root / "state/record"
        original = path.stat().st_mtime_ns
        self.shell("printf 'content\\n' | s4_atomic_write \"$S4_STATE/record\" 0600")
        self.assertEqual(path.stat().st_mtime_ns, original)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_symlink_file_and_directory_are_rejected(self):
        target = self.root / "target"
        target.write_text("must remain unchanged")
        (self.root / "state/link").symlink_to(target)
        self.shell("printf changed | s4_atomic_write \"$S4_STATE/link\" 0600", expected=78)
        self.assertEqual(target.read_text(), "must remain unchanged")
        (self.root / "state/linkdir").symlink_to(self.root / "run", target_is_directory=True)
        self.shell("printf changed | s4_atomic_write \"$S4_STATE/linkdir/new\" 0600", expected=78)
        self.assertFalse((self.root / "run/new").exists())

    def test_writable_ancestor_and_destination_are_rejected(self):
        writable = self.root / "state/writable"
        writable.mkdir(mode=0o777)
        writable.chmod(0o777)
        self.shell("printf bad | s4_atomic_write \"$S4_STATE/writable/new\" 0600", expected=78)
        file = self.root / "state/record"
        file.write_text("unchanged")
        file.chmod(0o666)
        self.shell("printf bad | s4_atomic_write \"$S4_STATE/record\" 0600", expected=78)
        self.assertEqual(file.read_text(), "unchanged")

    def test_rename_failure_preserves_old_record(self):
        path = self.root / "state/record"
        path.write_text("old")
        path.chmod(0o600)
        self.shell("mv() { return 1; }; printf new | s4_atomic_write \"$S4_STATE/record\" 0600", expected=1)
        self.assertEqual(path.read_text(), "old")
        self.assertEqual(list(path.parent.glob("record.*")), [])

    def test_state_is_not_sourced_and_corrupt_integers_reset(self):
        (self.root / "state/components/bootstrap").write_text(
            'attempts=$(touch "$S4_RUN/executed")\nnext_attempt=99999999999999999999999999\n'
        )
        result = self.shell("s4_state_value bootstrap attempts; s4_state_value bootstrap next_attempt")
        self.assertEqual(result.stdout, "0\n0\n")
        self.assertFalse((self.root / "run/executed").exists())

    def test_first_failure_persists_pending_and_backoff(self):
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 28; }; s4_reconcile_component bootstrap yes", expected=75)
        state = self.state()
        self.assertEqual(state["status"], "pending")
        self.assertEqual(state["last_exit"], "28")
        self.assertEqual(state["attempts"], "1")
        self.assertIn(int(state["next_attempt"]), range(1000060, 1000091))

    def test_backoff_prevents_unnecessary_retry(self):
        (self.root / "state/components/bootstrap").write_text("attempts=2\nnext_attempt=1000300\n")
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { touch \"$S4_RUN/executed\"; }; s4_reconcile_component bootstrap no", expected=75)
        self.assertFalse((self.root / "run/executed").exists())

    def test_corrupt_attempt_count_cannot_overflow_backoff(self):
        (self.root / "state/components/bootstrap").write_text("attempts=9999999999\nnext_attempt=0\n")
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 1; }; s4_reconcile_component bootstrap yes", expected=75)
        state = self.state()
        self.assertEqual(state["attempts"], "11")
        self.assertIn(int(state["next_attempt"]), range(1003600, 1003631))

    def test_backwards_clock_does_not_strand_work(self):
        (self.root / "state/components/bootstrap").write_text("attempts=1\nnext_attempt=2000000000\n")
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { touch \"$S4_RUN/executed\"; return 1; }; s4_reconcile_component bootstrap no", expected=75)
        self.assertTrue((self.root / "run/executed").exists())

    def test_success_requires_postcondition(self):
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 0; }; s4_reconcile_component bootstrap yes", expected=75)
        self.assertEqual(self.state()["status"], "pending")

    def test_stale_success_marker_is_repaired(self):
        (self.root / "state/components/bootstrap").write_text("status=complete\nattempts=0\nnext_attempt=0\n")
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 5; }; s4_reconcile_component bootstrap no", expected=75)
        self.assertEqual(self.state()["status"], "pending")

    def test_verified_success_disables_only_repair_timer(self):
        self.shell('s4_verify_bootstrap() { return 0; }; s4_repair no')
        self.assertEqual(self.state()["status"], "complete")
        events = (self.root / "events").read_text()
        self.assertIn("disable --now azurelinux3s4-repair.timer", events)
        self.assertFalse((self.root / "run/timer-enabled").exists())

    def test_failure_keeps_repair_timer_enabled(self):
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 1; }; s4_repair yes", expected=75)
        self.assertTrue((self.root / "run/timer-enabled").exists())
        self.assertNotIn("disable", (self.root / "events").read_text())

    def test_timer_stop_is_verified(self):
        self.shell('s4_verify_bootstrap() { return 0; }; systemctl() { return 0; }; s4_repair no', expected=75)

    def test_bootstrap_checks_each_package_and_executable(self):
        self.shell('rpm() { [[ $2 != python3 ]]; }; s4_verify_bootstrap', expected=1)
        self.shell('rpm() { return 0; }; s4_verify_bootstrap')

    def test_installed_packages_with_broken_ca_are_not_complete(self):
        (self.root / 'ca-bundle').write_text('not a certificate bundle\n')
        self.shell('rpm() { return 0; }; s4_verify_bootstrap', expected=1)

    def test_installed_but_disabled_metadata_verifier_is_not_complete(self):
        (self.root / 'plugin-config').write_text('[main]\nenabled=0\n')
        self.shell('rpm() { return 0; }; s4_verify_bootstrap', expected=1)
        self.shell('s4_activate_verifier; rpm() { return 0; }; s4_verify_bootstrap')

    def test_misleading_plugin_section_is_not_accepted(self):
        (self.root / 'plugin-config').write_text('[unrelated]\nenabled=1\n[main]\nenabled=0\n')
        self.shell('rpm() { return 0; }; s4_verify_bootstrap', expected=1)

    def test_failed_trust_rebuild_blocks_network_transaction(self):
        self.shell('update-ca-trust() { return 42; }; s4_tdnf() { touch "$S4_RUN/executed"; }; s4_apply_bootstrap', expected=42)
        self.assertFalse((self.root / 'run/executed').exists())

    def test_transactions_have_timeout_refresh_and_no_stdin(self):
        result = self.shell('timeout() { printf "%s\\n" "$*"; if read -r line; then return 9; fi; }; s4_tdnf install example')
        self.assertIn("--kill-after=30s 15m tdnf -c", result.stdout)
        self.assertIn("--releasever=3.0 --refresh -y install example", result.stdout)

    def test_repository_policy_is_production_only(self):
        self.shell("s4_repositories")
        for name in ("base", "extended"):
            policy = (self.root / f"state/repos/{name}.repo").read_text()
            self.assertIn(f"https://packages.microsoft.com/azurelinux/3.0/prod/{name}/x86_64/", policy)
            for setting in ("gpgcheck=1", "repo_gpgcheck=1", "sslverify=1", "skip_if_unavailable=0"):
                self.assertIn(setting, policy)
            self.assertNotIn("preview", policy)
        self.assertIn("installonly_limit=3", (self.root / "state/tdnf.conf").read_text())

    def test_missing_trust_anchor_never_disables_signatures(self):
        (self.root / "rpm-key").unlink()
        self.shell("s4_repositories", expected=75)
        self.assertEqual(list((self.root / "state/repos").iterdir()), [])

    def test_missing_trust_anchor_records_pending_repair(self):
        (self.root / "rpm-key").unlink()
        self.shell("s4_repair yes", expected=75)
        self.assertEqual(self.state()["status"], "pending")
        self.assertEqual(self.state()["last_exit"], "75")
        self.assertTrue((self.root / "run/timer-enabled").exists())

    def test_failed_first_policy_write_does_not_continue(self):
        self.shell('s4_atomic_write() { printf "%s\\n" "$1"; return 29; }; s4_repositories', expected=29)
        self.assertFalse((self.root / "state/tdnf.conf").exists())

    def test_concurrent_operations_fail_without_blocking(self):
        self.shell("s4_lock; bash -c 'source \"$1\"; S4_RUN=$2; s4_lock' bash "
                   + shlex.quote(str(SCRIPT)) + " " + shlex.quote(str(self.root / "run")), expected=0)
        # The child inherited descriptor 9. An unrelated process must fail.
        lock = (self.root / "run/operation.lock").open("w")
        self.addCleanup(lock.close)
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.shell("s4_lock", expected=75)

    def test_unit_installation_failure_is_not_masked(self):
        self.shell('systemctl() { [[ $1 != daemon-reload ]]; }; s4_install_units', expected=1)
        self.assertFalse((self.root / "run/timer-enabled").exists())

    def test_units_resume_at_boot_without_network_online_dependency(self):
        self.shell("s4_install_units")
        service = (self.root / "units/azurelinux3s4-repair.service").read_text()
        timer = (self.root / "units/azurelinux3s4-repair.timer").read_text()
        self.assertIn("KillMode=control-group", service)
        self.assertIn("TimeoutStartSec=20min", service)
        self.assertNotIn("network-online.target", service)
        self.assertIn("OnBootSec=2min", timer)
        self.assertIn("OnUnitInactiveSec=1min", timer)
        self.assertIn("RandomizedDelaySec=30s", timer)

    def test_status_never_claims_full_hardening(self):
        self.shell("s4_verify_bootstrap() { return 0; }; s4_reconcile_component bootstrap yes")
        result = self.shell("s4_status")
        self.assertIn("server_ready=no", result.stdout)
        self.assertIn("network containment", result.stdout)


if __name__ == "__main__":
    unittest.main()
