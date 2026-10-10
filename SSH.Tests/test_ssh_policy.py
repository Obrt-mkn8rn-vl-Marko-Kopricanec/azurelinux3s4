import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("s4_ssh_policy", ROOT / "SSH/policy.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class SSHPolicyTests(unittest.TestCase):
    def test_default_candidate_is_explicit_loopback_only_and_has_no_authority(self):
        bundle = POLICY.bundle()
        self.assertEqual(bundle["source_prefixes"], ["127.0.0.1/32", "::1/128"])
        self.assertEqual(bundle["listen_addresses"], ["127.0.0.1", "::1"])
        self.assertEqual(bundle["admin_account_name"], "azurelinux3s4-admin")
        self.assertEqual(len(bundle["authority"]), 15)
        self.assertTrue(all(flag is False for flag in bundle["authority"].values()))

    def test_candidate_bytes_mode_and_digest_are_bound(self):
        files = POLICY.bundle()["files"]
        self.assertEqual(len(files), 1)
        entry = files[0]
        self.assertEqual(entry["file"], "ssh/sshd_config")
        self.assertEqual(entry["mode"], "0644")
        self.assertEqual(entry["bytes"], len(entry["content"].encode()))
        self.assertEqual(entry["sha256"], hashlib.sha256(entry["content"].encode()).hexdigest())

    def test_exact_key_account_and_forwarding_declarations_are_standalone(self):
        content = POLICY.bundle()["files"][0]["content"]
        directives = {}
        for line in content.splitlines():
            if line.startswith("#"): continue
            key, value = line.split(" ", 1)
            directives.setdefault(key, []).append(value)
        for key, value in {"PermitRootLogin": "no", "PasswordAuthentication": "no",
                           "KbdInteractiveAuthentication": "no", "AuthenticationMethods": "publickey",
                           "UsePAM": "yes", "StrictModes": "yes", "DisableForwarding": "yes",
                           "AllowTcpForwarding": "no", "AllowStreamLocalForwarding": "no",
                           "AllowAgentForwarding": "no", "X11Forwarding": "no", "PermitTunnel": "no",
                           "PermitUserRC": "no", "PermitUserEnvironment": "no",
                           "AuthorizedKeysFile": "/etc/azurelinux3s4/ssh/admin_authorized_keys"}.items():
            self.assertEqual(directives[key], [value])
        self.assertNotIn("Include", directives)
        self.assertNotIn("Match", directives)
        self.assertEqual(directives["Ciphers"], ["aes256-gcm@openssh.com,aes128-gcm@openssh.com"])
        self.assertEqual(directives["MACs"], ["hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"])
        self.assertEqual(directives["AllowUsers"], ["azurelinux3s4-admin@127.0.0.1/32 azurelinux3s4-admin@::1/128"])

    def test_bounded_explicit_rfc1918_and_ula_lan_inputs_compile(self):
        bundle = POLICY.bundle(["fd01:2::/64", "192.168.4.0/24", "10.3.0.0/24"],
                               ["fd01:2::1", "192.168.4.2", "10.3.0.2"])
        self.assertEqual(bundle["source_prefixes"], ["10.3.0.0/24", "192.168.4.0/24", "fd01:2::/64"])
        self.assertTrue(all(flag is False for flag in bundle["authority"].values()))

    def test_source_and_listener_order_do_not_change_candidate_bytes(self):
        first = POLICY.bundle(["10.3.0.0/24", "fd01:2::/64"], ["10.3.0.2", "fd01:2::1"])
        second = POLICY.bundle(["fd01:2::/64", "10.3.0.0/24"], ["fd01:2::1", "10.3.0.2"])
        self.assertEqual(first, second)

    def test_public_cgnat_reserved_link_local_mapped_and_broad_prefixes_refuse(self):
        for prefix, listener in [("0.0.0.0/0", "10.0.0.1"), ("192.0.2.0/24", "192.0.2.8"),
                                 ("100.64.0.0/10", "100.64.0.1"), ("198.18.0.0/15", "198.18.0.1"),
                                 ("169.254.0.0/16", "169.254.1.2"), ("127.0.0.0/8", "127.0.0.1"),
                                 ("::/0", "::1"), ("2001:db8::/32", "2001:db8::1"),
                                 ("fe80::/10", "fe80::1"), ("::ffff:a00:0/104", "::ffff:a00:1")]:
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                POLICY.bundle([prefix], [listener])

    def test_host_bit_prefixes_netmask_spellings_and_noncanonical_literals_refuse(self):
        for prefix, listener in [("10.1.2.3/24", "10.1.2.1"), ("10.1.2.0/255.255.255.0", "10.1.2.1"),
                                 ("10.1.2.0/24", "010.1.2.1"), ("fdAB::/64", "fdab::1"),
                                 ("fdab::/64", "fdab:0:0:0:0:0:0:1")]:
            with self.subTest(prefix=prefix, listener=listener), self.assertRaises(ValueError):
                POLICY.bundle([prefix], [listener])

    def test_scope_ids_control_bytes_wildcards_and_hostnames_cannot_inject_config(self):
        for listener in ["fd01:2::1%eth0", "fd01:2::1%eth0\nPermitRootLogin yes", "10.3.0.2\nInclude /operator",
                         "localhost", "10.3.*", "10.3.0.2 #override", "10.3.0.2\x00", "10.3.0.2\r"]:
            with self.subTest(listener=listener), self.assertRaises(ValueError):
                POLICY.bundle(["10.3.0.0/24", "fd01:2::/64"], [listener])

    def test_duplicates_overlaps_and_missing_listener_correspondence_refuse(self):
        for prefixes, listeners in [(["10.0.0.0/8", "10.3.0.0/24"], ["10.3.0.2"]),
                                    (["10.3.0.0/24", "10.3.0.0/24"], ["10.3.0.2"]),
                                    (["10.3.0.0/24"], ["10.3.0.2", "10.3.0.2"]),
                                    (["10.3.0.0/24", "fd01:2::/64"], ["10.3.0.2"]),
                                    (["10.3.0.0/24"], ["10.4.0.2"])]:
            with self.subTest(prefixes=prefixes, listeners=listeners), self.assertRaises(ValueError):
                POLICY.bundle(prefixes, listeners)

    def test_network_broadcast_and_subnet_anycast_listener_boundaries_refuse(self):
        for prefix, listener in [("10.3.0.0/24", "10.3.0.0"), ("10.3.0.0/24", "10.3.0.255"),
                                 ("fd01:2::/64", "fd01:2::")]:
            with self.subTest(listener=listener), self.assertRaises(ValueError):
                POLICY.bundle([prefix], [listener])
        self.assertEqual(POLICY.bundle(["10.3.0.0/31"], ["10.3.0.0"])["listen_addresses"], ["10.3.0.0"])

    def test_empty_wrong_type_or_excessive_input_refuses(self):
        for prefixes, listeners in [((), ()), ("10.0.0.0/8", ["10.0.0.1"]), (["10.0.0.0/8"], {}),
                                    (["10.0.0.0/8"] * 65, ["10.0.0.1"]), ([None], ["10.0.0.1"]),
                                    (["10.0.0.0/8"], ["a" * 65])]:
            with self.subTest(prefixes=prefixes), self.assertRaises(ValueError): POLICY.bundle(prefixes, listeners)

    def test_locality_shell_forwarding_and_crypto_limits_remain_explicit(self):
        limits = " ".join(POLICY.bundle()["limits"])
        for value in ("NAT/proxies/VPN/tunnels", "another forwarder", "cryptographic policy admission remains unfinished",
                      "No sudo removal", "not a vendor drop-in"):
            self.assertIn(value, limits)

    def test_standalone_installer_emits_exact_candidate_without_checkout_or_preflight(self):
        with tempfile.TemporaryDirectory(prefix="s4-ssh-delivery-") as directory:
            delivered = Path(directory) / "setup.sh"
            delivered.write_bytes((ROOT / "azurelinux3s4.sh").read_bytes())
            delivered.chmod(0o755)
            result = subprocess.run([str(delivered), "--ssh-policy"], cwd=directory, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout), POLICY.bundle())
            self.assertEqual(result.stderr, b"")
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ["setup.sh"])

    def test_cli_override_refuses_without_candidate_output(self):
        for command in [[str(ROOT / "azurelinux3s4.sh"), "--ssh-policy", "--listen=0.0.0.0"],
                        [sys.executable, "-I", str(ROOT / "SSH/policy.py"), "--listen=0.0.0.0"]]:
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64, result.stderr.decode())
            self.assertEqual(result.stdout, b"")

    def test_emit_failure_withholds_all_batch_json(self):
        namespace = dict(vars(POLICY))
        namespace["bundle"] = lambda: (_ for _ in ()).throw(ValueError("fixture invalid candidate"))
        code = "import importlib.util; s=importlib.util.spec_from_file_location('p'," + repr(str(ROOT / "SSH/policy.py")) + "); p=importlib.util.module_from_spec(s); s.loader.exec_module(p); p.bundle=lambda: (_ for _ in ()).throw(ValueError('fixture invalid candidate')); raise SystemExit(p.main())"
        result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 75, result.stderr.decode())
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"SSH candidate refused: fixture invalid candidate\n")


class NativeSSHParserTests(unittest.TestCase):
    def parse(self, bundle, address):
        source = bundle["files"][0]
        with tempfile.TemporaryDirectory(prefix="s4-ssh-native-", dir="/dev/shm") as directory:
            key = Path(directory) / "fixture_host_key"
            generated = subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                                       capture_output=True, timeout=10)
            self.assertEqual(generated.returncode, 0, generated.stderr.decode())
            self.assertEqual(generated.stdout + generated.stderr, b"")
            lines, substitutions = [], []
            for line in source["content"].splitlines(keepends=True):
                if line.startswith("HostKey "):
                    substitutions.append({"original": line.strip(), "delivered": "HostKey " + str(key)})
                    line = "HostKey " + str(key) + "\n"
                lines.append(line)
            self.assertEqual(len(substitutions), 2)
            config = Path(directory) / "sshd_config"
            config.write_text("".join(lines))
            config.chmod(0o600)
            result = subprocess.run(["/usr/sbin/sshd", "-T", "-f", str(config), "-C",
                                     "user=azurelinux3s4-admin,host=fixture.invalid,addr=" + address + ",laddr=" + bundle["listen_addresses"][0] + ",lport=22"],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b"")
            values = {}
            for line in result.stdout.decode().splitlines():
                name, value = line.split(" ", 1)
                values.setdefault(name, []).append(value)
            for name, value in {"permitrootlogin": "no", "passwordauthentication": "no",
                                "kbdinteractiveauthentication": "no", "pubkeyauthentication": "yes",
                                "authenticationmethods": "publickey", "usepam": "yes", "strictmodes": "yes",
                                "disableforwarding": "yes", "allowtcpforwarding": "no", "allowstreamlocalforwarding": "no",
                                "allowagentforwarding": "no", "x11forwarding": "no", "permittunnel": "no",
                                "permituserrc": "no", "permituserenvironment": "no",
                                "authorizedkeysfile": "/etc/azurelinux3s4/ssh/admin_authorized_keys",
                                "trustedusercakeys": "none", "channeltimeout": "session=5m"}.items():
                self.assertEqual(values[name], [value])
            self.assertEqual(sorted(values["allowusers"]), sorted(POLICY.ADMIN + "@" + prefix for prefix in bundle["source_prefixes"]))
            expected_listens = [(("[" + value + "]") if ":" in value else value) + ":22" for value in bundle["listen_addresses"]]
            self.assertEqual(sorted(values["listenaddress"]), sorted(expected_listens))
            record = {"actual_parser_wait_exit": result.returncode, "actual_fixture_keygen_wait_exit": generated.returncode,
                      "candidate_source_sha256": source["sha256"], "candidate": bundle,
                      "delivered_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
                      "hostkey_path_delivery_substitutions": substitutions, "effective_config_stdout": result.stdout.decode(),
                      "effective_config_stderr": result.stderr.decode(),
                      "native_parser_version": subprocess.run(["/usr/sbin/sshd", "-V"], capture_output=True, check=True).stderr.decode().strip(),
                      "ssh_authentication_executed": False, "listener_activated": False, "system_keys_provisioned": False,
                      "accounts_created": False, "native_azure_policy_proven": False, "installation_authorized": False, "server_ready": False}
        self.assertFalse(Path(directory).exists())
        self.record = {"owned_key_directory_removed": True, **record}

    def test_existing_native_parser_reports_exact_default_effective_candidate(self):
        self.parse(POLICY.bundle(), "192.0.2.7")

    def test_existing_native_parser_reports_exact_explicit_private_lan_model(self):
        self.parse(POLICY.bundle(["10.3.0.0/24", "fd01:2::/64"], ["10.3.0.2", "fd01:2::1"]), "10.3.0.4")


if __name__ == "__main__":
    unittest.main()
