import json
import os
from pathlib import Path
import resource
import subprocess
import sys
try:
    root = Path(sys.argv[1])
    capacity = sys.argv[4] == "yes"
    effects = sys.argv[5] in ("yes", "interpreter-paths")
    path_context = sys.argv[5] == "interpreter-paths"
    if sys.argv[4] not in ("", "yes") or sys.argv[5] not in ("", "yes", "interpreter-paths") or (capacity and effects):
        raise ValueError("unsupported internal diagnostic mode")
    output_limit = 32 * 1024 * 1024 if capacity or effects else 1048576
    evidence_limit = 32 * 1024 * 1024 if effects else 1048576
    unit = "azurelinux3s4-check-" + root.name.removeprefix("update-check.") + ".service"
    if any(character not in "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in str(root) + sys.argv[2]):
        raise ValueError("test workspace or database path is unsupported")
    command = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--unit=" + unit,
        "--property=RuntimeMaxSec=12min", "--property=TimeoutStopSec=15s", "--property=KillMode=control-group",
        "--property=ProtectSystem=strict", "--property=ReadWritePaths=" + str(root),
        "--property=ReadOnlyPaths=" + str(root / "packages") + " " + str(root / "vendor.asc") + " " + sys.argv[2],
        "--property=PrivateNetwork=yes", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes", "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
        "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectKernelLogs=yes",
        "--property=ProtectControlGroups=yes", "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
        "--property=LockPersonality=yes", "--property=UMask=0077", "--property=MemoryMax=768M",
        "--property=LimitFSIZE=" + str(output_limit), "--property=InaccessiblePaths=/run/systemd/private /run/dbus/system_bus_socket",
        "--property=UnsetEnvironment=RPM_CONFIGDIR RPM_POPTEXEC_PATH LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH",
        "--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin", "--setenv=LC_ALL=C", "--setenv=LANG=C",
        "--setenv=HOME=" + str(root / "home"), "--", "python3", "-I", str(root / "test.py"), str(root),
        *sys.argv[2:4], *(["capacity"] if capacity else ["interpreter-paths"] if path_context else ["effects"] if effects else [])]
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))
    with (root / "native.log").open("xb") as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output, preexec_fn=limits)
        completed = False
        try:
            code = process.wait(timeout=750)
            completed = True
        finally:
            if not completed:
                stopped = subprocess.run(["systemctl", "stop", unit], stdin=subprocess.DEVNULL,
                                         capture_output=True, timeout=30)
                process.kill()
                process.wait(timeout=15)
                if stopped.returncode:
                    raise ValueError("native test shutdown could not be confirmed")
    data = (root / "native.log").read_bytes()
    if code or not 0 < len(data) <= evidence_limit:
        print(data[:65536].decode("utf-8", "replace"), file=sys.stderr)
        raise ValueError("native RPM test did not provide bounded successful evidence")
    proof = json.loads(data)
    if (proof.get("schema") != 1 or proof.get("test_passed") is not True
            or any(proof.get(name) is not False for name in ("installs_performed", "scripts_executed", "installation_authorized", "storage_capacity_checked", "freshness_proven"))):
        raise ValueError("native test evidence is incomplete")
    if effects:
        observed = proof.get("effects", {})
        if (observed.get("schema") != 1 or observed.get("script_metadata_observed") is not True
                or observed.get("removals_bound_to_installed_instances") is not True
                or observed.get("installed_headers_observed") != proof["baseline"]["headers"]
                or len(observed["incoming"]) != len(proof["additions"])
                or [value["nevra"] for value in observed["removals"]] != proof["removals"]
                or any(observed.get(name) is not False for name in ("installed_headers_authenticated",
                    "trigger_selection_complete", "script_execution_plan_complete", "script_policy_satisfied",
                    "removal_policy_satisfied", "rollback_policy_satisfied"))):
            raise ValueError("native effects evidence is incomplete")
    if path_context:
        declared = proof.get("namespace_inventory", {})
        if (declared.get("schema") != 1 or not isinstance(declared.get("incoming"), list)
                or not isinstance(declared.get("removals"), list)
                or len(declared["incoming"]) != len(proof["additions"])
                or len(declared["removals"]) != len(proof["removals"])
                or any(declared.get(name) is not False for name in ("installed_headers_authenticated",
                    "operation_selection_complete", "snapshot_atomic", "installation_authorized"))):
            raise ValueError("native interpreter namespace evidence is incomplete")
    (root / "result.json").write_text(json.dumps(proof, sort_keys=True) + "\n")
except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: update compatibility deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
