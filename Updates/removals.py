import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys


KERNELS = frozenset(("kernel", "kernel-mshv", "kernel-uvm", "kernel-uki", "kernel-64k", "kernel-hwe"))
LIMIT = 32 * 1024 * 1024


def number(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("removal evidence integer is missing or excessive")
    return value


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("removal evidence digest is invalid")
    return value


def package(value):
    name, nevra = value["name"], value["nevra"]
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,255}", name)
            or not isinstance(nevra, str) or len(nevra) > 1024 or not nevra.startswith(name + "-")):
        raise ValueError("package name and native identity are inconsistent")
    # Parse only the bounded canonical binary NEVRA subset emitted by RPM.
    # No RPM version comparison, dependency or renamed-provider equivalence is
    # inferred from these strings. Unsupported identities remain pending.
    match = re.fullmatch(r"(?:[0-9]+:)?[A-Za-z0-9._+~^]+-[A-Za-z0-9._+~^]+\.(x86_64|aarch64|noarch)",
                         nevra[len(name) + 1:])
    if not match:
        raise ValueError("package identity is outside the supported binary NEVRA subset")
    number(value["header_bytes"], 8, 8 * 1024 * 1024)
    digest(value["header_sha256"])
    return name, match[1]


def artifact(value):
    path = value["file"]
    if not isinstance(path, str) or not re.fullmatch(r"packages/(?:0|[1-9][0-9]{0,2})\.rpm", path):
        raise ValueError("incoming artifact does not identify a private snapshot")
    number(int(path[9:-4]), 0, 127)
    number(value["bytes"], 1, 512 * 1024 * 1024)
    digest(value["sha256"])
    if not isinstance(value["nevra"], str) or len(value["nevra"]) > 1024:
        raise ValueError("incoming native identity is invalid")
    return path, value["sha256"], value["bytes"], value["nevra"]


def observe(proof):
    if not isinstance(proof, dict):
        raise ValueError("removal evidence is not an object")
    if type(proof.get("schema")) is not int or proof["schema"] != 1 or proof.get("test_passed") is not True:
        raise ValueError("removal evidence lacks the current native TEST result")
    for flag in ("installs_performed", "scripts_executed", "installation_authorized",
                 "storage_capacity_checked", "freshness_proven"):
        if proof.get(flag) is not False:
            raise ValueError("removal evidence exceeds its diagnostic authority")
    digest(proof["manifest_sha256"])
    baseline = proof["baseline"]
    if not isinstance(baseline, dict):
        raise ValueError("installed observation is missing")
    headers = number(baseline["headers"], 1, 32768)
    digest(baseline["sha256"])
    audit = proof["effects"]
    if (not isinstance(audit, dict) or type(audit.get("schema")) is not int or audit["schema"] != 1
            or audit.get("script_metadata_observed") is not True
            or audit.get("removals_bound_to_installed_instances") is not True
            or type(audit.get("installed_headers_observed")) is not int
            or audit["installed_headers_observed"] != headers):
        raise ValueError("removal evidence lacks bound installed-instance observations")
    for flag in ("installed_headers_authenticated", "trigger_selection_complete", "script_execution_plan_complete",
                 "script_policy_satisfied", "removal_policy_satisfied", "rollback_policy_satisfied"):
        if audit.get(flag) is not False:
            raise ValueError("removal evidence claims an unestablished policy")
    incoming, additions, removals, identities = audit["incoming"], proof["additions"], audit["removals"], proof["removals"]
    if (any(not isinstance(value, list) for value in (incoming, additions, removals, identities))
            or len(incoming) != len(additions) or len(incoming) > 128
            or len(removals) != len(identities) or len(removals) > headers):
        raise ValueError("removal evidence inventories are inconsistent or excessive")
    if proof.get("rpm_test_performed") is not bool(additions) or (removals and not additions):
        raise ValueError("a removal must come from a nonempty current package TEST")
    if any(not isinstance(value, dict) for value in incoming + additions + removals):
        raise ValueError("removal evidence record is not an object")
    if sorted(map(artifact, incoming)) != sorted(map(artifact, additions)):
        raise ValueError("incoming observations differ from the SAME tested snapshots")
    if [value["nevra"] for value in removals] != identities:
        raise ValueError("removal inventory differs from the native TEST elements")
    snapshots, replacements = {}, {}
    for value in incoming:
        binding, key = artifact(value), package(value)
        if binding[0] in snapshots or key in replacements:
            raise ValueError("incoming replacement is duplicated or ambiguous")
        snapshots[binding[0]] = value
        replacements[key] = value
    for value in additions:
        if type(value.get("install_only")) is not bool or type(value.get("pretrans_present")) is not bool:
            raise ValueError("incoming native element flags are missing")
        source = snapshots[value["file"]]
        if value["install_only"] != (source["name"] in KERNELS):
            raise ValueError("incoming kernel retention mode is inconsistent")
    instances, used, matches = set(), set(), []
    for removed in removals:
        key = package(removed)
        instance = number(removed["instance"], 1, 2 ** 32 - 1)
        if instance in instances or key in used:
            raise ValueError("removed installed instance or replacement is repeated")
        instances.add(instance)
        if key[0] in KERNELS:
            raise ValueError("installed kernel removal is outside the update safeguard")
        replacement = replacements.get(key)
        if replacement is None or removed.get("classification") != "same-name-replacement":
            raise ValueError("installed removal lacks a unique SAME-name-and-architecture replacement")
        if removed["nevra"] == replacement["nevra"]:
            raise ValueError("same-identity erase/reinstall is outside the update safeguard")
        used.add(key)
        matches.append({"instance": instance, "name": key[0], "architecture": key[1],
                        "removed_nevra": removed["nevra"], "removed_header_sha256": removed["header_sha256"],
                        "replacement_nevra": replacement["nevra"], "file": replacement["file"],
                        "sha256": replacement["sha256"], "bytes": replacement["bytes"],
                        "replacement_header_sha256": replacement["header_sha256"]})
    proof["removal_guard"] = {"schema": 1, "matches": matches,
        "same_name_architecture_replacements_only": True, "kernel_removals_refused": True,
        "scope": "current TEST elements; one removed instance per unique same-name/architecture incoming snapshot",
        "versions_compared_by_guard": False, "package_continuity_proven": False,
        "critical_package_closure_complete": False, "removal_policy_satisfied": False,
        "rollback_policy_satisfied": False, "installation_authorized": False}
    return proof


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("removal evidence has a duplicate JSON field")
        result[key] = value
    return result


def main():
    try:
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 65))
        path = Path(sys.argv[1]) / "result.json"
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= LIMIT):
            raise ValueError("removal proof is not a bounded private regular file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            if identity(os.fstat(stream.fileno())) != identity(before):
                raise ValueError("removal proof changed before opening")
            data = stream.read(LIMIT + 1)
            if identity(os.fstat(stream.fileno())) != identity(before) or len(data) != before.st_size:
                raise ValueError("removal proof changed while reading")
        proof = observe(json.loads(data, object_pairs_hook=unique_object))
        proof["removal_guard"]["input_sha256"] = hashlib.sha256(data).hexdigest()
        encoded = json.dumps(proof, sort_keys=True)
        if len(encoded.encode("utf-8")) > 64 * 1024 * 1024:
            raise ValueError("removal observations exceed their output bound")
        print(encoded)
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, OverflowError, IndexError, StopIteration) as error:
        print("Update removal safeguard deferred: " + str(error), file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())
