import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

try:
    root, database, architecture = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if sys.argv[4:] not in ([], ["capacity"], ["effects"], ["interpreter-paths"]):
        raise ValueError("unsupported RPM diagnostic mode")
    capacity, effects = sys.argv[4:] == ["capacity"], sys.argv[4:] in (["effects"], ["interpreter-paths"])
    path_context = sys.argv[4:] == ["interpreter-paths"]
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if (any(int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapBnd", "CapAmb"))
            or status["NoNewPrivs"].strip() != "1"):
        raise ValueError("RPM test sandbox lacks its privilege restriction")
    for path in (Path("/"), Path("/etc"), Path("/usr"), Path("/var/lib"), database,
                 root / "packages", root / "vendor.asc"):
        if not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise ValueError("RPM test sandbox lacks read-only protection: " + str(path))
    for path in ("/run/systemd/private", "/run/dbus/system_bus_socket"):
        if os.access(path, os.R_OK | os.W_OK):
            raise ValueError("RPM test sandbox exposes a privileged manager socket")
    if {entry.name for entry in Path("/sys/class/net").iterdir()} != {"lo"}:
        raise ValueError("RPM test sandbox exposes host network interfaces")

    plan = json.loads((root / "plan.json").read_text())
    admitted = json.loads((root / "admission.json").read_text())
    records = plan["packages"]
    if (set(plan) != {"schema", "manifest_sha256", "packages"} or plan["schema"] != 1
            or not re.fullmatch(r"[0-9a-f]{64}", plan["manifest_sha256"])
            or not isinstance(records, list) or len(records) > 128
            or admitted.get("snapshots_retained") is not True or admitted.get("installs_performed") is not False
            or admitted.get("freshness_proven") is not False or admitted.get("schema") != 1
            or admitted.get("vendor_fingerprint") != "2BC94FFF7015A5F28F1537AD0CD9FED33135CE90"
            or len(admitted["artifacts"]) != len(records)):
        raise ValueError("batch context or repeated admission is malformed")
    paths, total = [], 0
    def digest(path):
        observed = path.lstat()
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.geteuid()
                or observed.st_mode & 0o777 != 0o400 or observed.st_nlink != 1
                or not 0 < observed.st_size <= 512 * 1024 * 1024):
            raise ValueError("test input is not the private read-only snapshot")
        value = hashlib.sha256()
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                value.update(block)
        return value.hexdigest(), observed.st_size
    for index, (record, artifact) in enumerate(zip(records, admitted["artifacts"])):
        if (set(record) != {"file", "path", "bytes", "sha256"}
                or record["file"] != "packages/" + str(index) + ".rpm"
                or set(artifact) != {"path", "bytes", "sha256"}
                or artifact != {"path": record["path"], "bytes": record["bytes"], "sha256": record["sha256"]}):
            raise ValueError("repeated admission differs from the retained manifest")
        path = root / "packages" / (str(index) + ".rpm")
        if digest(path) != (record["sha256"], record["bytes"]):
            raise ValueError("native test bytes differ from the admitted snapshots")
        paths.append(os.fsencode(path))
        total += record["bytes"]
    if total > 1024 * 1024 * 1024:
        raise ValueError("test batch exceeds its aggregate bound")
    key = root / "vendor.asc"
    if digest(key) != ("1092f37ec429e58bf9c7f898df17c3c32eb2ce3c4c037afb8ffe2d2b42e16e89", 983):
        raise ValueError("native test key differs from its vetted pin")

    lib = C.CDLL("librpm.so.9", mode=os.RTLD_NOW | os.RTLD_LOCAL)
    if C.c_char_p.in_dll(lib, "RPMVERSION").value != b"4.18.2":
        raise ValueError("native RPM ABI has not been vetted for this test")
    pointer, integer, unsigned, string = C.c_void_p, C.c_int, C.c_uint, C.c_char_p
    def bind(name, result, *arguments):
        function = getattr(lib, name)
        function.restype, function.argtypes = result, arguments
        return function
    signatures = {
        "rpmReadConfigFiles": (integer, string, string), "rpmtsCreate": (pointer,),
        "rpmPushMacro": (integer, pointer, string, string, string, integer),
        "rpmtsFree": (pointer, pointer), "rpmtsSetRootDir": (integer, pointer, string),
        "rpmtsSetDBMode": (integer, pointer, integer), "rpmtsOpenDB": (integer, pointer, integer),
        "rpmtsSetFlags": (unsigned, pointer, unsigned), "rpmtsFlags": (unsigned, pointer),
        "rpmtsSetVSFlags": (unsigned, pointer, unsigned), "rpmtsSetVfyFlags": (unsigned, pointer, unsigned),
        "rpmtsSetVfyLevel": (integer, pointer, integer), "rpmtsSetKeyring": (integer, pointer, pointer),
        "rpmKeyringNew": (pointer,), "rpmPubkeyRead": (pointer, string),
        "rpmKeyringAddKey": (integer, pointer, pointer), "rpmPubkeyFree": (pointer, pointer),
        "rpmKeyringFree": (pointer, pointer), "Fopen": (pointer, string, string),
        "Ferror": (integer, pointer), "Fclose": (integer, pointer),
        "rpmReadPackageFile": (integer, pointer, pointer, string, C.POINTER(pointer)),
        "headerGetString": (string, pointer, integer), "headerFree": (pointer, pointer),
        "headerIsEntry": (integer, pointer, integer),
        "rpmtsAddInstallElement": (integer, pointer, pointer, string, integer, pointer),
        "rpmtsCheck": (integer, pointer), "rpmtsOrder": (integer, pointer),
        "rpmtsRun": (integer, pointer, pointer, unsigned), "rpmtsProblems": (pointer, pointer),
        "rpmpsNumProblems": (integer, pointer), "rpmpsFree": (pointer, pointer),
        "rpmtsNElements": (integer, pointer), "rpmtsElement": (pointer, pointer, integer),
        "rpmteType": (integer, pointer), "rpmteN": (string, pointer),
        "rpmteNEVRA": (string, pointer), "rpmteKey": (string, pointer),
        "rpmtsInitIterator": (pointer, pointer, integer, pointer, C.c_size_t),
        "rpmdbNextIterator": (pointer, pointer), "rpmdbGetIteratorOffset": (unsigned, pointer),
        "rpmdbFreeIterator": (pointer, pointer), "headerExport": (pointer, pointer, C.POINTER(unsigned)),
        "rpmlogGetNrecsByMask": (integer, unsigned), "rpmlogSetMask": (integer, integer),
    }
    api = {name: bind(name, *signature) for name, signature in signatures.items()}
    if effects:
        api["rpmteDBInstance"] = bind("rpmteDBInstance", unsigned, pointer)
        api["headerGetAsString"] = bind("headerGetAsString", pointer, pointer, integer)
    if capacity or path_context:
        extra = {
            "rpmfiNew": (pointer, pointer, pointer, integer, unsigned),
            "rpmfiFree": (pointer, pointer), "rpmfiInit": (pointer, pointer, integer),
            "rpmfiNext": (integer, pointer), "rpmfiFC": (unsigned, pointer),
            "rpmfiFN": (string, pointer), "rpmfiFSize": (C.c_uint64, pointer),
            "rpmfiFMode": (C.c_uint16, pointer), "rpmfiFFlags": (unsigned, pointer),
            "rpmfiFLink": (string, pointer),
            "headerGet": (integer, pointer, integer, pointer, unsigned),
            "rpmtdNew": (pointer,), "rpmtdFree": (pointer, pointer),
            "rpmtdFreeData": (None, pointer), "rpmtdCount": (unsigned, pointer),
            "rpmtdType": (integer, pointer),
        }
        api.update({name: bind(name, *signature) for name, signature in extra.items()})
    libc = C.CDLL(None)
    libc.free.argtypes, libc.free.restype = [pointer], None
    if api["rpmReadConfigFiles"](None, None):
        raise ValueError("native RPM configuration could not be loaded")
    if api["rpmPushMacro"](None, b"_dbpath", None, os.fsencode(database), -7):
        raise ValueError("native RPM could not select the checked installed database")
    api["rpmlogSetMask"](15)  # Emergency through error; native warnings are not success records.
    def errors():
        if api["rpmlogGetNrecsByMask"](15):
            raise ValueError("native RPM reported an error")
    flags = 1 | 4 | 16 | 128  # TEST, NOSCRIPTS, NOTRIGGERS, NOPLUGINS.
    def transaction():
        ts = api["rpmtsCreate"]()
        if not ts:
            raise ValueError("native transaction allocation failed")
        try:
            if api["rpmtsSetRootDir"](ts, b"/") or api["rpmtsSetDBMode"](ts, os.O_RDONLY):
                raise ValueError("native read-only transaction policy failed")
            api["rpmtsSetFlags"](ts, flags)
            api["rpmtsSetVSFlags"](ts, 0)
            api["rpmtsSetVfyFlags"](ts, 0)
            api["rpmtsSetVfyLevel"](ts, 3)  # Digest AND signature, without administrator relaxation.
            keyring, pubkey = api["rpmKeyringNew"](), api["rpmPubkeyRead"](os.fsencode(key))
            try:
                if not keyring or not pubkey or api["rpmKeyringAddKey"](keyring, pubkey) or api["rpmtsSetKeyring"](ts, keyring):
                    raise ValueError("native in-memory pinned keyring could not be established")
            finally:
                if pubkey:
                    api["rpmPubkeyFree"](pubkey)
                if keyring:
                    api["rpmKeyringFree"](keyring)
            if api["rpmtsFlags"](ts) != flags or api["rpmtsOpenDB"](ts, os.O_RDONLY):
                raise ValueError("native TEST/read-only state was not observed")
            errors()
            return ts
        except BaseException:
            api["rpmtsFree"](ts)
            raise
    def effect_identity(header):
        name, identity = api["headerGetString"](header, 1000), None
        material = api["headerGetAsString"](header, 5016)
        try:
            if material:
                identity = C.string_at(material)
            if (not name or not re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9+._-]{0,255}", name)
                    or not identity or not 0 < len(identity) <= 1024
                    or any(value < 33 or value > 126 for value in identity)):
                raise ValueError("effects package identity is unsupported")
            return {"name": name.decode("ascii"), "nevra": identity.decode("ascii")}
        finally:
            if material:
                libc.free(material)
    effects_bytes, signed_header_bytes = 0, 0
    def observe_effects(header, exported):
        global effects_bytes
        value = {**effect_identity(header), **audit_header(exported)}
        effects_bytes += len(json.dumps(value, sort_keys=True).encode("utf-8"))
        # Retain at most 16MiB of metadata before plan/removal duplication;
        # the final 32MiB output cap is separate and positively checked.
        if effects_bytes > 16 * 1024 * 1024:
            raise ValueError("effects observations exceed their aggregate bound")
        return value
    def baseline(observations=None):
        # Header content + instance IDs observed before and after; not an RPM
        # mutation lock or authority to reuse this observation for installation.
        ts, iterator = transaction(), None
        try:
            iterator = api["rpmtsInitIterator"](ts, 0, None, 0)
            if not iterator:
                raise ValueError("installed header iteration failed")
            entries, total = [], 0
            while header := api["rpmdbNextIterator"](iterator):
                size = unsigned()
                material = api["headerExport"](header, C.byref(size))
                if not material:
                    raise ValueError("installed header export failed")
                try:
                    total += size.value
                    if not 0 < size.value <= 8 * 1024 * 1024 or total > 512 * 1024 * 1024 or len(entries) >= 32768:
                        raise ValueError("installed baseline exceeds its finite inspection bounds")
                    instance = api["rpmdbGetIteratorOffset"](iterator)
                    exported = C.string_at(material, size.value)
                    entries.append((instance, hashlib.sha256(exported).hexdigest()))
                    if observations is not None:
                        if not instance or instance in observations:
                            raise ValueError("effects installed instance is missing or duplicated")
                        observations[instance] = {"instance": instance, **observe_effects(header, exported)}
                finally:
                    libc.free(material)
            errors()
            if not entries or len({entry[0] for entry in entries}) != len(entries):
                raise ValueError("installed header baseline is empty or ambiguous")
            return {"headers": len(entries), "sha256": hashlib.sha256(
                json.dumps(sorted(entries), separators=(",", ":")).encode()).hexdigest()}
        finally:
            if iterator:
                api["rpmdbFreeIterator"](iterator)
            api["rpmtsFree"](ts)
    installed_effects, incoming_effects, removal_effects, removed_instances = {}, [], [], set()
    before = baseline(installed_effects if effects else None)
    ts = transaction()
    install_only = {b"kernel", b"kernel-mshv", b"kernel-uvm", b"kernel-uki", b"kernel-64k", b"kernel-hwe"}
    additions, removals = [], []
    pretrans = {}
    inventory, path_incoming, path_removed = [], [], []
    file_total, header_total, payload_total = 0, 0, 0
    def tag_info(header, tag):
        td = api["rpmtdNew"]()
        if not td:
            raise ValueError("signed file tag allocation failed")
        try:
            present = api["headerGet"](header, tag, td, 0)
            if present not in (0, 1):
                raise ValueError("signed file tag observation failed")
            return (api["rpmtdType"](td), api["rpmtdCount"](td)) if present else None
        finally:
            api["rpmtdFreeData"](td)
            api["rpmtdFree"](td)
    def payload(header, index, owner=None):
        global file_total, header_total, payload_total
        fi, material = None, None
        try:
            names = tag_info(header, 1117)  # BASENAMES, string array.
            if names is None:
                if tag_info(header, 1027) is not None:
                    raise ValueError("obsolete signed file paths are unsupported")
                count = 0
            else:
                if names[0] != 8:
                    raise ValueError("signed basename array type is invalid")
                count = names[1]
            file_total += count
            if file_total > 131072:
                raise ValueError("signed file inventory exceeds its count bound")
            # rpmfi otherwise silently defaults missing attributes to zero;
            # validate types/counts BEFORE its C iterator indexes those arrays.
            short, long = tag_info(header, 1028), tag_info(header, 5008)
            arrays = [(tag_info(header, 1030), 3), (tag_info(header, 1037), 4)]
            if short is not None:
                arrays.append((short, 4))
            if long is not None:
                arrays.append((long, 5))
            if count and short is None and long is None:
                raise ValueError("signed file size array is missing")
            for entry, kind in arrays:
                if (count and entry != (kind, count)) or (entry is not None and entry != (kind, count)):
                    raise ValueError("signed file attribute array type/count differs")
            links = tag_info(header, 1036)
            if links is not None and links != (8, count):
                raise ValueError("signed symlink array type/count differs")
            # Load only sizes/modes/flags/links and the validated path triplet.
            # The earlier independent cryptographic admission and native TEST
            # continue to verify signatures/digests; this is inventory control.
            fi_flags = ((1 << 20) - 2) & ~((1 << 6) | (1 << 7) | (1 << 9) | (1 << 17))
            fi = api["rpmfiNew"](ts, header, 0, fi_flags)
            if not fi or api["rpmfiFC"](fi) != count or not api["rpmfiInit"](fi, 0):
                raise ValueError("signed file inventory could not be loaded consistently")
            size = unsigned()
            material = api["headerExport"](header, C.byref(size))
            header_total += size.value
            if not material or not 0 < size.value <= 8 * 1024 * 1024 or header_total > 64 * 1024 * 1024:
                raise ValueError("signed header inventory exceeds its bound")
            files, seen = [], set()
            for expected in range(count):
                if api["rpmfiNext"](fi) != expected:
                    raise ValueError("signed file inventory ended or changed unexpectedly")
                name, link = api["rpmfiFN"](fi), api["rpmfiFLink"](fi)
                length, mode, flags = api["rpmfiFSize"](fi), api["rpmfiFMode"](fi), api["rpmfiFFlags"](fi)
                if not name or len(name) > 4096 or name in seen or length > 16 * 1024 ** 3:
                    raise ValueError("signed file metadata is missing, duplicated or excessive")
                if stat.S_ISLNK(mode) and (links is None or not link):
                    raise ValueError("signed symlink target is missing")
                seen.add(name)
                payload_total += length
                if payload_total > 64 * 1024 ** 3:
                    raise ValueError("expanded signed payload exceeds its bound")
                files.append({"path": name.decode("utf-8"), "bytes": length, "mode": mode,
                              "flags": flags, "link": link.decode("utf-8") if link else ""})
            if api["rpmfiNext"](fi) != -1:
                raise ValueError("signed file inventory has unexpected trailing entries")
            if owner is None:
                inventory.append({"file": records[index]["file"], "sha256": records[index]["sha256"],
                                  "bytes": records[index]["bytes"], "header_bytes": size.value, "files": files})
            else:
                if (size.value != owner["header_bytes"]
                        or hashlib.sha256(C.string_at(material, size.value)).hexdigest() != owner["header_sha256"]):
                    raise ValueError("interpreter namespace header differs from the observed owner")
                fields = ("name", "nevra", "header_bytes", "header_sha256", "instance") if index is None else (
                    "name", "nevra", "header_bytes", "header_sha256", "file", "sha256", "bytes")
                value = {**{name: owner[name] for name in fields}, "files": files}
                (path_removed if index is None else path_incoming).append(value)
        finally:
            if material:
                libc.free(material)
            if fi:
                api["rpmfiFree"](fi)
    def removed_payload(owner):
        # rpmteHeader is not populated at this pre-execution point. Read the
        # actual database instance, retaining the iterator's weak header until
        # its identity/export digest and file declarations have been checked.
        instance, iterator = unsigned(owner["instance"]), None
        try:
            iterator = api["rpmtsInitIterator"](ts, 0, C.byref(instance), C.sizeof(instance))
            if not iterator:
                raise ValueError("interpreter removal header iterator is unavailable")
            header = api["rpmdbNextIterator"](iterator)
            if (not header or api["rpmdbGetIteratorOffset"](iterator) != instance.value
                    or effect_identity(header) != {name: owner[name] for name in ("name", "nevra")}):
                raise ValueError("interpreter removal header differs from its observed instance")
            payload(header, None, owner)
            if api["rpmdbNextIterator"](iterator):
                raise ValueError("interpreter removal header query is ambiguous")
            errors()
        finally:
            if iterator:
                api["rpmdbFreeIterator"](iterator)
    opened, consumed, callback_errors = {}, set(), []
    callback_type = C.CFUNCTYPE(pointer, pointer, integer, C.c_uint64, C.c_uint64, pointer, pointer)
    @callback_type
    def notify(header, what, amount, total, key, data):
        try:
            if what & ((1 << 15) | (1 << 16) | (1 << 17)):
                raise ValueError("native TEST attempted package script execution")
            if what in (4, 8):
                path = C.string_at(key) if key else None
                if path not in paths:
                    raise ValueError("native callback requested bytes outside the admitted snapshots")
                if what == 4:
                    if path in opened:
                        raise ValueError("native callback requested an already-open snapshot")
                    fd = api["Fopen"](path, b"r.ufdio")
                    if not fd or api["Ferror"](fd):
                        if fd:
                            api["Fclose"](fd)
                        raise ValueError("native callback could not open its admitted snapshot")
                    opened[path] = fd
                    consumed.add(path)
                    return fd
                fd = opened.pop(path, None)
                if not fd or api["Fclose"](fd):
                    raise ValueError("native callback could not close its snapshot")
        except (ValueError, OSError) as error:
            callback_errors.append(str(error))
        return None
    set_notify = bind("rpmtsSetNotifyCallback", integer, pointer, callback_type, pointer)
    try:
        if set_notify(ts, notify, None):
            raise ValueError("native snapshot callback could not be established")
        for index, path in enumerate(paths):
            fd, header = api["Fopen"](path, b"r.ufdio"), pointer()
            try:
                if not fd or api["Ferror"](fd) or api["rpmReadPackageFile"](ts, fd, path, C.byref(header)) or not header:
                    raise ValueError("native signed snapshot header read failed")
                name, arch = api["headerGetString"](header, 1000), api["headerGetString"](header, 1022)
                if not name or not re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9+._-]{0,255}", name) or arch not in (architecture.encode(), b"noarch"):
                    raise ValueError("snapshot is not a target-architecture binary RPM")
                if api["rpmtsAddInstallElement"](ts, header, path, int(name not in install_only), None):
                    raise ValueError("native mixed transaction could not admit every input")
                pretrans[path] = bool(api["headerIsEntry"](header, 1151))
                if capacity:
                    payload(header, index)
                if effects:
                    size = unsigned()
                    exported = api["headerExport"](header, C.byref(size))
                    try:
                        if not exported or not 0 < size.value <= 8 * 1024 * 1024:
                            raise ValueError("effects signed header export exceeds its bound")
                        signed_header_bytes += size.value
                        if signed_header_bytes > 64 * 1024 * 1024:
                            raise ValueError("effects signed headers exceed their aggregate bound")
                        incoming_effects.append({"file": records[index]["file"],
                            "sha256": records[index]["sha256"], "bytes": records[index]["bytes"],
                            **observe_effects(header, C.string_at(exported, size.value))})
                    finally:
                        if exported:
                            libc.free(exported)
                    if path_context:
                        payload(header, index, incoming_effects[-1])
            finally:
                if header:
                    api["headerFree"](header)
                if fd and api["Fclose"](fd):
                    raise ValueError("native snapshot descriptor close failed")
        if api["rpmtsCheck"](ts):
            raise ValueError("native dependency check failed")
        def no_problems():
            problems = api["rpmtsProblems"](ts)
            try:
                if api["rpmpsNumProblems"](problems):
                    raise ValueError("native transaction has unresolved problems")
            finally:
                if problems:
                    api["rpmpsFree"](problems)
            errors()
        no_problems()
        if api["rpmtsOrder"](ts):
            raise ValueError("native transaction ordering failed")
        count = api["rpmtsNElements"](ts)
        if not len(paths) <= count <= 32768 + 128:
            raise ValueError("native transaction element count is inconsistent")
        for index in range(count):
            element = api["rpmtsElement"](ts, index)
            if not element:
                raise ValueError("native transaction element is missing")
            kind, name = api["rpmteType"](element), api["rpmteN"](element)
            identity = api["rpmteNEVRA"](element)
            if not identity or len(identity) > 1024:
                raise ValueError("native transaction identity is malformed")
            if kind == 1:
                additions.append({"snapshot": os.fsdecode(api["rpmteKey"](element)),
                                  "nevra": identity.decode("ascii"), "install_only": name in install_only})
            elif kind == 2 and name not in install_only:
                removals.append(identity.decode("ascii"))
                if effects:
                    instance = api["rpmteDBInstance"](element)
                    observed = installed_effects.get(instance)
                    if (not observed or observed["nevra"] != identity.decode("ascii")
                            or observed["name"].encode("ascii") != name
                            or instance in removed_instances):
                        raise ValueError("native removal differs from the observed installed instance")
                    removed_instances.add(instance)
                    removal_effects.append({**observed, "classification": "same-name-replacement"
                        if any(value["name"] == observed["name"] for value in incoming_effects)
                        else "other-removal"})
                    if path_context:
                        removed_payload(observed)
            else:
                raise ValueError("native plan would remove a retained kernel or has an unknown element")
        if sorted(os.fsencode(value["snapshot"]) for value in additions) != sorted(paths):
            raise ValueError("native plan replaced or dropped an admitted input")
        if api["rpmtsFlags"](ts) != flags or api["rpmtsRun"](ts, None, (1 << 7) | (1 << 8)):
            # Only capacity/inode filters: all signature, dependency, file,
            # architecture and older/already-installed package checks remain.
            raise ValueError("native TEST transaction rejected the batch")
        if callback_errors or opened or consumed != set(paths):
            raise ValueError("native TEST did not consume and close exactly the admitted snapshots")
        no_problems()
    finally:
        for fd in opened.values():
            api["Fclose"](fd)
        api["rpmtsFree"](ts)
    after = baseline()
    if after != before:
        raise ValueError("installed header context changed during compatibility inspection")
    for index, record in enumerate(records):
        if digest(root / "packages" / (str(index) + ".rpm")) != (record["sha256"], record["bytes"]):
            raise ValueError("native test snapshots changed")
    for addition in additions:
        path = os.fsencode(addition.pop("snapshot"))
        index = paths.index(path)
        addition.update(file=records[index]["file"], sha256=records[index]["sha256"], bytes=records[index]["bytes"])
        addition["pretrans_present"] = pretrans[path]
    proof = {"schema": 1, "manifest_sha256": plan["manifest_sha256"],
                      "baseline": before, "additions": additions, "removals": removals,
                      "rpm_test_performed": bool(paths), "test_passed": True,
                      "installs_performed": False, "scripts_executed": False,
                      "installation_authorized": False, "storage_capacity_checked": False,
                      "freshness_proven": False}
    if capacity:
        data = json.dumps({"schema": 1, "manifest_sha256": plan["manifest_sha256"],
                           "artifacts": inventory}, sort_keys=True).encode("utf-8")
        if len(data) > 32 * 1024 * 1024:
            raise ValueError("signed file inventory exceeds its output bound")
        with (root / "inventory.json").open("xb") as output:
            output.write(data)
        proof["payload_inventory"] = {"sha256": hashlib.sha256(data).hexdigest(),
                                      "bytes": len(data), "files": file_total}
    if effects:
        binding = lambda value: (value["file"], value["sha256"], value["bytes"], value["nevra"])
        if sorted(map(binding, incoming_effects)) != sorted(map(binding, additions)):
            raise ValueError("native additions differ from the observed admitted header identities")
        proof["effects"] = {"schema": 1, "incoming": incoming_effects, "removals": removal_effects,
            "installed_versions": installed_version_inventory(installed_effects, before),
            "installed_script_owners": [value for _, value in sorted(installed_effects.items()) if value["tags"]],
            "installed_headers_observed": before["headers"], "script_metadata_observed": True,
            "removals_bound_to_installed_instances": True, "installed_headers_authenticated": False,
            "trigger_selection_complete": False, "script_execution_plan_complete": False,
            "script_policy_satisfied": False, "removal_policy_satisfied": False,
            "rollback_policy_satisfied": False}
    if path_context:
        proof["namespace_inventory"] = {"schema": 1, "incoming": path_incoming, "removals": path_removed,
            "files": file_total, "scope": "declared native incoming/removal header file paths only",
            "installed_headers_authenticated": False, "operation_selection_complete": False,
            "snapshot_atomic": False, "installation_authorized": False}
    data = json.dumps(proof, sort_keys=True)
    if effects and len(data.encode("utf-8")) > 32 * 1024 * 1024:
        raise ValueError("effects report exceeds its output bound")
    print(data)
except (ValueError, KeyError, TypeError, OSError, UnicodeError, AttributeError) as error:
    print("azurelinux3s4: RPM compatibility deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
