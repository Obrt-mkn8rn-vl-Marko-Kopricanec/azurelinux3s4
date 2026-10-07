"""Local admission projection; no accounts, units, runtime or host policy install.

Only the root-fd, trusted root IDs, journal PATH and process-identity delivery
are substituted. Actual inherited stdio, O_PATH walk/connect, peer credentials,
inode/mount rechecks, native filters and forwarding use production functions.
The explicitly named without-recheck sensitivity mode additionally omits one
comparison/refusal in a private in-process copy; it is not production evidence.
"""

import ast
import errno
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import socket
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("s4_admission_relay", ROOT / "Web/relay.py")
RELAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELAY)


def main():
    directory, mode = Path(sys.argv[1]), sys.argv[2]
    RELAY.ROOT_UID = os.getuid()
    RELAY.ROOT_GID = os.getgid()
    RELAY.JOURNAL = str(directory / "journal.sock")
    RELAY.backend_root = lambda: os.open(directory, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    # This models a checked caller and dedicated account allocation ONLY.
    # The current Debian UID is also the fixture server; no native multi-UID
    # account, root/capability/NNP or PID1 authorization proof is inferred.
    context = (os.getuid() + 1, os.getuid(), os.getgid())
    RELAY.process_identity = lambda: context
    if mode == "extra-fd":
        calls, extras = [], []
        original = RELAY.close_runtime_extras

        def observed():
            calls.append(None)
            if len(calls) == 2:
                extras.append(socket.socket(socket.AF_UNIX))
            return context

        def scrubbed(backend):
            descriptor = extras[0].fileno()
            original(backend)
            try:
                os.fstat(descriptor)
            except OSError as error:
                import errno
                assert error.errno == errno.EBADF
            else:
                raise AssertionError("startup lookup descriptor survived")

        RELAY.process_identity = observed
        RELAY.close_runtime_extras = scrubbed
    elif mode == "changed-accounts":
        calls = []

        def changed():
            calls.append(None)
            return context if len(calls) == 1 else (context[0] + 1, *context[1:])

        RELAY.process_identity = changed
    elif mode in ("replace-leaf", "replace-leaf-without-recheck"):
        original = RELAY.backend_path
        calls, replacements, scrubbed = [], [], []
        cleanup = RELAY.close_inherited
        omitted = mode == "replace-leaf-without-recheck"

        def cleaned():
            cleanup()
            scrubbed.append(True)

        RELAY.close_inherited = cleaned
        if omitted:
            # Sensitivity model ONLY: remove the single comparison/refusal,
            # preserving the second path walk, descriptor cleanup and all
            # other production admission/sealing/forwarding operations.
            source = inspect.getsource(RELAY.connect_backend)
            tree, removed = ast.parse(source), []

            class OmitRecheck(ast.NodeTransformer):
                def visit_If(self, node):
                    if (len(node.body) == 1 and isinstance(node.body[0], ast.Raise)
                            and isinstance(node.body[0].exc, ast.Call)
                            and isinstance(node.body[0].exc.func, ast.Name)
                            and node.body[0].exc.func.id == "ValueError"
                            and len(node.body[0].exc.args) == 1
                            and isinstance(node.body[0].exc.args[0], ast.Constant)
                            and node.body[0].exc.args[0].value ==
                            "backend ancestry/socket changed during admission"):
                        removed.append(ast.dump(node))
                        return ast.copy_location(ast.Pass(), node)
                    return self.generic_visit(node)

            tree = ast.fix_missing_locations(OmitRecheck().visit(tree))
            assert len(removed) == 1, "sensitivity model must omit exactly one recheck"
            exec(compile(tree, "omitted-recheck-sensitivity-model", "exec"), vars(RELAY))

        def replace(uid, gid):
            calls.append(None)
            if len(calls) == 2:
                assert scrubbed == [True], "production inherited cleanup must run first"
                path = directory / "run/azurelinux3s4-web/http.sock"
                previous = path.lstat()
                retained = path.with_name("retained-original.sock")
                path.rename(retained)
                # Allocate after the production scrubber, and retain this
                # listener through main(). An early EBADF cannot certify a
                # replacement or the production inode-change refusal.
                replacement = socket.socket(socket.AF_UNIX)
                replacements.append(replacement)
                replacement.bind(str(path))
                path.chmod(0o666)
                replacement.listen(1)
                current, preserved = path.lstat(), retained.lstat()
                old_id, new_id = (previous.st_dev, previous.st_ino), (current.st_dev, current.st_ino)
                assert old_id != new_id
                assert (preserved.st_dev, preserved.st_ino) == old_id
                assert stat.S_ISSOCK(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o666
                assert (current.st_uid, current.st_gid) == (uid, gid)
                assert replacement.getsockname() == str(path)
                assert replacement.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
                proof = {"original_identity": old_id, "replacement_identity": new_id,
                         "preserved_identity": (preserved.st_dev, preserved.st_ino),
                         "replacement_mode": current.st_mode, "replacement_uid": current.st_uid,
                         "replacement_gid": current.st_gid, "replacement_listener": True,
                         "inherited_cleanup_completed": True, "backend_path_call": len(calls),
                         "production_recheck_omitted": omitted}
                if omitted:
                    proof.update(original_connect_source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                                 removed_recheck_ast=removed[0], model_ast=ast.dump(tree))
                (directory / "replacement-proof.json").write_text(json.dumps(proof) + "\n")
            return original(uid, gid)

        RELAY.backend_path = replace
    elif mode != "normal":
        raise ValueError("unknown admission fixture")
    sys.argv = ["worker"]
    try:
        return RELAY.main()
    finally:
        if mode in ("replace-leaf", "replace-leaf-without-recheck"):
            for replacement in replacements:
                try:
                    replacement.close()
                except OSError as error:
                    # The positive omission model reaches the unchanged
                    # production extra-FD scrubber, which closes this listener.
                    if error.errno != errno.EBADF:
                        raise


if __name__ == "__main__":
    sys.exit(main())
