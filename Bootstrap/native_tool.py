"""Shared held-executable admission for explicit local developer-native checks."""

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import time

SPEC = importlib.util.spec_from_file_location('native_tool_release', Path(__file__).with_name('release.py'))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
OUTPUT_LIMIT = 1024 * 1024


class PinnedExecutable:
    def __init__(self, stack, expected, *, path, label, environment, timeout=10):
        self.path, self.label = path, label
        self.environment, self.timeout = dict(environment), timeout
        self.leaf = Path(path).name
        if type(expected) is not str or not re.fullmatch('[0-9a-f]{64}', expected):
            raise ValueError('explicit expected native executable SHA256 required')
        self.links = []
        self.parent = RELEASE.anchor(stack, str(Path(path).parent), self.links)
        self.fd = os.open(self.leaf, RELEASE.READ, dir_fd=self.parent)
        stack.callback(os.close, self.fd)
        self.before = os.fstat(self.fd)
        if (not stat.S_ISREG(self.before.st_mode) or self.before.st_uid != 0
                or self.before.st_nlink != 1 or self.before.st_mode & 0o7022
                or not self.before.st_mode & 0o111 or not 0 < self.before.st_size <= 32 * 1024 * 1024):
            raise ValueError('bounded protected root-owned native executable required')
        self.expected, self.commands = expected, []
        self.check()

    def check(self):
        for _ in range(2):
            os.lseek(self.fd, 0, os.SEEK_SET)
            digest, size = hashlib.sha256(), 0
            while True:
                raw = os.read(self.fd, min(128 * 1024, self.before.st_size + 1 - size))
                if not raw: break
                size += len(raw); digest.update(raw)
                if size > self.before.st_size: raise ValueError(self.label + ' executable changed size')
            if size != self.before.st_size or digest.hexdigest() != self.expected:
                raise ValueError(self.label + ' executable pin mismatch')
        for current in (os.fstat(self.fd), os.stat(self.leaf, dir_fd=self.parent, follow_symlinks=False)):
            if RELEASE.identity(current) != RELEASE.identity(self.before):
                raise ValueError(self.label + ' executable identity changed')
        RELEASE.check_links(self.links)

    def run(self, arguments, raw=b'', descriptors=()):
        # Tools supply fixed commands/environments; no CLI selects this path.
        # Retained descriptors are inherited only for these explicit input bytes.
        self.check()
        start = time.monotonic()
        child = subprocess.run([self.path, *arguments], executable='/proc/self/fd/' + str(self.fd),
                               pass_fds=(self.fd, *descriptors), input=raw, capture_output=True,
                               env=self.environment, cwd='/', timeout=self.timeout, check=False)
        self.commands.append({'arguments': list(arguments), 'actual_returncode': child.returncode,
                              'elapsed_seconds': time.monotonic() - start,
                              'stdout_bytes': len(child.stdout), 'stderr_bytes': len(child.stderr),
                              'stdout_sha256': hashlib.sha256(child.stdout).hexdigest(),
                              'stderr_sha256': hashlib.sha256(child.stderr).hexdigest()})
        self.last_stdout, self.last_stderr = child.stdout, child.stderr
        if (child.returncode != 0 or len(child.stdout) > OUTPUT_LIMIT or len(child.stderr) > OUTPUT_LIMIT):
            raise ValueError('local ' + self.label + ' check refused')
        self.check()
        return child.stdout
