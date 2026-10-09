"""Admit one protected explicit server manifest; never modify the host."""

import contextlib as dep_context
import hashlib as dep_hash
import json as dep_json
import os as dep_os
import re as dep_re
import stat as dep_stat


DEP_SOURCE_LIMIT = 64 * 1024
DEP_TRUSTED_UID = 0
DEP_OPEN = dep_os.O_RDONLY | dep_os.O_NOFOLLOW | dep_os.O_NONBLOCK | dep_os.O_CLOEXEC


def deployment_path(value):
    if (type(value) is not str or not 2 <= len(value) <= 1024
            or not dep_re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value)):
        raise ValueError('explicit canonical absolute manifest path required')
    parts = value[1:].split('/')
    if len(parts) > 16 or any(part in ('.', '..') or len(part) > 255 for part in parts):
        raise ValueError('manifest path bounds')
    return parts


def deployment_identity(info):
    # atime can change from the actual reads and is not a correspondence field.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def deployment_directory(info):
    if (not dep_stat.S_ISDIR(info.st_mode) or info.st_uid != DEP_TRUSTED_UID
            or info.st_mode & 0o022):
        raise ValueError('unprotected manifest ancestry')


def deployment_leaf(info):
    if (not dep_stat.S_ISREG(info.st_mode) or info.st_uid != DEP_TRUSTED_UID
            or info.st_gid != DEP_TRUSTED_UID or info.st_nlink != 1
            or dep_stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= DEP_SOURCE_LIMIT):
        raise ValueError('manifest must be a bounded root-owned single-link 0600 file')


def deployment_bytes(fd):
    result = bytearray()
    while True:
        chunk = dep_os.read(fd, min(8192, DEP_SOURCE_LIMIT + 1 - len(result)))
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > DEP_SOURCE_LIMIT:
            raise ValueError('actual manifest EOF bound')


def deployment_read(path):
    parts = deployment_path(path)
    if dep_os.geteuid() != DEP_TRUSTED_UID:
        raise ValueError('protected manifest observation requires root')
    # ExitStack ordinary checked closes finish before any data is returned.
    with dep_context.ExitStack() as stack:
        root = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY)
        stack.callback(dep_os.close, root)
        initial_root = dep_os.fstat(root)
        deployment_directory(initial_root)
        held = [(root, initial_root)]
        links = []
        parent = root
        for name in parts[:-1]:
            before = dep_os.stat(name, dir_fd=parent, follow_symlinks=False)
            deployment_directory(before)
            child = dep_os.open(name, DEP_OPEN | dep_os.O_DIRECTORY, dir_fd=parent)
            stack.callback(dep_os.close, child)
            current = dep_os.fstat(child)
            deployment_directory(current)
            if deployment_identity(before) != deployment_identity(current):
                raise ValueError('manifest directory changed on open')
            links.append((parent, name, before))
            held.append((child, current))
            parent = child
        name = parts[-1]
        before = dep_os.stat(name, dir_fd=parent, follow_symlinks=False)
        deployment_leaf(before)
        fd = dep_os.open(name, DEP_OPEN, dir_fd=parent)
        stack.callback(dep_os.close, fd)
        initial = dep_os.fstat(fd)
        deployment_leaf(initial)
        if deployment_identity(before) != deployment_identity(initial):
            raise ValueError('manifest changed on open')
        first = deployment_bytes(fd)
        dep_os.lseek(fd, 0, dep_os.SEEK_SET)
        second = deployment_bytes(fd)
        if first != second or len(first) != initial.st_size:
            raise ValueError('manifest bytes changed')
        for observed in (dep_os.fstat(fd), dep_os.stat(name, dir_fd=parent, follow_symlinks=False)):
            deployment_leaf(observed)
            if deployment_identity(observed) != deployment_identity(initial):
                raise ValueError('manifest leaf changed')
        for directory, previous in held:
            current = dep_os.fstat(directory)
            deployment_directory(current)
            if deployment_identity(current) != deployment_identity(previous):
                raise ValueError('manifest ancestry changed')
        for directory, entry, previous in links:
            if deployment_identity(dep_os.stat(entry, dir_fd=directory, follow_symlinks=False)) != deployment_identity(previous):
                raise ValueError('manifest directory path changed')
        fresh = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY)
        stack.callback(dep_os.close, fresh)
        if deployment_identity(dep_os.fstat(fresh)) != deployment_identity(initial_root):
            raise ValueError('manifest root changed')
    return first


def deployment_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate manifest key')
        result[key] = value
    return result


def deployment_decode(data):
    if (type(data) is not bytes or not 0 < len(data) <= DEP_SOURCE_LIMIT
            or not data.endswith(b'\n') or any(byte < 32 and byte != 10 or byte > 126 for byte in data)):
        raise ValueError('bounded ASCII/LF manifest required')
    result = dep_json.loads(data, object_pairs_hook=deployment_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite manifest number')))
    return result, {'bytes': len(data), 'sha256': dep_hash.sha256(data).hexdigest()}
