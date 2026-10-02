"""POSIX held-descriptor snapshot; target bytes are never imported or executed."""

import os
import stat


class InputUnavailable(Exception):
    def __init__(self, code):
        self.code = code


def snapshot(path, maximum):
    if (
        os.name != "posix"
        or os.open not in os.supports_dir_fd
        or not all(
            hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
        )
    ):
        raise InputUnavailable("snapshot_platform_unsupported")
    if type(path) is not str or not path or "\0" in path or ".." in path.split(os.sep):
        raise InputUnavailable("invalid_input_path")
    if type(maximum) is not int or not 1 <= maximum <= 16 * 1024 * 1024:
        raise InputUnavailable("invalid_input_budget")
    components = os.path.abspath(path).split(os.sep)[1:]
    if not components or not components[-1]:
        raise InputUnavailable("invalid_input_path")
    descriptors = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        current = os.open(os.sep, directory_flags)
        descriptors.append(current)
        for component in components[:-1]:
            if component:
                current = os.open(component, directory_flags, dir_fd=current)
                descriptors.append(current)
        target = os.open(
            components[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=current,
        )
        descriptors.append(target)
        before = os.fstat(target)
        if not stat.S_ISREG(before.st_mode):
            raise InputUnavailable("input_not_regular")
        if before.st_size > maximum:
            raise InputUnavailable("input_bytes_budget")
        chunks, size = [], 0
        while size <= maximum:
            block = os.read(target, min(65536, maximum + 1 - size))
            if not block:
                break
            size += len(block)
            chunks.append(block)
        after = os.fstat(target)
        keys = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if size > maximum:
            raise InputUnavailable("input_bytes_budget")
        if size != after.st_size or any(
            getattr(before, key) != getattr(after, key) for key in keys
        ):
            raise InputUnavailable("input_changed_during_snapshot")
        return b"".join(chunks)
    except (OSError, ValueError):
        raise InputUnavailable("input_snapshot_unavailable") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
