import contextlib
import os
from typing import Any
from pydantic import (
    TypeAdapter,
)


def build_userstr_signature(data: dict[str, str]) -> str:
    data_bytes = TypeAdapter(dict[str, str]).dump_json(data)
    data_hex = data_bytes.hex()
    return f"bdd-manage-user-{data_hex}"


def build_userid(prefix: str, suffix: str) -> str:
    return f"{prefix}.{suffix}"


@contextlib.contextmanager
def exception_context(msg: str):
    try:
        yield
    except Exception as ex:
        msg = f"{msg}: {ex.args[0]}" if ex.args else str(msg)
        ex.args = (msg,) + ex.args[1:]
        raise


def ensure(cond: Any, *ctx):
    if not cond:
        msg = ": ".join(("assertion failed",) + ctx)
        raise AssertionError(msg)


def opener_private(path: str, flags: int) -> int:
    return os.open(path, flags, 0o600)
