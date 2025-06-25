from abc import abstractmethod
from collections.abc import Callable
import contextlib
from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Generic, Literal, TypeVar
from pydantic import (
    BaseModel,
    TypeAdapter,
)
import re
import subprocess

from app.types import Config, UserConfig, UserGroup


def build_userstr_signature(data: dict[str, str]) -> str:
    data_bytes = TypeAdapter(dict[str, str]).dump_json(data)
    data_hex = data_bytes.hex()
    return f"bdd-manage-user-{data_hex}"


def build_userid(prefix: str, suffix: str) -> str:
    return f"{prefix}.{suffix}"


def get_userid(user: UserConfig, group: UserGroup) -> str:
    return build_userid(user.prefix, group.suffix)


@contextlib.contextmanager
def exception_context(msg: str):
    try:
        yield
    except Exception as ex:
        msg = f"{msg}: {ex.args[0]}" if ex.args else str(msg)
        ex.args = (msg,) + ex.args[1:]
        raise


def ensure(cond: Any, *ctx: str):
    if not cond:
        msg = ": ".join(("assertion failed",) + ctx)
        raise AssertionError(msg)


def opener_private(path: str, flags: int) -> int:
    return os.open(path, flags, 0o600)


def repr_cmdpart(s: str) -> str:
    r = repr(s)
    if r == f"'{s}'":
        return s
    else:
        return r


def repr_cmd(cmd: str | list[str]) -> str:
    if isinstance(cmd, str):
        return repr_cmdpart(cmd)
    else:
        return " ".join(repr_cmdpart(arg) for arg in cmd)


class UserBundle(BaseModel):
    user: UserConfig
    group: UserGroup
    id: str


def find_users_in_group(
    config: Config, group_name: str | None
) -> list[UserBundle] | None:
    if group_name == "":
        group_name = None
    user_bundles: list[UserBundle] = []
    group_found = False
    for group in config.groups:
        if group_name is not None and group.suffix != group_name:
            continue
        group_found = True
        for user in group.users:
            user_bundles.append(CmdBase.newbundle(user, group))
    if not group_found:
        return None
    return user_bundles


T = TypeVar("T", default=UserBundle)


@dataclass(kw_only=True)
class CmdBase(Generic[T]):
    type CmdSpec = list[str] | str
    type CmdArgs = dict[str, str] | Callable[[T], dict[str, str] | None]

    getid: Callable[[T], str]
    failures: dict[str, Exception]
    users: list[T] = field(default_factory=list[T])
    sequential: bool = True

    @staticmethod
    def newbundle(user: UserConfig, group: UserGroup) -> UserBundle:
        return UserBundle(
            user=user, group=group, id=build_userid(user.prefix, group.suffix)
        )

    def fail(self, data: T, exc: Exception, critical: bool):
        username = (self.getid)(data)
        if critical:
            self.failures[username] = exc
            print(f"user {username} critically failed: {exc}")
        else:
            print(f"subcommand for user {username} failed: {exc}")

    def runfunc(
        self,
        func: Callable[[T], None | Literal[False]],
        *,
        critical: bool = True,
        errortype: type[Exception] | tuple[type[Exception], ...] = Exception,
    ) -> tuple[int, int]:
        tries = 0
        oks = 0
        for data in self.users:
            if self.sequential and (self.getid)(data) in self.failures:
                continue
            # Run custom function
            tries += 1
            try:
                result = func(data)
                if result is False:
                    tries -= 1
                else:
                    oks += 1
            except errortype as err:
                self.fail(data, err, critical)
        return oks, tries

    def runcmd(
        self,
        cmd: CmdSpec,
        args: CmdArgs,
        *,
        cwd: Path | None = None,
        input: str | None = None,
        capture_output: bool = False,
        critical: bool = True,
    ):
        if len(self.users) == 0:
            return
        print(
            f"$ {repr_cmd(cmd)}{'' if input is None else f' < {repr_cmdpart(input)}'}"
        )

        def run_it(data: T):
            # Personalize args
            user_args: dict[str, str]
            if isinstance(args, dict):
                user_args = args  # type: ignore
            else:
                maybe_user_args = args(data)
                if maybe_user_args is None:
                    return False
                else:
                    user_args = maybe_user_args
            # Get input
            cmd_input = (
                None if input is None else input.format(**user_args).encode("utf-8")
            )
            # Run personalized cmd
            if isinstance(cmd, str):
                user_cmd = cmd.format(**user_args)
                exit_status = os.system(user_cmd)
                if exit_status != 0:
                    raise RuntimeError(f"command failed: '{user_cmd}'")
            else:
                user_cmd = [arg.format(**user_args) for arg in cmd]
                subprocess.run(
                    user_cmd,
                    check=True,
                    cwd=cwd,
                    input=cmd_input,
                    capture_output=capture_output,
                )

        oks, tries = self.runfunc(
            run_it,
            critical=critical,
            errortype=(subprocess.CalledProcessError, RuntimeError),
        )
        print(f"    executed {tries} times, failed {tries - oks} times")

    def runsql(self, query: str, args: CmdArgs):
        query_simplified = re.sub(r"\s+", " ", query.strip())
        self.runcmd(
            ["sudo", "-u", "postgres", "psql", "-c", query_simplified],
            args,
            cwd=Path("/"),
        )

    @abstractmethod
    def exec(self) -> None: ...
