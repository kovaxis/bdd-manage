"""
Utilities to run a function in a subprocess (ie. as a different user, or within tmux).
"""

from collections.abc import Callable
import getpass
import os
from pathlib import Path
import subprocess
import sys
from typing import TypeVar

from pydantic import BaseModel, ValidationError
from typer import Typer


app = Typer()


_id_to_func: dict[
    str, tuple[Callable[[BaseModel], BaseModel], type[BaseModel], type[BaseModel]]
] = {}
_func_to_id: dict[Callable[[BaseModel], BaseModel], str] = {}

P = TypeVar("P", bound=BaseModel)
R = TypeVar("R", bound=BaseModel)


def register_subrun_func(id: str, param: type[P], ret: type[R], func: Callable[[P], R]):
    _id_to_func[id] = (func, param, ret)  # type: ignore
    _func_to_id[func] = id  # type: ignore


@app.command("_subrun", hidden=True)
def subrun(id: str) -> None:
    if id not in _id_to_func:
        raise RuntimeError("invalid subrun function id")
    func, param_ty, ret_ty = _id_to_func[id]
    args = param_ty.model_validate_json(sys.stdin.read())
    ret = func(args)
    print()
    print(ret_ty.model_dump_json(ret))


def run_as_user(user: str | None, func: Callable[[P], R], args: P) -> R:
    assert func in _func_to_id
    subrun_id = _func_to_id[func]  # type: ignore
    lookedup_func, param_ty, ret_ty = _id_to_func[subrun_id]
    if (
        (user == "root" and os.geteuid() == 0)
        or getpass.getuser() == user
        or user is None
    ):
        # No need to run as a different user
        ret = ret_ty.model_validate_json(
            lookedup_func(
                param_ty.model_validate_json(args.model_dump_json())
            ).model_dump_json()
        )
        return ret  # type: ignore
    completed = subprocess.run(
        [
            "sudo",
        ]
        + ([] if user == "root" else ["-u", user])
        + [
            f"ORIGINAL_PWD={os.getcwd()}",
            "ALLOW_ROOT=true",
            "uv",
            "run",
            "python",
            "-m",
            "app.main",
            "_subrun",
            subrun_id,
        ],
        cwd=Path(sys.argv[0]).parent.parent,
        stdout=subprocess.PIPE,
        input=args.model_dump_json().encode(),
    )
    if completed.returncode != 0:
        sys.stdout.buffer.write(completed.stdout)
    completed.check_returncode()
    for line in completed.stdout.split(b"\n"):
        try:
            ret = ret_ty.model_validate_json(line)
            return ret  # type: ignore
        except ValidationError:
            pass
    raise RuntimeError("subrun did not print resulting value")
