import csv
from pathlib import Path
import sys
import traceback
from typing import Annotated
from pydantic import (
    BaseModel,
    StringConstraints,
    TypeAdapter,
    ValidationError,
)

from app.types import DEFAULT_CONFIG_PATH, Config, UserGroup
from app.types import (
    USERNAME_PATTERN,
    USERSTR_SIGNATURE_PATTERN,
    SystemUser,
    SystemUsers,
    UserConfig,
    UserConfigBase,
)
from app.util import build_userid, ensure, exception_context


class UserGroupProto(BaseModel):
    suffix: Annotated[str, StringConstraints(pattern=r"[a-zA-Z0-9\-_]{1,24}")]
    base: UserConfigBase = UserConfigBase()
    users: list[UserConfig]
    csv: dict[str, str]


class ConfigProto(BaseModel):
    base: UserConfigBase
    groups: list[UserGroupProto]


EXAMPLE_CFG: ConfigProto = ConfigProto(
    base=UserConfigBase(),
    groups=[
        UserGroupProto(
            suffix="example",
            base=UserConfigBase(),
            users=[],
            csv={
                "example-userlist": "",
            },
        )
    ],
)


def read_system_users() -> SystemUsers:
    """
    Leer la lista de usuarios presentes en el sistema.
    Cada usuario tiene un diccionario de atributos asociados.
    """
    users: list[SystemUser] = []
    with Path("/etc/passwd").open() as passwd_file:
        for userline in passwd_file:
            userfields = userline.split(":")
            username = userfields[0]
            usercomment = userfields[4]
            idmat = USERNAME_PATTERN.fullmatch(username)
            sigmat = USERSTR_SIGNATURE_PATTERN.fullmatch(usercomment)
            if sigmat:
                if not idmat:
                    print(
                        f"WARNING: user {username} does not conform to username pattern, skipping"
                    )
                    continue
                try:
                    fields = TypeAdapter(dict[str, str]).validate_json(
                        bytes.fromhex(sigmat[1])
                    )
                except ValidationError as e:
                    print(
                        f"WARNING: user {username} has invalid `fields` string, skipping: {e}"
                    )
                    continue
                prefix = idmat[1]
                suffix = idmat[2]
                users.append(
                    SystemUser(id=username, prefix=prefix, suffix=suffix, fields=fields)
                )

    by_id = {user.id: user for user in users}
    by_group: dict[str, dict[str, SystemUser]] = {}
    for user in users:
        group_users = by_group.setdefault(user.suffix, {})
        group_users[user.prefix] = user
    return SystemUsers(as_list=users, by_id=by_id, by_group=by_group)


def read_config(cfg_path: Path | None) -> Config:
    """
    Leer una configuración de alumnos en formato JSON, posiblemente con CSV embebido.
    """

    if cfg_path is None:
        cfg_path = DEFAULT_CONFIG_PATH

    try:
        with exception_context(f"reading config file from '{cfg_path}'"):
            if not cfg_path.exists():
                cfg_path.write_bytes(EXAMPLE_CFG.model_dump_json(indent=4).encode())
                print(f"wrote example config to {cfg_path}")
            cfg = ConfigProto.model_validate_json(cfg_path.read_bytes())
        out = Config(groups=[])
        for groupproto in cfg.groups:
            with exception_context(f"group with suffix '{groupproto.suffix}'"):
                users_to_add: list[UserConfig] = []
                # Read users in JSON form
                for userproto in groupproto.users:
                    with exception_context(f"user '{userproto.prefix}'"):
                        userparams = cfg.base.model_dump()
                        userparams.update(groupproto.base.model_dump())
                        userparams.update(userproto.model_dump())
                        users_to_add.append(UserConfig.model_validate(userparams))
                # Read users in CSV form
                for csv_index, (csv_name, csv_string) in enumerate(
                    groupproto.csv.items()
                ):
                    with exception_context(f"csv '{csv_name}' at index {csv_index}"):
                        line = 0
                        for row in csv.DictReader(csv_string.splitlines()):
                            line += 1
                            with exception_context(f"row at line {line} ({row})"):
                                userparams = cfg.base.model_dump()
                                userparams.update(groupproto.base.model_dump())
                                userparams.update(row)
                                users_to_add.append(
                                    UserConfig.model_validate(userparams)
                                )
                seen_prefixes: set[str] = set()
                for user in users_to_add:
                    ensure(
                        user.prefix not in seen_prefixes,
                        f"Usuario duplicado: '{build_userid(user.prefix, groupproto.suffix)}'",
                    )
                    seen_prefixes.add(user.prefix)
                outgroup = UserGroup(suffix=groupproto.suffix, users=users_to_add)
                out.groups.append(outgroup)
        print(
            f"Read {sum(len(g.users) for g in out.groups)} users in {len(out.groups)} groups from {cfg_path}"
        )
        return out
    except ValidationError:
        traceback.print_exc()
        print("Configuración inválida.")
        print(
            "Prueba moviendo la configuración a una ubicación temporal y corre el comando de nuevo para regenerar la configuración de ejemplo."
        )
        sys.exit(1)
    except FileNotFoundError:
        print(
            f"No se encontró la configuración en '{cfg_path}'",
            file=sys.stderr,
        )
        sys.exit(1)
