from pathlib import Path
import sys
from typer import Typer
import typer
import string

from app.sync import sync_state
from app.util import CmdBase, find_users_in_group


app = Typer()


class RunCmd(CmdBase):
    cmd: str
    userdicts: dict[str, dict[str, str]]

    def exec(self):
        self.runcmd(self.cmd, lambda data: self.userdicts[data.id])


@app.command(
    "run",
    help="Correr un comando para cada usuario, reemplazando valores como {id}, {password} y otros por sus valores respectivos.",
)
def run_command_per_user(group_name: str | None, *, config_path: Path | None = None):
    """
    Código para correr un comando arbitrario por usuario
    """
    config = sync_state(config_path=config_path)
    if group_name == "":
        group_name = None

    command = str(typer.prompt("Ingresar comando", err=True)).strip()
    if not command:
        print("Error: no se ingresó un comando", file=sys.stderr)
        sys.exit(1)

    keys = {
        item[1] for item in string.Formatter().parse(command) if item[1] is not None
    }
    keys_without_id = keys - {"id"}

    user_bundles = find_users_in_group(config, group_name)
    group_found = user_bundles is not None
    user_bundles = user_bundles or []

    userdicts: dict[str, dict[str, str]] = {}
    for bundle in user_bundles:
        userdict: dict[str, str] = {}
        for key, val in bundle.user.model_dump():
            userdict[key] = str(val)
        userdicts[bundle.id] = userdict

    valid_users: set[str] = {
        username
        for username, userdict in userdicts.items()
        if keys_without_id.issubset(userdict.keys())
    }
    invalid_users = set(userdicts.keys()) - valid_users

    if keys:
        print(f'El comando "{command}" utiliza los atributos {", ".join(keys)}.')
    if len(userdicts) == 0:
        if sum(len(group.users) for group in config.groups) == 0:
            print("No hay usuarios en el sistema. No se corrió ningún comando.")
        elif group_found:
            print(f"No hay usuarios en el grupo {group_name}.")
        else:
            print(f'No existe el grupo "{group_name}".')
        return
    if invalid_users:
        if not valid_users:
            print(
                "Ningún usuario tiene todos los atributos necesarios definidos. Revisa que estén bien escritos."
            )
            sys.exit(1)
        print(
            f"{len(invalid_users)}/{len(userdicts)} usuarios tienen estos atributos indefinidos"
        )
        print(f"Se ignorarán estos usuarios: {', '.join(sorted(invalid_users))}")
        typer.confirm(
            f"Confirmas que quieres correr el comando solo para {len(valid_users)}/{len(userdicts)} usuarios?"
        )

    runcmd = RunCmd(
        failures={},
        getid=lambda data: data.id,
        users=user_bundles,
        cmd=command,
        userdicts=userdicts,
    )
    runcmd.exec()
