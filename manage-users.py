#!/usr/bin/env python3

# Script para crear, destruir y manejar usuarios.
# Correr el comando con el argumento `--help` para ver la descripcion y posibles comandos.

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
import re
import sys
import subprocess
import os


def parse_args() -> argparse.Namespace:
    # Manejo de parametros
    p = argparse.ArgumentParser(
        description="""
    Crear, destruir o manejar usuarios.

    Se necesita una lista de usuarios en formato CSV, con RUN, Nro de alumno e ID de usuario.
    Ver el archivo `lista_alumnos.csv.example` para el formato.

    Subcomandos:
    - create: Crea los usuarios de la lista. El parametro `--template` permite inicializar sus carpetas home con archivos iniciales.
    - destroy: Elimina los usuarios de la lista y sus respectivos archivos.
    - lock: Bloquea la cuenta de todos los usuarios de la lista.
    - unlock: Desbloquea las cuentas de todos los usuarios de la lista.
    - kick: Detiene las conexiones actuales de todos los usuarios de la lista.
    """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("lista_alumnos", help="Archivo .csv con la lista de alumnos")
    p.add_argument(
        "accion",
        choices=["create", "destroy", "lock", "unlock", "kick"],
        help="Qué acción realizar",
    )
    p.add_argument(
        "--template",
        help="Directorio con los archivos default que cada usuario tendrá en su carpeta home",
    )
    return p.parse_args()


@dataclass
class User:
    """
    Datos de un usuario.
    """

    id: str
    n_alumno: str
    run: str
    seccion: str = ""


# Regular expressions que matchean con los nombres de los distintos campos del .csv
# Case-insensitive
FIELDS = {
    "run": r"run",
    "n_alumno": r"n.{0,3}\salumno",
    "seccion": r"secci.{1,3}n",
    "id": r"u?id",
}


def ensure(cond: bool, *ctx):
    """
    Si `cond` es falso, imprime un error y termina.
    """

    if not cond:
        print(": ".join(("assertion failed",) + ctx))
        sys.exit(1)


def validate_users(users: dict[str, User]):
    """
    Asegurarse que los datos de los usuarios sean validos.
    """
    ensure(len(users) > 0, "no users found in csv file")
    for user in users.values():
        ctx = f"user {user}"
        ensure(re.fullmatch(r"[a-zA-Z0-9._-]{1,24}", user.id), "user id", ctx)
        ensure(re.fullmatch(r"[a-zA-Z]", user.id[0]), "user id start", ctx)
        ensure(re.fullmatch(r"[a-zA-Z0-9]", user.id[-1]), "user id end", ctx)
        ensure(re.fullmatch(r"[0-9A-Za-z]{1,30}", user.n_alumno), "n alumno", ctx)
        ensure(re.fullmatch(r"[0-9]{1,12}-[0-9Kk]", user.run), "run", ctx)
        ensure(re.fullmatch(r"[0-9]{1,3}", user.seccion), "seccion", ctx)
    sections = {user.seccion for user in users.values()}
    if len(sections) > 1:
        print(
            f"trabajando con {len(users)} usuarios de las secciones {', '.join(sections)}"
        )


def read_users(conf: argparse.Namespace) -> dict[str, User]:
    """
    Leer el CSV de los usuarios.
    """
    try:
        users: dict[str, User] = {}
        list_path = Path(__file__).with_name(conf.lista_alumnos)
        with open(list_path, encoding="utf-8", newline="") as file:
            line = 0
            for row in csv.DictReader(file):
                ctx = f"row at line {line} ({row})"
                line += 1
                userdata = {}
                for key, pattern in FIELDS.items():
                    regex = re.compile(pattern, re.IGNORECASE)
                    value = None
                    for k, v in row.items():
                        if regex.fullmatch(k):
                            ensure(
                                value is None,
                                f"duplicate field {key}",
                                ctx,
                            )
                            value = v
                    ensure(
                        value is not None,
                        f"missing field {key}",
                        ctx,
                    )
                    userdata[key] = value
                user = User(**userdata)
                ensure(user.id not in users, f"duplicate user {user.id}")
                users[user.id] = user
        validate_users(users)
        print(f"read {len(users)} valid users")
        return users
    except FileNotFoundError:
        print(
            f"no se encontro la lista de alumnos en '{conf.lista_alumnos}'",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    conf = parse_args()
    users = read_users(conf)

    match conf.accion:
        case "create":
            # Codigo para crear los usuarios
            for user in users.values():
                name = user.id
                pwd = user.n_alumno
                subprocess.run(
                    ["sudo", "useradd", name, "-s", "/bin/bash", "-m"], check=True
                )
                subprocess.run(
                    ["sudo", "passwd", name], input=f"{pwd}\n{pwd}\n".encode()
                )
                subprocess.run(["sudo", "chmod", "-R", "2750", f"/home/{name}"])
                subprocess.run(
                    ["sudo", "chown", "-R", f"{name}:www-data", f"/home/{name}"]
                )
                if conf.template:
                    ensure(
                        Path(conf.template).is_dir(),
                        f"template path '{conf.template}' is not a directory",
                    )
                    os.system(
                        f"sudo -u {name} cp -r {Path(conf.template).joinpath('*')} /home/{name}/"
                    )
                print(f"created user {name}")
        case "destroy":
            # Codigo para destruir los usuarios
            for user in users.values():
                subprocess.run(["sudo", "deluser", user.id, "--remove-home"])
                print(f"deleted user {user.id}")
        case "lock":
            # Codigo para bloquear los usuarios
            for user in users.values():
                subprocess.run(["sudo", "passwd", "-l", user.id])
                print(f"locked user {user.id}")
        case "unlock":
            # Codigo para desbloquear los usuarios
            for user in users.values():
                subprocess.run(["sudo", "passwd", "-u", user.id])
                print(f"unlocked user {user.id}")
        case "kick":
            # Codigo para matar los procesos de los usuarios
            for user in users.values():
                subprocess.run(["killall", "-9", "--user", user.id])
                print(f"killed processes of user {user.id}")
        case _:
            raise RuntimeError(f"unknown action {conf.accion}")

    print("done")

    # sshd_config = "\n\n".join(
    #     f"Match User {user.id}\n    PasswordAuthentication yes" for user in users.values()
    # )
    #
    # os.makedirs("/etc/ssh/sshd_config.d", exist_ok=True)
    # Path("/etc/ssh/sshd_config.d/10-password-login-for-users.conf").write_text(sshd_config)
