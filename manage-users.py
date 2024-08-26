#!/usr/bin/env python3

# Script para crear, destruir y manejar usuarios.
# Correr el comando con el argumento `--help` para ver la descripcion y posibles comandos.

import argparse
import contextlib
import csv
from dataclasses import dataclass
import dataclasses
from datetime import datetime
from pathlib import Path
import re
import sys
import subprocess
import os
import traceback
from hashlib import blake2b as good_hash


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
    - scan: Escanear las carpetas HOME y recordar información sobre la fecha de entrega.
    """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("lista_alumnos", help="Archivo .csv con la lista de alumnos")
    p.add_argument(
        "accion",
        choices=["create", "destroy", "lock", "unlock", "kick", "scan"],
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
    run: str = ""
    section: str = ""


@dataclass
class UserScan:
    """
    Datos de entrega de un usuario.
    """

    id: str
    ultimo_cambio_detectado: datetime
    hash: str
    mtime: datetime


@contextlib.contextmanager
def exception_context(msg: str):
    try:
        yield
    except Exception as ex:
        msg = f"{msg}: {ex.args[0]}" if ex.args else str(msg)
        ex.args = (msg,) + ex.args[1:]
        raise


def ensure(cond: bool, *ctx):
    """
    Si `cond` es falso, imprime un error y termina.
    """

    if not cond:
        msg = ": ".join(("assertion failed",) + ctx)
        raise AssertionError(msg)


def find_field(record: dict[str, str], regex: str) -> str | None:
    value = None
    for k, v in record.items():
        if re.fullmatch(regex, k, re.IGNORECASE):
            if value is not None:
                raise RuntimeError(f"duplicate field {k}")
            value = v
    return value


def get_field(record: dict[str, str], regex: str) -> str:
    value = find_field(record, regex)
    if value is None:
        raise RuntimeError(f"field {regex} not found")
    return value


def read_user(record: dict[str, str]) -> User:
    uid = find_field(record, r"u?id")
    if uid is None:
        email = get_field(record, r"e-?mail")
        ensure("@" in email, "email @")
        uid = email[: email.find("@")]
    return User(
        id=uid,
        n_alumno=get_field(record, r"n.{0,3}\salumno"),
        section=find_field(record, r"secci.{0,3}n") or "",
        run=find_field(record, r"run") or "",
    )


def validate_users(users: dict[str, User]):
    """
    Asegurarse que los datos de los usuarios sean validos.
    """
    ensure(len(users) > 0, "no users found in csv file")
    for user in users.values():
        with exception_context(f"user {user}"):
            ensure(re.fullmatch(r"[a-zA-Z0-9._-]{1,24}", user.id), "user id")
            ensure(re.fullmatch(r"[a-zA-Z]", user.id[0]), "user id start")
            ensure(re.fullmatch(r"[a-zA-Z0-9]", user.id[-1]), "user id end")
            ensure(re.fullmatch(r"[0-9A-Za-z]{1,30}", user.n_alumno), "n alumno")
            ensure(re.fullmatch(r"[0-9]{1,12}-[0-9Kk]", user.run), "run")


def read_users(list_path: Path) -> dict[str, User]:
    """
    Leer el CSV de los usuarios.
    """
    try:
        users: dict[str, User] = {}
        with open(list_path, encoding="utf-8", newline="") as file:
            line = 0
            for row in csv.DictReader(file):
                line += 1
                with exception_context(f"row at line {line} ({row})"):
                    user = read_user(row)
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


def read_userscan(path: Path) -> dict[str, UserScan]:
    """
    Leer un CSV de scans de usuarios.
    """
    with exception_context(f"leyendo csv de userscan en {path}"):
        userscan = {}
        fields = dataclasses.fields(UserScan)
        with open(path, encoding="utf-8", newline="") as file:
            for row in csv.DictReader(file):
                args = {}
                for field in fields:
                    if field.name in row:
                        x = row[field.name]
                        if field.type is datetime:
                            x = datetime.fromisoformat(x)
                        args[field.name] = x
                user = UserScan(**args)
                userscan[user.id] = user
        return userscan


def write_userscan(path: Path, userscan: dict[str, UserScan]):
    with exception_context(f"escribiendo csv de usercan en {path}"):
        with open(path, encoding="utf-8", newline="") as file:
            fields = dataclasses.fields(UserScan)
            writer = csv.DictWriter(file, fieldnames=[field.name for field in fields])
            writer.writeheader()
            for user in userscan.values():
                row = {}
                for field in fields:
                    x = getattr(user, field.name)
                    if field.type is datetime:
                        x = datetime.isoformat(x)
                    row[field.name] = x
                writer.writerow(row)


def hash_filesystem(path: Path, root: Path | None = None) -> bytes:
    if root is None:
        root = path
    hx = good_hash()
    hx.update(b"d" if path.is_dir() else b"f")
    hx.update(path.relative_to(root).as_posix().encode())
    if path.is_dir():
        hashes: list[str] = []
        for subfile in path.iterdir():
            hashes.append(hash_filesystem(subfile))
        hashes.sort()
        for h in hashes:
            hx.update(h)
    else:
        hx.update(path.read_bytes())
    return hx.digest()


def get_mtime(path: Path) -> datetime:
    t = datetime.fromtimestamp(path.lstat().st_mtime)
    if path.is_dir():
        for subpath in path.iterdir():
            t = max(t, get_mtime(subpath))
    return t


if __name__ == "__main__":
    conf = parse_args()
    users = read_users(Path(__file__).with_name(conf.lista_alumnos))

    match conf.accion:
        case "create":
            # Codigo para crear los usuarios
            for user in users.values():
                try:
                    name = user.id
                    pwd = user.n_alumno
                    subprocess.run(
                        ["sudo", "useradd", name, "-s", "/bin/bash", "-m"], check=True
                    )
                    subprocess.run(
                        ["sudo", "passwd", name],
                        input=f"{pwd}\n{pwd}\n".encode(),
                        check=True,
                    )
                    subprocess.run(
                        ["sudo", "chmod", "-R", "2750", f"/home/{name}"], check=True
                    )
                    subprocess.run(
                        ["sudo", "chown", "-R", f"{name}:www-data", f"/home/{name}"],
                        check=True,
                    )
                    if conf.template:
                        ensure(
                            Path(conf.template).is_dir(),
                            f"template path '{conf.template}' is not a directory",
                        )
                        ensure(
                            os.system(
                                f"sudo -u {name} cp -r {Path(conf.template).joinpath('*')} /home/{name}/"
                            )
                            == 0,
                            "copying home template failed",
                        )
                    print(f"created user {name}")
                except subprocess.CalledProcessError:
                    traceback.print_exc()
                    print(f"failed to create user {user.id}")
        case "destroy":
            # Codigo para destruir los usuarios
            for user in users.values():
                try:
                    subprocess.run(["sudo", "deluser", user.id, "--remove-home"])
                    print(f"deleted user {user.id}")
                except subprocess.CalledProcessError:
                    traceback.print_exc()
                    print(f"failed to destroy user {user.id}")
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
        case "scan":
            # Código para escanear las carpetas HOME y determinar horas de entrega
            scantime = datetime.now()
            scan_path = Path(conf.lista_alumnos)
            scan_path = scan_path.with_stem(scan_path.stem + "_scan")
            userscan: dict[str, UserScan] = {}
            if scan_path.exists():
                userscan = read_userscan(scan_path)
            try:
                for user in users.values():
                    subprocess.run(["sudo", "passwd", "-l", user.id])
                print("locked all users")
                for user in users.values():
                    home = Path(f"/home/{user.id}")
                    h = hash_filesystem(home).hex()
                    mtime = get_mtime(home)
                    old = userscan.get(user.id)
                    oldh = None if old is None else old.hash
                    change = scantime if h != oldh else old.ultimo_cambio_detectado
                    userscan[user.id] = UserScan(
                        id=user.id,
                        ultimo_cambio_detectado=change,
                        hash=h,
                        mtime=mtime,
                    )
                    print(f"scanned user {user.id}")
                write_userscan(scan_path, userscan)
            finally:
                for user in users.values():
                    try:
                        for user in users.values():
                            subprocess.run(["sudo", "passwd", "-u", user.id])
                    except subprocess.CalledProcessError:
                        traceback.print_exc()
                print("unlocked users")

        case _:
            raise RuntimeError(f"unknown action {conf.accion}")

    print("done")

    # sshd_config = "\n\n".join(
    #     f"Match User {user.id}\n    PasswordAuthentication yes" for user in users.values()
    # )
    #
    # os.makedirs("/etc/ssh/sshd_config.d", exist_ok=True)
    # Path("/etc/ssh/sshd_config.d/10-password-login-for-users.conf").write_text(sshd_config)
