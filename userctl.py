#!/usr/bin/env python3

# Script para crear, destruir y en general manejar usuarios.
# Correr el comando con el argumento `--help` para ver la descripcion y posibles comandos.

import argparse
import pkg_resources
import contextlib
import csv
import dataclasses
from datetime import datetime
from pathlib import Path
import re
import sys
import subprocess
import os
import traceback
from hashlib import blake2b as good_hash
from types import NoneType
from typing import Any, Optional, Union, get_args, get_origin


def autoinstall_deps(required_deps: dict[str, str]):
    installed = {pkg.key for pkg in pkg_resources.working_set}
    missing = sorted(set(required_deps) - installed)
    if missing:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--upgrade", "pip"]
        )
        subprocess.check_call([sys.executable, "-m", "pip", "install", *[required_deps[depname] for depname in missing]])


autoinstall_deps({
    "pydantic": "pydantic>=2.0.0,<3.0.0",
    "pydantic-argparse": "git+https://github.com/cody-mar10/pydantic-argparse.git@4a79a48aa393a8b8947229d40f297fbad5802ac1",
})

from pydantic import BaseModel, Field, ValidationError  # noqa: E402
import pydantic_argparse  # noqa: E402


SCRIPT_DIR: Path = Path(__file__).resolve().parent


class User(BaseModel):
    """
    Datos de un usuario.
    """

    id: str
    n_alumno: str
    run: str = ""
    section: str = ""


class FsInfo(BaseModel):
    name: bytes
    mtime: datetime
    contents: list["FsInfo"] | bytes


class UserScan(BaseModel):
    """
    Datos de entrega de un usuario.
    Un snapshot de la carpeta `home` del usuario.
    """

    home: FsInfo


class Scan(BaseModel):
    """
    Un escaneo hecho en una fecha/hora particular.
    """

    scantime: datetime
    users: dict[str, UserScan]


class ScanReport(BaseModel):
    """
    Un reporte de usuario hecho a partir de varios escaneos.
    """

    usuario: str
    ultimo_cambio_detectado: str
    ultimo_archivo_cambiado: str
    timestamp_escaneo: str
    tiene_archivo_php: str


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


USERSTR_SIGNATURE = "bdd-manage-userstring%"


def serialize_user(user: User) -> str:
    userstr = user.model_dump_json()
    userstr = userstr.replace("%", "%%")
    userstr = userstr.replace(":", "%.")
    userstr = USERSTR_SIGNATURE + userstr
    return userstr


def deserialize_user(userstr: str) -> User | None:
    if not userstr.startswith(USERSTR_SIGNATURE):
        return None
    userstr = userstr.removeprefix(USERSTR_SIGNATURE)
    userstr = userstr.replace("%.", ":")
    userstr = userstr.replace("%%", "%")
    return User.model_validate_json(userstr)


def read_system_users() -> dict[str, User]:
    """
    Leer la lista de usuarios presentes en el sistema.
    """
    users = {}
    with Path("/etc/passwd").open() as passwd_file:
        for userline in passwd_file:
            userfields = userline.split(":")
            username = userfields[0]
            usercomment = userfields[4]
            try:
                with exception_context(f"parsing user {username} in /etc/passwd"):
                    user = deserialize_user(usercomment)
                    if user:
                        ensure(user.id == username, "user id is not equal to username")
                        users[username] = user
            except Exception:
                traceback.print_exc()
    return users


def find_field_fuzzy(record: dict[str, str], regex: str) -> str | None:
    value = None
    for k, v in record.items():
        if re.fullmatch(regex, k, re.IGNORECASE):
            if value is not None:
                raise RuntimeError(f"duplicate field {k}")
            value = v
    return value


def get_field_fuzzy(record: dict[str, str], regex: str) -> str:
    value = find_field_fuzzy(record, regex)
    if value is None:
        raise RuntimeError(f"field {regex} not found")
    return value


def read_user_list(list_path: Path) -> dict[str, User]:
    """
    Leer una lista de usuarios en formato CSV.
    """

    def read_user(record: dict[str, str]) -> User:
        uid = find_field_fuzzy(record, r"u?id")
        if uid is None:
            email = get_field_fuzzy(record, r"e-?mail")
            ensure("@" in email, "email @")
            uid = email[: email.find("@")]
        return User(
            id=uid,
            n_alumno=get_field_fuzzy(record, r"n.{0,3}\salumno"),
            section=find_field_fuzzy(record, r"secci.{0,3}n") or "",
            run=find_field_fuzzy(record, r"ru[nt]") or "",
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
                    x = row.get(field.name)
                    if (
                        not (
                            get_origin(field.type) == Union
                            and NoneType in get_args(field.type)
                        )
                        and x is None
                    ):
                        raise RuntimeError(f"value for field {field.name} not found")
                    if field.type is datetime:
                        x = datetime.fromisoformat(x)
                    if field.type is bool:
                        x = bool(x)
                    args[field.name] = x
                user = UserScan(**args)
                userscan[user.id] = user
        return userscan


def write_userscan(path: Path, userscan: dict[str, UserScan]):
    with exception_context(f"escribiendo csv de usercan en {path}"):
        with open(path, "w", encoding="utf-8", newline="") as file:
            fields = dataclasses.fields(UserScan)
            writer = csv.DictWriter(file, fieldnames=[field.name for field in fields])
            writer.writeheader()
            for user in userscan.values():
                row = {}
                for field in fields:
                    x = getattr(user, field.name)
                    if field.type is datetime:
                        x = datetime.isoformat(x)
                    if field.type is bool:
                        x = str(x)
                    row[field.name] = x
                writer.writerow(row)


class AddArgs(pydantic_argparse.BaseCommand):
    lista: Path = Field(description="Lista de alumnos a agregar, en formato CSV.")
    template: Path = Field(
        Path("./user_template"),
        description="Directorio con los contenidos iniciales de la carpeta HOME para un usuario.",
    )

    def add_users(self, conf: "GlobalArgs"):
        """
        Código para añadir usuarios desde una lista de alumnos.
        """
        old_users = read_system_users()
        new_users = read_user_list(self.lista)
        created = 0
        for user in new_users.values():
            try:
                name = user.id
                pwd = user.n_alumno
                subprocess.run(
                    [
                        "sudo",
                        "useradd",
                        name,
                        "-s",
                        "/bin/bash",
                        "-m",
                        "-c",
                        serialize_user(user),
                    ],
                    check=True,
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
                if self.template.exists():
                    ensure(
                        self.template.is_dir(),
                        f"template path '{self.template}' is not a directory",
                    )
                    ensure(
                        os.system(
                            f"sudo -u {name} cp -r {self.template.joinpath('*')} /home/{name}/"
                        )
                        == 0,
                        "copying home template failed",
                    )
                print(f"created user {name}")
                created += 1
            except subprocess.CalledProcessError:
                traceback.print_exc()
                print(f"failed to create user {user.id}")
        new_users = read_system_users()
        print(
            f"existían {len(old_users)} usuarios de alumno, se crearon {created} usuarios nuevos, ahora existen {len(new_users)} usuarios de alumno"
        )


class RemoveArgs(pydantic_argparse.BaseCommand):
    keep: Optional[Path] = Field(
        None, description="No eliminar los usuarios que estén presentes en esta lista."
    )
    force: bool = Field(False, description="No preguntar por confirmación")

    def delete_users(self, conf: "GlobalArgs"):
        """
        Código para eliminar usuarios.
        """
        sys_users = read_system_users()
        keep = set()
        if self.keep:
            keep_list = read_user_list(self.keep)
            keep = set(keep_list.keys())
        delete_users = set(sys_users.keys()) - keep
        if delete_users and not self.force:
            print(f"se eliminarán {len(delete_users)}/{len(sys_users)} usuarios de alumnos. confirmar? (Y/n) ", end="", flush=True)
            if input().strip().lower() == "n":
                print("cancelado")
                sys.exit(1)
        for username in delete_users:
            user = sys_users[username]
            try:
                subprocess.run(["sudo", "deluser", user.id, "--remove-home"])
                print(f"deleted user {user.id}")
            except subprocess.CalledProcessError:
                traceback.print_exc()
                print(f"failed to destroy user {user.id}")
        new_users = read_system_users()
        print(
            f"existían {len(sys_users)} usuarios de alumno, se pidió no eliminar una lista de {len(keep)} alumnos, ahora hay {len(new_users)} usuarios de alumno"
        )


class ScanArgs(pydantic_argparse.BaseCommand):
    out: Optional[Path] = Field(
        None,
        description="Generar un reporte y almacenarlo en esta ruta en formato CSV.",
    )
    lock: bool = Field(
        False,
        description="Bloquear las cuentas de los usuarios mientras se realiza el escaneo.",
    )

    def scan_users(self, conf: "GlobalArgs"):
        """
        Código para escanear las carpetas HOME y determinar horas de entrega
        """
        scantime = datetime.now()
        users = read_system_users()

        # Escanear usuarios
        scan = self.do_scan(scantime, users)

        # Agregar escaneo al archivo .scandb
        db_path = SCRIPT_DIR.joinpath(".scandb")
        with exception_context(f"writing scan to {db_path}"):
            with db_path.open("a", encoding="utf-8") as db_file:
                db_file.write(scan.model_dump_json() + "\n")

        # Generar un reporte
        if self.out:
            all_scans = self.read_scandb(db_path)
            self.generate_report(all_scans, self.out)

    def do_scan(self, scantime: datetime, users: dict[str, User]) -> Scan:
        scan = Scan(scantime=scantime, users={})
        try:
            if self.lock:
                print("locking users")
                for user in users.values():
                    subprocess.run(["sudo", "passwd", "-l", user.id])
                print("locked all users")
            print(f"scanning {len(users)} users")
            for user in users.values():
                home = Path(f"/home/{user.id}")
                userscan = UserScan(home=self.visit_fs(home))
                scan.users[user.id] = userscan
                print(f"scanned user {user.id}")
        finally:
            if self.lock:
                print("unlocking users")
                for user in users.values():
                    try:
                        for user in users.values():
                            subprocess.run(["sudo", "passwd", "-u", user.id])
                    except subprocess.CalledProcessError:
                        traceback.print_exc()
                print("unlocked users")
        print(f"se escanearon {len(scan.users)} usuarios")
        return scan

    def visit_fs(self, path: Path) -> FsInfo:
        mtime = datetime.fromtimestamp(path.lstat().st_mtime)
        name = path.name.encode()
        if path.is_dir():
            contents: list[FsInfo] = []
            for subpath in path.iterdir():
                if not os.access(subpath, os.R_OK):
                    continue
                contents.append(self.visit_fs(subpath))
            contents.sort(key=lambda sub: sub.name)
        else:
            contents = good_hash(path.read_bytes()).digest()
        return FsInfo(name=name, mtime=mtime, contents=contents)

    def read_scandb(self, db_path: Path) -> list[Scan]:
        scans = []
        with exception_context(f"reading scan database from {db_path}"):
            with db_path.open() as db_file:
                line = 0
                for scanline in db_file:
                    line += 1
                    try:
                        scan = Scan.model_validate_json(scanline)
                        scans.append(scan)
                    except ValidationError:
                        traceback.print_exc()
                        print(f"failed to parse scan at line {line}, ignoring")
        return scans

    def generate_report(self, all_scans: list[Scan], out_path: Path):
        scans_by_user: dict[str, list[tuple[datetime, UserScan]]] = {}
        for scan in all_scans:
            for username, userscan in scan.users.items():
                scans_by_user.setdefault(username, []).append((scan.scantime, userscan))

        report: list[ScanReport] = []
        for username, scans in scans_by_user.items():
            scans.sort(key=lambda x: x[0])
            now_scantime, now_scan = scans[-1]
            now_hash = self.hash_scan(now_scan)
            change = self.get_scan_mtime(now_scan)
            for old_scantime, old_scan in reversed(scans[0:-1]):
                if self.hash_scan(old_scan) != now_hash:
                    change = max(change, (old_scantime, "mtime was tampered!"))
                    break
            report.append(
                ScanReport(
                    usuario=username,
                    ultimo_cambio_detectado=change[0].isoformat(),
                    ultimo_archivo_cambiado=change[1],
                    timestamp_escaneo=now_scantime.isoformat(),
                    tiene_archivo_php="SI" if self.has_php(now_scan.home) else "NO",
                )
            )

        with exception_context(f"writing userscan report at {out_path}"):
            with out_path.open("w", encoding="utf-8", newline="") as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=list(
                        ScanReport.model_json_schema()["properties"].keys()
                    ),
                )
                writer.writeheader()
                for user_report in report:
                    writer.writerow(user_report.model_dump())
        print(
            f"se genero un reporte de {len(report)} usuarios a partir de {len(all_scans)} escaneos"
        )

    def hash_scan(self, scan: UserScan) -> bytes:
        return self.hash_fsinfo(scan.home)

    def hash_fsinfo(self, info: FsInfo) -> bytes:
        hx = good_hash()
        hx.update(good_hash(info.name).digest())
        if isinstance(info.contents, bytes):
            hx.update("f")
            hx.update(info.contents)
        else:
            hx.update("d")
            hashes: list[bytes] = []
            for sub in info.contents:
                hashes.append(self.hash_fsinfo(sub))
            hashes.sort()
            for h in hashes:
                hx.update(h)
        return hx.digest()

    def get_scan_mtime(self, scan: UserScan) -> tuple[datetime, str]:
        return self.get_fsinfo_mtime(scan.home, "/") or (scan.home.mtime, "/")

    def get_fsinfo_mtime(
        self, fsinfo: FsInfo, path: str
    ) -> tuple[datetime, str] | None:
        if isinstance(fsinfo.contents, bytes):
            return (fsinfo.mtime, path + fsinfo.name.decode(errors="replace"))
        else:
            max_mtime: datetime | None = None
            for sub in fsinfo.contents:
                sub_mtime = self.get_fsinfo_mtime(
                    sub, path + fsinfo.name.decode(errors="replace") + "/"
                )
                if sub_mtime is not None and (
                    max_mtime is None or sub_mtime > max_mtime
                ):
                    max_mtime = sub_mtime
            return max_mtime

    def has_php(self, fsinfo: FsInfo) -> bool:
        if isinstance(fsinfo.contents, bytes):
            return fsinfo.name.decode(errors="replace").endswith(".php")
        else:
            for sub in fsinfo.contents:
                if self.has_php(sub):
                    return True
            return False


class RunArgs(pydantic_argparse.BaseCommand):
    command: str = Field(
        description="Comando a correr. Keywords como {id}, {run} o {n_alumno} se reemplazarán por los valores apropiados."
    )

    def run_command_per_user(self, conf: "GlobalArgs"):
        """
        Código para correr un comando arbitrario por usuario
        """
        users = read_system_users()
        print(f"corriendo comando para {len(users)} usuarios")
        ok_runs = 0
        for user in users.values():
            cmd = self.command
            cmd = cmd.replace("{id}", user.id)
            cmd = cmd.replace("{n_alumno}", user.n_alumno)
            cmd = cmd.replace("{run}", user.run)
            print(f'corriendo comando "{cmd}"')
            result = os.system(cmd)
            if result == 0:
                ok_runs += 1
            else:
                print(
                    f"el comando falló para el usuario {user.id} (exit code {result})"
                )
        print(f"{ok_runs}/{len(users)} comandos ejecutaron correctamente")


class GlobalArgs(BaseModel):
    create: Optional[AddArgs] = Field(
        description="Crear usuarios a partir de una lista de usuarios en formato CSV."
    )
    destroy: Optional[RemoveArgs] = Field(
        description="Eliminar usuarios, opcionalmente manteniendo una lista de usuarios."
    )
    scan: Optional[ScanArgs] = Field(
        description="Escanear las carpetas HOME de los usuarios para determinar las últimas fechas de modificación."
    )
    run: Optional[RunArgs] = Field(description="Correr un comando por cada usuario.")


def parse_args() -> GlobalArgs:
    parser = pydantic_argparse.ArgumentParser(GlobalArgs, description="Crear, destruir y manejar usuarios.")
    return parser.parse_typed_args()

    def is_types(ty: type[Any], allow: tuple[type[Any]]) -> bool:
        if ty in allow:
            return True
        if get_origin(ty) == Union:
            for subty in get_args(ty):
                if subty not in allow:
                    return False
            return True
        return False

    def populate_parser(parser: argparse.ArgumentParser, ty: BaseModel):
        nonlocal subcommand_i
        subparsers = None
        for fieldname, field in ty.model_fields.items():
            ty = field.annotation
            if is_types(ty, (str, NoneType)):
                # Add basic string arg
                parser.add_argument()
            elif is_types(ty, (int, NoneType)):
                pass
            elif is_types(ty, (float, NoneType)):
                pass
            elif is_types(ty, (bool, NoneType)):
                pass
            else:
                # Subcommand
                ty_args = get_args(ty)
                ensure(get_origin(ty) == Union)
                ensure(len(ty_args) == 2)
                ensure(NoneType in ty_args)
                subty = next(subty for subty in ty_args if subty is not NoneType)
                if subparsers is None:
                    subcommand_i += 1
                    subparsers = parser.add_subparsers(dest=f"_subcommand_{subcommand_i}")
                subparser = subparsers.add_parser(name=fieldname, description=field.description)
                populate_parser(subparser, subty)


    parser = argparse.ArgumentParser(description="Crear, destruir y manejar usuarios.")
    subcommand_i = 0
    populate_parser(parser, GlobalArgs)
    args = parser.parse_args()
    raise NotImplemented


if __name__ == "__main__":
    conf = parse_args()
    parser = pydantic_argparse.ArgumentParser(
        model=GlobalArgs,
        description="Crear, destruir y manejar usuarios.",
    )
    conf: GlobalArgs = parser.parse_typed_args()

    if conf.create:
        conf.create.add_users(conf)
    elif conf.destroy:
        conf.destroy.delete_users(conf)
    elif conf.scan:
        conf.scan.scan_users(conf)
    elif conf.run:
        conf.run.run_command_per_user(conf)
    else:
        raise RuntimeError("no command to run?")

    print("done")
