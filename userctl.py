#!/usr/bin/env python3

# Script para crear, destruir y en general manejar usuarios.
# Correr el comando con el argumento `--help` para ver la descripcion y posibles comandos.

import importlib
import importlib.util
import contextlib
import csv
from datetime import datetime
from pathlib import Path
import re
import string
import sys
import subprocess
import os
import traceback
from hashlib import blake2b as good_hash
from typing import Any, Optional


def autoinstall_deps(required_deps: dict[str, str]):
    missing = {
        name
        for name in required_deps.keys()
        if not importlib.util.find_spec(name.replace("-", "_"))
    }
    if missing:
        # subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                *[required_deps[depname] for depname in missing],
            ]
        )
        print("dependencias instaladas, por favor volver a correr")
        sys.exit(1)


autoinstall_deps(
    {
        "pydantic": "pydantic>=2.0.0,<3.0.0",
        "pydantic-argparse": "git+https://github.com/cody-mar10/pydantic-argparse.git@4a79a48aa393a8b8947229d40f297fbad5802ac1",
    }
)

from pydantic import BaseModel, Field, TypeAdapter, ValidationError  # noqa: E402
import pydantic_argparse  # noqa: E402


CFG_DIR: Path = Path(__file__).resolve().parent


class FsInfo(BaseModel):
    """
    Información compacta sobre un archivo/directorio.
    Almacena la estructura de los archivos y un hash de cada archivo, pero no los contenidos enteros.
    """

    name: str
    mtime: datetime
    contents: list["FsInfo"] | str


class User(BaseModel):
    """
    Datos sobre un usuario.
    """

    id: str
    fields: dict[str, str]


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


def ensure(cond: Any, *ctx):
    if not cond:
        msg = ": ".join(("assertion failed",) + ctx)
        raise AssertionError(msg)


def confirm(msg: str, default_confirm: bool = True) -> None:
    print(
        f"{msg} ({'Y' if default_confirm else 'y'}/{'n' if default_confirm else 'N'}) ",
        end="",
        flush=True,
    )
    userinput = input().strip().lower()
    if default_confirm:
        do_cancel = userinput == "n"
    else:
        do_cancel = userinput != "y"
    if do_cancel:
        print("cancelado")
        sys.exit(1)


USERSTR_SIGNATURE = "bdd-manage-user"


def opener_private(path: str, flags: int) -> int:
    return os.open(path, flags, 0o600)


def read_userdb() -> dict[str, User]:
    """
    Leer la base de datos `.userdb`, que contiene los atributos de los usuarios (como la contraseña original).
    """
    path = CFG_DIR.joinpath(".userdb")
    if path.exists():
        try:
            with exception_context(f'reading userdb from "{path}"'):
                return TypeAdapter(dict[str, User]).validate_json(path.read_bytes())
        except Exception:
            traceback.print_exc()
    return {}


def write_userdb(userdb: dict[str, User]):
    path = CFG_DIR.joinpath(".userdb")
    with open(path, "wb", opener=opener_private) as file:
        file.write(TypeAdapter(dict[str, User]).dump_json(userdb))


def read_system_users() -> dict[str, User]:
    """
    Leer la lista de usuarios presentes en el sistema.
    La lista se lee directo de los usuarios de linux, pero los atributos se complementan desde `.userdb`.
    """
    userdb = read_userdb()
    users: dict[str, User] = {}
    with Path("/etc/passwd").open() as passwd_file:
        for userline in passwd_file:
            userfields = userline.split(":")
            username = userfields[0]
            usercomment = userfields[4]
            if usercomment == USERSTR_SIGNATURE:
                if username in userdb and userdb[username].id == username:
                    users[username] = userdb[username]
                else:
                    users[username] = User(id=username, fields={})
                    print(f"WARNING: user {username} is not in .userdb")
    return users


def read_user_list(list_path: Path) -> dict[str, User]:
    """
    Leer una lista de usuarios en formato CSV.
    """

    def read_user(record: dict[str, str]) -> User:
        if "id" not in record and "email" in record:
            email = record["email"]
            ensure("@" in email, "email no tiene @")
            record["id"] = email[: email.find("@")]
        ensure(
            "id" in record,
            "lista de usuarios no tiene 'id' ni 'email', no se puede continuar",
        )
        id = record["id"]
        del record["id"]
        return User(id=id, fields=record)

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
        print(f"read {len(users)} users from {list_path}")
        return users
    except FileNotFoundError:
        print(
            f"no se encontro la lista de alumnos en '{list_path}'",
            file=sys.stderr,
        )
        sys.exit(1)


class CreateCmd(pydantic_argparse.BaseCommand):
    list: Path = Field(description="Lista de alumnos a agregar, en formato CSV.")
    template: Path = Field(
        Path("./user_template"),
        description="Directorio con los contenidos iniciales de la carpeta HOME para un usuario.",
    )

    def add_users(self, conf: "GlobalArgs"):
        """
        Código para añadir usuarios desde una lista de alumnos.
        """
        old_users = read_system_users()
        new_users = read_user_list(self.list)
        created = 0

        # Check that users have passwords
        password_field = "password"
        no_password = 0
        for user in new_users.values():
            no_password += int(not user.fields.get(password_field))
        if no_password > 0:
            print(
                f"{no_password}/{len(new_users)} usuarios a crear no tienen campo '{password_field}'"
            )
            print("abortando")
            sys.exit(1)

        # Write .userdb
        userdb = read_userdb()
        for user in new_users.values():
            userdb[user.id] = user
        write_userdb(userdb)

        # Create users
        for user in new_users.values():
            try:
                name = user.id
                password = user.fields[password_field]
                # Create Linux user
                subprocess.run(
                    [
                        "sudo",
                        "useradd",
                        name,
                        "-s",
                        "/bin/bash",
                        "-m",
                        "-c",
                        USERSTR_SIGNATURE,
                    ],
                    check=True,
                )
                # Set password
                subprocess.run(
                    ["sudo", "passwd", name],
                    input=f"{password}\n{password}\n".encode(),
                    check=True,
                )
                # Limit memory usage
                SYSTEMD_USER_SLICE = (
                    "\n".join(
                        map(
                            str.strip,
                            """
                    # Limitar uso de memoria y CPU de los usuarios
                    [Slice]
                    MemoryHigh=3%
                    MemoryMax=4%
                    CPUQuota=50%
                """.splitlines(),
                        )
                    )
                    + "\n"
                )
                uid_numeric = (
                    subprocess.check_output(["id", "-u", name]).decode().strip()
                )
                subprocess.run(
                    [
                        "sudo",
                        "mkdir",
                        "-p",
                        f"/etc/systemd/system/user-{uid_numeric}.slice.d",
                    ],
                    check=True,
                )
                subprocess.run(
                    [
                        "sudo",
                        "tee",
                        f"/etc/systemd/system/user-{uid_numeric}.slice.d/50-limit-memory.conf",
                    ],
                    input=SYSTEMD_USER_SLICE.encode(),
                    check=True,
                )
                # Initialize home with template
                if self.template.exists():
                    ensure(
                        self.template.is_dir(),
                        f"template path '{self.template}' is not a directory",
                    )
                    ensure(
                        os.system(
                            f"sudo cp -r {self.template.joinpath('*')} /home/{name}/"
                        )
                        == 0,
                        "copying home template failed",
                    )
                # Configurate permissions on home directory
                # (all permissions to self, read-only to the group, none to others)
                subprocess.run(
                    ["sudo", "chmod", "-R", "2750", f"/home/{name}"], check=True
                )
                # (setup the user's group to www-data so that apache can read from this users' home directory)
                subprocess.run(
                    ["sudo", "chown", "-R", f"{name}:www-data", f"/home/{name}"],
                    check=True,
                )
                # Create the user and its database, and setup postgres permissions
                CREATE_USER_SQL = """
                    CREATE ROLE "{user}" NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT LOGIN NOREPLICATION;
                    ALTER ROLE "{user}" WITH CONNECTION LIMIT 6;
                    ALTER ROLE "{user}" WITH PASSWORD '{password}';
                    CREATE DATABASE "{user}" OWNER "{user}";
                    REVOKE ALL PRIVILEGES ON DATABASE "{user}" FROM PUBLIC;
                """
                for line in CREATE_USER_SQL.splitlines():
                    line = line.strip()
                    if line:
                        line = line.replace("{user}", name)
                        line = line.replace(
                            "{password}",
                            password.replace("\\", "\\\\").replace("'", "\\'"),
                        )
                        subprocess.run(
                            [
                                "sudo",
                                "-u",
                                "postgres",
                                "psql",
                                "-c",
                                line,
                            ],
                            cwd="/",
                            check=True,
                        )
                print(f"created user {name}")
                created += 1
            except subprocess.CalledProcessError:
                traceback.print_exc()
                print(f"failed to create user {user.id}")
        try:
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        except subprocess.CalledProcessError:
            traceback.print_exc()
            print("failed to reload systemd daemon to update resource usage limits")
        new_users = read_system_users()
        print(
            f"existían {len(old_users)} usuarios de alumno, se crearon {created} usuarios nuevos, ahora existen {len(new_users)} usuarios de alumno"
        )


class DestroyCmd(pydantic_argparse.BaseCommand):
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
            confirm(
                f"se eliminarán {len(delete_users)}/{len(sys_users)} usuarios de alumnos. confirmar?",
                default_confirm=False,
            )
        for username in delete_users:
            user = sys_users[username]
            try:
                # Delete the systemd cgroup slice that limits memory usage
                uid_numeric = (
                    subprocess.check_output(["id", "-u", user.id]).decode().strip()
                )
                subprocess.run(
                    [
                        "sudo",
                        "rm",
                        f"/etc/systemd/system/user-{uid_numeric}.slice.d/50-limit-memory.conf",
                    ]
                )
                subprocess.run(
                    ["sudo", "rmdir", f"/etc/systemd/system/user-{uid_numeric}.slice.d"]
                )
                # Delete the linux user
                subprocess.run(["sudo", "deluser", user.id, "--remove-home"])
                # Delete the user's database and postgres user
                DESTROY_USER_SQL = """
                    DROP DATABASE "{user}";
                    DROP ROLE "{user}";
                """
                for line in DESTROY_USER_SQL.splitlines():
                    line = line.strip()
                    if line:
                        subprocess.run(
                            [
                                "sudo",
                                "-u",
                                "postgres",
                                "psql",
                                "-c",
                                line.replace("{user}", user.id),
                            ],
                            cwd="/",
                        )
                print(f"deleted user {user.id}")
            except subprocess.CalledProcessError:
                traceback.print_exc()
                print(f"failed to destroy user {user.id}")
        try:
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        except subprocess.CalledProcessError:
            traceback.print_exc()
            print("failed to reload systemd daemon to update resource usage limits")
        new_users = read_system_users()
        print(
            f"existían {len(sys_users)} usuarios de alumno, se pidió no eliminar una lista de {len(keep)} alumnos, ahora hay {len(new_users)} usuarios de alumno"
        )


class ScanCmd(pydantic_argparse.BaseCommand):
    out: Optional[Path] = Field(
        None,
        description="Generar un reporte y almacenarlo en esta ruta en formato CSV.",
    )
    lock: bool = Field(
        False,
        description="Bloquear las cuentas de los usuarios mientras se realiza el escaneo.",
    )
    no_scan: bool = Field(
        False,
        description="No escanear, generar un reporte solo a partir de escaneos pasados.",
    )
    allow_tamper: bool = Field(
        False,
        description="Generar un escaneo permitiendo a los alumnos eliminar archivos.",
    )
    subdirectory: Path = Field(
        Path("."),
        description="Escanear específicamente esta subcarpeta dentro de la carpeta home.",
    )

    def scan_users(self, conf: "GlobalArgs"):
        """
        Código para escanear las carpetas HOME y determinar horas de entrega
        """
        scantime = datetime.now()
        users = read_system_users()

        # Escanear usuarios
        db_path = CFG_DIR.joinpath(".scandb")
        if not self.no_scan:
            scan = self.do_scan(scantime, users)

            # Agregar escaneo al archivo .scandb
            with exception_context(f"writing scan to {db_path}"):
                with open(
                    db_path, "a", encoding="utf-8", opener=opener_private
                ) as db_file:
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
        name = path.name
        contents: str | list[FsInfo]
        if path.is_dir():
            contents = []
            for subpath in path.iterdir():
                if not os.access(subpath, os.R_OK):
                    continue
                contents.append(self.visit_fs(subpath))
            contents.sort(key=lambda sub: sub.name)
        else:
            contents = good_hash(path.read_bytes()).digest().hex()
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
                        print(
                            f"failed to parse scan at line {line}, ignoring this scan"
                        )
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
            if not self.allow_tamper:
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
        hx.update(good_hash(info.name.encode()).digest())
        if isinstance(info.contents, str):
            hx.update(b"f")
            hx.update(info.contents.encode())
        else:
            hx.update(b"d")
            hashes: list[bytes] = []
            for sub in info.contents:
                hashes.append(self.hash_fsinfo(sub))
            hashes.sort()
            for h in hashes:
                hx.update(h)
        return hx.digest()

    def get_scan_mtime(self, scan: UserScan) -> tuple[datetime, str]:
        fsinfo = scan.home
        deleted = (datetime.now(), f"{self.subdirectory} does not exist")
        for part in self.subdirectory.parts:
            if not isinstance(fsinfo.contents, list):
                return deleted
            for subfile in fsinfo.contents:
                if subfile.name == part:
                    fsinfo = subfile
                    break
            else:
                return deleted
        return self.get_fsinfo_mtime(fsinfo, f"{self.subdirectory}") or (
            fsinfo.mtime,
            f"{self.subdirectory}",
        )

    def get_fsinfo_mtime(
        self, fsinfo: FsInfo, path: str
    ) -> tuple[datetime, str] | None:
        if isinstance(fsinfo.contents, str):
            return (fsinfo.mtime, path + fsinfo.name)
        else:
            max_mtime: tuple[datetime, str] | None = None
            for sub in fsinfo.contents:
                sub_mtime = self.get_fsinfo_mtime(sub, path + fsinfo.name + "/")
                if sub_mtime is not None and (
                    max_mtime is None or sub_mtime > max_mtime
                ):
                    max_mtime = sub_mtime
            return max_mtime

    def has_php(self, fsinfo: FsInfo) -> bool:
        if isinstance(fsinfo.contents, str):
            return fsinfo.name.endswith(".php")
        else:
            for sub in fsinfo.contents:
                if self.has_php(sub):
                    return True
            return False


class RunCmd(pydantic_argparse.BaseCommand):
    def run_command_per_user(self, conf: "GlobalArgs"):
        """
        Código para correr un comando arbitrario por usuario
        """
        users = read_system_users()

        print("ingresar comando: ", file=sys.stderr, flush=True, end="")
        command = input().strip()
        if not command:
            print("error: no se ingresó un comando", file=sys.stderr)
            sys.exit(1)

        keys = {
            item[1] for item in string.Formatter().parse(command) if item[1] is not None
        }
        keys_without_id = keys - {"id"}
        valid_users: set[str] = {
            user.id
            for user in users.values()
            if keys_without_id.issubset(user.fields.keys())
        }
        invalid_users = set(users.keys()) - valid_users
        if keys:
            print(f'el comando "{command}" utiliza los atributos {", ".join(keys)}')
        if invalid_users:
            if not valid_users:
                print(
                    "ningún usuario tiene todos los atributos necesarios definidos. revisa que estén bien escritos."
                )
                sys.exit(1)
            print(
                f"{len(invalid_users)}/{len(users)} usuarios tienen estos atributos indefinidos"
            )
            print(f"se ignorarán estos usuarios: {', '.join(sorted(invalid_users))}")
            confirm(
                f"confirmas que quieres correr el comando solo para {len(valid_users)}/{len(users)} usuarios?"
            )

        print(f"corriendo comando para {len(valid_users)} usuarios")
        ok_runs = 0
        for username in sorted(valid_users):
            user = users[username]
            cmd = command.format(id=user.id, **user.fields)
            print(f'corriendo comando "{cmd}"')
            result = os.system(cmd)
            if result == 0:
                ok_runs += 1
            else:
                print(
                    f"el comando falló para el usuario {user.id} (exit code {result})"
                )
        print(f"{ok_runs}/{len(valid_users)} comandos ejecutaron correctamente")


class ListCmd(pydantic_argparse.BaseCommand):
    compare_to: Optional[Path] = Field(
        None,
        description="Comparar la lista de usuarios en el sistema contra esta lista de usuarios en formato CSV.",
    )

    def list_users(self, conf: "GlobalArgs"):
        """
        Código para mostrar información sobre los usuarios.
        """

        def show(msg: str, a: set[str]):
            print(f"{len(a)} {msg}: {' '.join(sorted(a))}")

        system = set(read_system_users().keys())
        show("usuarios en el sistema", system)
        if self.compare_to:
            print()
            cmp = set(read_user_list(self.compare_to).keys())
            show(f"usuarios leídos de {self.compare_to}", cmp)
            print()
            show("usuarios en ambas listas", system & cmp)
            print()
            show("usuarios en el sistema pero no en la lista", system - cmp)
            print()
            show("usuarios en la lista pero no en el sistema", cmp - system)


class GlobalArgs(BaseModel):
    create: Optional[CreateCmd] = Field(
        None,
        description="Crear usuarios a partir de una lista de usuarios en formato CSV.",
    )
    destroy: Optional[DestroyCmd] = Field(
        None,
        description="Eliminar usuarios, opcionalmente manteniendo una lista de usuarios.",
    )
    scan: Optional[ScanCmd] = Field(
        None,
        description="Escanear las carpetas HOME de los usuarios para determinar las últimas fechas de modificación.",
    )
    run: Optional[RunCmd] = Field(
        None,
        description="Correr un comando por cada usuario. El comando se recibe por stdin, y se reemplazan identificadores como {id} o {password}.",
    )
    list: Optional[ListCmd] = Field(
        None,
        description="Listar los usuarios en el sistema, opcionalmente comparando contra una lista de alumnos.",
    )


def parse_args() -> GlobalArgs:
    parser = pydantic_argparse.ArgumentParser(
        GlobalArgs, description="Crear, destruir y manejar usuarios."
    )
    return parser.parse_typed_args()


if __name__ == "__main__":
    if os.geteuid() == 0:
        print("userctl should not run as root")
        sys.exit(1)
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
    elif conf.list:
        conf.list.list_users(conf)
    else:
        raise RuntimeError("no command to run?")
