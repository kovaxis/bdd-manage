from abc import abstractmethod
from collections.abc import Callable
from rich import reconfigure
from typer import Typer
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
from typing import Annotated, Any, Generic, Optional, TypeVar
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from app.io import read_system_users
from app.util import exception_context, opener_private

app = Typer()


class FsInfo(BaseModel):
    """
    Información compacta sobre un archivo/directorio.
    Almacena la estructura de los archivos y un hash de cada archivo, pero no los contenidos enteros.
    """

    name: str
    mtime: datetime
    contents: list["FsInfo"] | str


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


class ScanCmd(BaseModel):
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

    def scan_users(self):
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
        return self.get_fsinfo_mtime(scan.home, "/") or (scan.home.mtime, "/")

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
