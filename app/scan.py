import gzip
import math
from typer import Typer
from datetime import datetime
from pathlib import Path
import subprocess
import os
import traceback
from hashlib import blake2b as good_hash
from pydantic import (
    BaseModel,
)

from app.subrun import register_subrun_func, run_as_user
from app.sync import sync_state
from app.types import DEFAULT_SCANS_PATH, Config, FsInfo, Scan, UserScan
from app.util import exception_context, get_userid, opener_private

app = Typer()


class ScanReport(BaseModel):
    """
    Un reporte de usuario hecho a partir de varios escaneos.
    """

    usuario: str
    ultimo_cambio_detectado: str
    ultimo_archivo_cambiado: str
    timestamp_escaneo: str
    tiene_archivo_php: str


def scan_path(path: Path) -> FsInfo:
    stat = path.lstat()
    name = path.name
    contents: str | list[FsInfo]
    if path.is_dir(follow_symlinks=False):
        contents = []
        for subpath in path.iterdir():
            if not os.access(subpath, os.R_OK):
                continue
            contents.append(scan_path(subpath))
        contents.sort(key=lambda sub: sub.name)
    else:
        contents = good_hash(path.read_bytes()).digest().hex()
    return FsInfo(
        name=name,
        mtime=math.floor(stat.st_mtime),
        ctime=math.floor(stat.st_ctime),
        mode=stat.st_mode,
        contents=contents,
    )


class ScanArgs(BaseModel):
    config: Config
    scantime: datetime
    lock: bool


class ScanRet(BaseModel):
    scan: Scan


def scan_as_root(p: ScanArgs) -> ScanRet:
    try:
        scan = Scan(scantime=p.scantime, users={})
        if p.lock:
            print("locking users")
            for group in p.config.groups:
                for user in group.users:
                    subprocess.run(["sudo", "passwd", "-l", get_userid(user, group)])
            print("locked all users")
        print(f"scanning {sum(len(group.users) for group in p.config.groups)} users")
        for group in p.config.groups:
            for user in group.users:
                userid = get_userid(user, group)
                home = Path(f"/home/{userid}")
                userscan = UserScan(home=scan_path(home))
                scan.users[userid] = userscan
                print(f"scanned user {userid}")
        return ScanRet(scan=scan)
    finally:
        if p.lock:
            print("unlocking users")
            for group in p.config.groups:
                for user in group.users:
                    try:
                        subprocess.run(
                            ["sudo", "passwd", "-u", get_userid(user, group)]
                        )
                    except subprocess.CalledProcessError:
                        traceback.print_exc()
            print("unlocked users")


register_subrun_func("scan.scan", ScanArgs, ScanRet, scan_as_root)


class WriteResultArgs(BaseModel):
    db_path: Path
    scan: Scan


class WriteResultRet(BaseModel):
    pass


def write_scan_result(p: WriteResultArgs) -> WriteResultRet:
    with exception_context(f"writing scan to {p.db_path}"):
        with open(p.db_path, "ab", opener=opener_private) as db_compressed_file:
            with gzip.open(db_compressed_file, "ab") as db_file:
                db_file.write((p.scan.model_dump_json() + "\n").encode())
    return WriteResultRet()


register_subrun_func("scan.write", WriteResultArgs, WriteResultRet, write_scan_result)


@app.command(
    "scan",
    help="Escanear las carpetas HOME de los usuarios, agregando el escaneo a una base de datos de instantáneas en el tiempo.",
)
def scan_users(
    *,
    config_path: Path | None = None,
    scans_path: Path | None = None,
    lock: bool = False,
    write_result_as_user: str | None = None,
):
    scantime = datetime.now()
    config = sync_state(config_path=config_path)

    # Realizar escaneo
    scan = run_as_user(
        "root", scan_as_root, ScanArgs(config=config, scantime=scantime, lock=lock)
    )

    # Agregar escaneo al archivo .scandb
    db_path = scans_path or DEFAULT_SCANS_PATH
    run_as_user(
        write_result_as_user,
        write_scan_result,
        WriteResultArgs(db_path=db_path, scan=scan.scan),
    )
