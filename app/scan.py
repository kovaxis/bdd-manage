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

from app.sync import sync_state
from app.types import DEFAULT_SCANS_PATH, FsInfo, Scan, UserScan
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


@app.command(
    "scan",
    help="Escanear las carpetas HOME de los usuarios, agregando el escaneo a una base de datos de instantáneas en el tiempo.",
)
def scan_users(
    *,
    config_path: Path | None = None,
    scans_path: Path | None = None,
    lock: bool = False,
):
    scantime = datetime.now()
    config = sync_state(config_path=config_path)

    # Realizar escaneo
    scan = Scan(scantime=scantime, users={})
    try:
        if lock:
            print("locking users")
            for group in config.groups:
                for user in group.users:
                    subprocess.run(["sudo", "passwd", "-l", get_userid(user, group)])
            print("locked all users")
        print(f"scanning {sum(len(group.users) for group in config.groups)} users")
        for group in config.groups:
            for user in group.users:
                userid = get_userid(user, group)
                home = Path(f"/home/{userid}")
                userscan = UserScan(home=scan_path(home))
                scan.users[userid] = userscan
                print(f"scanned user {userid}")
    finally:
        if lock:
            print("unlocking users")
            for group in config.groups:
                for user in group.users:
                    try:
                        subprocess.run(
                            ["sudo", "passwd", "-u", get_userid(user, group)]
                        )
                    except subprocess.CalledProcessError:
                        traceback.print_exc()
            print("unlocked users")

    # Agregar escaneo al archivo .scandb
    db_path = scans_path or DEFAULT_SCANS_PATH
    with exception_context(f"writing scan to {db_path}"):
        with open(db_path, "ab", opener=opener_private) as db_compressed_file:
            with gzip.open(db_compressed_file, "ab") as db_file:
                db_file.write((scan.model_dump_json() + "\n").encode())
