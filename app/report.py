import csv
from dataclasses import dataclass
from datetime import datetime
import gzip
from pathlib import Path
import re
import traceback
from typing import Annotated
from pydantic import BaseModel, Field, ValidationError
from typer import Typer

from app.scan import FsInfo
from app.sync import sync_state
from app.types import DEFAULT_SCANS_PATH, Scan
from app.util import UserBundle, exception_context, find_users_in_group

app = Typer()


@dataclass
class FileItem:
    path: Path
    change: datetime
    is_dir: bool
    fsinfo: FsInfo


@dataclass
class ReportCtx:
    revscandb: list[Scan]
    cachedscans: dict[int, dict[str, dict[Path, FileItem] | None]]
    subdir: Path
    ignore_hidden: bool
    ignore_metadata: bool
    ignore_dirs: bool
    regex: re.Pattern[str] | None

    def subflatten(
        self,
        out: dict[Path, FileItem],
        path: Path,
        fsinfo: FsInfo,
        homein: tuple[str, ...],
    ):
        is_dir = isinstance(fsinfo.contents, list)
        if (
            len(homein) == 0  # Exclude files above `homein` path
            and not (
                self.ignore_dirs and is_dir
            )  # Exclude directories if ignoring them
            and (
                self.regex is None or self.regex.fullmatch(str(path))
            )  # If regex is present, include only if it matches
        ):
            # Include this file/directory in the scan
            out[path] = FileItem(
                path=path,
                change=datetime.fromtimestamp(
                    fsinfo.mtime if self.ignore_metadata else fsinfo.ctime
                ),
                is_dir=is_dir,
                fsinfo=fsinfo,
            )
        if isinstance(fsinfo.contents, list):
            for child in fsinfo.contents:
                if self.ignore_hidden and child.name.startswith("."):
                    continue
                if len(homein) != 0 and homein[0] != child.name:
                    continue
                self.subflatten(out, path / child.name, child, homein[1:])

    def flatten(self, fsinfo: FsInfo) -> dict[Path, FileItem]:
        out: dict[Path, FileItem] = {}
        self.subflatten(out, Path("."), fsinfo, self.subdir.parts)
        return out

    def getscan(self, idx: int, user: str) -> dict[Path, FileItem] | None:
        if idx not in self.cachedscans:
            self.cachedscans[idx] = {}
        if user not in self.cachedscans[idx]:
            if user in self.revscandb[idx].users:
                userscan = self.revscandb[idx].users[user]
                self.cachedscans[idx][user] = self.flatten(userscan.home)
            else:
                self.cachedscans[idx][user] = None
        return self.cachedscans[idx][user]


class ScanReport(BaseModel):
    """
    Un reporte de usuario hecho a partir de varios escaneos.
    """

    usuario: str
    ultimo_cambio_detectado: str
    ultimo_archivo_cambiado: str
    timestamp_escaneo: str
    tiene_archivo_php: str


def read_scandb(
    db_path: Path | None,
    min_time: datetime | None,
    max_time: datetime | None,
) -> list[Scan]:
    db_path = db_path or DEFAULT_SCANS_PATH
    if not db_path.exists():
        print(f"warning: no scandb file found at {db_path}")
        return []

    scans: list[Scan] = []
    with exception_context(f"reading scan database from {db_path}"):
        with db_path.open("rb") as db_compressed_file:
            with gzip.open(db_compressed_file, "rb") as db_file:
                print(f"reading {db_path.stat().st_size / 1024}KB scan database")
                line = 0
                for scanline in db_file:
                    line += 1
                    try:
                        scan = Scan.model_validate_json(scanline)
                        if (min_time is None or scan.scantime >= min_time) and (
                            max_time is None or scan.scantime <= max_time
                        ):
                            scans.append(scan)
                    except ValidationError:
                        traceback.print_exc()
                        print(
                            f"failed to parse scan at line {line}, ignoring this scan"
                        )
    return scans


def generate_report_for_user(
    ctx: ReportCtx,
    bundle: UserBundle,
) -> ScanReport:
    for i in range(0, len(ctx.revscandb)):
        scan = ctx.getscan(i, bundle.id)
        if scan is not None:
            scantime = str(ctx.revscandb[i].scantime)
            if ctx.ignore_metadata:
                # Chequear hashes pasados de los contenidos del archivo
                for item in scan.values():
                    current_hash = item.fsinfo.contents
                    if isinstance(current_hash, list):
                        continue
                    for j in range(i + 1, len(ctx.revscandb)):
                        older_hash = None
                        older_scan = ctx.getscan(j, bundle.id)
                        if older_scan and item.path in older_scan:
                            older_hash = older_scan[item.path].fsinfo.contents
                        if older_hash == current_hash:
                            # Sabemos que por lo menos desde este instante hasta el presente el archivo no ha cambiado
                            item.change = min(item.change, ctx.revscandb[j].scantime)
                        else:
                            # Sabemos que hasta este instante el archivo era distinto
                            item.change = max(item.change, ctx.revscandb[j].scantime)
                            break
            items = sorted(
                scan.values(),
                key=lambda item: (item.change, not item.is_dir, item.path),
                reverse=True,
            )
            has_php = any(item.path.suffix == ".php" for item in items)
            if items:
                return ScanReport(
                    usuario=bundle.id,
                    timestamp_escaneo=scantime,
                    ultimo_archivo_cambiado=str(items[0].path),
                    ultimo_cambio_detectado=str(items[0].change),
                    tiene_archivo_php="Si" if has_php else "No",
                )
            else:
                return ScanReport(
                    usuario=bundle.id,
                    timestamp_escaneo=scantime,
                    ultimo_archivo_cambiado="No hay archivos",
                    ultimo_cambio_detectado="",
                    tiene_archivo_php="Si" if has_php else "No",
                )
    return ScanReport(
        usuario=bundle.id,
        timestamp_escaneo="No hay escaneos para este usuario",
        ultimo_archivo_cambiado="",
        ultimo_cambio_detectado="",
        tiene_archivo_php="No",
    )


@app.command("report", help="Generar un reporte de última modificación de archivos.")
def generate_report(
    group_name: Annotated[
        str | None,
        Field(description="Generar reporte solo para los usuarios en este grupo."),
    ],
    out: Annotated[
        Path, Field(description="Dónde guardar el .csv generado como reporte.")
    ],
    *,
    config_path: Path | None = None,
    db_path: Path | None = None,
    min_time: Annotated[
        datetime | None,
        Field(description="Considerar desde este tiempo en adelante."),
    ] = None,
    max_time: Annotated[
        datetime | None, Field(description="Considerar solo hasta este tiempo.")
    ] = None,
    subdir: Annotated[
        Path, Field(description="Considerar solo este subdirectorio.")
    ] = Path("."),
    ignore_hidden: Annotated[
        bool,
        Field(
            description="Ignorar archivos que comienzen con '.' para el cálculo de última modificación.",
        ),
    ] = True,
    ignore_metadata: Annotated[
        bool,
        Field(
            description="Ignorar cambios de metadata, y solo considerar cambios de contenido en archivos.",
        ),
    ] = True,
    regex: Annotated[
        str | None,
        Field(
            description="Filtrar usando esta expresión regular. (OJO: No es un glob-pattern)",
        ),
    ] = None,
):
    compiled_regex = None if regex is None else re.compile(regex)

    config = sync_state(config_path=config_path)
    user_bundles = find_users_in_group(config, group_name)
    scandb = read_scandb(db_path, min_time, max_time)

    if not user_bundles:
        if sum(len(group.users) for group in config.groups) == 0:
            print("No hay usuarios en el sistema. No se generó ningún reporte.")
        elif user_bundles is not None:
            print(f"No hay usuarios en el grupo {group_name}.")
        else:
            print(f'No existe el grupo "{group_name}".')
        return

    ctx = ReportCtx(
        revscandb=sorted(scandb, key=lambda scan: scan.scantime, reverse=True),
        cachedscans={},
        subdir=subdir,
        ignore_hidden=ignore_hidden,
        ignore_metadata=ignore_metadata,
        ignore_dirs=ignore_metadata,
        regex=compiled_regex,
    )
    report: list[ScanReport] = []
    user_bundles.sort(key=lambda bundle: bundle.id)
    for bundle in user_bundles:
        report.append(generate_report_for_user(ctx, bundle))

    with exception_context(f"writing userscan report at {out}"):
        with out.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=list(ScanReport.model_json_schema()["properties"].keys()),
            )
            writer.writeheader()
            for user_report in report:
                writer.writerow(user_report.model_dump())
    print(
        f"se genero un reporte de {len(report)} usuarios a partir de {len(scandb)} escaneos"
    )
